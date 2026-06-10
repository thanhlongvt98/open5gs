/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "context.h"

#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#if HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

#include "arp-nd.h"
#include "event.h"
#include "gtp-path.h"
#include "pfcp-path.h"
#include "rule-match.h"

#define UPF_GTP_HANDLED     1

const uint8_t proxy_mac_addr[] = { 0x0e, 0x00, 0x00, 0x00, 0x00, 0x01 };

static ogs_pkbuf_pool_t *packet_pool = NULL;

static void upf_gtp_handle_multicast(ogs_pkbuf_t *recvbuf);

static int check_framed_routes(upf_sess_t *sess, int family, uint32_t *addr)
{
    int i = 0;
    ogs_ipsubnet_t *routes = family == AF_INET ?
        sess->ipv4_framed_routes : sess->ipv6_framed_routes;

    if (!routes)
        return false;

    for (i = 0; i < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI; i++) {
        uint32_t *sub = routes[i].sub;
        uint32_t *mask = routes[i].mask;

        if (!routes[i].family)
            break;

        if (family == AF_INET) {
            if (sub[0] == (addr[0] & mask[0]))
                return true;
        } else {
            if (sub[0] == (addr[0] & mask[0]) &&
                sub[1] == (addr[1] & mask[1]) &&
                sub[2] == (addr[2] & mask[2]) &&
                sub[3] == (addr[3] & mask[3]))
                return true;
        }
    }
    return false;
}

#define ETHERTYPE_8021Q 0x8100  /* IEEE 802.1Q VLAN tag (TSN streams carry VID + PCP) */

/* Return the L3 EtherType, transparently peeling an 802.1Q VLAN tag if present, so a
 * tagged TSN frame classifies by its inner type (IP / gPTP) instead of 0x8100 -- this
 * also stops a tagged frame from being mislogged as "[DROP] Invalid eth_type [8100]". */
static uint16_t _get_eth_type(uint8_t *data, uint len) {
    if (len <= ETHER_HDR_LEN)
        return 0;
    struct ether_header *hdr = (struct ether_header *)data;
    uint16_t et = htobe16(hdr->ether_type);
    if (et == ETHERTYPE_8021Q && len >= ETHER_HDR_LEN + 4)
        return htobe16(*(uint16_t *)(data + ETHER_HDR_LEN + 2));  /* inner type, after the TCI */
    return et;
}

/* Extract the 802.1Q VID + PCP from a tagged frame; returns false if untagged.
 * TCI = PCP[3] | DEI[1] | VID[12] (IEEE 802.1Q). DS-TT/NW-TT per TS 23.501 §5.28.3. */
static bool _get_vlan(const uint8_t *data, uint len, uint16_t *vid, uint8_t *pcp) {
    if (len < ETHER_HDR_LEN + 4)
        return false;
    if (htobe16(*(const uint16_t *)(data + 12)) != ETHERTYPE_8021Q)
        return false;
    uint16_t tci = htobe16(*(const uint16_t *)(data + ETHER_HDR_LEN));
    if (vid)
        *vid = tci & 0x0FFF;
    if (pcp)
        *pcp = (uint8_t)((tci >> 13) & 0x7);
    return true;
}

/* UPF-local Ethernet fast-path classification (observability only).
 * Runs only for Ethernet PDU sessions (Step-1 sess->correlation.ethernet). */
#define ETHERTYPE_GPTP 0x88F7  /* IEEE 802.1AS / 1588 gPTP (TS 23.501 §5.27.1.2.2.1) */

typedef enum {
    UPF_ETH_CLASS_HIT,           /* Ethernet frame on a matched PDR */
    UPF_ETH_CLASS_MISS,          /* matched PDR, no stream binding (populated in Step 3) */
    UPF_ETH_CLASS_NO_PDR_MATCH,  /* session known (N3 TEID) but no PDR/filter hit */
    UPF_ETH_CLASS_GPTP,          /* EtherType 0x88F7 -> NW-TT gPTP path */
} upf_eth_class_t;

static const char *upf_eth_class_str(upf_eth_class_t c)
{
    switch (c) {
    case UPF_ETH_CLASS_HIT:          return "HIT";
    case UPF_ETH_CLASS_MISS:         return "MISS";
    case UPF_ETH_CLASS_NO_PDR_MATCH: return "NO_PDR_MATCH";
    case UPF_ETH_CLASS_GPTP:         return "GPTP";
    default:                         return "UNKNOWN";
    }
}

/* NW-TT MAC-learning bridge (TS 23.501 §5.8.2.5.3).
 *
 * The Ethernet PDU session's N6 egress is a TAP device handing us full L2
 * frames. We use the first configured TAP as the bridge port (single Ethernet
 * DN in this testbed; matches OAI's single N6 redirect interface). */
static ogs_pfcp_dev_t *upf_eth_bridge_dev(void)
{
    ogs_pfcp_dev_t *dev = NULL;
    ogs_list_for_each(&ogs_pfcp_self()->dev_list, dev) {
        if (dev->is_tap)
            return dev;
    }
    return NULL;
}

/* Match a DL L2 frame against a parsed Ethernet packet filter (TS 24.501
 * §9.11.4.13). All present components must match (logical AND). A VID or PCP
 * component on an untagged frame fails the match. Empty filter never matches.
 *
 * swap_mac: the AF/PCF emits the filter in UL-canonical form (dst-MAC = the
 * remote/NW endpoint) so the UE's UL classifier matches UL frames as-is. On the
 * DL (CORE) interface the remote endpoint is the frame's SOURCE, so the UPF
 * swaps the dst/src MAC comparison (TS 29.244 §5.2.1A.2A). VID/PCP/EtherType are
 * direction-independent and compared as-is. */
static bool upf_eth_frame_matches(
        const ogs_pf_content_t *c, uint8_t *data, uint len, bool swap_mac)
{
    int i;
    uint16_t vid = 0, et;
    uint8_t pcp = 0;
    bool tagged;
    const uint8_t *dst = data;          /* frame dst MAC */
    const uint8_t *src = data + 6;      /* frame src MAC */

    if (len < ETHER_HDR_LEN)
        return false;

    tagged = _get_vlan(data, len, &vid, &pcp);

    for (i = 0; i < c->num_of_component; i++) {
        switch (c->component[i].type) {
        case OGS_PACKET_FILTER_DESTINATION_MAC_ADDRESS_TYPE:
            if (memcmp(swap_mac ? src : dst, c->component[i].mac, 6) != 0)
                return false;
            break;
        case OGS_PACKET_FILTER_SOURCE_MAC_ADDRESS_TYPE:
            if (memcmp(swap_mac ? dst : src, c->component[i].mac, 6) != 0)
                return false;
            break;
        case OGS_PACKET_FILTER_8021Q_C_TAG_VID_TYPE:
            if (!tagged || (c->component[i].vid & 0x0FFF) != (vid & 0x0FFF))
                return false;
            break;
        case OGS_PACKET_FILTER_8021Q_C_TAG_PCP_DEI_TYPE:
            /* component stores (pcp << 1) | DEI; compare the 3-bit PCP */
            if (!tagged || ((c->component[i].pcp_dei >> 1) & 0x7) != pcp)
                return false;
            break;
        case OGS_PACKET_FILTER_ETHERTYPE_TYPE:
            et = _get_eth_type(data, len);
            if (c->component[i].ethertype != et)
                return false;
            break;
        default:
            break;
        }
    }
    return c->num_of_component > 0;
}

/* True if the PDR carries any Ethernet packet-filter rule (is_eth). */
static bool upf_pdr_has_eth_rule(ogs_pfcp_pdr_t *pdr)
{
    ogs_pfcp_rule_t *rule = NULL;
    ogs_list_for_each(&pdr->rule_list, rule)
        if (rule->is_eth)
            return true;
    return false;
}

/* True if any of the PDR's Ethernet packet-filter rules matches the frame.
 * swap: DL (CORE) passes true (filter is UL-canonical, dst-MAC = remote = the
 * DL frame's source); UL (ACCESS) passes false (dst-MAC = the UL frame's dst).
 * See upf_eth_frame_matches (TS 29.244 §5.2.1A.2A). */
static bool upf_eth_pdr_matches(
        ogs_pfcp_pdr_t *pdr, uint8_t *data, uint len, bool swap)
{
    ogs_pfcp_rule_t *rule = NULL;
    ogs_list_for_each(&pdr->rule_list, rule) {
        if (!rule->is_eth)
            continue;
        if (upf_eth_frame_matches(&rule->eth_content, data, len, swap))
            return true;
    }
    return false;
}

/* Select the downlink PDR of an Ethernet PDU session and hand the raw L2 frame
 * to ogs_pfcp_up_handle_pdr(), which applies the FAR Outer Header Creation
 * (GTP-U encap toward the gNB). Consumes pkbuf on success.
 *
 * PDR selection (TS 23.501 §5.7.1.1, TS 24.501 §9.11.4.13): a PDR carrying an
 * Ethernet packet filter (is_eth) matches only frames with the TSN stream's L2
 * identity (dst MAC / C-TAG VID / PCP / EtherType) and steers them onto the
 * dedicated QoS flow (QFI 2 / 5QI 85). A DL PDR with no eth filter is the
 * match-all default flow (QFI 1) and receives everything else. The pdr_list is
 * precedence-sorted, so the first eth filter that matches wins.
 * Returns true if the frame was forwarded (pkbuf consumed). */
static bool upf_eth_dl_forward(upf_sess_t *sess, ogs_pkbuf_t *pkbuf)
{
    ogs_pfcp_pdr_t *pdr = NULL, *selected_pdr = NULL, *fallback_pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_user_plane_report_t report;
    int i;

    ogs_assert(sess);
    ogs_assert(pkbuf);

    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        bool has_eth_filter = false, eth_matched = false;

        far = pdr->far;
        if (!far)
            continue;
        if (pdr->src_if != OGS_PFCP_INTERFACE_CORE)
            continue;
        if (far->dst_if != OGS_PFCP_INTERFACE_ACCESS)
            continue;
        if (far->outer_header_creation.gtpu4 == 0 &&
            far->outer_header_creation.gtpu6 == 0)
            continue;

        /* Candidate DL PDR: inspect its Ethernet packet-filter rules.
         * DL (CORE): swap MAC (filter is UL-canonical). */
        has_eth_filter = upf_pdr_has_eth_rule(pdr);
        if (has_eth_filter)
            eth_matched = upf_eth_pdr_matches(
                    pdr, pkbuf->data, pkbuf->len, true /* DL: swap MAC */);

        if (has_eth_filter) {
            if (eth_matched && !selected_pdr)
                selected_pdr = pdr;     /* precise TSN-stream match */
        } else if (!fallback_pdr) {
            fallback_pdr = pdr;         /* match-all default flow */
        }
    }

    pdr = selected_pdr ? selected_pdr : fallback_pdr;
    if (!pdr)
        return false;

    for (i = 0; i < pdr->num_of_urr; i++)
        upf_sess_urr_acc_add(sess, pdr->urr[i], pkbuf->len, false);

    ogs_assert(true == ogs_pfcp_up_handle_pdr(
                pdr, OGS_GTPU_MSGTYPE_GPDU, NULL, pkbuf, &report));
    return true;
}

/* Flood a DL broadcast/multicast L2 frame to every active Ethernet PDU session
 * (TS 23.501 §5.8.2.5.3). Each session gets its own copy. Returns true if at
 * least one Ethernet session was found (the caller then frees the original). */
/* NW-TT 802.1Qbv gate: returns true (=> drop) when a VLAN-tagged frame's PCP is not
 * in this session's gate allowed-PCP set programmed by the PMIC (TS 23.501 §5.28.3;
 * IEEE 802.1Q §8.6.8.4). Untagged frames and sessions with no parsed gate pass. The
 * PMIC gate is per-traffic-class/PCP; the strict per-cycle time window is a later
 * refinement gated on gate-synchronized talkers. */
static bool upf_nwtt_gate_blocks(const upf_sess_t *sess, ogs_pkbuf_t *pkbuf,
        const char *dir)
{
    uint16_t vid = 0;
    uint8_t pcp = 0;
    if (!sess || !sess->nwtt.gate_pcp_mask)
        return false;
    if (!_get_vlan(pkbuf->data, pkbuf->len, &vid, &pcp))
        return false;
    if ((sess->nwtt.gate_pcp_mask >> pcp) & 0x1)
        return false;
    ogs_info("[UPF] NW-TT gate DROP %s vid[%u] pcp[%u] (allowed mask[0x%02x])",
             dir, vid, pcp, sess->nwtt.gate_pcp_mask);
    return true;
}

static bool upf_eth_dl_flood(ogs_pkbuf_t *pkbuf)
{
    upf_sess_t *sess = NULL;
    bool any = false;

    ogs_list_for_each(&upf_self()->sess_list, sess) {
        ogs_pkbuf_t *clone = NULL;
        if (!sess->correlation.ethernet)
            continue;
        any = true;
        /* NW-TT DL gate: skip this session if the frame's PCP is gated out. */
        if (upf_nwtt_gate_blocks(sess, pkbuf, "DL-flood"))
            continue;
        clone = ogs_pkbuf_copy(pkbuf);
        if (!clone)
            continue;
        if (!upf_eth_dl_forward(sess, clone))
            ogs_pkbuf_free(clone);
    }
    return any;
}

static void _gtpv1_tun_recv_common_cb(
        short when, ogs_socket_t fd, bool has_eth, void *data)
{
    ogs_pkbuf_t *recvbuf = NULL;

    upf_sess_t *sess = NULL;
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_pdr_t *fallback_pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_user_plane_report_t report;
    int i;

    recvbuf = ogs_tun_read(fd, packet_pool);
    if (!recvbuf) {
        ogs_warn("ogs_tun_read() failed");
        return;
    }

    if (has_eth) {
        ogs_pkbuf_t *replybuf = NULL;
        uint16_t eth_type = _get_eth_type(recvbuf->data, recvbuf->len);
        uint8_t size;

        /* NW-TT bridge DL ingress. The full L2 frame is intact
         * (dst MAC | src MAC | ethertype | ...). Resolve the destination MAC to
         * an Ethernet PDU session and GTP-U-encap the whole frame toward the
         * gNB; flood broadcast/multicast to all Ethernet sessions. Only IP-over-
         * TAP frames (no Ethernet PDU session) fall through to the ARP/ND/IP
         * handling below. (TS 23.501 §5.6.10.2, §5.8.2.5.3.) */
        if (recvbuf->len >= 2 * UPF_MAC_ALEN) {
            const uint8_t *dst_mac = recvbuf->data;
            bool group_addr = (dst_mac[0] & 0x01); /* broadcast or multicast */

            /* NW-TT DL VID/PCP observability (validate the per-flow 802.1Q tag in). */
            uint16_t dl_vid = 0; uint8_t dl_pcp = 0;
            if (_get_vlan(recvbuf->data, recvbuf->len, &dl_vid, &dl_pcp))
                ogs_info("[UPF] Ethernet DL vid[%u] pcp[%u] ethertype[0x%04x] %s",
                         dl_vid, dl_pcp, _get_eth_type(recvbuf->data, recvbuf->len),
                         group_addr ? "(flood)" : "(unicast)");

            if (!group_addr) {
                upf_sess_t *esess = upf_sess_find_by_mac(dst_mac);
                if (esess && esess->correlation.ethernet) {
                    /* NW-TT DL gate: drop a unicast frame gated out for this session. */
                    if (upf_nwtt_gate_blocks(esess, recvbuf, "DL"))
                        goto cleanup;
                    if (upf_eth_dl_forward(esess, recvbuf))
                        return; /* recvbuf consumed by ogs_pfcp_up_handle_pdr() */
                    goto cleanup;
                }
            } else {
                if (upf_eth_dl_flood(recvbuf))
                    goto cleanup; /* copies forwarded; free the original */
            }
        }

        if (eth_type == ETHERTYPE_ARP) {
            if (is_arp_req(recvbuf->data, recvbuf->len) &&
                    upf_sess_find_by_ipv4(
                        arp_parse_target_addr(recvbuf->data, recvbuf->len))) {
                replybuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
                ogs_assert(replybuf);
                ogs_pkbuf_reserve(replybuf, OGS_TUN_MAX_HEADROOM);
                ogs_pkbuf_put(replybuf, OGS_MAX_PKT_LEN-OGS_TUN_MAX_HEADROOM);
                size = arp_reply(replybuf->data, recvbuf->data, recvbuf->len,
                    proxy_mac_addr);
                ogs_pkbuf_trim(replybuf, size);
                ogs_info("[SEND] reply to ARP request: %u", size);
            } else {
                goto cleanup;
            }
        } else if (eth_type == ETHERTYPE_IPV6 &&
                    is_nd_req(recvbuf->data, recvbuf->len)) {
            replybuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
            ogs_assert(replybuf);
            ogs_pkbuf_reserve(replybuf, OGS_TUN_MAX_HEADROOM);
            ogs_pkbuf_put(replybuf, OGS_MAX_PKT_LEN-OGS_TUN_MAX_HEADROOM);
            size = nd_reply(replybuf->data, recvbuf->data, recvbuf->len,
                proxy_mac_addr);
            ogs_pkbuf_trim(replybuf, size);
            ogs_info("[SEND] reply to ND solicit: %u", size);
        }
        if (replybuf) {
            if (ogs_tun_write(fd, replybuf) != OGS_OK)
                ogs_warn("ogs_tun_write() for reply failed");
            
            ogs_pkbuf_free(replybuf);
            goto cleanup;
        }
        /* downlink gPTP detection (NW-TT DL ingress observed).
         * sess is not yet known here (pre-strip); the gate is interface-level
         * (has_eth = TAP/Ethernet). The full NW-TT DL ingress action (TSi
         * timestamp, correctionField/rateRatio update, TSi suffix; forward to
         * DS-TT per TS 23.501 §5.27.1.2.2.1) is deferred -- we only observe it,
         * then fall through to the existing drop. */
        if (eth_type == ETHERTYPE_GPTP) {
            /* Known/expected NW-TT DL gPTP frame: observation + forward is
             * deferred (see above). Drop it QUIETLY at debug level and skip the
             * generic eth_type error + hexdump below, which otherwise floods the
             * log ~1/sec with this benign, expected frame. */
            ogs_debug("[UPF] Ethernet DL class[%s] ethertype[0x%04x] len[%d] "
                      "(NW-TT gPTP ingress observed; timestamp/forward deferred)",
                      upf_eth_class_str(UPF_ETH_CLASS_GPTP), eth_type, recvbuf->len);
            goto cleanup;
        }

        if (eth_type != ETHERTYPE_IP && eth_type != ETHERTYPE_IPV6) {
            ogs_error("[DROP] Invalid eth_type [%x]]", eth_type);
            ogs_log_hexdump(OGS_LOG_ERROR, recvbuf->data, recvbuf->len);
            goto cleanup;
        }
        ogs_pkbuf_pull(recvbuf, ETHER_HDR_LEN);
    }

    sess = upf_sess_find_by_ue_ip_address(recvbuf);
    if (!sess)
        goto cleanup;

    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        far = pdr->far;
        ogs_assert(far);

        /* Check if PDR is Downlink */
        if (pdr->src_if != OGS_PFCP_INTERFACE_CORE)
            continue;

        /* Save the Fallback PDR : Lowest precedence downlink PDR */
        fallback_pdr = pdr;

        /* Check if FAR is Downlink */
        if (far->dst_if != OGS_PFCP_INTERFACE_ACCESS)
            continue;

        /* Check if Outer header creation */
        if (far->outer_header_creation.ip4 == 0 &&
            far->outer_header_creation.ip6 == 0 &&
            far->outer_header_creation.udp4 == 0 &&
            far->outer_header_creation.udp6 == 0 &&
            far->outer_header_creation.gtpu4 == 0 &&
            far->outer_header_creation.gtpu6 == 0)
            continue;

        /* Check if Rule List in PDR */
        if (ogs_list_first(&pdr->rule_list) &&
            ogs_pfcp_pdr_rule_find_by_packet(pdr, recvbuf) == NULL)
            continue;

        break;
    }

    if (!pdr)
        pdr = fallback_pdr;

    if (!pdr) {
        if (ogs_global_conf()->parameter.multicast) {
            upf_gtp_handle_multicast(recvbuf);
        }
        goto cleanup;
    }

    /* Increment total & dl octets + pkts */
    for (i = 0; i < pdr->num_of_urr; i++)
        upf_sess_urr_acc_add(sess, pdr->urr[i], recvbuf->len, false);

    ogs_assert(true == ogs_pfcp_up_handle_pdr(
                pdr, OGS_GTPU_MSGTYPE_GPDU, NULL, recvbuf, &report));

    /*
     * Issue #2210, Discussion #2208, #2209
     *
     * Metrics reduce data plane performance.
     * It should not be used on the UPF/SGW-U data plane
     * until this issue is resolved.
     */
#if 0
    upf_metrics_inst_global_inc(UPF_METR_GLOB_CTR_GTP_OUTDATAPKTN3UPF);
    upf_metrics_inst_by_qfi_add(pdr->qer->qfi,
        UPF_METR_CTR_GTP_OUTDATAVOLUMEQOSLEVELN3UPF, recvbuf->len);
#endif

    if (report.type.downlink_data_report) {
        ogs_assert(pdr->sess);
        sess = UPF_SESS(pdr->sess);
        ogs_assert(sess);

        report.downlink_data.pdr_id = pdr->id;
        if (pdr->qer && pdr->qer->qfi)
            report.downlink_data.qfi = pdr->qer->qfi; /* for 5GC */

        ogs_assert(OGS_OK ==
            upf_pfcp_send_session_report_request(sess, &report));
    }

    /*
     * The ogs_pfcp_up_handle_pdr() function
     * buffers or frees the Packet Buffer(pkbuf) memory.
     */
    return;

cleanup:
    ogs_pkbuf_free(recvbuf);
}

static void _gtpv1_tun_recv_cb(short when, ogs_socket_t fd, void *data)
{
    _gtpv1_tun_recv_common_cb(when, fd, false, data);
}

static void _gtpv1_tun_recv_eth_cb(short when, ogs_socket_t fd, void *data)
{
    _gtpv1_tun_recv_common_cb(when, fd, true, data);
}

static void _gtpv1_u_recv_cb(short when, ogs_socket_t fd, void *data)
{
    int len;
    ssize_t size;
    char buf1[OGS_ADDRSTRLEN];
    char buf2[OGS_ADDRSTRLEN];

    upf_sess_t *sess = NULL;

    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sock_t *sock = NULL;
    ogs_sockaddr_t from;

    ogs_gtp2_header_t *gtp_h = NULL;
    ogs_gtp2_header_desc_t header_desc;
    ogs_pfcp_user_plane_report_t report;

    ogs_assert(fd != INVALID_SOCKET);
    sock = data;
    ogs_assert(sock);

    pkbuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
    ogs_pkbuf_put(pkbuf, OGS_MAX_PKT_LEN-OGS_TUN_MAX_HEADROOM);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ogs_recv() failed");
        goto cleanup;
    }

    ogs_pkbuf_trim(pkbuf, size);

    ogs_assert(pkbuf);
    ogs_assert(pkbuf->len);

    gtp_h = (ogs_gtp2_header_t *)pkbuf->data;
    if (gtp_h->version != OGS_GTP2_VERSION_1) {
        ogs_error("[DROP] Invalid GTPU version [%d]", gtp_h->version);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    len = ogs_gtpu_parse_header(&header_desc, pkbuf);
    if (len < 0) {
        ogs_error("[DROP] Cannot decode GTPU packet");
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }
    if (header_desc.type == OGS_GTPU_MSGTYPE_ECHO_REQ) {
        ogs_pkbuf_t *echo_rsp;

        ogs_debug("[RECV] Echo Request from [%s]", OGS_ADDR(&from, buf1));
        echo_rsp = ogs_gtp2_handle_echo_req(pkbuf);
        ogs_expect(echo_rsp);
        if (echo_rsp) {
            ssize_t sent;

            /* Echo reply */
            ogs_debug("[SEND] Echo Response to [%s]", OGS_ADDR(&from, buf1));

            sent = ogs_sendto(fd, echo_rsp->data, echo_rsp->len, 0, &from);
            if (sent < 0 || sent != echo_rsp->len) {
                ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                        "ogs_sendto() failed");
            }
            ogs_pkbuf_free(echo_rsp);
        }
        goto cleanup;
    }
    if (header_desc.type != OGS_GTPU_MSGTYPE_END_MARKER &&
        pkbuf->len <= len) {
        ogs_error("[DROP] Small GTPU packet(type:%d len:%d)",
                header_desc.type, len);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    ogs_trace("[RECV] GPU-U Type [%d] from [%s] : TEID[0x%x]",
            header_desc.type, OGS_ADDR(&from, buf1), header_desc.teid);

    /* Remove GTP header and send packets to TUN interface */
    ogs_assert(ogs_pkbuf_pull(pkbuf, len));

    if (header_desc.type == OGS_GTPU_MSGTYPE_END_MARKER) {
        /* Nothing */

    } else if (header_desc.type == OGS_GTPU_MSGTYPE_ERR_IND) {
        ogs_pfcp_far_t *far = NULL;

        far = ogs_pfcp_far_find_by_gtpu_error_indication(pkbuf);
        if (far) {
            ogs_assert(true ==
                ogs_pfcp_up_handle_error_indication(far, &report));

            if (report.type.error_indication_report) {
                ogs_assert(far->sess);
                sess = UPF_SESS(far->sess);
                ogs_assert(sess);

                ogs_assert(OGS_OK ==
                    upf_pfcp_send_session_report_request(sess, &report));
            }

        } else {
            ogs_error("[DROP] Cannot find FAR by Error-Indication");
            ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        }
    } else if (header_desc.type == OGS_GTPU_MSGTYPE_GPDU) {
        uint16_t eth_type = 0;
        struct ip *ip_h = NULL;
        uint32_t *src_addr = NULL;
        ogs_pfcp_object_t *pfcp_object = NULL;
        ogs_pfcp_sess_t *pfcp_sess = NULL;
        ogs_pfcp_pdr_t *pdr = NULL;
        ogs_pfcp_far_t *far = NULL;

        ogs_pfcp_subnet_t *subnet = NULL;
        ogs_pfcp_dev_t *dev = NULL;
        int i;

        ip_h = (struct ip *)pkbuf->data;
        ogs_assert(ip_h);

        /*
         * Issue #2210, Discussion #2208, #2209
         *
         * Metrics reduce data plane performance.
         * It should not be used on the UPF/SGW-U data plane
         * until this issue is resolved.
         */
#if 0
        upf_metrics_inst_global_inc(UPF_METR_GLOB_CTR_GTP_INDATAPKTN3UPF);
        upf_metrics_inst_by_qfi_add(header_desc.qos_flow_identifier,
                UPF_METR_CTR_GTP_INDATAVOLUMEQOSLEVELN3UPF, pkbuf->len);
#endif

        pfcp_object = ogs_pfcp_object_find_by_teid(header_desc.teid);
        if (!pfcp_object) {
            /*
             * TS23.527 Restoration procedures
             * 4.3 UPF Restoration Procedures
             * 4.3.2 Restoration Procedure for PSA UPF Restart
             *
             * The UPF shall not send GTP-U Error indication message
             * for a configurable period after an UPF restart
             * when the UPF receives a G-PDU not matching any PDRs.
             */
            if (ogs_time_ntp32_now() >
                   (ogs_pfcp_self()->local_recovery +
                    ogs_time_sec(ogs_local_conf()->time.message.pfcp.
                        association_interval))) {
                ogs_error("[%s] Send Error Indication [TEID:0x%x] to [%s]",
                        OGS_ADDR(&sock->local_addr, buf1),
                        header_desc.teid,
                        OGS_ADDR(&from, buf2));
                ogs_gtp1_send_error_indication(
                        sock, header_desc.teid,
                        header_desc.qos_flow_identifier, &from);
            }
            goto cleanup;
        }

        switch(pfcp_object->type) {
        case OGS_PFCP_OBJ_PDR_TYPE:
            /* UPF does not use PDR TYPE */
            ogs_assert_if_reached();
            pdr = (ogs_pfcp_pdr_t *)pfcp_object;
            ogs_assert(pdr);
            break;
        case OGS_PFCP_OBJ_SESS_TYPE:
            pfcp_sess = (ogs_pfcp_sess_t *)pfcp_object;
            ogs_assert(pfcp_sess);

            ogs_list_for_each(&pfcp_sess->pdr_list, pdr) {

                /* Check if Source Interface */
                if (pdr->src_if != OGS_PFCP_INTERFACE_ACCESS &&
                    pdr->src_if != OGS_PFCP_INTERFACE_CP_FUNCTION)
                    continue;

                /* Check if TEID */
                if (header_desc.teid != pdr->f_teid.teid)
                    continue;

                /* Check if QFI */
                if (pdr->qfi && pdr->qfi != header_desc.qos_flow_identifier)
                    continue;

                /* Check if Rule List in PDR */
                if (ogs_list_first(&pdr->rule_list)) {
                    if (upf_pdr_has_eth_rule(pdr)) {
                        /* Ethernet PDU-session UL PDR: the SDF rule is an L2 eth
                         * filter (is_eth), not an IP rule. ogs_pfcp_pdr_rule_
                         * find_by_packet() is IP-only and treats an Ethernet
                         * frame as "non-IP" → returns NULL → the frame would be
                         * dropped with a GTP-U Error Indication. Match the eth
                         * filter instead. UL (ACCESS): the filter is UL-canonical
                         * (dst-MAC = remote = the UL frame's dst) → no MAC swap. */
                        if (!upf_eth_pdr_matches(
                                pdr, pkbuf->data, pkbuf->len, false))
                            continue;
                    } else if (ogs_pfcp_pdr_rule_find_by_packet(
                                pdr, pkbuf) == NULL) {
                        continue;
                    }
                }

                break;
            }

            if (!pdr) {
                /*
                 * TS23.527 Restoration procedures
                 * 4.3 UPF Restoration Procedures
                 * 4.3.2 Restoration Procedure for PSA UPF Restart
                 *
                 * The UPF shall not send GTP-U Error indication message
                 * for a configurable period after an UPF restart
                 * when the UPF receives a G-PDU not matching any PDRs.
                 */
                if (ogs_time_ntp32_now() >
                       (ogs_pfcp_self()->local_recovery +
                        ogs_time_sec(ogs_local_conf()->time.message.pfcp.
                            association_interval))) {
                    ogs_error(
                            "[%s] Send Error Indication [TEID:0x%x] to [%s]",
                            OGS_ADDR(&sock->local_addr, buf1),
                            header_desc.teid,
                            OGS_ADDR(&from, buf2));
                    ogs_gtp1_send_error_indication(
                            sock, header_desc.teid,
                            header_desc.qos_flow_identifier, &from);
                }
                goto cleanup;
            }

            break;
        default:
            ogs_fatal("Unknown type [%d]", pfcp_object->type);
            ogs_assert_if_reached();
        }

        ogs_assert(pdr);
        ogs_assert(pdr->sess);
        ogs_assert(pdr->sess->obj.type == OGS_PFCP_OBJ_SESS_TYPE);

        sess = UPF_SESS(pdr->sess);
        ogs_assert(sess);

        far = pdr->far;
        ogs_assert(far);

        /* classify the uplink Ethernet frame (observability only).
         * Done here at the matched-PDR point, before the IP-centric forwarding
         * logic below — which does not apply to an Ethernet PDU session (no UE IP).
         * The inner payload is the UE's Ethernet frame (GTP-U header already
         * stripped). Gated on the Step-1 sess->correlation.ethernet flag. */
        if (sess->correlation.ethernet) {
            uint16_t inner_eth_type = _get_eth_type(pkbuf->data, pkbuf->len);
            upf_eth_class_t klass = (inner_eth_type == ETHERTYPE_GPTP)
                ? UPF_ETH_CLASS_GPTP : UPF_ETH_CLASS_HIT;
            /* NW-TT UL VID/PCP observability (validate the per-flow 802.1Q tag out). */
            uint16_t ul_vid = 0; uint8_t ul_pcp = 0;
            _get_vlan(pkbuf->data, pkbuf->len, &ul_vid, &ul_pcp);
            ogs_info("[UPF] Ethernet UL class[%s] ethertype[0x%04x] vid[%u] pcp[%u] QFI[%d] "
                     "SEID[0x%llx]", upf_eth_class_str(klass), inner_eth_type, ul_vid, ul_pcp,
                     pdr->qfi, (unsigned long long)sess->upf_n4_seid);
        }

        /* NW-TT bridge UL egress. For an Ethernet PDU session
         * the GTP-U payload is the UE's raw L2 frame (no UE IP). Learn the inner
         * source MAC for DL return traffic, then deliver the frame verbatim to
         * the N6 TAP bridge port. (TS 23.501 §5.6.10.2, §5.8.2.5.3.) */
        if (sess->correlation.ethernet) {
            ogs_pfcp_dev_t *eth_dev = upf_eth_bridge_dev();

            if (pkbuf->len >= 2 * UPF_MAC_ALEN) {
                /* learn_mac returns true only for genuinely new MACs (hash-deduped).
                 * Report each new MAC to the SMF so the AF gets the pinned MAC after
                 * pin_mac.py changes oaitap_ueN (TS 23.501 §5.28.1). */
                if (upf_sess_learn_mac(sess, pkbuf->data + UPF_MAC_ALEN))
                    upf_sess_report_learned_mac(sess, pkbuf->data + UPF_MAC_ALEN);
            }

            /* NW-TT 802.1Qbv gate enforcement (UL egress to N6). Note: the OAI UE
             * already discards wrong-PCP UL frames via its UL QoS rules, so this is a
             * redundant-but-spec-correct second check on the network side. */
            if (upf_nwtt_gate_blocks(sess, pkbuf, "UL"))
                goto cleanup;

            if (far->dst_if == OGS_PFCP_INTERFACE_CORE && eth_dev) {
                for (i = 0; i < pdr->num_of_urr; i++)
                    upf_sess_urr_acc_add(sess, pdr->urr[i], pkbuf->len, true);
                if (ogs_tun_write(eth_dev->fd, pkbuf) != OGS_OK)
                    ogs_warn("ogs_tun_write() (NW-TT UL) failed");
            } else {
                ogs_error("[DROP] Ethernet UL: no NW-TT TAP egress "
                          "(dst_if[%d])", far->dst_if);
            }
            goto cleanup;
        }

        if (ip_h->ip_v == 4 && sess->ipv4) {
            src_addr = (void *)&ip_h->ip_src.s_addr;
            ogs_assert(src_addr);

            /*
             * From Issue #1354
             *
             * Do not check Indirect Tunnel
             *    pdr->dst_if = OGS_PFCP_INTERFACE_ACCESS;
             *    far->dst_if = OGS_PFCP_INTERFACE_ACCESS;
             */
            if (far->dst_if != OGS_PFCP_INTERFACE_ACCESS) {

                if (src_addr[0] == sess->ipv4->addr[0]) {
                    /* Source IP address should be matched in uplink */
                } else if (check_framed_routes(sess, AF_INET, src_addr)) {
                    /* Or source IP address should match a framed route */
                } else {
                    ogs_error("[DROP] Source IP-%d Spoofing APN:%s SrcIf:%d DstIf:%d TEID:0x%x",
                                ip_h->ip_v, pdr->dnn, pdr->src_if, far->dst_if, header_desc.teid);
                    ogs_error("       SRC:%08X, UE:%08X",
                        be32toh(src_addr[0]), be32toh(sess->ipv4->addr[0]));
                    ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);

                    goto cleanup;
                }
            }

            subnet = sess->ipv4->subnet;
            eth_type = ETHERTYPE_IP;

        } else if (ip_h->ip_v == 6 && sess->ipv6) {
            struct ip6_hdr *ip6_h = (struct ip6_hdr *)pkbuf->data;
            ogs_assert(ip6_h);
            src_addr = (void *)ip6_h->ip6_src.s6_addr;
            ogs_assert(src_addr);

            /*
             * From Issue #1354
             *
             * Do not check Router Advertisement
             *    pdr->src_if = OGS_PFCP_INTERFACE_CP_FUNCTION;
             *    far->dst_if = OGS_PFCP_INTERFACE_ACCESS;
             *
             * Do not check Indirect Tunnel
             *    pdr->dst_if = OGS_PFCP_INTERFACE_ACCESS;
             *    far->dst_if = OGS_PFCP_INTERFACE_ACCESS;
             */
            if (far->dst_if != OGS_PFCP_INTERFACE_ACCESS) {

/*
 * Discussion #1776 was raised,
 * but we decided not to allow unspecified addresses
 * because Open5GS has already sent interface identifiers
 * in the registgration/attach process.
 *
 *
 * RFC4861
 * 4.  Message Formats
 * 4.1.  Router Solicitation Message Format
 * IP Fields:
 *    Source Address
 *                  An IP address assigned to the sending interface, or
 *                  the unspecified address if no address is assigned
 *                  to the sending interface.
 *
 * 6.1.  Message Validation
 * 6.1.1.  Validation of Router Solicitation Messages
 *  Hosts MUST silently discard any received Router Solicitation
 *  Messages.
 *
 *  A router MUST silently discard any received Router Solicitation
 *  messages that do not satisfy all of the following validity checks:
 *
 *  ..
 *  ..
 *
 *  - If the IP source address is the unspecified address, there is no
 *    source link-layer address option in the message.
 */
                if (IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)src_addr) &&
                    src_addr[2] == sess->ipv6->addr[2] &&
                    src_addr[3] == sess->ipv6->addr[3]) {
                    /*
                     * if Link-local address,
                     * Interface Identifier should be matched
                     */
                } else if (src_addr[0] == sess->ipv6->addr[0] &&
                            src_addr[1] == sess->ipv6->addr[1]) {
                    /*
                     * If Global address
                     * 64 bit prefix should be matched
                     */
                } else if (check_framed_routes(sess, AF_INET6, src_addr)) {
                    /* Or source IP address should match a framed route */
                } else {
                    ogs_error("[DROP] Source IP-%d Spoofing APN:%s SrcIf:%d DstIf:%d TEID:0x%x",
                                ip_h->ip_v, pdr->dnn, pdr->src_if, far->dst_if, header_desc.teid);
                    ogs_error("SRC:%08x %08x %08x %08x",
                            be32toh(src_addr[0]), be32toh(src_addr[1]),
                            be32toh(src_addr[2]), be32toh(src_addr[3]));
                    ogs_error("UE:%08x %08x %08x %08x",
                            be32toh(sess->ipv6->addr[0]),
                            be32toh(sess->ipv6->addr[1]),
                            be32toh(sess->ipv6->addr[2]),
                            be32toh(sess->ipv6->addr[3]));
                    ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);

                    goto cleanup;
                }
            }

            subnet = sess->ipv6->subnet;
            eth_type = ETHERTYPE_IPV6;

        } else {
            ogs_error("Invalid packet [IP version:%d, Packet Length:%d]",
                    ip_h->ip_v, pkbuf->len);
            ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
            goto cleanup;
        }

        if (far->dst_if == OGS_PFCP_INTERFACE_CORE) {

            if (!subnet) {
#if 0 /* It's redundant log message */
                ogs_error("[DROP] Cannot find subnet V:%d, IPv4:%p, IPv6:%p",
                        ip_h->ip_v, sess->ipv4, sess->ipv6);
                ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
#endif
                goto cleanup;
            }

            dev = subnet->dev;
            ogs_assert(dev);

            /* Increment total & ul octets + pkts */
            for (i = 0; i < pdr->num_of_urr; i++)
                upf_sess_urr_acc_add(sess, pdr->urr[i], pkbuf->len, true);

            if (dev->is_tap) {
                ogs_assert(eth_type);
                eth_type = htobe16(eth_type);
                ogs_pkbuf_push(pkbuf, sizeof(eth_type));
                memcpy(pkbuf->data, &eth_type, sizeof(eth_type));
                ogs_pkbuf_push(pkbuf, ETHER_ADDR_LEN);
                memcpy(pkbuf->data, proxy_mac_addr, ETHER_ADDR_LEN);
                ogs_pkbuf_push(pkbuf, ETHER_ADDR_LEN);
                memcpy(pkbuf->data, dev->mac_addr, ETHER_ADDR_LEN);
            }

            /* TODO: if destined to another UE, hairpin back out. */
            if (ogs_tun_write(dev->fd, pkbuf) != OGS_OK)
                ogs_warn("ogs_tun_write() failed");

        } else if (far->dst_if == OGS_PFCP_INTERFACE_ACCESS) {
            ogs_assert(true == ogs_pfcp_up_handle_pdr(
                        pdr, header_desc.type, &header_desc, pkbuf, &report));

            if (report.type.downlink_data_report) {
                ogs_error("Indirect Data Fowarding Buffered");

                report.downlink_data.pdr_id = pdr->id;
                if (pdr->qer && pdr->qer->qfi)
                    report.downlink_data.qfi = pdr->qer->qfi; /* for 5GC */

                ogs_assert(OGS_OK ==
                    upf_pfcp_send_session_report_request(sess, &report));
            }

            /*
             * The ogs_pfcp_up_handle_pdr() function
             * buffers or frees the Packet Buffer(pkbuf) memory.
             */
            return;

        } else if (far->dst_if == OGS_PFCP_INTERFACE_CP_FUNCTION) {

            if (!far->gnode) {
                ogs_error("No Outer Header Creation in FAR");
                goto cleanup;
            }

            if ((far->apply_action & OGS_PFCP_APPLY_ACTION_FORW) == 0) {
                ogs_error("Not supported Apply Action [0x%x]",
                            far->apply_action);
                goto cleanup;
            }

            ogs_assert(true == ogs_pfcp_up_handle_pdr(
                        pdr, header_desc.type, &header_desc, pkbuf, &report));

            ogs_assert(report.type.downlink_data_report == 0);

            /*
             * The ogs_pfcp_up_handle_pdr() function
             * buffers or frees the Packet Buffer(pkbuf) memory.
             */
            return;

        } else {
            ogs_fatal("Not implemented : FAR-DST_IF[%d]", far->dst_if);
            ogs_assert_if_reached();
        }
    } else {
        ogs_error("[DROP] Invalid GTPU Type [%d]", header_desc.type);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
    }

cleanup:
    ogs_pkbuf_free(pkbuf);
}

int upf_gtp_init(void)
{
    ogs_pkbuf_config_t config;
    memset(&config, 0, sizeof config);

    config.cluster_2048_pool = ogs_app()->pool.packet;

#if OGS_USE_TALLOC == 1
    /* allocate a talloc pool for GTP to ensure it doesn't have to go back
     * to the libc malloc all the time */
    packet_pool = talloc_pool(__ogs_talloc_core, 1000*1024);
    ogs_assert(packet_pool);
#else
    packet_pool = ogs_pkbuf_pool_create(&config);
#endif

    return OGS_OK;
}

void upf_gtp_final(void)
{
    ogs_pkbuf_pool_destroy(packet_pool);
}

static void _get_dev_mac_addr(char *ifname, uint8_t *mac_addr)
{
#ifdef SIOCGIFHWADDR
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    ogs_assert(fd);
    struct ifreq req;
    memset(&req, 0, sizeof(req));
    ogs_cpystrn(req.ifr_name, ifname, IF_NAMESIZE-1);
    ogs_assert(ioctl(fd, SIOCGIFHWADDR, &req) == 0);
    memcpy(mac_addr, req.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
#else
    struct ifaddrs *ifap;
    ogs_assert(getifaddrs(&ifap) == 0);
    struct ifaddrs *p;
    for (p = ifap; p; p = p->ifa_next) {
        if (strncmp(ifname, p->ifa_name, IF_NAMESIZE-1) == 0) {
            struct sockaddr_dl* sdp = (struct sockaddr_dl*) p->ifa_addr;
            memcpy(mac_addr, sdp->sdl_data + sdp->sdl_nlen, ETHER_ADDR_LEN);
            freeifaddrs(ifap);
            return;
        }
    }
    ogs_assert(0); /* interface not found. */
#endif
}

int upf_gtp_open(void)
{
    ogs_pfcp_dev_t *dev = NULL;
    ogs_pfcp_subnet_t *subnet = NULL;
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;
    int rc;

    ogs_list_for_each(&ogs_gtp_self()->gtpu_list, node) {
        sock = ogs_gtp_server(node);
        if (!sock) return OGS_ERROR;

        if (sock->family == AF_INET)
            ogs_gtp_self()->gtpu_sock = sock;
        else if (sock->family == AF_INET6)
            ogs_gtp_self()->gtpu_sock6 = sock;

        node->poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, _gtpv1_u_recv_cb, sock);
        ogs_assert(node->poll);
    }

    OGS_SETUP_GTPU_SERVER;

    /* NOTE : tun device can be created via following command.
     *
     * $ sudo ip tuntap add name ogstun mode tun
     *
     * Also, before running upf, assign the one IP from IP pool of UE
     * to ogstun. The IP should not be assigned to UE
     *
     * $ sudo ifconfig ogstun 45.45.0.1/16 up
     *
     */

    /* Open Tun interface */
    ogs_list_for_each(&ogs_pfcp_self()->dev_list, dev) {
        dev->is_tap = strstr(dev->ifname, "tap");
        dev->fd = ogs_tun_open(dev->ifname, OGS_MAX_IFNAME_LEN, dev->is_tap);
        if (dev->fd == INVALID_SOCKET) {
            ogs_error("tun_open(dev:%s) failed", dev->ifname);
            return OGS_ERROR;
        }

        if (dev->is_tap) {
            _get_dev_mac_addr(dev->ifname, dev->mac_addr);
            dev->poll = ogs_pollset_add(ogs_app()->pollset,
                    OGS_POLLIN, dev->fd, _gtpv1_tun_recv_eth_cb, NULL);
            ogs_assert(dev->poll);
        } else {
            dev->poll = ogs_pollset_add(ogs_app()->pollset,
                    OGS_POLLIN, dev->fd, _gtpv1_tun_recv_cb, NULL);
            ogs_assert(dev->poll);
        }

        ogs_assert(dev->poll);
    }

    /*
     * On Linux, it is possible to create a persistent tun/tap
     * interface which will continue to exist even if open5gs quit,
     * although this is normally not required.
     * It can be useful to set up a tun/tap interface owned
     * by a non-root user, so open5gs can be started without
     * needing any root privileges at all.
     */

    /* Set P-to-P IP address with Netmask
     * Note that Linux will skip this configuration */
    ogs_list_for_each(&ogs_pfcp_self()->subnet_list, subnet) {
        ogs_assert(subnet->dev);
        rc = ogs_tun_set_ip(subnet->dev->ifname, &subnet->gw, &subnet->sub);
        if (rc != OGS_OK) {
            ogs_error("ogs_tun_set_ip(dev:%s) failed", subnet->dev->ifname);
            return OGS_ERROR;
        }
    }

    return OGS_OK;
}

void upf_gtp_close(void)
{
    ogs_pfcp_dev_t *dev = NULL;

    ogs_socknode_remove_all(&ogs_gtp_self()->gtpu_list);

    ogs_list_for_each(&ogs_pfcp_self()->dev_list, dev) {
        if (dev->poll)
            ogs_pollset_remove(dev->poll);
        ogs_closesocket(dev->fd);
    }
}

static void upf_gtp_handle_multicast(ogs_pkbuf_t *recvbuf)
{
    struct ip *ip_h =  NULL;
    struct ip6_hdr *ip6_h = NULL;
    ogs_pfcp_user_plane_report_t report;

    ip_h = (struct ip *)recvbuf->data;
    if (ip_h->ip_v == 6) {
#if COMPILE_ERROR_IN_MAC_OS_X  /* Compiler error in Mac OS X platform */
        ip6_h = (struct ip6_hdr *)recvbuf->data;
        if (IN6_IS_ADDR_MULTICAST(&ip6_h->ip6_dst))
#else
        struct in6_addr ip6_dst;
        ip6_h = (struct ip6_hdr *)recvbuf->data;
        memcpy(&ip6_dst, &ip6_h->ip6_dst, sizeof(struct in6_addr));
        if (IN6_IS_ADDR_MULTICAST(&ip6_dst))
#endif
        {
            upf_sess_t *sess = NULL;

            /* IPv6 Multicast */
            ogs_list_for_each(&upf_self()->sess_list, sess) {
                if (sess->ipv6) {
                    /* PDN IPv6 is available */
                    ogs_pfcp_pdr_t *pdr = NULL;

                    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
                        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) {
                            ogs_pkbuf_t *sendbuf = ogs_pkbuf_copy(recvbuf);
                            ogs_assert(sendbuf);
                            ogs_assert(true ==
                                ogs_pfcp_up_handle_pdr(
                                    pdr, OGS_GTPU_MSGTYPE_GPDU,
                                    NULL, sendbuf, &report));
                            break;
                        }
                    }

                    return;
                }
            }
        }
    }
}
