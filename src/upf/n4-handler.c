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
#include "pfcp-path.h"
#include "gtp-path.h"
#include "n4-handler.h"

#define NWTT_GCL_MAX_ENTRIES 64
#define NWTT_TAP_IFACE       "ogstapeth"

typedef struct {
    uint8_t  gate_states;
    uint32_t dur_ns;
} upf_gcl_entry_t;

typedef struct {
    bool     gate_enabled;
    uint64_t base_ns;
    uint64_t cycle_ns;
    int      n;
    upf_gcl_entry_t entries[NWTT_GCL_MAX_ENTRIES];
} upf_gcl_t;

/* Minimal base64 decoder (the UPF does not link ogs-crypt). Returns decoded length. */
static int upf_b64_decode(const char *in, uint8_t *out, int outcap)
{
    int n = 0, bits = 0, acc = 0, v;
    for (; in && *in; in++) {
        char c = *in;
        if (c >= 'A' && c <= 'Z')      v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+')             v = 62;
        else if (c == '/')             v = 63;
        else                           continue; /* '=' padding / whitespace */
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n < outcap)
                out[n++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return n;
}

/* Parse the NW-TT PMIC (TS 24.539 MANAGE PORT COMMAND, base64-encoded as carried over
 * N5/N4) into the 802.1Qbv gate's allowed-PCP set: the OR of every AdminControlList
 * entry's GateStatesValue bitmap (bit p set => PCP p is gated open). Returns 0 on any
 * parse failure so the data path fails open (enforces nothing). */
static uint8_t upf_pmic_parse_gate_pcp_mask(const void *b64)
{
    uint8_t raw[512], mask = 0;
    int n, i, end;
    uint16_t list_len, name, vlen, j;

    if (!b64)
        return 0;
    n = upf_b64_decode((const char *)b64, raw, sizeof(raw));
    /* MANAGE PORT COMMAND: msg_type(1)=0x01 | port-management-list length(2) | operations. */
    if (n < 3 || raw[0] != 0x01)
        return 0;
    list_len = (raw[1] << 8) | raw[2];
    i = 3;
    end = (3 + (int)list_len <= n) ? 3 + (int)list_len : n;
    /* Set-parameter op: op-code(1) | port-parameter name(2) | value-length(2) | value. */
    while (i + 5 <= end) {
        name = (raw[i + 1] << 8) | raw[i + 2];
        vlen = (raw[i + 3] << 8) | raw[i + 4];
        if (i + 5 + (int)vlen > end)
            break;
        /* AdminControlList (0x0006): entries of [gate-op(1), GateStatesValue(1), time(4)]. */
        if (name == 0x0006)
            for (j = 0; j + 6 <= vlen; j += 6)
                mask |= raw[i + 5 + j + 1];
        i += 5 + vlen;
    }
    return mask;
}

/* Parse the full GCL from the PMIC into gcl_out. Returns true on success. */
static bool upf_pmic_parse_gcl(const void *b64, upf_gcl_t *gcl_out)
{
    uint8_t raw[512];
    int n, i, end;
    uint16_t list_len, name, vlen, j;

    memset(gcl_out, 0, sizeof(*gcl_out));
    if (!b64)
        return false;
    n = upf_b64_decode((const char *)b64, raw, sizeof(raw));
    if (n < 3 || raw[0] != 0x01)
        return false;

    list_len = ((uint16_t)raw[1] << 8) | raw[2];
    i = 3;
    end = (3 + (int)list_len <= n) ? 3 + (int)list_len : n;

    while (i + 5 <= end) {
        name = ((uint16_t)raw[i + 1] << 8) | raw[i + 2];
        vlen = ((uint16_t)raw[i + 3] << 8) | raw[i + 4];
        if (i + 5 + (int)vlen > end)
            break;
        const uint8_t *v = &raw[i + 5];

        if (name == 0x0003 && vlen >= 1) {
            gcl_out->gate_enabled = (v[0] & 0x01) != 0;

        } else if (name == 0x0004 && vlen >= 10) {
            /* ADMIN_BASE_TIME: 6-octet secs + 4-octet nanos */
            uint64_t secs = 0;
            for (int k = 0; k < 6; k++) secs = (secs << 8) | v[k];
            uint32_t nanos = ((uint32_t)v[6] << 24) | ((uint32_t)v[7] << 16) |
                             ((uint32_t)v[8] << 8)  |  (uint32_t)v[9];
            gcl_out->base_ns = secs * 1000000000ULL + nanos;

        } else if (name == 0x0007 && vlen >= 8) {
            /* ADMIN_CYCLE_TIME: num/den; den=1e9 => cycle_ns=num */
            uint32_t num = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) |
                           ((uint32_t)v[2] << 8)  |  (uint32_t)v[3];
            uint32_t den = ((uint32_t)v[4] << 24) | ((uint32_t)v[5] << 16) |
                           ((uint32_t)v[6] << 8)  |  (uint32_t)v[7];
            gcl_out->cycle_ns = (den > 0) ? ((uint64_t)num * 1000000000ULL / den) : num;

        } else if (name == 0x0006) {
            /* ADMIN_CONTROL_LIST: [gate-op(1), GateStates(1), TimeInterval(4)] */
            for (j = 0; j + 6 <= vlen && gcl_out->n < NWTT_GCL_MAX_ENTRIES; j += 6) {
                gcl_out->entries[gcl_out->n].gate_states = v[j + 1];
                gcl_out->entries[gcl_out->n].dur_ns =
                    ((uint32_t)v[j + 2] << 24) | ((uint32_t)v[j + 3] << 16) |
                    ((uint32_t)v[j + 4] << 8)  |  (uint32_t)v[j + 5];
                gcl_out->n++;
            }
        }
        i += 5 + vlen;
    }
    return gcl_out->cycle_ns > 0 && gcl_out->n > 0;
}

/* Program tc taprio + clsact/flower classifier on the NW-TT egress TAP.
 * The TAP is created with IFF_MULTI_QUEUE (see ogs_tun_open), which is
 * sufficient for taprio: netif_is_multiqueue() checks the device's allocated
 * queue count, not the number of attached fds, so no extra fds are needed. */
static void nwtt_program_taprio(const upf_gcl_t *gcl)
{
    char cmd[2048];
    int pos;

    if (!gcl->gate_enabled || gcl->cycle_ns == 0 || gcl->n == 0)
        return;

    /* clsact (idempotent: delete then add) */
    snprintf(cmd, sizeof(cmd),
             "/usr/sbin/tc qdisc del dev %s clsact 2>/dev/null; "
             "/usr/sbin/tc qdisc add dev %s clsact",
             NWTT_TAP_IFACE, NWTT_TAP_IFACE);
    if (system(cmd) != 0) {
        ogs_warn("[UPF] NW-TT taprio: clsact add failed on %s; staying on C2(a)", NWTT_TAP_IFACE);
        return;
    }

    /* egress flower PCP→TC classifier */
    for (int pcp = 0; pcp < 8; pcp++) {
        snprintf(cmd, sizeof(cmd),
                 "/usr/sbin/tc filter add dev %s egress protocol 802.1Q "
                 "flower vlan_prio %d action skbedit priority %d",
                 NWTT_TAP_IFACE, pcp, pcp);
        system(cmd);
    }

    /* taprio qdisc — testbed: num_tc 1 maps every priority to TC0 / queue 0.
     * The TAP has a single reader fd (real_num_tx_queues == 1), so all egress
     * already lands on queue 0 — no scatter to unread queues.  Per-TC gating
     * needs a real NIC; this proves decode + install only. */
    pos = snprintf(cmd, sizeof(cmd),
        "/usr/sbin/tc qdisc replace dev %s root taprio"
        " num_tc 1 map 0 0 0 0 0 0 0 0"
        " queues 1@0"
        " base-time %llu"
        " clockid CLOCK_TAI flags 0",
        NWTT_TAP_IFACE, (unsigned long long)gcl->base_ns);

    for (int e = 0; e < gcl->n && pos < (int)sizeof(cmd) - 64; e++) {
        uint8_t gs1 = gcl->entries[e].gate_states ? 0x01 : 0x00;
        pos += snprintf(cmd + pos, sizeof(cmd) - pos,
                        " sched-entry S 0x%02x %u",
                        gs1, gcl->entries[e].dur_ns);
    }

    if (system(cmd) != 0) {
        ogs_warn("[UPF] NW-TT taprio: qdisc replace failed on %s; staying on C2(a)",
                 NWTT_TAP_IFACE);
        /* Drop the clsact classifier so we are fully back to C2(a). */
        snprintf(cmd, sizeof(cmd), "/usr/sbin/tc qdisc del dev %s clsact 2>/dev/null", NWTT_TAP_IFACE);
        system(cmd);
        return;
    }

    ogs_info("[UPF] NW-TT taprio programmed on %s: cycle=%lluns base=%lluns entries=%d",
             NWTT_TAP_IFACE,
             (unsigned long long)gcl->cycle_ns,
             (unsigned long long)gcl->base_ns,
             gcl->n);
}

static void upf_n4_handle_create_urr(upf_sess_t *sess, ogs_pfcp_tlv_create_urr_t *create_urr_arr,
                              uint8_t *cause_value, uint8_t *offending_ie_value)
{
    int i;
    ogs_pfcp_urr_t *urr;

    *cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    for (i = 0; i < OGS_MAX_NUM_OF_URR; i++) {
        urr = ogs_pfcp_handle_create_urr(&sess->pfcp, &create_urr_arr[i],
                    cause_value, offending_ie_value);
        if (!urr)
            return;

        /* TODO: enable counters somewhere else if ISTM not set, upon first pkt received */
        if (urr->meas_info.istm) {
            upf_sess_urr_acc_timers_setup(sess, urr);
        }
    }
}

void upf_n4_handle_session_establishment_request(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_establishment_request_t *req)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_pdr_t *created_pdr[OGS_MAX_NUM_OF_PDR];
    int num_of_created_pdr = 0;
    uint8_t cause_value = 0;
    uint8_t offending_ie_value = 0;
    int i;

    ogs_pfcp_sereq_flags_t sereq_flags;
    bool restoration_indication = false;

    upf_metrics_inst_global_inc(UPF_METR_GLOB_CTR_SM_N4SESSIONESTABREQ);

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Establishment Request");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_MANDATORY_IE_MISSING, 0);
        upf_metrics_inst_by_cause_add(OGS_PFCP_CAUSE_MANDATORY_IE_MISSING,
                UPF_METR_CTR_SM_N4SESSIONESTABFAIL, 1);
        return;
    }

    memset(&sereq_flags, 0, sizeof(sereq_flags));
    if (req->pfcpsereq_flags.presence == 1)
        sereq_flags.value = req->pfcpsereq_flags.u8;

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        created_pdr[i] = ogs_pfcp_handle_create_pdr(&sess->pfcp,
                &req->create_pdr[i], &sereq_flags,
                &cause_value, &offending_ie_value);
        if (created_pdr[i] == NULL)
            break;
    }
    num_of_created_pdr = i;
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (ogs_pfcp_handle_create_far(&sess->pfcp, &req->create_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    upf_n4_handle_create_urr(sess, &req->create_urr[0], &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    if (req->apn_dnn.presence) {
        char apn_dnn[OGS_MAX_DNN_LEN+1];

        if (ogs_fqdn_parse(apn_dnn, req->apn_dnn.data,
            ogs_min(req->apn_dnn.len, OGS_MAX_DNN_LEN)) <= 0) {
            ogs_error("Invalid APN");
            cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            goto cleanup;
        }

        if (sess->apn_dnn)
            ogs_free(sess->apn_dnn);
        sess->apn_dnn = ogs_strdup(apn_dnn);
        ogs_assert(sess->apn_dnn);
    }

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (ogs_pfcp_handle_create_qer(&sess->pfcp, &req->create_qer[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
        upf_metrics_inst_by_dnn_add(sess->apn_dnn,
                UPF_METR_GAUGE_UPF_QOSFLOWS, 1);
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    ogs_pfcp_handle_create_bar(&sess->pfcp, &req->create_bar,
                &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Setup GTP Node */
    ogs_list_for_each(&sess->pfcp.far_list, far) {
        if (OGS_ERROR == ogs_pfcp_setup_far_gtpu_node(far)) {
            ogs_fatal("CHECK CONFIGURATION: upf.gtpu");
            ogs_fatal("ogs_pfcp_setup_far_gtpu_node() failed");
            goto cleanup;
        }
        if (far->gnode)
            ogs_pfcp_far_f_teid_hash_set(far);
    }

    /* PFCPSEReq-Flags */
    if (sereq_flags.restoration_indication == 1) {
        for (i = 0; i < num_of_created_pdr; i++) {
            pdr = created_pdr[i];
            ogs_assert(pdr);

    /*
     * Only perform TEID restoration via swap when F-TEID.ch is false.
     *
     * When F-TEID.ch is false, it means the TEID has already been assigned, and
     * the restoration process can safely perform the swap.
     *
     * If F-TEID.ch is true, it indicates that the UPF needs to assign
     * a new TEID for the first time, so performing a swap is not appropriate
     * in this case.
     */
            if (pdr->f_teid_len > 0 && pdr->f_teid.ch == false) {
                cause_value = ogs_pfcp_pdr_swap_teid(pdr);
                if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
                    goto cleanup;
            }
        }
        restoration_indication = true;
    }

    for (i = 0; i < num_of_created_pdr; i++) {
        pdr = created_pdr[i];
        ogs_assert(pdr);

        /* Setup UE IP address */
        if (pdr->ue_ip_addr_len) {
            if (req->pdn_type.presence == 1) {
                cause_value = upf_sess_set_ue_ip(sess, req->pdn_type.u8, pdr);
                if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
                    goto cleanup;
            } else {
                ogs_error("No PDN Type");
            }
        }

        if (pdr->ipv4_framed_routes) {
            cause_value =
                upf_sess_set_ue_ipv4_framed_routes(sess,
                        pdr->ipv4_framed_routes);
            if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
                goto cleanup;
        }

        if (pdr->ipv6_framed_routes) {
            cause_value =
                upf_sess_set_ue_ipv6_framed_routes(sess,
                        pdr->ipv6_framed_routes);
            if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
                goto cleanup;
        }

        /* Setup UPF-N3-TEID & QFI Hash */
        if (pdr->f_teid_len)
            ogs_pfcp_object_teid_hash_set(
                    OGS_PFCP_OBJ_SESS_TYPE, pdr, restoration_indication);
    }

    /* record the PDU session type as UPF-local correlation
     * state (logs creation for an Ethernet PDU session). Done independently of
     * the UE-IP block above, since an Ethernet session carries no UE IP. */
    if (req->pdn_type.presence == 1)
        upf_sess_set_correlation(sess, req->pdn_type.u8);

    /* the SMF requests creation of this session's 5GS-TSN-bridge
     * port via the standard PFCP create_bridge_info_for_tsc IE (TS 29.244). Assign
     * a DS-TT port number; it is returned in created_bridge_info_for_tsc in the
     * establishment response (see upf_n4_build_session_establishment_response). */
    if (req->create_bridge_info_for_tsc.presence) {
        sess->nwtt.bridge = true;
        sess->nwtt.ds_tt_port_number = upf_sess_assign_dstt_port();
        ogs_info("[UPF] NW-TT bridge port created: DS-TT port[%u] (SMF-SEID[0x%llx])",
                 sess->nwtt.ds_tt_port_number,
                 (unsigned long long)sess->smf_n4_f_seid.seid);
    }

    /* Send Buffered Packet to gNB/SGW */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) { /* Downlink */
            ogs_pfcp_send_buffered_packet(pdr);
        }
    }

    if (restoration_indication == true ||
        ogs_pfcp_self()->up_function_features.ftup == 0)
        ogs_assert(OGS_OK ==
            upf_pfcp_send_session_establishment_response(
                xact, sess, NULL, 0));
    else
        ogs_assert(OGS_OK ==
            upf_pfcp_send_session_establishment_response(
                xact, sess, created_pdr, num_of_created_pdr));

    return;

cleanup:
    upf_metrics_inst_by_cause_add(cause_value,
            UPF_METR_CTR_SM_N4SESSIONESTABFAIL, 1);
    ogs_pfcp_sess_clear(&sess->pfcp);
    ogs_pfcp_send_error_message(xact, sess ? sess->smf_n4_f_seid.seid : 0,
            OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
            cause_value, offending_ie_value);
}

void upf_n4_handle_session_modification_request(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_modification_request_t *req)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_pdr_t *created_pdr[OGS_MAX_NUM_OF_PDR];
    int num_of_created_pdr = 0;
    uint8_t cause_value = 0;
    uint8_t offending_ie_value = 0;
    int i;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Modification Request");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    /* the SMF carries the NW-TT Port Management Information
     * Container (PMIC = the CNC's PSFP stream filter/gate tables) inside the
     * standard PFCP tsc_management_information IE (TS 29.244). Record receipt;
     * parsing/enforcing the PSFP tables is deferred to a later step. */
    if (req->tsc_management_information.presence) {
        ogs_pfcp_tlv_port_management_information_container_t *pmic =
            &req->tsc_management_information.port_management_information_container;
        if (pmic->presence) {
            /* program the NW-TT port — store the PMIC managed
             * object (PSFP stream filter + gate-control list). Best-effort:
             * the blob is retained on the port for the data-path to consult;
             * hard gate enforcement is a later refinement. */
            sess->nwtt.pmic_present = true;
            sess->nwtt.pmic_len = pmic->len;
            if (sess->nwtt.pmic)
                ogs_free(sess->nwtt.pmic);
            sess->nwtt.pmic = ogs_calloc(1, pmic->len + 1);
            if (sess->nwtt.pmic && pmic->data)
                memcpy(sess->nwtt.pmic, pmic->data, pmic->len);
            /* C2(a): allowed-PCP set for the data-path gate. */
            sess->nwtt.gate_pcp_mask =
                upf_pmic_parse_gate_pcp_mask(sess->nwtt.pmic);
            ogs_info("[UPF] NW-TT PMIC applied: %u octets, gate PCP mask[0x%02x], "
                     "NW-TT port[%u] (DS-TT port[%u])", pmic->len,
                     sess->nwtt.gate_pcp_mask,
                     req->tsc_management_information.nw_tt_port_number.presence ?
                        be32toh(*(uint32_t *)req->tsc_management_information.
                            nw_tt_port_number.data) : 0,
                     sess->nwtt.ds_tt_port_number);

            /* C2(b): decode the full GCL and program taprio on the NW-TT egress. */
            upf_gcl_t gcl;
            if (upf_pmic_parse_gcl(sess->nwtt.pmic, &gcl)) {
                ogs_info("[UPF] NW-TT GCL decoded: cycle=%lluns base=%lluns entries=%d",
                         (unsigned long long)gcl.cycle_ns,
                         (unsigned long long)gcl.base_ns, gcl.n);
                nwtt_program_taprio(&gcl);
            } else {
                ogs_warn("[UPF] NW-TT: GCL decode failed; only C2(a) active");
            }
        }
    }

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        created_pdr[i] = ogs_pfcp_handle_create_pdr(&sess->pfcp,
                &req->create_pdr[i], NULL, &cause_value, &offending_ie_value);
        if (created_pdr[i] == NULL)
            break;
    }
    num_of_created_pdr = i;
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        if (ogs_pfcp_handle_update_pdr(&sess->pfcp, &req->update_pdr[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        if (ogs_pfcp_handle_remove_pdr(&sess->pfcp, &req->remove_pdr[i],
                &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (ogs_pfcp_handle_create_far(&sess->pfcp, &req->create_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (ogs_pfcp_handle_update_far_flags(&sess->pfcp, &req->update_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Send End Marker to gNB */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) { /* Downlink */
            far = pdr->far;
            if (far && far->smreq_flags.send_end_marker_packets)
                ogs_assert(OGS_ERROR != ogs_pfcp_send_end_marker(pdr));
        }
    }
    /* Clear PFCPSMReq-Flags */
    ogs_list_for_each(&sess->pfcp.far_list, far)
        far->smreq_flags.value = 0;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (ogs_pfcp_handle_update_far(&sess->pfcp, &req->update_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (ogs_pfcp_handle_remove_far(&sess->pfcp, &req->remove_far[i],
                &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    upf_n4_handle_create_urr(sess, &req->create_urr[0], &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_URR; i++) {
        if (ogs_pfcp_handle_update_urr(&sess->pfcp, &req->update_urr[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_URR; i++) {
        if (ogs_pfcp_handle_remove_urr(&sess->pfcp, &req->remove_urr[i],
                &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (ogs_pfcp_handle_create_qer(&sess->pfcp, &req->create_qer[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
        upf_metrics_inst_by_dnn_add(sess->apn_dnn,
                UPF_METR_GAUGE_UPF_QOSFLOWS, 1);
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (ogs_pfcp_handle_update_qer(&sess->pfcp, &req->update_qer[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (ogs_pfcp_handle_remove_qer(&sess->pfcp, &req->remove_qer[i],
                &cause_value, &offending_ie_value) == false)
            break;
        upf_metrics_inst_by_dnn_add(sess->apn_dnn,
                UPF_METR_GAUGE_UPF_QOSFLOWS, -1);
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    ogs_pfcp_handle_create_bar(&sess->pfcp, &req->create_bar,
                &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    ogs_pfcp_handle_remove_bar(&sess->pfcp, &req->remove_bar,
            &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Setup GTP Node */
    ogs_list_for_each(&sess->pfcp.far_list, far) {
        if (OGS_ERROR == ogs_pfcp_setup_far_gtpu_node(far)) {
            ogs_fatal("CHECK CONFIGURATION: upf.gtpu");
            ogs_fatal("ogs_pfcp_setup_far_gtpu_node() failed");
            goto cleanup;
        }
        if (far->gnode)
            ogs_pfcp_far_f_teid_hash_set(far);
    }

    for (i = 0; i < num_of_created_pdr; i++) {
        pdr = created_pdr[i];
        ogs_assert(pdr);

        /* Setup UPF-N3-TEID & QFI Hash */
        if (pdr->f_teid_len)
            ogs_pfcp_object_teid_hash_set(OGS_PFCP_OBJ_SESS_TYPE, pdr, false);
    }

    /* Send Buffered Packet to gNB/SGW */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) { /* Downlink */
            ogs_pfcp_send_buffered_packet(pdr);
        }
    }

    if (ogs_pfcp_self()->up_function_features.ftup == 0)
        ogs_assert(OGS_OK ==
            upf_pfcp_send_session_modification_response(
                xact, sess, NULL, 0));
    else
        ogs_assert(OGS_OK ==
            upf_pfcp_send_session_modification_response(
                xact, sess, created_pdr, num_of_created_pdr));
    return;

cleanup:
    ogs_pfcp_sess_clear(&sess->pfcp);
    ogs_pfcp_send_error_message(xact, sess ? sess->smf_n4_f_seid.seid : 0,
            OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE,
            cause_value, offending_ie_value);
}

void upf_n4_handle_session_deletion_request(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_deletion_request_t *req)
{
    ogs_pfcp_qer_t *qer = NULL;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Deletion Request");

    if (!sess) {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_DELETION_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }
    upf_pfcp_send_session_deletion_response(xact, sess);

    ogs_list_for_each(&sess->pfcp.qer_list, qer) {
        upf_metrics_inst_by_dnn_add(sess->apn_dnn,
                UPF_METR_GAUGE_UPF_QOSFLOWS, -1);
    }
    upf_sess_remove(sess);
}

void upf_n4_handle_session_report_response(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_report_response_t *rsp)
{
    uint8_t cause_value = 0;

    ogs_assert(xact);
    ogs_assert(rsp);

    ogs_pfcp_xact_commit(xact);

    ogs_debug("Session Report Response");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        cause_value = OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
    }

    if (rsp->cause.presence) {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_error("PFCP Cause[%d] : Not Accepted", rsp->cause.u8);
            cause_value = rsp->cause.u8;
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("Cause request not accepted[%d]", cause_value);
        return;
    } else {
        upf_metrics_inst_global_inc(UPF_METR_GLOB_CTR_SM_N4SESSIONREPORTSUCC);
    }

}
