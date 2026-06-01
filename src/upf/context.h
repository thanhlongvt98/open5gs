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

#ifndef UPF_CONTEXT_H
#define UPF_CONTEXT_H

#include "upf-config.h"

#if HAVE_NET_IF_H
#include <net/if.h>
#endif

#include "ogs-gtp.h"
#include "ogs-pfcp.h"
#include "ogs-app.h"

#include "ipfw/ogs-ipfw.h"

#include "timer.h"
#include "upf-sm.h"
#include "metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __upf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __upf_log_domain

struct upf_route_trie_node;

typedef struct upf_context_s {
    ogs_hash_t *upf_n4_seid_hash;   /* hash table (UPF-N4-SEID) */
    ogs_hash_t *smf_n4_seid_hash;   /* hash table (SMF-N4-SEID) */
    ogs_hash_t *smf_n4_f_seid_hash; /* hash table (SMF-N4-F-SEID) */
    ogs_hash_t *ipv4_hash;  /* hash table (IPv4 Address) */
    ogs_hash_t *ipv6_hash;  /* hash table (IPv6 Address) */
    ogs_hash_t *mac_hash;   /* hash table (learned dst-MAC -> Ethernet sess) */

    /* IPv4 framed routes trie */
    struct upf_route_trie_node *ipv4_framed_routes;
    /* IPv6 framed routes trie */
    struct upf_route_trie_node *ipv6_framed_routes;

    ogs_list_t sess_list;
} upf_context_t;

/* trie mapping from IP framed routes to session. */
struct upf_route_trie_node {
    struct upf_route_trie_node *left;
    struct upf_route_trie_node *right;
    upf_sess_t *sess;
};

#define UPF_MAC_ALEN 6

/* A learned source MAC for an Ethernet PDU session. The mac[] field backs the
 * key stored in upf_self()->mac_hash (the hash keeps the pointer, not a copy). */
typedef struct upf_sess_mac_s {
    ogs_lnode_t lnode;
    uint8_t     mac[UPF_MAC_ALEN];
} upf_sess_mac_t;

/* Accounting: */
typedef struct upf_sess_urr_acc_s {
    bool reporting_enabled;
    ogs_timer_t *t_validity_time; /* Quota Validity Time expiration handler */
    ogs_timer_t *t_time_quota; /* Time Quota expiration handler */
    ogs_timer_t *t_time_threshold; /* Time Threshold expiration handler */
    uint32_t time_start; /* When t_time_* started */
    ogs_pfcp_urr_ur_seqn_t report_seqn; /* Next seqn to use when reporting */
    uint64_t total_octets;
    uint64_t ul_octets;
    uint64_t dl_octets;
    uint64_t total_pkts;
    uint64_t ul_pkts;
    uint64_t dl_pkts;
    ogs_time_t time_of_first_packet;
    ogs_time_t time_of_last_packet;
    /* Snapshot of measurement when last report was sent: */
    struct {
        uint64_t total_octets;
        uint64_t ul_octets;
        uint64_t dl_octets;
        uint64_t total_pkts;
        uint64_t ul_pkts;
        uint64_t dl_pkts;
        ogs_time_t timestamp;
    } last_report;
} upf_sess_urr_acc_t;

#define UPF_SESS(pfcp_sess) ogs_container_of(pfcp_sess, upf_sess_t, pfcp)
typedef struct upf_sess_s {
    ogs_lnode_t     lnode;
    ogs_pool_id_t   id;
    ogs_pool_id_t   *upf_n4_seid_node;  /* A node of UPF-N4-SEID */

    ogs_pfcp_sess_t pfcp;

    uint64_t        upf_n4_seid;        /* UPF SEID is derived from NODE */
    struct {
        uint64_t    seid;
        ogs_ip_t    ip;
    } smf_n4_f_seid;                    /* SMF SEID is received from Peer */

    /* APN Configuration */
    ogs_pfcp_ue_ip_t *ipv4;
    ogs_pfcp_ue_ip_t *ipv6;

    ogs_ipsubnet_t   *ipv4_framed_routes;
    ogs_ipsubnet_t   *ipv6_framed_routes;

    char            *gx_sid;            /* Gx Session ID */
    ogs_pfcp_node_t *pfcp_node;

    /* Accounting: */
    upf_sess_urr_acc_t urr_acc[OGS_MAX_NUM_OF_URR]; /* FIXME: This probably needs to be mved to a hashtable or alike */
    char            *apn_dnn;            /* APN/DNN Item */

    /* UPF-local Ethernet PDU session correlation state (Phase 5 Step 1).
     * SMF owns session/QoS intent; this is a UPF-local cache for NW-TT
     * observability (Step 5) and Ethernet fast-path classification (Step 2).
     * Deliberately NOT placed in the shared lib/pfcp (Issue 5-A). */
    struct {
        bool    ethernet;      /* session_type == OGS_PDU_SESSION_TYPE_ETHERNET */
        uint8_t session_type;  /* OGS_PDU_SESSION_TYPE_* seen at N4 establishment */
    } correlation;

    /* NW-TT MAC-learning bridge (Phase 5 Step 4): the inner source MACs learned
     * from UL frames on this Ethernet PDU session. Each entry's mac[] backs a
     * key in upf_self()->mac_hash; the list lets us evict them on session
     * removal. TS 23.501 §5.8.2.5.3 / §5.6.10.2. */
    ogs_list_t      mac_list;

    /* NW-TT bridge-port state from the standard PFCP TSC IEs (Phase 5 Step 3).
     * Populated only when the SMF sends create_bridge_info_for_tsc / a PMIC over
     * N4 (TS 29.244). UPF-local (Issue 5-A); the shared lib/pfcp is unchanged. */
    struct {
        bool     bridge;             /* create_bridge_info_for_tsc was received */
        uint32_t ds_tt_port_number;  /* assigned per PDU session (this DS-TT port) */
        bool     pmic_present;       /* a PMIC (PSFP tables) has been received */
        uint32_t pmic_len;           /* length of the last PMIC (octets) */
        void    *pmic;               /* 202606 Step 08: programmed PMIC blob   */
    } nwtt;
} upf_sess_t;

void upf_context_init(void);
void upf_context_final(void);
upf_context_t *upf_self(void);

int upf_context_parse_config(void);

upf_sess_t *upf_sess_add_by_message(ogs_pfcp_message_t *message);

upf_sess_t *upf_sess_add(ogs_pfcp_f_seid_t *f_seid);
int upf_sess_remove(upf_sess_t *sess);
void upf_sess_remove_all(void);
upf_sess_t *upf_sess_find_by_smf_n4_seid(uint64_t seid);
upf_sess_t *upf_sess_find_by_smf_n4_f_seid(ogs_pfcp_f_seid_t *f_seid);
upf_sess_t *upf_sess_find_by_upf_n4_seid(uint64_t seid);
upf_sess_t *upf_sess_find_by_ipv4(uint32_t addr);
upf_sess_t *upf_sess_find_by_ipv6(uint32_t *addr6);
/* Phase 5 Step 4: NW-TT MAC-learning bridge for Ethernet PDU sessions.
 * upf_sess_learn_mac() records an inner source MAC seen on UL; the matching
 * upf_sess_find_by_mac() resolves a DL frame's destination MAC to its session. */
void upf_sess_learn_mac(upf_sess_t *sess, const uint8_t *mac);
upf_sess_t *upf_sess_find_by_mac(const uint8_t *mac);
upf_sess_t *upf_sess_find_by_id(ogs_pool_id_t id);

uint8_t upf_sess_set_ue_ip(upf_sess_t *sess,
        uint8_t session_type, ogs_pfcp_pdr_t *pdr);
/* Phase 5 Step 1: record the PDU session type as UPF-local correlation state
 * (logs the creation for an Ethernet PDU session). */
void upf_sess_set_correlation(upf_sess_t *sess, uint8_t session_type);
/* Phase 5 Step 3: assign a DS-TT port number for a 5GS-TSN-bridge PDU session
 * (returned in the PFCP created_bridge_info_for_tsc IE). Monotonic, >= 1. */
uint32_t upf_sess_assign_dstt_port(void);
uint8_t upf_sess_set_ue_ipv4_framed_routes(upf_sess_t *sess,
        char *framed_routes[]);
uint8_t upf_sess_set_ue_ipv6_framed_routes(upf_sess_t *sess,
        char *framed_routes[]);

void upf_sess_urr_acc_add(upf_sess_t *sess, ogs_pfcp_urr_t *urr, size_t size, bool is_uplink);
void upf_sess_urr_acc_fill_usage_report(upf_sess_t *sess, const ogs_pfcp_urr_t *urr,
                                        ogs_pfcp_user_plane_report_t *report, unsigned int idx);
void upf_sess_urr_acc_snapshot(upf_sess_t *sess, ogs_pfcp_urr_t *urr);
void upf_sess_urr_acc_timers_setup(upf_sess_t *sess, ogs_pfcp_urr_t *urr);

#ifdef __cplusplus
}
#endif

#endif /* UPF_CONTEXT_H */
