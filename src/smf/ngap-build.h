/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef SMF_NGAP_BUILD_H
#define SMF_NGAP_BUILD_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CN Packet Delay Budget (TS 23.501 §5.7.3.4) in 0.01 ms units, signalled on a
 * NonDynamic5QIDescriptor (TS 38.413 §9.3.1.28, ext IEs 187/188) so the NG-RAN
 * scheduler can compute the radio deadline 5G-AN PDB = PDB - CN PDB. The CN PDB is
 * a per-5QI value: it must fit inside that 5QI's PDB (TS 23.501 Table 5.7.4-1), so a
 * single global constant would over-subtract for tight delay-critical 5QIs (e.g. 5QI
 * 85, 5 ms PDB) and under-subtract for relaxed ones. Only delay-critical GBR 5QIs
 * (82-86) carry a CN PDB; a 5QI with no table entry signals none (TS 23.501 §5.7.3.4
 * — CN PDB is a delay-critical-GBR concept). Values are a topology constant
 * (PSA-UPF <-> NG-RAN); lab knob, tune per 5QI as experiments demand. */
typedef struct smf_cn_pdb_s {
    uint8_t  five_qi;        /* standardized 5QI index */
    uint16_t cn_pdb_dl_001ms;/* DL CN PDB, 0.01 ms units (0 = omit direction) */
    uint16_t cn_pdb_ul_001ms;/* UL CN PDB, 0.01 ms units (0 = omit direction) */
} smf_cn_pdb_t;

static const smf_cn_pdb_t smf_cn_pdb_table[] = {
    /* CN PDB per TS 23.501 R17 Table 5.7.4-1 NOTEs 4/5/6 (static UPF<->5G-AN delay),
     * applied symmetrically to DL and UL (the spec gives one one-way value). */
    { 82, 100, 100 },  /* NOTE 4: 1.00 ms */
    { 83, 100, 100 },  /* NOTE 4: 1.00 ms */
    { 84, 500, 500 },  /* NOTE 6: 5.00 ms */
    { 85, 200, 200 },  /* NOTE 5: 2.00 ms */
    { 86, 200, 200 },  /* NOTE 5: 2.00 ms */
    /* 5QIs 87-90 are R18 additions (not in R17 Table 5.7.4-1).
     * CN PDB values below are extrapolated and UNVERIFIED against
     * R18 — verify against TS 23.501 R18 Table 5.7.4-1 before relying on them. */
    { 87, 100, 100 },  /* NOTE 4: 1.00 ms */
    { 88, 100, 100 },  /* NOTE 4: 1.00 ms */
    { 89, 100, 100 },  /* NOTE 4: 1.00 ms */
    { 90, 100, 100 },  /* NOTE 4: 1.00 ms */
};

/* Return the per-5QI CN PDB entry for a standardized 5QI, or NULL when the 5QI is
 * not delay-critical GBR (no CN PDB extension is then signalled). */
static inline const smf_cn_pdb_t *smf_cn_pdb_lookup(uint8_t five_qi)
{
    unsigned int i;
    for (i = 0; i < OGS_ARRAY_SIZE(smf_cn_pdb_table); i++) {
        if (smf_cn_pdb_table[i].five_qi == five_qi)
            return &smf_cn_pdb_table[i];
    }
    return NULL;
}

ogs_pkbuf_t *ngap_build_pdu_session_resource_setup_request_transfer(
        smf_sess_t *sess);

ogs_pkbuf_t *ngap_build_pdu_session_resource_modify_request_transfer(
        smf_sess_t *sess, bool include_gbr);

ogs_pkbuf_t *ngap_build_pdu_session_resource_release_request_transfer(
        smf_sess_t *sess, NGAP_Cause_PR group, long cause);

ogs_pkbuf_t *ngap_build_pdu_session_resource_release_command_transfer(
        smf_sess_t *sess, int state, NGAP_Cause_PR group, long cause);

ogs_pkbuf_t *ngap_build_path_switch_request_ack_transfer(smf_sess_t *sess);

ogs_pkbuf_t *ngap_build_handover_command_transfer(smf_sess_t *sess);

#ifdef __cplusplus
}
#endif

#endif /* SMF_NGAP_BUILD_H */
