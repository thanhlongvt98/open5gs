/*
 * Copyright (C) 2019-2025 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef PCF_NPCF_HANDLER_H
#define PCF_NPCF_HANDLER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PCF QoS mapping table: standardized Delay-critical GBR 5QIs from TS 23.501 R17
 * Table 5.7.4-1, restricted to the set the gNB knows from its default config
 * (CU-CP + DU) so no per-5QI gNB qos block is needed. */
typedef struct pcf_tsc_5qi_s {
    uint8_t  five_qi;
    uint8_t  priority;      /* Priority Level (lower = higher priority). */
    uint16_t pdb_ms;        /* Packet Delay Budget, ms. */
    uint8_t  per_scalar;    /* Packet Error Rate = per_scalar x 10^-per_exponent. */
    uint8_t  per_exponent;
    uint16_t mdbv;          /* Default Maximum Data Burst Volume, bytes. */
    uint16_t avg_window_ms; /* Default Averaging Window, ms. */
    uint16_t cn_pdb_ms;     /* Static CN PDB (UPF<->5G-AN), ms (NOTE 4/5/6). */
} pcf_tsc_5qi_t;

static const pcf_tsc_5qi_t pcf_tsc_5qi_table[] = {
    /* 5QI prio pdb  per(s,e)  mdbv  avgw  cnpdb   (TS 23.501 R17 Table 5.7.4-1) */
    {  82,  19,  10,  1, 4,    255,  2000,   1 }, /* Discrete Automation         */
    {  83,  22,  10,  1, 4,    1354, 2000,   1 }, /* Discrete Automation / V2X   */
    {  84,  24,  30,  1, 5,    1354, 2000,   5 }, /* Intelligent transport sys.  */
    {  85,  21,  5,   1, 5,    255,  2000,   2 }, /* Electricity dist. high volt.*/
    {  86,  18,  5,   1, 4,    1354, 2000,   2 }, /* V2X collision avoidance     */
    /* 5QIs 87-90 are R18 additions (not in R17 Table 5.7.4-1).
     * CN PDB and characteristics below are extrapolated and UNVERIFIED against
     * R18 — verify against TS 23.501 R18 Table 5.7.4-1 before relying on them. */
    {  87,  25,  5,   1, 3,    500,  2000,   1 }, /* Interactive - motion track. */
    {  88,  25,  10,  1, 3,    1125, 2000,   1 }, /* Interactive - motion track. */
    {  89,  25,  15,  1, 4,    17000,2000,   1 }, /* Visual content cloud/edge   */
    {  90,  25,  20,  1, 4,    63000,2000,   1 }, /* Visual content cloud/edge   */
};

/* Fallback 5QI when the AF's tsnQos carries no usable requirement.
 * 85 (delay-critical GBR, PDB 5ms) = the subscriber-provisioned Ethernet-session 5QI,
 * so the AF-requested TSC flow folds onto the same QoS flow (no 84/85 split). */
#define PCF_TSC_5QI_DEFAULT 85

bool pcf_npcf_am_policy_control_handle_create(pcf_ue_am_t *pcf_ue_am,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);

bool pcf_npcf_smpolicycontrol_handle_create(pcf_sess_t *sess,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
bool pcf_npcf_smpolicycontrol_handle_delete(pcf_sess_t *sess,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);

bool pcf_npcf_policyauthorization_handle_create(pcf_sess_t *sess,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
bool pcf_npcf_policyauthorization_handle_update(
        pcf_sess_t *sess, pcf_app_t *app,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
bool pcf_npcf_policyauthorization_handle_delete(
        pcf_sess_t *sess, pcf_app_t *app,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);

#ifdef __cplusplus
}
#endif

#endif /* PCF_NPCF_HANDLER_H */
