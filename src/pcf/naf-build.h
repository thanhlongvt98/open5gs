/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef PCF_NAF_BUILD_H
#define PCF_NAF_BUILD_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

ogs_sbi_request_t *pcf_naf_callback_build_policyauthorization_terminate(
        pcf_app_t *app_session, void *data);

/* Build the PCF -> TSN AF new-bridge notification POST (TS 29.514 §4.2.5.16):
 * POST {notifUri}/new-bridge with a PduSessionTsnBridge body (§5.6.2.40). The
 * tsnBridgeInfo carries bridgeId, dsttPortNum, dsttAddr (DS-TT port MAC from
 * N1) and dsttResidTime (UE-DS-TT residence time, ns). */
ogs_sbi_request_t *pcf_naf_build_tsn_bridge_new_bridge(
        const char *af_uri,
        int bridge_id, int ds_tt_port, const char *ds_tt_mac,
        bool has_resid_time, int resid_time_ns);

#ifdef __cplusplus
}
#endif

#endif /* PCF_NAF_BUILD_H */
