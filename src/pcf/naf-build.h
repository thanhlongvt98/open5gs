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

/* option-3: build the PCF -> TSN AF bridge relay POST (/v1/bridges).
 * Carries spec-defined fields only (TS 23.501 §5.28.1): bridge_id, ds_tt_port,
 * ds_tt_mac, nw_tt_port, nw_tt_mac, ds_tt_resid_time_ns. NW-TT info comes
 * from env vars TSN_NW_TT_PORT / TSN_NW_TT_MAC. No supi. */
ogs_sbi_request_t *pcf_naf_build_tsn_bridge_register(
        const char *af_uri,
        int bridge_id, int ds_tt_port, const char *ds_tt_mac);

#ifdef __cplusplus
}
#endif

#endif /* PCF_NAF_BUILD_H */
