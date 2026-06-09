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

#include "naf-build.h"

ogs_sbi_request_t *pcf_naf_callback_build_policyauthorization_terminate(
        pcf_app_t *app_session, void *data)
{
    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;
    
    ogs_assert(app_session);

    memset(&message, 0, sizeof(message));
    message.h.method = (char *)OGS_SBI_HTTP_METHOD_POST;
    message.h.uri = ogs_msprintf("%s/%s",
                app_session->notif_uri, OGS_SBI_RESOURCE_NAME_TERMINATE);
    if (!message.h.uri) {
        ogs_error("No message.h.uri");
        goto end;
    }

    request = ogs_sbi_build_request(&message);
    ogs_assert(request);

end:

    if (message.h.uri)
        ogs_free(message.h.uri);

    return request;
}

/*
 * option-3: PCF -> TSN AF bridge relay (TS 23.501 §5.28.1). When the PCF
 * learns the DS-TT MAC from the SMF's tsnBridgeInfo (TS 29.512), it POSTs the
 * 5GS bridge descriptor to the AF /v1/bridges. Body carries only spec-defined
 * fields: bridge_id, ds_tt_port, ds_tt_mac, nw_tt_port, nw_tt_mac,
 * ds_tt_resid_time_ns. NW-TT port/MAC come from env vars TSN_NW_TT_PORT /
 * TSN_NW_TT_MAC. No supi (not a spec field for the bridge descriptor).
 */
ogs_sbi_request_t *pcf_naf_build_tsn_bridge_register(
        const char *af_uri,
        int bridge_id, int ds_tt_port, const char *ds_tt_mac)
{
    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;
    char *body = NULL;
    const char *nw_tt_mac_env = getenv("TSN_NW_TT_MAC");
    const char *nw_tt_port_env = getenv("TSN_NW_TT_PORT");
    int nw_tt_port = nw_tt_port_env ? atoi(nw_tt_port_env) : 2;
    const char *nw_tt_mac = nw_tt_mac_env ? nw_tt_mac_env : "";

    ogs_assert(af_uri);

    memset(&message, 0, sizeof(message));
    message.h.method = (char *)OGS_SBI_HTTP_METHOD_POST;
    message.h.uri = ogs_strdup(af_uri);
    if (!message.h.uri) {
        ogs_error("No message.h.uri");
        goto end;
    }

    request = ogs_sbi_build_request(&message);
    ogs_assert(request);

    body = ogs_msprintf(
            "{\"bridge_id\":%d,\"ds_tt_port\":%d,"
            "\"ds_tt_mac\":\"%s\","
            "\"nw_tt_port\":%d,\"nw_tt_mac\":\"%s\","
            "\"ds_tt_resid_time_ns\":1000}",
            bridge_id, ds_tt_port,
            ds_tt_mac ? ds_tt_mac : "",
            nw_tt_port, nw_tt_mac);
    ogs_assert(body);

    request->http.content = body;          /* freed by ogs_sbi_request_free() */
    request->http.content_length = strlen(body);
    ogs_sbi_header_set(request->http.headers,
            OGS_SBI_CONTENT_TYPE, OGS_SBI_CONTENT_JSON_TYPE);

end:

    if (message.h.uri)
        ogs_free(message.h.uri);

    return request;
}
