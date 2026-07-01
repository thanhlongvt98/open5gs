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

#include "sbi/openapi/model/pdu_session_tsn_bridge.h"
#include "sbi/openapi/model/tsn_bridge_info.h"

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
 * PCF -> TSN AF new-bridge notification (TS 29.514 §4.2.5.16 "Notification
 * about TSC user plane node Information, no Individual Application Session
 * Context exists"). When the SMF reports a new 5GS bridge (TsnBridgeInfo over
 * N7, TS 29.512), the PCF POSTs a PduSessionTsnBridge to the AF's locally
 * configured notification URI with the "new-bridge" segment appended.
 *
 * Body = PduSessionTsnBridge (TS 29.514 §5.6.2.40): the mandatory
 * tsnBridgeInfo (bridgeId, dsttPortNum, dsttAddr = the DS-TT *port* MAC from
 * N1, dsttResidTime = UE-DS-TT residence time in ns). Built via
 * OpenAPI_pdu_session_tsn_bridge_convertToJSON so the wire format stays
 * aligned with the generated model. NW-TT info is the AF's concern (it has
 * no DS-TT-side N1 source) and is injected there from env.
 */
ogs_sbi_request_t *pcf_naf_build_tsn_bridge_new_bridge(
        const char *af_uri,
        int bridge_id, int ds_tt_port, const char *ds_tt_mac,
        bool has_resid_time, int resid_time_ns)
{
    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;
    OpenAPI_tsn_bridge_info_t *bridge_info = NULL;
    OpenAPI_pdu_session_tsn_bridge_t *bridge = NULL;
    cJSON *json = NULL;
    char *json_str = NULL;
    char *content = NULL;

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

    bridge_info = OpenAPI_tsn_bridge_info_create(
            true, bridge_id,
            ds_tt_mac ? ogs_strdup(ds_tt_mac) : NULL,
            true, ds_tt_port,
            has_resid_time, resid_time_ns);
    if (!bridge_info) {
        ogs_error("OpenAPI_tsn_bridge_info_create() failed");
        goto end;
    }

    bridge = OpenAPI_pdu_session_tsn_bridge_create(
            bridge_info, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!bridge) {
        ogs_error("OpenAPI_pdu_session_tsn_bridge_create() failed");
        OpenAPI_tsn_bridge_info_free(bridge_info);
        goto end;
    }

    json = OpenAPI_pdu_session_tsn_bridge_convertToJSON(bridge);
    OpenAPI_pdu_session_tsn_bridge_free(bridge);
    if (!json) {
        ogs_error("OpenAPI_pdu_session_tsn_bridge_convertToJSON() failed");
        goto end;
    }

    json_str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!json_str) {
        ogs_error("cJSON_PrintUnformatted() failed");
        goto end;
    }

    content = ogs_strdup(json_str);
    cJSON_free(json_str);
    if (!content) {
        ogs_error("ogs_strdup() failed");
        goto end;
    }

    request->http.content = content;
    request->http.content_length = strlen(content);
    ogs_sbi_header_set(request->http.headers,
            OGS_SBI_CONTENT_TYPE, OGS_SBI_CONTENT_JSON_TYPE);

end:

    if (message.h.uri)
        ogs_free(message.h.uri);

    return request;
}
