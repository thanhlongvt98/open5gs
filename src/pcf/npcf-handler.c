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

#include "sbi-path.h"

#include "npcf-handler.h"

bool pcf_npcf_am_policy_control_handle_create(pcf_ue_am_t *pcf_ue_am,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *message)
{
    bool rc;
    int r;

    OpenAPI_policy_association_request_t *PolicyAssociationRequest = NULL;
    OpenAPI_guami_t *Guami = NULL;
    OpenAPI_lnode_t *node = NULL;

    uint64_t supported_features = 0;

    ogs_sbi_server_t *server = NULL;
    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_assert(pcf_ue_am);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);
    ogs_assert(message);

    PolicyAssociationRequest = message->PolicyAssociationRequest;
    if (!PolicyAssociationRequest) {
        ogs_error("[%s] No PolicyAssociationRequest", pcf_ue_am->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "[%s] No PolicyAssociationRequest", pcf_ue_am->supi,
                NULL));
        return false;
    }

    if (!PolicyAssociationRequest->notification_uri) {
        ogs_error("[%s] No notificationUri", pcf_ue_am->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "No notificationUri", pcf_ue_am->supi, NULL));
        return false;
    }

    if (!PolicyAssociationRequest->supi) {
        ogs_error("[%s] No supi", pcf_ue_am->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "No supi", pcf_ue_am->supi, NULL));
        return false;
    }

    if (!PolicyAssociationRequest->supp_feat) {
        ogs_error("[%s] No suppFeat", pcf_ue_am->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "No suppFeat", pcf_ue_am->supi, NULL));
        return false;
    }

    rc = ogs_sbi_getaddr_from_uri(&scheme, &fqdn, &fqdn_port, &addr, &addr6,
            PolicyAssociationRequest->notification_uri);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        ogs_error("[%s] Invalid URI [%s]",
                pcf_ue_am->supi, PolicyAssociationRequest->notification_uri);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "[%s] Invalid URI", pcf_ue_am->supi, NULL));
        return false;
    }

    if (pcf_ue_am->notification_uri)
        ogs_free(pcf_ue_am->notification_uri);
    pcf_ue_am->notification_uri = ogs_strdup(
            PolicyAssociationRequest->notification_uri);
    ogs_assert(pcf_ue_am->notification_uri);

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("%s: ogs_sbi_client_add()", OGS_FUNC);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        if (!client) {
            ogs_error("%s: ogs_sbi_client_add() failed", OGS_FUNC);

            ogs_free(fqdn);
            ogs_freeaddrinfo(addr);
            ogs_freeaddrinfo(addr6);

            return false;
        }
    }
    OGS_SBI_SETUP_CLIENT(&pcf_ue_am->namf, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    supported_features =
        ogs_uint64_from_string_hexadecimal(
                PolicyAssociationRequest->supp_feat);
    pcf_ue_am->am_policy_control_features &= supported_features;

    if (PolicyAssociationRequest->gpsi) {
        if (pcf_ue_am->gpsi)
            ogs_free(pcf_ue_am->gpsi);
        pcf_ue_am->gpsi = ogs_strdup(PolicyAssociationRequest->gpsi);
    }

    pcf_ue_am->access_type = PolicyAssociationRequest->access_type;

    if (PolicyAssociationRequest->pei) {
        if (pcf_ue_am->pei)
            ogs_free(pcf_ue_am->pei);
        pcf_ue_am->pei = ogs_strdup(PolicyAssociationRequest->pei);
    }

    Guami = PolicyAssociationRequest->guami;
    if (Guami && Guami->amf_id &&
        Guami->plmn_id && Guami->plmn_id->mnc && Guami->plmn_id->mcc) {
        ogs_sbi_parse_guami(&pcf_ue_am->guami, PolicyAssociationRequest->guami);
    }

    OpenAPI_list_for_each(PolicyAssociationRequest->allowed_snssais, node) {
        struct OpenAPI_snssai_s *Snssai = node->data;
        if (Snssai) {
            ogs_s_nssai_t s_nssai;
            s_nssai.sst = Snssai->sst;
            s_nssai.sd = ogs_s_nssai_sd_from_string(Snssai->sd);

            pcf_metrics_inst_by_slice_add(&pcf_ue_am->guami.plmn_id,
                    &s_nssai, PCF_METR_CTR_PA_POLICYAMASSOREQ, 1);
        } else {
            ogs_error("[%s] No Snssai", pcf_ue_am->supi);
        }
    }

    if (PolicyAssociationRequest->rat_type)
        pcf_ue_am->rat_type = PolicyAssociationRequest->rat_type;

    pcf_ue_am->policy_association_request =
        OpenAPI_policy_association_request_copy(
                pcf_ue_am->policy_association_request,
                message->PolicyAssociationRequest);

    if (PolicyAssociationRequest->ue_ambr)
        pcf_ue_am->subscribed_ue_ambr = OpenAPI_ambr_copy(
                pcf_ue_am->subscribed_ue_ambr,
                PolicyAssociationRequest->ue_ambr);

    if (ogs_sbi_supi_in_vplmn(pcf_ue_am->supi) == true) {
        /* Visited PLMN */
        OpenAPI_policy_association_t PolicyAssociation;

        ogs_sbi_message_t sendmsg;
        ogs_sbi_header_t header;
        ogs_sbi_response_t *response = NULL;

        memset(&PolicyAssociation, 0, sizeof(PolicyAssociation));
        PolicyAssociation.request = pcf_ue_am->policy_association_request;
        PolicyAssociation.supp_feat =
            ogs_uint64_to_string(pcf_ue_am->am_policy_control_features);
        ogs_assert(PolicyAssociation.supp_feat);

        memset(&header, 0, sizeof(header));
        header.service.name =
            (char *)OGS_SBI_SERVICE_NAME_NPCF_AM_POLICY_CONTROL;
        header.api.version = (char *)OGS_SBI_API_V1;
        header.resource.component[0] = (char *)OGS_SBI_RESOURCE_NAME_POLICIES;
        header.resource.component[1] = pcf_ue_am->association_id;

        memset(&sendmsg, 0, sizeof(sendmsg));
        sendmsg.PolicyAssociation = &PolicyAssociation;
        sendmsg.http.location = ogs_sbi_server_uri(server, &header);

        response = ogs_sbi_build_response(
                &sendmsg, OGS_SBI_HTTP_STATUS_CREATED);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        ogs_free(sendmsg.http.location);

        ogs_free(PolicyAssociation.supp_feat);

        return true;
    } else {
        /* Home PLMN */
        r = pcf_ue_am_sbi_discover_and_send(OGS_SBI_SERVICE_TYPE_NUDR_DR, NULL,
                pcf_nudr_dr_build_query_am_data, pcf_ue_am, stream, NULL);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);

        return (r == OGS_OK);
    }
}

bool pcf_npcf_smpolicycontrol_handle_create(pcf_sess_t *sess,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *message)
{
    bool rc;
    int status = 0;
    int r;
    char *strerror = NULL;
    pcf_ue_sm_t *pcf_ue_sm = NULL;

    OpenAPI_sm_policy_context_data_t *SmPolicyContextData = NULL;
    OpenAPI_plmn_id_nid_t *servingNetwork = NULL;
    OpenAPI_snssai_t *sliceInfo = NULL;

    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    char *home_network_domain = NULL;

    ogs_assert(sess);
    pcf_ue_sm = pcf_ue_sm_find_by_id(sess->pcf_ue_sm_id);
    ogs_assert(stream);
    ogs_assert(message);

    SmPolicyContextData = message->SmPolicyContextData;
    if (!SmPolicyContextData) {
        strerror = ogs_msprintf("[%s:%d] No SmPolicyContextData",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->supi) {
        strerror = ogs_msprintf("[%s:%d] No supi", pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->pdu_session_id) {
        strerror = ogs_msprintf("[%s:%d] No pduSessionId",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->pdu_session_type) {
        strerror = ogs_msprintf("[%s:%d] No pduSessionType",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->dnn) {
        strerror = ogs_msprintf("[%s:%d] No dnn", pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->notification_uri) {
        strerror = ogs_msprintf("[%s:%d] No notificationUri",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    /* an Ethernet PDU session (TS 23.501 §5.6.10) carries no UE
     * IP — the SM Policy Association is keyed by SUPI/DNN/MAC, not an address.
     * Only require an IPv4/IPv6 address for IP PDU session types. */
    if (SmPolicyContextData->pdu_session_type !=
                OpenAPI_pdu_session_type_ETHERNET &&
        !SmPolicyContextData->ipv4_address &&
        !SmPolicyContextData->ipv6_address_prefix) {
        strerror = ogs_msprintf(
                "[%s:%d] No IPv4 address[%p] or IPv6 prefix[%p]",
                pcf_ue_sm->supi, sess->psi,
                SmPolicyContextData->ipv4_address,
                SmPolicyContextData->ipv6_address_prefix);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    sliceInfo = SmPolicyContextData->slice_info;
    if (!sliceInfo) {
        strerror = ogs_msprintf("[%s:%d] No sliceInfo",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    servingNetwork = SmPolicyContextData->serving_network;
    if (servingNetwork) {
        if (!servingNetwork->mcc) {
            strerror = ogs_msprintf("[%s:%d] No servingNetwork->mcc",
                    pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }
        if (!servingNetwork->mnc) {
            strerror = ogs_msprintf("[%s:%d] No servingNetwork->mnc",
                    pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }
    } else {
        ogs_warn("No servingNetwork");
    }

    rc = ogs_sbi_getaddr_from_uri(&scheme, &fqdn, &fqdn_port, &addr, &addr6,
            SmPolicyContextData->notification_uri);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        strerror = ogs_msprintf("[%s:%d] Invalid URI [%s]",
                pcf_ue_sm->supi, sess->psi,
                SmPolicyContextData->notification_uri);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (SmPolicyContextData->gpsi) {
        if (pcf_ue_sm->gpsi)
            ogs_free(pcf_ue_sm->gpsi);
        pcf_ue_sm->gpsi = ogs_strdup(SmPolicyContextData->gpsi);
    }

    if (SmPolicyContextData->supp_feat) {
        uint64_t supported_features =
            ogs_uint64_from_string_hexadecimal(
                    SmPolicyContextData->supp_feat);
        sess->smpolicycontrol_features &= supported_features;
    } else {
        sess->smpolicycontrol_features = 0;
    }

    sess->pdu_session_type = SmPolicyContextData->pdu_session_type;

    /* Serving PLMN & Home PLMN */
    if (servingNetwork) {
        sess->serving.presence = true;
        ogs_sbi_parse_plmn_id_nid(&sess->serving.plmn_id, servingNetwork);

        sess->home.presence = true;
        memcpy(&sess->home.plmn_id, &sess->serving.plmn_id, OGS_PLMN_ID_LEN);
    }

    /*
     * TS29.512
     * 5 Npcf_SMPolicyControl Service API
     * 5.6 Data Model
     * 5.6.2 Structured data types
     * Table 5.6.2.3-1: Definition of type SmPolicyContextData
     *
     * NAME: dnn
     * Data type: Dnn
     * P: M
     * Cardinality: 1
     * The DNN of the PDU session, a full DNN with both the Network Identifier
     * and Operator Identifier, or a DNN with the Network Identifier only
     */
    home_network_domain = ogs_home_network_domain_from_fqdn(
            SmPolicyContextData->dnn);

    if (home_network_domain) {
        char dnn_network_identifer[OGS_MAX_DNN_LEN+1];
        uint16_t mcc = 0, mnc = 0;

        ogs_assert(home_network_domain > SmPolicyContextData->dnn);

        ogs_cpystrn(dnn_network_identifer, SmPolicyContextData->dnn,
            ogs_min(OGS_MAX_DNN_LEN,
                home_network_domain - SmPolicyContextData->dnn));

        if (sess->dnn)
            ogs_free(sess->dnn);
        sess->dnn = ogs_strdup(dnn_network_identifer);
        ogs_assert(sess->dnn);

        if (sess->full_dnn)
            ogs_free(sess->full_dnn);
        sess->full_dnn = ogs_strdup(SmPolicyContextData->dnn);
        ogs_assert(sess->full_dnn);

        mcc = ogs_plmn_id_mcc_from_fqdn(sess->full_dnn);
        mnc = ogs_plmn_id_mnc_from_fqdn(sess->full_dnn);

        /*
         * To generate the Home PLMN ID of the SMF-UE,
         * the length of the MNC is obtained
         * by comparing the MNC part of the SUPI and full-DNN.
         */
        if (mcc && mnc &&
            strncmp(pcf_ue_sm->supi, "imsi-", strlen("imsi-")) == 0) {
            int mnc_len = 0;
            char buf[OGS_PLMNIDSTRLEN];

            ogs_snprintf(buf, OGS_PLMNIDSTRLEN, "%03d%02d", mcc, mnc);
            if (strncmp(pcf_ue_sm->supi + 5, buf, strlen(buf)) == 0)
                mnc_len = 2;

            ogs_snprintf(buf, OGS_PLMNIDSTRLEN, "%03d%03d", mcc, mnc);
            if (strncmp(pcf_ue_sm->supi + 5, buf, strlen(buf)) == 0)
                mnc_len = 3;

            /* Change Home PLMN for VPLMN */
            if (mnc_len == 2 || mnc_len == 3) {
                if (sess->home.presence == true)
                    ogs_plmn_id_build(&sess->home.plmn_id, mcc, mnc, mnc_len);
            }
        }
    } else {
        if (sess->dnn)
            ogs_free(sess->dnn);
        sess->dnn = ogs_strdup(SmPolicyContextData->dnn);
        ogs_assert(sess->dnn);

        if (sess->full_dnn)
            ogs_free(sess->full_dnn);
        sess->full_dnn = NULL;
    }

    if (sess->notification_uri)
        ogs_free(sess->notification_uri);
    sess->notification_uri = ogs_strdup(SmPolicyContextData->notification_uri);
    ogs_assert(sess->notification_uri);

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("%s: ogs_sbi_client_add()", OGS_FUNC);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        if (!client) {
            strerror = ogs_msprintf("%s: ogs_sbi_client_add() failed",
                    OGS_FUNC);
            status = OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;
            ogs_freeaddrinfo(addr);
            goto cleanup;
        }
    }
    OGS_SBI_SETUP_CLIENT(&sess->nsmf, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    if (SmPolicyContextData->ipv4_address)
        ogs_assert(true ==
            pcf_sess_set_ipv4addr(sess, SmPolicyContextData->ipv4_address));
    if (SmPolicyContextData->ipv6_address_prefix)
        ogs_assert(true ==
            pcf_sess_set_ipv6prefix(
                sess, SmPolicyContextData->ipv6_address_prefix));

    if (SmPolicyContextData->ipv4_frame_route_list) {
        OpenAPI_lnode_t *node = NULL;

        OpenAPI_clear_and_free_string_list(sess->ipv4_frame_route_list);
        sess->ipv4_frame_route_list = OpenAPI_list_create();
        OpenAPI_list_for_each(
                SmPolicyContextData->ipv4_frame_route_list, node) {
            if (!node->data)
                continue;
            OpenAPI_list_add(
                    sess->ipv4_frame_route_list, ogs_strdup(node->data));
        }
    }

    if (SmPolicyContextData->ipv6_frame_route_list) {
        OpenAPI_lnode_t *node = NULL;

        OpenAPI_clear_and_free_string_list(sess->ipv6_frame_route_list);
        sess->ipv6_frame_route_list = OpenAPI_list_create();
        OpenAPI_list_for_each(
                SmPolicyContextData->ipv6_frame_route_list, node) {
            if (!node->data)
                continue;
            OpenAPI_list_add(
                    sess->ipv6_frame_route_list, ogs_strdup(node->data));
        }
    }

    sess->s_nssai.sst = sliceInfo->sst;
    sess->s_nssai.sd = ogs_s_nssai_sd_from_string(sliceInfo->sd);

    pcf_metrics_inst_by_slice_add(
            sess->home.presence == true ? &sess->home.plmn_id : NULL,
            &sess->s_nssai, PCF_METR_GAUGE_PA_SESSIONNBR, 1);
    pcf_metrics_inst_by_slice_add(
            sess->home.presence == true ? &sess->home.plmn_id : NULL,
            &sess->s_nssai, PCF_METR_CTR_PA_POLICYSMASSOREQ, 1);

    if (SmPolicyContextData->subs_sess_ambr)
        sess->subscribed_sess_ambr = OpenAPI_ambr_copy(
            sess->subscribed_sess_ambr, SmPolicyContextData->subs_sess_ambr);

    if (SmPolicyContextData->subs_def_qos)
        sess->subscribed_default_qos = OpenAPI_subscribed_default_qos_copy(
            sess->subscribed_default_qos, SmPolicyContextData->subs_def_qos);

    if (ogs_sbi_supi_in_vplmn(pcf_ue_sm->supi) == true) {
        /* Visited PLMN */
        r = pcf_sess_sbi_discover_and_send(
                    OGS_SBI_SERVICE_TYPE_NBSF_MANAGEMENT, NULL,
                    pcf_nbsf_management_build_register,
                    sess, stream, NULL);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);

        return (r == OGS_OK);
    } else {
        /* Home PLMN */
        r = pcf_sess_sbi_discover_and_send(
                OGS_SBI_SERVICE_TYPE_NUDR_DR, NULL,
                pcf_nudr_dr_build_query_sm_data, sess, stream, NULL);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);

        return (r == OGS_OK);
    }

cleanup:
    ogs_assert(status);
    ogs_assert(strerror);
    ogs_error("%s", strerror);
    /*
     * TS29.512
     * 4.2.2.2 SM Policy Association establishment 
     *
     * If the PCF is, due to incomplete, erroneous or missing
     * information (e.g. QoS, RAT type, subscriber information)
     * not able to provision a policy decision as response to
     * the request for PCC rules by the SMF, the PCF may reject
     * the request and include in an HTTP "400 Bad Request"
     * response message the "cause" attribute of the ProblemDetails
     * data structure set to "ERROR_INITIAL_PARAMETERS". 
     */
    ogs_assert(true ==
            ogs_sbi_server_send_error(stream, status, message,
                    strerror, NULL, "ERROR_INITIAL_PARAMETERS"));
    ogs_free(strerror);

    return false;
}

bool pcf_npcf_smpolicycontrol_handle_delete(pcf_sess_t *sess,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *message)
{
    int r;
    int status = 0;
    char *strerror = NULL;
    pcf_ue_sm_t *pcf_ue_sm = NULL;
    pcf_app_t *app_session = NULL;

    OpenAPI_sm_policy_delete_data_t *SmPolicyDeleteData = NULL;

    ogs_assert(sess);
    pcf_ue_sm = pcf_ue_sm_find_by_id(sess->pcf_ue_sm_id);
    ogs_assert(stream);
    ogs_assert(message);

    SmPolicyDeleteData = message->SmPolicyDeleteData;
    if (!SmPolicyDeleteData) {
        strerror = ogs_msprintf("[%s:%d] No SmPolicyDeleteData",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    ogs_list_for_each(&sess->app_list, app_session) {
        pcf_sbi_send_policyauthorization_terminate_notify(app_session);
    }

    if (pcf_sessions_number_by_snssai_and_dnn(
                pcf_ue_sm, &sess->s_nssai, sess->dnn) > 1) {
        ogs_expect(true ==
                ogs_sbi_send_response(stream, OGS_SBI_HTTP_STATUS_NO_CONTENT));
    } else if (sess->binding.resource_uri) {
        r = pcf_sess_sbi_discover_and_send(
                OGS_SBI_SERVICE_TYPE_NBSF_MANAGEMENT, NULL,
                pcf_nbsf_management_build_de_register, sess, stream, NULL);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
    } else {
        ogs_expect(true ==
                ogs_sbi_send_response(stream, OGS_SBI_HTTP_STATUS_NO_CONTENT));
    }

    return true;

cleanup:
    ogs_assert(status);
    ogs_assert(strerror);
    ogs_error("%s", strerror);
    ogs_assert(true ==
        ogs_sbi_server_send_error(stream, status, message, strerror, NULL,
                NULL));
    ogs_free(strerror);

    return false;
}

/*
 * handle the SMF-initiated Npcf_SMPolicyControl_Update
 * (TS 29.512 §4.2.4) — in particular the 5GS TSN bridge information reported by
 * the SMF when the TSN_BRIDGE_INFO trigger is met. The PCF records it and (per
 * TS 29.514) relays it to the subscribed TSN AF over N5.
 */
bool pcf_npcf_smpolicycontrol_handle_update(pcf_sess_t *sess,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_sm_policy_update_context_data_t *UpdateData = NULL;

    ogs_assert(sess);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    UpdateData = recvmsg->SmPolicyUpdateContextData;
    if (!UpdateData) {
        ogs_error("No SmPolicyUpdateContextData");
        ogs_assert(true == ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST, recvmsg,
                "No SmPolicyUpdateContextData", NULL, NULL));
        return false;
    }

    if (UpdateData->tsn_bridge_info) {
        OpenAPI_tsn_bridge_info_t *bi = UpdateData->tsn_bridge_info;
        ogs_info("[PCF] 5GS TSN bridge reported: bridgeId[%d] DS-TT port[%d]"
                 "%s%s -> relay to TSN AF",
                 bi->is_bridge_id ? bi->bridge_id : -1,
                 bi->is_dstt_port_num ? bi->dstt_port_num : -1,
                 bi->dstt_addr ? " DS-TT MAC " : "",
                 bi->dstt_addr ? bi->dstt_addr : "");

        /* the DS-TT MAC lets the PCF bind the N5 app-session by ueMac
         * (Ethernet sessions have no UE IP, TS 29.514). Store it for the local
         * app-session lookup, and register a BSF binding by MAC (TS 29.521
         * PcfBinding.macAddr48). The 204 to the SMF is deferred to the BSF
         * register response (mac_register_pending). */
        if (bi->dstt_addr &&
            pcf_sess_set_mac_addr(sess, bi->dstt_addr) == true) {
            int r;

            /* Register the BSF MAC-binding FIRST (local, fast) so it is in place
             * before the AF's ueMac app-session create (triggered by the relay
             * below) reaches the PCF -> avoids a discover-by-MAC 404 race. */
            sess->mac_register_pending = true;
            r = pcf_sess_sbi_discover_and_send(
                    OGS_SBI_SERVICE_TYPE_NBSF_MANAGEMENT, NULL,
                    pcf_nbsf_management_build_register, sess, stream, NULL);
            ogs_expect(r == OGS_OK);

            /* Notify the TSN AF of the new 5GS bridge over standard N5
             * (TS 29.514 §4.2.5.16): POST PduSessionTsnBridge to
             * {notifUri}/new-bridge. dsttAddr = the DS-TT *port* MAC from N1;
             * dsttResidTime = UE-DS-TT residence time (ns). */
            pcf_sbi_send_tsn_bridge_new_bridge(
                    bi->is_bridge_id ? bi->bridge_id : 0,
                    bi->is_dstt_port_num ? bi->dstt_port_num : 0,
                    bi->dstt_addr,
                    bi->is_dstt_resid_time, bi->dstt_resid_time);

            if (r == OGS_OK)
                return true; /* 204 sent by the BSF register response handler */
            sess->mac_register_pending = false;
        }
    }

    ogs_expect(true ==
            ogs_sbi_send_response(stream, OGS_SBI_HTTP_STATUS_NO_CONTENT));

    return true;
}

/* PCF QoS mapping table: standardized Delay-critical GBR 5QIs from TS 23.501 R17
 * Table 5.7.4-1, restricted to the set the gNB knows from its default config
 * (CU-CP + DU) so no per-5QI gNB qos block is needed. */
static const struct {
    uint8_t  five_qi;
    uint8_t  priority;      /* Priority Level (lower = higher priority). */
    uint16_t pdb_ms;        /* Packet Delay Budget, ms. */
    uint16_t mdbv;          /* Maximum Data Burst Volume, bytes. */
} pcf_tsc_5qi_table[] = {
    { 82, 19, 10,  255  },
    { 83, 22, 10,  1354 },
    { 84, 24, 30,  1354 },
    { 85, 21, 5,   255  },
    { 86, 18, 5,   1354 },
};

/* Fallback 5QI when the AF's tsnQos carries no usable requirement.
 * 85 (delay-critical GBR, PDB 5ms) = the subscriber-provisioned Ethernet-session 5QI,
 * so the AF-requested TSC flow folds onto the same QoS flow (no 84/85 split). */
#define PCF_TSC_5QI_DEFAULT 85

/* Map the AF's TsnQosContainer (TS 29.514 §5.6.2.35) to a standardized
 * delay-critical-GBR 5QI (PCF QoS mapping, TS 23.501 §5.28.4 / §5.27.3 point 5).
 * The PCF mapping table maps the TSN QoS information (priority / PDB / TSC burst
 * size) to the 5GS QoS profile: the selected 5QI's standardized characteristics
 * (Table 5.7.4-1) must satisfy the requirement — MDBV >= burst (§5.27.3 point 1),
 * PDB <= requested (point 2), priority matching the traffic class.
 *
 * The TSC traffic pattern (TSCAI) is signalled SEPARATELY and comes from the CNC
 * (tscaiInput) — it is NOT derived from the 5QI's table values, so each stream
 * keeps its CNC-computed periodicity/burst-arrival/survival. Here the PCF only
 * selects the QoS-flow 5QI. */
static void pcf_map_tsn_qos_to_5qi(ogs_dyn_5qi_t *dyn,
        bool has_prio, int prio_level,
        bool has_pdb, int pack_delay,
        bool has_burst, int burst_size)
{
    const size_t n = sizeof(pcf_tsc_5qi_table) / sizeof(pcf_tsc_5qi_table[0]);
    uint8_t selected = PCF_TSC_5QI_DEFAULT;
    size_t i;

    /* Standardized 5QI -> NGAP NonDynamic5QIDescriptor (dynamic path stays off). */
    dyn->is_dynamic = false;
    dyn->delay_critical = true;

    /* Tier 1: exact (priority, PDB) match, with MDBV satisfying the burst if given. */
    if (has_prio && has_pdb) {
        for (i = 0; i < n; i++) {
            if (pcf_tsc_5qi_table[i].priority == (uint8_t)prio_level &&
                    pcf_tsc_5qi_table[i].pdb_ms == (uint16_t)pack_delay &&
                    (!has_burst || pcf_tsc_5qi_table[i].mdbv >= (uint16_t)burst_size)) {
                dyn->five_qi = pcf_tsc_5qi_table[i].five_qi;
                return;
            }
        }
    }

    /* Tier 2: best satisfying row — tightest PDB that still meets the requirement
     * (PDB <= requested when given, MDBV >= burst when given). */
    if (has_pdb || has_burst) {
        bool found = false;
        uint16_t best_pdb = 0;
        for (i = 0; i < n; i++) {
            if (has_pdb && pcf_tsc_5qi_table[i].pdb_ms > (uint16_t)pack_delay)
                continue;
            if (has_burst && pcf_tsc_5qi_table[i].mdbv < (uint16_t)burst_size)
                continue;
            if (!found || pcf_tsc_5qi_table[i].pdb_ms < best_pdb) {
                best_pdb = pcf_tsc_5qi_table[i].pdb_ms;
                selected = pcf_tsc_5qi_table[i].five_qi;
                found = true;
            }
        }
    }

    dyn->five_qi = selected;
}

bool pcf_npcf_policyauthorization_handle_create(pcf_sess_t *sess,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    bool rc;
    int i, j, rv, status = 0;
    char *strerror = NULL;
    pcf_ue_sm_t *pcf_ue_sm = NULL;
    pcf_app_t *app_session = NULL;

    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    OpenAPI_app_session_context_t *AppSessionContext = NULL;
    OpenAPI_app_session_context_req_data_t *AscReqData = NULL;

    uint64_t supported_features = 0;

    ogs_sbi_server_t *server = NULL;
    ogs_sbi_header_t header;
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_session_data_t session_data;

    ogs_ims_data_t ims_data;
    ogs_media_component_t *media_component = NULL;
    ogs_media_sub_component_t *sub = NULL;

    OpenAPI_list_t *MediaComponentList = NULL;
    OpenAPI_map_t *MediaComponentMap = NULL;
    OpenAPI_media_component_t *MediaComponent = NULL;

    OpenAPI_list_t *SubComponentList = NULL;
    OpenAPI_map_t *SubComponentMap = NULL;
    OpenAPI_media_sub_component_t *SubComponent = NULL;

    OpenAPI_list_t *fDescList = NULL;

    OpenAPI_sm_policy_decision_t SmPolicyDecision;

    OpenAPI_list_t *PccRuleList = NULL;
    OpenAPI_map_t *PccRuleMap = NULL;
    OpenAPI_pcc_rule_t *PccRule = NULL;

    OpenAPI_list_t *QosDecisionList = NULL;
    OpenAPI_map_t *QosDecisionMap = NULL;
    OpenAPI_qos_data_t *QosData = NULL;
    OpenAPI_list_t *QosCharsList = NULL;
    OpenAPI_map_t *QosCharsMap = NULL;
    OpenAPI_qos_characteristics_t *QosChars = NULL;

    OpenAPI_lnode_t *node = NULL, *node2 = NULL, *node3 = NULL;

    ogs_assert(sess);
    pcf_ue_sm = pcf_ue_sm_find_by_id(sess->pcf_ue_sm_id);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    memset(&ims_data, 0, sizeof(ims_data));
    memset(&session_data, 0, sizeof(ogs_session_data_t));

    AppSessionContext = recvmsg->AppSessionContext;
    if (!AppSessionContext) {
        strerror = ogs_msprintf("[%s:%d] No AppSessionContext",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    AscReqData = AppSessionContext->asc_req_data;
    if (!AscReqData) {
        strerror = ogs_msprintf("[%s:%d] No AscReqData",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!AscReqData->supp_feat) {
        strerror = ogs_msprintf("[%s:%d] No AscReqData->suppFeat",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!AscReqData->notif_uri) {
        strerror = ogs_msprintf("[%s:%d] No AscReqData->notifUri",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    /* medComponents is OPTIONAL in TS 29.514 (§4.2.2.2: provided "if available";
     * the PCF acts only "if the request contains the medComponents attribute"). A
     * bridge-management app-session that carries ONLY a Port Management Container
     * (tsnPortManContDstt/Nwtts) and no media is valid: it authorizes the 802.1Qbv
     * gate schedule (PMIC) without requesting any QoS flow. Reject only when there is
     * neither media nor a PMIC (nothing to authorize). This also avoids forcing a
     * QoS-flow add (PCC rule) onto a TSN session whose flow is subscriber-provisioned. */
    if (!AscReqData->med_components &&
            !AscReqData->tsn_port_man_cont_dstt &&
            (!AscReqData->tsn_port_man_cont_nwtts ||
             !AscReqData->tsn_port_man_cont_nwtts->first)) {
        strerror = ogs_msprintf("[%s:%d] No AscReqData media components or PMIC",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    rc = ogs_sbi_getaddr_from_uri(&scheme, &fqdn, &fqdn_port, &addr, &addr6,
            AscReqData->notif_uri);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        strerror = ogs_msprintf("[%s:%d] Invalid URI [%s]",
                pcf_ue_sm->supi, sess->psi, AscReqData->notif_uri);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    supported_features = ogs_uint64_from_string_hexadecimal(
            AscReqData->supp_feat);
    sess->policyauthorization_features &= supported_features;

    if (sess->policyauthorization_features != supported_features) {
        ogs_free(AscReqData->supp_feat);
        AscReqData->supp_feat =
            ogs_uint64_to_string(sess->policyauthorization_features);
        ogs_assert(AscReqData->supp_feat);
    }

    MediaComponentList = AscReqData->med_components;
    OpenAPI_list_for_each(MediaComponentList, node) {
        MediaComponentMap = node->data;
        if (MediaComponentMap) {
            MediaComponent = MediaComponentMap->value;
            if (MediaComponent) {
                if (ims_data.num_of_media_component >=
                        OGS_ARRAY_SIZE(ims_data.media_component)) {
                    ogs_error("OVERFLOW ims_data.num_of_media_component "
                            "[%d:%d:%d]",
                            ims_data.num_of_media_component,
                            OGS_MAX_NUM_OF_MEDIA_COMPONENT,
                            (int)OGS_ARRAY_SIZE(ims_data.media_component));
                    break;
                }
                media_component = &ims_data.
                    media_component[ims_data.num_of_media_component];
                media_component->media_component_number =
                    MediaComponent->med_comp_n;
                media_component->media_type = MediaComponent->med_type;
                if (MediaComponent->mar_bw_dl)
                    media_component->max_requested_bandwidth_dl =
                        ogs_sbi_bitrate_from_string(MediaComponent->mar_bw_dl);
                if (MediaComponent->mar_bw_ul)
                    media_component->max_requested_bandwidth_ul =
                        ogs_sbi_bitrate_from_string(MediaComponent->mar_bw_ul);
                if (MediaComponent->mir_bw_dl)
                    media_component->min_requested_bandwidth_dl =
                        ogs_sbi_bitrate_from_string(MediaComponent->mir_bw_dl);
                if (MediaComponent->mir_bw_ul)
                    media_component->min_requested_bandwidth_ul =
                        ogs_sbi_bitrate_from_string(MediaComponent->mir_bw_ul);
                if (MediaComponent->rr_bw)
                    media_component->rr_bandwidth =
                        ogs_sbi_bitrate_from_string(MediaComponent->rr_bw);
                if (MediaComponent->rs_bw)
                    media_component->rs_bandwidth =
                        ogs_sbi_bitrate_from_string(MediaComponent->rs_bw);
                media_component->flow_status = MediaComponent->f_status;

                /* capture the AF's TSCAI input containers (TS 29.514)
                 * into the internal media component so they are carried onto
                 * the PCC rule and emitted toward the SMF on the
                 * SmPolicyDecision. */
                if (MediaComponent->tscai_input_dl &&
                        !MediaComponent->is_tscai_input_dl_null) {
                    OpenAPI_tscai_input_container_t *Tin =
                        MediaComponent->tscai_input_dl;
                    ogs_tscai_input_t *tdl = &media_component->tscai_input_dl;
                    tdl->present = true;
                    tdl->is_periodicity = Tin->is_periodicity;
                    tdl->periodicity = Tin->periodicity;
                    if (Tin->burst_arrival_time)
                        ogs_cpystrn(tdl->burst_arrival_time,
                                Tin->burst_arrival_time, OGS_TSCAI_BAT_STR_LEN);
                    tdl->is_sur_time_in_num_msg = Tin->is_sur_time_in_num_msg;
                    tdl->sur_time_in_num_msg = Tin->sur_time_in_num_msg;
                    tdl->is_sur_time_in_time = Tin->is_sur_time_in_time;
                    tdl->sur_time_in_time = Tin->sur_time_in_time;
                }
                if (MediaComponent->tscai_input_ul &&
                        !MediaComponent->is_tscai_input_ul_null) {
                    OpenAPI_tscai_input_container_t *Tin =
                        MediaComponent->tscai_input_ul;
                    ogs_tscai_input_t *tul = &media_component->tscai_input_ul;
                    tul->present = true;
                    tul->is_periodicity = Tin->is_periodicity;
                    tul->periodicity = Tin->periodicity;
                    if (Tin->burst_arrival_time)
                        ogs_cpystrn(tul->burst_arrival_time,
                                Tin->burst_arrival_time, OGS_TSCAI_BAT_STR_LEN);
                    tul->is_sur_time_in_num_msg = Tin->is_sur_time_in_num_msg;
                    tul->sur_time_in_num_msg = Tin->sur_time_in_num_msg;
                    tul->is_sur_time_in_time = Tin->is_sur_time_in_time;
                    tul->sur_time_in_time = Tin->sur_time_in_time;
                }

                /* Map the AF's TsnQosContainer to a standardized delay-critical
                 * GBR 5QI (TS 29.514 §5.6.2.35 -> TS 23.501 §5.28.4); the CNC-defined
                 * TSCAI is carried separately (tscaiInput), unaffected by the 5QI. */
                if (MediaComponent->tsn_qos)
                    pcf_map_tsn_qos_to_5qi(&media_component->dyn_5qi,
                            MediaComponent->tsn_qos->is_tsc_prio_level,
                            MediaComponent->tsn_qos->tsc_prio_level,
                            MediaComponent->tsn_qos->is_tsc_pack_delay,
                            MediaComponent->tsn_qos->tsc_pack_delay,
                            MediaComponent->tsn_qos->is_max_tsc_burst_size,
                            MediaComponent->tsn_qos->max_tsc_burst_size);

                SubComponentList = MediaComponent->med_sub_comps;
                OpenAPI_list_for_each(SubComponentList, node2) {
                    if (media_component->num_of_sub >=
                            OGS_ARRAY_SIZE(media_component->sub)) {
                        ogs_error("OVERFLOW media_component->num_of_sub "
                                "[%d:%d:%d]",
                                media_component->num_of_sub,
                                OGS_MAX_NUM_OF_MEDIA_SUB_COMPONENT,
                                (int)OGS_ARRAY_SIZE(media_component->sub));
                        break;
                    }
                    sub = &media_component->sub[media_component->num_of_sub];

                    SubComponentMap = node2->data;
                    if (SubComponentMap) {
                        SubComponent = SubComponentMap->value;
                        if (SubComponent) {
                            sub->flow_number = SubComponent->f_num;
                            sub->flow_usage = SubComponent->flow_usage;

                            fDescList = SubComponent->f_descs;
                            OpenAPI_list_for_each(fDescList, node3) {
                                ogs_flow_t *flow = NULL;

                                if (sub->num_of_flow >=
                                        OGS_ARRAY_SIZE(sub->flow)) {
                                    ogs_error(
                                        "OVERFLOW sub->num_of_flow [%d:%d:%d]",
                                        sub->num_of_flow,
                                        OGS_MAX_NUM_OF_FLOW_IN_MEDIA_SUB_COMPONENT,
                                        (int)OGS_ARRAY_SIZE(sub->flow));
                                    break;
                                }
                                flow = &sub->flow[sub->num_of_flow];
                                if (node3->data) {
                                    flow->description = ogs_strdup(node3->data);
                                    ogs_assert(flow->description);

                                    sub->num_of_flow++;
                                }
                            }

                            /* TSN Ethernet PDU session: carry the real L2
                             * stream filter (TS 29.514 EthFlowDescription)
                             * as an "eth|..." sentinel in flow->description so
                             * the SMF builds a proper Ethernet ogs_pf_content_t
                             * (TS 24.501 §9.11.4.13) for the UE QoS rule.
                             * A second flow for gPTP (EtherType 0x88F7) is
                             * always added so gPTP sync packets are classified
                             * onto this QoS flow. */
                            if (sub->num_of_flow == 0 &&
                                    SubComponent->ethf_descs &&
                                    SubComponent->ethf_descs->count > 0) {
                                OpenAPI_lnode_t *eth_node = NULL;
                                OpenAPI_eth_flow_description_t *eth_desc = NULL;
                                ogs_flow_t *flow = NULL;
                                ogs_flow_t *flow2 = NULL;
                                const char *dst_mac = "-";
                                const char *src_mac = "-";
                                char vid_str[8] = "-";
                                char pcp_str[4] = "-";
                                const char *eth_type = "-";

                                eth_node = SubComponent->ethf_descs->first;
                                if (eth_node)
                                    eth_desc = eth_node->data;

                                if (eth_desc) {
                                    if (eth_desc->dest_mac_addr)
                                        dst_mac = eth_desc->dest_mac_addr;
                                    if (eth_desc->source_mac_addr)
                                        src_mac = eth_desc->source_mac_addr;
                                    if (eth_desc->eth_type)
                                        eth_type = eth_desc->eth_type;
                                    /* Decode first VLAN tag: 4-hex TCI string
                                     * e.g. "A064" → PCP=5, VID=100 */
                                    if (eth_desc->vlan_tags &&
                                            eth_desc->vlan_tags->count > 0 &&
                                            eth_desc->vlan_tags->first) {
                                        const char *tag =
                                            (const char *)
                                            eth_desc->vlan_tags->first->data;
                                        if (tag) {
                                            long tci = strtol(tag, NULL, 16);
                                            int vid = (int)(tci & 0x0FFF);
                                            int pcp = (int)((tci >> 13) & 0x7);
                                            ogs_snprintf(vid_str,
                                                sizeof(vid_str), "%d", vid);
                                            ogs_snprintf(pcp_str,
                                                sizeof(pcp_str), "%d", pcp);
                                        }
                                    }
                                }

                                /* Primary flow: TSN stream L2 filter */
                                if (sub->num_of_flow <
                                        (int)OGS_ARRAY_SIZE(sub->flow)) {
                                    flow = &sub->flow[sub->num_of_flow];
                                    flow->description = ogs_msprintf(
                                        "eth|%s|%s|%s|%s|%s",
                                        dst_mac, src_mac,
                                        vid_str, pcp_str, eth_type);
                                    ogs_assert(flow->description);
                                    flow->direction = OGS_FLOW_BIDIRECTIONAL;
                                    sub->num_of_flow++;
                                    ogs_info("[PCF] EthFlowDescription -> "
                                        "L2 sentinel (TSN stream): %s",
                                        flow->description);
                                }

                                /* Secondary flow: gPTP (EtherType 0x88F7) */
                                if (sub->num_of_flow <
                                        (int)OGS_ARRAY_SIZE(sub->flow)) {
                                    flow2 = &sub->flow[sub->num_of_flow];
                                    flow2->description =
                                        ogs_strdup("eth|-|-|-|-|88f7");
                                    ogs_assert(flow2->description);
                                    flow2->direction = OGS_FLOW_BIDIRECTIONAL;
                                    sub->num_of_flow++;
                                }
                            }
                            media_component->num_of_sub++;
                        }
                    }
                }
                ims_data.num_of_media_component++;
            }
        }
    }

    app_session = pcf_app_add(sess);
    ogs_assert(app_session);

    if (app_session->notif_uri)
        ogs_free(app_session->notif_uri);
    app_session->notif_uri = ogs_strdup(AscReqData->notif_uri);
    ogs_assert(app_session->notif_uri);

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("%s: ogs_sbi_client_add()", OGS_FUNC);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        if (!client) {
            strerror = ogs_msprintf("%s: ogs_sbi_client_add() failed",
                    OGS_FUNC);
            status = OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;
            ogs_freeaddrinfo(addr);
            goto cleanup;
        }
    }
    OGS_SBI_SETUP_CLIENT(&app_session->naf, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    rv = pcf_db_qos_data(
            pcf_ue_sm->supi,
            sess->home.presence == true ? &sess->home.plmn_id : NULL,
            &sess->s_nssai, sess->dnn, &session_data);
    if (rv != OGS_OK) {
        strerror = ogs_msprintf("[%s:%d] Cannot find SUPI in DB",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_NOT_FOUND;
        goto cleanup;
    }

    memset(&SmPolicyDecision, 0, sizeof(SmPolicyDecision));

    PccRuleList = OpenAPI_list_create();
    ogs_assert(PccRuleList);

    QosDecisionList = OpenAPI_list_create();
    ogs_assert(QosDecisionList);
    QosCharsList = OpenAPI_list_create();
    ogs_assert(QosCharsList);

    for (i = 0; i < ims_data.num_of_media_component; i++) {
        int flow_presence = 0;

        ogs_pcc_rule_t *pcc_rule = NULL;
        ogs_pcc_rule_t *db_pcc_rule = NULL;
        uint8_t qos_index = 0;
        ogs_media_component_t *media_component = &ims_data.media_component[i];

        if (media_component->media_type == OpenAPI_media_type_NULL) {
            strerror = ogs_msprintf("[%s:%d] Media-Type is Required",
                    pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }

        switch(media_component->media_type) {
        case OpenAPI_media_type_AUDIO:
            qos_index = OGS_QOS_INDEX_1;
            break;
        case OpenAPI_media_type_VIDEO:
            qos_index = OGS_QOS_INDEX_2;
            break;
        case OpenAPI_media_type_CONTROL:
            qos_index = OGS_QOS_INDEX_5;
            break;
        case OpenAPI_media_type_DATA:
            /* TSN/Ethernet flows use medType DATA (TS 29.514 §5.6.2.7); take the
             * baseline QoS template from the provisioned index 1 PCC rule — the
             * dynamic 5QI derived from tsnQos overrides it below. */
            qos_index = OGS_QOS_INDEX_1;
            break;
        default:
            strerror = ogs_msprintf("[%s:%d] Unknown Media-Type [%d]",
                    pcf_ue_sm->supi, sess->psi, media_component->media_type);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }

        for (j = 0; j < session_data.num_of_pcc_rule; j++) {
            if (session_data.pcc_rule[j].qos.index == qos_index) {
                db_pcc_rule = &session_data.pcc_rule[j];
                break;
            }
        }

        if (!db_pcc_rule &&
            (media_component->media_type == OpenAPI_media_type_CONTROL)) {
            /*
             * Check for default bearer for IMS signalling
             * QCI 5 and ARP 1
             */
            if (session_data.session.qos.index != OGS_QOS_INDEX_5 ||
                session_data.session.qos.arp.priority_level != 1) {
                strerror = ogs_msprintf("[%s:%d] CHECK WEBUI : "
                    "Even the Default Bearer(QCI:%d,ARP:%d) "
                    "cannot support IMS signalling.",
                    pcf_ue_sm->supi, sess->psi,
                    session_data.session.qos.index,
                    session_data.session.qos.arp.priority_level);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            } else {
                continue;
            }
        }

        if (!db_pcc_rule) {
            strerror = ogs_msprintf("[%s:%d] CHECK WEBUI : "
                "No PCC Rule in DB [QoS Index:%d] - "
                "Please add PCC Rule using WEBUI",
                pcf_ue_sm->supi, sess->psi, qos_index);
            status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
            goto cleanup;
        }

        for (j = 0; j < app_session->num_of_pcc_rule; j++) {
            if (app_session->pcc_rule[j].qos.index == qos_index) {
                pcc_rule = &app_session->pcc_rule[j];
                break;
            }
        }

        if (!pcc_rule) {
            pcc_rule = &app_session->pcc_rule[app_session->num_of_pcc_rule];
            ogs_assert(pcc_rule);

            pcc_rule->id = ogs_msprintf("%s-a%s",
                            db_pcc_rule->id, app_session->app_session_id);
            ogs_assert(pcc_rule->id);

            memcpy(&pcc_rule->qos, &db_pcc_rule->qos, sizeof(ogs_qos_t));

            pcc_rule->flow_status = db_pcc_rule->flow_status;
            pcc_rule->precedence = db_pcc_rule->precedence;

            /* Install Flow */
            flow_presence = 1;
            rv = ogs_pcc_rule_install_flow_from_media(
                    pcc_rule, media_component);
            if (rv != OGS_OK) {
                strerror = ogs_msprintf("[%s:%d] install_flow() failed",
                    pcf_ue_sm->supi, sess->psi);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            }

            app_session->num_of_pcc_rule++;

        } else {
            int count = 0;

            /* Check Flow */
            count = ogs_pcc_rule_num_of_flow_equal_to_media(
                    pcc_rule, media_component);
            if (count == -1) {
                strerror = ogs_msprintf("[%s:%d] matched_flow() failed",
                    pcf_ue_sm->supi, sess->psi);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            }

            if (pcc_rule->num_of_flow != count) {
                /* Re-install Flow */
                flow_presence = 1;
                rv = ogs_pcc_rule_install_flow_from_media(
                        pcc_rule, media_component);
                if (rv != OGS_OK) {
                    strerror = ogs_msprintf("[%s:%d] re-install_flow() failed",
                        pcf_ue_sm->supi, sess->psi);
                    status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                    goto cleanup;
                }
            }
        }

        /* Update QoS */
        rv = ogs_pcc_rule_update_qos_from_media(pcc_rule, media_component);
        if (rv != OGS_OK) {
            strerror = ogs_msprintf("[%s:%d] update_qos() failed",
                pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
            goto cleanup;
        }

        /* if we failed to get QoS from IMS, apply WEBUI QoS */
        if (pcc_rule->qos.mbr.downlink == 0)
            pcc_rule->qos.mbr.downlink = db_pcc_rule->qos.mbr.downlink;
        if (pcc_rule->qos.mbr.uplink == 0)
            pcc_rule->qos.mbr.uplink = db_pcc_rule->qos.mbr.uplink;
        if (pcc_rule->qos.gbr.downlink == 0)
            pcc_rule->qos.gbr.downlink = db_pcc_rule->qos.gbr.downlink;
        if (pcc_rule->qos.gbr.uplink == 0)
            pcc_rule->qos.gbr.uplink = db_pcc_rule->qos.gbr.uplink;

        /**************************************************************
         * Build PCC Rule & QoS Decision
         *************************************************************/
        PccRule = ogs_sbi_build_pcc_rule(pcc_rule, flow_presence);
        ogs_assert(PccRule->pcc_rule_id);

        PccRuleMap = OpenAPI_map_create(PccRule->pcc_rule_id, PccRule);
        ogs_assert(PccRuleMap);

        OpenAPI_list_add(PccRuleList, PccRuleMap);

        QosData = ogs_sbi_build_qos_data(pcc_rule);
        ogs_assert(QosData);
        ogs_assert(QosData->qos_id);

        QosDecisionMap = OpenAPI_map_create(QosData->qos_id, QosData);
        ogs_assert(QosDecisionMap);

        OpenAPI_list_add(QosDecisionList, QosDecisionMap);

        /* For a dynamically-assigned 5QI, signal the authorized QoS
         * characteristics in the SmPolicyDecision qosChars, keyed by the 5QI
         * value (TS 29.512 §4.2.6.6.3). QosData->5qi references this entry. */
        QosChars = ogs_sbi_build_qos_characteristics(pcc_rule);
        if (QosChars) {
            QosCharsMap = OpenAPI_map_create(
                    ogs_msprintf("%d", QosChars->_5qi), QosChars);
            ogs_assert(QosCharsMap);
            OpenAPI_list_add(QosCharsList, QosCharsMap);
        }
    }

    if (PccRuleList->count)
        SmPolicyDecision.pcc_rules = PccRuleList;

    if (QosDecisionList->count)
        SmPolicyDecision.qos_decs = QosDecisionList;

    if (QosCharsList->count)
        SmPolicyDecision.qos_chars = QosCharsList;

    memset(&sendmsg, 0, sizeof(sendmsg));

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NPCF_POLICYAUTHORIZATION;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] = (char *)OGS_SBI_RESOURCE_NAME_APP_SESSIONS;
    header.resource.component[1] = (char *)app_session->app_session_id;
    sendmsg.http.location = ogs_sbi_server_uri(server, &header);
    ogs_assert(sendmsg.http.location);

    /* forward the AF's per-port PMIC containers onto the
     * SmPolicyDecision toward the SMF (TS 29.514 -> TS 29.512). Shallow copy —
     * AscReqData outlives the update-notify send. */
    SmPolicyDecision.tsn_port_man_cont_dstt = AscReqData->tsn_port_man_cont_dstt;
    SmPolicyDecision.tsn_port_man_cont_nwtts =
        AscReqData->tsn_port_man_cont_nwtts;

    sendmsg.AppSessionContext = recvmsg->AppSessionContext;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_CREATED);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    ogs_free(sendmsg.http.location);

    /* Also send the update-notify for a PMIC-only decision (no PCC rules / QoS
     * decisions): a bridge-management app-session forwards the 802.1Qbv gate schedule
     * (tsnPortManContDstt/Nwtts) to the SMF without requesting any QoS flow. */
    if (PccRuleList->count || QosDecisionList->count ||
            SmPolicyDecision.tsn_port_man_cont_dstt ||
            (SmPolicyDecision.tsn_port_man_cont_nwtts &&
             SmPolicyDecision.tsn_port_man_cont_nwtts->first)) {
        ogs_assert(true == pcf_sbi_send_smpolicycontrol_update_notify(
                                sess, &SmPolicyDecision));
    }

    OpenAPI_list_for_each(PccRuleList, node) {
        PccRuleMap = node->data;
        if (PccRuleMap) {
            PccRule = PccRuleMap->value;
            if (PccRule)
                ogs_sbi_free_pcc_rule(PccRule);
            ogs_free(PccRuleMap);
        }
    }
    OpenAPI_list_free(PccRuleList);

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            QosData = QosDecisionMap->value;
            if (QosData)
                ogs_sbi_free_qos_data(QosData);
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);

    OpenAPI_list_for_each(QosCharsList, node) {
        QosCharsMap = node->data;
        if (QosCharsMap) {
            QosChars = QosCharsMap->value;
            if (QosChars)
                OpenAPI_qos_characteristics_free(QosChars);
            if (QosCharsMap->key)
                ogs_free(QosCharsMap->key);
            ogs_free(QosCharsMap);
        }
    }
    OpenAPI_list_free(QosCharsList);

    ogs_ims_data_free(&ims_data);
    OGS_SESSION_DATA_FREE(&session_data);

    return true;

cleanup:
    ogs_assert(status);
    ogs_assert(strerror);
    ogs_error("%s", strerror);
    ogs_assert(true ==
        ogs_sbi_server_send_error(stream, status, recvmsg, strerror, NULL,
                NULL));
    ogs_free(strerror);

    OpenAPI_list_for_each(PccRuleList, node) {
        PccRuleMap = node->data;
        if (PccRuleMap) {
            PccRule = PccRuleMap->value;
            if (PccRule)
                ogs_sbi_free_pcc_rule(PccRule);
            ogs_free(PccRuleMap);
        }
    }
    OpenAPI_list_free(PccRuleList);

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            QosData = QosDecisionMap->value;
            if (QosData)
                ogs_sbi_free_qos_data(QosData);
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);

    OpenAPI_list_for_each(QosCharsList, node) {
        QosCharsMap = node->data;
        if (QosCharsMap) {
            QosChars = QosCharsMap->value;
            if (QosChars)
                OpenAPI_qos_characteristics_free(QosChars);
            if (QosCharsMap->key)
                ogs_free(QosCharsMap->key);
            ogs_free(QosCharsMap);
        }
    }
    OpenAPI_list_free(QosCharsList);

    ogs_ims_data_free(&ims_data);
    OGS_SESSION_DATA_FREE(&session_data);

    return false;
}

bool pcf_npcf_policyauthorization_handle_update(
        pcf_sess_t *sess, pcf_app_t *app_session,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    int i, j, rv, status = 0;
    char *strerror = NULL;
    pcf_ue_sm_t *pcf_ue_sm = NULL;

    OpenAPI_app_session_context_update_data_patch_t
        *AppSessionContextUpdateDataPatch = NULL;
    OpenAPI_app_session_context_update_data_t *AscUpdateData = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_session_data_t session_data;

    ogs_ims_data_t ims_data;
    ogs_media_component_t *media_component = NULL;
    ogs_media_sub_component_t *sub = NULL;

    OpenAPI_list_t *MediaComponentList = NULL;
    OpenAPI_map_t *MediaComponentMap = NULL;
    OpenAPI_media_component_rm_t *MediaComponent = NULL;

    OpenAPI_list_t *SubComponentList = NULL;
    OpenAPI_map_t *SubComponentMap = NULL;
    OpenAPI_media_sub_component_rm_t *SubComponent = NULL;

    OpenAPI_list_t *fDescList = NULL;

    OpenAPI_sm_policy_decision_t SmPolicyDecision;

    OpenAPI_list_t *PccRuleList = NULL;
    OpenAPI_map_t *PccRuleMap = NULL;
    OpenAPI_pcc_rule_t *PccRule = NULL;

    OpenAPI_list_t *QosDecisionList = NULL;
    OpenAPI_map_t *QosDecisionMap = NULL;
    OpenAPI_qos_data_t *QosData = NULL;
    OpenAPI_list_t *QosCharsList = NULL;
    OpenAPI_map_t *QosCharsMap = NULL;
    OpenAPI_qos_characteristics_t *QosChars = NULL;

    OpenAPI_lnode_t *node = NULL, *node2 = NULL, *node3 = NULL;

    ogs_assert(sess);
    pcf_ue_sm = pcf_ue_sm_find_by_id(sess->pcf_ue_sm_id);
    ogs_assert(app_session);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    memset(&ims_data, 0, sizeof(ims_data));
    memset(&session_data, 0, sizeof(ogs_session_data_t));

    AppSessionContextUpdateDataPatch =
        recvmsg->AppSessionContextUpdateDataPatch;
    if (!AppSessionContextUpdateDataPatch) {
        strerror = ogs_msprintf("[%s:%d] No AppSessionContextUpdateDataPatch",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    AscUpdateData = AppSessionContextUpdateDataPatch->asc_req_data;
    if (!AscUpdateData) {
        strerror = ogs_msprintf("[%s:%d] No AscUpdateData",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!AscUpdateData->med_components) {
        strerror = ogs_msprintf("[%s:%d] No AscUpdateData->MediaCompoenent",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    MediaComponentList = AscUpdateData->med_components;
    OpenAPI_list_for_each(MediaComponentList, node) {
        MediaComponentMap = node->data;
        if (MediaComponentMap) {
            MediaComponent = MediaComponentMap->value;
            if (MediaComponent) {
                if (ims_data.num_of_media_component >=
                        OGS_ARRAY_SIZE(ims_data.media_component)) {
                    ogs_error("OVERFLOW ims_data.num_of_media_component "
                            "[%d:%d:%d]",
                            ims_data.num_of_media_component,
                            OGS_MAX_NUM_OF_MEDIA_COMPONENT,
                            (int)OGS_ARRAY_SIZE(ims_data.media_component));
                    break;
                }
                media_component = &ims_data.
                    media_component[ims_data.num_of_media_component];

                media_component->media_component_number =
                    MediaComponent->med_comp_n;
                media_component->media_type = MediaComponent->med_type;
                if (MediaComponent->mar_bw_dl)
                    media_component->max_requested_bandwidth_dl =
                        ogs_sbi_bitrate_from_string(MediaComponent->mar_bw_dl);
                if (MediaComponent->mar_bw_ul)
                    media_component->max_requested_bandwidth_ul =
                        ogs_sbi_bitrate_from_string(MediaComponent->mar_bw_ul);
                if (MediaComponent->mir_bw_dl)
                    media_component->min_requested_bandwidth_dl =
                        ogs_sbi_bitrate_from_string(MediaComponent->mir_bw_dl);
                if (MediaComponent->mir_bw_ul)
                    media_component->min_requested_bandwidth_ul =
                        ogs_sbi_bitrate_from_string(MediaComponent->mir_bw_ul);
                if (MediaComponent->rr_bw)
                    media_component->rr_bandwidth =
                        ogs_sbi_bitrate_from_string(MediaComponent->rr_bw);
                if (MediaComponent->rs_bw)
                    media_component->rs_bandwidth =
                        ogs_sbi_bitrate_from_string(MediaComponent->rs_bw);
                media_component->flow_status = MediaComponent->f_status;

                /* capture the AF's TSCAI input containers (TS 29.514)
                 * into the internal media component so they are carried onto
                 * the PCC rule and emitted toward the SMF on the
                 * SmPolicyDecision. */
                if (MediaComponent->tscai_input_dl &&
                        !MediaComponent->is_tscai_input_dl_null) {
                    OpenAPI_tscai_input_container_t *Tin =
                        MediaComponent->tscai_input_dl;
                    ogs_tscai_input_t *tdl = &media_component->tscai_input_dl;
                    tdl->present = true;
                    tdl->is_periodicity = Tin->is_periodicity;
                    tdl->periodicity = Tin->periodicity;
                    if (Tin->burst_arrival_time)
                        ogs_cpystrn(tdl->burst_arrival_time,
                                Tin->burst_arrival_time, OGS_TSCAI_BAT_STR_LEN);
                    tdl->is_sur_time_in_num_msg = Tin->is_sur_time_in_num_msg;
                    tdl->sur_time_in_num_msg = Tin->sur_time_in_num_msg;
                    tdl->is_sur_time_in_time = Tin->is_sur_time_in_time;
                    tdl->sur_time_in_time = Tin->sur_time_in_time;
                }
                if (MediaComponent->tscai_input_ul &&
                        !MediaComponent->is_tscai_input_ul_null) {
                    OpenAPI_tscai_input_container_t *Tin =
                        MediaComponent->tscai_input_ul;
                    ogs_tscai_input_t *tul = &media_component->tscai_input_ul;
                    tul->present = true;
                    tul->is_periodicity = Tin->is_periodicity;
                    tul->periodicity = Tin->periodicity;
                    if (Tin->burst_arrival_time)
                        ogs_cpystrn(tul->burst_arrival_time,
                                Tin->burst_arrival_time, OGS_TSCAI_BAT_STR_LEN);
                    tul->is_sur_time_in_num_msg = Tin->is_sur_time_in_num_msg;
                    tul->sur_time_in_num_msg = Tin->sur_time_in_num_msg;
                    tul->is_sur_time_in_time = Tin->is_sur_time_in_time;
                    tul->sur_time_in_time = Tin->sur_time_in_time;
                }

                /* Map the AF's TsnQosContainer to a standardized delay-critical
                 * GBR 5QI (TS 29.514 §5.6.2.35 -> TS 23.501 §5.28.4); the CNC-defined
                 * TSCAI is carried separately (tscaiInput), unaffected by the 5QI. */
                if (MediaComponent->tsn_qos)
                    pcf_map_tsn_qos_to_5qi(&media_component->dyn_5qi,
                            MediaComponent->tsn_qos->is_tsc_prio_level,
                            MediaComponent->tsn_qos->tsc_prio_level,
                            MediaComponent->tsn_qos->is_tsc_pack_delay,
                            MediaComponent->tsn_qos->tsc_pack_delay,
                            MediaComponent->tsn_qos->is_max_tsc_burst_size,
                            MediaComponent->tsn_qos->max_tsc_burst_size);

                SubComponentList = MediaComponent->med_sub_comps;
                OpenAPI_list_for_each(SubComponentList, node2) {
                    if (media_component->num_of_sub >=
                            OGS_ARRAY_SIZE(media_component->sub)) {
                        ogs_error("OVERFLOW media_component->num_of_sub "
                                "[%d:%d:%d]",
                                media_component->num_of_sub,
                                OGS_MAX_NUM_OF_MEDIA_SUB_COMPONENT,
                                (int)OGS_ARRAY_SIZE(media_component->sub));
                        break;
                    }
                    sub = &media_component->sub[media_component->num_of_sub];

                    SubComponentMap = node2->data;
                    if (SubComponentMap) {
                        SubComponent = SubComponentMap->value;
                        if (SubComponent) {
                            sub->flow_number = SubComponent->f_num;
                            sub->flow_usage = SubComponent->flow_usage;

                            fDescList = SubComponent->f_descs;
                            OpenAPI_list_for_each(fDescList, node3) {
                                ogs_flow_t *flow = NULL;

                                if (sub->num_of_flow >=
                                        OGS_ARRAY_SIZE(sub->flow)) {
                                    ogs_error(
                                        "OVERFLOW sub->num_of_flow [%d:%d:%d]",
                                        sub->num_of_flow,
                                        OGS_MAX_NUM_OF_FLOW_IN_MEDIA_SUB_COMPONENT,
                                        (int)OGS_ARRAY_SIZE(sub->flow));
                                    break;
                                }
                                flow = &sub->flow[sub->num_of_flow];
                                if (node3->data) {
                                    flow->description = ogs_strdup(node3->data);
                                    ogs_assert(flow->description);

                                    sub->num_of_flow++;
                                }
                            }

                            /* TSN Ethernet PDU session: carry the real L2
                             * stream filter (TS 29.514 EthFlowDescription)
                             * as an "eth|..." sentinel in flow->description so
                             * the SMF builds a proper Ethernet ogs_pf_content_t
                             * (TS 24.501 §9.11.4.13) for the UE QoS rule.
                             * A second flow for gPTP (EtherType 0x88F7) is
                             * always added so gPTP sync packets are classified
                             * onto this QoS flow. */
                            if (sub->num_of_flow == 0 &&
                                    SubComponent->ethf_descs &&
                                    SubComponent->ethf_descs->count > 0) {
                                OpenAPI_lnode_t *eth_node = NULL;
                                OpenAPI_eth_flow_description_t *eth_desc = NULL;
                                ogs_flow_t *flow = NULL;
                                ogs_flow_t *flow2 = NULL;
                                const char *dst_mac = "-";
                                const char *src_mac = "-";
                                char vid_str[8] = "-";
                                char pcp_str[4] = "-";
                                const char *eth_type = "-";

                                eth_node = SubComponent->ethf_descs->first;
                                if (eth_node)
                                    eth_desc = eth_node->data;

                                if (eth_desc) {
                                    if (eth_desc->dest_mac_addr)
                                        dst_mac = eth_desc->dest_mac_addr;
                                    if (eth_desc->source_mac_addr)
                                        src_mac = eth_desc->source_mac_addr;
                                    if (eth_desc->eth_type)
                                        eth_type = eth_desc->eth_type;
                                    if (eth_desc->vlan_tags &&
                                            eth_desc->vlan_tags->count > 0 &&
                                            eth_desc->vlan_tags->first) {
                                        const char *tag =
                                            (const char *)
                                            eth_desc->vlan_tags->first->data;
                                        if (tag) {
                                            long tci = strtol(tag, NULL, 16);
                                            int vid = (int)(tci & 0x0FFF);
                                            int pcp = (int)((tci >> 13) & 0x7);
                                            ogs_snprintf(vid_str,
                                                sizeof(vid_str), "%d", vid);
                                            ogs_snprintf(pcp_str,
                                                sizeof(pcp_str), "%d", pcp);
                                        }
                                    }
                                }

                                /* Primary flow: TSN stream L2 filter */
                                if (sub->num_of_flow <
                                        (int)OGS_ARRAY_SIZE(sub->flow)) {
                                    flow = &sub->flow[sub->num_of_flow];
                                    flow->description = ogs_msprintf(
                                        "eth|%s|%s|%s|%s|%s",
                                        dst_mac, src_mac,
                                        vid_str, pcp_str, eth_type);
                                    ogs_assert(flow->description);
                                    flow->direction = OGS_FLOW_BIDIRECTIONAL;
                                    sub->num_of_flow++;
                                    ogs_info("[PCF] EthFlowDescription -> "
                                        "L2 sentinel (TSN stream): %s",
                                        flow->description);
                                }

                                /* Secondary flow: gPTP (EtherType 0x88F7) */
                                if (sub->num_of_flow <
                                        (int)OGS_ARRAY_SIZE(sub->flow)) {
                                    flow2 = &sub->flow[sub->num_of_flow];
                                    flow2->description =
                                        ogs_strdup("eth|-|-|-|-|88f7");
                                    ogs_assert(flow2->description);
                                    flow2->direction = OGS_FLOW_BIDIRECTIONAL;
                                    sub->num_of_flow++;
                                }
                            }
                            media_component->num_of_sub++;
                        }
                    }
                }
                ims_data.num_of_media_component++;
            }
        }
    }

    rv = pcf_db_qos_data(
            pcf_ue_sm->supi,
            sess->home.presence == true ? &sess->home.plmn_id : NULL,
            &sess->s_nssai, sess->dnn, &session_data);
    if (rv != OGS_OK) {
        strerror = ogs_msprintf("[%s:%d] Cannot find SUPI in DB",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_NOT_FOUND;
        goto cleanup;
    }

    memset(&SmPolicyDecision, 0, sizeof(SmPolicyDecision));

    PccRuleList = OpenAPI_list_create();
    ogs_assert(PccRuleList);

    QosDecisionList = OpenAPI_list_create();
    ogs_assert(QosDecisionList);
    QosCharsList = OpenAPI_list_create();
    ogs_assert(QosCharsList);

    for (i = 0; i < ims_data.num_of_media_component; i++) {
        int flow_presence = 0;

        ogs_pcc_rule_t *pcc_rule = NULL;
        ogs_pcc_rule_t *db_pcc_rule = NULL;
        uint8_t qos_index = 0;
        ogs_media_component_t *media_component = &ims_data.media_component[i];

        if (media_component->media_type == OpenAPI_media_type_NULL) {
            strerror = ogs_msprintf("[%s:%d] Media-Type is Required",
                    pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }

        switch(media_component->media_type) {
        case OpenAPI_media_type_AUDIO:
            qos_index = OGS_QOS_INDEX_1;
            break;
        case OpenAPI_media_type_VIDEO:
            qos_index = OGS_QOS_INDEX_2;
            break;
        case OpenAPI_media_type_CONTROL:
            qos_index = OGS_QOS_INDEX_5;
            break;
        case OpenAPI_media_type_DATA:
            /* TSN/Ethernet flows use medType DATA (TS 29.514 §5.6.2.7); take the
             * baseline QoS template from the provisioned index 1 PCC rule — the
             * dynamic 5QI derived from tsnQos overrides it below. */
            qos_index = OGS_QOS_INDEX_1;
            break;
        default:
            strerror = ogs_msprintf("[%s:%d] Unknown Media-Type [%d]",
                    pcf_ue_sm->supi, sess->psi, media_component->media_type);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }

        for (j = 0; j < session_data.num_of_pcc_rule; j++) {
            if (session_data.pcc_rule[j].qos.index == qos_index) {
                db_pcc_rule = &session_data.pcc_rule[j];
                break;
            }
        }

        if (!db_pcc_rule &&
            (media_component->media_type == OpenAPI_media_type_CONTROL)) {
            /*
             * Check for default bearer for IMS signalling
             * QCI 5 and ARP 1
             */
            if (session_data.session.qos.index != OGS_QOS_INDEX_5 ||
                session_data.session.qos.arp.priority_level != 1) {
                strerror = ogs_msprintf("[%s:%d] CHECK WEBUI : "
                    "Even the Default Bearer(QCI:%d,ARP:%d) "
                    "cannot support IMS signalling.",
                    pcf_ue_sm->supi, sess->psi,
                    session_data.session.qos.index,
                    session_data.session.qos.arp.priority_level);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            } else {
                continue;
            }
        }

        if (!db_pcc_rule) {
            strerror = ogs_msprintf("[%s:%d] CHECK WEBUI : "
                "No PCC Rule in DB [QoS Index:%d] - "
                "Please add PCC Rule using WEBUI",
                pcf_ue_sm->supi, sess->psi, qos_index);
            status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
            goto cleanup;
        }

        for (j = 0; j < app_session->num_of_pcc_rule; j++) {
            if (app_session->pcc_rule[j].qos.index == qos_index) {
                pcc_rule = &app_session->pcc_rule[j];
                break;
            }
        }

        if (!pcc_rule) {
            pcc_rule = &app_session->pcc_rule[app_session->num_of_pcc_rule];
            ogs_assert(pcc_rule);

            pcc_rule->id = ogs_strdup(app_session->app_session_id);
            ogs_assert(pcc_rule->id);

            memcpy(&pcc_rule->qos, &db_pcc_rule->qos, sizeof(ogs_qos_t));

            pcc_rule->flow_status = db_pcc_rule->flow_status;
            pcc_rule->precedence = db_pcc_rule->precedence;

            /* Install Flow */
            flow_presence = 1;
            rv = ogs_pcc_rule_install_flow_from_media(
                    pcc_rule, media_component);
            if (rv != OGS_OK) {
                strerror = ogs_msprintf("[%s:%d] install_flow() failed",
                    pcf_ue_sm->supi, sess->psi);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            }

            app_session->num_of_pcc_rule++;

        } else {
            int count = 0;

            /* Check Flow */
            count = ogs_pcc_rule_num_of_flow_equal_to_media(
                    pcc_rule, media_component);
            if (count == -1) {
                strerror = ogs_msprintf("[%s:%d] matched_flow() failed",
                    pcf_ue_sm->supi, sess->psi);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            }

            if (pcc_rule->num_of_flow != count) {
                /* Re-install Flow */
                flow_presence = 1;
                rv = ogs_pcc_rule_install_flow_from_media(
                        pcc_rule, media_component);
                if (rv != OGS_OK) {
                    strerror = ogs_msprintf("[%s:%d] re-install_flow() failed",
                        pcf_ue_sm->supi, sess->psi);
                    status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                    goto cleanup;
                }
            }
        }

        /* Update QoS */
        rv = ogs_pcc_rule_update_qos_from_media(pcc_rule, media_component);
        if (rv != OGS_OK) {
            strerror = ogs_msprintf("[%s:%d] update_qos() failed",
                pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
            goto cleanup;
        }

        /* if we failed to get QoS from IMS, apply WEBUI QoS */
        if (pcc_rule->qos.mbr.downlink == 0)
            pcc_rule->qos.mbr.downlink = db_pcc_rule->qos.mbr.downlink;
        if (pcc_rule->qos.mbr.uplink == 0)
            pcc_rule->qos.mbr.uplink = db_pcc_rule->qos.mbr.uplink;
        if (pcc_rule->qos.gbr.downlink == 0)
            pcc_rule->qos.gbr.downlink = db_pcc_rule->qos.gbr.downlink;
        if (pcc_rule->qos.gbr.uplink == 0)
            pcc_rule->qos.gbr.uplink = db_pcc_rule->qos.gbr.uplink;

        /**************************************************************
         * Build PCC Rule & QoS Decision
         *************************************************************/
        PccRule = ogs_sbi_build_pcc_rule(pcc_rule, flow_presence);
        ogs_assert(PccRule->pcc_rule_id);

        PccRuleMap = OpenAPI_map_create(PccRule->pcc_rule_id, PccRule);
        ogs_assert(PccRuleMap);

        OpenAPI_list_add(PccRuleList, PccRuleMap);

        QosData = ogs_sbi_build_qos_data(pcc_rule);
        ogs_assert(QosData);
        ogs_assert(QosData->qos_id);

        QosDecisionMap = OpenAPI_map_create(QosData->qos_id, QosData);
        ogs_assert(QosDecisionMap);

        OpenAPI_list_add(QosDecisionList, QosDecisionMap);

        /* For a dynamically-assigned 5QI, signal the authorized QoS
         * characteristics in the SmPolicyDecision qosChars, keyed by the 5QI
         * value (TS 29.512 §4.2.6.6.3). QosData->5qi references this entry. */
        QosChars = ogs_sbi_build_qos_characteristics(pcc_rule);
        if (QosChars) {
            QosCharsMap = OpenAPI_map_create(
                    ogs_msprintf("%d", QosChars->_5qi), QosChars);
            ogs_assert(QosCharsMap);
            OpenAPI_list_add(QosCharsList, QosCharsMap);
        }
    }

    if (PccRuleList->count)
        SmPolicyDecision.pcc_rules = PccRuleList;

    if (QosDecisionList->count)
        SmPolicyDecision.qos_decs = QosDecisionList;

    if (QosCharsList->count)
        SmPolicyDecision.qos_chars = QosCharsList;

    memset(&sendmsg, 0, sizeof(sendmsg));

    sendmsg.AppSessionContextUpdateDataPatch =
        recvmsg->AppSessionContextUpdateDataPatch;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    if (PccRuleList->count || QosDecisionList->count) {
        ogs_assert(true == pcf_sbi_send_smpolicycontrol_update_notify(
                            sess, &SmPolicyDecision));
    }

    OpenAPI_list_for_each(PccRuleList, node) {
        PccRuleMap = node->data;
        if (PccRuleMap) {
            PccRule = PccRuleMap->value;
            if (PccRule)
                ogs_sbi_free_pcc_rule(PccRule);
            ogs_free(PccRuleMap);
        }
    }
    OpenAPI_list_free(PccRuleList);

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            QosData = QosDecisionMap->value;
            if (QosData)
                ogs_sbi_free_qos_data(QosData);
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);

    OpenAPI_list_for_each(QosCharsList, node) {
        QosCharsMap = node->data;
        if (QosCharsMap) {
            QosChars = QosCharsMap->value;
            if (QosChars)
                OpenAPI_qos_characteristics_free(QosChars);
            if (QosCharsMap->key)
                ogs_free(QosCharsMap->key);
            ogs_free(QosCharsMap);
        }
    }
    OpenAPI_list_free(QosCharsList);

    ogs_ims_data_free(&ims_data);
    OGS_SESSION_DATA_FREE(&session_data);

    return true;

cleanup:
    ogs_assert(status);
    ogs_assert(strerror);
    ogs_error("%s", strerror);
    ogs_assert(true ==
        ogs_sbi_server_send_error(stream, status, recvmsg, strerror,
                NULL, NULL));
    ogs_free(strerror);

    OpenAPI_list_for_each(PccRuleList, node) {
        PccRuleMap = node->data;
        if (PccRuleMap) {
            PccRule = PccRuleMap->value;
            if (PccRule)
                ogs_sbi_free_pcc_rule(PccRule);
            ogs_free(PccRuleMap);
        }
    }
    OpenAPI_list_free(PccRuleList);

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            QosData = QosDecisionMap->value;
            if (QosData)
                ogs_sbi_free_qos_data(QosData);
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);

    OpenAPI_list_for_each(QosCharsList, node) {
        QosCharsMap = node->data;
        if (QosCharsMap) {
            QosChars = QosCharsMap->value;
            if (QosChars)
                OpenAPI_qos_characteristics_free(QosChars);
            if (QosCharsMap->key)
                ogs_free(QosCharsMap->key);
            ogs_free(QosCharsMap);
        }
    }
    OpenAPI_list_free(QosCharsList);

    ogs_ims_data_free(&ims_data);
    OGS_SESSION_DATA_FREE(&session_data);

    return false;
}

bool pcf_npcf_policyauthorization_handle_delete(
        pcf_sess_t *sess, pcf_app_t *app_session,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    int i;

    OpenAPI_sm_policy_decision_t SmPolicyDecision;

    OpenAPI_list_t *PccRuleList = NULL;
    OpenAPI_map_t *PccRuleMap = NULL;

    OpenAPI_list_t *QosDecisionList = NULL;
    OpenAPI_map_t *QosDecisionMap = NULL;

    OpenAPI_lnode_t *node = NULL;

    ogs_assert(true == ogs_sbi_send_http_status_no_content(stream));

    ogs_assert(app_session);

    memset(&SmPolicyDecision, 0, sizeof(SmPolicyDecision));

    PccRuleList = OpenAPI_list_create();
    ogs_assert(PccRuleList);

    QosDecisionList = OpenAPI_list_create();
    ogs_assert(QosDecisionList);

    for (i = 0; i < app_session->num_of_pcc_rule; i++) {
        ogs_pcc_rule_t *pcc_rule = &app_session->pcc_rule[i];

        ogs_assert(pcc_rule);

        PccRuleMap = OpenAPI_map_create(pcc_rule->id, NULL);
        ogs_assert(PccRuleMap);

        OpenAPI_list_add(PccRuleList, PccRuleMap);

        QosDecisionMap = OpenAPI_map_create(pcc_rule->id, NULL);
        ogs_assert(QosDecisionMap);

        OpenAPI_list_add(QosDecisionList, QosDecisionMap);
    }

    if (PccRuleList->count)
        SmPolicyDecision.pcc_rules = PccRuleList;

    if (QosDecisionList->count)
        SmPolicyDecision.qos_decs = QosDecisionList;

    if (PccRuleList->count || QosDecisionList->count) {
        ogs_assert(true == pcf_sbi_send_smpolicycontrol_delete_notify(
                            sess, app_session, &SmPolicyDecision));
    } else {
        pcf_app_remove(app_session);
    }

    OpenAPI_list_for_each(PccRuleList, node) {
        PccRuleMap = node->data;
        if (PccRuleMap) {
            ogs_free(PccRuleMap);
        }
    }
    OpenAPI_list_free(PccRuleList);

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);

    return true;
}
