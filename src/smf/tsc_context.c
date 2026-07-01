/*
 * SMF-local TSC context lifecycle.
 *
 * See tsc_context.h for the data model.
 */

#include "context.h"
#include "gsm-build.h"
#include "ngap-build.h"
#include "sbi-path.h"

static OGS_POOL(smf_tsc_context_pool, smf_tsc_context_t);

void smf_tsc_context_pool_init(int size) {
    ogs_pool_init(&smf_tsc_context_pool, size);
}

void smf_tsc_context_pool_final(void) {
    ogs_pool_final(&smf_tsc_context_pool);
}

smf_tsc_context_t *smf_sess_tsc_add(smf_sess_t *sess)
{
    smf_tsc_context_t *tsc = NULL;

    ogs_assert(sess);

    /* Idempotent: an existing context is updated in place. */
    if (sess->tsc)
        return sess->tsc;

    ogs_pool_alloc(&smf_tsc_context_pool, &tsc);
    if (!tsc) {
        ogs_error("ogs_pool_alloc() failed");
        return NULL;
    }
    memset(tsc, 0, sizeof(*tsc));

    tsc->status = SMF_TSC_STATUS_ABSENT;
    tsc->pdu_session_id = sess->psi;

    sess->tsc = tsc;

    ogs_info("[SMF] TSC context created (PSI[%d])", sess->psi);

    return tsc;
}

void smf_sess_tsc_remove(smf_sess_t *sess)
{
    ogs_assert(sess);

    if (sess->tsc) {
        ogs_pool_free(&smf_tsc_context_pool, sess->tsc);
        sess->tsc = NULL;
    }
}

void smf_sess_tsc_set_status(smf_tsc_context_t *tsc,
        smf_tsc_status_e status, const char *reason)
{
    ogs_assert(tsc);

    tsc->status = status;
    ogs_cpystrn(tsc->downgrade_reason, reason ? reason : "",
            sizeof(tsc->downgrade_reason));

    if (status == SMF_TSC_STATUS_PARTIAL || status == SMF_TSC_STATUS_DOWNGRADED)
        ogs_warn("[SMF] TSC %s: %s (periodicity[%llu us])",
                status == SMF_TSC_STATUS_PARTIAL ? "PARTIAL" : "DOWNGRADED",
                tsc->downgrade_reason,
                (unsigned long long)tsc->periodicity_us);
    else
        ogs_info("[SMF] TSC status[%d]", status);
}

void smf_sess_tsc_derive(const smf_tsc_context_t *tsc,
        uint32_t *periodicity_5g, uint64_t *bat_5g, bool *has_bat)
{
    ogs_assert(tsc);
    ogs_assert(periodicity_5g);
    ogs_assert(bat_5g);
    ogs_assert(has_bat);

    /* rateRatio = 1 (single grandmaster): periodicity passes through. */
    *periodicity_5g = (uint32_t)tsc->periodicity_us;

    /* Burst arrival time is encoded only once the 5G-domain value exists (clock
     * drift conversion). The raw TSN-domain value is never emitted. */
    *has_bat = (tsc->burst_arrival_time_5g != 0);
    *bat_5g = tsc->burst_arrival_time_5g;
}

static int smf_tsc_count_gbr_bearers(smf_sess_t *sess)
{
    smf_bearer_t *qos_flow = NULL;
    int count = 0;

    ogs_assert(sess);

    ogs_list_for_each(&sess->bearer_list, qos_flow) {
        if (qos_flow->qos.index == SMF_TSC_GBR_5QI)
            count++;
    }

    ogs_list_for_each_entry(&sess->qos_flow_to_modify_list,
            qos_flow, to_modify_node) {
        smf_bearer_t *existing = NULL;
        bool in_bearer_list = false;

        if (qos_flow->qos.index != SMF_TSC_GBR_5QI)
            continue;

        ogs_list_for_each(&sess->bearer_list, existing) {
            if (existing == qos_flow) {
                in_bearer_list = true;
                break;
            }
        }
        if (!in_bearer_list)
            count++;
    }

    return count;
}

static smf_bearer_t *smf_tsc_find_qos_flow_by_5qi(
        smf_sess_t *sess, uint8_t five_qi)
{
    smf_bearer_t *qos_flow = NULL;
    smf_bearer_t *candidate = NULL;
    int match_count = 0;

    ogs_assert(sess);

    if (ogs_list_count(&sess->qos_flow_to_modify_list) > 0) {
        ogs_list_for_each_entry(&sess->qos_flow_to_modify_list,
                qos_flow, to_modify_node) {
            if (qos_flow->qos.index == five_qi) {
                candidate = qos_flow;
                match_count++;
            }
        }
        if (match_count == 1)
            return candidate;
    }

    candidate = NULL;
    match_count = 0;
    ogs_list_for_each(&sess->bearer_list, qos_flow) {
        if (qos_flow->qos.index == five_qi) {
            candidate = qos_flow;
            match_count++;
        }
    }
    if (match_count == 1)
        return candidate;

    return NULL;
}

void smf_tsc_bind_qfi(smf_sess_t *sess)
{
    smf_bearer_t *tsc_qos_flow = NULL;
    smf_bearer_t *qos_flow = NULL;
    smf_bearer_t *candidate = NULL;
    int match_count = 0;
    uint8_t previous_qfi = 0;

    ogs_assert(sess);

    if (!sess->tsc) {
        ogs_debug("[SMF] CP6_DBG tsc_qfi_bind_skip: PSI[%d] reason=no_tsc",
                sess->psi);
        return;
    }
    if (sess->tsc->status != SMF_TSC_STATUS_ACTIVE) {
        ogs_debug("[SMF] CP6_DBG tsc_qfi_bind_skip: PSI[%d] reason=not_active "
                "status[%d]", sess->psi, sess->tsc->status);
        return;
    }

    previous_qfi = sess->tsc->qfi;

    if (sess->tsc->pcc_rule_id[0] != '\0') {
        tsc_qos_flow = smf_qos_flow_find_by_pcc_rule_id(
                sess, sess->tsc->pcc_rule_id);
        if (!tsc_qos_flow &&
                ogs_list_count(&sess->qos_flow_to_modify_list) > 0) {
            candidate = NULL;
            match_count = 0;
            ogs_list_for_each_entry(&sess->qos_flow_to_modify_list,
                    qos_flow, to_modify_node) {
                if (qos_flow->pcc_rule.id &&
                        strcmp(qos_flow->pcc_rule.id,
                            sess->tsc->pcc_rule_id) == 0) {
                    candidate = qos_flow;
                    match_count++;
                }
            }
            if (match_count == 1)
                tsc_qos_flow = candidate;
        }
    }

    if (!tsc_qos_flow && sess->tsc->pcc_rule_id[0] != '\0' &&
            smf_tsc_count_gbr_bearers(sess) == 1) {
        ogs_list_for_each(&sess->bearer_list, qos_flow) {
            if (qos_flow->qos.index == SMF_TSC_GBR_5QI) {
                tsc_qos_flow = qos_flow;
                break;
            }
        }
        if (!tsc_qos_flow) {
            ogs_list_for_each_entry(&sess->qos_flow_to_modify_list,
                    qos_flow, to_modify_node) {
                if (qos_flow->qos.index == SMF_TSC_GBR_5QI) {
                    tsc_qos_flow = qos_flow;
                    break;
                }
            }
        }
    }

    if (!tsc_qos_flow)
        tsc_qos_flow = smf_tsc_find_qos_flow_by_5qi(sess, SMF_TSC_GBR_5QI);

    if (tsc_qos_flow) {
        sess->tsc->qfi = tsc_qos_flow->qfi;
        if (previous_qfi != tsc_qos_flow->qfi) {
            ogs_info("[SMF] CP6_DBG tsc_qfi_bind: PSI[%d] pcc_rule_id[%s] "
                     "qfi[%d]", sess->psi, sess->tsc->pcc_rule_id,
                     tsc_qos_flow->qfi);
        }
    } else {
        ogs_info("[SMF] CP6_DBG tsc_qfi_bind_fail: PSI[%d] reason=no_bearer "
                 "pcc_rule_id[%s]", sess->psi, sess->tsc->pcc_rule_id);
    }
}

bool smf_tsc_ngap_encode_on_qos_flow(
        smf_sess_t *sess, smf_bearer_t *qos_flow)
{
    ogs_assert(sess);
    ogs_assert(qos_flow);

    if (!sess->tsc || sess->tsc->status != SMF_TSC_STATUS_ACTIVE) {
        ogs_info("[SMF] CP6_DBG tsc_encode_skip: PSI[%d] qfi[%d] "
                 "reason=not_active", sess->psi, qos_flow->qfi);
        return false;
    }

    if (qos_flow->qfi == sess->tsc->qfi)
        return true;

    if (qos_flow->qos.index != SMF_TSC_GBR_5QI) {
        ogs_info("[SMF] CP6_DBG tsc_encode_skip: PSI[%d] qfi[%d] "
                 "reason=not_gbr", sess->psi, qos_flow->qfi);
        return false;
    }

    if (sess->tsc->pcc_rule_id[0] != '\0') {
        if (!qos_flow->pcc_rule.id ||
                strcmp(qos_flow->pcc_rule.id, sess->tsc->pcc_rule_id) != 0) {
            if (smf_tsc_count_gbr_bearers(sess) == 1) {
                sess->tsc->qfi = qos_flow->qfi;
                ogs_info("[SMF] CP6_DBG tsc_encode_single_gbr_fallback: "
                         "PSI[%d] qfi[%d] tsc_pcc[%s] flow_pcc[%s]",
                         sess->psi, qos_flow->qfi, sess->tsc->pcc_rule_id,
                         qos_flow->pcc_rule.id ? qos_flow->pcc_rule.id : "");
                return true;
            }
            ogs_info("[SMF] CP6_DBG tsc_encode_skip: PSI[%d] qfi[%d] "
                     "reason=pcc_mismatch tsc_pcc[%s] flow_pcc[%s]",
                     sess->psi, qos_flow->qfi, sess->tsc->pcc_rule_id,
                     qos_flow->pcc_rule.id ? qos_flow->pcc_rule.id : "");
            return false;
        }
    }

    sess->tsc->qfi = qos_flow->qfi;
    ogs_info("[SMF] CP6_DBG tsc_qfi_bind: PSI[%d] pcc_rule_id[%s] qfi[%d]",
             sess->psi, sess->tsc->pcc_rule_id, qos_flow->qfi);
    return true;
}

static smf_bearer_t *smf_tsc_find_gbr_qos_flow(smf_sess_t *sess)
{
    smf_bearer_t *tsc_qos_flow = NULL;

    ogs_assert(sess);

    if (!sess->tsc || sess->tsc->status != SMF_TSC_STATUS_ACTIVE)
        return NULL;

    if (sess->tsc->qfi != 0)
        tsc_qos_flow = smf_qos_flow_find_by_qfi(sess, sess->tsc->qfi);
    if (!tsc_qos_flow && sess->tsc->pcc_rule_id[0] != '\0')
        tsc_qos_flow = smf_qos_flow_find_by_pcc_rule_id(
                sess, sess->tsc->pcc_rule_id);
    if (!tsc_qos_flow)
        tsc_qos_flow = smf_tsc_find_qos_flow_by_5qi(sess, SMF_TSC_GBR_5QI);

    return tsc_qos_flow;
}

bool smf_tsc_send_n2_follow_up_if_needed(smf_sess_t *sess)
{
    smf_bearer_t *tsc_qos_flow = NULL;
    smf_n1_n2_message_transfer_param_t param;

    ogs_assert(sess);

    if (!sess->tsc || sess->tsc->status != SMF_TSC_STATUS_ACTIVE) {
        ogs_info("[SMF] CP6_DBG tsc_follow_up_skip: PSI[%d] reason=not_active",
                sess->psi);
        return false;
    }
    if (sess->tsc->n2_tsc_encoded) {
        ogs_info("[SMF] CP6_DBG tsc_follow_up_skip: PSI[%d] "
                 "reason=already_encoded", sess->psi);
        return false;
    }

    tsc_qos_flow = smf_tsc_find_gbr_qos_flow(sess);
    if (!tsc_qos_flow) {
        ogs_info("[SMF] CP6_DBG tsc_follow_up_skip: PSI[%d] reason=no_gbr_flow",
                sess->psi);
        return false;
    }

    ogs_info("[SMF] CP6_DBG tsc_follow_up_n1n2: PSI[%d] qfi[%d]",
            sess->psi, tsc_qos_flow->qfi);

    sess->tsc->n2_tsc_encoded = false;

    ogs_list_init(&sess->qos_flow_to_modify_list);
    ogs_list_add(&sess->qos_flow_to_modify_list, &tsc_qos_flow->to_modify_node);

    sess->pti = OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED;
    memset(&param, 0, sizeof(param));
    param.state = SMF_NETWORK_REQUESTED_QOS_FLOW_MODIFICATION;
    param.n1smbuf = gsm_build_pdu_session_modification_command(sess, 0, 0);
    ogs_assert(param.n1smbuf);
    param.n2smbuf =
        ngap_build_pdu_session_resource_modify_request_transfer(sess, true);
    ogs_assert(param.n2smbuf);

    smf_namf_comm_send_n1_n2_message_transfer(sess, NULL, &param);

    ogs_list_init(&sess->qos_flow_to_modify_list);

    return true;
}
