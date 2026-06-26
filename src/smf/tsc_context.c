/*
 * SMF-local TSC context lifecycle.
 *
 * See tsc_context.h for the data model.
 */

#include "context.h"

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
