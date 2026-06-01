/*
 * Phase 6 Step 1 — SMF-local TSC context lifecycle.
 *
 * See tsc_context.h for the data model and the Issue 6-B/6-C rationale.
 */

#include "context.h"

tsc_context_t *smf_sess_tsc_add(smf_sess_t *sess)
{
    tsc_context_t *tsc = NULL;

    ogs_assert(sess);

    /* Idempotent: an existing context is updated in place (Step 2). */
    if (sess->tsc)
        return sess->tsc;

    tsc = ogs_calloc(1, sizeof(*tsc));
    if (!tsc) {
        ogs_error("ogs_calloc() failed");
        return NULL;
    }

    tsc->status = TSC_STATUS_ABSENT;
    tsc->pdu_session_id = sess->psi;

    sess->tsc = tsc;

    ogs_info("[SMF] TSC context created (PSI[%d])", sess->psi);

    return tsc;
}

void smf_sess_tsc_remove(smf_sess_t *sess)
{
    ogs_assert(sess);

    if (sess->tsc) {
        ogs_free(sess->tsc);
        sess->tsc = NULL;
    }
}
