/*
 * Phase 6 Step 1 — SMF-local TSC (Time-Sensitive Communication) context.
 *
 * Frozen, SMF-local data model for per-session TSC assistance state on the
 * standards control-plane path (TSN AF -> PCF -> SMF -> NGAP). Holds the TSCAI
 * timing inputs received from upstream policy plus derived/status fields used
 * later for TSCAI derivation (Step 3) and downgrade decisions (Step 4).
 *
 * Issue 6-B: this state is deliberately NOT placed in the shared
 * lib/proto/types.h schema. It is attached to smf_sess_t via a single nullable
 * pointer (NULL for baseline, non-TSC sessions).
 * Issue 6-C: 3GPP-facing names use the tsc_ prefix (never tsn_).
 */

#ifndef SMF_TSC_CONTEXT_H
#define SMF_TSC_CONTEXT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration only — avoids a circular include with context.h, which
 * includes this header. */
typedef struct smf_sess_s smf_sess_t;

typedef enum {
    TSC_STATUS_ACTIVE,      /* full TSC assistance present and valid     */
    TSC_STATUS_PARTIAL,     /* some optional IEs absent, degraded hint   */
    TSC_STATUS_DOWNGRADED,  /* unsupported field or peer limit triggered */
    TSC_STATUS_ABSENT       /* no TSC assistance for this session        */
} tsc_status_t;

typedef struct {
    /* TSCAI inputs (TS 23.501 R17 Table 5.27.2-1; from tscaiInputUl/Dl,
     * TS 29.512) */
    uint64_t   periodicity_us;          /* TSCAI Periodicity                 */
    uint64_t   burst_arrival_time_tsn;  /* BEFORE clock conversion: TSN clock*/
    uint64_t   burst_arrival_time_5g;   /* AFTER  clock conversion: 5G clock */
                                        /* See TS 23.501 §5.27.2             */
    /* External-time minus 5GS-time offset (ns) used to convert the TSC
     * Assistance Container's external-GM burst arrival time to the 5GS clock
     * (TS 23.501 §5.27.2.4). Measured by the NW-TT/UPF and reported to the SMF
     * via the PFCP Clock Drift Report (TS 29.244 §5.26.4 / §8.2.149). 0 in a
     * single-time-domain deployment where the 5GS shares the external GM. */
    int64_t    clock_drift_offset_ns;
    uint32_t   survival_time_us;        /* TSCAI Survival Time; 0 = absent   */
    enum { TSC_UL, TSC_DL, TSC_BOTH } direction;  /* TSCAI flow direction    */

    /* QoS input — NOT part of TSCAI. Feeds the QoS MDBV characteristic
     * (TS 23.501 §5.7.3.7), not the TSC Assistance Information. */
    uint32_t   burst_size_bytes;        /* TSN max burst -> MDBV derivation  */

    /* Binding to the SMF session / QoS flow */
    uint8_t    qfi;
    uint32_t   pdu_session_id;

    /* Status */
    tsc_status_t status;
    char         downgrade_reason[128]; /* populated when DOWNGRADED         */
} tsc_context_t;

/*
 * Lifecycle helpers (defined in tsc_context.c).
 *
 *   smf_sess_tsc_add():    allocate the per-session TSC context on first TSC
 *                          assistance; returns the existing context on repeat
 *                          (Step-2 in-place update). Returns NULL only on
 *                          allocation failure.
 *   smf_sess_tsc_remove(): free the context and reset sess->tsc to NULL.
 *
 * Step 1 wires only the remove() on session release; the policy-driven add()
 * call is added in Step 2 (PCF -> SMF ingestion).
 */
/* Phase 6 Step 4: stable downgrade/partial reason strings (for Phase-7/8
 * scenario labeling). */
#define TSC_REASON_NO_PERIODICITY \
    "TSCAI missing mandatory periodicity; flow on baseline 5QI"
#define TSC_REASON_PERIODICITY_RANGE \
    "TSCAI periodicity exceeds NGAP max 640000 us; flow on baseline 5QI"
#define TSC_REASON_RAN_GBR \
    "NG-RAN cannot guarantee GFBR (TS 23.501 5.7.2.4); flow on baseline 5QI"

tsc_context_t *smf_sess_tsc_add(smf_sess_t *sess);
void           smf_sess_tsc_remove(smf_sess_t *sess);

/*
 * Phase 6 Step 4: set the TSC status and record a concrete reason, logging the
 * outcome (ogs_warn for PARTIAL/DOWNGRADED, ogs_info otherwise) so the baseline
 * fallback is explicit in worklog/logs/. reason may be NULL for ACTIVE/ABSENT.
 */
void smf_sess_tsc_set_status(tsc_context_t *tsc,
        tsc_status_t status, const char *reason);

/*
 * Phase 6 Step 3: derive the RAN-facing TSCAI (5G clock domain) from the
 * ingested context, ready for NGAP encoding (TS 23.501 §5.7.3.4 / TS 29.512).
 * Single-grandmaster topology (TS 23.501 §5.27.1) -> rateRatio = 1 and UPF
 * time-offset = 0, so periodicity passes through unchanged. The 5G-domain burst
 * arrival time is produced by the Phase-7 clock conversion; until then it is
 * absent (*has_bat = false) and never substituted with the TSN-domain value.
 */
void smf_sess_tsc_derive(const tsc_context_t *tsc,
        uint32_t *periodicity_5g, uint64_t *bat_5g, bool *has_bat);

#ifdef __cplusplus
}
#endif

#endif /* SMF_TSC_CONTEXT_H */
