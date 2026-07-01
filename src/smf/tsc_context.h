/*
 * SMF-local TSC (Time-Sensitive Communication) context.
 *
 * Frozen, SMF-local data model for per-session TSC assistance state on the
 * standards control-plane path (TSN AF -> PCF -> SMF -> NGAP). Holds the TSCAI
 * timing inputs received from upstream policy plus derived/status fields used
 * later for TSCAI derivation and downgrade decisions.
 *
 * Issue 6-B: this state is deliberately NOT placed in the shared
 * lib/proto/types.h schema. It is attached to smf_sess_t via a single nullable
 * pointer (NULL for baseline, non-TSC sessions).
 * Issue 6-C: 3GPP-facing names use the tsc_ prefix (never tsn_).
 */

#ifndef SMF_TSC_CONTEXT_H
#define SMF_TSC_CONTEXT_H

#include "ogs-core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TS 29.512 PccRule.pccRuleId — no explicit max in the API schema; sized for
 * lab/PCF rule identifiers. */
#define OGS_MAX_PCC_RULE_ID_LEN         64

/* Forward declaration only — avoids a circular include with context.h, which
 * includes this header. */
typedef struct smf_sess_s smf_sess_t;
typedef struct smf_bearer_s smf_bearer_t;

typedef enum {
    SMF_TSC_DIR_UL,         /* uplink TSCAI flow only                    */
    SMF_TSC_DIR_DL,         /* downlink TSCAI flow only                  */
    SMF_TSC_DIR_BOTH        /* both uplink and downlink TSCAI flows      */
} smf_tsc_dir_e;

typedef enum {
    SMF_TSC_STATUS_ACTIVE,      /* full TSC assistance present and valid     */
    SMF_TSC_STATUS_PARTIAL,     /* some optional IEs absent, degraded hint   */
    SMF_TSC_STATUS_DOWNGRADED,  /* unsupported field or peer limit triggered */
    SMF_TSC_STATUS_ABSENT       /* no TSC assistance for this session        */
} smf_tsc_status_e;

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
    smf_tsc_dir_e direction;            /* TSCAI flow direction               */

    /* QoS input — NOT part of TSCAI. Feeds the QoS MDBV characteristic
     * (TS 23.501 §5.7.3.7), not the TSC Assistance Information. */
    uint32_t   burst_size_bytes;        /* TSN max burst -> MDBV derivation  */

    /* Binding to the SMF session / QoS flow (TS 23.501 §5.27.2 / TS 29.512) */
    char       pcc_rule_id[OGS_MAX_PCC_RULE_ID_LEN + 1];
    uint8_t    qfi;
    uint32_t   pdu_session_id;

    /* Status */
    smf_tsc_status_e status;
    char             downgrade_reason[128]; /* populated when DOWNGRADED      */

    /* Set true when NGAP modify transfer actually carries TSC Traffic
     * Characteristics for this session (ngap-build.c modify paths). */
    bool             n2_tsc_encoded;
} smf_tsc_context_t;

/*
 * Lifecycle helpers (defined in tsc_context.c).
 *
 *   smf_sess_tsc_add():    allocate the per-session TSC context on first TSC
 *                          assistance; returns the existing context on repeat
 *                          (in-place update). Returns NULL only on
 *                          allocation failure.
 *   smf_sess_tsc_remove(): free the context and reset sess->tsc to NULL.
 *
 * The context is removed on session release; the policy-driven add() call
 * fires on PCF -> SMF ingestion.
 */
/* Stable downgrade/partial reason strings (for scenario labeling). */
#define SMF_TSC_REASON_NO_PERIODICITY \
    "TSCAI missing mandatory periodicity; flow on baseline 5QI"
#define SMF_TSC_REASON_PERIODICITY_RANGE \
    "TSCAI periodicity exceeds NGAP max 640000 us; flow on baseline 5QI"
#define SMF_TSC_REASON_RAN_GBR \
    "NG-RAN cannot guarantee GFBR (TS 23.501 5.7.2.4); flow on baseline 5QI"

/* Standardized delay-critical GBR 5QI for TSN (TS 23.501 Table 5.7.4-1). */
#define SMF_TSC_GBR_5QI 85

void smf_tsc_context_pool_init(int size);
void smf_tsc_context_pool_final(void);

smf_tsc_context_t *smf_sess_tsc_add(smf_sess_t *sess);
void               smf_sess_tsc_remove(smf_sess_t *sess);

/*
 * Set the TSC status and record a concrete reason, logging the
 * outcome (ogs_warn for PARTIAL/DOWNGRADED, ogs_info otherwise) so the baseline
 * fallback is explicit in worklog/logs/. reason may be NULL for ACTIVE/ABSENT.
 */
void smf_sess_tsc_set_status(smf_tsc_context_t *tsc,
        smf_tsc_status_e status, const char *reason);

/*
 * Derive the RAN-facing TSCAI (5G clock domain) from the ingested context,
 * ready for NGAP encoding (TS 23.501 §5.7.3.4 / TS 29.512). Single-grandmaster
 * topology (TS 23.501 §5.27.1) -> rateRatio = 1 and UPF time-offset = 0, so
 * periodicity passes through unchanged. The 5G-domain burst arrival time is
 * produced by the clock conversion; until then it is absent (*has_bat = false)
 * and never substituted with the TSN-domain value.
 */
void smf_sess_tsc_derive(const smf_tsc_context_t *tsc,
        uint32_t *periodicity_5g, uint64_t *bat_5g, bool *has_bat);

/*
 * Bind sess->tsc->qfi to the QoS flow that carries TSC assistance (TS 23.501
 * §5.27.2): PCC rule id on the bearer list, then on qos_flow_to_modify_list,
 * then the sole delay-critical GBR (5QI 85) flow as last resort. No-op when TSC
 * is absent, not ACTIVE, or qfi is already set.
 */
void smf_tsc_bind_qfi(smf_sess_t *sess);

/*
 * Return true when TSC Traffic Characteristics should be encoded on this QoS
 * flow in an NGAP modify transfer. Re-binds qfi to the delay-critical GBR
 * (5QI 85) bearer when pcc_rule_id matches (or is unset) even if qfi was
 * previously bound to a different flow.
 */
bool smf_tsc_ngap_encode_on_qos_flow(
        smf_sess_t *sess, smf_bearer_t *qos_flow);

/*
 * Send a network-requested N1N2 modify with only the TSC GBR QoS flow when
 * TSC is ACTIVE but n2_tsc_encoded is still false. Returns true if sent.
 */
bool smf_tsc_send_n2_follow_up_if_needed(smf_sess_t *sess);

#ifdef __cplusplus
}
#endif

#endif /* SMF_TSC_CONTEXT_H */
