/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
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

#include "ngap-build.h"

/* CN Packet Delay Budget (TS 23.501 §5.7.3.4) in 0.01 ms units, signalled on a
 * NonDynamic5QIDescriptor (TS 38.413 §9.3.1.28, ext IEs 187/188) so the NG-RAN
 * scheduler can compute the radio deadline 5G-AN PDB = PDB - CN PDB. The CN PDB is
 * a per-5QI value: it must fit inside that 5QI's PDB (TS 23.501 Table 5.7.4-1), so a
 * single global constant would over-subtract for tight delay-critical 5QIs (e.g. 5QI
 * 85, 5 ms PDB) and under-subtract for relaxed ones. Only delay-critical GBR 5QIs
 * (82-86) carry a CN PDB; a 5QI with no table entry signals none (TS 23.501 §5.7.3.4
 * — CN PDB is a delay-critical-GBR concept). Values are a topology constant
 * (PSA-UPF <-> NG-RAN); lab knob, tune per 5QI as experiments demand. */
typedef struct smf_cn_pdb_s {
    uint8_t  five_qi;        /* standardized 5QI index */
    uint16_t cn_pdb_dl_001ms;/* DL CN PDB, 0.01 ms units (0 = omit direction) */
    uint16_t cn_pdb_ul_001ms;/* UL CN PDB, 0.01 ms units (0 = omit direction) */
} smf_cn_pdb_t;

static const smf_cn_pdb_t smf_cn_pdb_table[] = {
    /* CN PDB per TS 23.501 R17 Table 5.7.4-1 NOTEs 4/5/6 (static UPF<->5G-AN delay),
     * applied symmetrically to DL and UL (the spec gives one one-way value). */
    { 82, 100, 100 },  /* NOTE 4: 1.00 ms */
    { 83, 100, 100 },  /* NOTE 4: 1.00 ms */
    { 84, 500, 500 },  /* NOTE 6: 5.00 ms */
    { 85, 200, 200 },  /* NOTE 5: 2.00 ms */
    { 86, 200, 200 },  /* NOTE 5: 2.00 ms */
    /* 5QIs 87-90 are R18 additions (not in R17 Table 5.7.4-1).
     * CN PDB values below are extrapolated and UNVERIFIED against
     * R18 — verify against TS 23.501 R18 Table 5.7.4-1 before relying on them. */
    { 87, 100, 100 },  /* NOTE 4: 1.00 ms */
    { 88, 100, 100 },  /* NOTE 4: 1.00 ms */
    { 89, 100, 100 },  /* NOTE 4: 1.00 ms */
    { 90, 100, 100 },  /* NOTE 4: 1.00 ms */
};

/* Return the per-5QI CN PDB entry for a standardized 5QI, or NULL when the 5QI is
 * not delay-critical GBR (no CN PDB extension is then signalled). */
static const smf_cn_pdb_t *smf_cn_pdb_lookup(uint8_t five_qi)
{
    unsigned int i;
    for (i = 0; i < OGS_ARRAY_SIZE(smf_cn_pdb_table); i++) {
        if (smf_cn_pdb_table[i].five_qi == five_qi)
            return &smf_cn_pdb_table[i];
    }
    return NULL;
}

/*
 * Build one NGAP TSC Assistance Information (TS 38.413 §9.3.1.131) from the
 * SMF-local TSC context, for a single direction. Carries the mandatory
 * Periodicity (5G-domain, µs), the optional Burst Arrival Time (only when the
 * 5G-domain value exists), and the optional Survival Time extension (id 327)
 * when present.
 */
static NGAP_TSCAssistanceInformation_t *smf_ngap_build_tsc_assistance(
        const smf_tsc_context_t *tsc)
{
    NGAP_TSCAssistanceInformation_t *tscai = NULL;
    uint32_t periodicity_5g = 0;
    uint64_t bat_5g = 0;
    bool has_bat = false;

    smf_sess_tsc_derive(tsc, &periodicity_5g, &bat_5g, &has_bat);

    tscai = CALLOC(1, sizeof(NGAP_TSCAssistanceInformation_t));
    ogs_assert(tscai);

    /* Periodicity: INTEGER (0..640000), unit 1 µs (TS 38.413 §9.3.1.132). */
    tscai->periodicity = (NGAP_Periodicity_t)periodicity_5g;

    if (has_bat) {
        /* Burst Arrival Time: OCTET STRING (ReferenceTime), already 5G-domain.
         * 8-octet big-endian carrier; exact ReferenceTime formatting follows
         * the clock-drift conversion when the value is first produced. */
        uint8_t buf[8];
        int i;
        for (i = 7; i >= 0; i--) {
            buf[i] = (uint8_t)(bat_5g & 0xff);
            bat_5g >>= 8;
        }
        tscai->burstArrivalTime =
            CALLOC(1, sizeof(NGAP_BurstArrivalTime_t));
        ogs_assert(tscai->burstArrivalTime);
        ogs_assert(OCTET_STRING_fromBuf(
                tscai->burstArrivalTime, (const char *)buf, sizeof(buf)) == 0);
    }

    if (tsc->survival_time_us > 0) {
        /* Survival Time extension (id 327) on the TSC Assistance Information. */
        NGAP_ProtocolExtensionContainer_11905P339_t *extContainer = NULL;
        NGAP_TSCAssistanceInformation_ExtIEs_t *extIe = NULL;

        extContainer = CALLOC(1,
                sizeof(NGAP_ProtocolExtensionContainer_11905P339_t));
        ogs_assert(extContainer);
        tscai->iE_Extensions =
            (struct NGAP_ProtocolExtensionContainer *)extContainer;

        extIe = CALLOC(1, sizeof(NGAP_TSCAssistanceInformation_ExtIEs_t));
        ogs_assert(extIe);
        ASN_SEQUENCE_ADD(&extContainer->list, extIe);

        extIe->id = NGAP_ProtocolIE_ID_id_SurvivalTime;
        extIe->criticality = NGAP_Criticality_ignore;
        extIe->extensionValue.present =
            NGAP_TSCAssistanceInformation_ExtIEs__extensionValue_PR_SurvivalTime;
        extIe->extensionValue.choice.SurvivalTime =
            (NGAP_SurvivalTime_t)tsc->survival_time_us;
    }

    return tscai;
}

/*
 * Fill the NGAP QoS Characteristics IE from the flow QoS. When the QoS carries
 * operator-defined Dynamic 5QI characteristics (TS 23.501 §5.7.3) a
 * Dynamic5QIDescriptor is built (TS 38.413 §9.3.1.18); otherwise the
 * standardized NonDynamic5QIDescriptor is used.
 */
static void smf_ngap_build_qos_characteristics(
        NGAP_QosCharacteristics_t *qosCharacteristics, ogs_qos_t *qos)
{
    ogs_assert(qosCharacteristics);
    ogs_assert(qos);

    if (qos->dyn_5qi.is_dynamic) {
        NGAP_Dynamic5QIDescriptor_t *dynamic5QI =
            CALLOC(1, sizeof(NGAP_Dynamic5QIDescriptor_t));
        ogs_assert(dynamic5QI);
        qosCharacteristics->present = NGAP_QosCharacteristics_PR_dynamic5QI;
        qosCharacteristics->choice.dynamic5QI = dynamic5QI;

        dynamic5QI->priorityLevelQos = qos->dyn_5qi.priority_level;
        dynamic5QI->packetDelayBudget = qos->dyn_5qi.packet_delay_budget;
        dynamic5QI->packetErrorRate.pERScalar =
            qos->dyn_5qi.packet_error_rate.scalar;
        dynamic5QI->packetErrorRate.pERExponent =
            qos->dyn_5qi.packet_error_rate.exponent;

        /* Optional reference 5QI (TS 38.413 §9.3.1.18): the gNB derives its DRB
         * configuration from this standardized 5QI; the dynamic characteristics
         * above override the standardized ones for the scheduler. */
        if (qos->index) {
            dynamic5QI->fiveQI = CALLOC(1, sizeof(NGAP_FiveQI_t));
            ogs_assert(dynamic5QI->fiveQI);
            *dynamic5QI->fiveQI = qos->index;
        }

        if (qos->dyn_5qi.delay_critical) {
            dynamic5QI->delayCritical =
                CALLOC(1, sizeof(NGAP_DelayCritical_t));
            ogs_assert(dynamic5QI->delayCritical);
            *dynamic5QI->delayCritical = NGAP_DelayCritical_delay_critical;
        }
        if (qos->dyn_5qi.averaging_window) {
            dynamic5QI->averagingWindow =
                CALLOC(1, sizeof(NGAP_AveragingWindow_t));
            ogs_assert(dynamic5QI->averagingWindow);
            *dynamic5QI->averagingWindow = qos->dyn_5qi.averaging_window;
        }
        if (qos->dyn_5qi.max_data_burst_volume) {
            dynamic5QI->maximumDataBurstVolume =
                CALLOC(1, sizeof(NGAP_MaximumDataBurstVolume_t));
            ogs_assert(dynamic5QI->maximumDataBurstVolume);
            *dynamic5QI->maximumDataBurstVolume =
                qos->dyn_5qi.max_data_burst_volume;
        }
        return;
    }

    NGAP_NonDynamic5QIDescriptor_t *nonDynamic5QI =
        CALLOC(1, sizeof(NGAP_NonDynamic5QIDescriptor_t));
    ogs_assert(nonDynamic5QI);
    qosCharacteristics->present = NGAP_QosCharacteristics_PR_nonDynamic5QI;
    qosCharacteristics->choice.nonDynamic5QI = nonDynamic5QI;
    nonDynamic5QI->fiveQI = qos->index;

    /* Explicit MDBV on a standardized 5QI overrides the 5QI table default
     * (TS 38.413 §9.3.1.28; TS 23.501 §5.7.3.7), so the gNB sizes the CG/SPS
     * grant to the real TSC burst. NonDynamic path only — Dynamic path above
     * is pre-existing and carries its own MDBV without a separate log. */
    if (qos->dyn_5qi.max_data_burst_volume) {
        nonDynamic5QI->maximumDataBurstVolume =
            CALLOC(1, sizeof(NGAP_MaximumDataBurstVolume_t));
        ogs_assert(nonDynamic5QI->maximumDataBurstVolume);
        *nonDynamic5QI->maximumDataBurstVolume =
            qos->dyn_5qi.max_data_burst_volume;
        ogs_info("[SMF] NGAP MDBV encoded on NonDynamic5QI: 5QI[%d] MDBV[%d B]",
                 qos->index, qos->dyn_5qi.max_data_burst_volume);
    }

    /* CN Packet Delay Budget DL/UL extension (TS 38.413 §9.3.1.28, ext IEs 187/188;
     * ExtendedPacketDelayBudget in 0.01 ms units) so the gNB can subtract it from the
     * standardized 5QI PDB to get the 5G-AN PDB (TS 23.501 §5.7.3.4). Per-5QI: only
     * delay-critical GBR 5QIs in the table carry it; others (e.g. 5QI 9) get none.
     * Mirrors the TSC Survival-Time extension idiom above. */
    const smf_cn_pdb_t *cn_pdb = smf_cn_pdb_lookup(qos->index);
    if (cn_pdb && (cn_pdb->cn_pdb_dl_001ms > 0 || cn_pdb->cn_pdb_ul_001ms > 0)) {
        NGAP_ProtocolExtensionContainer_11905P193_t *extContainer =
            CALLOC(1, sizeof(NGAP_ProtocolExtensionContainer_11905P193_t));
        ogs_assert(extContainer);
        nonDynamic5QI->iE_Extensions =
            (struct NGAP_ProtocolExtensionContainer *)extContainer;

        if (cn_pdb->cn_pdb_dl_001ms > 0) {
            NGAP_NonDynamic5QIDescriptor_ExtIEs_t *dlIe =
                CALLOC(1, sizeof(NGAP_NonDynamic5QIDescriptor_ExtIEs_t));
            ogs_assert(dlIe);
            ASN_SEQUENCE_ADD(&extContainer->list, dlIe);
            dlIe->id = NGAP_ProtocolIE_ID_id_CNPacketDelayBudgetDL;
            dlIe->criticality = NGAP_Criticality_ignore;
            dlIe->extensionValue.present =
                NGAP_NonDynamic5QIDescriptor_ExtIEs__extensionValue_PR_ExtendedPacketDelayBudget;
            dlIe->extensionValue.choice.ExtendedPacketDelayBudget =
                cn_pdb->cn_pdb_dl_001ms;
        }
        if (cn_pdb->cn_pdb_ul_001ms > 0) {
            NGAP_NonDynamic5QIDescriptor_ExtIEs_t *ulIe =
                CALLOC(1, sizeof(NGAP_NonDynamic5QIDescriptor_ExtIEs_t));
            ogs_assert(ulIe);
            ASN_SEQUENCE_ADD(&extContainer->list, ulIe);
            ulIe->id = NGAP_ProtocolIE_ID_id_CNPacketDelayBudgetUL;
            ulIe->criticality = NGAP_Criticality_ignore;
            ulIe->extensionValue.present =
                NGAP_NonDynamic5QIDescriptor_ExtIEs__extensionValue_PR_ExtendedPacketDelayBudget_1;
            ulIe->extensionValue.choice.ExtendedPacketDelayBudget_1 =
                cn_pdb->cn_pdb_ul_001ms;
        }
        ogs_info("[SMF] NGAP CN PDB encoded on NonDynamic5QI: 5QI[%d] DL[%d x0.01ms] "
                 "UL[%d x0.01ms]", qos->index,
                 cn_pdb->cn_pdb_dl_001ms, cn_pdb->cn_pdb_ul_001ms);
    }
}

/**
 * Fill common QoS flow level parameters: 5QI, ARP, and optional GBR/MBR.
 */
static void fill_qos_level_parameters(
    NGAP_QosFlowLevelQosParameters_t *params,
    const ogs_qos_t *qos,
    bool include_gbr)
{
    NGAP_AllocationAndRetentionPriority_t
        *allocationAndRetentionPriority = NULL;

    /* Allocation and Retention Priority */
    allocationAndRetentionPriority =
        &params->allocationAndRetentionPriority;

    allocationAndRetentionPriority->priorityLevelARP = qos->arp.priority_level;
    if (qos->arp.pre_emption_capability == OGS_5GC_PRE_EMPTION_ENABLED)
        allocationAndRetentionPriority->pre_emptionCapability =
            NGAP_Pre_emptionCapability_may_trigger_pre_emption;
    if (qos->arp.pre_emption_vulnerability == OGS_5GC_PRE_EMPTION_ENABLED)
        allocationAndRetentionPriority->pre_emptionVulnerability =
            NGAP_Pre_emptionVulnerability_pre_emptable;

    smf_ngap_build_qos_characteristics(
            &params->qosCharacteristics, (ogs_qos_t *)qos);

    /* Optional GBR/MBR Information */
    if (include_gbr &&
        qos->mbr.downlink && qos->mbr.uplink &&
        qos->gbr.downlink && qos->gbr.uplink) {
        NGAP_GBR_QosInformation_t *gBR_QosInformation =
            params->gBR_QosInformation = CALLOC(1, sizeof(*gBR_QosInformation));
        ogs_assert(gBR_QosInformation);

        ogs_assert(qos->mbr.downlink <= OGS_MAX_BITRATE_NGAP);
        ogs_assert(qos->mbr.uplink <= OGS_MAX_BITRATE_NGAP);
        ogs_assert(qos->gbr.downlink <= OGS_MAX_BITRATE_NGAP);
        ogs_assert(qos->gbr.uplink <= OGS_MAX_BITRATE_NGAP);

        asn_uint642INTEGER(&gBR_QosInformation->maximumFlowBitRateDL,
                qos->mbr.downlink);
        asn_uint642INTEGER(&gBR_QosInformation->maximumFlowBitRateUL,
                qos->mbr.uplink);
        asn_uint642INTEGER(&gBR_QosInformation->
                guaranteedFlowBitRateDL, qos->gbr.downlink);
        asn_uint642INTEGER(&gBR_QosInformation->
                guaranteedFlowBitRateUL, qos->gbr.uplink);
    } else if (include_gbr &&
               (qos->mbr.downlink || qos->mbr.uplink ||
                qos->gbr.downlink || qos->gbr.uplink)) {
        ogs_error("Missing one or more MBR/GBR parameters; "
                "defaulting to Non-GBR flow ");
        ogs_error("    MBR[DL:%lld,UL:%lld]",
            (long long)qos->mbr.downlink, (long long)qos->mbr.uplink);
        ogs_error("    GBR[DL:%lld,UL:%lld]",
            (long long)qos->gbr.downlink, (long long)qos->gbr.uplink);
    }
}

ogs_pkbuf_t *ngap_build_pdu_session_resource_setup_request_transfer(
        smf_sess_t *sess)
{
    smf_bearer_t *qos_flow = NULL;
    ogs_ip_t upf_n3_ip;

    NGAP_PDUSessionResourceSetupRequestTransfer_t message;

    NGAP_PDUSessionResourceSetupRequestTransferIEs_t *ie = NULL;
    NGAP_PDUSessionAggregateMaximumBitRate_t *PDUSessionAggregateMaximumBitRate;
    NGAP_UPTransportLayerInformation_t *UPTransportLayerInformation = NULL;
    NGAP_GTPTunnel_t *gTPTunnel = NULL;
    NGAP_DataForwardingNotPossible_t *DataForwardingNotPossible = NULL;
    NGAP_PDUSessionType_t *PDUSessionType = NULL;
    NGAP_SecurityIndication_t *SecurityIndication = NULL;
    NGAP_QosFlowSetupRequestList_t *QosFlowSetupRequestList = NULL;
    NGAP_QosFlowSetupRequestItem_t *QosFlowSetupRequestItem = NULL;

    ogs_assert(sess);

    ogs_debug("PDUSessionResourceSetupRequestTransfer");
    memset(&message, 0, sizeof(NGAP_PDUSessionResourceSetupRequestTransfer_t));

    if (sess->session.ambr.downlink || sess->session.ambr.uplink) {
        ie = CALLOC(1,
                sizeof(NGAP_PDUSessionResourceSetupRequestTransferIEs_t));
        ogs_assert(ie);
        ASN_SEQUENCE_ADD(&message.protocolIEs, ie);

        ie->id = NGAP_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate;
        ie->criticality = NGAP_Criticality_reject;
        ie->value.present = NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_PDUSessionAggregateMaximumBitRate;

        PDUSessionAggregateMaximumBitRate =
            &ie->value.choice.PDUSessionAggregateMaximumBitRate;

        asn_uint642INTEGER(&PDUSessionAggregateMaximumBitRate->
            pDUSessionAggregateMaximumBitRateUL, sess->session.ambr.uplink);
        asn_uint642INTEGER(&PDUSessionAggregateMaximumBitRate->
            pDUSessionAggregateMaximumBitRateDL, sess->session.ambr.downlink);
    }

    ie = CALLOC(1, sizeof(NGAP_PDUSessionResourceSetupRequestTransferIEs_t));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(&message.protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_UL_NGU_UP_TNLInformation;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_UPTransportLayerInformation;

    UPTransportLayerInformation = &ie->value.choice.UPTransportLayerInformation;

    gTPTunnel = CALLOC(1, sizeof(struct NGAP_GTPTunnel));
    ogs_assert(gTPTunnel);
    UPTransportLayerInformation->present =
        NGAP_UPTransportLayerInformation_PR_gTPTunnel;
    UPTransportLayerInformation->choice.gTPTunnel = gTPTunnel;

    ogs_assert(OGS_OK == ogs_sockaddr_to_ip(
                sess->local_ul_addr, sess->local_ul_addr6, &upf_n3_ip));
    ogs_assert(OGS_OK == ogs_asn_ip_to_BIT_STRING(
                &upf_n3_ip, &gTPTunnel->transportLayerAddress));
    ogs_asn_uint32_to_OCTET_STRING(sess->local_ul_teid, &gTPTunnel->gTP_TEID);

    if (sess->handover.data_forwarding_not_possible == true) {
        ie = CALLOC(1,
                sizeof(NGAP_PDUSessionResourceSetupRequestTransferIEs_t));
        ogs_assert(ie);
        ASN_SEQUENCE_ADD(&message.protocolIEs, ie);

        ie->id = NGAP_ProtocolIE_ID_id_DataForwardingNotPossible;
        ie->criticality = NGAP_Criticality_reject;
        ie->value.present = NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_DataForwardingNotPossible;

        DataForwardingNotPossible = &ie->value.choice.DataForwardingNotPossible;

        *DataForwardingNotPossible =
            NGAP_DataForwardingNotPossible_data_forwarding_not_possible;
    }

    ie = CALLOC(1, sizeof(NGAP_PDUSessionResourceSetupRequestTransferIEs_t));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(&message.protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_PDUSessionType;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_PDUSessionType;

    PDUSessionType = &ie->value.choice.PDUSessionType;

    *PDUSessionType = OGS_PDU_SESSION_TYPE_IPV4;
    switch (sess->session.session_type) {
    case OGS_PDU_SESSION_TYPE_IPV4 :
        *PDUSessionType = NGAP_PDUSessionType_ipv4;
        break;
    case OGS_PDU_SESSION_TYPE_IPV6 :
        *PDUSessionType = NGAP_PDUSessionType_ipv6;
        break;
    case OGS_PDU_SESSION_TYPE_IPV4V6 :
        *PDUSessionType = NGAP_PDUSessionType_ipv4v6;
        break;
    case OGS_PDU_SESSION_TYPE_ETHERNET :
        *PDUSessionType = NGAP_PDUSessionType_ethernet;
        break;
    default:
        ogs_fatal("Unknown PDU Session Type [%d]", sess->session.session_type);
        ogs_assert_if_reached();
    }

    if (smf_self()->security_indication.integrity_protection_indication &&
        smf_self()->security_indication.confidentiality_protection_indication) {

        ie = CALLOC(1,
                sizeof(NGAP_PDUSessionResourceSetupRequestTransferIEs_t));
        ogs_assert(ie);
        ASN_SEQUENCE_ADD(&message.protocolIEs, ie);

        ie->id = NGAP_ProtocolIE_ID_id_SecurityIndication;
        ie->criticality = NGAP_Criticality_reject;
        ie->value.present = NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_SecurityIndication;

        SecurityIndication = &ie->value.choice.SecurityIndication;

        SecurityIndication->integrityProtectionIndication =
                smf_integrity_protection_indication_value2enum(
                    smf_self()->security_indication.
                        integrity_protection_indication);
        ogs_assert(SecurityIndication->integrityProtectionIndication >= 0);

        SecurityIndication->confidentialityProtectionIndication =
                smf_confidentiality_protection_indication_value2enum(
                    smf_self()->security_indication.
                        confidentiality_protection_indication);
        ogs_assert(SecurityIndication->
                confidentialityProtectionIndication >= 0);

        if (smf_self()->security_indication.
                maximum_integrity_protected_data_rate_uplink) {

            ogs_assert(
                SecurityIndication->integrityProtectionIndication ==
                    NGAP_IntegrityProtectionIndication_required ||
                SecurityIndication->integrityProtectionIndication ==
                    NGAP_IntegrityProtectionIndication_preferred);

            SecurityIndication->maximumIntegrityProtectedDataRate_UL =
                CALLOC(1, sizeof(NGAP_MaximumIntegrityProtectedDataRate_t));
            ogs_assert(SecurityIndication->
                    maximumIntegrityProtectedDataRate_UL);
            *(SecurityIndication->maximumIntegrityProtectedDataRate_UL) =
                smf_maximum_integrity_protected_data_rate_uplink_value2enum(
                    smf_self()->security_indication.
                        maximum_integrity_protected_data_rate_uplink);
            ogs_assert(
                *(SecurityIndication->
                    maximumIntegrityProtectedDataRate_UL) >= 0);

            if (smf_self()->security_indication.
                    maximum_integrity_protected_data_rate_downlink) {
                NGAP_ProtocolExtensionContainer_11905P297_t
                    *extContainer = NULL;
                NGAP_SecurityIndication_ExtIEs_t *extIe = NULL;
                NGAP_MaximumIntegrityProtectedDataRate_t
                    *MaximumIntegrityProtectedDataRate = NULL;

                extContainer = CALLOC(1,
                        sizeof(NGAP_ProtocolExtensionContainer_11905P297_t));
                ogs_assert(extContainer);
                SecurityIndication->iE_Extensions =
                    (struct NGAP_ProtocolExtensionContainer *)extContainer;

                extIe = CALLOC(1, sizeof(NGAP_SecurityIndication_ExtIEs_t));
                ogs_assert(extIe);
                ASN_SEQUENCE_ADD(&extContainer->list, extIe);

                extIe->id =
                    NGAP_ProtocolIE_ID_id_MaximumIntegrityProtectedDataRate_DL;
                extIe->criticality = NGAP_Criticality_ignore;
                extIe->extensionValue.present = NGAP_SecurityIndication_ExtIEs__extensionValue_PR_MaximumIntegrityProtectedDataRate;

                MaximumIntegrityProtectedDataRate =
                    &extIe->extensionValue.choice.
                        MaximumIntegrityProtectedDataRate;

                *MaximumIntegrityProtectedDataRate =
                smf_maximum_integrity_protected_data_rate_downlink_value2enum(
                        smf_self()->security_indication.
                            maximum_integrity_protected_data_rate_downlink);
                ogs_assert(*MaximumIntegrityProtectedDataRate >= 0);
            }
        }
    }

    ie = CALLOC(1, sizeof(NGAP_PDUSessionResourceSetupRequestTransferIEs_t));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(&message.protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_QosFlowSetupRequestList;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_QosFlowSetupRequestList;

    QosFlowSetupRequestList = &ie->value.choice.QosFlowSetupRequestList;

    if (HOME_ROUTED_ROAMING_IN_VSMF(sess)) {
        OpenAPI_list_t *qosFlowsSetupList = NULL;
        OpenAPI_qos_flow_setup_item_t *qosFlowSetupItem = NULL;
        OpenAPI_qos_flow_profile_t *qosFlowProfile = NULL;
        OpenAPI_lnode_t *node = NULL;

        ogs_qos_t qos;

        qosFlowsSetupList = sess->h_smf_qos_flows_setup_list;
        ogs_assert(qosFlowsSetupList);

        node = qosFlowsSetupList->first;
        ogs_assert(node);
        qosFlowSetupItem = node->data;
        ogs_assert(qosFlowSetupItem);

        qosFlowProfile = qosFlowSetupItem->qos_flow_profile;
        ogs_assert(qosFlowProfile);

        memset(&qos, 0, sizeof(qos));

        qos.index = qosFlowProfile->_5qi;
        ogs_assert(qosFlowProfile->arp);
        qos.arp.priority_level = qosFlowProfile->arp->priority_level;
        if (qosFlowProfile->arp->preempt_cap ==
            OpenAPI_preemption_capability_NOT_PREEMPT)
            qos.arp.pre_emption_capability = OGS_5GC_PRE_EMPTION_DISABLED;
        else if (qosFlowProfile->arp->preempt_cap ==
            OpenAPI_preemption_capability_MAY_PREEMPT)
            qos.arp.pre_emption_capability = OGS_5GC_PRE_EMPTION_ENABLED;
        else {
            ogs_error("Invalid preempt_cap [%d]",
                    qosFlowProfile->arp->preempt_cap);
            ogs_assert_if_reached();
        }

        if (qosFlowProfile->arp->preempt_vuln ==
            OpenAPI_preemption_vulnerability_NOT_PREEMPTABLE)
            qos.arp.pre_emption_vulnerability = OGS_5GC_PRE_EMPTION_DISABLED;
        else if (qosFlowProfile->arp->preempt_vuln ==
            OpenAPI_preemption_vulnerability_PREEMPTABLE)
            qos.arp.pre_emption_vulnerability = OGS_5GC_PRE_EMPTION_ENABLED;
        else {
            ogs_error("Invalid preempt_vuln [%d]",
                    qosFlowProfile->arp->preempt_vuln);
            ogs_assert_if_reached();
        }

        QosFlowSetupRequestItem =
            CALLOC(1, sizeof(struct NGAP_QosFlowSetupRequestItem));
        ogs_assert(QosFlowSetupRequestItem);
        ASN_SEQUENCE_ADD(&QosFlowSetupRequestList->list,
            QosFlowSetupRequestItem);

        QosFlowSetupRequestItem->qosFlowIdentifier = qosFlowSetupItem->qfi;

        fill_qos_level_parameters(
                &QosFlowSetupRequestItem->qosFlowLevelQosParameters,
                &qos, true);

    } else {
        ogs_list_for_each(&sess->bearer_list, qos_flow) {
            QosFlowSetupRequestItem =
                CALLOC(1, sizeof(struct NGAP_QosFlowSetupRequestItem));
            ogs_assert(QosFlowSetupRequestItem);
            ASN_SEQUENCE_ADD(&QosFlowSetupRequestList->list,
                QosFlowSetupRequestItem);

            QosFlowSetupRequestItem->qosFlowIdentifier = qos_flow->qfi;

            fill_qos_level_parameters(
                    &QosFlowSetupRequestItem->qosFlowLevelQosParameters,
                    &qos_flow->qos, true);

        /* Attach TSC Traffic Characteristics (id 196) on this QoS Flow Setup
         * Request Item when the session carries TSC assistance for this QFI.
         * Direction selects the DL/UL sub-IE(s). Baseline flows add nothing. */
        if (sess->tsc && sess->tsc->status == SMF_TSC_STATUS_ACTIVE &&
                qos_flow->qfi == sess->tsc->qfi) {
            NGAP_ProtocolExtensionContainer_11905P280_t *tscExtContainer = NULL;
            NGAP_QosFlowSetupRequestItem_ExtIEs_t *tscExtIe = NULL;
            NGAP_TSCTrafficCharacteristics_t *TSCTrafficCharacteristics = NULL;

            tscExtContainer = CALLOC(1,
                    sizeof(NGAP_ProtocolExtensionContainer_11905P280_t));
            ogs_assert(tscExtContainer);
            QosFlowSetupRequestItem->iE_Extensions =
                (struct NGAP_ProtocolExtensionContainer *)tscExtContainer;

            tscExtIe = CALLOC(1, sizeof(NGAP_QosFlowSetupRequestItem_ExtIEs_t));
            ogs_assert(tscExtIe);
            ASN_SEQUENCE_ADD(&tscExtContainer->list, tscExtIe);

            tscExtIe->id = NGAP_ProtocolIE_ID_id_TSCTrafficCharacteristics;
            tscExtIe->criticality = NGAP_Criticality_ignore;
            tscExtIe->extensionValue.present =
                NGAP_QosFlowSetupRequestItem_ExtIEs__extensionValue_PR_TSCTrafficCharacteristics;

            TSCTrafficCharacteristics =
                &tscExtIe->extensionValue.choice.TSCTrafficCharacteristics;

            if (sess->tsc->direction == SMF_TSC_DIR_DL ||
                    sess->tsc->direction == SMF_TSC_DIR_BOTH)
                TSCTrafficCharacteristics->tSCAssistanceInformationDL =
                    smf_ngap_build_tsc_assistance(sess->tsc);
            if (sess->tsc->direction == SMF_TSC_DIR_UL ||
                    sess->tsc->direction == SMF_TSC_DIR_BOTH)
                TSCTrafficCharacteristics->tSCAssistanceInformationUL =
                    smf_ngap_build_tsc_assistance(sess->tsc);

            ogs_info("[SMF] NGAP TSC Traffic Characteristics encoded: "
                     "QFI[%d] dir[%d] periodicity[%llu us]",
                     qos_flow->qfi, sess->tsc->direction,
                     (unsigned long long)sess->tsc->periodicity_us);
        } else if (sess->tsc && sess->tsc->status != SMF_TSC_STATUS_ABSENT &&
                qos_flow->qfi == sess->tsc->qfi) {
            /* TSC was requested for this flow but is not ACTIVE (PARTIAL or
             * DOWNGRADED) — omit the IE and run on the 5QI. The reason is
             * surfaced so the baseline fallback is explicit in logs. */
            ogs_warn("[SMF] NGAP TSC IE omitted: QFI[%d] status[%d] reason[%s] "
                     "-- flow proceeds on baseline 5QI",
                     qos_flow->qfi, sess->tsc->status,
                     sess->tsc->downgrade_reason);
        }
        }
    }

    return ogs_asn_encode(
            &asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &message);
}

ogs_pkbuf_t *ngap_build_pdu_session_resource_modify_request_transfer(
        smf_sess_t *sess, bool include_gbr)
{
    NGAP_PDUSessionResourceModifyRequestTransfer_t message;

    NGAP_PDUSessionResourceModifyRequestTransferIEs_t *ie = NULL;

    NGAP_QosFlowAddOrModifyRequestList_t *QosFlowAddOrModifyRequestList = NULL;
    NGAP_QosFlowAddOrModifyRequestItem_t *QosFlowAddOrModifyRequestItem = NULL;

    smf_bearer_t *qos_flow = NULL;

    ogs_assert(sess);

    ogs_debug("PDUSessionResourceModifyRequestTransfer");
    memset(&message, 0, sizeof(NGAP_PDUSessionResourceModifyRequestTransfer_t));

    ie = CALLOC(1, sizeof(NGAP_PDUSessionResourceModifyRequestTransferIEs_t));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(&message.protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_QosFlowAddOrModifyRequestList;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_PDUSessionResourceModifyRequestTransferIEs__value_PR_QosFlowAddOrModifyRequestList;

    QosFlowAddOrModifyRequestList =
        &ie->value.choice.QosFlowAddOrModifyRequestList;

    /* Home-Routed V-SMF: QoS flow */
    if (HOME_ROUTED_ROAMING_IN_VSMF(sess)) {
        OpenAPI_lnode_t *node = NULL;
        OpenAPI_list_for_each(
                sess->h_smf_qos_flows_add_mod_request_list, node) {
            OpenAPI_qos_flow_add_modify_request_item_t
                *qosFlowAddModRequestItem = node->data;
            if (qosFlowAddModRequestItem) {
                OpenAPI_qos_flow_profile_t *qosFlowProfile =
                    qosFlowAddModRequestItem->qos_flow_profile;
                if (qosFlowProfile) {
                    ogs_qos_t qos;

                    memset(&qos, 0, sizeof(qos));

                    qos.index = qosFlowProfile->_5qi;
                    ogs_assert(qosFlowProfile->arp);
                    qos.arp.priority_level =
                        qosFlowProfile->arp->priority_level;
                    if (qosFlowProfile->arp->preempt_cap ==
                        OpenAPI_preemption_capability_NOT_PREEMPT)
                        qos.arp.pre_emption_capability =
                            OGS_5GC_PRE_EMPTION_DISABLED;
                    else if (qosFlowProfile->arp->preempt_cap ==
                        OpenAPI_preemption_capability_MAY_PREEMPT)
                        qos.arp.pre_emption_capability =
                            OGS_5GC_PRE_EMPTION_ENABLED;
                    else {
                        ogs_error("Invalid preempt_cap [%d]",
                                qosFlowProfile->arp->preempt_cap);
                        ogs_assert_if_reached();
                    }

                    if (qosFlowProfile->arp->preempt_vuln ==
                        OpenAPI_preemption_vulnerability_NOT_PREEMPTABLE)
                        qos.arp.pre_emption_vulnerability =
                            OGS_5GC_PRE_EMPTION_DISABLED;
                    else if (qosFlowProfile->arp->preempt_vuln ==
                        OpenAPI_preemption_vulnerability_PREEMPTABLE)
                        qos.arp.pre_emption_vulnerability =
                            OGS_5GC_PRE_EMPTION_ENABLED;
                    else {
                        ogs_error("Invalid preempt_vuln [%d]",
                                qosFlowProfile->arp->preempt_vuln);
                        ogs_assert_if_reached();
                    }

                    if (qosFlowProfile->gbr_qos_flow_info) {
                        OpenAPI_gbr_qos_flow_information_t *gbrQosFlowInfo =
                                qosFlowProfile->gbr_qos_flow_info;
                        if (gbrQosFlowInfo->max_fbr_dl)
                            qos.mbr.downlink =
                                ogs_sbi_bitrate_from_string(
                                        gbrQosFlowInfo->max_fbr_dl);
                        if (gbrQosFlowInfo->max_fbr_ul)
                            qos.mbr.uplink =
                                ogs_sbi_bitrate_from_string(
                                        gbrQosFlowInfo->max_fbr_ul);
                        if (gbrQosFlowInfo->gua_fbr_dl)
                            qos.gbr.downlink =
                                ogs_sbi_bitrate_from_string(
                                        gbrQosFlowInfo->gua_fbr_dl);
                        if (gbrQosFlowInfo->gua_fbr_ul)
                            qos.gbr.uplink =
                                ogs_sbi_bitrate_from_string(
                                        gbrQosFlowInfo->gua_fbr_ul);
                    }

                    QosFlowAddOrModifyRequestItem =
                        CALLOC(1, sizeof(*QosFlowAddOrModifyRequestItem));
                    ogs_assert(QosFlowAddOrModifyRequestItem);
                    ASN_SEQUENCE_ADD(
                            &QosFlowAddOrModifyRequestList->list,
                            QosFlowAddOrModifyRequestItem);

                    QosFlowAddOrModifyRequestItem->qosFlowIdentifier =
                        qosFlowAddModRequestItem->qfi;

                    QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters =
                            CALLOC(1, sizeof(NGAP_QosFlowLevelQosParameters_t));
                    ogs_assert(QosFlowAddOrModifyRequestItem->
                            qosFlowLevelQosParameters);

                    fill_qos_level_parameters(
                            QosFlowAddOrModifyRequestItem->
                                qosFlowLevelQosParameters, &qos, true);

                    /* TSC Traffic Characteristics on the Modify path (home-routed). */
                    if (sess->tsc && sess->tsc->status == SMF_TSC_STATUS_ACTIVE &&
                            qosFlowAddModRequestItem->qfi == sess->tsc->qfi) {
                        NGAP_ProtocolExtensionContainer_11905P269_t *tscExtContainer = NULL;
                        NGAP_QosFlowAddOrModifyRequestItem_ExtIEs_t *tscExtIe = NULL;
                        NGAP_TSCTrafficCharacteristics_t *TSCTrafficCharacteristics = NULL;

                        tscExtContainer = CALLOC(1,
                                sizeof(NGAP_ProtocolExtensionContainer_11905P269_t));
                        ogs_assert(tscExtContainer);
                        QosFlowAddOrModifyRequestItem->iE_Extensions =
                            (struct NGAP_ProtocolExtensionContainer *)tscExtContainer;

                        tscExtIe = CALLOC(1,
                                sizeof(NGAP_QosFlowAddOrModifyRequestItem_ExtIEs_t));
                        ogs_assert(tscExtIe);
                        ASN_SEQUENCE_ADD(&tscExtContainer->list, tscExtIe);

                        tscExtIe->id = NGAP_ProtocolIE_ID_id_TSCTrafficCharacteristics;
                        tscExtIe->criticality = NGAP_Criticality_ignore;
                        tscExtIe->extensionValue.present =
                            NGAP_QosFlowAddOrModifyRequestItem_ExtIEs__extensionValue_PR_TSCTrafficCharacteristics;

                        TSCTrafficCharacteristics =
                            &tscExtIe->extensionValue.choice.TSCTrafficCharacteristics;

                        if (sess->tsc->direction == SMF_TSC_DIR_DL ||
                                sess->tsc->direction == SMF_TSC_DIR_BOTH)
                            TSCTrafficCharacteristics->tSCAssistanceInformationDL =
                                smf_ngap_build_tsc_assistance(sess->tsc);
                        if (sess->tsc->direction == SMF_TSC_DIR_UL ||
                                sess->tsc->direction == SMF_TSC_DIR_BOTH)
                            TSCTrafficCharacteristics->tSCAssistanceInformationUL =
                                smf_ngap_build_tsc_assistance(sess->tsc);

                        ogs_info("[SMF] NGAP TSC Traffic Characteristics encoded (modify): "
                                 "QFI[%d] dir[%d] periodicity[%llu us]",
                                 qosFlowAddModRequestItem->qfi, sess->tsc->direction,
                                 (unsigned long long)sess->tsc->periodicity_us);
                    } else if (sess->tsc && sess->tsc->status != SMF_TSC_STATUS_ABSENT &&
                            qosFlowAddModRequestItem->qfi == sess->tsc->qfi) {
                        ogs_warn("[SMF] NGAP TSC IE omitted (modify): QFI[%d] status[%d] "
                                 "reason[%s] -- flow proceeds on baseline 5QI",
                                 qosFlowAddModRequestItem->qfi, sess->tsc->status,
                                 sess->tsc->downgrade_reason);
                    }
                }
            }
        }

    } else {
        /* Default: iterate modify-list */
        ogs_list_for_each_entry(&sess->qos_flow_to_modify_list,
                                 qos_flow, to_modify_node) {
            QosFlowAddOrModifyRequestItem =
                CALLOC(1, sizeof(*QosFlowAddOrModifyRequestItem));
            ogs_assert(QosFlowAddOrModifyRequestItem);
            ASN_SEQUENCE_ADD(
                    &QosFlowAddOrModifyRequestList->list,
                    QosFlowAddOrModifyRequestItem);
            QosFlowAddOrModifyRequestItem->qosFlowIdentifier = qos_flow->qfi;

            QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters =
                    CALLOC(1, sizeof(NGAP_QosFlowLevelQosParameters_t));
            ogs_assert(
                    QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters);
            fill_qos_level_parameters(
                    QosFlowAddOrModifyRequestItem->qosFlowLevelQosParameters,
                    &qos_flow->qos, include_gbr);

            /* TSC Traffic Characteristics on the Modify path. */
            if (sess->tsc && sess->tsc->status == SMF_TSC_STATUS_ACTIVE &&
                    qos_flow->qfi == sess->tsc->qfi) {
                NGAP_ProtocolExtensionContainer_11905P269_t *tscExtContainer = NULL;
                NGAP_QosFlowAddOrModifyRequestItem_ExtIEs_t *tscExtIe = NULL;
                NGAP_TSCTrafficCharacteristics_t *TSCTrafficCharacteristics = NULL;

                tscExtContainer = CALLOC(1,
                        sizeof(NGAP_ProtocolExtensionContainer_11905P269_t));
                ogs_assert(tscExtContainer);
                QosFlowAddOrModifyRequestItem->iE_Extensions =
                    (struct NGAP_ProtocolExtensionContainer *)tscExtContainer;

                tscExtIe = CALLOC(1,
                        sizeof(NGAP_QosFlowAddOrModifyRequestItem_ExtIEs_t));
                ogs_assert(tscExtIe);
                ASN_SEQUENCE_ADD(&tscExtContainer->list, tscExtIe);

                tscExtIe->id = NGAP_ProtocolIE_ID_id_TSCTrafficCharacteristics;
                tscExtIe->criticality = NGAP_Criticality_ignore;
                tscExtIe->extensionValue.present =
                    NGAP_QosFlowAddOrModifyRequestItem_ExtIEs__extensionValue_PR_TSCTrafficCharacteristics;

                TSCTrafficCharacteristics =
                    &tscExtIe->extensionValue.choice.TSCTrafficCharacteristics;

                if (sess->tsc->direction == SMF_TSC_DIR_DL ||
                        sess->tsc->direction == SMF_TSC_DIR_BOTH)
                    TSCTrafficCharacteristics->tSCAssistanceInformationDL =
                        smf_ngap_build_tsc_assistance(sess->tsc);
                if (sess->tsc->direction == SMF_TSC_DIR_UL ||
                        sess->tsc->direction == SMF_TSC_DIR_BOTH)
                    TSCTrafficCharacteristics->tSCAssistanceInformationUL =
                        smf_ngap_build_tsc_assistance(sess->tsc);

                ogs_info("[SMF] NGAP TSC Traffic Characteristics encoded (modify): "
                         "QFI[%d] dir[%d] periodicity[%llu us]",
                         qos_flow->qfi, sess->tsc->direction,
                         (unsigned long long)sess->tsc->periodicity_us);
            } else if (sess->tsc && sess->tsc->status != SMF_TSC_STATUS_ABSENT &&
                    qos_flow->qfi == sess->tsc->qfi) {
                ogs_warn("[SMF] NGAP TSC IE omitted (modify): QFI[%d] status[%d] "
                         "reason[%s] -- flow proceeds on baseline 5QI",
                         qos_flow->qfi, sess->tsc->status,
                         sess->tsc->downgrade_reason);
            }
        }
    }

    return ogs_asn_encode(
            &asn_DEF_NGAP_PDUSessionResourceModifyRequestTransfer, &message);
}

ogs_pkbuf_t *ngap_build_pdu_session_resource_release_request_transfer(
        smf_sess_t *sess, NGAP_Cause_PR group, long cause)
{
    NGAP_PDUSessionResourceModifyRequestTransfer_t message;

    NGAP_PDUSessionResourceModifyRequestTransferIEs_t *ie = NULL;

    NGAP_QosFlowListWithCause_t *QosFlowListWithCause = NULL;
    NGAP_QosFlowWithCauseItem_t *QosFlowWithCauseItem = NULL;
    NGAP_QosFlowIdentifier_t *qosFlowIdentifier = NULL;
    NGAP_Cause_t *Cause = NULL;

    smf_bearer_t *qos_flow = NULL;

    ogs_assert(sess);

    ogs_debug("PDUSessionResourceModifyRequestTransfer");
    memset(&message, 0, sizeof(NGAP_PDUSessionResourceModifyRequestTransfer_t));

    ie = CALLOC(1, sizeof(NGAP_PDUSessionResourceModifyRequestTransferIEs_t));
    ASN_SEQUENCE_ADD(&message.protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_QosFlowToReleaseList;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_PDUSessionResourceModifyRequestTransferIEs__value_PR_QosFlowListWithCause;

    QosFlowListWithCause = &ie->value.choice.QosFlowListWithCause;

    /* Home-Routed V-SMF: QoS flow */
    if (HOME_ROUTED_ROAMING_IN_VSMF(sess)) {
        OpenAPI_lnode_t *node = NULL;
        OpenAPI_list_for_each(sess->h_smf_qos_flows_rel_request_list, node) {
            OpenAPI_qos_flow_release_request_item_t
                *qosFlowRelRequestItem = node->data;
            if (qosFlowRelRequestItem) {

                QosFlowWithCauseItem = CALLOC(1, sizeof(*QosFlowWithCauseItem));
                ASN_SEQUENCE_ADD(&QosFlowListWithCause->list,
                        QosFlowWithCauseItem);

                qosFlowIdentifier = &QosFlowWithCauseItem->qosFlowIdentifier;

                *qosFlowIdentifier = qosFlowRelRequestItem->qfi;

                Cause = &QosFlowWithCauseItem->cause;
                Cause->present = group;
                Cause->choice.radioNetwork = cause;
            }
        }
    } else {
        ogs_list_for_each_entry(
                &sess->qos_flow_to_modify_list, qos_flow, to_modify_node) {

            QosFlowWithCauseItem = CALLOC(1, sizeof(*QosFlowWithCauseItem));
            ASN_SEQUENCE_ADD(&QosFlowListWithCause->list, QosFlowWithCauseItem);

            qosFlowIdentifier = &QosFlowWithCauseItem->qosFlowIdentifier;

            *qosFlowIdentifier = qos_flow->qfi;

            Cause = &QosFlowWithCauseItem->cause;
            Cause->present = group;
            Cause->choice.radioNetwork = cause;

        }
    }

    return ogs_asn_encode(
            &asn_DEF_NGAP_PDUSessionResourceModifyRequestTransfer, &message);
}

ogs_pkbuf_t *ngap_build_pdu_session_resource_release_command_transfer(
        smf_sess_t *sess, int state, NGAP_Cause_PR group, long cause)
{
    NGAP_PDUSessionResourceReleaseCommandTransfer_t message;
    NGAP_Cause_t *Cause = NULL;

    ogs_assert(sess);
    ogs_assert(state);
    sess->ngap_state.pdu_session_resource_release = state;

    ogs_debug("PDUSessionResourceReleaseCommandTransfer");
    memset(&message, 0,
            sizeof(NGAP_PDUSessionResourceReleaseCommandTransfer_t));

    ogs_debug("    Group[%d] Cause[%d]", group, (int)cause);

    Cause = &message.cause;
    Cause->present = group;
    Cause->choice.radioNetwork = cause;

    return ogs_asn_encode(
            &asn_DEF_NGAP_PDUSessionResourceReleaseCommandTransfer, &message);
}

ogs_pkbuf_t *ngap_build_path_switch_request_ack_transfer(smf_sess_t *sess)
{
    NGAP_PathSwitchRequestAcknowledgeTransfer_t message;

#if 0 /* The following is optional. So I've removed */
    ogs_ip_t upf_n3_ip;

    NGAP_UPTransportLayerInformation_t *UPTransportLayerInformation = NULL;
    NGAP_GTPTunnel_t *gTPTunnel = NULL;
#endif

    ogs_assert(sess);

    ogs_debug("PathSwitchRequestAcknowledgeTransfer");
    memset(&message, 0, sizeof(NGAP_PathSwitchRequestAcknowledgeTransfer_t));

#if 0 /* The following is optional. So I've removed */

    message.uL_NGU_UP_TNLInformation = CALLOC(1, sizeof(NGAP_UPTransportLayerInformation_t));
    UPTransportLayerInformation = message.uL_NGU_UP_TNLInformation;

    gTPTunnel = CALLOC(1, sizeof(struct NGAP_GTPTunnel));
    UPTransportLayerInformation->present =
        NGAP_UPTransportLayerInformation_PR_gTPTunnel;
    UPTransportLayerInformation->choice.gTPTunnel = gTPTunnel;

    ogs_assert(OGS_OK == ogs_sockaddr_to_ip(
                sess->local_ul_addr, sess->local_ul_addr6, &upf_n3_ip));
    ogs_assert(OGS_OK == ogs_asn_ip_to_BIT_STRING(
                &upf_n3_ip, &gTPTunnel->transportLayerAddress));
    ogs_asn_uint32_to_OCTET_STRING(sess->local_ul_teid, &gTPTunnel->gTP_TEID);

#endif

    return ogs_asn_encode(
            &asn_DEF_NGAP_PathSwitchRequestAcknowledgeTransfer, &message);
}

ogs_pkbuf_t *ngap_build_handover_command_transfer(smf_sess_t *sess)
{
    NGAP_HandoverCommandTransfer_t message;

    ogs_ip_t local_dl_ip;

    ogs_assert(sess);

    ogs_debug("HandoverCommandTransfer");
    memset(&message, 0, sizeof(NGAP_HandoverCommandTransfer_t));

    if (sess->handover.indirect_data_forwarding == true) {
        ogs_pfcp_pdr_t *pdr = NULL;

        NGAP_UPTransportLayerInformation_t
            *dLForwardingUP_TNLInformation = NULL;
        NGAP_GTPTunnel_t *gTPTunnel = NULL;
        NGAP_QosFlowToBeForwardedList_t *qosFlowToBeForwardedList = NULL;

        message.dLForwardingUP_TNLInformation = dLForwardingUP_TNLInformation =
            CALLOC(1, sizeof(*dLForwardingUP_TNLInformation));
        ogs_assert(dLForwardingUP_TNLInformation);

        dLForwardingUP_TNLInformation->present =
            NGAP_UPTransportLayerInformation_PR_gTPTunnel;
        dLForwardingUP_TNLInformation->choice.gTPTunnel = gTPTunnel =
            CALLOC(1, sizeof(*gTPTunnel));
        ogs_assert(gTPTunnel);

        ogs_assert(OGS_OK == ogs_sockaddr_to_ip(
                sess->handover.local_dl_addr, sess->handover.local_dl_addr6,
                &local_dl_ip));
        ogs_assert(OGS_OK == ogs_asn_ip_to_BIT_STRING(
                    &local_dl_ip, &gTPTunnel->transportLayerAddress));
        ogs_asn_uint32_to_OCTET_STRING(
                sess->handover.local_dl_teid, &gTPTunnel->gTP_TEID);

        ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
            ogs_pfcp_far_t *far = pdr->far;
            ogs_assert(far);

            if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS &&
                far->dst_if == OGS_PFCP_INTERFACE_ACCESS) {
                NGAP_QosFlowToBeForwardedItem_t *qosFlowToBeForwardedItem;
                NGAP_QosFlowIdentifier_t *qosFlowIdentifier = NULL;

                if (!qosFlowToBeForwardedList) {
                    message.qosFlowToBeForwardedList =
                        qosFlowToBeForwardedList =
                            CALLOC(1, sizeof(*qosFlowToBeForwardedList));
                    ogs_assert(qosFlowToBeForwardedList);
                }

                qosFlowToBeForwardedItem =
                    CALLOC(1, sizeof(*qosFlowToBeForwardedItem));
                ogs_assert(qosFlowToBeForwardedItem);

                ASN_SEQUENCE_ADD(&qosFlowToBeForwardedList->list,
                        qosFlowToBeForwardedItem);

                qosFlowIdentifier =
                    &qosFlowToBeForwardedItem->qosFlowIdentifier;

                *qosFlowIdentifier = pdr->qfi;
            }
        }
    }

    return ogs_asn_encode(&asn_DEF_NGAP_HandoverCommandTransfer, &message);
}
