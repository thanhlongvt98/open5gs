/*
 * SPDX-FileCopyrightText: Copyright (C) 2026 Le Thanh Long
 * SPDX-License-Identifier: MIT
 */

#include "ogs-sbi.h"
#include "ogs-pfcp.h"
#include "ipfw/ogs-ipfw.h"
#include "pfcp/build.h"
#include "core/abts.h"

static void eth_flow_roundtrip_test(abts_case *tc, void *data)
{
    ogs_pf_content_t content;
    OpenAPI_eth_flow_description_t *eth = NULL;

    ogs_pf_content_from_eth_fields(
            "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
            "100", "5", "88f7", &content);

    ABTS_INT_EQUAL(tc, 5, content.num_of_component);

    eth = ogs_eth_flow_description_from_pf_content(&content);
    ABTS_PTR_NOTNULL(tc, eth);
    ABTS_PTR_NOTNULL(tc, eth->dest_mac_addr);
    ABTS_PTR_NOTNULL(tc, eth->source_mac_addr);
    ABTS_PTR_NOTNULL(tc, eth->eth_type);
    ABTS_TRUE(tc, eth->vlan_tags != NULL);

    memset(&content, 0, sizeof(content));
    ogs_pf_content_from_eth_flow_description(eth, &content);
    ABTS_INT_EQUAL(tc, 5, content.num_of_component);

    OpenAPI_eth_flow_description_free(eth);
}

static void pfcp_eth_filter_test(abts_case *tc, void *data)
{
    ogs_pf_content_t src, dst;
    ogs_pfcp_tlv_ethernet_packet_filter_t message;

    memset(&message, 0, sizeof(message));
    ogs_pf_content_from_eth_fields(
            NULL, NULL, NULL, NULL, "88f7", &src);
    ABTS_INT_EQUAL(tc, 1, src.num_of_component);

    ogs_pfcp_build_ethernet_packet_filter(&message, &src, 0);
    ABTS_INT_EQUAL(tc, 1, message.presence);
    ABTS_INT_EQUAL(tc, 1, message.ethertype.presence);

    ogs_pfcp_parse_ethernet_packet_filter(&dst, &message);
    ABTS_INT_EQUAL(tc, 1, dst.num_of_component);
    ABTS_INT_EQUAL(tc, OGS_PACKET_FILTER_ETHERTYPE_TYPE,
            dst.component[0].type);
    ABTS_INT_EQUAL(tc, 0x88f7, dst.component[0].ethertype);
}

abts_suite *test_eth_flow(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, eth_flow_roundtrip_test, NULL);
    abts_run_test(suite, pfcp_eth_filter_test, NULL);

    return suite;
}
