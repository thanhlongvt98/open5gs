/*
 * SPDX-FileCopyrightText: Copyright (C) 2026 Le Thanh Long
 * SPDX-License-Identifier: MIT
 */

#include "ogs-sbi.h"
#include "ipfw/ogs-ipfw.h"
#include "pfcp/ogs-pfcp.h"
#include "core/abts.h"

static void eth_flow_roundtrip_test(abts_case *tc, void *data)
{
    ogs_pf_content_t content;

    ogs_pf_content_from_eth_sentinel(
            "eth|aa:bb:cc:dd:ee:ff|11:22:33:44:55:66|100|5|88f7", &content);

    ABTS_INT_EQUAL(tc, 5, content.num_of_component);
}

static void test_eth_packet_filter_roundtrip(abts_case *tc, void *data)
{
    ogs_pf_content_t c;
    ogs_pfcp_tlv_ethernet_packet_filter_t tlv;
    ogs_pfcp_rule_t rule;
    uint8_t mac[13], ctag[3], etype[2];
    int k;
    bool found_dst = false, found_vid = false, found_etype = false;

    memset(&c, 0, sizeof(c));
    memset(&tlv, 0, sizeof(tlv));
    memset(&rule, 0, sizeof(rule));

    /* Build content: dst MAC 0xaa:bb:cc:dd:ee:ff (0x81), VID 100 (0x83),
     * EtherType 0x88f7 (0x87) */
    c.num_of_component = 3;
    c.component[0].type = 0x81;
    c.component[0].mac[0] = 0xaa; c.component[0].mac[1] = 0xbb;
    c.component[0].mac[2] = 0xcc; c.component[0].mac[3] = 0xdd;
    c.component[0].mac[4] = 0xee; c.component[0].mac[5] = 0xff;
    c.component[1].type = 0x83;
    c.component[1].vid = 100;
    c.component[2].type = 0x87;
    c.component[2].ethertype = 0x88f7;

    ogs_pfcp_encode_eth_packet_filter(&tlv, &c, 1, false, mac, ctag, etype);

    ABTS_TRUE(tc, tlv.presence == 1);
    ABTS_TRUE(tc, tlv.mac_address.presence == 1);
    ABTS_TRUE(tc, tlv.c_tag.presence == 1);
    ABTS_TRUE(tc, tlv.ethertype.presence == 1);

    ogs_pfcp_parse_eth_packet_filter(&rule, &tlv);

    ABTS_TRUE(tc, rule.is_eth);

    for (k = 0; k < rule.eth_content.num_of_component; k++) {
        if (rule.eth_content.component[k].type == 0x81) {
            ABTS_TRUE(tc, rule.eth_content.component[k].mac[0] == 0xaa);
            ABTS_TRUE(tc, rule.eth_content.component[k].mac[5] == 0xff);
            found_dst = true;
        }
        if (rule.eth_content.component[k].type == 0x83) {
            ABTS_INT_EQUAL(tc, 100, (int)rule.eth_content.component[k].vid);
            found_vid = true;
        }
        if (rule.eth_content.component[k].type == 0x87) {
            ABTS_INT_EQUAL(tc, 0x88f7,
                    (int)rule.eth_content.component[k].ethertype);
            found_etype = true;
        }
    }

    ABTS_TRUE(tc, found_dst);
    ABTS_TRUE(tc, found_vid);
    ABTS_TRUE(tc, found_etype);
}

abts_suite *test_eth_flow(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, eth_flow_roundtrip_test, NULL);
    abts_run_test(suite, test_eth_packet_filter_roundtrip, NULL);

    return suite;
}
