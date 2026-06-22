/*
 * SPDX-FileCopyrightText: Copyright (C) 2026 Le Thanh Long
 * SPDX-License-Identifier: MIT
 */

#include "ogs-sbi.h"
#include "ipfw/ogs-ipfw.h"
#include "core/abts.h"

static void eth_flow_roundtrip_test(abts_case *tc, void *data)
{
    ogs_pf_content_t content;

    ogs_pf_content_from_eth_sentinel(
            "eth|aa:bb:cc:dd:ee:ff|11:22:33:44:55:66|100|5|88f7", &content);

    ABTS_INT_EQUAL(tc, 5, content.num_of_component);
}

abts_suite *test_eth_flow(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, eth_flow_roundtrip_test, NULL);

    return suite;
}
