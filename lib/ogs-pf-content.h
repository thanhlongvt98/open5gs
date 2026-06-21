/*
 * SPDX-FileCopyrightText: Copyright (C) 2026 Le Thanh Long
 * SPDX-License-Identifier: MIT
 *
 * Shared packet-filter content model (TS 24.501 §9.11.4.13).
 * Kept free of lib/proto ↔ lib/ipfw circular includes.
 */

#ifndef OGS_PF_CONTENT_H
#define OGS_PF_CONTENT_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_MAX_NUM_OF_PACKET_FILTER_COMPONENT 16
#define OGS_PACKET_FILTER_MATCH_ALL 1
#define OGS_PACKET_FILTER_PROTOCOL_IDENTIFIER_NEXT_HEADER_TYPE 48
#define OGS_PACKET_FILTER_IPV4_REMOTE_ADDRESS_TYPE 16
#define OGS_PACKET_FILTER_IPV4_LOCAL_ADDRESS_TYPE 17
#define OGS_PACKET_FILTER_IPV6_REMOTE_ADDRESS_TYPE 32
#define OGS_PACKET_FILTER_IPV6_REMOTE_ADDRESS_PREFIX_LENGTH_TYPE 33
#define OGS_PACKET_FILTER_IPV6_LOCAL_ADDRESS_TYPE 34
#define OGS_PACKET_FILTER_IPV6_LOCAL_ADDRESS_PREFIX_LENGTH_TYPE 35
#define OGS_PACKET_FILTER_SINGLE_LOCAL_PORT_TYPE 64
#define OGS_PACKET_FILTER_LOCAL_PORT_RANGE_TYPE 65
#define OGS_PACKET_FILTER_SINGLE_REMOTE_PORT_TYPE 80
#define OGS_PACKET_FILTER_REMOTE_PORT_RANGE_TYPE 81
#define OGS_PACKET_FILTER_SECURITY_PARAMETER_INDEX_TYPE 96
#define OGS_PACKET_FILTER_TOS_TRAFFIC_CLASS_TYPE 112
#define OGS_PACKET_FILTER_FLOW_LABEL_TYPE 128
#define OGS_PACKET_FILTER_DESTINATION_MAC_ADDRESS_TYPE 0x81
#define OGS_PACKET_FILTER_SOURCE_MAC_ADDRESS_TYPE      0x82
#define OGS_PACKET_FILTER_8021Q_C_TAG_VID_TYPE         0x83
#define OGS_PACKET_FILTER_8021Q_C_TAG_PCP_DEI_TYPE     0x85
#define OGS_PACKET_FILTER_ETHERTYPE_TYPE               0x87

typedef struct ogs_pf_content_s {
    uint8_t length;
    struct {
        uint8_t type;
        union {
            uint8_t proto;
            struct {
                uint32_t addr;
                uint32_t mask;
            } ipv4;
            struct {
                uint32_t addr[4];
                uint8_t prefixlen;
            } ipv6;
            struct {
                uint32_t addr[4];
                uint32_t mask[4];
            } ipv6_mask;
            struct {
                uint16_t low;
                uint16_t high;
            } port;
            uint8_t mac[6];
            uint16_t vid;
            uint8_t pcp_dei;
            uint16_t ethertype;
        };
    } component[OGS_MAX_NUM_OF_PACKET_FILTER_COMPONENT];
    uint8_t num_of_component;
} ogs_pf_content_t;

#ifdef __cplusplus
}
#endif

#endif /* OGS_PF_CONTENT_H */
