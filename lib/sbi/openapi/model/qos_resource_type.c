
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "qos_resource_type.h"

char* OpenAPI_qos_resource_type_ToString(OpenAPI_qos_resource_type_e qos_resource_type)
{
    /* TS 29.571 QosResourceType values: NON_GBR / GBR / DELAY_CRITICAL_GBR. The
     * open5gs enum identifiers are *_CRITICAL_GBR but the wire JSON strings must
     * be the spec values for interoperability. */
    const char *qos_resource_typeArray[] =  { "NULL", "NON_GBR", "GBR", "DELAY_CRITICAL_GBR" };
    size_t sizeofArray = sizeof(qos_resource_typeArray) / sizeof(qos_resource_typeArray[0]);
    if (qos_resource_type < sizeofArray)
        return (char *)qos_resource_typeArray[qos_resource_type];
    else
        return (char *)"Unknown";
}

OpenAPI_qos_resource_type_e OpenAPI_qos_resource_type_FromString(char* qos_resource_type)
{
    int stringToReturn = 0;
    /* TS 29.571 QosResourceType values: NON_GBR / GBR / DELAY_CRITICAL_GBR. The
     * open5gs enum identifiers are *_CRITICAL_GBR but the wire JSON strings must
     * be the spec values for interoperability. */
    const char *qos_resource_typeArray[] =  { "NULL", "NON_GBR", "GBR", "DELAY_CRITICAL_GBR" };
    size_t sizeofArray = sizeof(qos_resource_typeArray) / sizeof(qos_resource_typeArray[0]);
    while (stringToReturn < sizeofArray) {
        if (strcmp(qos_resource_type, qos_resource_typeArray[stringToReturn]) == 0) {
            return stringToReturn;
        }
        stringToReturn++;
    }
    return 0;
}

