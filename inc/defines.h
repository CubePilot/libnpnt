/*
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */



 /**
 * @file    inc/defines.h
 * @brief   Common Defines
 * @{
 */
#ifndef DEFINES_H
#define DEFINES_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mxml/mxml.h>


#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
    char *raw_permart;
    uint16_t raw_permart_len;
    void*   security_handle;
    mxml_node_t *parsed_permart;
    struct {
        float* vertlat;     //degrees
        float* vertlon;     //degrees
        float maxAltitude; //meters
        uint8_t nverts;
    } fence;
    struct {
        char* uinNo;
        char* adcNumber;
        char* ficNumber;
        struct tm flightStartTime;
        struct tm flightEndTime;
    } params;
} npnt_s;

#define NPNT_INV_ART                -1
#define NPNT_INV_AUTH               -3
#define NPNT_INV_STATE              -4
#define NPNT_ALREADY_SET            -5
#define NPNT_UNALLOC_HANDLE         -6
#define NPNT_PARSE_FAILED           -7
#define NPNT_INV_DGST               -8
#define NPNT_INV_SIGN               -9
#define NPNT_BAD_FENCE              -10
#define NPNT_INV_FPARAMS            -11
#define NPNT_INV_BAD_ALT            -12

#ifdef __cplusplus
} // extern "C"
#endif

#endif //#ifndef DEFINES_H

 /** @} */