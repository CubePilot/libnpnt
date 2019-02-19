/*
 * This file is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Code by Siddharth Bharat Purohit
 */

#pragma once
 /**
 * @file    inc/defines.h
 * @brief   Common Defines
 * @{
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <mxml/mxml.h>
// Defined by user
#include <npnt_config.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
    struct {
        char *raw_permart;
        uint16_t raw_permart_len;
        mxml_node_t *parsed_permart;
        npnt_sha_t pa_sha_handler;
        uint8_t id[16];
        uint8_t id_len;
    } pa_params;

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
    } flight_params;

    struct {
        bool log_started;
        char last_loghash[DIGEST_VALUE_LEN];
        int  log_fd;
        char curr_loghash[DIGEST_VALUE_LEN];
        char base64_buffer[3];
        int8_t base64_buffer_idx;
        npnt_sha_t sha_handler;
    } logger;
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

 /** @} */