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

#include <npnt_internal.h>
#include <npnt.h>
#include <mxml/mxml.h>

/**
 * @brief   Sets Current Permission Artifact.
 * @details This method consumes peremission artefact in raw format
 *          and sets up npnt structure.
 *
 * @param[in] npnt_handle       npnt handle
 * @param[in] permart           permission json artefact in base64 format as received
 *                              from server
 * @param[in] permart_length    size of permission json artefact in base64 format as received
 *                              from server
 * @param[in] signature         signature of permart in base64 format
 * @param[in] signature_length  length of the signature of permart in base64 format 
 * 
 * @return           Error id if faillure, 0 if no breach
 * @retval NPNT_INV_ART   Invalid Artefact
 *         NPNT_INV_AUTH  signed by unauthorised entity
 *         NPNT_INV_STATE artefact can't setup in current aircraft state
 *         NPNT_ALREADY_SET artefact already set, free previous artefact first
 * @iclass control_iface
 */
int8_t npnt_set_permart(npnt_s *handle, uint8_t *permart, uint16_t permart_length, uint8_t base64_encoded)
{
    if (!handle) {
        return NPNT_UNALLOC_HANDLE;
    }
    int16_t ret = 0;
    //Extract XML from base64 encoded permart
    if (handle->pa_params.raw_permart) {
        return NPNT_ALREADY_SET;
    }

    if (base64_encoded) {
        handle->pa_params.raw_permart = (char*)base64_decode(permart, permart_length, &handle->pa_params.raw_permart_len);
        if (!handle->pa_params.raw_permart) {
            return NPNT_PARSE_FAILED;
        }
    } else {
        handle->pa_params.raw_permart = (char*)malloc(permart_length);
        if (!handle->pa_params.raw_permart) {
            return NPNT_PARSE_FAILED;
        }
        memcpy(handle->pa_params.raw_permart, permart, permart_length);
    }

    //parse XML permart
    handle->pa_params.parsed_permart = mxmlLoadString(NULL, handle->pa_params.raw_permart, MXML_OPAQUE_CALLBACK);
    if (!handle->pa_params.parsed_permart) {
        return NPNT_PARSE_FAILED;
    }

    //Verify Artifact against Sender's Public Key
    ret = npnt_verify_permart(handle);
    if (ret < 0) {
        return ret;
    }

    //Collect Fence points from verified artefact
    ret = npnt_alloc_and_get_fence_points(handle, handle->fence.vertlat, handle->fence.vertlon);
    if (ret <= 0) {
        handle->fence.nverts = 0;
        return NPNT_BAD_FENCE;
    }
    handle->fence.nverts = ret;
    ret = 0;

    //Get Max Altitude
    ret = npnt_get_max_altitude(handle, &handle->fence.maxAltitude);
    if (ret < 0) {
        return NPNT_INV_BAD_ALT;
    }

    //Set Flight Params from artefact
    ret = npnt_populate_flight_params(handle);
    if (ret < 0) {
        handle->fence.nverts = 0;
        return NPNT_INV_FPARAMS;
    }

    ret = 0;
    return ret;
}

//Verify the data contained in parsed XML
int8_t npnt_verify_permart(npnt_s *handle)
{
    char* raw_perm_without_sign;
    char* signed_info;
    const uint8_t* rcvd_digest_value;
    // char *test_str;
    int16_t permission_length, signedinfo_length;
    char digest_value[DIGEST_VALUE_LEN];
    const uint8_t* signature = NULL;
    uint8_t* raw_signature = NULL;
    uint16_t signature_len, raw_signature_len;
    uint8_t* base64_digest_value = NULL;
    uint16_t base64_digest_value_len;
    uint16_t curr_ptr = 0, curr_length;
    char last_empty_element[20];
    int8_t ret = 0;
    
    reset_sha256(&handle->pa_params.pa_sha_handler);
    
    //Digest Signed Info
    update_sha256(&handle->pa_params.pa_sha_handler, "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">", 
                strlen("<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"));
    signed_info = strstr(handle->pa_params.raw_permart, "<SignedInfo>") + strlen("<SignedInfo>");
    if (signed_info == NULL) {
        ret = NPNT_INV_ART;
        goto fail;
    }
    signedinfo_length = strstr(handle->pa_params.raw_permart, "<SignatureValue") - signed_info;
    if (signedinfo_length < 0) {
        ret = NPNT_INV_ART;
        goto fail;
    }
    while (curr_ptr < signedinfo_length) {
        curr_length = 1;
        if (signed_info[curr_ptr] == '<') {
            while((curr_ptr + curr_length) < signedinfo_length) {
                if (signed_info[curr_ptr + curr_length] == ' ') {
                    last_empty_element[curr_length - 1] = '\0';
                    break;
                } else if (signed_info[curr_ptr + curr_length] == '>') {
                    last_empty_element[0] = '\0';
                    break;
                }
                last_empty_element[curr_length - 1] = signed_info[curr_ptr + curr_length];
                curr_length++;
            }
        }

        if (strlen(last_empty_element) != 0) {
            if (signed_info[curr_ptr] == '/') {
                if (signed_info[curr_ptr + 1] == '>') {
                    update_sha256(&handle->pa_params.pa_sha_handler, "></", 3);
                    update_sha256(&handle->pa_params.pa_sha_handler, last_empty_element, strlen(last_empty_element));
                    last_empty_element[0] = '\0';
                    curr_ptr += curr_length;
                    continue;
                }
            }
        }

        update_sha256(&handle->pa_params.pa_sha_handler, &signed_info[curr_ptr], curr_length);
        curr_ptr += curr_length;
    }
    final_sha256(&handle->pa_params.pa_sha_handler, digest_value);

    //fetch SignatureValue from xml
    signature = (const uint8_t*)mxmlGetOpaque(mxmlFindElement(handle->pa_params.parsed_permart, handle->pa_params.parsed_permart, "SignatureValue", NULL, NULL, MXML_DESCEND));
    if (signature == NULL) {
        ret = NPNT_INV_SIGN;
        goto fail;
    }
    signature_len = strlen((char*)signature);
    raw_signature = base64_decode(signature, signature_len, &raw_signature_len);
    //Check authenticity of the artifact
    if (npnt_check_authenticity(handle, digest_value, DIGEST_VALUE_LEN, raw_signature, raw_signature_len) <= 0) {
        ret = NPNT_INV_AUTH;
        goto fail;
    }

    //Digest Canonicalised Permission Artifact
    raw_perm_without_sign = strstr(handle->pa_params.raw_permart, "<UAPermission");
    if (raw_perm_without_sign == NULL) {
        ret = NPNT_INV_ART;
        goto fail;
    }
    permission_length = strstr(handle->pa_params.raw_permart, "<Signature") - raw_perm_without_sign;
    if (permission_length < 0) {
        ret = NPNT_INV_ART;
        goto fail;
    }

#ifdef DEBUG_ARTPROC
    char* test_str = (char*)malloc(permission_length + 1);
    memcpy(test_str, raw_perm_without_sign, permission_length);
    test_str[permission_length] = '\0';
    printf("\n RAW PERMISSION: \n%s", test_str);
#endif
    reset_sha256(&handle->pa_params.pa_sha_handler);
    curr_ptr = 0;
    curr_length = 0;
    //Canonicalise Permission Artefact by converting Empty elements to start-end tag pairs
    while (curr_ptr < permission_length) {
        curr_length = 1;
        if (raw_perm_without_sign[curr_ptr] == '<') {
            while((curr_ptr + curr_length) < permission_length) {
                if (raw_perm_without_sign[curr_ptr + curr_length] == ' ') {
                    last_empty_element[curr_length - 1] = '\0';
                    break;
                } else if (raw_perm_without_sign[curr_ptr + curr_length] == '>') {
                    last_empty_element[0] = '\0';
                    break;
                }
                last_empty_element[curr_length - 1] = raw_perm_without_sign[curr_ptr + curr_length];
                curr_length++;
            }
        }

        if (strlen(last_empty_element) != 0) {
            if (raw_perm_without_sign[curr_ptr] == '/') {
                if (raw_perm_without_sign[curr_ptr + 1] == '>') {
                    update_sha256(&handle->pa_params.pa_sha_handler, "></", 3);
                    update_sha256(&handle->pa_params.pa_sha_handler, last_empty_element, strlen(last_empty_element));
                    last_empty_element[0] = '\0';
                    curr_ptr += curr_length;
                    continue;
                }
            }
        }

        update_sha256(&handle->pa_params.pa_sha_handler, &raw_perm_without_sign[curr_ptr], curr_length);
        curr_ptr += curr_length;
    }

    //Skip Signature for Digestion
    raw_perm_without_sign = strstr(handle->pa_params.raw_permart, "</Signature>") + strlen("</Signature>");
    update_sha256(&handle->pa_params.pa_sha_handler, raw_perm_without_sign, strlen(raw_perm_without_sign));
    final_sha256(&handle->pa_params.pa_sha_handler, digest_value);
    base64_digest_value = base64_encode((uint8_t*)digest_value, DIGEST_VALUE_LEN, &base64_digest_value_len);
//#ifdef DEBUG_ARTPROC
    printf("\nDigest Value: \n%s\n", base64_digest_value);
    printf("\nDigest Value: \n%s\n", mxmlGetOpaque(mxmlFindElement(handle->pa_params.parsed_permart, handle->pa_params.parsed_permart, "DigestValue", NULL, NULL, MXML_DESCEND)));
//#endif
    //Check Digestion
    rcvd_digest_value = (const uint8_t*)mxmlGetOpaque(mxmlFindElement(handle->pa_params.parsed_permart, handle->pa_params.parsed_permart, "DigestValue", NULL, NULL, MXML_DESCEND));
    for (uint16_t i = 0; i < base64_digest_value_len - 1; i++) {
        if (base64_digest_value[i] != rcvd_digest_value[i]) {
            ret = NPNT_INV_DGST;
            goto fail;
        }
    }

    //base64_digest_value no longer needed
    free(base64_digest_value);
    base64_digest_value = NULL;
fail:
    if (base64_digest_value) {
        free(base64_digest_value);
    }
    return ret;
}

int8_t npnt_alloc_and_get_fence_points(npnt_s* handle, float* vertlat, float* vertlon)
{
    //Calculate number of vertices
    mxml_node_t *first_coordinate, *current_coordinate;
    uint16_t nverts = 0;
    const char* lat_str;
    const char* lon_str;
    first_coordinate = mxmlGetFirstChild(mxmlFindElement(handle->pa_params.parsed_permart, handle->pa_params.parsed_permart, "Coordinates", NULL, NULL, MXML_DESCEND));
    current_coordinate = first_coordinate;
    while (current_coordinate) {
        if (mxmlGetElement(current_coordinate) == NULL) {
            current_coordinate = mxmlGetNextSibling(current_coordinate);
            continue;
        }
        if (strcmp(mxmlGetElement(current_coordinate), "Coordinate") != 0) {
            current_coordinate = mxmlGetNextSibling(current_coordinate);
            continue;
        }
        current_coordinate = mxmlGetNextSibling(current_coordinate);
        nverts++;
    }

    //Allocate vertices
    vertlat = (float*)malloc(nverts*sizeof(float));
    vertlon = (float*)malloc(nverts*sizeof(float));

    if (!vertlat || !vertlon) {
        return -1;
    }
    //read coordinates
    nverts = 0;
    current_coordinate = first_coordinate;
    while(current_coordinate) {
        if (mxmlGetElement(current_coordinate) == NULL) {
            current_coordinate = mxmlGetNextSibling(current_coordinate);
            continue;
        }
        if (strcmp(mxmlGetElement(current_coordinate), "Coordinate") != 0) {
            current_coordinate = mxmlGetNextSibling(current_coordinate);
            continue;
        }
        lat_str = mxmlElementGetAttr(current_coordinate, "latitude");
        if (lat_str) {
            vertlat[nverts] = atof(lat_str);
        } else {
            goto fail;
        }
        lon_str = mxmlElementGetAttr(current_coordinate, "longitude");
        if (lon_str) {
            vertlon[nverts] = atof(lon_str);
        } else {
            goto fail;
        }
        // printf("\n%s %.20f %.20f\n", mxmlGetElement(current_coordinate), vertlat[nverts], vertlon[nverts]);
        current_coordinate = mxmlGetNextSibling(current_coordinate);
        nverts++;
    }
    handle->fence.vertlat = vertlat;
    handle->fence.vertlon = vertlon;
    return nverts;
fail:
    free(vertlat);
    free(vertlon);
    return -1;
}

int8_t npnt_get_max_altitude(npnt_s* handle, float* altitude)
{
    if (!altitude) {
        return -1;
    }
 #ifndef PERMART_SKIP_ALT
    const char* alt_str;
    mxml_node_t* flightparams;
    flightparams = mxmlFindElement(handle->parsed_permart, handle->parsed_permart, "FlightParameters", NULL, NULL, MXML_DESCEND);
    if (flightparams == NULL) {
        return -1;
    }
    alt_str = mxmlElementGetAttr(flightparams, "maxAltitude");
    if (alt_str) {
        *altitude = atof(alt_str);
        // printf("Altitude: %f\n", *altitude);
    } else {
        return -1;
    }
#else
    *altitude = 1200;
#endif
    return 0;
}

int8_t npnt_ist_date_time_to_unix_time(const char* dt_string, struct tm* date_time)
{
    char data[5] = {};
    if (strlen(dt_string) < 19 && strlen(dt_string) > 40) {
        return -1;
    }
    if (!date_time) {
        return -1;
    }
    memset(date_time, 0, sizeof(struct tm));

    //read year
    memcpy(data, dt_string, 4);
    data[4] = '\0';
    date_time->tm_year = atoi(data) - 1900;
    //read month
    memcpy(data, &dt_string[5], 2);
    data[2] = '\0';
    date_time->tm_mon = atoi(data) - 1;
    //read day
    memcpy(data, &dt_string[8], 2);
    data[2] = '\0';
    date_time->tm_mday = atoi(data);
    //read hour
    memcpy(data, &dt_string[11], 2);
    data[2] = '\0';
    date_time->tm_hour = atoi(data) - 5; //also apply IST to UTC offset
    //read minute
    memcpy(data, &dt_string[14], 2); //also apply IST to UTC offset
    data[2] = '\0';
    date_time->tm_min = atoi(data) - 30;
    //read second
    memcpy(data, &dt_string[17], 2);
    data[2] = '\0';
    date_time->tm_sec = atoi(data);

    return 0;
    // time_t tim = mktime(date_time);
    // printf("\nUnixTime: %s\n", ctime(&tim));
}

char* npnt_get_attr(mxml_node_t *node, const char* attr)
{
    const char* tmp = NULL;
    char* ret = NULL;
    tmp = mxmlElementGetAttr(node, attr);
    if (!tmp) {
        return NULL;
    }
    ret = (char*)malloc(strlen(tmp) + 1);
    if (!ret) {
        return NULL;
    }
    strcpy(ret, tmp);
    return ret;
}

int8_t npnt_populate_flight_params(npnt_s* handle)
{
    mxml_node_t *ua_detail, *flight_params;
    ua_detail = mxmlFindElement(handle->pa_params.parsed_permart, handle->pa_params.parsed_permart, "UADetails", NULL, NULL, MXML_DESCEND);
    if (!ua_detail) {
        return NPNT_INV_FPARAMS;
    }
    flight_params = mxmlFindElement(handle->pa_params.parsed_permart, handle->pa_params.parsed_permart, "FlightParameters", NULL, NULL, MXML_DESCEND);
    if (!flight_params) {
        return NPNT_INV_FPARAMS;
    }

    handle->flight_params.uinNo = npnt_get_attr(ua_detail, "uinNo");
    if (!handle->flight_params.uinNo) {
        return NPNT_INV_FPARAMS;
    }

#ifndef PERMART_SKIP_FPARAMS
    handle->params.adcNumber = npnt_get_attr(flight_params, "adcNumber");
    if (!handle->params.adcNumber) {
        return NPNT_INV_FPARAMS;
    }

    handle->params.ficNumber = npnt_get_attr(flight_params, "ficNumber");
    if (!handle->params.ficNumber) {
        return NPNT_INV_FPARAMS;
    }
#else
    handle->flight_params.adcNumber = "RCA0001";
    handle->flight_params.ficNumber = "00000RO";
#endif

    if (npnt_ist_date_time_to_unix_time(mxmlElementGetAttr(flight_params, "flightEndTime"), &handle->flight_params.flightEndTime) < 0) {
        return NPNT_INV_FPARAMS;
    }
    if (npnt_ist_date_time_to_unix_time(mxmlElementGetAttr(flight_params, "flightStartTime"), &handle->flight_params.flightStartTime) < 0) {
        return NPNT_INV_FPARAMS;
    }
    return 0;
}


