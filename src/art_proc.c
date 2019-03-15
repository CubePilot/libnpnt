/*
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

#include <npnt_internal.h>

int8_t npnt_init_handle(npnt_s *handle)
{
    if (!handle) {
        return NPNT_UNALLOC_HANDLE;
    }
    handle->parsed_permart = NULL;
    handle->raw_permart = NULL;
    handle->raw_permart_len = 0;
    handle->security_handle = NULL;
    return 0;
}

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
int8_t npnt_set_permart(npnt_s *handle, uint8_t *permart, uint16_t permart_length)
{
    if (!handle) {
        return NPNT_UNALLOC_HANDLE;
    }
    //Extract XML from base64 encoded permart
    if (handle->raw_permart) {
        return NPNT_ALREADY_SET;
    }

    handle->raw_permart = base64_decode(permart, permart_length, &handle->raw_permart_len);
    if (!handle->raw_permart) {
        return NPNT_PARSE_FAILED;
    }

    //parse XML permart
    handle->parsed_permart = mxmlLoadString(NULL, handle->raw_permart, MXML_OPAQUE_CALLBACK);
    if (!handle->parsed_permart) {
        return NPNT_PARSE_FAILED;
    }

    return npnt_verify_permart(handle);
}

//Verify the data contained in parsed XML
int8_t npnt_verify_permart(npnt_s *handle)
{
    char* raw_perm_without_sign;
    char* rcvd_digest_value;
    // char *test_str;
    int16_t permission_length;
    char digest_value[20];
    char* base64_digest_value = NULL;
    uint16_t base64_digest_value_len;
    uint16_t curr_ptr = 0, curr_length;
    char last_empty_element[20];
    int8_t ret = 0;
    //Digest Canonicalised Permission Artifact
    raw_perm_without_sign = strstr(handle->raw_permart, "<UAPermission>");
    if (raw_perm_without_sign == NULL) {
        ret = NPNT_INV_ART;
        goto fail;
    }
    permission_length = strstr(handle->raw_permart, "<Signature") - raw_perm_without_sign;
    if (permission_length < 0) {
        ret = NPNT_INV_ART;
        goto fail;
    }
    // test_str = (char*)malloc(permission_length + 1);
    // memcpy(test_str, raw_perm_without_sign, permission_length);
    // test_str[permission_length] = '\0';
    // printf("\n RAW PERMISSION: \n%s", test_str);

    reset_sha1();

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
                    update_sha1("></", 3);
                    update_sha1(last_empty_element, strlen(last_empty_element));
                    last_empty_element[0] = '\0';
                    curr_ptr += curr_length;
                    continue;
                }
            }
        }

        update_sha1(&raw_perm_without_sign[curr_ptr], curr_length);
        curr_ptr += curr_length;
    }

    //Skip Signature for Digestion
    raw_perm_without_sign = strstr(handle->raw_permart, "</Signature>") + strlen("</Signature>");
    update_sha1(raw_perm_without_sign, strlen(raw_perm_without_sign));
    final_sha1(digest_value);
    base64_digest_value = base64_encode(digest_value, 20, &base64_digest_value_len);
    // printf("\nDigest Value: \n%s\n", base64_digest_value);
    // printf("\nDigest Value: \n%s\n", mxmlGetOpaque(mxmlFindElement(handle->parsed_permart, handle->parsed_permart, "DigestValue", NULL, NULL, MXML_DESCEND)));
    
    //Check Digestion
    rcvd_digest_value = mxmlGetOpaque(mxmlFindElement(handle->parsed_permart, handle->parsed_permart, "DigestValue", NULL, NULL, MXML_DESCEND));
    for (uint16_t i = 0; i < base64_digest_value_len - 1; i++) {
        if (base64_digest_value[i] != rcvd_digest_value[i]) {
            ret = NPNT_INV_DGST;
            goto fail;
        }
    }

fail:
    if (base64_digest_value) {
        free(base64_digest_value);
    }
    return ret;
}