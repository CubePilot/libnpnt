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

#ifndef IST_TIME_OFFSET
#define IST_TIME_OFFSET 19800
#endif

int npnt_log_write(npnt_s* handle, const char* data, uint32_t len)
{
    if (handle->logger.log_fd <= 0) {
        return -1;
    }
    if (!write_logfile(handle, data, len)) {
        return -1;
    }
    // do digest
    update_sha256(&handle->logger.sha_handler, data, len);
    return 0;
}

static void remove_trailing_zeros(char* data)
{
    for (uint8_t i = (strlen(data)-1); i > 0; i--) {
        if (data[i] == '0') {
            data[i] = '\0';
        } else {
            break;
        }
    }
}

int npnt_log_common_data(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt)
{
    char data[40];
    uint8_t ret = snprintf(data, 40, "\"timeStamp\":%ld,", unix_ts + IST_TIME_OFFSET);
    if (ret >= 40 || ret <= 0) {
        return -1;
    }
    if (npnt_log_write(handle, data, ret) < 0) {
        return -1;
    }

    ret = snprintf(data, 40, "\"longitude\":%.6f", lon);
    remove_trailing_zeros(data);
    if (ret >= 40 || ret <= 0) {
        return -1;
    }
    if (npnt_log_write(handle, data, strlen(data)) < 0) {
        return -1;
    }


    ret = snprintf(data, 40, ",\"latitude\":%.6f", lat);
    remove_trailing_zeros(data);
    if (ret >= 40 || ret <= 0) {
        return -1;
    }
    if (npnt_log_write(handle, data, strlen(data)) < 0) {
        return -1;
    }

    ret = snprintf(data, 40, ",\"altitude\":%.4f", alt);
    remove_trailing_zeros(data);
    if (ret >= 40 || ret <= 0) {
        return -1;
    }
    if (npnt_log_write(handle, data, strlen(data)) < 0) {
        return -1;
    }

    char clos_brace = '}';
    if (npnt_log_write(handle, &clos_brace, 1)) {
        return -1;
    }
    return 0;
}

int npnt_start_logger(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt)
{
    if (handle->logger.log_started) {
        return 0;
    }

    if (!open_logfile(handle)) {
        return -1;
    }

#ifdef SIGN_LOG
    //base64 of JWS header for {"alg":"RS256"}
    const char header[] = "eyJhbGciOiJSUzI1NiJ9";
    
    write_logfile(handle, "{\"protected\":\"", strlen("{\"protected\":\""));
#endif

    reset_sha256(&handle->logger.sha_handler);

#ifdef SIGN_LOG
    update_sha256(&handle->logger.sha_handler, header, strlen(header));
    update_sha256(&handle->logger.sha_handler, ".", 1);

    write_logfile(handle, header, strlen(header));
    write_logfile(handle, "\",\"payload\":\"", strlen("\",\"payload\":\""));
#endif

    memset(handle->logger.curr_loghash, 0, DIGEST_VALUE_LEN);
    // record_lastloghash((uint8_t*)handle->logger.curr_loghash, DIGEST_VALUE_LEN);

    // Write initial bits
#ifdef SIGN_LOG
    npnt_log_write(handle, "{\"flightLog\":");
#endif
    npnt_log_write(handle, "{\"permissionArtefact\":\"", strlen("{\"permissionArtefact\":\""));

    if (handle->pa_params.id) {
        npnt_log_write(handle, (const char*)handle->pa_params.id, strlen(handle->pa_params.id));
    }

    npnt_log_write(handle, "\",\"previousLogHash\":\"", strlen("\",\"previousLogHash\":\""));

    if (handle->logger.last_loghash) {
        char *hash = hexify(handle->logger.last_loghash, DIGEST_VALUE_LEN);
        if (hash != NULL) {
            printf("Prev Hash: %s\n", hash);
            npnt_log_write(handle, hash, strlen(hash));
            free(hash); // we are done with hash
        }
    }
    npnt_log_write(handle, "\",\"logEntries\":[", strlen("\",\"logEntries\":["));

    if (npnt_log_write(handle, "{\"entryType\":\"TAKEOFF/ARM\",", strlen("{\"entryType\":\"TAKEOFF/ARM\",")) < 0) {
        return -1;
    }

    npnt_log_common_data(handle, unix_ts, lat, lon, alt);
    handle->logger.log_started = true;
    return 0;
}

int npnt_log_gps_fail_event(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt) {
    if (!handle->logger.log_started) {
        return 0;
    }
    char data[] = ",{\"entryType\":\"GPS_FAIL\",";

    if (npnt_log_write(handle, data, strlen(data)) < 0) {
        return -1;
    }

    if (npnt_log_common_data(handle, unix_ts, lat, lon, alt) < 0) {
        return -1;
    }
    return 0;
}

int npnt_log_fence_breach_event(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt) {
    if (!handle->logger.log_started) {
        return 0;
    }
    const char data[] = ",{\"entryType\":\"GEOFENCE_BREACH\",";

    if (npnt_log_write(handle, data, strlen(data)) < 0) {
        return -1;
    }

    if (npnt_log_common_data(handle, unix_ts, lat, lon, alt) < 0) {
        return -1;
    }
    return 0;
}

int npnt_log_time_breach_event(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt) {
    if (!handle->logger.log_started) {
        return 0;
    }
    const char data[] = ",{\"entryType\":\"TIME_BREACH\",";

    if (npnt_log_write(handle, data, strlen(data)) < 0) {
        return -1;
    }

    if (npnt_log_common_data(handle, unix_ts, lat, lon, alt) < 0) {
        return -1;
    }
    return 0;
}

int npnt_stop_logger(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt) {
    if (!handle->logger.log_started) {
        return 0;
    }
    const char data[] = ",{\"entryType\":\"LAND/DISARM\",";

    if (npnt_log_write(handle, data, strlen(data)) < 0) {
        return -1;
    }

    if (npnt_log_common_data(handle, unix_ts, lat, lon, alt) < 0) {
        return -1;
    }
    const char logentry_clos[] = "]}";
    npnt_log_write(handle, logentry_clos, strlen(logentry_clos));

    final_sha256(&handle->logger.sha_handler, handle->logger.curr_loghash);

#ifdef DEBUG_LOGGER
    uint8_t* base64_final_hash = base64url_encode((const uint8_t*)handle->logger.curr_loghash, DIGEST_VALUE_LEN, NULL);
    printf("\nFinal Hash: %s", base64_final_hash);
    free(base64_final_hash);
#endif

#ifdef SIGN_LOG
    write_logfile(handle, "\",\"signature\":\"", strlen("\",\"signature\":\""));

    uint8_t signature[SIGNATURE_BYTE_LEN+1];
    sign_data_with_self_key(handle->logger.curr_loghash, DIGEST_VALUE_LEN, signature);

    uint8_t* base64_signature = base64url_encode(signature, SIGNATURE_BYTE_LEN, NULL);
    write_logfile(handle, base64_signature, strlen(base64_signature));
    write_logfile(handle, "\"}", strlen("\"}"));
#endif
    record_lastloghash((uint8_t*)handle->logger.curr_loghash, DIGEST_VALUE_LEN);

    close_logfile(handle);
    handle->logger.log_started = false;
#ifdef SIGN_LOG
    free(base64_signature);
#endif
    return 0;
}
