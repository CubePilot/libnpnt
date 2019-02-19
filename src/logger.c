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


int npnt_log_write(npnt_s* handle, const char* data, uint32_t len)
{
    if (handle->logger.log_fd <= 0) {
        return -1;
    }
    // do digest
    for (uint8_t i=0; i<len;i++) {
        handle->logger.base64_buffer[handle->logger.base64_buffer_idx++] = data[i];
        handle->logger.base64_buffer_idx %= 3;

        if (handle->logger.base64_buffer_idx == 0) {
            uint16_t base64_data_len;
            char* base64_data = base64url_encode((const uint8_t*)handle->logger.base64_buffer, 3, &base64_data_len);

            if (!write_logfile(handle, base64_data, base64_data_len)) {
                return -1;
            }
            update_sha256(&handle->logger.sha_handler, base64_data, base64_data_len);
            free(base64_data);
        }
    }
    return 0;
}

int npnt_log_common_data(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt)
{
    char data[40];
    uint8_t ret = snprintf(data, 40, "\"TimeStamp\":%ld,", unix_ts);
    if (ret >= 40 || ret <= 0) {
        return -1;
    }
    if (npnt_log_write(handle, data, ret) < 0) {
        return -1;
    }

    ret = snprintf(data, 40, "\"Longitude\":%.6f,", lon);
    if (ret >= 40 || ret <= 0) {
        return -1;
    }
    if (npnt_log_write(handle, data, ret) < 0) {
        return -1;
    }


    ret = snprintf(data, 40, "\"Latitude\":%.6f,", lat);
    if (ret >= 40 || ret <= 0) {
        return -1;
    }
    if (npnt_log_write(handle, data, ret) < 0) {
        return -1;
    }

    ret = snprintf(data, 40, "\"Altitude\":%.4f", alt);
    if (ret >= 40 || ret <= 0) {
        return -1;
    }
    if (npnt_log_write(handle, data, ret) < 0) {
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

    //base64 of JWS header for {"alg":"RS256"}
    const char header[] = "eyJhbGciOiJSUzI1NiJ9";
    
    write_logfile(handle, "{\"protected\":\"", strlen("{\"protected\":\""));

    reset_sha256(&handle->logger.sha_handler);
    update_sha256(&handle->logger.sha_handler, header, strlen(header));
    update_sha256(&handle->logger.sha_handler, ".", 1);

    write_logfile(handle, header, strlen(header));
    write_logfile(handle, "\",\"payload\":\"", strlen("\",\"payload\":\""));


    memset(handle->logger.curr_loghash, 0, DIGEST_VALUE_LEN);
    record_lastloghash((uint8_t*)handle->logger.curr_loghash, DIGEST_VALUE_LEN);

    // Write initial bits
    npnt_log_write(handle, "{\"FlightLog\":{\"PermissionArtefact\":\"", strlen("{\"FlightLog\":{\"PermissionArtefact\":\""));

    //npnt_log_write(handle, (const char*)handle->pa_params.id, handle->pa_params.id_len);

    npnt_log_write(handle, "\",\"previous_log_hash\":\"", strlen("\",\"previous_log_hash\":\""));

    uint16_t base64_hash_len = 0;
    char *base64_hash = base64url_encode(handle->logger.last_loghash
, DIGEST_VALUE_LEN, &base64_hash_len);

    if (base64_hash == NULL) {
        return -1;
    }
    npnt_log_write(handle, (const char*)base64_hash, base64_hash_len);
    npnt_log_write(handle, "\",\"LogEntries\":[", strlen("\",\"LogEntries\":["));

    if (npnt_log_write(handle, "{\"Entry_type\":\"TAKEOFF/ARM\",", strlen("{\"Entry_type\":\"TAKEOFF/ARM\",")) < 0) {
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
    char data[] = ",{\"Entry_type\":\"GPS_FAIL\",";

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
    const char data[] = ",{\"Entry_type\":\"GEOFENCE_BREACH\",";

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
    const char data[] = ",{\"Entry_type\":\"TIME_BREACH\",";

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
    const char data[] = ",{\"Entry_type\":\"LAND/DISARM\",";

    if (npnt_log_write(handle, data, strlen(data)) < 0) {
        return -1;
    }

    if (npnt_log_common_data(handle, unix_ts, lat, lon, alt) < 0) {
        return -1;
    }
    const char logentry_clos[] = "]}}";
    npnt_log_write(handle, logentry_clos, strlen(logentry_clos));


    //there might be a need for padding
    if (handle->logger.base64_buffer_idx != 0) {
        uint16_t base64_data_len;
        char* base64_data = base64url_encode((const uint8_t*)handle->logger.base64_buffer, handle->logger.base64_buffer_idx, &base64_data_len);
        if (!write_logfile(handle, base64_data, base64_data_len)) {
            return -1;
        }
        update_sha256(&handle->logger.sha_handler, base64_data, base64_data_len);
        printf("%s",base64_data);
        free(base64_data);
    }

    final_sha256(&handle->logger.sha_handler, handle->logger.curr_loghash);

#ifdef DEBUG_LOGGER
    uint8_t* base64_final_hash = base64url_encode((const uint8_t*)handle->logger.curr_loghash, DIGEST_VALUE_LEN, NULL);
    printf("\nFinal Hash: %s", base64_final_hash);
    free(base64_final_hash);
#endif

    write_logfile(handle, "\",\"signature\":\"", strlen("\",\"signature\":\""));

    uint8_t signature[SIGNATURE_BYTE_LEN+1];
    sign_data_with_self_key(handle->logger.curr_loghash, DIGEST_VALUE_LEN, signature);

    uint8_t* base64_signature = base64url_encode(signature, SIGNATURE_BYTE_LEN, NULL);
    write_logfile(handle, base64_signature, strlen(base64_signature));
    write_logfile(handle, "\"}", strlen("\"}"));

    record_lastloghash((uint8_t*)handle->logger.curr_loghash, DIGEST_VALUE_LEN);

    close_logfile(handle);
    handle->logger.log_started = false;
    free(base64_signature);
    return 0;
}
