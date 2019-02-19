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

 /**
 * @file    inc/npnt_internal.h
 * @brief   Internal methods and structs
 * @{
 */
#include <defines.h>
#include <log_iface.h>
#include <security_iface.h>
#include <control_iface.h>


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * null terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
uint8_t* base64_encode(const uint8_t *src, uint16_t len, uint16_t *out_len);
uint8_t* base64url_encode(const uint8_t *src, uint16_t len, uint16_t *out_len);

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
uint8_t* base64_decode(const uint8_t *src, uint16_t len, uint16_t *out_len);

int8_t npnt_ist_date_time_to_unix_time(const char* dt_string, struct tm* date_time);
char* npnt_get_attr(mxml_node_t *node, const char* attr);

#ifdef __cplusplus
} // extern "C"
#endif
 /** @} */