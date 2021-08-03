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
 * @file    inc/npnt.h
 * @brief   Common Headers for NPNT library
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

//Common helper headers, to be defined by user
void reset_sha256(npnt_sha_t* sha_handler);
void update_sha256(npnt_sha_t* sha_handler, const char* data, uint16_t data_len);
void final_sha256(npnt_sha_t* sha_handler, uint8_t* hash);
bool open_logfile(npnt_s *handle);
bool write_logfile(npnt_s *handle, const char* data, uint32_t len);
bool close_logfile(npnt_s *handle);
bool sign_data_with_self_key(uint8_t* data, uint32_t len, uint8_t *signature);
bool record_lastloghash(uint8_t* data, uint8_t data_len);
char* hexify(const uint8_t* bytes, uint32_t len);

#ifdef __cplusplus
} // extern "C"
#endif
