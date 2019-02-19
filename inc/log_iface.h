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
 * @file    inc/log_iface.h
 * @brief   Interface definitions for NPNT Breach logging
 * @{
 */


#include <defines.h>

#ifdef __cplusplus
extern "C"
{
#endif
int npnt_start_logger(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt);
int npnt_stop_logger(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt);
int npnt_log_gps_fail_event(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt);
int npnt_log_fence_breach_event(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt);
int npnt_log_time_breach_event(npnt_s* handle, time_t unix_ts, float lat, float lon, float alt);

#ifdef __cplusplus
} // extern "C"
#endif

 /** @} */
