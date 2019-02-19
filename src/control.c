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

#include <control_iface.h>

int8_t npnt_init_handle(npnt_s *handle)
{
    if (!handle) {
        return NPNT_UNALLOC_HANDLE;
    }
    handle->pa_params.parsed_permart = NULL;
    handle->pa_params.raw_permart = NULL;
    handle->pa_params.raw_permart_len = 0;
    return 0;
}


int8_t npnt_reset_handle(npnt_s *handle)
{
    if (!handle) {
        return NPNT_UNALLOC_HANDLE;
    }

    if (handle->pa_params.raw_permart) {
        free(handle->pa_params.raw_permart);
    }
    
    if (handle->pa_params.parsed_permart) {
        free(handle->pa_params.parsed_permart);
    }
    
    if (handle->fence.vertlat) {
        free(handle->fence.vertlat);
    }

    if (handle->fence.vertlon) {
        free(handle->fence.vertlon);
    }

    if (handle->flight_params.uinNo) {
        handle->flight_params.uinNo = NULL;
    }

    if (handle->flight_params.adcNumber) {
        handle->flight_params.adcNumber = NULL;
    }

    if (handle->flight_params.ficNumber) {
        handle->flight_params.ficNumber = NULL;
    }

    memset(handle, 0, sizeof(npnt_s));

    return 0;
}
