/*
 * This file is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>


// User Implemented Methods

/**
 * @brief   Sets up Security module and return handler.
 * @details Implementer of this method needs initialise security 
 *          mechanism as specified by the regulation and share the 
 *          handle to the same via this method
 *
 * @param[in] npnt_handle      npnt handle
 * 
 * @return              pointer to security handler.
 * @retval NULL         security handler failed to initialise.
 *
 * @iclass security_iface
 */
void* npnt_set_security_handle(npnt_s *npnt_handle);


/**
 * @brief   Checks if the raw data is authentic.
 * @details Implementer of this method needs to check the authenticity
 *          of raw data with signature against the public key provided 
 *          by DGCA Server.
 *
 * @param[in] npnt_handle        npnt handle
 * @param[in] raw_data           signed raw data to be authenticated
 * @param[in] raw_data_len       signed raw data to be authenticated
 * @param[in] signature          signature of signed raw data
 * @param[in] signature_len      length of signature
 * 
 * @return           Errcode of authentication check, 0 if authentication was successful
 * @retval 0         Successful Authentication
 *
 * @iclass security_iface
 */
int npnt_check_authenticity(npnt_s *npnt_handle, uint8_t* raw_data, uint16_t raw_data_len, uint8_t* signature, uint16_t signature_len);

/**
 * @brief   Signs raw data.
 * @details Implementer of this method needs to sign the raw data
 *          and signature against the private key generated in-system.
 *
 * @param[in] npnt_handle        npnt handle
 * @param[in] raw_data           signed raw data to be authenticated
 * @param[in] raw_data_len       signed raw data to be authenticated
 * @param[in] signature          signature of signed raw data
 * @param[in] signature_len      length of signature
 * @param[out] signature_len     updated length of signature
 * 
 * @return           Errcode of signature failure, 0 if signature was generated successfully
 * @retval 0         Successfully Signed
 *
 * @iclass security_iface
 */
int npnt_sign_raw_data(npnt_s *npnt_handle, uint8_t* raw_data, uint16_t raw_data_len, uint8_t* signature, uint16_t* signature_len);


//Implemented by libnpnt

/**
 * @brief   Initialise Security interface.
 * @details This method needs to sign the raw data
 *          and signature against the private key generated in-system.
 *
 * @param[in] npnt_handle        npnt handle
 * @param[in] raw_data           signed raw data to be authenticated
 * @param[in] raw_data_len       signed raw data to be authenticated
 * @param[in] signature          signature of signed raw data
 * @param[in] signature_len      length of signature
 * @param[out] signature_len     updated length of signature
 * 
 * @return           Errcode of signature failure, 0 if signature was generated successfully
 * @retval 0         Successfully Signed
 *
 * @iclass security_iface
 */

int npnt_security_init(npnt_s* npnt_handle);