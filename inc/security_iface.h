/*
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

#include <stdint.h>
#include <defines.h>

#ifdef __cplusplus
extern "C"
{
#endif
 /**
 * @file    inc/log_iface.h
 * @brief   Interface definitions for NPNT Breach logging
 * @{
 */

// User Implemented Methods
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
int8_t npnt_check_authenticity(npnt_s *handle, uint8_t* raw_data, uint16_t raw_data_len, const uint8_t* signature, uint16_t signature_len);

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
int8_t npnt_sign_raw_data(npnt_s *handle, uint8_t* raw_data, uint16_t raw_data_len, uint8_t* signature, uint16_t* signature_len);


//Implemented by libnpnt

/**
 * @brief   Initialise Security interface.
 * @details This method calls the necessary methods to setup security 
 *          interface
 *
 * @param[in] npnt_handle        npnt handle
 * 
 * @return           Errcode of failure, 0 if successful
 * @retval 0         Iface Successfully Setup
 *
 * @iclass security_iface
 */
int8_t npnt_security_init(npnt_s* handle);

#ifdef __cplusplus
} // extern "C"
#endif
 /** @} */
