/*
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/. 
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

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
uint8_t* base64_encode(const uint8_t *src, uint16_t len, uint16_t *out_len);

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

 /** @} */