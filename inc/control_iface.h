/*
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

#ifndef CONTROL_IFACE_H
#define CONTROL_IFACE_H 
 /**
 * @file    inc/control_iface.h
 * @brief   Interface definitions for NPNT control
 * @{
 */

#include <defines.h>
#include <stdint.h>
#include <stdbool.h>
//User Implemented Methods
/**
 * @brief   Returns Current GPS Time in 64bit UTC format.
 * @details This method returns time in UTC format
 *
 * 
 * @return           Time in 64bit UTC
 * @retval 0         GPS Time not available
 *
 * @iclass control_iface
 */
uint64_t npnt_utc_time();

/**
 * @brief   Return Absolute Location 
 * @details This method returns lattitude and longitude in degrees
 *          and Altitude in meters Above Ground Level
 *
 * @param[out] 
 * 
 * @return           -Errorcode if failure, 0 if GPS position available
 * @retval NPNT_ERR_POS   Absolute position not available
 *
 * @iclass control_iface
 */
int8_t npnt_abs_position(float *gps_lat, float *gps_lon, float *altitude_agl);

/**
 * @brief   Return Absolute Location 
 * @details This method returns lattitude and longitude in degrees
 *          and Altitude in meters Above Ground Level
 *
 * @param[out] 
 * 
 * @return            Code of aircraft state
 * @retval NPNT_GPS_WAIT   Waiting for GPS lock
 *         NPNT_PERM_WAIT  Waiting for permission
 *         NPNT_RTF        Ready to Fly
 *         NPNT_ARMED      actuators activated
 *         NPNT_INFLIGHT   aircraft flying
 *         NPNT_LANDED     aircraft landed
 *         NPNT_CRASHED    aircraft crashed
 *
 * @iclass control_iface
 */
int8_t npnt_aircraft_state(npnt_s *npnt_handle);

//Implemented by libnpnt
/**
 * @brief   Returns Breach State.
 * @details This method checks based on the current info the state
 *          of the breach.
 *
 * @param[in] npnt_handle        npnt handle
 * 
 * @return           Breach type, 0 if no breach
 * @retval NPNT_BR_TIME   There has been a time breach
 *         NPNT_BR_FENCE  There has been a fence breach
 *
 * @iclass control_iface
 */
int8_t npnt_breach_state(npnt_s *npnt_handle);

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
 *         NPNT_INCOMP_ART Incomplete Artefact
 *         NPNT_INV_AUTH  signed by unauthorised entity
 *         NPNT_INV_STATE artefact can't setup in current aircraft state
 *
 * @iclass control_iface
 */
int8_t npnt_set_permart(npnt_s *handle, uint8_t *permart, uint16_t permart_length);

int8_t npnt_init_handle(npnt_s *handle);

int8_t npnt_verify_permart(npnt_s *handle);

int8_t npnt_alloc_and_get_fence_points(npnt_s* handle, float* vertx, float* verty);

int8_t npnt_get_max_altitude(npnt_s* handle, float* altitude);

int8_t npnt_populate_flight_params(npnt_s* handle);

bool npnt_pnpoly(int nvert, float *vertx, float *verty, float testx, float testy);

/** @} */
#endif //CONTROL_IFACE_H
