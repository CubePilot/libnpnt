/*
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

#include <control_iface.h>

int8_t npnt_init_handle(npnt_s *handle)
{
    if (!handle) {
        return NPNT_UNALLOC_HANDLE;
    }
    handle->parsed_permart = NULL;
    handle->raw_permart = NULL;
    handle->raw_permart_len = 0;
    handle->security_handle = NULL;
    return 0;
}

 /*
 *  The point in polygon algorithm is based on:
 *  http://www.ecse.rpi.edu/Homepages/wrf/Research/Short_Notes/pnpoly.html
 */
bool npnt_pnpoly(int nvert, float *vertx, float *verty, float testx, float testy)
{
  int i, j, c = 0;
  for (i = 0, j = nvert-1; i < nvert; j = i++) {
    if ( ((verty[i]>testy) != (verty[j]>testy)) &&
	 (testx < (vertx[j]-vertx[i]) * (testy-verty[i]) / (verty[j]-verty[i]) + vertx[i]) )
       c = !c;
  }
  return c;
}
