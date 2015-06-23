/*
 * spp_mod_sec.h
 * 
 * Copyright 2015 Fakhri Zulkifli <d0lph1n98@yahoo.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */
 
/*
 * spp_mod_sec.h: Definitions, structs, function prototype(s) for
 * 		  the ModSecurity Preprocessor
 *
 * Author: Fakhri Zulkifli <d0lph1n98@yahoo.com>
 */

#ifndef SPP_MOD_SEC_H
#define SPP_MOD_SEC_H

//#define MAJOR_VERSION   2
//#define MINOR_VERSION   0
//#define BUILD_VERSION   1
//#define PREPROC_NAME    SF_MOD_SEC

#define MAX_PORTS 65536

/*
 * Default ModSecurity Port
 */
#define ModSec_Port	80

//#define ModSecSetup	DYNAMIC_PREPROC_SETUP
extern void SetupModSec();

typedef struct _ModSecConfig
{
 	u_int16_t portToCheck;
} ModSecConfig;

#endif /* SPP_MOD_SEC_H */
