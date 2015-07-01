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

#define MAX_PORTS 65536

/*
 * Default ModSecurity Port
 */
#define MODSEC_PORT 80

extern void SetupModSec();

typedef struct _modsecPortlistNode
{
    u_int16_t server_port;
} ModSecPortNode;

typedef struct _modsecConfig
{
    char ports[MAX_PORTS/8];
} ModSecConfig;

#define MODSEC_SERVERPORTS_KEYWORD 		"server_ports"

#endif /* SPP_MOD_SEC_H */
