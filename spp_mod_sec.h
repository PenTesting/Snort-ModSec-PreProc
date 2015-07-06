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

#include "sfPolicy.h"
#include "sfPolicyUserData.h"
#include "snort_bounds.h"

#define MAX_PORTS 65536

/*
 * Default web server port
 * TODO: SSL_ENABLED port
 */
#define DEFAULT_WEBSERV_PORT 80

extern void SetupModSec();
extern DynamicPreprocessorData _dpd;

/*
 * Data type containing the configuration of the module
 */
typedef struct
{
    /*
     * Port where the webserver with web interface will listen onto
     */
    unsigned webserv_port;

    /*
     * (Absolute) path to the directory containing the HTML files for the web interface
     */
    char webserv_dir[1024];

    /*
     * (Absolute) path to the directory containing Mod Security core rule set
     */
    char core_ruleset_dir[1024];

} ModSec_config;

typedef struct ModSec_snort_alert
{
    /* Identifiers of the alert */
    unsigned int   gid;
    unsigned int   sid;
    unsigned int   rev;

    /* Snort priority, description,
     * classification and timestamp
     * of the alert 
     */
    unsigned short priority;
    char 	   *desc;
    char 	   *classification;
    time_t 	   timestamp;

    /* IP header information */
    uint8_t 	   ip_tos;
    uint16_t 	   ip_len;
    uint16_t 	   ip_id;
    uint8_t 	   ip_ttl;
    uint8_t 	   ip_proto;
    uint32_t 	   ip_src_addr;
    uint32_t 	   ip_dst_addr;

    /* TCP header information */
    uint16_t 	   tcp_src_port;
    uint16_t 	   tcp_dst_port;
    uint32_t 	   tcp_seq;
    uint32_t 	   tcp_ack;
    uint8_t 	   tcp_flags;
    uint16_t 	   tcp_window;
    uint16_t 	   tcp_len;

    /*
     * Reference to the TCP Stream 
     * associated to the alert, if any
     */
    struct pkt_info *stream;

    /*
     * Pointer to the next alert in 
     * the log, if any
     */
    struct _ModSec_snort_alert *next;

    /*
     * Hierarchies for addresses and ports,
     * if the clustering algorithm is used 
     */
    //hierarchy_node *h_node[CLUSTER_TYPES];

    /*
     * Hyperalert information, pre-conditions 
     * and post-conditions 
     */
    ModSec_hyperalert_info *hyperalert;

    /*
     * Latitude and longitude of the attacker IP, 
     * if available
     */
    double geocoord[2];

    /* Parent alerts in the chain, if any */
    struct _ModSec_snort_alert **parent_alerts;

    /* Number of parent alerts */
    unsigned int 	n_parentes_alerts;

    /*
     * Array of directly correlated 'derived' 
     * alerts from the current one, if any 
     */
    struct _ModSec_snort_alert 	**derived_alerts;

    /** Number of derived alerts */
    unsigned int 	n_derived_alerts;

    /*
     * Alert ID on the database, if the alerts 
     * are stored on a database as well 
     */
    unsigned long int 	alert_id;
} ModSec_snort_int;

typedef struct
{
    unsigned int gid;
    unsigned int sid;
    unsigned int rev;

} ModSec_hyperalert_key;

typedef struct
{
    /* Hyperalert key */
    ModSec_hyperalert_info;

    /** Pre-conditions, as array of strings */
    char 	**preconds;

    /** Number of post-conditions */
    unsigned int 	n_preconds;

    /** Post-conditions, as array of strings */
    char 	**postconds;

    /** Number of post-conditions */
    unsigned int 	n_postconds;

    /** Make the struct 'hashable' */
    UT_hash_handle 	hh;

} ModSec_hyperalert_info;

/** Function pointer to the function used for getting the alert list (from log file, db, ...) */
extern ModSec_snort_alert* (*get_alerts)(void);

/** Buffer containing the alerts to be serialized on the binary history file */
extern ModSec_snort_alert  **alerts_pool;

/** Number of alerts contained in the buffer to be serialized */
extern unsigned int 	   alerts_pool_count;

/** Mutex variable for writing on the output database */
extern pthread_mutex_t 	outdb_mutex;

/** Configuration of the module */
extern ModSec_config 	*config;

#endif /* SPP_MOD_SEC_H */
