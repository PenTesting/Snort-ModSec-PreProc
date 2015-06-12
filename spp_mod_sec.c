/*
 * spp_mod_sec.c
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
 * ModSecurity Preprocessor
 * Author: Fakhri Zulkifli <d0lph1n98@yahoo.com>
 *
 * Parse ModSecurity CRS. Alert malicious traffic in HTTP protocol and tells
 * the iptables to drop the packet.
 */

#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "preprocids.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preproc_lib.h"
#include "sf_dynamic_preprocessor.h"
#include "snort_debug.h"

#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats examplePerfStats;
#endif

#include "sf_types.h"
#include "spp_mod_sec.h"

#define GENERATOR_EXAMPLE 256
#define SRC_PORT_MATCH  1
#define SRC_PORT_MATCH_STR "spp_mod_sec_preprocessor: src port match"
#define DST_PORT_MATCH  2
#define DST_PORT_MATCH_STR "spp_mod_sec_preprocessor: dest port match"

/*typedef struct _ModSecConfig
{
    u_int16_t portToCheck;

} ModSecConfig;



const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 1;
const int BUILD_VERSION = 1;
const char *PREPROC_NAME = "SF_MOD_SEC";
*/

tSfPolicyUserContextId ex_config = NULL;
ModSecConfig *ex_eval_config = NULL;

static void ModSecInit(struct _SnortConfig *, char *);
static void ModSecProcess(void *, void *);
static ModSecConfig * ModSecParse(char *);
#ifdef SNORT_RELOAD
static void ModSecReload(struct _SnortConfig *, char *, void **);
static int ModSecReloadVerify(struct _SnortConfig *, void *);
static int ModSecReloadSwapPolicyFree(tSfPolicyUserContextId, tSfPolicyId, void *);
static void * ModSecReloadSwap(struct _SnortConfig *, void *);
static void ModSecReloadSwapFree(void *);
#endif

void SetupModSec(void)
{
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("mod_sec", ModSecInit);
#else
    _dpd.registerPreproc("mod_sec", ModSecInit, ModSecReload,
            ModSecReloadVerify, ModSecReloadSwap, ModSecReloadSwapFree);
#endif
    _dpd.logMsg("ModSecurity Rules Loaded!\n");

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: ModSec is setup\n"););
}

static void ModSecInit(struct _SnortConfig *sc, char *args)
{
    ModSecConfig *config;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);

    _dpd.logMsg("ModSec dynamic preprocessor configuration\n");

    if (ex_config == NULL)
    {
        ex_config = sfPolicyConfigCreate();
        if (ex_config == NULL)
            _dpd.fatalMsg("Could not allocate configuration struct.\n");
    }

    config = ModSecParse(args);
    sfPolicyUserPolicySet(ex_config, policy_id);
    sfPolicyUserDataSetCurrent(ex_config, config);

    /* Register the preprocessor function, Transport layer, ID 10000 */
    _dpd.addPreproc(sc, ModSecProcess, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP);

#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("mod_sec", (void *)&examplePerfStats, 0, _dpd.totalPerfStats);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: ModSec is initialized\n"););
}

static ModSecConfig * ModSecParse(char *args)
{
    char *arg;
    char *argEnd;
    long port;
    ModSecConfig *config = (ModSecConfig *)calloc(1, sizeof(ModSecConfig));

    if (config == NULL)
        _dpd.fatalMsg("Could not allocate configuration struct.\n");

    arg = strtok(args, " \t\n\r");
    if(arg && !strcasecmp("port", arg))
    {
        arg = strtok(NULL, "\t\n\r");
        if (!arg)
        {
            _dpd.fatalMsg("ModSec: Missing port\n");
        }

        port = strtol(arg, &argEnd, 10);
        if (port < 0 || port > 65535)
        {
            _dpd.fatalMsg("ModSec: Invalid port %d\n", port);
        }
        config->portToCheck = (u_int16_t)port;

        _dpd.logMsg("    Port: %d\n", config->portToCheck);
    }
    else
    {
        _dpd.fatalMsg("ModSec: Invalid option %s\n",
            arg?arg:"(missing port)");
    }

    return config;
}

void ModSecProcess(void *pkt, void *context)
{
    SFSnortPacket *p = (SFSnortPacket *)pkt;
    ModSecConfig *config;
    PROFILE_VARS;

    sfPolicyUserPolicySet(ex_config, _dpd.getNapRuntimePolicy());
    config = (ModSecConfig *)sfPolicyUserDataGetCurrent(ex_config);
    if (config == NULL)
        return;

    // preconditions - what we registered for 
    assert(IsUDP(p) || IsTCP(p));

    PREPROC_PROFILE_START(examplePerfStats);

    if (p->src_port == config->portToCheck)
    {
        /* Source port matched, log alert */
        _dpd.alertAdd(GENERATOR_EXAMPLE, SRC_PORT_MATCH,
                      1, 0, 3, SRC_PORT_MATCH_STR, 0);

        PREPROC_PROFILE_END(examplePerfStats);
        return;
    }

    if (p->dst_port == config->portToCheck)
    {
        /* Destination port matched, log alert */
        _dpd.alertAdd(GENERATOR_EXAMPLE, DST_PORT_MATCH,
                      1, 0, 3, DST_PORT_MATCH_STR, 0);
        PREPROC_PROFILE_END(examplePerfStats);
        return;
    }
    
    PREPROC_PROFILE_END(examplePerfStats);
}

#ifdef SNORT_RELOAD
static void ModSecReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId ex_swap_config;
    ModSecConfig *config;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);

    _dpd.logMsg("ModSec dynamic preprocessor configuration\n");

    ex_swap_config = sfPolicyConfigCreate();
    if (ex_swap_config == NULL)
        _dpd.fatalMsg("Could not allocate configuration struct.\n");

    config = ModSecParse(args);
    sfPolicyUserPolicySet(ex_swap_config, policy_id);
    sfPolicyUserDataSetCurrent(ex_swap_config, config);

    /* Register the preprocessor function, Transport layer, ID 10000 */
    _dpd.addPreproc(sc, ModSecProcess, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP);

    *new_config = (void *)ex_swap_config;
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: Example is initialized\n"););
}

static int ModSecReloadVerify(struct _SnortConfig *sc, void *swap_config)
{
    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        _dpd.errMsg("Streaming & reassembly must be enabled for ModSec preprocessor\n");
        return -1;
    }

    return 0;
}

static int ModSecReloadSwapPolicyFree(tSfPolicyUserContextId config, tSfPolicyId policyId, void *data)
{
    ModSecConfig *policy_config = (ModSecConfig *)data;

    sfPolicyUserDataClear(config, policyId);
    free(policy_config);
    return 0;
}

static void * ModSecReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId ex_swap_config = (tSfPolicyUserContextId)swap_config;
    tSfPolicyUserContextId old_config = ex_config;

    if (ex_swap_config == NULL)
        return NULL;

    ex_config = ex_swap_config;

    return (void *)old_config;
}

static void ModSecReloadSwapFree(void *data)
{
    tSfPolicyUserContextId config = (tSfPolicyUserContextId)data;

    if (data == NULL)
        return;

    sfPolicyUserDataFreeIterate(config, ModSecReloadSwapPolicyFree);
    sfPolicyConfigDelete(config);
}
#endif
