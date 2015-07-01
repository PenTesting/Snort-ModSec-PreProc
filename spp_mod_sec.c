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
 * Snort ModSecurity Preprocessor
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
#include "spp_mod_sec.h"

#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats modsecPerfStats;
#endif

#define GENERATOR_SPP_MODSEC 129
#define SRC_PORT_MATCH  1
#define SRC_PORT_MATCH_STR "spp_mod_sec_preprocessor: src port match"
#define DST_PORT_MATCH  2
#define DST_PORT_MATCH_STR "spp_mod_sec_preprocessor: dest port match"

const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 1;
const int BUILD_VERSION = 1;
const char *PREPROC_NAME = "SF_MODSEC";

#define SetupModSec DYNAMIC_PREPROC_SETUP

#ifdef TARGET_BASED
int16_t modsec_app_id = SFTARGET_UNKNOWN_PROTOCOL;
#endif

/* Arguments are: gid, sid, rev, classification, priority, message, rule_info */
#define ALERT(x,y) { _dpd.alertAdd(GENERATOR_SPP_MODSEC, x, 1, 0, 3, y, 0 ); }

/* Convert port value into an index for the modsec_config->ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

tSfPolicyUserContextId modsec_config = NULL;
ModSecConfig *modsec_eval_config = NULL;

/*
 * Function prototype(s)
 */
static void ModSecInit(struct _SnortConfig *, char *);
static void ModSecProcess(void *, void *);
static ModSecConfig * ModSecParse(char *);
static void ParseModSecRule(void *, void *);
static inline int CheckModSecPort(uint16_t);
static void enablePortStreamServices(struct _SnortConfig *, ModSecConfig *, tSfPolicyId);
#ifdef TARGET_BASED
static void _addServicesToStreamFilter(struct _SnortConfig *, tSfPolicyId);
#endif
static void ModSecFreeConfig(tSfPolicyUserContextId config);
static int ModSecCheckConfig(struct _SnortConfig *);
static void ModSecCleanExit(int, void *);


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
    _dpd.logMsg("ModSecurity Preprocessor Initialized!\n");

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: ModSec is setup\n"););
}

/* Initializes the ModSec preprocessor module and registers
 * it in the preprocessor list.
 *
 * PARAMETERS:
 *
 * argp: 	Pointer to argument string to process for config
 * 			data.
 *
 * RETURNS: 	Nothing.
 */
static void ModSecInit(struct _SnortConfig *sc, char *argp)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);
    ModSecConfig *pPolicyConfig = NULL;

    _dpd.logMsg("ModSec dynamic preprocessor configuration\n");

    if (modsec_config == NULL)
    {
        modsec_config = sfPolicyConfigCreate();
        if (modsec_config == NULL)
	{
            DynamicPreprocessorFatalMessage("Could not allocate configuration struct.\n");
	}

	if(_dpd.streamAPI == NULL)
	{
	    DynamicPreprocessorFatalMessage("SetupModSec(): The Stream preprocessor must be enabled.\n");
	}

	_dpd.addPreprocConfCheck(sc, ModSecConfig);
	_dpd.addPreprocExit(ModSecCleanExit, NULL< PRIORITY_LAST, PP_MODSEC);

#ifdef PERF_PROFILING
	_dpd.addPreprocProfileFunc("mod_sec", (void *)&modsecPerfStats, 0, _dpd.totalPerfStats);
#endif

#ifdef TARGET_BASED
	modsec_app_id = _dpd.findProtocolReference("mod_sec");
	if(modsec_app_id == SFTARGET_UNKNOWN_PROTOCOL)
	   modsec_app_id = _dpd.addProtocolReference("mod_sec");

	// register with session to handle applications
	_dpd.sessionAPI = _dpd.addProtocolReference("mod_sec");

#endif
    }

    sfPolicyUserPolicySet(modsec_config, policy_id);
    pPolicyConfig = (ModSecConfig *)sfPolicyUserDataSetCurrent(modsec_config);
    if(pPolicyConfig != NULL)
    {
        DynamicPreprocessorFatalMessage("ModSec preprocessor can only be "
	    				"configured once.\n");
    }

    pPolicyConfig = (ModSecConfig *)calloc(1, sizeof(ModSecConfig));
    if(!pPolicyConfig)
    {
        DynamicPreprocessorFatalMessage("Could not allocate memory for "
	    				"ModSec preprocessor configuration.\n");
    }

    sfPolicyUserDataSetCurrent(modsec_config, pPolicyConfig);

    ParseModSecArgs(pPolicyConfig, (u_char *)argp);

    _dpd.addPreproc(sc, ModSecProcess, PRIORITY_APPLICATION, PP_MODSEC, PROTO_BIT__TCP | PROTO_BIT__UDP);

    enablePortStreamServices(sc, pPolicyConfig, policy_id);

#ifdef TARGET_BASED
    _addServicesToStreamFilter(sc, policy_id);
#endif
}
    /* config = ModSecParse(argp); */
    /* sfPolicyUserPolicySet(modsec_config, policy_id); */
    /* sfPolicyUserDataSetCurrent(modsec_config, config); */
    /*  */
    /* #<{(| Register the preprocessor function, Transport layer, ID 10000 |)}># */
    /* _dpd.addPreproc(sc, ModSecProcess, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP); */
    /*  */
    /* DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: ModSec is initialized\n");); */


static ModSecConfig * ModSecParse(char *argp)
{
    char *arg = NULL;
    char *argEnd = NULL;
    int port;
    
    ModSecConfig *config = (ModSecConfig *)calloc(1, sizeof(ModSecConfig));

    if (config == NULL)
        _dpd.fatalMsg("Could not allocate configuration struct.\n");

    config->ports[PORT_INDEX(80)] |= CONV_PORT(80);

    arg = strtok(argp, " ");

    if(!argp)
    {
      /* Help Display */
      return;
    }

    argEnd = strdup((char*) argp);

    if(!argEnd)
    {
      DynamicPreprocessorFatalMessage("Could not allocate memory to parse ModSec options.\n");
      return;
    }

    while(arg) {
        if(!strcmp(arg, MODSEC_SERVERPORTS_KEYWORD))
        {
	    /* Use the user specified '80' */
	    config->ports[ PORT_INDEX( 80 ) ] = 0;

            arg = strtok(NULL, "\t\n\r");
            if (!arg)
            {
                _dpd.fatalMsg("ModSec: Missing port\n");
            }

	    /* Remove the braces, they said */
	    arg = strtok(NULL, " ");
	    if ((!arg) || (arg[0] != '{'))
	    {
	      DynamicPreprocessorFatalMessage("Bad value specified for %s.\n",MODSEC_SERVERPORTS_KEYWORD);
	    }

	    while ((arg) && (arg[0] != '}'))
	    {
	      if (!isdigit((int)arg[0]))
	      {
		DynamicPreprocessorFatalMessage("Bad prot &s.\n", arg);
	      }
	      else
	      {
		port = atoi(arg);
		if(port < 0 || port > MAX_PORTS)
		{
		  DynamicPreprocessorFatalMessage("Port value illegitimate: %s\n", arg);
		}

		config->ports[PORT_INDEX(port)] |= CONV_PORT(port);
	      }

	      arg = strtok(NULL, " ");
	    }
	}
            /* port = strtol(arg, &argEnd, 10); */
            /* if (port < 0 || port > 65535) */
            /* { */
            /*     _dpd.fatalMsg("ModSec: Invalid port %d\n", port); */
            /* } */
            /* config->portToCheck = (u_int16_t)port; */
            /*  */
            /* _dpd.logMsg("    Port: %d\n", config->portToCheck); */
       
        else
        {
            /* _dpd.fatalMsg("ModSec: Invalid option %s\n", */
            /*               arg?arg:"(missing port)"); */
	    DynamicPreprocessorFatalMessage("Invalid argument: %s\n", arg);
	    return;
        }

	arg = strtok(NULL, " ");
    }
    return config;
}

/* Main runtime entry point for ModSec preprocessor.
 * Analyzes ModSec packets for anomalies/exploits.
 *
 * PARAMETERS:
 *
 * packetp: 	Pointer to current packet to process.
 * contextp: 	Pointer to context block, not used.
 *
 * RETURNS: 	Nothing.
 */
void ModSecProcess(void *pkt, void *context)
{
    SFSnortPacket *p = (SFSnortPacket *)pkt;
    ModSecConfig *config;
    char tmp[12];
    bzero(tmp, 12);
    int length = 11;

    if(length > p->payload_size)
        length = p->payload_size;

    void removeSubstr(char *string, char *sub) {
        char *match = string;
        int len = strlen(sub);
        while((match = strstr(match, sub))) {
            *match = '\0';
            strcat(string, match+len);
            match++;
        }
    }

    sfPolicyUserPolicySet(modsec_config, _dpd.getNapRuntimePolicy());
    config = (ModSecConfig *)sfPolicyUserDataGetCurrent(modsec_config);
    if (config == NULL)
        return;

    if (!p) return;

    // preconditions - what we registered for
    assert(IsUDP(p) || IsTCP(p));

    _dpd.logMsg(p);

    /* if (p->src_port == config->portToCheck) */
    /* { */
    /*     #<{(| Source port matched, log alert |)}># */
    /*     _dpd.alertAdd(GENERATOR_EXAMPLE, SRC_PORT_MATCH, */
    /*                   1, 0, 3, SRC_PORT_MATCH_STR, 0); */
    /*  */
    /*     return; */
    /* } */
    /*  */
    /* if (p->dst_port == config->portToCheck) */
    /* { */
    /*     #<{(| Destination port matched, log alert |)}># */
    /*     _dpd.alertAdd(GENERATOR_EXAMPLE, DST_PORT_MATCH, */
    /*                   1, 0, 3, DST_PORT_MATCH_STR, 0); */
    /*     return; */
    /* } */

    if (p->src_port == ports)
    {

        if(length > 0) {
            _dpd.logMsg("Copying %i bytes of packet payload into buffer\n",length);
            strncpy(tmp, (const char *) p->payload, length);
            _dpd.logMsg("Payload data: %s\n", tmp);
        }

        _dpd.alertAdd(GENERATOR_EXAMPLE, DST_PORT_MATCH, 1, 0, 3, DST_PORT_MATCH_STR, 0);

        int y;
        FILE *data;
        char action;
        char line[100]; 	// output parsed string is limited
        int counter = 0;
        char keyword[] = "";	// no function whatsoever
        int result,index = 0;

        struct rule {
            char keyword1[100];
            char keyword2[100];
        } ruleset[10];

        if((data=fopen("rule", "r")) != NULL) {
            while(fgets(line,sizeof(line),data)) {
                if((strcmp(line,keyword))) {
                    char s[10] = "$,";
                    char *token = strtok(line, s);

                    while(token != NULL) {
                        if(counter == 1) {
                            strcpy(ruleset[index].keyword1, token);
                        }
                        if(counter == 2) {
                            strcpy(ruleset[index].keyword2, token);
                        }
                        counter++;
                        token = strtok(NULL, s);
                    }
                }
            }
        }

        /* Skid's code */
        for(y = 0; y < index; ++y) {
            removeSubstr(ruleset[y].keyword1, "ARGS|XML:/* \"");
            removeSubstr(ruleset[y].keyword1, "RGS_NAMES|");
            printf("%s ", ruleset[y].keyword1);
            removeSubstr(ruleset[y].keyword2, "\" \"phase:2");
            printf("%s ", ruleset[y].keyword2);
            printf("\n");
        }

        fclose(data);
        return;
    }

    if(p->dst_port = ports)
    {
        _dpd.alertAdd(GENERATOR_EXAMPLE, DST_PORT_MATCH, 1, 0, 3, DST_PORT_MATCH_STR, 0);

        if(length > 0) {
            _dpd.logMsg("Copying %i bytes of packet payload into buffer\n", length);
            strncpy(tmp, (const char *) p->payload, length);
            _dpd.logMsg("Payload data: %s\n", tmp);
        }
    }
}

/* Parses and processes the configuration arguments
 * supplied in the ModSec preprocessor rule.
 *
 * PARAMETERS:
 *
 * argp: 	Pointer to string containing the config arguments.
 *
 * RETURNS: 	Nothing.
 */
static void
ParseModSecArgs(ModSecConfig *config, u_char* argp)
{
    char *arg = NULL;
    char *argEnd = NULL;
    int port;


}
void ParseModSecRule(void *, void *)
{

}

static int ModSecFreeConfigPolicy(
    	tSfPolicyUserContextId config,
	tSfPolicyId policyId,
	void *pData
    	)
{
  ModSecConfig *pPolicyConfig = (ModSecConfig *)pData;

  // should free the ModSecConfig
  
  sfPolicyUserDataClear(config, policyId);
  free(pPolicyConfig);
  return 0;
}

static void ModSecFreeConfig(tSfPolicyUserContextId config)
{
    if(config == NULL)
       return;

    sfPolicyUserDataFreeIterate(config, ModSecFreeConfigPolicy);
    sfPolicyConfigDelete(config);
}

/* Validates given port as an ModSec server port
 *
 * PARAMETERS:
 *
 * port: 	Port to validate.
 *
 * RETURNS: 	TRUE, if the port is indeed an ModSev server prot.
 * 	  FALSE, otherwise.
 */
static inline int
CheckModSecPort(uint16_t port)
{
  if(modsec_eval_config->ports[PORT_INDEX(port)] & CONV_PORT(port))
  {
    return 1;
  }

  return 0;
}

static void enablePortStreamServices(struct _SnortConfig *sc, ModSecConfig *config, tSfPolicyId policy_id)
{
    if(config == NULL)
      	return;

    if(_dpd.streamAPI)
    {
        uint32_t portNum;

	for(portNum = 0; portNum < MAX_PORTS; portNum++)
	{
	    if(config->ports[(portNum/8)] & (1<<(portNum%8)))
	    {
	        // Add port to port
		_dpd.streamAPI->set_port_filter_status(sc, IPPROTO_TCP, (uint16_t)portNum,
		    				       PORT_MONITOR_SESSION, policy_id, 1);
		_dpd.streamAPI->register_reassembly_port(NULL,
		    					(uint16_t) portNum,
							SSN_DIR_FROM_SERVER | SSN_DIR_FROM_CLIENT);
		_dpd.sessionAPI->enable_preproc_for_port(sc, PP_MODSEC, PROTO_BIT__TCP | PROTO_BIT__UDP, (uint16_t) portNum);
	    }
	}
    }
}
#ifdef TARGET_BASED
static void _addServicesToStreamFilter(struct _SnortConfig *sc, tSfPolicyId policy_id)
{
    _dpd.streamAPI->set_service_filter_status(sc, modsec_app_id, PORT_MONITOR_SESSION, policy_id, 1);
}
#endif

static int ModSecCheckPolicyConfig(
    	struct _SnortConfig *sc,
	tSfPolicyUserContextId config,
	tSfPolicyId policyId,
	void* pData
    	)
{
    _dpd.setParserPolicy(sc, policyId);

    if(_dpd.streamAPI == NULL)
    {
        _dpd.errMsg("ModSecCheckPolicyConfig(): The Stream preprocessor must be enabled.\n");
	return -1;
    }
}

static int ModSecCheckConfig(struct _SnortConfig *sc)
{
    int rval;

    if((rval = sfPolicyUserDataIterate(sc, modsec_config, ModSecCheckPolicyConfig)))
       return rval;

    return 0;
}

static void ModSecCleanExit(int signal, void *data)
{
  if(modsec_config != NULL)
  {
      ModSecFreeConfig(modsec_config);
      modsec_config = NULL;
  }
}

#ifdef SNORT_RELOAD
static void ModSecReload(struct _SnortConfig *sc, char *argp, void **new_config)
{
    tSfPolicyUserContextId modsec_swap_config = (tSfPolicyUserContextId)*new_config;
    ModSecConfig *config;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);

    _dpd.logMsg("ModSec dynamic preprocessor configuration\n");

    modsec_swap_config = sfPolicyConfigCreate();
    if (modsec_swap_config == NULL)
        _dpd.fatalMsg("Could not allocate configuration struct.\n");

    config = ModSecParse(argp);
    sfPolicyUserPolicySet(modsec_swap_config, policy_id);
    sfPolicyUserDataSetCurrent(modsec_swap_config, config);

    /* Register the preprocessor function, Transport layer, ID 10000 */
    _dpd.addPreproc(sc, ModSecProcess, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP);

    *new_config = (void *)modsec_swap_config;
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
    tSfPolicyUserContextId old_config = modsec_config;

    if (modsec_swap_config == NULL)
        return NULL;

    modsec_config = modsec_swap_config;

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
