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

/*
 * Generator id. Define here the same as the official registry
 * in generators.h
 */
#define GENERATOR_SPP_MODSEC 146

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

/* Already put in preprocids.h, still the same :( */
#define PP_MODSEC 		43

/*
 * Function prototype(s)
 */
ModSecData * ModSecGetNewSession(SFSnortPacket *, tSfPolicyId);
static void ModSecInit(struct _SnortConfig *, char *);
static void ModSecProcess(void *, void *);
static ModSecConfig * ModSecParse(char *);
//static void ParseModSecRule(void *, void *);
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

	_dpd.addPreprocConfCheck(sc, ModSecCheckConfig);
	_dpd.addPreprocExit(ModSecCleanExit, NULL, PRIORITY_LAST, PP_MODSEC);

#ifdef PERF_PROFILING
	_dpd.addPreprocProfileFunc("mod_sec", (void *)&modsecPerfStats, 0, _dpd.totalPerfStats);
#endif

#ifdef TARGET_BASED
	modsec_app_id = _dpd.findProtocolReference("mod_sec");
	if(modsec_app_id == SFTARGET_UNKNOWN_PROTOCOL)
	   modsec_app_id = _dpd.addProtocolReference("mod_sec");

	// register with session to handle applications
	//_dpd.sessionAPI = _dpd.addProtocolReference("mod_sec");
	_dpd.sessionAPI->register_service_handler(PP_MODSEC, modsec_app_id);

#endif
    }

    sfPolicyUserPolicySet(modsec_config, policy_id);
    // Already declared ../include/sfPolicyUserData.h:96:19 ?
    //pPolicyConfig = (ModSecConfig *)sfPolicyUserDataSetCurrent(modsec_config);
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


/* static ModSecConfig * ModSecParse(char *argp) */
/* { */
/*     char *arg = NULL; */
/*     char *argEnd = NULL; */
/*     int port; */
/*      */
/*     ModSecConfig *config = (ModSecConfig *)calloc(1, sizeof(ModSecConfig)); */
/*  */
/*     if (config == NULL) */
/*         _dpd.fatalMsg("Could not allocate configuration struct.\n"); */
/*  */
/*     config->ports[PORT_INDEX(80)] |= CONV_PORT(80); */
/*  */
/*     arg = strtok(argp, " "); */
/*  */
/*     if(!argp) */
/*     { */
/*       #<{(| Help Display |)}># */
/*       return; */
/*     } */
/*  */
/*     argEnd = strdup((char*) argp); */
/*  */
/*     if(!argEnd) */
/*     { */
/*       DynamicPreprocessorFatalMessage("Could not allocate memory to parse ModSec options.\n"); */
/*       return; */
/*     } */
/*  */
/*     while(arg) { */
/*         if(!strcmp(arg, MODSEC_SERVERPORTS_KEYWORD)) */
/*         { */
/* 	    #<{(| Use the user specified '80' |)}># */
/* 	    config->ports[ PORT_INDEX( 80 ) ] = 0; */
/*  */
/*             arg = strtok(NULL, "\t\n\r"); */
/*             if (!arg) */
/*             { */
/*                 _dpd.fatalMsg("ModSec: Missing port\n"); */
/*             } */
/*  */
/* 	    #<{(| Remove the braces, they said |)}># */
/* 	    arg = strtok(NULL, " "); */
/* 	    if ((!arg) || (arg[0] != '{')) */
/* 	    { */
/* 	      DynamicPreprocessorFatalMessage("Bad value specified for %s.\n",MODSEC_SERVERPORTS_KEYWORD); */
/* 	    } */
/*  */
/* 	    while ((arg) && (arg[0] != '}')) */
/* 	    { */
/* 	      if (!isdigit((int)arg[0])) */
/* 	      { */
/* 		DynamicPreprocessorFatalMessage("Bad prot &s.\n", arg); */
/* 	      } */
/* 	      else */
/* 	      { */
/* 		port = atoi(arg); */
/* 		if(port < 0 || port > MAX_PORTS) */
/* 		{ */
/* 		  DynamicPreprocessorFatalMessage("Port value illegitimate: %s\n", arg); */
/* 		} */
/*  */
/* 		config->ports[PORT_INDEX(port)] |= CONV_PORT(port); */
/* 	      } */
/*  */
/* 	      arg = strtok(NULL, " "); */
/* 	    } */
/* 	} */
/*             #<{(| port = strtol(arg, &argEnd, 10); |)}># */
/*             #<{(| if (port < 0 || port > 65535) |)}># */
/*             #<{(| { |)}># */
/*             #<{(|     _dpd.fatalMsg("ModSec: Invalid port %d\n", port); |)}># */
/*             #<{(| } |)}># */
/*             #<{(| config->portToCheck = (u_int16_t)port; |)}># */
/*             #<{(|  |)}># */
/*             #<{(| _dpd.logMsg("    Port: %d\n", config->portToCheck); |)}># */
/*         */
/*         else */
/*         { */
/*             #<{(| _dpd.fatalMsg("ModSec: Invalid option %s\n", |)}># */
/*             #<{(|               arg?arg:"(missing port)"); |)}># */
/* 	    DynamicPreprocessorFatalMessage("Invalid argument: %s\n", arg); */
/* 	    return; */
/*         } */
/*  */
/* 	arg = strtok(NULL, " "); */
/*     } */
/*     return config; */
/* } */

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

    /* TODO: get the parameter from the user */

}

/* void ParseModSecRule(void *, void *) */
/* { */
/*  */
/* } */

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
    ModSecData *modsecsessp = NULL;
    ModSecConfig *config;
    uint8_t source = 0;
    uint8_t dest = 0;
    uint8_t known_port = 0;
    uint8_t direction;
    unsigned int offset = 0;
#ifdef TARGET_BASED
    int16_t app_id = SFTARGET_UNKNOWN_PROTOCOL;
#endif
    uint32_t search_dir_ver, search_dir_keyinit;
    char flags = STREAM_FLPOLICY_SET_ABSOLUTE;
    tSfPolicyId policy_id = _dpd.getNapRuntimePolicy();
    PROFILE_VARS;

    sfPolicyUserPolicySet(modsec_config, policy_id);

    /* char tmp[12]; */
    /* bzero(tmp, 12); */
    /* int length = 11; */

    /* if(length > p->payload_size) */
    /*     length = p->payload_size; */

    /*
     * removeSubstr function
     *
     * Remove a pattern from the string.
     */
    void removeSubstr(char *string, char *sub) {
        char *match = string;
        int len = strlen(sub);
        while((match = strstr(match, sub))) {
            *match = '\0';
            strcat(string, match+len);
            match++;
        }
    }

    /* sfPolicyUserPolicySet(modsec_config, _dpd.getNapRuntimePolicy()); */
    /* config = (ModSecConfig *)sfPolicyUserDataGetCurrent(modsec_config); */
    if (config == NULL)
        return;

    if (!p) return;

    // preconditions - what we registered for
    assert(IsUDP(p) || IsTCP(p));
    //assert(p->payload && p->payload_size && IPH_IS_VALID(p) && p->tcp_header)

    PREPROC_PROFILE_START(modsecPerfStats);

    modsec_eval_config = sfPolicyUserDataGetCurrent(modsec_config);

    /* Get previously block. */
    	modsecsessp = _dpd.sessionAPI->get_application_data(p->stream_session, PP_MODSEC);
    if(modsecsessp != NULL)
    {
      	modsec_eval_config = sfPolicyUserDataGet(modsecsessp->config, modsecsessp->policy_id);
      	known_port = 1;
    }
    else
    {
      	/* If no autodetection, check the ports to make sure this is 
	 * running on an SSH port, otherwise no need to examine the traffic 
	 */
#ifdef TARGET_BASED
      	app_id = _dpd.sessionAPI->get_application_protocol_id(p->stream_session);
	if(app_id == SFTARGET_UNKNOWN_PROTOCOL)
	{
	    PREPROC_PROFILE_END(modsecPerfStats);
	    return;
	}

	if(app_id && (app_id != modsec_app_id))
	{
	    PREPROC_PROFILE_END(modsecPerfStats);
	    return;
	}

	if(app_id == modsec_app_id) 
	{
	    known_port = 1;
	}

	if(!app_id)
	{
#endif
	    source = (uint8_t)CheckModSecPort(p->src_port);
	    dest = (uint8_t)CheckModSecPort(p->dst_port);

	    if(!modsec_eval_config->AutodetectEnabled && !source && !dest)
	    {

	        /* No ModSec port */
	        PREPROC_PROFILE_END(modsecPerfStats);
		return;
	    }
#ifdef TARGET_BASED
	}
#endif

	/* Check the stream session. If no data-block attached,
	 * create one.
	 */
	modsecsessp = ModSecGetNewSession(p, policy_id);

	/* Some code below is commented out until ModSec flag is defined */

	if(!modsecsessp)
	{
	    known_port = (source || dest ? 1 : 0);

	    /* If this is not ModSec port, but autodetect is on, flag this session
	     * to reduce false positives later on */
	    /* if(!known_port && ssh_eval_config->AutodetectEnabled); */
	    /* { */
	    /*     modsecsessp->state_flags |= <modsec-flag-autodetect-here>; */
		/* flags = <modsec-append-stream>; */
	    /* } */
	}
    }

    /* Do not process if some packets is missed */
    {
        PREPROC_PROFILE_END(modsecPerfStats);
	return;
    }

    /* If session is good. Turn on stream assembly */
    /* if(!(modsecsessp->state_flags & <modsec-flag-reassembly-set>)) */
    /* { */
    /*     _dpd.streamAPI->set_reassembly(p->stream_session, STREAM_FLPOLICY_FOOTPRINT, SSN_DIR_BOTH, flags); */
	/* //modsecsessp->state_flags |= <modsec-flag-reassembly-set>; */
    /* } */

    /* Make sure the preprocessor should run */
    /* check if we're waiting on stream reassembly */
    if(p->flags & FLAG_STREAM_INSERT)
    {
        PREPROC_PROFILE_END(modsecPerfStats);
	return;
    }

    if((_dpd.sessionAPI->get_session_flags(p->stream_session) && SSNFLAG_MIDSTREAM)
	  || _dpd.streamAPI->missed_packets(p->stream_session, SSN_DIR_BOTH))
    {
        /* Order only matters if the packets are not encrypted */
        /* if(!(modsecsessp->state_flags & <modsec-flag-sess-encrypted>)) */
	/* { */
	/*   #<{(| Do not turn off reassembly if autodetected since another preprocessor */
	/*    * may actually be looking at this session as well and the ModSec */
	/*    * autodetect of this session may be wrong |)}># */
      	/*   if(!(modsecsessp->state_flags & <modsec-flag-autodetected>)) */
	/*   { */
	/*       _dpd.streamAPI->set_reassembly(p->stream_session, STREAM_FLPOLICY_IGNORE, SSN_DIR_BOTH, STREAM_FLPOLICY_SET_APPEND); */
	/*   } */
	/*  */
	/*   modsecsessp->state_flags |= <modsec-flag-missed-packets>; */
	/*    */
	/*   PREPROC_PROFILE_END(modsecPerfStats); */
    	/*   return; */
	/* } */
    }
    
    /* Get the direction of the packets */
    /* if(p->flags & FLAG_FROM_SERVER) */
    /* { */
    /*     direction = <modsec-dir-from-server>; */
	/* search_dir_ver = <modsec-flag-serv-idstring-seen>; */
	/* search_dir_keyinit = <modsec-flag-client-skey-seen> | <modsec-flag-client-kexinit-seen>; */
    /* } */
    /* else */
    /* { */
    /*     direction = <modsec-dir-from-client>; */
	/* search_dir_ver = <modsec-flag-client-idstring-seen>; */
	/* search_dir_keyinit = <modsec-flag-client-skey-seen> | <modsec-flag-client-kexinit-seen>; */
    /* } */
   
    /* If ModSec have different protocol version only */
    /* if(!(modsecsessp->state_flags & <modsec-flag-sess-encrypted>)) */
    /* { */
    /*     #<{(| If server and client have not performed the protocol */
	/*  * version exchange yet, must look for version strings. */
	/*  |)}># */
    /*   if(!(modsecsessp->state_flags & search_dir_ver)) */
    /*   { */
	/*   offset = ProcessModSecProtocolVersionExchange(modsecsessp, p, direction, known_port); */
	/*   if(!offset) */
	/*   { */
	/*       #<{(| Error processing protovers exchange msg |)}># */
	/*       PREPROC_PROFILE_END(modsecPerfStats); */
	/*       return; */
	/*   } */
    /*  */
	/*   #<{(| found protocol version. Stream reassembly might have appended an modsec packet, */
	/*    * such as the key exchange init. Thus call ProcessModSecKeyInitExchange() too. */
	/*    |)}># */
    /*   } */
    
    
    
    // Get the snort packet
    //_dpd.logMsg(p);

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

    if (p->src_port == port)
    {

        if(length > 0) {
            _dpd.logMsg("Copying %i bytes of packet payload into buffer\n",length);
            strncpy(tmp, (const char *) p->payload, length);
            _dpd.logMsg("Payload data: %s\n", tmp);
        }

        _dpd.alertAdd(GENERATOR_SPP_MODSEC, DST_PORT_MATCH, 1, 0, 3, DST_PORT_MATCH_STR, 0);

        int y;
        FILE *data;
        char action;
        char line[100]; 	// output parsed string is limited
        int counter = 0;
        char keyword[] = "";	// no function whatsoever
        int index = 0;
	//int result;

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

    if(p->dst_port = port)
    {
        _dpd.alertAdd(GENERATOR_SPP_MODSEC, DST_PORT_MATCH, 1, 0, 3, DST_PORT_MATCH_STR, 0);

        if(length > 0) {
            _dpd.logMsg("Copying %i bytes of packet payload into buffer\n", length);
            strncpy(tmp, (const char *) p->payload, length);
            _dpd.logMsg("Payload data: %s\n", tmp);
        }
    }
}

ModSecData * ModSecGetNewSession(SFSnortPacket *p, tSfPolicyId policy_id)
{
    ModSecData *datap = NULL;

    /* Sanity check ? */
    if((!p) || (!p->stream_session))
    {
        return NULL;
    }

    datap = (ModSecData *)calloc(1, sizeof(ModSecData));

    if(!datap)
        return NULL;

    /* Register the new data block in the stream session */
    _dpd.sessionAPI->ssh_application_data(p->stream_session, PP_MODSEC, datap, FreeModSecData);

    datap->policy_id = policy_id;
    datap->config = modsec_config;
    ((ModSecConfig *))sfPolicyUserDataGetCurrent(modsec_config)->ref_count++;

    return datap;
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

/* Registered as a callback with data blocks when
 * they are added to the underlying stream session. Called 
 * by the stream preprocessor when a session is about to be
 * destroyed.
 *
 * PARAMETERS:
 *
 * idatap: 	Pointer to the moribound data.
 *
 * RETURNS: 	Nothing.
 */
static void
FreeModSecData(void *idatap)
{
    ModSecData *ssn = (ModSecdata *)idatap;
    ModSecConfig *config = NULL;

    if(ssn = NULL)
        return;

    if(ssn->config != NULL)
    {
        config = (ModSecConfig *)sfPolicyUserDataGet(ssn->config, ssn->policy_id);
    }

    if(config != NULL)
    {
        config->ref_count--;
	if((config->ref_count == 0) &&
	    (ssn->config != modsec_config))
	{
	    sfPolicyUserDataClear(ssn->config, ssn->policy_id);
	    free(config);

	    if(sfPolicyUserPolicyGetActive(ssn->config) == 0)
	    {
	        /* No more outstanding configs - free the config array */
	        ModSecFreeConfig(ssn->config);
	    }
	}
    }

    free(ssn);
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
    /* tSfPolicyUserContextId modsec_swap_config = (tSfPolicyUserContextId)*new_config; */
    /* ModSecConfig *config; */
    /* tSfPolicyId policy_id = _dpd.getParserPolicy(sc); */

    tSfPolicyUserContextId modsec_swap_config = (tSfPolicyUserContextId)*new_config;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);
    ModSecConfig * pPolicyConfig = NULL;

    _dpd.logMsg("ModSec dynamic preprocessor configuration reloaded\n");

    /* modsec_swap_config = sfPolicyConfigCreate(); */
    /* if (modsec_swap_config == NULL) */
    /*     _dpd.fatalMsg("Could not allocate configuration struct.\n"); */
    /*  */
    /* config = ModSecParse(argp); */
    /* sfPolicyUserPolicySet(modsec_swap_config, policy_id); */
    /* sfPolicyUserDataSetCurrent(modsec_swap_config, config); */
    /*  */
    /* #<{(| Register the preprocessor function, Transport layer, ID 10000 |)}># */
    /* _dpd.addPreproc(sc, ModSecProcess, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP); */
    /*  */
    /* *new_config = (void *)modsec_swap_config; */
    /* DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: Example is initialized\n");); */

    if(modsec_swap_config == NULL)
    {

        //create a context
	modsec_swap_config = sfPolicyConfigCreate();
	if(modsec_swap_config == NULL)
	{
	    DynamicPreprocessorFatalMessage("Failed to allocate memory "
					    "for ModSec config.\n");
	}

	if(_dpd.streamAPI == NULL)
	{
	    DynamicPreprocessorFatalMessage("SetupModSec(): The Stream preprocessor must be enabled.\n");
	}
	*new_config = (void *)modsec_swap_config;
    }

    sfPolicyUserPolicySet(modsec_swap_config, policy_id);
    pPolicyConfig = (ModSecConfig *)sfPolicyUserDataGetCurrent(modsec_swap_config);
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
    sfPolicyUserDataSetCurrent(modsec_swap_config, pPolicyConfig);

    ParseModSecArgs(pPolicyConfig, (u_char *)argp);

    _dpd.addPreproc(sc, ModSecProcess, PRIORITY_APPLICATION, PP_MODSEC, PROTO_BIT__TCP | PROTO_BIT__UDP);

    enablePortStreamServices(sc, pPolicyConfig, policy_id);

#ifdef TARGET_BASED
    _addServicesToStreamFilter(sc, policy_id);
#endif
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
    tSfPolicyUserContextId modsec_swap_config = (tSfPolicyUserContextId)swap_config;
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
