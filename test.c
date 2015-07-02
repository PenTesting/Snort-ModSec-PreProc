#define SRC_CCN_MATCH 		3
#define SRC_CCN_MATCH_STR 	"example_preprocessor: source port matched"
#define DST_CCN_MATCH 		4
#define DST_CCN_MATCH_STR 	"example_preprocessor: destination port matched"
#define SRCH_STRING 	 	"4444 4444 4444 4444"

void ExampleProcess(void *pkt, void *context)
{
    SFSnortPacket *p = (SFSnortPacket *)pkt;
    int i,result;

    if(!p->ip4_header || p->ip4_header->proto != IPROTO_TCP || !p->tcp_header)
    {
        /* Not for me */
        return;
    }

    if(p->src_port == portToCheck)
    {
        char *ptr = (char *) p->payload;
	for(i=0;i<(p->payload_size - 19);i++)
	{
	    result = strncmp(&ptr[i], SRCH_STRING, 19);
	    if(result == 0) {
	      _dpd.logMsg("CCN found in outgoing traffic");
	      /* Source port matched, log alert */
	      _dpd.alertAdd(GENERATOR_EXAMPLE, SRC_CCN_MATCH, 1, 0, 3, SRC_CCN_MATCH_STR, 0);
	      return;
	    }
	}
    }

    if(p->dst_port = portToCheck)
    {
        char *ptr = (char *) p->payload;
	for(i = 0;i < (p->payload_size - 19);i++)
	{
	    result = strncmp(&ptr[i], SRCH_STRING, 19);
	    if(result == 0) {
	        _dpd.logMsg("CCN foudn in incoming traffic");
		/* Destination port matched, log alert */
		_dpd.alertAdd(GENERATOR_EXAMPLE, DST_CCN_MATCH, 1, 0 ,3, DST_CCN_MATCH_STR, 0);
		return;
	    }
	}
    }
}
