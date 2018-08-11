#include "Http_Cookie_Extract.h"

#define REGEX_HOST "REGEX_HOST"
#define REGEX_ACCOUNT "REGEX_ACCOUNT"
#define CONF_SETTING "SETTING"

HC_Conf* hc_conf ;

const char* module_name = "HTTP_COOKIE_EXTRACT";
const char* http_cookie_config_path = "/home/zhangshuai/sapp_run/conf/http_cookie_extract.conf";
const char* http_cookie_log_path = "/home/zhangshuai/log/http_cookie_extract.log";
const char* http_cookie_result_path = "../log/extract_result.log";

enum _extract_items
{
	HOST = 0 ,
	ACCOUNT ,
	IPADDR
};

void Http_Cookie_Extract_INIT()
{
	printf("Http_Cookie_Extract_INIT ... \n");
	hc_conf = (HC_Conf*)malloc(sizeof(HC_Conf));
//	hc_conf->host_regex = "";
//	hc_conf->account_regex = "";
	hc_conf->runtime_log_handler = NULL;
	hc_conf->host_regex_t = NULL;
	hc_conf->account_regex_t = NULL;
	MESA_load_profile_string_nodef(http_cookie_config_path, CONF_SETTING,REGEX_HOST, hc_conf->host_regex, MAX_REGEX_LEN);
	MESA_load_profile_string_nodef(http_cookie_config_path, CONF_SETTING,REGEX_ACCOUNT, hc_conf->account_regex, MAX_REGEX_LEN);
	regcomp(hc_conf->host_regex_t, hc_conf->host_regex, REG_EXTENDED);
	regcomp(hc_conf->account_regex_t, hc_conf->account_regex, REG_EXTENDED);
	hc_conf->runtime_log_handler = MESA_create_runtime_log_handle(http_cookie_log_path, RLOG_LV_INFO);
	if(NULL == hc_conf->runtime_log_handler)
	{
		printf("MESA_create_runtime_log_handle failed!!!");
		return;
	}
}

void Http_Cookie_Extract_DESTORY()
{
	printf("Http_Cookie_Extract_DESTORY in...\n");
	if(NULL == hc_conf)
	{
		return;
	}
	regfree(hc_conf->host_regex_t);
	regfree(hc_conf->account_regex_t);
	MESA_destroy_runtime_log_handle(hc_conf->runtime_log_handler);
	free(hc_conf);
	hc_conf = NULL;
}

int init_http_cookie_extract_info(HC_Info **pme)
{
	HC_Info *hc_info = (HC_Info *)malloc(sizeof(HC_Info));
//	hc_info->host = "";
//	hc_info->account = "";

//释放socket指针
//	hc_info->ip_addr = NULL;
	memset(((HC_Info*)pme)->already_extract, 0, ITEMS_EXTRACT_NUM);
	*pme = hc_info;
	//是否需要释放hc_info?????????????
	return 0;
}

void destroy_http_cookie_extract_info(HC_Info **pme)
{
	if(NULL == *pme)
	{
		return;
	}
	free(*pme);
	*pme = NULL;
}

void ipaddr_extract_stream(HC_Info **pme , struct streaminfo *a_stream)
{
//	struct _socket_pairs* socket_pairs = (_socket_pairs *)malloc(sizeof(_socket_pairs));
//	struct stream_tuple4_v4* v4_addr_info;
//	struct stream_tuple4_v6* v6_addr_info;
	unsigned short tunnel_type;
	int len = sizeof(short);
	MESA_get_stream_opt(a_stream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &len);
	if(STREAM_TUNNLE_NON == tunnel_type)
	{
		switch(a_stream->addr.addrtype)
		{
			case ADDR_TYPE_IPV4:
				(*pme)->addrtype = ADDR_TYPE_IPV4;
				(*pme)->ip_addr.tuple4_v4 = a_stream->addr.tuple4_v4;
/*				v4_addr_info=a_stream->addr.tuple4_v4;
//				inet_ntop(AF_INET, &(v4_addr_info->saddr), socket_pairs->sip, IP4_LEN);	
//				inet_ntop(AF_INET, &(v4_addr_info->daddr), socket_pairs->dip, IP4_LEN);	
				socket_pairs->sport = v4_addr_info->source;
				socket_pairs->dport = v4_addr_info->dest;*/
				break;
			case ADDR_TYPE_IPV6:
				(*pme)->addrtype = ADDR_TYPE_IPV6;
				(*pme)->ip_addr.tuple4_v6 = a_stream->addr.tuple4_v6;
/*				v6_addr_info=a_stream->addr.tuple4_v6;
				snprintf(socket_pairs->sip, IPV6_ADDR_LEN, "%s", v6_addr_info->saddr);
				snprintf(socket_pairs->dip, IPV6_ADDR_LEN, "%s", v6_addr_info->daddr);
				socket_pairs->sport = v6_addr_info->source;
				socket_pairs->dport = v6_addr_info->dest;  */
				break;
			default:
				break;
		}
		(*pme)->already_extract[IPADDR] = 1;
	}
}

int regex_matching(regex_t* reg, char* buf, char* result)
{
	int status = -1, nm = 2;
	regmatch_t pmatch[nm];

	status = regexec(reg, buf, nm, pmatch, 0);
	if (REG_NOMATCH == status)
	{
		MESA_handle_runtime_log(hc_conf->runtime_log_handler, RLOG_LV_FATAL, module_name, "no matching...");
		return 0;
	}
	else if(REG_NOERROR == status)
	{
		if (((sizeof(pmatch)/sizeof(regmatch_t)) < 2) || -1 == pmatch[1].rm_so)
		{
			MESA_handle_runtime_log(hc_conf->runtime_log_handler, RLOG_LV_FATAL, module_name, "no matching...");
			return 0;
		}
		memset(result, 0, sizeof(result));
		memcpy(result, buf+pmatch[1].rm_so, pmatch[1].rm_eo - pmatch[1].rm_so);
	}
	return 1;
}

void http_extract_session_info(stSessionInfo* session_info, HC_Info **pme)
{
	int buflen = 0;
	char *account = NULL;
	if (0 != (buflen = session_info->buflen))
	{
		//printf("buf: %s\n",session_info->buf);
		switch(session_info->prot_flag){
			case HTTP_HOST:
				if(1 == ((HC_Info *)(*pme))->already_extract[HOST])
				{
					break;
				}
				if(1 == regex_matching(hc_conf->host_regex_t , session_info->buf, (*pme)->host))
				{
//					memcpy(((HC_Info *)(*pme))->host,session_info->buf,buflen+1);
					((HC_Info *)(*pme))->already_extract[HOST] = 1;
				}
				break;
			case HTTP_COOKIE:
				if(1 == ((HC_Info *)(*pme))->already_extract[ACCOUNT])
				{
					break;
				}
				if(1 == regex_matching(hc_conf->account_regex_t , session_info->buf, (*pme)->account))
				{
//					memcpy(((HC_Info *)(*pme))->host,account,sizeof(account)+1);
					((HC_Info *)(*pme))->already_extract[ACCOUNT] = 1;
				}
				break;
			default:
				break;
		}
	}
}

void record_http_cookie_extract(HC_Info **pme)
{
	if(NULL == *pme)
	{
		return;
	}
	if(1 == (*pme)->already_extract[HOST] && 1 == (*pme)->already_extract[ACCOUNT] && 1 == (*pme)->already_extract[IPADDR] )
	{
		char extract_info[MAX_EXTRACT_INFO_LEN] = {0};
		if (ADDR_TYPE_IPV4 == (*pme)->addrtype)
		{		
			char sip[IPV4_ADDR_P_LEN];
			char dip[IPV4_ADDR_P_LEN];
			struct stream_tuple4_v4 *tuple4_v4 = (struct stream_tuple4_v4 *)((*pme)->ip_addr.tuple4_v4);
			inet_ntop(AF_INET, &(tuple4_v4->saddr), sip, IPV4_ADDR_N_LEN);
			inet_ntop(AF_INET, &(tuple4_v4->daddr), dip, IPV4_ADDR_N_LEN);
			snprintf(extract_info, MAX_EXTRACT_INFO_LEN, "\n\t\t\t\tIP_tuple:\t%s:%d -> %s:%d\n\t\t\t\tHost:\t%s\n\t\t\t\tAccount:\t%s", sip,tuple4_v4->source,dip,tuple4_v4->source,(*pme)->host,(*pme)->account);
			MESA_handle_runtime_log(hc_conf->runtime_log_handler, RLOG_LV_INFO, module_name, extract_info);
		}
		else if (ADDR_TYPE_IPV6 == (*pme)->addrtype)
		{
			struct stream_tuple4_v6 *tuple4_v6 = (struct stream_tuple4_v6 *)((*pme)->ip_addr.tuple4_v6);
			snprintf(extract_info, MAX_EXTRACT_INFO_LEN, "\n\t\t\t\tIP_tuple:\t%s:%d -> %s:%d\n\t\t\t\tHost:\t%s\n\t\t\t\tAccount:\t%s", tuple4_v6->saddr,tuple4_v6->source,tuple4_v6->daddr,tuple4_v6->source,(*pme)->host,(*pme)->account);
			MESA_handle_runtime_log(hc_conf->runtime_log_handler, RLOG_LV_INFO, module_name, extract_info);
		} 
//		printf("host: %s\naccount: %s\nsip: %s\nsport: %d\n",(*pme)->host,(*pme)->account,(*pme)->socket_pairs->sip,(*pme)->socket_pairs->sport);
	}
}

char Http_Cookie_Extract_Entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,void *a_packet)
{
	printf("Http_Cookie_Extract_Entry in......................\n");
	if(NULL == session_info){
		MESA_handle_runtime_log(hc_conf->runtime_log_handler, RLOG_LV_FATAL, module_name, "session_info is NULL.");
		*pme = NULL;
		return PROT_STATE_DROPME;
	}
	
	if(session_info->session_state&SESSION_STATE_PENDING)
	{
//		MESA_handle_runtime_log(hc_conf->runtime_log_handler, RLOG_LV_INFO, module_name, "session_state_pending.");
		if(0 != init_http_cookie_extract_info((HC_Info **)pme))
		{
			MESA_handle_runtime_log(hc_conf->runtime_log_handler, RLOG_LV_FATAL, module_name, "http_cookie_extract initianize failed.");
			return PROT_STATE_DROPME;
		}
		ipaddr_extract_stream((HC_Info **)pme,a_stream);
	}

	http_extract_session_info(session_info, (HC_Info **)pme);

	if(session_info->session_state&SESSION_STATE_CLOSE)
	{
//		MESA_handle_runtime_log(hc_conf->runtime_log_handler, RLOG_LV_INFO, module_name, "session_state_close.");
		record_http_cookie_extract((HC_Info **)pme);
		destory_http_cookie_extract_info((HC_Info **)pme);
		return PROT_STATE_DROPME;
	}
	printf("Http_Cookie_Extract_Entry out\n");
	return PROT_STATE_GIVEME;
}
