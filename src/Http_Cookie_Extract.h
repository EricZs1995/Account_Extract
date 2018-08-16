#ifndef _HTTP_COOKIE_EXTRACT_H_
#define _HTTP_COOKIE_EXTRACT_H_

#include <MESA/http.h>
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#define MAX_IP_LEN 128
#define MAX_ACCOUNT_LEN 128
#define MAX_HOST_LEN 128
#define MAX_REGEX_LEN 128
#define ITEMS_EXTRACT_NUM 3
#define IPV4_ADDR_N_LEN	(sizeof(unsigned int))
#define IPV4_ADDR_P_LEN 16
#define MAX_EXTRACT_INFO_LEN 512
typedef struct _http_cookie_extract_config
{
	char host_regex[MAX_REGEX_LEN+1];
	char account_regex[MAX_REGEX_LEN+1];
	regex_t* host_regex_t;
	regex_t* account_regex_t;
	void* runtime_log_handler;
}HC_Conf;


typedef struct _http_cookie_extract_info
{
	char host[MAX_HOST_LEN+1];
	char account[MAX_ACCOUNT_LEN+1];
//	struct _socket_pairs *socket_pairs;
	unsigned char addrtype;
	int already_extract[ITEMS_EXTRACT_NUM];
	union
	{
			struct stream_tuple4_v4 *tuple4_v4;
			struct stream_tuple4_v6 *tuple4_v6;
	}ip_addr;
}HC_Info;

#ifdef _cplusplus
extern "C" 
{
#endif

void Http_Cookie_Extract_INIT(void);
void Http_Cookie_Extract_DESTORY(void);
char Http_Cookie_Extract_Entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,void *a_packet);

#ifdef _cplusplus 
}
#endif

#endif
