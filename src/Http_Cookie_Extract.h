#ifndef _HTTP_COOKIE_EXTRACT_H_
#define _HTTP_COOKIE_EXTRACT_H_

#include <MESA/http.h>
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#define PATH_EXTRACT_CONF ""
#define PATH_EXTRACT_LOG ""
#define MAX_IP_LEN 128
#define MAX_ACCOUNT_LEN 128
#define MAX_HOST_LEN 128
#define MAX_REGEX_LEN 128
#define ITEMS_EXTRACT_NUM 3

struct _http_cookie_extract_config
{
	char host_regex[MAX_REGEX_LEN];
	char account_regex[MAX_REGEX_LEN];
}HC_Conf;

struct _http_cookie_extract_info
{
	char host[MAX_HOST_LEN];
	char acount[MAX_ACCOUNT_LEN];
	struct _socket_pairs *socket_pairs;
	int already_extract[ITEMS_EXTRACT_NUM];
}HC_Info;

struct _socket_pairs
{
//是否要加1
	char sip[MAX_IP_LEN];
	ushort sport;
	char dip[MAX_IP_LEN];
	ushort dport;
};

#ifndef _cplusplus
extern "C" 
{
#endif

void Http_Cookie_Extract_INIT(void);
void Http_Cookie_Extract_DESTORY(void);
char Http_Cookie_Extract_Entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,void *a_packet);


#ifndef _cplusplus 
}
#endif

#endif