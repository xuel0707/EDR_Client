#ifndef _NET_H
#define _NET_H

#include <linux/limits.h>
#include <pwd.h>
#include <grp.h>

#include "common.h"

#define OP_LEN_MAX		20
#define LOG_NAME_MAX	40
#define EVENT_NAME_MAX	40
#define TASK_COMM_LEN	16


struct net_msg_args {
	uid_t uid;                                              
	int tgid;
	unsigned int pid;  

	char comm[TASK_COMM_LEN]; 
	unsigned short protocol; 
	unsigned short sport;                  
	unsigned short dport;
	unsigned int saddr;                        
	unsigned int daddr;       

	unsigned short event_id;
    char loglevel;
	char behavior_id;
	char terminate;
	char blockip;          
	struct timeval2 event_tv;           
    
	unsigned int repeat;                
	int domain_query_type;              
	unsigned int effective_time;        
	unsigned int portscan_lockip_time;  
	unsigned int portscan_max;         
	unsigned int honey_lockip_time;    
	unsigned int ports_count;           
	unsigned short reason;             
	char ip[S_IPLEN];                   
	char domain[S_DOMAIN_NAMELEN];    
};

#endif /* _NET_H */
