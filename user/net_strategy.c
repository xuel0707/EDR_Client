#include "header.h"

int black_dns_list_size = 0;
int white_dns_list_size = 0;
int trust_dns_list_size = 0;
int filter_dns_list_size = 0;

static int black_dns_mem_size = 0;
static int white_dns_mem_size = 0;
static int trust_dns_mem_size = 0;
static int filter_dns_mem_size = 0;

static char *black_dns_mem = NULL;
static char *white_dns_mem = NULL;
static char *trust_dns_mem = NULL;
static char *filter_dns_mem = NULL;

static struct kern_net_rules nrule = {0};

static unsigned long sniper_ip2addr(struct sniper_ip *ip)
{
	return ( (((unsigned long)ip->ip[0]) << 24) +
		 (((unsigned long)ip->ip[1]) << 16) +
		 (((unsigned long)ip->ip[2]) <<  8) +
		  ((unsigned long)ip->ip[3]) );
}

/* 匹配ip, 匹配返回1，没匹配返回0 */
static int ip_inrange(struct sniper_ip *ip, struct sniper_iprange *ipr)
{
	unsigned long ipaddr = sniper_ip2addr(ip);
	unsigned long fromaddr = sniper_ip2addr(&ipr->fromip);
	unsigned long toaddr = sniper_ip2addr(&ipr->toip);
	int n = 0;

	/* 0.0.0.0表示任意ip */
	if (fromaddr == 0) {
		return 1;
	}

	/* x.x.x.x - y.y.y.y */
	if (ipr->toip.ip[0] != 0) {
		/* fromip <= ip <= toip */
		if (fromaddr <= ipaddr && ipaddr <= toaddr) {
			return 1;
		}
		return 0;
	}

	/* x.x.x.x */
	if (ipr->sniper_ipmask == 0) {
		if (ipaddr == fromaddr) {
			return 1;
		}
		return 0;
	}

	/* x.x.x.x/z */
	n = 32 - ipr->sniper_ipmask;
	if ( (ipaddr >> n) == (fromaddr >> n)) {
		return 1;
	}

	return 0;
}

void update_asset_conf(void)
{
	/* 资产清点手动更新标志 */
	is_sync_once = is_sync_global;

	int i = 0;
	unsigned int module_st = 0;
	pthread_rwlock_rdlock(&conf_asset.lock);
	for (i=0; i < conf_asset.num; i++) {
		/* hardware */
		if (strcmp(conf_asset.collect_items[i].name, "hardware") == 0) {
			module_st |= 1;
		}
		/* partition */
		if (strcmp(conf_asset.collect_items[i].name, "partition") == 0) {
			module_st |= 1 << 9;
		}
		/* services */
		if (strcmp(conf_asset.collect_items[i].name, "services") == 0) {
			module_st |= 1 << 10;
		}
		/* software */
		if (strcmp(conf_asset.collect_items[i].name, "software") == 0) {
			module_st |= 1 << 11;
		}
		/* install_pkg */
		if (strcmp(conf_asset.collect_items[i].name, "install_pkg") == 0) {
			module_st |= 1 << 12;
		}
		/* process */
		if (strcmp(conf_asset.collect_items[i].name, "process") == 0) {
			module_st |= 1 << 13;
		}
		/* port */
		if (strcmp(conf_asset.collect_items[i].name, "port") == 0) {
			module_st |= 1 << 14;
		}
		/* database */
		if (strcmp(conf_asset.collect_items[i].name, "database") == 0) {
			module_st |= 1 << 15;
		}
		/* jar */
		if (strcmp(conf_asset.collect_items[i].name, "jar") == 0) {
			module_st |= 1 << 16;
		}

		/* container */
		if (strcmp(conf_asset.collect_items[i].name, "container") == 0) {
			module_st |= 1 << 17;
		}
		/* account */
		if (strcmp(conf_asset.collect_items[i].name, "account") == 0) {
			module_st |= 1 << 18;
		}
		/* starter */
		if (strcmp(conf_asset.collect_items[i].name, "starter") == 0) {
			module_st |= 1 << 19; 
		}
		/* share */
		if (strcmp(conf_asset.collect_items[i].name, "share") == 0) {
			module_st |= 1 << 20;
		}
		/* env */
		if (strcmp(conf_asset.collect_items[i].name, "env") == 0) {
			module_st |= 1 << 21;
		}
		/* task */
		if (strcmp(conf_asset.collect_items[i].name, "task") == 0) {
			module_st |= 1 << 22;
		}
		/* kernel */
		if (strcmp(conf_asset.collect_items[i].name, "kernel") == 0) {
			module_st |= 1 << 23;
		}

		/* web_middleware */
		if (strcmp(conf_asset.collect_items[i].name, "web_middleware") == 0) {
			module_st |= 1 << 24;
		}
		/* web_app */
		if (strcmp(conf_asset.collect_items[i].name, "web_app") == 0) {
			module_st |= 1 << 25;
		}
		/* website */
		if (strcmp(conf_asset.collect_items[i].name, "website") == 0) {
			module_st |= 1 << 26;
		}
		/* web_framework */
		if (strcmp(conf_asset.collect_items[i].name, "web_framework") == 0) {
			module_st |= 1 << 27;
		}

		/* vuln */
		if (strcmp(conf_asset.collect_items[i].name, "vuln") == 0) {
			module_st |= 1 << 28;
		}
		/* os */
		// if (strcmp(conf_asset.collect_items[i].name, "os") == 0) {
			module_st |= 1 << 29;
		// }
	}
	conf_asset.module_st = module_st;
	pthread_rwlock_unlock(&conf_asset.lock);
	// INFO("module---------%u\n", module_st);

	return;
}

static void parse_port(char *port_str, int *fromport, int *toport)
{
	int ret = 0;
	char *ptr = NULL;

	if (!port_str || !fromport || !toport) {
		return;
	}

	ptr = strchr(port_str, '-');
	if (!ptr) {
		*fromport = atoi(port_str);
		*toport = atoi(port_str);
		return;
	}

	*ptr = 0;
	*fromport = atoi(port_str);
	*toport = atoi(ptr+1);

	if (*fromport > *toport) {  /* fromport一定要小于toport */
		ret = *fromport;
		*fromport = *toport;
		*toport = ret;
	}
}

static void black_conf(void) 
{
	int i = 0;
	int j = 0;
	int len = 0;
	int index = 0;
	int count = 0;

	/* 黑名单 */
	///////////////////////////////////////////////////
	///////////////////////////////////////////////////
	pthread_rwlock_wrlock(&rule_black_global.lock);
	/* 域名黑名单，默认打开阻断 */
	if (black_rule.domain.domain_num) {
		for (i=0; i<black_rule.domain.domain_num; i++) {
			if (black_rule.domain.domain_list[i].domain) {
				free(black_rule.domain.domain_list[i].domain);
				black_rule.domain.domain_list[i].domain = NULL;
			}
		}
		free(black_rule.domain.domain_list);
		black_rule.domain.domain_list = NULL;
		black_rule.domain.domain_num = 0;
	}
	for (i=0; i<rule_black_global.domain_num; i++) {
		count += rule_black_global.domain[i].domain_num;
	}

	black_dns_list_size = 0;
	black_rule.domain.domain_num = count;
	if (black_rule.domain.domain_num) {
		net_rule.domain.enable = TURNON;
		black_rule.enable = TURNON;
		black_rule.domain.enable = TURNON;

		black_rule.domain.domain_list = (PRULE_DOMAIN_LIST)malloc(sizeof(PRULE_DOMAIN_LIST)*count);
		if (black_rule.domain.domain_list) {
			for (i=0; i<rule_black_global.domain_num; i++) {
				for (j=0; j<rule_black_global.domain[i].domain_num; j++) {
					len = strlen(rule_black_global.domain[i].domain_list[j].list) + 1;
					black_dns_list_size += len;
					black_rule.domain.domain_list[index].domain = (char*)calloc(len, sizeof(char));
					snprintf(black_rule.domain.domain_list[index].domain, len, "%s", rule_black_global.domain[i].domain_list[j].list);
					// INFO("black domain--%s--\n", black_rule.domain.domain_list[index].domain);
					index ++;
				}
			}
		} else {
			black_rule.domain.domain_num = 0;
			black_rule.domain.domain_list = NULL;
			// MON_ERROR("Domin conf init faild\n");
		}
	} else {
		black_rule.domain.domain_num = 0;
		black_rule.domain.domain_list = NULL;
	}

	/* 规则黑名单的访问控制对应内核里的黑名单
	 * 规则黑名单里的IP对就内核里的lockip,对应远程登录模块
	 */
	// INFO("====%d\n", rule_black_global.access_control_num);
	/* 释放in的IP黑名单 */
	if (black_rule.connect.inbound.connect_num) {
		for (i=0; i<black_rule.connect.inbound.connect_num; i++) {
			if (black_rule.connect.inbound.connect_list[i].ip) {
				free(black_rule.connect.inbound.connect_list[i].ip);
			}
			if (black_rule.connect.inbound.connect_list[i].protocol) {
				free(black_rule.connect.inbound.connect_list[i].protocol);
			}
		}
		if (black_rule.connect.inbound.connect_list) {
			free(black_rule.connect.inbound.connect_list);
			black_rule.connect.inbound.connect_list = NULL;
		}
		black_rule.connect.inbound.connect_num = 0;
	}
	/* 释放out的IP黑名单 */
	if (black_rule.connect.outbound.connect_num) {
		for (i=0; i<black_rule.connect.outbound.connect_num; i++) {
			if (black_rule.connect.outbound.connect_list[i].ip) {
				free(black_rule.connect.outbound.connect_list[i].ip);
			}
			if (black_rule.connect.outbound.connect_list[i].protocol) {
				free(black_rule.connect.outbound.connect_list[i].protocol);
			}
		}
		if (black_rule.connect.outbound.connect_list) {
			free(black_rule.connect.outbound.connect_list);
			black_rule.connect.outbound.connect_list = NULL;
		}
		black_rule.connect.outbound.connect_num = 0;
	}

	for (i=0; i<rule_black_global.access_control_num; i++) {
		for (j=0; j<rule_black_global.access_control[i].connect_num; j++) {
			if (strncmp(rule_black_global.access_control[i].connect_list[j].direction, "in", 2) == 0) {
				black_rule.connect.inbound.connect_num ++;
				if (rule_black_global.access_control[i].connect_list[j].port) {
					char *tmp = strchr(rule_black_global.access_control[i].connect_list[j].port, ',');
					while (tmp) {
						++ tmp;
						tmp = strchr(tmp, ',');
						black_rule.connect.inbound.connect_num ++;
					}
				}
			} else if (strncmp(rule_black_global.access_control[i].connect_list[j].direction, "out", 3) == 0) {
				black_rule.connect.outbound.connect_num ++;
				if (rule_black_global.access_control[i].connect_list[j].port) {
					char *tmp = strchr(rule_black_global.access_control[i].connect_list[j].port, ',');
					while (tmp) {
						++ tmp;
						tmp = strchr(tmp, ',');
						black_rule.connect.outbound.connect_num ++;
					}
				}
			}
		}
	}
	if (black_rule.connect.inbound.connect_num) {
		index = 0;
		net_rule.enable = TURNON;
		black_rule.enable = TURNON;
		black_rule.connect.inbound.enable = TURNON;
		black_rule.connect.inbound.connect_list = (PRULE_CONNECT_LIST)calloc(sizeof(RULE_CONNECT_LIST), black_rule.connect.inbound.connect_num);
		if (black_rule.connect.inbound.connect_list) {
			for (i=0; i<rule_black_global.access_control_num; i++) {
				for (j=0; j<rule_black_global.access_control[i].connect_num; j++) {
					if (strncmp(rule_black_global.access_control[i].connect_list[j].direction, "in", 2) == 0) {
						char port_str[4096] = {0};
						char *port_p = port_str;
						snprintf(port_str, sizeof(port_str), "%s", rule_black_global.access_control[i].connect_list[j].port);
						char *tmp = strchr(port_str, ',');
						if (tmp) { /* 对于 88,99,999 端口字符串 */
							while (tmp) {
								*tmp = '\0';
								len = strlen(rule_black_global.access_control[i].connect_list[j].ip) + 1;
								black_rule.connect.inbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
								snprintf(black_rule.connect.inbound.connect_list[index].ip, len, "%s", 
													rule_black_global.access_control[i].connect_list[j].ip);
								len = 64;
								black_rule.connect.inbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
								snprintf(black_rule.connect.inbound.connect_list[index].protocol, len, "%s", 
													rule_black_global.access_control[i].connect_list[j].protocol);
								black_rule.connect.inbound.connect_list[index].fromport = atoi(port_p);
								black_rule.connect.inbound.connect_list[index].toport = atoi(port_p);
								index ++;
								
								++ tmp;
								port_p = tmp;
								tmp = strchr(tmp, ',');
							}
							len = strlen(rule_black_global.access_control[i].connect_list[j].ip) + 1;
							black_rule.connect.inbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
							snprintf(black_rule.connect.inbound.connect_list[index].ip, len, "%s", 
												rule_black_global.access_control[i].connect_list[j].ip);
							len = 64;
							black_rule.connect.inbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
							snprintf(black_rule.connect.inbound.connect_list[index].protocol, len, "%s", 
												rule_black_global.access_control[i].connect_list[j].protocol);
							black_rule.connect.inbound.connect_list[index].fromport = atoi(port_p);
							black_rule.connect.inbound.connect_list[index].toport = atoi(port_p);
							index ++;
						} else {
							parse_port(rule_black_global.access_control[i].connect_list[j].port, 
								&black_rule.connect.inbound.connect_list[index].fromport,
								&black_rule.connect.inbound.connect_list[index].toport);
							len = strlen(rule_black_global.access_control[i].connect_list[j].ip) + 1;
							black_rule.connect.inbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
							snprintf(black_rule.connect.inbound.connect_list[index].ip, len, "%s", 
											rule_black_global.access_control[i].connect_list[j].ip);
							len = 64;
							black_rule.connect.inbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
							snprintf(black_rule.connect.inbound.connect_list[index].protocol, len, "%s", 
											rule_black_global.access_control[i].connect_list[j].protocol);
							index ++;
							// INFO("inlen:%d--%s-%s\n", len, rule_black_global.access_control[i].connect_list[j].ip, rule_black_global.access_control[i].connect_list[j].protocol);
						}
					}
				}
			}
		}
	}
#if 0
	for (i=0; i<black_rule.connect.inbound.connect_num; i++) {
		INFO("blackin--%s--%s--%d-%d\n", black_rule.connect.inbound.connect_list[i].ip,
								black_rule.connect.inbound.connect_list[i].protocol,
								black_rule.connect.inbound.connect_list[i].fromport,
								black_rule.connect.inbound.connect_list[i].toport);
	}
#endif
	if (black_rule.connect.outbound.connect_num) {
		index = 0;
		net_rule.enable = TURNON;
		black_rule.enable = TURNON;
		black_rule.connect.outbound.enable = TURNON;
		black_rule.connect.outbound.connect_list = (PRULE_CONNECT_LIST)calloc(sizeof(RULE_CONNECT_LIST), black_rule.connect.outbound.connect_num);
		if (black_rule.connect.outbound.connect_list) {
			for (i=0; i<rule_black_global.access_control_num; i++) {
				for (j=0; j<rule_black_global.access_control[i].connect_num; j++) {
					if (strncmp(rule_black_global.access_control[i].connect_list[j].direction, "out", 3) == 0) {
						char port_str[4096] = {0};
						char *port_p = port_str;
						snprintf(port_str, sizeof(port_str), "%s", rule_black_global.access_control[i].connect_list[j].port);
						char *tmp = strchr(port_str, ',');
						if (tmp) { /* 对于 88,99,999 端口字符串 */
							while (tmp) {
								*tmp = '\0';
								len = strlen(rule_black_global.access_control[i].connect_list[j].ip) + 1;
								black_rule.connect.outbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
								snprintf(black_rule.connect.outbound.connect_list[index].ip, len, "%s", 
													rule_black_global.access_control[i].connect_list[j].ip);
								len = 64;
								black_rule.connect.outbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
								snprintf(black_rule.connect.outbound.connect_list[index].protocol, len, "%s", 
													rule_black_global.access_control[i].connect_list[j].protocol);
								black_rule.connect.outbound.connect_list[index].fromport = atoi(port_p);
								black_rule.connect.outbound.connect_list[index].toport = atoi(port_p);
								index ++;
								
								++ tmp;
								port_p = tmp;
								tmp = strchr(tmp, ',');
							}
							len = strlen(rule_black_global.access_control[i].connect_list[j].ip) + 1;
							black_rule.connect.outbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
							snprintf(black_rule.connect.outbound.connect_list[index].ip, len, "%s", 
												rule_black_global.access_control[i].connect_list[j].ip);
							len = 64;
							black_rule.connect.outbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
							snprintf(black_rule.connect.outbound.connect_list[index].protocol, len, "%s", 
												rule_black_global.access_control[i].connect_list[j].protocol);
							black_rule.connect.outbound.connect_list[index].fromport = atoi(port_p);
							black_rule.connect.outbound.connect_list[index].toport = atoi(port_p);
							index ++;
						} else {
							parse_port(rule_black_global.access_control[i].connect_list[j].port,
									&black_rule.connect.outbound.connect_list[index].fromport, 
									&black_rule.connect.outbound.connect_list[index].toport);
						
							len = strlen(rule_black_global.access_control[i].connect_list[j].ip) + 1;
							// INFO("outlen:%d--%s-%s-%s\n", len, rule_black_global.access_control[i].connect_list[j].ip, 
							// 									rule_black_global.access_control[i].connect_list[j].port, 
							// 									rule_black_global.access_control[i].connect_list[j].protocol);
							black_rule.connect.outbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
							snprintf(black_rule.connect.outbound.connect_list[index].ip, len, "%s", 
												rule_black_global.access_control[i].connect_list[j].ip);
							len = 64;
							black_rule.connect.outbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
							snprintf(black_rule.connect.outbound.connect_list[index].protocol, len, "%s", 
												rule_black_global.access_control[i].connect_list[j].protocol);
							index ++;
						}
					}
				}
			}
		}
	}
#if 0
	for (i=0; i<black_rule.connect.outbound.connect_num; i++) {
		INFO("blackout--%s--%s--%d-%d\n", black_rule.connect.outbound.connect_list[i].ip,
								black_rule.connect.outbound.connect_list[i].protocol,
								black_rule.connect.outbound.connect_list[i].fromport,
								black_rule.connect.outbound.connect_list[i].toport);
	}
#endif
	pthread_rwlock_unlock(&rule_black_global.lock);
	///////////////////////////////////////////////////

}

/* 白名单 */
static void white_conf(void)
{
	int i = 0, j = 0, len = 0, index = 0, count = 0, size = 0;

	pthread_rwlock_wrlock(&rule_white_global.lock);

	/* 域名白名单 */
	/* 先释放老的域名白名单 */
	if (white_rule.domain.domain_num) {
		for (i = 0; i < white_rule.domain.domain_num; i++) {
			if (white_rule.domain.domain_list[i].domain) {
				free(white_rule.domain.domain_list[i].domain);
				white_rule.domain.domain_list[i].domain = NULL;
			}
		}
		if (white_rule.domain.domain_list) {
			free(white_rule.domain.domain_list);
			white_rule.domain.domain_list = NULL;
		}
		white_rule.domain.domain_num = 0;
	}

	/* 再获取新的域名白名单 */
	count = 0;
	for (i = 0; i < rule_white_global.domain_num; i++) {
		count += rule_white_global.domain[i].domain_num;
	}

	white_dns_list_size = 0;
	white_rule.domain.domain_num = count;
	if (white_rule.domain.domain_num) {
		net_rule.domain.enable = TURNON;
		white_rule.enable = TURNON;
		white_rule.domain.enable = TURNON;

		size = sizeof(PRULE_DOMAIN_LIST) * count;
		white_rule.domain.domain_list = (PRULE_DOMAIN_LIST)malloc(size);

		if (white_rule.domain.domain_list) {
			index = 0;
			for (i = 0; i < rule_white_global.domain_num; i++) {
				for (j = 0; j < rule_white_global.domain[i].domain_num; j++) {
					len = strlen(rule_white_global.domain[i].domain_list[j].list) + 1;
					white_dns_list_size += len;
					white_rule.domain.domain_list[index].domain = (char*)calloc(len, sizeof(char));
					snprintf(white_rule.domain.domain_list[index].domain, len, "%s", rule_white_global.domain[i].domain_list[j].list);
					// INFO("w--%s---\n", white_rule.domain.domain_list[i].domain);
					index ++;
				}
			}
		} else {
			white_rule.domain.domain_num = 0;
			white_rule.domain.domain_list = NULL;
		}
	} else {
		white_rule.domain.domain_num = 0;
		white_rule.domain.domain_list = NULL;
	}

	/* 释放in的IP白名单 */
	if (white_rule.connect.inbound.connect_num) {
		for (i=0; i<white_rule.connect.inbound.connect_num; i++) {
			if (white_rule.connect.inbound.connect_list[i].ip) {
				free(white_rule.connect.inbound.connect_list[i].ip);
			}
			if (white_rule.connect.inbound.connect_list[i].protocol) {
				free(white_rule.connect.inbound.connect_list[i].protocol);
			}
		}
		if (white_rule.connect.inbound.connect_list) {
			free(white_rule.connect.inbound.connect_list);
			white_rule.connect.inbound.connect_list = NULL;
		}
		white_rule.connect.inbound.connect_num = 0;
	}
	/* 释放out的IP白名单 */
	if (white_rule.connect.outbound.connect_num) {
		for (i=0; i<white_rule.connect.outbound.connect_num; i++) {
			if (white_rule.connect.outbound.connect_list[i].ip) {
				free(white_rule.connect.outbound.connect_list[i].ip);
			}
			if (white_rule.connect.outbound.connect_list[i].protocol) {
				free(white_rule.connect.outbound.connect_list[i].protocol);
			}
		}
		if (white_rule.connect.outbound.connect_list) {
			free(white_rule.connect.outbound.connect_list);
			white_rule.connect.outbound.connect_list = NULL;
		}
		white_rule.connect.outbound.connect_num = 0;
	}

	for (i=0; i<rule_white_global.access_control_num; i++) {
		for (j=0; j<rule_white_global.access_control[i].connect_num; j++) {
			if (strncmp(rule_white_global.access_control[i].connect_list[j].direction, "in", 2) == 0) {
				white_rule.connect.inbound.connect_num ++;
				if (rule_white_global.access_control[i].connect_list[j].port) {
					char *tmp = strchr(rule_white_global.access_control[i].connect_list[j].port, ',');
					while (tmp) {
						++ tmp;
						tmp = strchr(tmp, ',');
						white_rule.connect.inbound.connect_num ++;
					}
				}
			} else if (strncmp(rule_white_global.access_control[i].connect_list[j].direction, "out", 3) == 0) {
				white_rule.connect.outbound.connect_num ++;
				if (rule_white_global.access_control[i].connect_list[j].port) {
					char *tmp = strchr(rule_white_global.access_control[i].connect_list[j].port, ',');
					while (tmp) {
						++ tmp;
						tmp = strchr(tmp, ',');
						white_rule.connect.outbound.connect_num ++;
					}
				}
			}
		}
	}
	if (white_rule.connect.inbound.connect_num) {
		index = 0;
		net_rule.enable = TURNON;
		white_rule.enable = TURNON;
		white_rule.connect.inbound.enable = TURNON;
		white_rule.connect.inbound.connect_list = (PRULE_CONNECT_LIST)calloc(sizeof(RULE_CONNECT_LIST), white_rule.connect.inbound.connect_num);
		if (white_rule.connect.inbound.connect_list) {
			for (i=0; i<rule_white_global.access_control_num; i++) {
				for (j=0; j<rule_white_global.access_control[i].connect_num; j++) {
					if (strncmp(rule_white_global.access_control[i].connect_list[j].direction, "in", 2) == 0) {
						char port_str[4096] = {0};
						char *port_p = port_str;
						snprintf(port_str, sizeof(port_str), "%s", rule_white_global.access_control[i].connect_list[j].port);
						char *tmp = strchr(port_str, ',');
						if (tmp) { /* 对于 88,99,999 端口字符串 */
							while (tmp) {
								*tmp = '\0';
								len = strlen(rule_white_global.access_control[i].connect_list[j].ip) + 1;
								white_rule.connect.inbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
								snprintf(white_rule.connect.inbound.connect_list[index].ip, len, "%s", 
													rule_white_global.access_control[i].connect_list[j].ip);
								len = 64;
								white_rule.connect.inbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
								snprintf(white_rule.connect.inbound.connect_list[index].protocol, len, "%s", 
													rule_white_global.access_control[i].connect_list[j].protocol);
								white_rule.connect.inbound.connect_list[index].fromport = atoi(port_p);
								white_rule.connect.inbound.connect_list[index].toport = atoi(port_p);
								index ++;
								
								++ tmp;
								port_p = tmp;
								tmp = strchr(tmp, ',');
							}
							len = strlen(rule_white_global.access_control[i].connect_list[j].ip) + 1;
							white_rule.connect.inbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
							snprintf(white_rule.connect.inbound.connect_list[index].ip, len, "%s", 
												rule_white_global.access_control[i].connect_list[j].ip);
							len = 64;
							white_rule.connect.inbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
							snprintf(white_rule.connect.inbound.connect_list[index].protocol, len, "%s", 
												rule_white_global.access_control[i].connect_list[j].protocol);
							white_rule.connect.inbound.connect_list[index].fromport = atoi(port_p);
							white_rule.connect.inbound.connect_list[index].toport = atoi(port_p);
							index ++;
						} else {
							parse_port(rule_white_global.access_control[i].connect_list[j].port, 
								   &white_rule.connect.inbound.connect_list[index].fromport,
								   &white_rule.connect.inbound.connect_list[index].toport);
							len = strlen(rule_white_global.access_control[i].connect_list[j].ip) + 1;
							white_rule.connect.inbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
							snprintf(white_rule.connect.inbound.connect_list[index].ip, len, "%s", 
											rule_white_global.access_control[i].connect_list[j].ip);
							len = 64;
							white_rule.connect.inbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
							snprintf(white_rule.connect.inbound.connect_list[index].protocol, len, "%s", 
											rule_white_global.access_control[i].connect_list[j].protocol);
							index ++;
							// INFO("inlen:%d--%s-%s\n", len, rule_white_global.access_control[i].connect_list[j].ip, rule_white_global.access_control[i].connect_list[j].protocol);
						}
					}
				}
			}
		}
	}
#if 0
	for (i=0; i<white_rule.connect.inbound.connect_num; i++) {
		INFO("whitein--%s--%s--%d-%d\n", white_rule.connect.inbound.connect_list[i].ip,
								white_rule.connect.inbound.connect_list[i].protocol,
								white_rule.connect.inbound.connect_list[i].fromport,
								white_rule.connect.inbound.connect_list[i].toport);
	}
#endif
	if (white_rule.connect.outbound.connect_num) {
		index = 0;
		net_rule.enable = TURNON;
		white_rule.enable = TURNON;
		white_rule.connect.outbound.enable = TURNON;
		white_rule.connect.outbound.connect_list = (PRULE_CONNECT_LIST)calloc(sizeof(RULE_CONNECT_LIST), white_rule.connect.outbound.connect_num);
		if (white_rule.connect.outbound.connect_list) {
			for (i=0; i<rule_white_global.access_control_num; i++) {
				for (j=0; j<rule_white_global.access_control[i].connect_num; j++) {
					if (strncmp(rule_white_global.access_control[i].connect_list[j].direction, "out", 3) == 0) {
						char port_str[4096] = {0};
						char *port_p = port_str;
						snprintf(port_str, sizeof(port_str), "%s", rule_white_global.access_control[i].connect_list[j].port);
						char *tmp = strchr(port_str, ',');
						if (tmp) { /* 对于 88,99,999 端口字符串 */
							while (tmp) {
								*tmp = '\0';
								len = strlen(rule_white_global.access_control[i].connect_list[j].ip) + 1;
								white_rule.connect.outbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
								snprintf(white_rule.connect.outbound.connect_list[index].ip, len, "%s", 
													rule_white_global.access_control[i].connect_list[j].ip);
								len = 64;
								white_rule.connect.outbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
								snprintf(white_rule.connect.outbound.connect_list[index].protocol, len, "%s", 
													rule_white_global.access_control[i].connect_list[j].protocol);
								white_rule.connect.outbound.connect_list[index].fromport = atoi(port_p);
								white_rule.connect.outbound.connect_list[index].toport = atoi(port_p);
								index ++;
								
								++ tmp;
								port_p = tmp;
								tmp = strchr(tmp, ',');
							}
							len = strlen(rule_white_global.access_control[i].connect_list[j].ip) + 1;
							white_rule.connect.outbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
							snprintf(white_rule.connect.outbound.connect_list[index].ip, len, "%s", 
												rule_white_global.access_control[i].connect_list[j].ip);
							len = 64;
							white_rule.connect.outbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
							snprintf(white_rule.connect.outbound.connect_list[index].protocol, len, "%s", 
												rule_white_global.access_control[i].connect_list[j].protocol);
							white_rule.connect.outbound.connect_list[index].fromport = atoi(port_p);
							white_rule.connect.outbound.connect_list[index].toport = atoi(port_p);
							index ++;
						} else {
							parse_port(rule_white_global.access_control[i].connect_list[j].port,
									&white_rule.connect.outbound.connect_list[index].fromport, 
									&white_rule.connect.outbound.connect_list[index].toport);
							len = strlen(rule_white_global.access_control[i].connect_list[j].ip) + 1;
							// INFO("outlen:%d--%s-%s\n", len, rule_white_global.access_control[i].connect_list[j].ip, rule_white_global.access_control[i].connect_list[j].protocol);
							white_rule.connect.outbound.connect_list[index].ip = (char*)calloc(len, sizeof(char));
							snprintf(white_rule.connect.outbound.connect_list[index].ip, len, "%s", 
												rule_white_global.access_control[i].connect_list[j].ip);
							len = 64;
							white_rule.connect.outbound.connect_list[index].protocol = (char*)calloc(len, sizeof(char));
							snprintf(white_rule.connect.outbound.connect_list[index].protocol, len, "%s", 
												rule_white_global.access_control[i].connect_list[j].protocol);
							index ++;
						}
					}
				}
			}
		}
	}
#if 0
	for (i=0; i<white_rule.connect.outbound.connect_num; i++) {
		INFO("whiteout--%s--%s--%d-%d\n", white_rule.connect.outbound.connect_list[i].ip,
								white_rule.connect.outbound.connect_list[i].protocol,
								white_rule.connect.outbound.connect_list[i].fromport,
								white_rule.connect.outbound.connect_list[i].toport);
	}
#endif
	pthread_rwlock_unlock(&rule_white_global.lock);
	///////////////////////////////////////////////////
}

static void trust_conf(void)
{
	int i = 0;
	int j = 0;
	int len = 0;
	int index = 0;
	int count = 0;

	/* 可信名单 */
	///////////////////////////////////////////////////
	///////////////////////////////////////////////////
	pthread_rwlock_wrlock(&rule_trust_global.lock);
	/* 域名可信名单 */
	if (trust_rule.domain.domain_num) {
		for (i=0; i<trust_rule.domain.domain_num; i++) {
			if (trust_rule.domain.domain_list[i].domain) {
				free(trust_rule.domain.domain_list[i].domain);
				trust_rule.domain.domain_list[i].domain = NULL;
			}
		}
		free(trust_rule.domain.domain_list);
		trust_rule.domain.domain_list = NULL;
		trust_rule.domain.domain_num = 0;
	}
	for (i=0; i<rule_trust_global.domain_num; i++) {
		count += rule_trust_global.domain[i].domain_num;
	}

	trust_dns_list_size = 0;
	trust_rule.domain.domain_num = count;
	if (trust_rule.domain.domain_num) {
		net_rule.domain.enable = TURNON;
		trust_rule.enable = TURNON;
		trust_rule.domain.enable = TURNON;
		index = 0;
		trust_rule.domain.domain_list = (PRULE_DOMAIN_LIST)malloc(sizeof(PRULE_DOMAIN_LIST)*count);
		if (trust_rule.domain.domain_list) {
			for (i=0; i<rule_trust_global.domain_num; i++) {
				for (j=0; j<rule_trust_global.domain[i].domain_num; j++) {
					len = strlen(rule_trust_global.domain[i].domain_list[j].list) + 1;
					trust_dns_list_size += len;
					trust_rule.domain.domain_list[index].domain = (char*)calloc(len, sizeof(char));
					snprintf(trust_rule.domain.domain_list[index].domain, len, "%s", rule_trust_global.domain[i].domain_list[j].list);
					// INFO("trust-%d----%s\n", i, trust_rule.domain.domain_list[i].domain);
					index ++;
				}
			}
		} else {
			trust_rule.domain.domain_num = 0;
			trust_rule.domain.domain_list = NULL;
		}
	} else {
		trust_rule.domain.domain_num = 0;
		trust_rule.domain.domain_list = NULL;
	}
	#if 0
	for (i=0; i<count; i++) {
		INFO("trust--count:%d====%s\n", count, trust_rule.domain.domain_list[i].domain);
	}
	#endif
	/* IP可信名单 */
	count = trust_rule.network.honey_num + trust_rule.network.honey_num_v6;
	if (count) {
		free(trust_rule.network.honey_ip_list);
		trust_rule.network.honey_ip_list = NULL;
		trust_rule.network.honey_num = 0;
		trust_rule.network.honey_num_v6 = 0;
	}
	count = 0;
	int ipv4_count = 0;
	int ipv6_count = 0;
	/* 计算总的IP数量 */
	for (i=0; i<rule_trust_global.ip_num; i++) {
		for (j=0; j<rule_trust_global.ip[i].ip_num; j++) {
			if (strchr(rule_trust_global.ip[i].ip_list[j].list, ':')) { /* 以字符串中有无:区分IPv4与IPv6 */
				ipv6_count ++;
			} else {
				ipv4_count ++;
			}
		}
		count += rule_trust_global.ip[i].ip_num;
	}

	ipv6_count = ipv4_count;

	if (count) {
		trust_rule.enable = TURNON;
		trust_rule.network.enable = TURNON;
		index = 0;
		trust_rule.network.honey_ip_list = (PRULE_IP_LIST)malloc(sizeof(RULE_IP_LIST)*count);
		if (trust_rule.network.honey_ip_list) {
			for (i=0; i<rule_trust_global.ip_num; i++) {
				for (j=0; j<rule_trust_global.ip[i].ip_num; j++) {
					if (strchr(rule_trust_global.ip[i].ip_list[j].list, ':')) { /* 以字符串中有无:区分IPv4与IPv6 */
						struct in6_addr result;
						if (inet_pton(AF_INET6, rule_trust_global.ip[i].ip_list[j].list, &result) != 1) {
							MON_ERROR("Invalid IPv6:%s\n", rule_trust_global.ip[i].ip_list[j].list);
							continue;
						}
						// snprintf(trust_rule.network.honey_ip_list[ipv6_count].ip, sizeof(trust_rule.network.honey_ip_list[ipv6_count].ip), "%s", result.s6_addr);
						memcpy (trust_rule.network.honey_ip_list[ipv6_count].ip, &result, sizeof(struct in6_addr));
						// INFO("-ipv6-trust--i:%d-%s\n", ipv6_count, rule_trust_global.ip[i].ip_list[j].list);
						ipv6_count ++;
					} else {
						snprintf(trust_rule.network.honey_ip_list[index].ip, 
										sizeof(trust_rule.network.honey_ip_list[index].ip), 
										"%s", rule_trust_global.ip[i].ip_list[j].list);
						// INFO("-ipv4-trust--i:%d-%s\n", index, rule_trust_global.ip[i].ip_list[j].list);
						int tmp_num = 0;
						trust_rule.network.honey_ip_list[index].type = 0;
						for (; tmp_num<rule_trust_global.ip[i].event_num; tmp_num++) {
							// INFO("-%d-%s---\n", rule_trust_global.ip[i].event_flags, rule_trust_global.ip[i].event_names[tmp_num].list);
							if (strncmp(rule_trust_global.ip[i].event_names[tmp_num].list, "PortScan", 8) == 0) {
								trust_rule.network.honey_ip_list[index].type |= NET_MPORT_SCAN;
							}
							if (strncmp(rule_trust_global.ip[i].event_names[tmp_num].list, "HoneyPort", 9) == 0) {
								trust_rule.network.honey_ip_list[index].type |= NET_MHONEY_PORT;
							}
						}

						index ++;
					}
					// INFO("-ipv-trust-%s\n", rule_trust_global.ip[i].ip_list[j].list);
				}
			}
			trust_rule.network.honey_num = ipv4_count;
			trust_rule.network.honey_num_v6 = ipv6_count - ipv4_count;
		} else {
			trust_rule.network.honey_num = 0;
			trust_rule.network.honey_num_v6 = 0;
		}
	} else {
		trust_rule.network.honey_num = 0;
		trust_rule.network.honey_num_v6 = 0;
	}
	#if 0
	for (i=0; i<count; i++) {
		INFO("trust--count:%d====%s\n", count, trust_rule.network.honey_ip_list[i].ip);
	}
	INFO("ipv6--%d----ipv4--%d\n", trust_rule.network.honey_num_v6, trust_rule.network.honey_num);
	#endif
	pthread_rwlock_unlock(&rule_trust_global.lock);
	///////////////////////////////////////////////////
}

static void filter_conf(void)
{
	int i = 0;
	int j = 0;
	int len = 0;
	int index = 0;
	int count = 0;

	/* 过滤名单 */
	///////////////////////////////////////////////////
	///////////////////////////////////////////////////
	pthread_rwlock_wrlock(&rule_filter_global.lock);
	if (filter_rule.domain.domain_num) {
		for (i=0; i<filter_rule.domain.domain_num; i++) {
			if (filter_rule.domain.domain_list[i].domain) {
				free(filter_rule.domain.domain_list[i].domain);
				filter_rule.domain.domain_list[i].domain = NULL;
			}
		}
		free(filter_rule.domain.domain_list);
		filter_rule.domain.domain_list = NULL;
		filter_rule.domain.domain_num = 0;
	}

	for (i=0; i<rule_filter_global.domain_num; i++) {
		count += rule_filter_global.domain[i].domain_num;
	}

	filter_dns_list_size = 0;
	filter_rule.domain.domain_num = count;
	if (filter_rule.domain.domain_num) {
		net_rule.domain.enable = TURNON;
		filter_rule.enable = TURNON;
		filter_rule.domain.enable = TURNON;
		index = 0;
		filter_rule.domain.domain_list = (PRULE_DOMAIN_LIST)malloc(sizeof(PRULE_DOMAIN_LIST)*count);
		if (filter_rule.domain.domain_list) {
			for (i=0; i<rule_filter_global.domain_num; i++) {
				for (j=0; j<rule_filter_global.domain[i].domain_num; j++) {
					len = strlen(rule_filter_global.domain[i].domain_list[j].list) + 1;
					filter_dns_list_size += len;
					filter_rule.domain.domain_list[index].domain = (char*)calloc(len, sizeof(char));
					snprintf(filter_rule.domain.domain_list[index].domain, len, "%s", rule_filter_global.domain[i].domain_list[j].list);
					index ++;
					// INFO("-%d----%s\n", i, rule_filter_global.domain[i].domain_list->list);
				}
			}
		} else {
			filter_rule.domain.domain_num = 0;
			filter_rule.domain.domain_list = NULL;
		}
	} else {
		filter_rule.domain.domain_num = 0;
		filter_rule.domain.domain_list = NULL;
	}
	#if 0
	for (i=0; i<count; i++) {
		INFO("filter--count:%d====%s\n", count, filter_rule.domain.domain_list[i].domain);
	}
	#endif
	pthread_rwlock_unlock(&rule_filter_global.lock);
	///////////////////////////////////////////////////
}
/////////////////////////////////////////////////////////////////////
///////////////////////    规则配置         //////////////////////////
/////////////////////////////////////////////////////////////////////
void update_kernel_net_rules(void);
/* 发送网络规则配置到内核模块 */
void update_kernel_net_all_rules(void)
{
	/* 黑名单 */
	black_conf();
	/* 白名单 */
	white_conf();
	/* 可信名单 */
	trust_conf();
	/* 过滤名单 */
	filter_conf();

	update_kernel_net_rules();
}

/////////////////////////////////////////////////////////////////////
///////////////////////    策略配置         //////////////////////////
/////////////////////////////////////////////////////////////////////
/* 发送网络策略配置到内核模块 */
void update_kernel_net_policy(void)
{
	int i = 0;

	pthread_rwlock_rdlock(&protect_policy_global.lock);
	/* 访问恶意域名 */
	if (protect_policy_global.network.domain.enable) {
		net_rule.domain.enable = TURNON;
		black_rule.enable = TURNON;
		black_rule.domain.enable = TURNON;
	} else {
		net_rule.domain.enable = TURNOFF;
		black_rule.enable = TURNOFF;
		black_rule.domain.enable = TURNOFF;
	}
	/* 域名日志采集开，默认自定义域名黑名单开 */
	if (protect_policy_global.logcollector.dnsquery_enable) {
		net_rule.domain.enable = TURNON;
		black_rule.domain.enable = TURNOFF;
	}
	/* 端口扫描 */
	if (protect_policy_global.network.port.enable) {
		net_rule.port_scan.enable = TURNON;
	} else {
		net_rule.port_scan.enable = TURNOFF;
	}
	if (protect_policy_global.network.port.terminate) {
		net_rule.port_scan.locking = TURNON;
	} else {
		net_rule.port_scan.locking = TURNOFF;
	}
	/* 敏感端口 */
	if (net_rule.honey.ports) {
		free(net_rule.honey.ports);
		net_rule.honey.ports = NULL;
	}
	if (protect_policy_global.network.sensitive_port.enable) {
		net_rule.honey.enable = TURNON;
	} else {
		net_rule.honey.enable = TURNOFF;
	}
	if (protect_policy_global.network.sensitive_port.terminate) {
		net_rule.honey.locking = TURNON;
	} else {
		net_rule.honey.locking = TURNOFF;
	}
	net_rule.honey.num = protect_policy_global.network.sensitive_port.list_num;
	int size = net_rule.honey.num * sizeof(int);
	if (size > 0) {
		net_rule.honey.enable = TURNON;
		net_rule.honey.ports = malloc(size); /* 敏感端口内存申请 */
		if (net_rule.honey.ports) {
			memset(net_rule.honey.ports, 0x00, size);
			for (i=0; i<net_rule.honey.num; i++) {
				net_rule.honey.ports[i].port = protect_policy_global.network.sensitive_port.list[i].port;
			}
		}
	} 
	/* 网络行为采集 */
	net_rule.connect.enable = protect_policy_global.logcollector.network_enable;
	pthread_rwlock_unlock(&protect_policy_global.lock);

	// 默认开启，否则当策略、黑/白/过滤名单都不配置时，主机隔离不能生效
	net_rule.enable = TURNON;

	update_kernel_net_all_rules();

	return;
}

//TODO 支持ipv6
static int parse_ip(char *ipstr, struct sniper_ip *ip, char *desc)
{
	int ret = 0, ip0 = 0, ip1 = 0, ip2 = 0, ip3 = 0;

	if (!ipstr || !ip || !desc) {
		return -1;
	}

	/* sscanf会自动忽略ipstr开头结尾的空格，不需要自己处理 */
	/*
	 * 不能直接sscanf(ipstr, "%d.%d.%d.%d", &ip->ip[0], ...
	 * ip->ip[x]是char类型，按整型数处理会越界
	 * 如，update_kernel_net_server()中如下声明变量
	 *        unsigned short port = 0;
	 *        struct sniper_ip tmpip = {0};
	 * port = 443;
	 * parse_ip(ipstr, &tmpip, "server ip")之后，port的值就被置0了
	 */
	ret = sscanf(ipstr, "%d.%d.%d.%d", &ip0, &ip1, &ip2, &ip3);
	if (ret != 4 ||
	    ip0 < 0 || ip0 > 255 || ip1 < 0 || ip1 > 255 ||
	    ip2 < 0 || ip2 > 255 || ip3 < 0 || ip3 > 255) {
		MON_ERROR("%s: bad ip %s\n", desc, ipstr);
		return -1;
	}

	ip->ip[0] = ip0;
	ip->ip[1] = ip1;
	ip->ip[2] = ip2;
	ip->ip[3] = ip3;
	return 0;
}

/* 获得ip段的有效位 */
static int get_ip_segment_bit(unsigned char number)
{
	unsigned char tmp = 0;
	int i = 0, count = 8;
	int result = 0, flag = 1;

	/* 
	 * ip段用8位二进制表示, 从左往右数到最后一个1的位数均表示有效位
	 * 从右往左依次或上1, 直到结果与原值相同则退出比较，得到有效位的个数
	 * 例如:0b1110 0000有效位为3, 0b1111 1110有效位为7
	 */
	tmp = number;
	for (i = 1; i <= 8; i++) {
		result = tmp|flag;
		if (result == tmp) {
			break;
		}
		count--;
		tmp = number>>i;
	}

	return count;
}

/* 将ip形式的子网掩码转换成10进制的形式返回 */
static int mask_ip_to_dec(struct sniper_ip *ip) 
{
	int dec = 0, i = 0;
	int count = 0; 

	/* 
	 * 从右往左，计算ip段的有效位
	 * 当某个ip段的有效位不为0时，说明左边的所有ip段的有效位均为8
	 * 例如:255.255.0.0有效位为16, 255.255.192.0有效位为18
	 */
	for (i = 3; i >= 0; i--) {
		count = get_ip_segment_bit(ip->ip[i]);
		if (count != 0) {
			break;
		}
	}
	dec = (i * 8) + count;

	return dec;
}

static int parse_iprange(char *ipstr, struct sniper_iprange *ipr, char *desc)
{
	int i = 0, j = 0, ret = 0;
	int masktype = 0, maskiptype = 0, maskdectype = 0, rangetype = 0;
	int dotnum = 0;
	int ipmask = 0;
	char str[S_IPLEN] = {0};

	/* 消除ip字符串中的空格 */
	for (i = 0; i < S_IPLEN; i++) {
		if (ipstr[i] == 0) {
			break;
		}
		if (ipstr[i] != ' ') {
			str[j] = ipstr[i];
			j++;

			if (ipstr[i] == '/') {
				masktype = 1;
			} else if (ipstr[i] == '-') {
				rangetype = 1;
			} else if (ipstr[i] == '.') {
				if (masktype == 1) {
					dotnum++;
				}
			}
		}
	}

	if (dotnum == 3) {
		/* x.x.x.x/y.y.y.y */
		maskiptype = 1;
	} else if (dotnum == 0){
		/* x.x.x.x/z */
		maskdectype = 1;
	} else {
		return -1;
	}

	memset(ipr, 0, sizeof(struct sniper_iprange));
	if (masktype) {
		/* 
		 * 子网掩码为10进制形式表示时，借用toip.ip[1]存放sniper_ipmask值
		 * 因为sniper_ipcmp中比较ip[0]时就会退出，因此不需要对toip.ip中数值做处理
		 */
		if (maskdectype == 1) {
			ret = sscanf(str, "%d.%d.%d.%d/%d",
				(int *)&ipr->fromip.ip[0], (int *)&ipr->fromip.ip[1],
				(int *)&ipr->fromip.ip[2], (int *)&ipr->fromip.ip[3],
				(int *)&ipr->sniper_ipmask);
			if (ret != 5) {
				MON_ERROR("%s: bad iprange %s\n", desc, ipstr);
				ipr->fromip.ip[0] = SNIPER_BADIP;
				return -1;
			}
		}

		/* 
		 * 子网掩码为ip形式表示时，借用toip.ip存放4段地址
		 * 转换成十进制形式后，再将toip.ip情况，借用toip.ip[1]存放sniper_ipmask值
		 */
		if (maskiptype == 1) {
			ret = sscanf(str, "%d.%d.%d.%d/%d.%d.%d.%d",
				(int *)&ipr->fromip.ip[0], (int *)&ipr->fromip.ip[1],
				(int *)&ipr->fromip.ip[2], (int *)&ipr->fromip.ip[3],
				(int *)&ipr->toip.ip[0], (int *)&ipr->toip.ip[1],
				(int *)&ipr->toip.ip[2], (int *)&ipr->toip.ip[3]);
			if (ret != 8) {
				MON_ERROR("%s: bad iprange %s\n", desc, ipstr);
				ipr->fromip.ip[0] = SNIPER_BADIP;
				return -1;
			}

			/* 将ip形式的子网掩码转换成10进制的形式 */
			ipmask = mask_ip_to_dec(&ipr->toip);
			ipr->toip.ip[0] = 0;
			ipr->toip.ip[1] = 0;
			ipr->toip.ip[2] = 0;
			ipr->toip.ip[3] = 0;
			ipr->sniper_ipmask = ipmask;
		}

		/* 非网段单ip时，fromip > toip，两者交换 */
		if (ipr->toip.ip[0] && sniper_ipcmp(&ipr->fromip, &ipr->toip) > 0) {
			struct sniper_ip tmpip = {{0}};

			tmpip = ipr->toip;
			ipr->toip = ipr->fromip;
			ipr->fromip = tmpip;
		}
		return 0;
	}

	if (rangetype) {
		ret = sscanf(str, "%d.%d.%d.%d-%d.%d.%d.%d",
			(int *)&ipr->fromip.ip[0], (int *)&ipr->fromip.ip[1],
			(int *)&ipr->fromip.ip[2], (int *)&ipr->fromip.ip[3],
			(int *)&ipr->toip.ip[0], (int *)&ipr->toip.ip[1],
			(int *)&ipr->toip.ip[2], (int *)&ipr->toip.ip[3]);
		if (ret != 8) {
			MON_ERROR("%s: bad iprange %s\n", desc, ipstr);
			ipr->fromip.ip[0] = SNIPER_BADIP;
			return -1;
		}
		return 0;
	}

	ret = sscanf(str, "%d.%d.%d.%d",
		(int *)&ipr->fromip.ip[0], (int *)&ipr->fromip.ip[1],
		(int *)&ipr->fromip.ip[2], (int *)&ipr->fromip.ip[3]);
	if (ret != 4) {
		MON_ERROR("%s: bad ip %s\n", desc, ipstr);
		ipr->fromip.ip[0] = SNIPER_BADIP;
		return -1;
	}
	return 0;
}

static void update_kernel_net_ip(int msgtype, PRULE_IP_LIST ip_list, int count, char *desc)
{
	int i = 0;
	int size = sizeof(struct sniper_iprange) * count;
	struct sniper_iprange *ipr = NULL;

	ipr = malloc(size);
	if (!ipr) {
		MON_ERROR("update kernel %s fail, no memory!\n", desc);
		return;
	}
	memset(ipr, 0, size);

	for (i = 0; i < count; i++) {
		parse_iprange(ip_list[i].ip, &ipr[i], desc);
		ipr[i].type = ip_list[i].type;
	}

	if (send_data_to_kern(msgtype, (char *)ipr, size) < 0) {
		MON_ERROR("update kernel %s fail\n", desc);
	}

	free(ipr);
}
static void update_kernel_net_connection_filterip(void)
{
	update_kernel_net_ip(NLMSG_NET_CONNECTION_FILTERIP,
		filter_rule.network.connect_ip_list,
		filter_rule.network.connect_num,
		"connection filter ip");
}
static void update_kernel_net_lanip(void)
{
	update_kernel_net_ip(NLMSG_NET_LANIP,
		net_rule.internet_limit.ip_list,
		net_rule.internet_limit.num,
		"LAN ip");
}
static void update_kernel_net_honeyport_filterip(void)
{
	update_kernel_net_ip(NLMSG_NET_HONEYPORT_FILTERIP,
		filter_rule.network.honey_ip_list,
		filter_rule.network.honey_num,
		"honeyport filter ip");
}
static void update_kernel_net_honeyport_trustip(void)
{
	update_kernel_net_ip(NLMSG_NET_HONEYPORT_TRUSTIP,
		trust_rule.network.honey_ip_list,
		trust_rule.network.honey_num,
		"honeyport trust ip");
}
static void update_kernel_net_honeyport_trustipv6(void)
{
	int size = sizeof(struct in6_addr) * trust_rule.network.honey_num_v6;
	struct in6_addr *ipr = NULL;
	int i = 0;
	PRULE_IP_LIST ip = trust_rule.network.honey_ip_list+trust_rule.network.honey_num;

	ipr = malloc(size);
	if (!ipr) {
		MON_ERROR("update kernel %s fail, no memory!\n", "honeyport trust ipv6");
		return;
	}
	memset(ipr, 0, size);

	for (i=0; i<trust_rule.network.honey_num_v6; i++) {
		ipr[i] = *(struct in6_addr *)&ip[i];
	}
	if (send_data_to_kern(NLMSG_NET_HONEYPORT_TRUSTIPV6, (char *)ipr, size) < 0) {
		MON_ERROR("update kernel %s fail\n", "honeyport trust ipv6");
	}

	free(ipr);
}
/* 判断是否对外的服务端口 */
static int port_inuse(unsigned short port, char *file)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};

	fp = sniper_fopen(file, "r", NETWORK_GET);
	if (fp) {
		fgets(line, sizeof(line), fp);
		while (fgets(line, sizeof(line), fp)) {
			sockinfo_t info = {0};

			get_socket_info(line, &info);
			if (info.state == TCP_LISTEN &&
			    port == info.src_port &&
			    strncmp(info.src_ip, "127.", 4) != 0) {
				sniper_fclose(fp, NETWORK_GET);
				return 1;
			}
		}
		sniper_fclose(fp, NETWORK_GET);
	}

	return 0;
}

static unsigned short *get_realhoney(int size)
{
	int i = 0;
	unsigned short *port = NULL;

	port = malloc(size);
	if (!port) {
		MON_ERROR("update kernel honeyport fail, no memory!\n");
		return NULL;
	}
	memset(port, 0, size);

	for (i = 0; i < nrule.honeyport_count; i++) {
		port[i] = net_rule.honey.ports[i].port;

		/* 清除在使用的服务端口 */
		if (port_inuse(port[i], "/proc/net/tcp") ||
		    port_inuse(port[i], "/proc/net/tcp6")) {
			port[i] = 0;
		}
	}

	return port;
}

//TODO 要考虑udp端口吗
void update_kernel_net_honeyport(void)
{
	int size = nrule.honeyport_count * sizeof(int);
	unsigned short *port = NULL;

	port = get_realhoney(size);
	if (!port) {
		return;
	}

	if (send_data_to_kern(NLMSG_NET_HONEYPORT, (char *)port, size) < 0) {
		MON_ERROR("update kernel honeyport fail\n");
	}

	if (port) {
		free(port);
	}
}

/* 检查是否有nscd域名代理程序 */
static int has_nscd(char *proxy, pid_t *proxy_pid)
{
	int found = 0;
	DIR *procdirp = NULL;
	struct dirent *pident = NULL;
	char comm[S_COMMLEN] = {0};
	pid_t pid = 0;

	procdirp = sniper_opendir("/proc", PROCESS_GET);
	if (!procdirp) {
		MON_ERROR("get_dnsproxy fail, open /proc "
			"error: %s\n", strerror(errno));
		return found;
	}

	/* 遍历所有进程 */
	while ((pident = readdir(procdirp))) {
		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue;
		}

		pid = atoi(pident->d_name);
		if (pid <= 2) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue; //忽略内核线程
		}

		get_proc_comm(pid, comm);
		if (strcmp(comm, "nscd") == 0) {
			found = 1;
			*proxy_pid = pid;
			snprintf(proxy, S_COMMLEN, "%s", comm);
			break;
		}
	}
	sniper_closedir(procdirp, PROCESS_GET);

	return found;
}

/* 获取本地dns代理的程序名 */
static int get_dnsproxy(char *inostr, char *proxy, pid_t *proxy_pid)
{
	int found = 0;
	DIR *procdirp = NULL, *fddirp = NULL;
	struct dirent *pident = NULL, *fdent = NULL;
	char fddir[128] = {0}, fdpath[512] = {0};
	pid_t pid = 0;

	procdirp = sniper_opendir("/proc", PROCESS_GET);
	if (!procdirp) {
		MON_ERROR("get_dnsproxy fail, open /proc "
			"error: %s\n", strerror(errno));
		return found;
	}

	/* 遍历所有进程 */
	while ((pident = readdir(procdirp))) {
		if (pident->d_name[0] < '0' || pident->d_name[0] > '9') {
			continue;
		}

		pid = atoi(pident->d_name);
		if (pid <= 2) {
			continue;
		}
		if (is_kernel_thread(pid)) {
			continue; //忽略内核线程
		}

		snprintf(fddir, sizeof(fddir), "/proc/%d/fd", pid);
		fddirp = sniper_opendir(fddir, PROCESS_GET);
		if (!fddirp) {
			MON_ERROR("get_dnsproxy open %s error: %s\n",
				fddir, strerror(errno));
			continue;
		}

		/* 遍历进程的fd */
		while ((fdent = readdir(fddirp))) {
			char linkname[S_NAMELEN] = {0};

			if (fdent->d_name[0] < '0' || fdent->d_name[0] > '9') {
				continue;
			}

			snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd/%s", pid, fdent->d_name);
			/* readlink不加0结尾加，因此使用前必须清linkname，
			   否则上一次的值会干扰 */
			if (readlink(fdpath, linkname, sizeof(linkname)-1) <= 0) {
				MON_ERROR("get_dnsproxy readlink %s error: %s\n",
					fdpath, strerror(errno));
				continue;
			}
			if (strcmp(linkname, inostr) == 0) {
				found = 1;
				*proxy_pid = pid;
				get_proc_comm(pid, proxy);
				break;
			}
		}
		sniper_closedir(fddirp, PROCESS_GET);

		if (found) {
			break;
		}
	}
	sniper_closedir(procdirp, PROCESS_GET);

	return found;
}

/* 判断是否对外的服务端口 */
static int has_local_dnsproxy(char *file, char *proxy, pid_t *proxy_pid)
{
	int found = 0;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0}, inostr[S_NAMELEN] = {0};

	fp = sniper_fopen(file, "r", NETWORK_GET);
	if (fp) {
		fgets(line, sizeof(line), fp);
		while (fgets(line, sizeof(line), fp)) {
			sockinfo_t info = {0};

			get_socket_info(line, &info);
			if (info.src_port != 53 ||
			    strncmp(info.src_ip, "127.", 4) != 0) {
				continue;
			}

			snprintf(inostr, sizeof(inostr), "socket:[%lu]", info.inode);
			if (get_dnsproxy(inostr, proxy, proxy_pid)) {
				found = 1;
			}
			break;
		}
		sniper_fclose(fp, NETWORK_GET);
	}

	return found;
}
static int find_local_dnsproxy(char *proxy, pid_t *proxy_pid)
{
	if (has_local_dnsproxy("/proc/net/udp", proxy, proxy_pid) ||
	    has_local_dnsproxy("/proc/net/udp6", proxy, proxy_pid) ||
	    has_nscd(proxy, proxy_pid)) {
		return 1;
	}
	return 0;
}

static char *update_kernel_net_dns(int msgtype, PRULE_DOMAIN_LIST domain_list,
				   int count, int size,
				   char *old_rule, int old_size, char *desc)
{
	int i = 0, len = 0;
	char *rule = NULL, *ptr = NULL;
	struct rulefile_info rfinfo;

	rule = sniper_malloc(size, NETWORK_GET);
	if (!rule) {
		MON_ERROR("update kernel %s fail, no memory!\n", desc);
		return NULL;
	}

	ptr = rule;
	for (i = 0; i < count; i++) {
		len = strlen(domain_list[i].domain);
		strncpy(ptr, domain_list[i].domain, len);
		ptr += len + 1;
	}

	if (old_rule && old_size == size &&
	    memcmp(old_rule, rule, size) == 0) {
		sniper_free(rule, size, NETWORK_GET);
		printf("skip update %s, no change\n", desc);
		return NULL;
	}

	if (prepare_rulefile(rule, size, desc, &rfinfo) < 0) {
		sniper_free(rule, size, NETWORK_GET);
		MON_ERROR("skip update %s, prepare rulefile fail\n", desc);
		return NULL;
	}

	if (send_data_to_kern(msgtype, (char *)&rfinfo, sizeof(rfinfo)) < 0) {
		sniper_free(rule, size, NETWORK_GET);
		MON_ERROR("update kernel %s fail\n", desc);
		return NULL;
	}

	sniper_free(old_rule, old_size, NETWORK_GET);
	return rule;
}
static void update_kernel_net_dnsfilter(void)
{
	char *buf = NULL;

	if (filter_dns_list_size == 0) {
		sniper_free(filter_dns_mem, filter_dns_mem_size, NETWORK_GET);
		filter_dns_mem_size = 0;
		filter_dns_mem = NULL;
		return;
	}

	buf = update_kernel_net_dns(NLMSG_NET_DNSFILTER,
				filter_rule.domain.domain_list,
				filter_rule.domain.domain_num,
				filter_dns_list_size,
				filter_dns_mem,
				filter_dns_mem_size,
				"filter domain");
	if (buf) {
		filter_dns_mem = buf;
		filter_dns_mem_size = filter_dns_list_size;
	}
}
static void update_kernel_net_dnsblack(void)
{
	char *buf = NULL;

	if (black_dns_list_size == 0) {
		sniper_free(black_dns_mem, black_dns_mem_size, NETWORK_GET);
		black_dns_mem_size = 0;
		black_dns_mem = NULL;
		return;
	}

	buf = update_kernel_net_dns(NLMSG_NET_DNSBLACK,
				black_rule.domain.domain_list,
				black_rule.domain.domain_num,
				black_dns_list_size,
				black_dns_mem,
				black_dns_mem_size,
				"black domain");
	if (buf) {
		black_dns_mem = buf;
		black_dns_mem_size = black_dns_list_size;
	}
}

static void update_kernel_net_dnswhite(void)
{
	char *buf = NULL;

	if (white_dns_list_size == 0) {
		sniper_free(black_dns_mem, white_dns_mem_size, NETWORK_GET);
		white_dns_mem_size = 0;
		white_dns_mem = NULL;
		return;
	}

	buf = update_kernel_net_dns(NLMSG_NET_DNSWHITE,
				white_rule.domain.domain_list,
				white_rule.domain.domain_num,
				white_dns_list_size,
				white_dns_mem,
				white_dns_mem_size,
				"white domain");
	if (buf) {
		white_dns_mem = buf;
		white_dns_mem_size = white_dns_list_size;
	}
}
static void update_kernel_net_dnstrust(void)
{
	char *buf = NULL;

	if (trust_dns_list_size == 0) {
		sniper_free(black_dns_mem, trust_dns_mem_size, NETWORK_GET);
		trust_dns_mem_size = 0;
		trust_dns_mem = NULL;
		return;
	}

	buf = update_kernel_net_dns(NLMSG_NET_DNSTRUST,
				trust_rule.domain.domain_list,
				trust_rule.domain.domain_num,
				trust_dns_list_size,
				trust_dns_mem,
				trust_dns_mem_size,
				"trust domain");
	if (buf) {
		trust_dns_mem = buf;
		trust_dns_mem_size = trust_dns_list_size;
	}
}
/* 有黑白名单时更新内核里的名单。没有的话，内核自己会清理 */
static void update_kernel_net_blackwhite(int msgtype, RULE_CONNECT_BOUND *bound, char *desc)
{
	int i = 0, count = bound->connect_num;
	int size = sizeof(struct sniper_connrule) * count;
	struct sniper_connrule *rule = 0;
	PRULE_CONNECT_LIST connect_list = NULL;

	rule = sniper_malloc(size, NETWORK_GET);
	if (!rule) {
		MON_ERROR("update kernel %s fail, no memory %d!\n", desc, size);
		return;
	}

	for (i = 0; i < count; i++) {
		connect_list = &bound->connect_list[i];
		rule[i].fromport = connect_list->fromport;
		rule[i].toport = connect_list->toport;
		if (strstr(connect_list->protocol, "TCP") ||
		    strstr(connect_list->protocol, "tcp")) {
			rule[i].tcp = 1;
		}
		if (strstr(connect_list->protocol, "UDP") ||
		    strstr(connect_list->protocol, "udp")) {
			rule[i].udp = 1;
		}
		if (strstr(connect_list->protocol, "ICMP") ||
		    strstr(connect_list->protocol, "icmp")) {
			rule[i].icmp = 1;
		}
		parse_iprange(connect_list->ip, &rule[i].ipr, desc);
	}

	if (send_data_to_kern(msgtype, (char *)rule, size) < 0) {
		MON_ERROR("update kernel %s fail\n", desc);
	}

	sniper_free(rule, size, NETWORK_GET);
}
static void update_kernel_net_whitein(void)
{
	update_kernel_net_blackwhite(NLMSG_NET_WHITEIN,
		&white_rule.connect.inbound, "netin whitelist");
}
static void update_kernel_net_whiteout(void)
{
	update_kernel_net_blackwhite(NLMSG_NET_WHITEOUT,
		&white_rule.connect.outbound, "netout whitelist");
}
static void update_kernel_net_blackin(void)
{
	update_kernel_net_blackwhite(NLMSG_NET_BLACKIN,
		&black_rule.connect.inbound, "netin blacklist");
}
static void update_kernel_net_blackout(void)
{
	update_kernel_net_blackwhite(NLMSG_NET_BLACKOUT,
		&black_rule.connect.outbound, "netout blacklist");
}

/* 主机隔离开关 */
void update_kernel_net_host_quarantine(const int host_quarantine)
{
	if (host_quarantine == 1 || host_quarantine == 0) {
		int data = host_quarantine;
		// INFO("=%d=%d===%d\n", host_quarantine, data, sizeof(int));
		if (send_data_to_kern(NLMSG_NET_HOSTQUARANTINE,
				(char *)&data, sizeof(int)) < 0) {
			MON_ERROR("set kern_net_rules fail\n");
			return;
		}
	}

	return;
}

static int is_same_ip(struct sniper_ip *ip1, struct sniper_ip *ip2)
{
	if (ip1->ip[0] == ip2->ip[0] && ip1->ip[1] == ip2->ip[1] &&
	    ip1->ip[2] == ip2->ip[2] && ip1->ip[3] == ip2->ip[3]) {
		return 1;
	}
	return 0;
}

/*
 * 更新内核中的服务器ip列表
 * 服务器ip列表 = 去重(管控下发的服务器ip列表, 本地配置的服务器ip, 当前在用的服务器ip)
 * 排第一的服务器ip优先级最高
 */
void update_kernel_net_server(unsigned char *server_count)
{
	int i = 0, j = 0, n = 0, count = 0, size = 0, real_size = 0, repeat = 0;
	struct sniper_server *server = NULL;
	char *ip = NULL;
	unsigned short port = 0;
	struct sniper_ip tmpip = {{0}};

	count = conf_global.server_num;
	if (orig_servip[0]) {
		count++;
	}
	if (curr_servip[0]) {
		count++;
	}
	size = sizeof(struct sniper_server) * count;

	server = sniper_malloc(size, NETWORK_GET);
	if (!server) {
		MON_ERROR("update kernel servers ip fail, no memory!\n");
		return;
	}

	port = curr_servport ? curr_servport : orig_servport;

	/* 策略服务器IP列表 */
	n = 0;
	for (i = 0; i < conf_global.server_num; i++) {
		ip = conf_global.server_ip[i].list;

		if (parse_ip(ip, &tmpip, "server ip") < 0) {
			continue; //排除错误的ip
		}

		/* 取消重复的 */
		repeat = 0;
		for (j = 0; j < n; j++) {
			if (is_same_ip(&tmpip, &server[j].ip)) {
				repeat = 1;
				break;
			}
		}
		if (repeat) {
			continue;
		}

		server[n].ip = tmpip;
		server[n].port = port;
		server[n].wsport = ws_port ? ws_port : 8000;
		n++;
	}

	/* 加入本地配置的服务器ip */
	if (orig_servip[0] && parse_ip(orig_servip, &tmpip, "server ip") == 0) {
		/* 不重复才加入 */
		repeat = 0;
		for (j = 0; j < n; j++) {
			if (is_same_ip(&tmpip, &server[j].ip)) {
				server[j].port = orig_servport;
				repeat = 1;
				break;
			}
		}
		if (!repeat) {
			server[n].ip = tmpip;
			server[n].port = orig_servport;
			server[n].wsport = ws_port ? ws_port : 8000;
			n++;
		}
	}

	/* 加入当前正在使用的服务器ip */
	if (curr_servip[0] && parse_ip(curr_servip, &tmpip, "server ip") == 0) {
		/* 不重复才加入 */
		repeat = 0;
		for (j = 0; j < n; j++) {
			if (is_same_ip(&tmpip, &server[j].ip)) {
				server[j].port = curr_servport;
				server[j].active = 1; //指示这是当前正在用的服务器ip
				repeat = 1;
				break;
			}
		}
		if (!repeat) {
			server[n].ip = tmpip;
			server[n].port = curr_servport;
			server[n].wsport = ws_port ? ws_port : 8000;
			server[n].active = 1; //指示这是当前正在用的服务器ip
			n++;
		}
	}

	real_size = sizeof(struct sniper_server) * n; //n是真正的服务器ip个数
	if (send_data_to_kern(NLMSG_NET_SERVERIP, (char *)server, real_size) < 0) {
		MON_ERROR("update kernel servers ip fail\n");
	}

	sniper_free(server, size, NETWORK_GET);

	if (server_count) {
		*server_count = n;
	}
}

/* 关闭内核网络监控 */
void close_kernel_net_rules(void)
{
	int size = sizeof(struct kern_net_rules);
	struct kern_net_rules rule = {0};

	if (nrule.net_engine_on == 0) { //内核网络监控已关闭
		return;
	}

	if (send_data_to_kern(NLMSG_NET_RULES, (char *)&rule, size) < 0) {
		MON_ERROR("set kernel net rules off fail\n");
		return;
	}

	pthread_rwlock_wrlock(&protect_policy_global.lock);

	memset(&nrule, 0, size); //内核策略更新成功再清应用层策略
	//TODO 网络策略清空，有空间要释放吗

	pthread_rwlock_unlock(&protect_policy_global.lock);
}

void update_kernel_net_rules(void)
{
	int quarantine = 0;
	int nrule_size = sizeof(struct kern_net_rules);
	struct kern_net_rules new_nrule = {0};

	/*
	 * 2个使用场景都不需要加锁
	 * 1、策略线程更新策略后，调用本函数
	 * 2、本地调试模式(不带管控中心)，程序启动后自行设置进程策略
	 */

	//常用的dns代理有dnsmasq、bind(程序名named)、nscd
	//TODO 改到客户端启动遍历进程时检测，后面有新的dns代理通过listen hook检测
	//在初始化的时候清一下dns缓冲
	/* 进程监控阻断挖矿程序不可误阻断dnsproxy，所以这里总是取dnsproxy */
	new_nrule.local_dnsproxy = find_local_dnsproxy(new_nrule.dnsproxy, &new_nrule.dnsproxy_pid);

	if (net_rule.enable != TURNON) {
		/* 网络监控关闭，所有网络监控策略均空 */
		goto tellkern;
	}
	if (conf_global.licence_expire || client_disable == TURN_MY_ON) {
		goto tellkern;
	}

	new_nrule.net_engine_on = 1;

	if (net_rule.connect.enable == TURNON) {
		new_nrule.connection_watch = 1;
	}

	if (filter_rule.enable == TURNON &&
	    filter_rule.network.enable == TURNON) {
		new_nrule.connection_filterip_count = filter_rule.network.connect_num;
	}

	if (filter_rule.enable == TURNON &&
	    filter_rule.network.enable == TURNON) {
		new_nrule.sshlogin_filterip_count = filter_rule.network.login_num;
	}

	if (net_rule.internet_limit.enable == TURNON) {
		new_nrule.internet_watch = 1;
		new_nrule.internet_reject = 1;
		new_nrule.lanip_count = net_rule.internet_limit.num;
	}

	if (net_rule.honey.enable == TURNON && net_rule.honey.num) { /* 开端口诱捕 */
		/* 下面更新内核诱捕端口列表时去除服务端口 */
		new_nrule.honeyport_count = net_rule.honey.num;
		pthread_rwlock_rdlock(&protect_policy_global.lock);
		new_nrule.honey_lockip_seconds = protect_policy_global.network.sensitive_port.locking_time;
		pthread_rwlock_unlock(&protect_policy_global.lock);

		if (net_rule.honey.locking == TURNON) {
			new_nrule.honeyport_lockip = 1;
			new_nrule.honeyport_reject = 1;
		}

		if (filter_rule.enable == TURNON &&
		    filter_rule.network.enable == TURNON) {
			new_nrule.honeyport_filterip_count = filter_rule.network.honey_num;
		}
	}
	if (net_rule.port_scan.enable == TURNON) { /* 开端口扫描 */
		pthread_rwlock_rdlock(&protect_policy_global.lock);
		new_nrule.portscan_lock_time = protect_policy_global.network.port.locking_time;
		new_nrule.portscan_max = protect_policy_global.network.port.count;
		new_nrule.portscan_time = protect_policy_global.network.port.request_period;
		pthread_rwlock_unlock(&protect_policy_global.lock);
		if (net_rule.port_scan.locking == TURNON) {
			new_nrule.port_scan_lockip = 1;
		}
	}

	if (trust_rule.enable == TURNON &&
		trust_rule.network.enable == TURNON) {
		new_nrule.honeyport_trustip_count = trust_rule.network.honey_num;
		new_nrule.honeyport_trustipv6_count = trust_rule.network.honey_num_v6;
	}

	if (net_rule.domain.enable == TURNON) {
		new_nrule.dns_watch = 1;
		new_nrule.dnsblack_count = black_rule.domain.domain_num;

		if (filter_rule.enable == TURNON &&
		    filter_rule.domain.enable == TURNON) {
			new_nrule.dnsfilter_count = filter_rule.domain.domain_num;
		}

		if (black_rule.enable == TURNON &&
		    black_rule.domain.enable == TURNON) {
			/* 恶意域名阻断 */
			if (protect_policy_global.network.domain.terminate) {
				new_nrule.dns_reject = 1;
			} else {
				new_nrule.dns_reject = 0;
			}
		}
		if (white_rule.enable == TURNON && 
			white_rule.domain.enable == TURNON) {
			new_nrule.dnswhite_count = white_rule.domain.domain_num;
		}
		if (trust_rule.enable == TURNON &&
			trust_rule.domain.enable == TURNON) {
			new_nrule.dnstrust_count = trust_rule.domain.domain_num;
		}
	}

	if (black_rule.enable == TURNON &&
	    black_rule.connect.inbound.enable == TURNON) {
		new_nrule.blackin_count = black_rule.connect.inbound.connect_num;
		new_nrule.blackwhite_reject = 1;
	}
	if (black_rule.enable == TURNON &&
	    black_rule.connect.outbound.enable == TURNON) {
		new_nrule.blackout_count = black_rule.connect.outbound.connect_num;
		new_nrule.blackwhite_reject = 1;
	}
	if (white_rule.enable == TURNON &&
	    white_rule.connect.inbound.enable == TURNON) {
		new_nrule.whitein_count = white_rule.connect.inbound.connect_num;
		new_nrule.blackwhite_reject = 1;
	}
	if (white_rule.enable == TURNON &&
	    white_rule.connect.outbound.enable == TURNON) {
		new_nrule.whiteout_count = white_rule.connect.outbound.connect_num;
		new_nrule.blackwhite_reject = 1;
	}

	/* 如果是运维策略，关闭所有防御 */
	/* 学习策略可以启用防御的。有专门的学习策略 */
	if (current_learning_mode == MODE_OPEN ||
	    current_operation_mode == MODE_OPEN) {
		new_nrule.dns_reject = 0;
		new_nrule.internet_reject = 0;
		new_nrule.honeyport_reject = 0;
		new_nrule.blackwhite_reject = 0;

		new_nrule.honeyport_lockip = 0;
	}

tellkern:
	/* update_kernel_net_server()里取去重后的server_count */
	update_kernel_net_server(&new_nrule.server_count);
	if (new_nrule.server_count) {
		localmode = 0;
	}

	if (memcmp(&new_nrule, &nrule, nrule_size) != 0) {
		if (send_data_to_kern(NLMSG_NET_RULES, (char *)&new_nrule, nrule_size) < 0) {
			MON_ERROR("set kern_net_rules fail\n");
			return;
		} else {
			nrule = new_nrule;
		}
	}
	if (!new_nrule.net_engine_on) {
		return;
	}

	if (new_nrule.connection_filterip_count) {
		update_kernel_net_connection_filterip();
	}

	if (new_nrule.lanip_count) {
		update_kernel_net_lanip();
	}

	if (new_nrule.honeyport_count) {
		update_kernel_net_honeyport();
	}

	if (new_nrule.honeyport_filterip_count) {
		update_kernel_net_honeyport_filterip();
	}

	if (new_nrule.honeyport_trustip_count) {
		update_kernel_net_honeyport_trustip();
	}

	if (new_nrule.honeyport_trustipv6_count) {
		update_kernel_net_honeyport_trustipv6();
	}

	if (new_nrule.dnsfilter_count) {
		update_kernel_net_dnsfilter();
	}

	if (new_nrule.dnsblack_count) {
		update_kernel_net_dnsblack();
	}

	if (new_nrule.dnswhite_count) {
		update_kernel_net_dnswhite();
	}

	if (new_nrule.dnstrust_count) {
		update_kernel_net_dnstrust();
	}

	if (new_nrule.whitein_count) {
		update_kernel_net_whitein();
	}
	if (new_nrule.whiteout_count) {
		update_kernel_net_whiteout();
	}
	if (new_nrule.blackin_count) {
		update_kernel_net_blackin();
	}
	if (new_nrule.blackout_count) {
		update_kernel_net_blackout();
	}

	quarantine = qr_status_global;  // 隔离策略
	if (client_mode_global == LEARNING_MODE) { // 学习模式不隔离
		quarantine = 0;
	}

	if (quarantine == 1) { // 隔离
		INFO("Host quarantined\n");
		update_kernel_net_host_quarantine(1);
	} else if (quarantine == 0) { // 取消隔离
		DBG2(DBGFLAG_POLICY, "Not quarantine host\n");
		update_kernel_net_host_quarantine(0);
	}
}

int net_connect_status(void)
{
	int status = 0;
	
	pthread_rwlock_rdlock(&protect_policy_global.lock);
	status = protect_policy_global.logcollector.network_enable;
	pthread_rwlock_unlock(&protect_policy_global.lock);

	return status;
}

/* 拆分ip每个段的数字, 成功返回0，失败返回-1 */
static int split_ip(char *ipstr, struct sniper_ip *ip)
{
	int i = 0, j = 0, ret = 0;
	char str[S_IPLEN] = {0};

	/* 消除ip字符串中的空格 */
	for (i = 0; i < S_IPLEN; i++) {
		if (ipstr[i] == 0) {
			break;
		}
		if (ipstr[i] != ' ') {
			str[j] = ipstr[i];
			j++;
		}
	}

	ret = sscanf(str, "%d.%d.%d.%d",
		(int *)&ip->ip[0], (int *)&ip->ip[1],
		(int *)&ip->ip[2], (int *)&ip->ip[3]);
	if (ret != 4) {
		MON_ERROR("split bad ip %s\n", ipstr);
		return -1;
	}
	return 0;
}

/* 检查match_ip是否在rule_ip范围之内，是返回1，否返回0 */
int check_ip_is_match(char *match_ip, char *rule_ip)
{
	int ret = 0;
	struct sniper_ip ip = {{0}}; 
	struct sniper_iprange rule_ipr = {{{0}}}; 

	ret = split_ip(match_ip, &ip);
	if (ret < 0) {
		return 0;
	}

	ret = parse_iprange(rule_ip, &rule_ipr, "check ip match"); 
	if (ret < 0) {
		return 0;
	}

	ret = ip_inrange(&ip, &rule_ipr);
	return ret;
}
