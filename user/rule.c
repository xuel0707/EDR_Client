#include "header.h"
#include "cJSON.h"

int black_ip_switch = 0;
int black_domain_switch = 0;
int black_user_switch = 0;
int black_access_in_switch = 0;
int black_access_out_switch = 0;

RULE_TRUST rule_trust_global = {0};
RULE_FILTER rule_filter_global = {0};
RULE_BLACK rule_black_global = {0};
RULE_WHITE rule_white_global = {0};
RULE_GLOBAL rule_global_global = {0};

RULE_TRUST old_rule_trust_global = {0};
RULE_FILTER old_rule_filter_global = {0};
RULE_BLACK old_rule_black_global = {0};
RULE_WHITE old_rule_white_global = {0};
RULE_GLOBAL old_rule_global_global = {0};

pthread_mutex_t rule_update_lock;

struct event_type_list {
	char name[32];
	int flag;
} event_type_list[] = {
	{ "DetectedByUsers",		EVENT_DetectedByUsers		}, //可疑木马
	{ "ReflectiveLoadingAttack",	EVENT_ReflectiveLoadingAttack	}, //内存攻击
	{ "ScriptBasedAttack",		EVENT_ScriptBasedAttack		}, //脚本攻击
	{ "ExsitingMalware",		EVENT_ExsitingMalware		}, //驻留病毒
	{ "DownloadExecution",		EVENT_DownloadExecution		}, //恶意程序
	{ "Mining",			EVENT_Mining			}, //恶意挖矿
	{ "Ransomeware",		EVENT_Ransomeware		}, //勒索软件
	{ "PrivilegeEscalation",	EVENT_PrivilegeEscalation	}, //非法提权
	{ "Webshell",			EVENT_Chopper			}, //中国菜刀命令执行
	{ "Tunnel",			EVENT_Tunnel			}, //隧道搭建
	{ "FakeSystemProcess",		EVENT_FakeSystemProcess		}, //伪造系统进程运行
	{ "SensitiveProgram",		EVENT_SensitiveProgram		}, //可疑命令执行
	{ "DangerousCommand",		EVENT_SensitiveProgram		}, //可疑命令执行
	{ "ServiceProcess",		EVENT_ServiceProcess		}, //对外服务进程异常执行
	{ "MBR",			EVENT_MBRAttack			}, //MBR防护
	{ "ReverseShell",		EVENT_ReverseShell		}, //反弹shell
	{ "Powershell",			EVENT_Powershell		}, //powershell
	{ "CommonProcess",		EVENT_CommonProcess		}, //一般进程
	{ "SensitiveFile",		EVENT_SensitiveFile		}, //敏感文件操作
	{ "PortScan",			EVENT_PortScan			}, //端口扫描超限
	{ "HoneyPort",			EVENT_HoneyPort			}, //敏感端口扫描
	{ "RemoteLogin",		EVENT_RemoteLogin		}, //远程登录
	{ "RequestMaliciousDomain",	EVENT_RequestMaliciousDomain	}, //访问恶意域名
	{ "DNSQuery",			EVENT_DNSQuery			}, //域名查询
	{ "LocalLogin",			EVENT_LocalLogin		}, //本地用户登录
	{ "RiskCommand",		EVENT_RiskCommand		}, //危险命令执行
	{ "AbnormalProcess",		EVENT_AbnormalProcess		}, //异常程序执行
	{ "ExecutableFiles",		EVENT_ExecutableFiles		}, //可执行文件识别
	{ "ScriptFiles",		EVENT_ScriptFiles		}, //脚本文件识别
	{ "IllegalScriptFiles",		EVENT_IllegalScriptFiles	}, //非法脚本识别
	{ "Webshell_detect",		EVENT_Webshell_detect		}, //webshell防护
	{ "AntivirusProtection",	EVENT_AntivirusProtection	}, //病毒防护
	{ "", 0}
};

/* 获取事件标志 */
static int event2flag(char *event_name)
{
	int i = 0;

	if (event_name == NULL) {
		return 0;
	}

	while (event_type_list[i].name[0]) {
		if (strcmp(event_name, event_type_list[i].name) == 0) {
			return event_type_list[i].flag;
		}
		i++;
	}
	return 0;
}

static void update_kernel_rule(void)
{

	update_kernel_process_rules();
	update_kernel_net_policy();
	update_kernel_file_policy();

}

void dump_rule(void)
{
	int i = 0, j = 0, k = 0;
	int num = 0, count = 0;
	FILE *fp = NULL;
	FILE *fp_en = NULL;

        fp = sniper_fopen(RULE_INFO_FILE, "w+", OTHER_GET);
        if (fp == NULL) {
                MON_ERROR("Update conf info to file failed\n");
                return;
        }

        fp_en = sniper_fopen(RULE_INFO_FILE_EN, "w+", OTHER_GET);
        if (fp_en == NULL) {
                MON_ERROR("Update conf info to file failed\n");
        	sniper_fclose(fp, OTHER_GET);
                return;
        }

	fprintf(fp, "[黑名单]\n");
	fprintf(fp_en, "[black list]\n");

	num = rule_black_global.process_num;
	if (num > 0) {
		fprintf(fp, "进程:\n");
		fprintf(fp_en, "process:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]进程名称:%s\n", i, rule_black_global.process[i].process_name);
			fprintf(fp_en, "  [%d]process name:%s\n", i, rule_black_global.process[i].process_name);
			fprintf(fp, "  [%d]进程路径:%s\n", i, rule_black_global.process[i].process_path);
			fprintf(fp_en, "  [%d]process path:%s\n", i, rule_black_global.process[i].process_path);
			fprintf(fp, "  [%d]进程参数:%s\n", i, rule_black_global.process[i].process_commandline);
			fprintf(fp_en, "  [%d]process parameters:%s\n", i, rule_black_global.process[i].process_commandline);
			fprintf(fp, "  [%d]进程参数条件:%s\n", i,rule_black_global.process[i].param);
			fprintf(fp_en, "  [%d]process parameter conditions:%s\n", i,rule_black_global.process[i].param);
			fprintf(fp, "  [%d]进程md5:%s\n", i, rule_black_global.process[i].md5);
			fprintf(fp_en, "  [%d]process md5:%s\n", i, rule_black_global.process[i].md5);
			fprintf(fp, "  [%d]进程用户:%s\n", i, rule_black_global.process[i].process_user);
			fprintf(fp_en, "  [%d]process user:%s\n", i, rule_black_global.process[i].process_user);
			fprintf(fp, "  [%d]父进程名:%s\n", i, rule_black_global.process[i].parent_process_name);
			fprintf(fp_en, "  [%d]parent process name:%s\n", i, rule_black_global.process[i].parent_process_name);
			fprintf(fp, "  [%d]远程IP:%s\n", i, rule_black_global.process[i].remote_ip);
			fprintf(fp_en, "  [%d]remote IP:%s\n", i, rule_black_global.process[i].remote_ip);
		}
	}

	num = rule_black_global.file_num;
	if (num > 0) {
		fprintf(fp, "文件:\n");
		fprintf(fp_en, "file:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]文件名:%s\n", i, rule_black_global.file[i].filename);
			fprintf(fp_en, "  [%d]file name:%s\n", i, rule_black_global.file[i].filename);
			fprintf(fp, "  [%d]文件路径:%s\n", i, rule_black_global.file[i].filepath);
			fprintf(fp_en, "  [%d]file path:%s\n", i, rule_black_global.file[i].filepath);
			fprintf(fp, "  [%d]md5:%s\n", i,rule_black_global.file[i].md5);
			fprintf(fp_en, "  [%d]md5:%s\n", i,rule_black_global.file[i].md5);
		}
	}

	num = rule_black_global.ip_num;
	if (num > 0) {
		fprintf(fp, "IP:\n");
		fprintf(fp_en, "IP:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]IP列表:", i);
			fprintf(fp_en, "  [%d]IP list:", i);
			count = rule_black_global.ip[i].ip_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_black_global.ip[i].ip_list[j].list);
				fprintf(fp_en, "%s;", rule_black_global.ip[i].ip_list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");

			fprintf(fp, "  [%d]适用事件:", i);
			fprintf(fp_en, "  [%d]applicable events:", i);
			count = rule_black_global.ip[i].event_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_black_global.ip[i].event_names[j].list);
				fprintf(fp_en, "%s;", rule_black_global.ip[i].event_names[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_black_global.domain_num;
	if (num > 0) {
		fprintf(fp, "域名:\n");
		fprintf(fp_en, "domain:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]域名列表:", i);
			fprintf(fp_en, "  [%d]domain list:", i);
			count = rule_black_global.domain[i].domain_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_black_global.domain[i].domain_list[j].list);
				fprintf(fp_en, "%s;", rule_black_global.domain[i].domain_list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_black_global.user_num;
	if (num > 0) {
		fprintf(fp, "用户:\n");
		fprintf(fp_en, "user:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]用户列表:", i);
			fprintf(fp_en, "  [%d]user list:", i);
			count = rule_black_global.user[i].user_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_black_global.user[i].user_list[j].list);
				fprintf(fp_en, "%s;", rule_black_global.user[i].user_list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");

			fprintf(fp, "  [%d]适用事件:", i);
			fprintf(fp_en, "  [%d]applicable events:", i);
			count = rule_black_global.user[i].event_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_black_global.user[i].event_names[j].list);
				fprintf(fp_en, "%s;", rule_black_global.user[i].event_names[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_black_global.access_control_num;
	if (num > 0) {
		fprintf(fp, "访问控制:\n");
		fprintf(fp_en, "access control:\n");
		for (i = 0; i< num; i++) {
			count = rule_black_global.access_control[i].connect_num;
			for (j = 0; j< count; j++) {
				fprintf(fp, "    [%d]方向:%s\n", j, rule_black_global.access_control[i].connect_list[j].direction);
				fprintf(fp_en, "    [%d]direction:%s\n", j, rule_black_global.access_control[i].connect_list[j].direction);
				fprintf(fp, "    [%d]协议:%s\n", j, rule_black_global.access_control[i].connect_list[j].protocol);
				fprintf(fp_en, "    [%d]protocol:%s\n", j, rule_black_global.access_control[i].connect_list[j].protocol);
				fprintf(fp, "    [%d]ip:%s\n", j, rule_black_global.access_control[i].connect_list[j].ip);
				fprintf(fp_en, "    [%d]ip:%s\n", j, rule_black_global.access_control[i].connect_list[j].ip);
				fprintf(fp, "    [%d]端口:%s\n", j, rule_black_global.access_control[i].connect_list[j].port);
				fprintf(fp_en, "    [%d]port:%s\n", j, rule_black_global.access_control[i].connect_list[j].port);
			}

		}
	}

	fprintf(fp, "[白名单]\n");
	fprintf(fp_en, "[white list]\n");

	num = rule_white_global.ip_num;
	if (num > 0) {
		fprintf(fp, "IP:\n");
		fprintf(fp_en, "IP:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]IP列表:", i);
			fprintf(fp_en, "  [%d]IP list:", i);
			count = rule_white_global.ip[i].ip_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_white_global.ip[i].ip_list[j].list);
				fprintf(fp_en, "%s;", rule_white_global.ip[i].ip_list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");

			fprintf(fp, "  [%d]适用事件:", i);
			fprintf(fp_en, "  [%d]applicable events:", i);
			count = rule_white_global.ip[i].event_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_white_global.ip[i].event_names[j].list);
				fprintf(fp_en, "%s;", rule_white_global.ip[i].event_names[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_white_global.domain_num;
	if (num > 0) {
		fprintf(fp, "域名:\n");
		fprintf(fp_en, "domain:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]域名列表:", i);
			fprintf(fp_en, "  [%d]domain list:", i);
			count = rule_white_global.domain[i].domain_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_white_global.domain[i].domain_list[j].list);
				fprintf(fp_en, "%s;", rule_white_global.domain[i].domain_list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_white_global.user_num;
	if (num > 0) {
		fprintf(fp, "用户:\n");
		fprintf(fp_en, "user:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]用户列表:", i);
			fprintf(fp_en, "  [%d]user list:", i);
			count = rule_white_global.user[i].user_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_white_global.user[i].user_list[j].list);
				fprintf(fp_en, "%s;", rule_white_global.user[i].user_list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");

			fprintf(fp, "  [%d]适用事件:", i);
			fprintf(fp_en, "  [%d]applicable events:", i);
			count = rule_white_global.user[i].event_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_white_global.user[i].event_names[j].list);
				fprintf(fp_en, "%s;", rule_white_global.user[i].event_names[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_white_global.access_control_num;
	if (num > 0) {
		fprintf(fp, "访问控制:\n");
		fprintf(fp_en, "access control:\n");
		for (i = 0; i< num; i++) {
			count = rule_white_global.access_control[i].connect_num;
			k = 0;
			for (j = 0; j< count; j++) {

				/* 互斥的连入连出白名单direction字段内容被修改过了，这边过滤不显示 */
				if (strcmp(rule_white_global.access_control[i].connect_list[j].direction, "ni") == 0 ||
				    strcmp(rule_white_global.access_control[i].connect_list[j].direction, "tuo") == 0) {
					k++;
					continue;
				}

				fprintf(fp, "    [%d]方向:%s\n", j-k, rule_white_global.access_control[i].connect_list[j].direction);
				fprintf(fp_en, "    [%d]direction:%s\n", j-k, rule_white_global.access_control[i].connect_list[j].direction);
				fprintf(fp, "    [%d]协议:%s\n", j-k, rule_white_global.access_control[i].connect_list[j].protocol);
				fprintf(fp_en, "    [%d]protocol:%s\n", j-k, rule_white_global.access_control[i].connect_list[j].protocol);
				fprintf(fp, "    [%d]ip:%s\n", j-k, rule_white_global.access_control[i].connect_list[j].ip);
				fprintf(fp_en, "    [%d]ip:%s\n", j-k, rule_white_global.access_control[i].connect_list[j].ip);
				fprintf(fp, "    [%d]端口:%s\n", j-k, rule_white_global.access_control[i].connect_list[j].port);
				fprintf(fp_en, "    [%d]port:%s\n", j-k, rule_white_global.access_control[i].connect_list[j].port);
			}
		}
	}

	if (rule_white_global.risk.weak_passwd_num > 0 &&
	    rule_white_global.risk.account_num > 0 &&
	    rule_white_global.risk.sys_num > 0) {
		fprintf(fp, "[风险发现]\n");
		fprintf(fp_en, "[risk finding]\n");
	}
	num = rule_white_global.risk.weak_passwd_num;
	if (num > 0) {
		fprintf(fp, "弱口令:");
		fprintf(fp_en, "weak password:");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]ID:[%d]\n", i, rule_white_global.risk.weak_passwd[i].id);
			fprintf(fp_en, "  [%d]ID:[%d]\n", i, rule_white_global.risk.weak_passwd[i].id);
			fprintf(fp, "  [%d]规则内容\n", i);
			fprintf(fp_en, "  [%d]rule content:\n", i);
			fprintf(fp, "  [%d]应用类型:", i);
			fprintf(fp_en, "  [%d]app type:", i);
			count = rule_white_global.risk.weak_passwd[i].rule.type_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%d;", rule_white_global.risk.weak_passwd[i].rule.app_type[j].list);
				fprintf(fp_en, "%d;", rule_white_global.risk.weak_passwd[i].rule.app_type[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
			fprintf(fp, "  [%d]用户列表:", i);
			fprintf(fp_en, "  [%d]user list:", i);
			count = rule_white_global.risk.weak_passwd[i].rule.list_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_white_global.risk.weak_passwd[i].rule.list[j].list);
				fprintf(fp_en, "%s;", rule_white_global.risk.weak_passwd[i].rule.list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_white_global.risk.account_num;
	if (num > 0) {
		fprintf(fp, "风险账号:\n");
		fprintf(fp_en, "risk account:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]ID:[%d]\n", i, rule_white_global.risk.account[i].id);
			fprintf(fp_en, "  [%d]ID:[%d]\n", i, rule_white_global.risk.account[i].id);
			fprintf(fp, "  [%d]规则内容\n", i);
			fprintf(fp_en, "  [%d]rule content:\n", i);
			fprintf(fp, "  [%d]用户列表:", i);
			fprintf(fp_en, "  [%d]user list:", i);
			count = rule_white_global.risk.account[i].rule.list_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_white_global.risk.account[i].rule.list[j].list);
				fprintf(fp_en, "%s;", rule_white_global.risk.account[i].rule.list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_white_global.risk.sys_num;
	if (num > 0) {
		fprintf(fp, "系统风险:\n");
		fprintf(fp_en, "systemic risk:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]ID:[%d]\n", i, rule_white_global.risk.sys[i].id);
			fprintf(fp_en, "  [%d]ID:[%d]\n", i, rule_white_global.risk.sys[i].id);
			fprintf(fp, "  [%d]规则内容\n", i);
			fprintf(fp_en, "  [%d]rule content:\n", i);
			fprintf(fp, "  [%d]KEY:", i);
			fprintf(fp_en, "  [%d]KEY:", i);
			count = rule_white_global.risk.sys[i].rule.list_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_white_global.risk.sys[i].rule.list[j].list);
				fprintf(fp_en, "%s;", rule_white_global.risk.sys[i].rule.list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	fprintf(fp, "[过滤名单]\n");
	fprintf(fp_en, "[filter list]\n");

	num = rule_filter_global.process_num;
	if (num >0) {
		fprintf(fp, "进程:\n");
		fprintf(fp_en, "process:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]进程名称:%s\n", i, rule_filter_global.process[i].process_name);
			fprintf(fp_en, "  [%d]process name:%s\n", i, rule_filter_global.process[i].process_name);
			fprintf(fp, "  [%d]进程路径:%s\n", i, rule_filter_global.process[i].process_path);
			fprintf(fp_en, "  [%d]process path:%s\n", i, rule_filter_global.process[i].process_path);
			fprintf(fp, "  [%d]进程参数:%s\n", i, rule_filter_global.process[i].process_commandline);
			fprintf(fp_en, "  [%d]process parameters:%s\n", i, rule_filter_global.process[i].process_commandline);
			fprintf(fp, "  [%d]进程参数条件:%s\n", i,rule_filter_global.process[i].param);
			fprintf(fp_en, "  [%d]process parameter conditions:%s\n", i,rule_filter_global.process[i].param);
			fprintf(fp, "  [%d]进程md5:%s\n", i, rule_filter_global.process[i].md5);
			fprintf(fp_en, "  [%d]process md5:%s\n", i, rule_filter_global.process[i].md5);
			fprintf(fp, "  [%d]进程用户:%s\n", i, rule_filter_global.process[i].process_user);
			fprintf(fp_en, "  [%d]process user:%s\n", i, rule_filter_global.process[i].process_user);
			fprintf(fp, "  [%d]父进程名:%s\n", i, rule_filter_global.process[i].parent_process_name);
			fprintf(fp_en, "  [%d]parent process name:%s\n", i, rule_filter_global.process[i].parent_process_name);
			fprintf(fp, "  [%d]远程IP:%s\n", i, rule_filter_global.process[i].remote_ip);
			fprintf(fp_en, "  [%d]remote IP:%s\n", i, rule_filter_global.process[i].remote_ip);
		}
	}

	num = rule_filter_global.file_num;
	if (num > 0) {
		fprintf(fp, "文件:\n");
		fprintf(fp_en, "file:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]文件名:%s\n", i, rule_filter_global.file[i].filename);
			fprintf(fp_en, "  [%d]file name:%s\n", i, rule_filter_global.file[i].filename);
			fprintf(fp, "  [%d]文件路径:%s\n", i, rule_filter_global.file[i].filepath);
			fprintf(fp_en, "  [%d]file path:%s\n", i, rule_filter_global.file[i].filepath);
			fprintf(fp, "  [%d]md5:%s\n", i, rule_filter_global.file[i].md5);
			fprintf(fp_en, "  [%d]md5:%s\n", i, rule_filter_global.file[i].md5);
/* 5.0.9新增 */
			fprintf(fp, "  [%d]进程名称:%s\n", i, rule_filter_global.file[i].process_name);
			fprintf(fp_en, "  [%d]process name:%s\n", i, rule_filter_global.file[i].process_name);

			fprintf(fp, "  [%d]进程路径:%s\n", i, rule_filter_global.file[i].process_path);
			fprintf(fp_en, "  [%d]process path:%s\n", i, rule_filter_global.file[i].process_path);
			
/* 5.0.9新增 */
		}
	}

	num = rule_filter_global.ip_num;
	if (num > 0) {
		fprintf(fp, "IP:\n");
		fprintf(fp_en, "IP:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]IP列表:", i);
			fprintf(fp_en, "  [%d]IP list:", i);
			count = rule_filter_global.ip[i].ip_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_filter_global.ip[i].ip_list[j].list);
				fprintf(fp_en, "%s;", rule_filter_global.ip[i].ip_list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");

			fprintf(fp, "  [%d]适用事件:", i);
			fprintf(fp_en, "  [%d]applicable events:", i);
			count = rule_filter_global.ip[i].event_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_filter_global.ip[i].event_names[j].list);
				fprintf(fp_en, "%s;", rule_filter_global.ip[i].event_names[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_filter_global.domain_num;
	if (num >0) {
		fprintf(fp, "域名:\n");
		fprintf(fp_en, "domain:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]域名列表:", i);
			fprintf(fp_en, "  [%d]domain list:", i);
			count = rule_filter_global.domain[i].domain_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_filter_global.domain[i].domain_list[j].list);
				fprintf(fp_en, "%s;", rule_filter_global.domain[i].domain_list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");

			fprintf(fp, "[%d]适用事件:", i);
			fprintf(fp_en, "[%d]applicable events:", i);
			count = rule_filter_global.domain[i].event_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_filter_global.domain[i].event_names[j].list);
				fprintf(fp_en, "%s;", rule_filter_global.domain[i].event_names[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	fprintf(fp, "[可信名单]\n");
	fprintf(fp_en, "[trust list]\n");

	num = rule_trust_global.process_num;
	if (num > 0) {
		fprintf(fp, "进程:\n");
		fprintf(fp_en, "process:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]进程名称:%s\n", i, rule_trust_global.process[i].process_name);
			fprintf(fp_en, "  [%d]process name:%s\n", i, rule_trust_global.process[i].process_name);
			fprintf(fp, "  [%d]进程路径:%s\n", i, rule_trust_global.process[i].process_path);
			fprintf(fp_en, "  [%d]process path:%s\n", i, rule_trust_global.process[i].process_path);
			fprintf(fp, "  [%d]进程参数:%s\n", i, rule_trust_global.process[i].process_commandline);
			fprintf(fp_en, "  [%d]process parameters:%s\n", i, rule_trust_global.process[i].process_commandline);
			fprintf(fp, "  [%d]进程参数条件:%s\n", i,rule_trust_global.process[i].param);
			fprintf(fp_en, "  [%d]process parameter conditions:%s\n", i,rule_trust_global.process[i].param);
			fprintf(fp, "  [%d]进程md5:%s\n", i, rule_trust_global.process[i].md5);
			fprintf(fp_en, "  [%d]process md5:%s\n", i, rule_trust_global.process[i].md5);
			fprintf(fp, "  [%d]进程用户:%s\n", i, rule_trust_global.process[i].process_user);
			fprintf(fp_en, "  [%d]process user:%s\n", i, rule_trust_global.process[i].process_user);
			fprintf(fp, "  [%d]父进程名:%s\n", i, rule_trust_global.process[i].parent_process_name);
			fprintf(fp_en, "  [%d]parent process name:%s\n", i, rule_trust_global.process[i].parent_process_name);
			fprintf(fp, "  [%d]远程IP:%s\n", i, rule_trust_global.process[i].remote_ip);
			fprintf(fp_en, "  [%d]remote IP:%s\n", i, rule_trust_global.process[i].remote_ip);

			fprintf(fp, "  [%d]适用事件:", i);
			fprintf(fp_en, "  [%d]applicable events:", i);
			count = rule_trust_global.process[i].event_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_trust_global.process[i].event_names[j].list);
				fprintf(fp_en, "%s;", rule_trust_global.process[i].event_names[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_trust_global.file_num;
	if (num > 0) {
		fprintf(fp, "文件:\n");
		fprintf(fp_en, "file:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]文件名:%s\n", i, rule_trust_global.file[i].filename);
			fprintf(fp_en, "  [%d]file name:%s\n", i, rule_trust_global.file[i].filename);
			fprintf(fp, "  [%d]文件路径:%s\n", i, rule_trust_global.file[i].filepath);
			fprintf(fp_en, "  [%d]file path:%s\n", i, rule_trust_global.file[i].filepath);
			fprintf(fp, "  [%d]md5:%s\n", i, rule_trust_global.file[i].md5);
			fprintf(fp_en, "  [%d]md5:%s\n", i, rule_trust_global.file[i].md5);
/* 5.0.9新增 */
			fprintf(fp, "  [%d]进程名称:%s\n", i, rule_trust_global.file[i].process_name);
			fprintf(fp_en, "  [%d]process name:%s\n", i, rule_trust_global.file[i].process_name);

			fprintf(fp, "  [%d]进程路径:%s\n", i, rule_trust_global.file[i].process_path);
			fprintf(fp_en, "  [%d]process path:%s\n", i, rule_trust_global.file[i].process_path);
/* 5.0.9新增 */
			fprintf(fp, "  [%d]适用事件:", i);
			fprintf(fp_en, "  [%d]applicable events:", i);
			count = rule_trust_global.file[i].event_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_trust_global.file[i].event_names[j].list);
				fprintf(fp_en, "%s;", rule_trust_global.file[i].event_names[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_trust_global.ip_num;
	if (num > 0) {
		fprintf(fp, "IP:\n");
		fprintf(fp_en, "IP:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]IP列表:", i);
			fprintf(fp_en, "  [%d]IP list:", i);
			count = rule_trust_global.ip[i].ip_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_trust_global.ip[i].ip_list[j].list);
				fprintf(fp_en, "%s;", rule_trust_global.ip[i].ip_list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");

			fprintf(fp, "  [%d]适用事件:", i);
			fprintf(fp_en, "  [%d]applicable events:", i);
			count = rule_trust_global.ip[i].event_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_trust_global.ip[i].event_names[j].list);
				fprintf(fp_en, "%s;", rule_trust_global.ip[i].event_names[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	num = rule_trust_global.domain_num;
	if (num > 0) {
		fprintf(fp, "域名:\n");
		fprintf(fp_en, "domain:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]域名列表:", i);
			fprintf(fp_en, "  [%d]domain list:", i);
			count = rule_trust_global.domain[i].domain_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_trust_global.domain[i].domain_list[j].list);
				fprintf(fp_en, "%s;", rule_trust_global.domain[i].domain_list[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");

			fprintf(fp, "  [%d]适用事件:", i);
			fprintf(fp_en, "  [%d]applicable events:", i);
			count = rule_trust_global.domain[i].event_num;
			if (count <= 0) {
				fprintf(fp, "无");
				fprintf(fp_en, "null");
			} 
			for (j = 0; j< count; j++) {
				fprintf(fp, "%s;", rule_trust_global.domain[i].event_names[j].list);
				fprintf(fp_en, "%s;", rule_trust_global.domain[i].event_names[j].list);
			}
			fprintf(fp, "\n");
			fprintf(fp_en, "\n");
		}
	}

	fprintf(fp, "[global]\n");
	fprintf(fp_en, "[global]\n");

	num = rule_global_global.trust.sign_num;
	if (num > 0) {
		fprintf(fp, "可信证书:\n");
		fprintf(fp_en, "trusted certificate:\n");
		for (i = 0; i< num; i++) {
			fprintf(fp, "  [%d]公司名称:%s\n", i, rule_global_global.trust.sign[i].company);
			fprintf(fp_en, "  [%d]company name:%s\n", i, rule_global_global.trust.sign[i].company);
			fprintf(fp, "  [%d]指纹信息:%s\n", i, rule_global_global.trust.sign[i].fingerprint);
			fprintf(fp_en, "  [%d]fingerprint information:%s\n", i, rule_global_global.trust.sign[i].fingerprint);
		}
	}

#if 0 //隐藏默认的矿池列表
	fprintf(fp, "矿池列表:");
	num = rule_global_global.black.minner_num;
	if (num <= 0) {
		fprintf(fp, "无");
	} 
	for (i = 0; i< num; i++) {
		fprintf(fp, "%s;", rule_global_global.black.minner[i].list);
	}
	fprintf(fp, "\n");
#endif

	fflush(fp);
	fflush(fp_en);
        sniper_fclose(fp, OTHER_GET);
        sniper_fclose(fp_en, OTHER_GET);
}

void free_rule_trust_ptr(struct _RULE_TRUST *ptr)
{
	int i = 0, j = 0, len = 0;
	int num = 0, count = 0;

	num = ptr->process_num;
        for (i = 0; i < num; i++) {
		free_valuestring(ptr->process[i].process_name);
		free_valuestring(ptr->process[i].process_path);
		free_valuestring(ptr->process[i].process_commandline);
		free_valuestring(ptr->process[i].param);
		free_valuestring(ptr->process[i].md5);
		free_valuestring(ptr->process[i].process_user);
		free_valuestring(ptr->process[i].parent_process_name);
		free_valuestring(ptr->process[i].remote_ip);

                count = ptr->process[i].event_num;
                for (j = 0; j < count; j++) {
                        free_valuestring(ptr->process[i].event_names[j].list);
                }
                len = sizeof(struct _POLICY_LIST) * count;
                sniper_free(ptr->process[i].event_names, len, POLICY_GET);
                ptr->process[i].event_num = 0;
        }
        len = sizeof(struct _TRUST_PROCESS) * num;
        sniper_free(ptr->process, len, POLICY_GET);
        ptr->process_num = 0;

	num = ptr->file_num;
        for (i = 0; i < num; i++) {
		free_valuestring(ptr->file[i].filename);
		free_valuestring(ptr->file[i].filepath);
		free_valuestring(ptr->file[i].extension);
		free_valuestring(ptr->file[i].md5);
		free_valuestring(ptr->file[i].process_name);
		free_valuestring(ptr->file[i].process_path);

                count = ptr->file[i].event_num;
                for (j = 0; j < count; j++) {
                        free_valuestring(ptr->file[i].event_names[j].list);
                }
                len = sizeof(struct _POLICY_LIST) * count;
                sniper_free(ptr->file[i].event_names, len, POLICY_GET);
                ptr->file[i].event_num = 0;
        }
        len = sizeof(struct _TRUST_PROCESS) * num;
        sniper_free(ptr->file, len, POLICY_GET);
        ptr->file_num = 0;

	num = ptr->ip_num;
	for (i = 0; i < num; i++) {
		count = ptr->ip[i].ip_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->ip[i].ip_list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->ip[i].ip_list, len, POLICY_GET);
		ptr->ip[i].ip_num = 0;

		count = ptr->ip[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->ip[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->ip[i].event_names, len, POLICY_GET);
		ptr->ip[i].event_num = 0;
	}
	len = sizeof(struct _TRUST_IP) * num;
	sniper_free(ptr->ip, len, POLICY_GET);
	ptr->ip_num = 0;

	num = ptr->domain_num;
	for (i = 0; i < num; i++) {
		count = ptr->domain[i].domain_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->domain[i].domain_list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->domain[i].domain_list, len, POLICY_GET);
		ptr->domain[i].domain_num = 0;

		count = ptr->domain[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->domain[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->domain[i].event_names, len, POLICY_GET);
		ptr->domain[i].event_num = 0;
	}
	len = sizeof(struct _TRUST_DOMAIN) * num;
	sniper_free(ptr->domain, len, POLICY_GET);
	ptr->domain_num = 0;

}

void free_rule_filter_ptr(struct _RULE_FILTER *ptr)
{
	int i = 0, j = 0, len = 0;
	int num = 0, count = 0;

	num = ptr->process_num;
        for (i = 0; i < num; i++) {
		free_valuestring(ptr->process[i].process_name);
		free_valuestring(ptr->process[i].process_path);
		free_valuestring(ptr->process[i].process_commandline);
		free_valuestring(ptr->process[i].param);
		free_valuestring(ptr->process[i].md5);
		free_valuestring(ptr->process[i].process_user);
		free_valuestring(ptr->process[i].parent_process_name);
		free_valuestring(ptr->process[i].remote_ip);

                count = ptr->process[i].event_num;
                for (j = 0; j < count; j++) {
                        free_valuestring(ptr->process[i].event_names[j].list);
                }
                len = sizeof(struct _POLICY_LIST) * count;
                sniper_free(ptr->process[i].event_names, len, POLICY_GET);
                ptr->process[i].event_num = 0;
        }
        len = sizeof(struct _FILTER_PROCESS) * num;
        sniper_free(ptr->process, len, POLICY_GET);
        ptr->process_num = 0;

	num = ptr->file_num;
        for (i = 0; i < num; i++) {
		free_valuestring(ptr->file[i].filename);
		free_valuestring(ptr->file[i].filepath);
		free_valuestring(ptr->file[i].extension);
		free_valuestring(ptr->file[i].md5);
		free_valuestring(ptr->file[i].process_name);
		free_valuestring(ptr->file[i].process_path);

                count = ptr->file[i].event_num;
                for (j = 0; j < count; j++) {
                        free_valuestring(ptr->file[i].event_names[j].list);
                }
                len = sizeof(struct _POLICY_LIST) * count;
                sniper_free(ptr->file[i].event_names, len, POLICY_GET);
                ptr->file[i].event_num = 0;
        }
        len = sizeof(struct _FILTER_PROCESS) * num;
        sniper_free(ptr->file, len, POLICY_GET);
        ptr->file_num = 0;

	num = ptr->ip_num;
	for (i = 0; i < num; i++) {
		count = ptr->ip[i].ip_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->ip[i].ip_list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->ip[i].ip_list, len, POLICY_GET);
		ptr->ip[i].ip_num = 0;

		count = ptr->ip[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->ip[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->ip[i].event_names, len, POLICY_GET);
		ptr->ip[i].event_num = 0;
	}
	len = sizeof(struct _FILTER_IP) * num;
	sniper_free(ptr->ip, len, POLICY_GET);
	ptr->ip_num = 0;

	num = ptr->domain_num;
	for (i = 0; i < num; i++) {
		count = ptr->domain[i].domain_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->domain[i].domain_list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->domain[i].domain_list, len, POLICY_GET);
		ptr->domain[i].domain_num = 0;

		count = ptr->domain[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->domain[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->domain[i].event_names, len, POLICY_GET);
		ptr->domain[i].event_num = 0;
	}
	len = sizeof(struct _FILTER_DOMAIN) * num;
	sniper_free(ptr->domain, len, POLICY_GET);
	ptr->domain_num = 0;

}

void free_rule_black_ptr(struct _RULE_BLACK *ptr)
{
	int i = 0, j = 0, len = 0;
	int num = 0, count = 0;

	num = ptr->process_num;
        for (i = 0; i < num; i++) {
		free_valuestring(ptr->process[i].process_name);
		free_valuestring(ptr->process[i].process_path);
		free_valuestring(ptr->process[i].process_commandline);
		free_valuestring(ptr->process[i].param);
		free_valuestring(ptr->process[i].md5);
		free_valuestring(ptr->process[i].process_user);
		free_valuestring(ptr->process[i].parent_process_name);
		free_valuestring(ptr->process[i].remote_ip);

                count = ptr->process[i].event_num;
                for (j = 0; j < count; j++) {
                        free_valuestring(ptr->process[i].event_names[j].list);
                }
                len = sizeof(struct _POLICY_LIST) * count;
                sniper_free(ptr->process[i].event_names, len, POLICY_GET);
                ptr->process[i].event_num = 0;
        }
        len = sizeof(struct _BLACK_PROCESS) * num;
        sniper_free(ptr->process, len, POLICY_GET);
        ptr->process_num = 0;

	num = ptr->file_num;
        for (i = 0; i < num; i++) {
		free_valuestring(ptr->file[i].filename);
		free_valuestring(ptr->file[i].filepath);
		free_valuestring(ptr->file[i].extension);
		free_valuestring(ptr->file[i].md5);

                count = ptr->file[i].event_num;
                for (j = 0; j < count; j++) {
                        free_valuestring(ptr->file[i].event_names[j].list);
                }
                len = sizeof(struct _POLICY_LIST) * count;
                sniper_free(ptr->file[i].event_names, len, POLICY_GET);
                ptr->file[i].event_num = 0;
        }
        len = sizeof(struct _BLACK_PROCESS) * num;
        sniper_free(ptr->file, len, POLICY_GET);
        ptr->file_num = 0;

	num = ptr->ip_num;
	for (i = 0; i < num; i++) {
		count = ptr->ip[i].ip_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->ip[i].ip_list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->ip[i].ip_list, len, POLICY_GET);
		ptr->ip[i].ip_num = 0;

		count = ptr->ip[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->ip[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->ip[i].event_names, len, POLICY_GET);
		ptr->ip[i].event_num = 0;
	}
	len = sizeof(struct _BLACK_IP) * num;
	sniper_free(ptr->ip, len, POLICY_GET);
	ptr->ip_num = 0;

	num = ptr->domain_num;
	for (i = 0; i < num; i++) {
		count = ptr->domain[i].domain_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->domain[i].domain_list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->domain[i].domain_list, len, POLICY_GET);
		ptr->domain[i].domain_num = 0;

		count = ptr->domain[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->domain[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->domain[i].event_names, len, POLICY_GET);
		ptr->domain[i].event_num = 0;
	}
	len = sizeof(struct _BLACK_DOMAIN) * num;
	sniper_free(ptr->domain, len, POLICY_GET);
	ptr->domain_num = 0;

	num = ptr->user_num;
	for (i = 0; i < num; i++) {
		count = ptr->user[i].user_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->user[i].user_list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->user[i].user_list, len, POLICY_GET);
		ptr->user[i].user_num = 0;

		count = ptr->user[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->user[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->user[i].event_names, len, POLICY_GET);
		ptr->user[i].event_num = 0;
	}
	len = sizeof(struct _BLACK_USER) * num;
	sniper_free(ptr->ip, len, POLICY_GET);
	ptr->user_num = 0;

	num = ptr->access_control_num;
	for (i = 0; i < num; i++) {
		count = ptr->access_control[i].connect_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->access_control[i].connect_list[j].direction);
			free_valuestring(ptr->access_control[i].connect_list[j].protocol);
			free_valuestring(ptr->access_control[i].connect_list[j].ip);
			free_valuestring(ptr->access_control[i].connect_list[j].port);
		}
		len = sizeof(struct _CONNECT_LIST) * count;
		sniper_free(ptr->access_control[i].connect_list, len, POLICY_GET);
		ptr->access_control[i].connect_num = 0;

		count = ptr->access_control[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->access_control[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->access_control[i].event_names, len, POLICY_GET);
		ptr->access_control[i].event_num = 0;
	}
	len = sizeof(struct _BLACK_ACCESS_CONTROL) * num;
	sniper_free(ptr->ip, len, POLICY_GET);
	ptr->access_control_num = 0;
}

void free_rule_white_ptr(struct _RULE_WHITE *ptr)
{
	int i = 0, j = 0, len = 0;
	int num = 0, count = 0;

	num = ptr->ip_num;
	for (i = 0; i < num; i++) {
		count = ptr->ip[i].ip_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->ip[i].ip_list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->ip[i].ip_list, len, POLICY_GET);
		ptr->ip[i].ip_num = 0;

		count = ptr->ip[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->ip[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->ip[i].event_names, len, POLICY_GET);
		ptr->ip[i].event_num = 0;
	}
	len = sizeof(struct _WHITE_IP) * num;
	sniper_free(ptr->ip, len, POLICY_GET);
	ptr->ip_num = 0;

	num = ptr->domain_num;
	for (i = 0; i < num; i++) {
		count = ptr->domain[i].domain_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->domain[i].domain_list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->domain[i].domain_list, len, POLICY_GET);
		ptr->domain[i].domain_num = 0;

		count = ptr->domain[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->domain[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->domain[i].event_names, len, POLICY_GET);
		ptr->domain[i].event_num = 0;
	}
	len = sizeof(struct _WHITE_DOMAIN) * num;
	sniper_free(ptr->domain, len, POLICY_GET);
	ptr->domain_num = 0;

	num = ptr->user_num;
	for (i = 0; i < num; i++) {
		count = ptr->user[i].user_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->user[i].user_list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->user[i].user_list, len, POLICY_GET);
		ptr->user[i].user_num = 0;

		count = ptr->user[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->user[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->user[i].event_names, len, POLICY_GET);
		ptr->user[i].event_num = 0;
	}
	len = sizeof(struct _WHITE_USER) * num;
	sniper_free(ptr->ip, len, POLICY_GET);
	ptr->user_num = 0;

	num = ptr->access_control_num;
	for (i = 0; i < num; i++) {
		count = ptr->access_control[i].connect_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->access_control[i].connect_list[j].direction);
			free_valuestring(ptr->access_control[i].connect_list[j].protocol);
			free_valuestring(ptr->access_control[i].connect_list[j].ip);
			free_valuestring(ptr->access_control[i].connect_list[j].port);
		}
		len = sizeof(struct _CONNECT_LIST) * count;
		sniper_free(ptr->access_control[i].connect_list, len, POLICY_GET);
		ptr->access_control[i].connect_num = 0;

		count = ptr->access_control[i].event_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->access_control[i].event_names[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->access_control[i].event_names, len, POLICY_GET);
		ptr->access_control[i].event_num = 0;
	}
	len = sizeof(struct _WHITE_ACCESS_CONTROL) * num;
	sniper_free(ptr->ip, len, POLICY_GET);
	ptr->access_control_num = 0;

	num = ptr->risk.weak_passwd_num;
	for (i = 0; i < num; i++) {
		count = ptr->risk.weak_passwd[i].rule.type_num;
		len = sizeof(struct _POLICY_INT_LIST) * count;
		sniper_free(ptr->risk.weak_passwd[i].rule.app_type, len, POLICY_GET);
		ptr->risk.weak_passwd[i].rule.type_num = 0;
		count = ptr->risk.weak_passwd[i].rule.list_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->risk.weak_passwd[i].rule.list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->risk.weak_passwd[i].rule.list, len, POLICY_GET);
		ptr->risk.weak_passwd[i].rule.list_num = 0;
	}
	len = sizeof(struct _RISK_PASSWD) * num;
	sniper_free(ptr->risk.weak_passwd, len, POLICY_GET);
	ptr->risk.weak_passwd_num = 0;

	num = ptr->risk.account_num;
	for (i = 0; i < num; i++) {
		count = ptr->risk.account[i].rule.list_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->risk.account[i].rule.list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->risk.account[i].rule.list, len, POLICY_GET);
		ptr->risk.account[i].rule.list_num = 0;
	}
	len = sizeof(struct _RISK_LIST) * num;
	sniper_free(ptr->risk.account, len, POLICY_GET);
	ptr->risk.account_num = 0;

	num = ptr->risk.account_num;
	for (i = 0; i < num; i++) {
		count = ptr->risk.account[i].rule.list_num;
		for (j = 0; j < count; j++) {
			free_valuestring(ptr->risk.account[i].rule.list[j].list);
		}
		len = sizeof(struct _POLICY_LIST) * count;
		sniper_free(ptr->risk.account[i].rule.list, len, POLICY_GET);
		ptr->risk.account[i].rule.list_num = 0;
	}
	len = sizeof(struct _RISK_LIST) * num;
	sniper_free(ptr->risk.account, len, POLICY_GET);
	ptr->risk.account_num = 0;
}

void free_rule_global_ptr(struct _RULE_GLOBAL *ptr)
{
	int i = 0, num = 0, len = 0;

	num = ptr->trust.sign_num;
        for (i = 0; i < num; i++) {
		free_valuestring(ptr->trust.sign[i].company);
		free_valuestring(ptr->trust.sign[i].fingerprint);
        }
        len = sizeof(struct _GLOBAL_TRUST) * num;
        sniper_free(ptr->trust.sign, len, POLICY_GET);
        ptr->trust.sign_num = 0;

	num = ptr->black.domain_num;
	for (i = 0; i < num; i++) {
		free_valuestring(ptr->black.domain[i].list);
	}
	len = sizeof(struct _POLICY_LIST) * num;
	sniper_free(ptr->black.domain, len, POLICY_GET);
	ptr->black.domain_num = 0;

	num = ptr->black.minner_num;
	for (i = 0; i < num; i++) {
		free_valuestring(ptr->black.minner[i].list);
	}
	len = sizeof(struct _POLICY_LIST) * num;
	sniper_free(ptr->black.minner, len, POLICY_GET);
	ptr->black.minner_num = 0;
}

static void save_old_trust_rule(void)
{
        free_rule_trust_ptr(&old_rule_trust_global);
        old_rule_trust_global = rule_trust_global;
}

static int get_trust_rule(struct _RULE_TRUST *rule_trust)
{
        rule_trust_global.process_num = rule_trust->process_num;
        rule_trust_global.file_num = rule_trust->file_num;
        rule_trust_global.ip_num = rule_trust->ip_num;
        rule_trust_global.domain_num = rule_trust->domain_num;
        rule_trust_global.process = rule_trust->process;
        rule_trust_global.file = rule_trust->file;
        rule_trust_global.ip = rule_trust->ip;
        rule_trust_global.domain = rule_trust->domain;

        return 0;
}

static void save_old_filter_rule(void)
{
        free_rule_filter_ptr(&old_rule_filter_global);
        old_rule_filter_global = rule_filter_global;
}

static int get_filter_rule(struct _RULE_FILTER *rule_filter)
{
        rule_filter_global.process_num = rule_filter->process_num;
        rule_filter_global.file_num = rule_filter->file_num;
        rule_filter_global.ip_num = rule_filter->ip_num;
        rule_filter_global.domain_num = rule_filter->domain_num;
        rule_filter_global.process = rule_filter->process;
        rule_filter_global.file = rule_filter->file;
        rule_filter_global.ip = rule_filter->ip;
        rule_filter_global.domain = rule_filter->domain;

        return 0;
}

static void save_old_black_rule(void)
{
        free_rule_black_ptr(&old_rule_black_global);
        old_rule_black_global = rule_black_global;
}

static int get_black_rule(struct _RULE_BLACK *rule_black)
{
        rule_black_global.process_num = rule_black->process_num;
        rule_black_global.file_num = rule_black->file_num;
        rule_black_global.ip_num = rule_black->ip_num;
        rule_black_global.domain_num = rule_black->domain_num;
        rule_black_global.user_num = rule_black->user_num;
        rule_black_global.access_control_num = rule_black->access_control_num;
        rule_black_global.process = rule_black->process;
        rule_black_global.file = rule_black->file;
        rule_black_global.ip = rule_black->ip;
        rule_black_global.domain = rule_black->domain;
        rule_black_global.user = rule_black->user;
        rule_black_global.access_control = rule_black->access_control;

        return 0;
}

static void save_old_white_rule(void)
{
        free_rule_white_ptr(&old_rule_white_global);
        old_rule_white_global = rule_white_global;
}

static int get_white_rule(struct _RULE_WHITE *rule_white)
{
        rule_white_global.ip_num = rule_white->ip_num;
        rule_white_global.domain_num = rule_white->domain_num;
        rule_white_global.user_num = rule_white->user_num;
        rule_white_global.access_control_num = rule_white->access_control_num;
        rule_white_global.ip = rule_white->ip;
        rule_white_global.domain = rule_white->domain;
        rule_white_global.user = rule_white->user;
        rule_white_global.access_control = rule_white->access_control;
        rule_white_global.risk = rule_white->risk;

        return 0;
}

static void save_old_global_rule(void)
{
        free_rule_global_ptr(&old_rule_global_global);
        old_rule_global_global = rule_global_global;
}

static int get_global_rule(struct _RULE_GLOBAL *rule_global)
{
        rule_global_global.trust = rule_global->trust;
        rule_global_global.black = rule_global->black;

        return 0;
}

static int get_rule_trust_process(cJSON *process, struct _RULE_TRUST *rule_trust)
{
	cJSON *process_name, *process_path, *process_commandline, *param;
	cJSON *md5, *process_user, *parent_process_name, *remote_ip;
	cJSON *event_names, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	num = cJSON_GetArraySize(process);
	rule_trust->process_num = num;
	rule_trust->process = (struct _TRUST_PROCESS *)sniper_malloc(sizeof(struct _TRUST_PROCESS)*num, POLICY_GET);
	if (rule_trust->process == NULL) {
		MON_ERROR("rule cJSON_Parse trust process malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(process, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem trust rule_list[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		process_name = cJSON_GetObjectItem(arrayItem, "process_name");
		if (!process_name) {
			MON_ERROR("rule cJSON_Parse trust process process_name error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_name);
		if (buf == NULL) {
			MON_ERROR("rule_trust->process[%d].process_name malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}
		rule_trust->process[i].process_name = buf;

		process_path = cJSON_GetObjectItem(arrayItem, "process_path");
		if (!process_path) {
			MON_ERROR("rule cJSON_Parse trust process process_path error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_path);
		if (buf == NULL) {
			MON_ERROR("rule_trust->process[%d].process_path malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}
		rule_trust->process[i].process_path = buf;

		process_commandline = cJSON_GetObjectItem(arrayItem, "process_commandline");
		if (!process_commandline) {
			MON_ERROR("rule cJSON_Parse trust process process_commandline error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_commandline);
		if (buf == NULL) {
			MON_ERROR("rule_trust->process[%d].process_commandline malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}
		rule_trust->process[i].process_commandline = buf;

		param = cJSON_GetObjectItem(arrayItem, "param");
		if (!param) {
			MON_ERROR("rule cJSON_Parse trust process param error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(param);
		if (buf == NULL) {
			MON_ERROR("rule_trust->process[%d].param malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}
		rule_trust->process[i].param = buf;

		md5 = cJSON_GetObjectItem(arrayItem, "md5");
		if (!md5) {
			MON_ERROR("rule cJSON_Parse trust process md5 error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			free_valuestring(rule_trust->process[i].param);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(md5);
		if (buf == NULL) {
			MON_ERROR("rule_trust->process[%d].md5 malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			free_valuestring(rule_trust->process[i].param);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}
		rule_trust->process[i].md5 = buf;

		process_user = cJSON_GetObjectItem(arrayItem, "process_user");
		if (!process_user) {
			MON_ERROR("rule cJSON_Parse trust process process_user error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			free_valuestring(rule_trust->process[i].param);
			free_valuestring(rule_trust->process[i].md5);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_user);
		if (buf == NULL) {
			MON_ERROR("rule_trust->process[%d].process_user malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			free_valuestring(rule_trust->process[i].param);
			free_valuestring(rule_trust->process[i].md5);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}
		rule_trust->process[i].process_user = buf;

		parent_process_name = cJSON_GetObjectItem(arrayItem, "parent_process_name");
		if (!parent_process_name) {
			MON_ERROR("rule cJSON_Parse trust process parent_process_name error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			free_valuestring(rule_trust->process[i].param);
			free_valuestring(rule_trust->process[i].md5);
			free_valuestring(rule_trust->process[i].process_user);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(parent_process_name);
		if (buf == NULL) {
			MON_ERROR("rule_trust->trust.process[%d].parent_process_name malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			free_valuestring(rule_trust->process[i].param);
			free_valuestring(rule_trust->process[i].md5);
			free_valuestring(rule_trust->process[i].process_user);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}
		rule_trust->process[i].parent_process_name = buf;

		remote_ip = cJSON_GetObjectItem(arrayItem, "remote_ip");
		if (!remote_ip) {
			MON_ERROR("rule cJSON_Parse trust process remote_ip error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			free_valuestring(rule_trust->process[i].param);
			free_valuestring(rule_trust->process[i].md5);
			free_valuestring(rule_trust->process[i].process_user);
			free_valuestring(rule_trust->process[i].parent_process_name);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(remote_ip);
		if (buf == NULL) {
			MON_ERROR("rule_trust->process[%d].remote_ip malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			free_valuestring(rule_trust->process[i].param);
			free_valuestring(rule_trust->process[i].md5);
			free_valuestring(rule_trust->process[i].process_user);
			free_valuestring(rule_trust->process[i].parent_process_name);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}
		rule_trust->process[i].remote_ip = buf;

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse trust process event_names error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			free_valuestring(rule_trust->process[i].param);
			free_valuestring(rule_trust->process[i].md5);
			free_valuestring(rule_trust->process[i].process_user);
			free_valuestring(rule_trust->process[i].parent_process_name);
			free_valuestring(rule_trust->process[i].remote_ip);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		count = cJSON_GetArraySize(event_names);
		rule_trust->process[i].event_num = count;
		rule_trust->process[i].event_names = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*count, POLICY_GET);
		if (rule_trust->process[i].event_names == NULL) {
			MON_ERROR("rule_trust->process[%d].event_names[%d].list malloc failed\n", i, j);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->process[m].process_name);
				free_valuestring(rule_trust->process[m].process_path);
				free_valuestring(rule_trust->process[m].process_commandline);
				free_valuestring(rule_trust->process[m].param);
				free_valuestring(rule_trust->process[m].md5);
				free_valuestring(rule_trust->process[m].process_user);
				free_valuestring(rule_trust->process[m].parent_process_name);
				free_valuestring(rule_trust->process[m].remote_ip);
				for (n = 0; n < rule_trust->process[m].event_num; n++) {
					free_valuestring(rule_trust->process[m].event_names[n].list);
				}
				sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->process[i].process_name);
			free_valuestring(rule_trust->process[i].process_path);
			free_valuestring(rule_trust->process[i].process_commandline);
			free_valuestring(rule_trust->process[i].param);
			free_valuestring(rule_trust->process[i].md5);
			free_valuestring(rule_trust->process[i].process_user);
			free_valuestring(rule_trust->process[i].parent_process_name);
			free_valuestring(rule_trust->process[i].remote_ip);
			sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < count; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("rule_trust->process[%d].event_names[%d].list\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_trust->process[m].process_name);
					free_valuestring(rule_trust->process[m].process_path);
					free_valuestring(rule_trust->process[m].process_commandline);
					free_valuestring(rule_trust->process[m].param);
					free_valuestring(rule_trust->process[m].md5);
					free_valuestring(rule_trust->process[m].process_user);
					free_valuestring(rule_trust->process[m].parent_process_name);
					free_valuestring(rule_trust->process[m].remote_ip);
					for (n = 0; n < rule_trust->process[m].event_num; n++) {
						free_valuestring(rule_trust->process[m].event_names[n].list);
					}
					sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_trust->process[i].process_name);
				free_valuestring(rule_trust->process[i].process_path);
				free_valuestring(rule_trust->process[i].process_commandline);
				free_valuestring(rule_trust->process[i].param);
				free_valuestring(rule_trust->process[i].md5);
				free_valuestring(rule_trust->process[i].process_user);
				free_valuestring(rule_trust->process[i].parent_process_name);
				free_valuestring(rule_trust->process[i].remote_ip);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->process[i].event_names[n].list);
				}
				sniper_free(rule_trust->process[i].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[i].event_num, POLICY_GET);
				sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_trust->process[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_trust->process[m].process_name);
					free_valuestring(rule_trust->process[m].process_path);
					free_valuestring(rule_trust->process[m].process_commandline);
					free_valuestring(rule_trust->process[m].param);
					free_valuestring(rule_trust->process[m].md5);
					free_valuestring(rule_trust->process[m].process_user);
					free_valuestring(rule_trust->process[m].parent_process_name);
					free_valuestring(rule_trust->process[m].remote_ip);
					for (n = 0; n < rule_trust->process[m].event_num; n++) {
						free_valuestring(rule_trust->process[m].event_names[n].list);
					}
					sniper_free(rule_trust->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_trust->process[i].process_name);
				free_valuestring(rule_trust->process[i].process_path);
				free_valuestring(rule_trust->process[i].process_commandline);
				free_valuestring(rule_trust->process[i].param);
				free_valuestring(rule_trust->process[i].md5);
				free_valuestring(rule_trust->process[i].process_user);
				free_valuestring(rule_trust->process[i].parent_process_name);
				free_valuestring(rule_trust->process[i].remote_ip);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->process[i].event_names[n].list);
				}
				sniper_free(rule_trust->process[i].event_names, sizeof(struct _POLICY_LIST)*rule_trust->process[i].event_num, POLICY_GET);
				sniper_free(rule_trust->process, sizeof(struct _TRUST_PROCESS)*rule_trust->process_num, POLICY_GET);
				return -1;
			}
			rule_trust->process[i].event_names[j].list = buf;
			rule_trust->process[i].event_flags |= event2flag(arrayList->valuestring);
		}
	}

	return 0;
}

static int get_rule_trust_file(cJSON *file, struct _RULE_TRUST *rule_trust)
{
	cJSON *filename, *filepath, *extension, *md5, *process_name, *process_path;
	cJSON *event_names, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	num = cJSON_GetArraySize(file);
	rule_trust->file_num = num;
	rule_trust->file = (struct _TRUST_FILE *)sniper_malloc(sizeof(struct _TRUST_FILE)*num, POLICY_GET);
	if (rule_trust->file == NULL) {
		MON_ERROR("rule cJSON_Parse trust file malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(file, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem trust rule_list[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}

		filename = cJSON_GetObjectItem(arrayItem, "filename");
		if (!filename) {
			MON_ERROR("rule cJSON_Parse trust file filename error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(filename);
		if (buf == NULL) {
			MON_ERROR("rule_trust->file[%d].filename malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}
		rule_trust->file[i].filename = buf;

		filepath = cJSON_GetObjectItem(arrayItem, "filepath");
		if (!filepath) {
			MON_ERROR("rule cJSON_Parse trust file filepath error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->file[i].filename);
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(filepath);
		if (buf == NULL) {
			MON_ERROR("rule_trust->file[%d].filepath malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->file[i].filename);
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}
		rule_trust->file[i].filepath = buf;

		extension = cJSON_GetObjectItem(arrayItem, "extension");
		if (!extension) {
			MON_ERROR("rule cJSON_Parse trust file extension error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->file[i].filename);
			free_valuestring(rule_trust->file[i].filepath);
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(extension);
		if (buf == NULL) {
			MON_ERROR("rule_trust->file[%d].extension malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->file[i].filename);
			free_valuestring(rule_trust->file[i].filepath);
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}
		rule_trust->file[i].extension = buf;

		md5 = cJSON_GetObjectItem(arrayItem, "md5");
		if (!md5) {
			MON_ERROR("rule cJSON_Parse trust file md5 error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->file[i].filename);
			free_valuestring(rule_trust->file[i].filepath);
			free_valuestring(rule_trust->file[i].extension);
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(md5);
		if (buf == NULL) {
			MON_ERROR("rule_trust->file[%d].md5 malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->file[i].filename);
			free_valuestring(rule_trust->file[i].filepath);
			free_valuestring(rule_trust->file[i].extension);
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}
		rule_trust->file[i].md5 = buf;

		/*
		 * 5.0.9新增的字段，和旧版本保持兼容，
		 * 没有该字段不报错退出，也开辟一个字节的空间, 方便后续使用和空间释放
		 */
		process_name = cJSON_GetObjectItem(arrayItem, "process_name");
		if (!process_name) {
			MON_WARNING("rule cJSON_Parse trust file process_name error\n");
			buf = get_customize_valuestring();
		} else {
			buf = get_my_valuestring(process_name);
		}
		if (buf == NULL) {
			MON_ERROR("rule_trust->file[%d].process_name malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, 
						sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->file[i].filename);
			free_valuestring(rule_trust->file[i].filepath);
			free_valuestring(rule_trust->file[i].extension);
			free_valuestring(rule_trust->file[i].md5);
			sniper_free(rule_trust->file, 
				sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}
		rule_trust->file[i].process_name = buf;

		/*
		 * 5.0.9新增的字段，和旧版本保持兼容，
		 * 没有该字段不报错退出，也开辟一个字节的空间, 方便后续使用和空间释放
		 */
		process_path = cJSON_GetObjectItem(arrayItem, "process_path");
		if (!process_path) {
			MON_WARNING("rule cJSON_Parse trust file process_path error\n");
			buf = get_customize_valuestring();
		} else {
			buf = get_my_valuestring(process_path);
		}
		if (buf == NULL) {
			MON_ERROR("rule_trust->file[%d].process_path malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, 
						sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->file[i].filename);
			free_valuestring(rule_trust->file[i].filepath);
			free_valuestring(rule_trust->file[i].extension);
			free_valuestring(rule_trust->file[i].md5);
			free_valuestring(rule_trust->file[i].process_name);
			sniper_free(rule_trust->file, 
					sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}
		rule_trust->file[i].process_path = buf;

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse trust file event_names error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->file[i].filename);
			free_valuestring(rule_trust->file[i].filepath);
			free_valuestring(rule_trust->file[i].extension);
			free_valuestring(rule_trust->file[i].md5);
			free_valuestring(rule_trust->file[i].process_name);
			free_valuestring(rule_trust->file[i].process_path);
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}

		count = cJSON_GetArraySize(event_names);
		rule_trust->file[i].event_num = count;
		rule_trust->file[i].event_names = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*count, POLICY_GET);
		if (rule_trust->file[i].event_names == NULL) {
			MON_ERROR("rule_trust->file[%d].event_names[%d].list malloc failed\n", i, j);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_trust->file[m].filename);
				free_valuestring(rule_trust->file[m].filepath);
				free_valuestring(rule_trust->file[m].extension);
				free_valuestring(rule_trust->file[m].md5);
				free_valuestring(rule_trust->file[m].process_name);
				free_valuestring(rule_trust->file[m].process_path);
				for (n = 0; n < rule_trust->file[m].event_num; n++) {
					free_valuestring(rule_trust->file[m].event_names[n].list);
				}
				sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_trust->file[i].filename);
			free_valuestring(rule_trust->file[i].filepath);
			free_valuestring(rule_trust->file[i].extension);
			free_valuestring(rule_trust->file[i].md5);
			free_valuestring(rule_trust->file[i].process_name);
			free_valuestring(rule_trust->file[i].process_path);
			sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < count; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("rule_trust->file[%d].event_names[%d].list\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_trust->file[m].filename);
					free_valuestring(rule_trust->file[m].filepath);
					free_valuestring(rule_trust->file[m].extension);
					free_valuestring(rule_trust->file[m].md5);
					free_valuestring(rule_trust->file[m].process_name);
					free_valuestring(rule_trust->file[m].process_path);
					for (n = 0; n < rule_trust->file[m].event_num; n++) {
						free_valuestring(rule_trust->file[m].event_names[n].list);
					}
					sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_trust->file[i].filename);
				free_valuestring(rule_trust->file[i].filepath);
				free_valuestring(rule_trust->file[i].extension);
				free_valuestring(rule_trust->file[i].md5);
				free_valuestring(rule_trust->file[i].process_name);
				free_valuestring(rule_trust->file[i].process_path);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->file[i].event_names[n].list);
				}
				sniper_free(rule_trust->file[i].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[i].event_num, POLICY_GET);
				sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_trust->file[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_trust->file[m].filename);
					free_valuestring(rule_trust->file[m].filepath);
					free_valuestring(rule_trust->file[m].extension);
					free_valuestring(rule_trust->file[m].md5);
					free_valuestring(rule_trust->file[m].process_name);
					free_valuestring(rule_trust->file[m].process_path);
					for (n = 0; n < rule_trust->file[m].event_num; n++) {
						free_valuestring(rule_trust->file[m].event_names[n].list);
					}
					sniper_free(rule_trust->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_trust->file[i].filename);
				free_valuestring(rule_trust->file[i].filepath);
				free_valuestring(rule_trust->file[i].extension);
				free_valuestring(rule_trust->file[i].md5);
				free_valuestring(rule_trust->file[i].process_name);
				free_valuestring(rule_trust->file[i].process_path);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->file[i].event_names[n].list);
				}
				sniper_free(rule_trust->file[i].event_names, sizeof(struct _POLICY_LIST)*rule_trust->file[i].event_num, POLICY_GET);
				sniper_free(rule_trust->file, sizeof(struct _TRUST_FILE)*rule_trust->file_num, POLICY_GET);
				return -1;
			}
			rule_trust->file[i].event_names[j].list = buf;
			rule_trust->file[i].event_flags |= event2flag(arrayList->valuestring);

		}
	}

	return 0;
}

static int get_rule_trust_ip(cJSON *ip, struct _RULE_TRUST *rule_trust)
{
	cJSON *event_names, *ip_list, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(ip);
	rule_trust->ip_num = count;
	rule_trust->ip = (struct _TRUST_IP *)sniper_malloc(sizeof(struct _TRUST_IP)*count, POLICY_GET);
        if (rule_trust->ip == NULL) {
                MON_ERROR("rule cJSON_Parse trust ip malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(ip, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem trust ip[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_trust->ip[m].ip_num; n++) {
					free_valuestring(rule_trust->ip[m].ip_list[n].list);
				}
				sniper_free(rule_trust->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_trust->ip[m].event_num; n++) {
					free_valuestring(rule_trust->ip[m].event_names[n].list);
				}
				sniper_free(rule_trust->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->ip, sizeof(struct _TRUST_IP)*rule_trust->ip_num, POLICY_GET);
                        return -1;
                }

		ip_list = cJSON_GetObjectItem(arrayItem, "ip_list");
		if (!ip_list) {
			MON_ERROR("rule cJSON_Parse trust ip[%d] ip_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_trust->ip[m].ip_num; n++) {
					free_valuestring(rule_trust->ip[m].ip_list[n].list);
				}
				sniper_free(rule_trust->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_trust->ip[m].event_num; n++) {
					free_valuestring(rule_trust->ip[m].event_names[n].list);
				}
				sniper_free(rule_trust->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->ip, sizeof(struct _TRUST_IP)*rule_trust->ip_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(ip_list);
		rule_trust->ip[i].ip_num = num;
		rule_trust->ip[i].ip_list = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_trust->ip[i].ip_list == NULL) {
			MON_ERROR("rule cJSON_Parse trust ip[%d] ip_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_trust->ip[m].ip_num; n++) {
					free_valuestring(rule_trust->ip[m].ip_list[n].list);
				}
				sniper_free(rule_trust->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_trust->ip[m].event_num; n++) {
					free_valuestring(rule_trust->ip[m].event_names[n].list);
				}
				sniper_free(rule_trust->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->ip, sizeof(struct _TRUST_IP)*rule_trust->ip_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(ip_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem trust ip[%d] ip_list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_trust->ip[m].ip_num; n++) {
						free_valuestring(rule_trust->ip[m].ip_list[n].list);
					}
					sniper_free(rule_trust->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_trust->ip[m].event_num; n++) {
						free_valuestring(rule_trust->ip[m].event_names[n].list);
					}
					sniper_free(rule_trust->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->ip[i].ip_list[n].list);
				}
				sniper_free(rule_trust->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[i].ip_num, POLICY_GET);
				sniper_free(rule_trust->ip, sizeof(struct _TRUST_IP)*rule_trust->ip_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_trust->ip[%d].ip_list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_trust->ip[m].ip_num; n++) {
						free_valuestring(rule_trust->ip[m].ip_list[n].list);
					}
					sniper_free(rule_trust->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_trust->ip[m].event_num; n++) {
						free_valuestring(rule_trust->ip[m].event_names[n].list);
					}
					sniper_free(rule_trust->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->ip[i].ip_list[n].list);
				}
				sniper_free(rule_trust->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[i].ip_num, POLICY_GET);
				sniper_free(rule_trust->ip, sizeof(struct _TRUST_IP)*rule_trust->ip_num, POLICY_GET);
				return -1;
			}
			rule_trust->ip[i].ip_list[j].list = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse trust ip[%d] event_names error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_trust->ip[m].ip_num; n++) {
					free_valuestring(rule_trust->ip[m].ip_list[n].list);
				}
				sniper_free(rule_trust->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_trust->ip[m].event_num; n++) {
					free_valuestring(rule_trust->ip[m].event_names[n].list);
				}
				sniper_free(rule_trust->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_trust->ip[i].ip_num; n++) {
				free_valuestring(rule_trust->ip[i].ip_list[n].list);
			}
			sniper_free(rule_trust->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[i].ip_num, POLICY_GET);
			sniper_free(rule_trust->ip, sizeof(struct _TRUST_IP)*rule_trust->ip_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_trust->ip[i].event_num = num;
		rule_trust->ip[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_trust->ip[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse trust ip[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_trust->ip[m].ip_num; n++) {
					free_valuestring(rule_trust->ip[m].ip_list[n].list);
				}
				sniper_free(rule_trust->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_trust->ip[m].event_num; n++) {
					free_valuestring(rule_trust->ip[m].event_names[n].list);
				}
				sniper_free(rule_trust->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_trust->ip[i].ip_num; n++) {
				free_valuestring(rule_trust->ip[i].ip_list[n].list);
			}
			sniper_free(rule_trust->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[i].ip_num, POLICY_GET);
			sniper_free(rule_trust->ip, sizeof(struct _TRUST_IP)*rule_trust->ip_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem trust ip[%d] event_names[%d]array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_trust->ip[m].ip_num; n++) {
						free_valuestring(rule_trust->ip[m].ip_list[n].list);
					}
					sniper_free(rule_trust->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_trust->ip[m].event_num; n++) {
						free_valuestring(rule_trust->ip[m].event_names[n].list);
					}
					sniper_free(rule_trust->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_trust->ip[i].ip_num; n++) {
					free_valuestring(rule_trust->ip[i].ip_list[n].list);
				}
				sniper_free(rule_trust->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[i].ip_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->ip[i].event_names[n].list);
				}
				sniper_free(rule_trust->ip[i].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[i].event_num, POLICY_GET);
				sniper_free(rule_trust->ip, sizeof(struct _TRUST_IP)*rule_trust->ip_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_trust->ip[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_trust->ip[m].ip_num; n++) {
						free_valuestring(rule_trust->ip[m].ip_list[n].list);
					}
					sniper_free(rule_trust->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_trust->ip[m].event_num; n++) {
						free_valuestring(rule_trust->ip[m].event_names[n].list);
					}
					sniper_free(rule_trust->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_trust->ip[i].ip_num; n++) {
					free_valuestring(rule_trust->ip[i].ip_list[n].list);
				}
				sniper_free(rule_trust->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_trust->ip[i].ip_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->ip[i].event_names[n].list);
				}
				sniper_free(rule_trust->ip[i].event_names, sizeof(struct _POLICY_LIST)*rule_trust->ip[i].event_num, POLICY_GET);
				sniper_free(rule_trust->ip, sizeof(struct _TRUST_IP)*rule_trust->ip_num, POLICY_GET);
				return -1;
			}
			rule_trust->ip[i].event_names[j].list = buf;
			rule_trust->ip[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_trust_domain(cJSON *domain, struct _RULE_TRUST *rule_trust)
{
	cJSON *event_names, *domain_list, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(domain);
	rule_trust->domain_num = count;
	rule_trust->domain = (struct _TRUST_DOMAIN *)sniper_malloc(sizeof(struct _TRUST_DOMAIN)*count, POLICY_GET);
        if (rule_trust->domain == NULL) {
                MON_ERROR("rule cJSON_Parse trust domain malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(domain, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem trust domain[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_trust->domain[m].domain_num; n++) {
					free_valuestring(rule_trust->domain[m].domain_list[n].list);
				}
				sniper_free(rule_trust->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_trust->domain[m].event_num; n++) {
					free_valuestring(rule_trust->domain[m].event_names[n].list);
				}
				sniper_free(rule_trust->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->domain, sizeof(struct _TRUST_DOMAIN)*rule_trust->domain_num, POLICY_GET);
                        return -1;
                }

		domain_list = cJSON_GetObjectItem(arrayItem, "domain_list");
		if (!domain_list) {
			MON_ERROR("rule cJSON_Parse trust domain[%d] domain_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_trust->domain[m].domain_num; n++) {
					free_valuestring(rule_trust->domain[m].domain_list[n].list);
				}
				sniper_free(rule_trust->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_trust->domain[m].event_num; n++) {
					free_valuestring(rule_trust->domain[m].event_names[n].list);
				}
				sniper_free(rule_trust->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->domain, sizeof(struct _TRUST_DOMAIN)*rule_trust->domain_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(domain_list);
		rule_trust->domain[i].domain_num = num;
		rule_trust->domain[i].domain_list = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_trust->domain[i].domain_list == NULL) {
			MON_ERROR("rule cJSON_Parse trust domain[%d] domain_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_trust->domain[m].domain_num; n++) {
					free_valuestring(rule_trust->domain[m].domain_list[n].list);
				}
				sniper_free(rule_trust->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_trust->domain[m].event_num; n++) {
					free_valuestring(rule_trust->domain[m].event_names[n].list);
				}
				sniper_free(rule_trust->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_trust->domain, sizeof(struct _TRUST_DOMAIN)*rule_trust->domain_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(domain_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem trust rule_list[%d] array error\n",i);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_trust->domain[m].domain_num; n++) {
						free_valuestring(rule_trust->domain[m].domain_list[n].list);
					}
					sniper_free(rule_trust->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_trust->domain[m].event_num; n++) {
						free_valuestring(rule_trust->domain[m].event_names[n].list);
					}
					sniper_free(rule_trust->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->domain[i].domain_list[n].list);
				}
				sniper_free(rule_trust->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[i].domain_num, POLICY_GET);
				sniper_free(rule_trust->domain, sizeof(struct _TRUST_DOMAIN)*rule_trust->domain_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_trust->domain[%d].domain_list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_trust->domain[m].domain_num; n++) {
						free_valuestring(rule_trust->domain[m].domain_list[n].list);
					}
					sniper_free(rule_trust->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_trust->domain[m].event_num; n++) {
						free_valuestring(rule_trust->domain[m].event_names[n].list);
					}
					sniper_free(rule_trust->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->domain[i].domain_list[n].list);
				}
				sniper_free(rule_trust->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[i].domain_num, POLICY_GET);
				sniper_free(rule_trust->domain, sizeof(struct _TRUST_DOMAIN)*rule_trust->domain_num, POLICY_GET);
				return -1;
			}
			rule_trust->domain[i].domain_list[j].list = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse trust domain[%d] event_names error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_trust->domain[m].domain_num; n++) {
					free_valuestring(rule_trust->domain[m].domain_list[n].list);
				}
				sniper_free(rule_trust->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_trust->domain[m].event_num; n++) {
					free_valuestring(rule_trust->domain[m].event_names[n].list);
				}
				sniper_free(rule_trust->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_trust->domain[i].domain_num; n++) {
				free_valuestring(rule_trust->domain[i].domain_list[n].list);
			}
			sniper_free(rule_trust->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[i].domain_num, POLICY_GET);
			sniper_free(rule_trust->domain, sizeof(struct _TRUST_DOMAIN)*rule_trust->domain_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_trust->domain[i].event_num = num;
		rule_trust->domain[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_trust->domain[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse trust domain[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_trust->domain[m].domain_num; n++) {
					free_valuestring(rule_trust->domain[m].domain_list[n].list);
				}
				sniper_free(rule_trust->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_trust->domain[m].event_num; n++) {
					free_valuestring(rule_trust->domain[m].event_names[n].list);
				}
				sniper_free(rule_trust->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_trust->domain[i].domain_num; n++) {
				free_valuestring(rule_trust->domain[i].domain_list[n].list);
			}
			sniper_free(rule_trust->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[i].domain_num, POLICY_GET);
			sniper_free(rule_trust->domain, sizeof(struct _TRUST_DOMAIN)*rule_trust->domain_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem trust domain[%d] event_names[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_trust->domain[m].domain_num; n++) {
						free_valuestring(rule_trust->domain[m].domain_list[n].list);
					}
					sniper_free(rule_trust->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_trust->domain[m].event_num; n++) {
						free_valuestring(rule_trust->domain[m].event_names[n].list);
					}
					sniper_free(rule_trust->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_trust->domain[i].domain_num; n++) {
					free_valuestring(rule_trust->domain[i].domain_list[n].list);
				}
				sniper_free(rule_trust->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[i].domain_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->domain[i].event_names[n].list);
				}
				sniper_free(rule_trust->domain[i].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[i].event_num, POLICY_GET);
				sniper_free(rule_trust->domain, sizeof(struct _TRUST_DOMAIN)*rule_trust->domain_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_trust->domain[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_trust->domain[m].domain_num; n++) {
						free_valuestring(rule_trust->domain[m].domain_list[n].list);
					}
					sniper_free(rule_trust->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_trust->domain[m].event_num; n++) {
						free_valuestring(rule_trust->domain[m].event_names[n].list);
					}
					sniper_free(rule_trust->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_trust->domain[i].domain_num; n++) {
					free_valuestring(rule_trust->domain[i].domain_list[n].list);
				}
				sniper_free(rule_trust->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_trust->domain[i].domain_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_trust->domain[i].event_names[n].list);
				}
				sniper_free(rule_trust->domain[i].event_names, sizeof(struct _POLICY_LIST)*rule_trust->domain[i].event_num, POLICY_GET);
				sniper_free(rule_trust->domain, sizeof(struct _TRUST_DOMAIN)*rule_trust->domain_num, POLICY_GET);
				return -1;
			}
			rule_trust->domain[i].event_names[j].list = buf;
			rule_trust->domain[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_trust(cJSON *data, struct _RULE_TRUST *rule_trust)
{
	cJSON *trust;
	cJSON *process, *file, *ip, *domain;

	trust = cJSON_GetObjectItem(data, "trust");
	if (!trust) {
		MON_ERROR("conf cJSON_Parse trust error\n");
		return -1;
	}

	process = cJSON_GetObjectItem(trust, "process");
	if (!process) {
		MON_ERROR("rule cJSON_Parse trust process error\n");
		rule_trust->process_num  = 0;
	} else {
		if (get_rule_trust_process(process, rule_trust) < 0) {
			rule_trust->process_num  = 0;
		}
	}

	file = cJSON_GetObjectItem(trust, "file");
	if (!file) {
		MON_ERROR("rule cJSON_Parse trust file error\n");
		rule_trust->file_num = 0;
	} else {
		if (get_rule_trust_file(file, rule_trust) < 0) {
			rule_trust->file_num = 0;
		}
	}

	ip = cJSON_GetObjectItem(trust, "ip");
	if (!ip) {
		MON_ERROR("rule cJSON_Parse trust ip error\n");
		rule_trust->ip_num = 0;
	} else {
		if (get_rule_trust_ip(ip, rule_trust) < 0) {
			rule_trust->ip_num = 0;
		}
	}

	domain = cJSON_GetObjectItem(trust, "domain");
	if (!domain) {
		MON_ERROR("rule cJSON_Parse trust domain error\n");
		rule_trust->domain_num = 0;
	} else {
		if (get_rule_trust_domain(domain, rule_trust) < 0) {
			rule_trust->domain_num = 0;
		}
	}

	return 0;
}

static int get_rule_filter_process(cJSON *process, struct _RULE_FILTER *rule_filter)
{
	cJSON *process_name, *process_path, *process_commandline, *param;
	cJSON *md5, *process_user, *parent_process_name, *remote_ip;
	cJSON *event_names, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	num = cJSON_GetArraySize(process);
	rule_filter->process_num = num;
	rule_filter->process = (struct _FILTER_PROCESS *)sniper_malloc(sizeof(struct _FILTER_PROCESS)*num, POLICY_GET);
	if (rule_filter->process == NULL) {
		MON_ERROR("rule cJSON_Parse filter process malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(process, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem filter rule_list[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		process_name = cJSON_GetObjectItem(arrayItem, "process_name");
		if (!process_name) {
			MON_ERROR("rule cJSON_Parse filter process process_name error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_name);
		if (buf == NULL) {
			MON_ERROR("rule_filter->process[%d].process_name malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}
		rule_filter->process[i].process_name = buf;

		process_path = cJSON_GetObjectItem(arrayItem, "process_path");
		if (!process_path) {
			MON_ERROR("rule cJSON_Parse filter process process_path error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_path);
		if (buf == NULL) {
			MON_ERROR("rule_filter->process[%d].process_path malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}
		rule_filter->process[i].process_path = buf;

		process_commandline = cJSON_GetObjectItem(arrayItem, "process_commandline");
		if (!process_commandline) {
			MON_ERROR("rule cJSON_Parse filter process process_commandline error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_commandline);
		if (buf == NULL) {
			MON_ERROR("rule_filter->process[%d].process_commandline malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}
		rule_filter->process[i].process_commandline = buf;

		param = cJSON_GetObjectItem(arrayItem, "param");
		if (!param) {
			MON_ERROR("rule cJSON_Parse filter process param error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(param);
		if (buf == NULL) {
			MON_ERROR("rule_filter->process[%d].param malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}
		rule_filter->process[i].param = buf;

		md5 = cJSON_GetObjectItem(arrayItem, "md5");
		if (!md5) {
			MON_ERROR("rule cJSON_Parse filter process md5 error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			free_valuestring(rule_filter->process[i].param);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(md5);
		if (buf == NULL) {
			MON_ERROR("rule_filter->process[%d].md5 malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			free_valuestring(rule_filter->process[i].param);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}
		rule_filter->process[i].md5 = buf;

		process_user = cJSON_GetObjectItem(arrayItem, "process_user");
		if (!process_user) {
			MON_ERROR("rule cJSON_Parse filter process process_user error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			free_valuestring(rule_filter->process[i].param);
			free_valuestring(rule_filter->process[i].md5);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_user);
		if (buf == NULL) {
			MON_ERROR("rule_filter->process[%d].process_user malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			free_valuestring(rule_filter->process[i].param);
			free_valuestring(rule_filter->process[i].md5);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}
		rule_filter->process[i].process_user = buf;

		parent_process_name = cJSON_GetObjectItem(arrayItem, "parent_process_name");
		if (!parent_process_name) {
			MON_ERROR("rule cJSON_Parse filter process parent_process_name error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			free_valuestring(rule_filter->process[i].param);
			free_valuestring(rule_filter->process[i].md5);
			free_valuestring(rule_filter->process[i].process_user);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(parent_process_name);
		if (buf == NULL) {
			MON_ERROR("rule_filter->filter.process[%d].parent_process_name malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			free_valuestring(rule_filter->process[i].param);
			free_valuestring(rule_filter->process[i].md5);
			free_valuestring(rule_filter->process[i].process_user);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}
		rule_filter->process[i].parent_process_name = buf;

		remote_ip = cJSON_GetObjectItem(arrayItem, "remote_ip");
		if (!remote_ip) {
			MON_ERROR("rule cJSON_Parse filter process remote_ip error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			free_valuestring(rule_filter->process[i].param);
			free_valuestring(rule_filter->process[i].md5);
			free_valuestring(rule_filter->process[i].process_user);
			free_valuestring(rule_filter->process[i].parent_process_name);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(remote_ip);
		if (buf == NULL) {
			MON_ERROR("rule_filter->process[%d].remote_ip malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			free_valuestring(rule_filter->process[i].param);
			free_valuestring(rule_filter->process[i].md5);
			free_valuestring(rule_filter->process[i].process_user);
			free_valuestring(rule_filter->process[i].parent_process_name);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}
		rule_filter->process[i].remote_ip = buf;

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse filter process event_names error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			free_valuestring(rule_filter->process[i].param);
			free_valuestring(rule_filter->process[i].md5);
			free_valuestring(rule_filter->process[i].process_user);
			free_valuestring(rule_filter->process[i].parent_process_name);
			free_valuestring(rule_filter->process[i].remote_ip);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		count = cJSON_GetArraySize(event_names);
		rule_filter->process[i].event_num = count;
		rule_filter->process[i].event_names = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*count, POLICY_GET);
		if (rule_filter->process[i].event_names == NULL) {
			MON_ERROR("rule_filter->process[%d].event_names[%d].list malloc failed\n", i, j);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->process[m].process_name);
				free_valuestring(rule_filter->process[m].process_path);
				free_valuestring(rule_filter->process[m].process_commandline);
				free_valuestring(rule_filter->process[m].param);
				free_valuestring(rule_filter->process[m].md5);
				free_valuestring(rule_filter->process[m].process_user);
				free_valuestring(rule_filter->process[m].parent_process_name);
				free_valuestring(rule_filter->process[m].remote_ip);
				for (n = 0; n < rule_filter->process[m].event_num; n++) {
					free_valuestring(rule_filter->process[m].event_names[n].list);
				}
				sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->process[i].process_name);
			free_valuestring(rule_filter->process[i].process_path);
			free_valuestring(rule_filter->process[i].process_commandline);
			free_valuestring(rule_filter->process[i].param);
			free_valuestring(rule_filter->process[i].md5);
			free_valuestring(rule_filter->process[i].process_user);
			free_valuestring(rule_filter->process[i].parent_process_name);
			free_valuestring(rule_filter->process[i].remote_ip);
			sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < count; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("rule_filter->process[%d].event_names[%d].list\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_filter->process[m].process_name);
					free_valuestring(rule_filter->process[m].process_path);
					free_valuestring(rule_filter->process[m].process_commandline);
					free_valuestring(rule_filter->process[m].param);
					free_valuestring(rule_filter->process[m].md5);
					free_valuestring(rule_filter->process[m].process_user);
					free_valuestring(rule_filter->process[m].parent_process_name);
					free_valuestring(rule_filter->process[m].remote_ip);
					for (n = 0; n < rule_filter->process[m].event_num; n++) {
						free_valuestring(rule_filter->process[m].event_names[n].list);
					}
					sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_filter->process[i].process_name);
				free_valuestring(rule_filter->process[i].process_path);
				free_valuestring(rule_filter->process[i].process_commandline);
				free_valuestring(rule_filter->process[i].param);
				free_valuestring(rule_filter->process[i].md5);
				free_valuestring(rule_filter->process[i].process_user);
				free_valuestring(rule_filter->process[i].parent_process_name);
				free_valuestring(rule_filter->process[i].remote_ip);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_filter->process[i].event_names[n].list);
				}
				sniper_free(rule_filter->process[i].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[i].event_num, POLICY_GET);
				sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_filter->process[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_filter->process[m].process_name);
					free_valuestring(rule_filter->process[m].process_path);
					free_valuestring(rule_filter->process[m].process_commandline);
					free_valuestring(rule_filter->process[m].param);
					free_valuestring(rule_filter->process[m].md5);
					free_valuestring(rule_filter->process[m].process_user);
					free_valuestring(rule_filter->process[m].parent_process_name);
					free_valuestring(rule_filter->process[m].remote_ip);
					for (n = 0; n < rule_filter->process[m].event_num; n++) {
						free_valuestring(rule_filter->process[m].event_names[n].list);
					}
					sniper_free(rule_filter->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_filter->process[i].process_name);
				free_valuestring(rule_filter->process[i].process_path);
				free_valuestring(rule_filter->process[i].process_commandline);
				free_valuestring(rule_filter->process[i].param);
				free_valuestring(rule_filter->process[i].md5);
				free_valuestring(rule_filter->process[i].process_user);
				free_valuestring(rule_filter->process[i].parent_process_name);
				free_valuestring(rule_filter->process[i].remote_ip);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_filter->process[i].event_names[n].list);
				}
				sniper_free(rule_filter->process[i].event_names, sizeof(struct _POLICY_LIST)*rule_filter->process[i].event_num, POLICY_GET);
				sniper_free(rule_filter->process, sizeof(struct _FILTER_PROCESS)*rule_filter->process_num, POLICY_GET);
				return -1;
			}
			rule_filter->process[i].event_names[j].list = buf;
			rule_filter->process[i].event_flags |= event2flag(arrayList->valuestring);
		}
	}

	return 0;
}

static int get_rule_filter_file(cJSON *file, struct _RULE_FILTER *rule_filter)
{
	cJSON *filename, *filepath, *extension, *md5, *process_name, *process_path;
	cJSON *event_names, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	num = cJSON_GetArraySize(file);
	rule_filter->file_num = num;
	rule_filter->file = (struct _FILTER_FILE *)sniper_malloc(sizeof(struct _FILTER_FILE)*num, POLICY_GET);
	if (rule_filter->file == NULL) {
		MON_ERROR("rule cJSON_Parse filter file malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(file, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem filter rule_list[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}

		filename = cJSON_GetObjectItem(arrayItem, "filename");
		if (!filename) {
			MON_ERROR("rule cJSON_Parse filter file filename error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(filename);
		if (buf == NULL) {
			MON_ERROR("rule_filter->file[%d].filename malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}
		rule_filter->file[i].filename = buf;

		filepath = cJSON_GetObjectItem(arrayItem, "filepath");
		if (!filepath) {
			MON_ERROR("rule cJSON_Parse filter file filepath error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->file[i].filename);
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(filepath);
		if (buf == NULL) {
			MON_ERROR("rule_filter->file[%d].filepath malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->file[i].filename);
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}
		rule_filter->file[i].filepath = buf;

		extension = cJSON_GetObjectItem(arrayItem, "extension");
		if (!extension) {
			MON_ERROR("rule cJSON_Parse filter file extension error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->file[i].filename);
			free_valuestring(rule_filter->file[i].filepath);
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(extension);
		if (buf == NULL) {
			MON_ERROR("rule_filter->file[%d].extension malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->file[i].filename);
			free_valuestring(rule_filter->file[i].filepath);
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}
		rule_filter->file[i].extension = buf;

		md5 = cJSON_GetObjectItem(arrayItem, "md5");
		if (!md5) {
			MON_ERROR("rule cJSON_Parse filter file md5 error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->file[i].filename);
			free_valuestring(rule_filter->file[i].filepath);
			free_valuestring(rule_filter->file[i].extension);
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(md5);
		if (buf == NULL) {
			MON_ERROR("rule_filter->file[%d].md5 malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->file[i].filename);
			free_valuestring(rule_filter->file[i].filepath);
			free_valuestring(rule_filter->file[i].extension);
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}
		rule_filter->file[i].md5 = buf;

		/*
		 * 5.0.9新增的字段，和旧版本保持兼容，
		 * 没有该字段不报错退出，也开辟一个字节的空间, 方便后续使用和空间释放
		 */
		process_name = cJSON_GetObjectItem(arrayItem, "process_name");
		if (!process_name) {
			MON_WARNING("rule cJSON_Parse filter file process_name error\n");
			buf = get_customize_valuestring();
		} else {
			buf = get_my_valuestring(process_name);
		}
		if (buf == NULL) {
			MON_ERROR("rule_filter->file[%d].process_name malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, 
						sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->file[i].filename);
			free_valuestring(rule_filter->file[i].filepath);
			free_valuestring(rule_filter->file[i].extension);
			free_valuestring(rule_filter->file[i].md5);
			sniper_free(rule_filter->file, 
					sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}
		rule_filter->file[i].process_name = buf;

		/*
		 * 5.0.9新增的字段，和旧版本保持兼容，
		 * 没有该字段不报错退出，也开辟一个字节的空间, 方便后续使用和空间释放
		 */
		process_path = cJSON_GetObjectItem(arrayItem, "process_path");
		if (!process_path) {
			MON_WARNING("rule cJSON_Parse filter file process_path error\n");
			buf = get_customize_valuestring();
		}  else {
			buf = get_my_valuestring(process_path);
		}
		if (buf == NULL) {
			MON_ERROR("rule_filter->file[%d].process_path malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, 
					sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->file[i].filename);
			free_valuestring(rule_filter->file[i].filepath);
			free_valuestring(rule_filter->file[i].extension);
			free_valuestring(rule_filter->file[i].md5);
			free_valuestring(rule_filter->file[i].process_name);
			sniper_free(rule_filter->file, 
					sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}
		rule_filter->file[i].process_path = buf;

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse filter file event_names error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->file[i].filename);
			free_valuestring(rule_filter->file[i].filepath);
			free_valuestring(rule_filter->file[i].extension);
			free_valuestring(rule_filter->file[i].md5);
			free_valuestring(rule_filter->file[i].process_name);
			free_valuestring(rule_filter->file[i].process_path);
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}

		count = cJSON_GetArraySize(event_names);
		rule_filter->file[i].event_num = count;
		rule_filter->file[i].event_names = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*count, POLICY_GET);
		if (rule_filter->file[i].event_names == NULL) {
			MON_ERROR("rule_filter->file[%d].event_names[%d].list malloc failed\n", i, j);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_filter->file[m].filename);
				free_valuestring(rule_filter->file[m].filepath);
				free_valuestring(rule_filter->file[m].extension);
				free_valuestring(rule_filter->file[m].md5);
				free_valuestring(rule_filter->file[m].process_name);
				free_valuestring(rule_filter->file[m].process_path);
				for (n = 0; n < rule_filter->file[m].event_num; n++) {
					free_valuestring(rule_filter->file[m].event_names[n].list);
				}
				sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_filter->file[i].filename);
			free_valuestring(rule_filter->file[i].filepath);
			free_valuestring(rule_filter->file[i].extension);
			free_valuestring(rule_filter->file[i].md5);
			free_valuestring(rule_filter->file[i].process_name);
			free_valuestring(rule_filter->file[i].process_path);
			sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < count; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("rule_filter->file[%d].event_names[%d].list\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_filter->file[m].filename);
					free_valuestring(rule_filter->file[m].filepath);
					free_valuestring(rule_filter->file[m].extension);
					free_valuestring(rule_filter->file[m].md5);
					free_valuestring(rule_filter->file[m].process_name);
					free_valuestring(rule_filter->file[m].process_path);
					for (n = 0; n < rule_filter->file[m].event_num; n++) {
						free_valuestring(rule_filter->file[m].event_names[n].list);
					}
					sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_filter->file[i].filename);
				free_valuestring(rule_filter->file[i].filepath);
				free_valuestring(rule_filter->file[i].extension);
				free_valuestring(rule_filter->file[i].md5);
				free_valuestring(rule_filter->file[i].process_name);
				free_valuestring(rule_filter->file[i].process_path);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_filter->file[i].event_names[n].list);
				}
				sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_filter->file[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_filter->file[m].filename);
					free_valuestring(rule_filter->file[m].filepath);
					free_valuestring(rule_filter->file[m].extension);
					free_valuestring(rule_filter->file[m].md5);
					free_valuestring(rule_filter->file[m].process_name);
					free_valuestring(rule_filter->file[m].process_path);
					for (n = 0; n < rule_filter->file[m].event_num; n++) {
						free_valuestring(rule_filter->file[m].event_names[n].list);
					}
					sniper_free(rule_filter->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->file[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_filter->file[i].filename);
				free_valuestring(rule_filter->file[i].filepath);
				free_valuestring(rule_filter->file[i].extension);
				free_valuestring(rule_filter->file[i].md5);
				free_valuestring(rule_filter->file[i].process_name);
				free_valuestring(rule_filter->file[i].process_path);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_filter->file[i].event_names[n].list);
				}
				sniper_free(rule_filter->file, sizeof(struct _FILTER_FILE)*rule_filter->file_num, POLICY_GET);
				return -1;
			}
			rule_filter->file[i].event_names[j].list = buf;
			rule_filter->file[i].event_flags |= event2flag(arrayList->valuestring);

		}
	}

	return 0;
}

static int get_rule_filter_ip(cJSON *ip, struct _RULE_FILTER *rule_filter)
{
	cJSON *event_names, *ip_list, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(ip);
	rule_filter->ip_num = count;
	rule_filter->ip = (struct _FILTER_IP *)sniper_malloc(sizeof(struct _FILTER_IP)*count, POLICY_GET);
        if (rule_filter->ip == NULL) {
                MON_ERROR("rule cJSON_Parse filter ip malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(ip, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem filter ip[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_filter->ip[m].ip_num; n++) {
					free_valuestring(rule_filter->ip[m].ip_list[n].list);
				}
				sniper_free(rule_filter->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_filter->ip[m].event_num; n++) {
					free_valuestring(rule_filter->ip[m].event_names[n].list);
				}
				sniper_free(rule_filter->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->ip, sizeof(struct _FILTER_IP)*rule_filter->ip_num, POLICY_GET);
                        return -1;
                }

		ip_list = cJSON_GetObjectItem(arrayItem, "ip_list");
		if (!ip_list) {
			MON_ERROR("rule cJSON_Parse filter ip[%d] ip_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_filter->ip[m].ip_num; n++) {
					free_valuestring(rule_filter->ip[m].ip_list[n].list);
				}
				sniper_free(rule_filter->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_filter->ip[m].event_num; n++) {
					free_valuestring(rule_filter->ip[m].event_names[n].list);
				}
				sniper_free(rule_filter->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->ip, sizeof(struct _FILTER_IP)*rule_filter->ip_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(ip_list);
		rule_filter->ip[i].ip_num = num;
		rule_filter->ip[i].ip_list = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_filter->ip[i].ip_list == NULL) {
			MON_ERROR("rule cJSON_Parse filter ip[%d] ip_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_filter->ip[m].ip_num; n++) {
					free_valuestring(rule_filter->ip[m].ip_list[n].list);
				}
				sniper_free(rule_filter->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_filter->ip[m].event_num; n++) {
					free_valuestring(rule_filter->ip[m].event_names[n].list);
				}
				sniper_free(rule_filter->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->ip, sizeof(struct _FILTER_IP)*rule_filter->ip_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(ip_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem filter ip[%d] ip_list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_filter->ip[m].ip_num; n++) {
						free_valuestring(rule_filter->ip[m].ip_list[n].list);
					}
					sniper_free(rule_filter->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_filter->ip[m].event_num; n++) {
						free_valuestring(rule_filter->ip[m].event_names[n].list);
					}
					sniper_free(rule_filter->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_filter->ip[i].ip_list[n].list);
				}
				sniper_free(rule_filter->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[i].ip_num, POLICY_GET);
				sniper_free(rule_filter->ip, sizeof(struct _FILTER_IP)*rule_filter->ip_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_filter->ip[%d].ip_list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_filter->ip[m].ip_num; n++) {
						free_valuestring(rule_filter->ip[m].ip_list[n].list);
					}
					sniper_free(rule_filter->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_filter->ip[m].event_num; n++) {
						free_valuestring(rule_filter->ip[m].event_names[n].list);
					}
					sniper_free(rule_filter->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_filter->ip[i].ip_list[n].list);
				}
				sniper_free(rule_filter->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[i].ip_num, POLICY_GET);
				sniper_free(rule_filter->ip, sizeof(struct _FILTER_IP)*rule_filter->ip_num, POLICY_GET);
				return -1;
			}
			rule_filter->ip[i].ip_list[j].list = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse filter ip[%d] event_names error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_filter->ip[m].ip_num; n++) {
					free_valuestring(rule_filter->ip[m].ip_list[n].list);
				}
				sniper_free(rule_filter->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_filter->ip[m].event_num; n++) {
					free_valuestring(rule_filter->ip[m].event_names[n].list);
				}
				sniper_free(rule_filter->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_filter->ip[i].ip_num; n++) {
				free_valuestring(rule_filter->ip[i].ip_list[n].list);
			}
			sniper_free(rule_filter->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[i].ip_num, POLICY_GET);
			sniper_free(rule_filter->ip, sizeof(struct _FILTER_IP)*rule_filter->ip_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_filter->ip[i].event_num = num;
		rule_filter->ip[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_filter->ip[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse filter ip[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_filter->ip[m].ip_num; n++) {
					free_valuestring(rule_filter->ip[m].ip_list[n].list);
				}
				sniper_free(rule_filter->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_filter->ip[m].event_num; n++) {
					free_valuestring(rule_filter->ip[m].event_names[n].list);
				}
				sniper_free(rule_filter->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_filter->ip[i].ip_num; n++) {
				free_valuestring(rule_filter->ip[i].ip_list[n].list);
			}
			sniper_free(rule_filter->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[i].ip_num, POLICY_GET);
			sniper_free(rule_filter->ip, sizeof(struct _FILTER_IP)*rule_filter->ip_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem filter ip[%d] event_names[%d]array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_filter->ip[m].ip_num; n++) {
						free_valuestring(rule_filter->ip[m].ip_list[n].list);
					}
					sniper_free(rule_filter->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_filter->ip[m].event_num; n++) {
						free_valuestring(rule_filter->ip[m].event_names[n].list);
					}
					sniper_free(rule_filter->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_filter->ip[i].ip_num; n++) {
					free_valuestring(rule_filter->ip[i].ip_list[n].list);
				}
				sniper_free(rule_filter->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[i].ip_num, POLICY_GET);
				for (n = 0; n < rule_filter->ip[i].event_num; n++) {
					free_valuestring(rule_filter->ip[i].event_names[n].list);
				}
				sniper_free(rule_filter->ip[i].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[i].event_num, POLICY_GET);
				sniper_free(rule_filter->ip, sizeof(struct _FILTER_IP)*rule_filter->ip_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_filter->ip[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_filter->ip[m].ip_num; n++) {
						free_valuestring(rule_filter->ip[m].ip_list[n].list);
					}
					sniper_free(rule_filter->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_filter->ip[m].event_num; n++) {
						free_valuestring(rule_filter->ip[m].event_names[n].list);
					}
					sniper_free(rule_filter->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_filter->ip[i].ip_num; n++) {
					free_valuestring(rule_filter->ip[i].ip_list[n].list);
				}
				sniper_free(rule_filter->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_filter->ip[i].ip_num, POLICY_GET);
				for (n = 0; n < rule_filter->ip[i].event_num; n++) {
					free_valuestring(rule_filter->ip[i].event_names[n].list);
				}
				sniper_free(rule_filter->ip[i].event_names, sizeof(struct _POLICY_LIST)*rule_filter->ip[i].event_num, POLICY_GET);
				sniper_free(rule_filter->ip, sizeof(struct _FILTER_IP)*rule_filter->ip_num, POLICY_GET);
				return -1;
			}
			rule_filter->ip[i].event_names[j].list = buf;
			rule_filter->ip[i].event_flags |= event2flag(arrayItem->valuestring);
		}
	}
	return 0;
}

static int get_rule_filter_domain(cJSON *domain, struct _RULE_FILTER *rule_filter)
{
	cJSON *event_names, *domain_list, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(domain);
	rule_filter->domain_num = count;
	rule_filter->domain = (struct _FILTER_DOMAIN *)sniper_malloc(sizeof(struct _FILTER_DOMAIN)*count, POLICY_GET);
        if (rule_filter->domain == NULL) {
                MON_ERROR("rule cJSON_Parse filter domain malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(domain, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem filter domain[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_filter->domain[m].domain_num; n++) {
					free_valuestring(rule_filter->domain[m].domain_list[n].list);
				}
				sniper_free(rule_filter->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_filter->domain[m].event_num; n++) {
					free_valuestring(rule_filter->domain[m].event_names[n].list);
				}
				sniper_free(rule_filter->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->domain, sizeof(struct _FILTER_DOMAIN)*rule_filter->domain_num, POLICY_GET);
                        return -1;
                }

		domain_list = cJSON_GetObjectItem(arrayItem, "domain_list");
		if (!domain_list) {
			MON_ERROR("rule cJSON_Parse filter domain[%d] domain_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_filter->domain[m].domain_num; n++) {
					free_valuestring(rule_filter->domain[m].domain_list[n].list);
				}
				sniper_free(rule_filter->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_filter->domain[m].event_num; n++) {
					free_valuestring(rule_filter->domain[m].event_names[n].list);
				}
				sniper_free(rule_filter->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->domain, sizeof(struct _FILTER_DOMAIN)*rule_filter->domain_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(domain_list);
		rule_filter->domain[i].domain_num = num;
		rule_filter->domain[i].domain_list = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_filter->domain[i].domain_list == NULL) {
			MON_ERROR("rule cJSON_Parse filter domain[%d] domain_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_filter->domain[m].domain_num; n++) {
					free_valuestring(rule_filter->domain[m].domain_list[n].list);
				}
				sniper_free(rule_filter->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_filter->domain[m].event_num; n++) {
					free_valuestring(rule_filter->domain[m].event_names[n].list);
				}
				sniper_free(rule_filter->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_filter->domain, sizeof(struct _FILTER_DOMAIN)*rule_filter->domain_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(domain_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem filter rule_list[%d] array error\n",i);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_filter->domain[m].domain_num; n++) {
						free_valuestring(rule_filter->domain[m].domain_list[n].list);
					}
					sniper_free(rule_filter->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_filter->domain[m].event_num; n++) {
						free_valuestring(rule_filter->domain[m].event_names[n].list);
					}
					sniper_free(rule_filter->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_filter->domain[i].domain_list[n].list);
				}
				sniper_free(rule_filter->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[i].domain_num, POLICY_GET);
				sniper_free(rule_filter->domain, sizeof(struct _FILTER_DOMAIN)*rule_filter->domain_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_filter->domain[%d].domain_list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_filter->domain[m].domain_num; n++) {
						free_valuestring(rule_filter->domain[m].domain_list[n].list);
					}
					sniper_free(rule_filter->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_filter->domain[m].event_num; n++) {
						free_valuestring(rule_filter->domain[m].event_names[n].list);
					}
					sniper_free(rule_filter->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_filter->domain[i].domain_list[n].list);
				}
				sniper_free(rule_filter->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[i].domain_num, POLICY_GET);
				sniper_free(rule_filter->domain, sizeof(struct _FILTER_DOMAIN)*rule_filter->domain_num, POLICY_GET);
				return -1;
			}
			rule_filter->domain[i].domain_list[j].list = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse filter domain[%d] event_names error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_filter->domain[m].domain_num; n++) {
					free_valuestring(rule_filter->domain[m].domain_list[n].list);
				}
				sniper_free(rule_filter->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_filter->domain[m].event_num; n++) {
					free_valuestring(rule_filter->domain[m].event_names[n].list);
				}
				sniper_free(rule_filter->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_filter->domain[i].domain_num; n++) {
				free_valuestring(rule_filter->domain[i].domain_list[n].list);
			}
			sniper_free(rule_filter->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[i].domain_num, POLICY_GET);
			sniper_free(rule_filter->domain, sizeof(struct _FILTER_DOMAIN)*rule_filter->domain_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_filter->domain[i].event_num = num;
		rule_filter->domain[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_filter->domain[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse filter domain[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_filter->domain[m].domain_num; n++) {
					free_valuestring(rule_filter->domain[m].domain_list[n].list);
				}
				sniper_free(rule_filter->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_filter->domain[m].event_num; n++) {
					free_valuestring(rule_filter->domain[m].event_names[n].list);
				}
				sniper_free(rule_filter->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_filter->domain[i].domain_num; n++) {
				free_valuestring(rule_filter->domain[i].domain_list[n].list);
			}
			sniper_free(rule_filter->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[i].domain_num, POLICY_GET);
			sniper_free(rule_filter->domain, sizeof(struct _FILTER_DOMAIN)*rule_filter->domain_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem filter domain[%d] event_names[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_filter->domain[m].domain_num; n++) {
						free_valuestring(rule_filter->domain[m].domain_list[n].list);
					}
					sniper_free(rule_filter->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_filter->domain[m].event_num; n++) {
						free_valuestring(rule_filter->domain[m].event_names[n].list);
					}
					sniper_free(rule_filter->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_filter->domain[i].domain_num; n++) {
					free_valuestring(rule_filter->domain[i].domain_list[n].list);
				}
				sniper_free(rule_filter->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[i].domain_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_filter->domain[i].event_names[n].list);
				}
				sniper_free(rule_filter->domain[i].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[i].event_num, POLICY_GET);
				sniper_free(rule_filter->domain, sizeof(struct _FILTER_DOMAIN)*rule_filter->domain_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_filter->domain[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_filter->domain[m].domain_num; n++) {
						free_valuestring(rule_filter->domain[m].domain_list[n].list);
					}
					sniper_free(rule_filter->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_filter->domain[m].event_num; n++) {
						free_valuestring(rule_filter->domain[m].event_names[n].list);
					}
					sniper_free(rule_filter->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_filter->domain[i].domain_num; n++) {
					free_valuestring(rule_filter->domain[i].domain_list[n].list);
				}
				sniper_free(rule_filter->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_filter->domain[i].domain_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_filter->domain[i].event_names[n].list);
				}
				sniper_free(rule_filter->domain[i].event_names, sizeof(struct _POLICY_LIST)*rule_filter->domain[i].event_num, POLICY_GET);
				sniper_free(rule_filter->domain, sizeof(struct _FILTER_DOMAIN)*rule_filter->domain_num, POLICY_GET);
				return -1;
			}
			rule_filter->domain[i].event_names[j].list = buf;
			rule_filter->domain[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_filter(cJSON *data, struct _RULE_FILTER *rule_filter)
{
	cJSON *filter;
	cJSON *process, *file, *ip, *domain;

	filter = cJSON_GetObjectItem(data, "filter");
	if (!filter) {
		MON_ERROR("conf cJSON_Parse filter error\n");
		return -1;
	}

	process = cJSON_GetObjectItem(filter, "process");
	if (!process) {
		MON_ERROR("rule cJSON_Parse filter process error\n");
		rule_filter->process_num  = 0;
	} else {
		if (get_rule_filter_process(process, rule_filter) < 0) {
			rule_filter->process_num  = 0;
		}
	}

	file = cJSON_GetObjectItem(filter, "file");
	if (!file) {
		MON_ERROR("rule cJSON_Parse filter file error\n");
		rule_filter->file_num = 0;
	} else {
		if (get_rule_filter_file(file, rule_filter) < 0) {
			rule_filter->file_num = 0;
		}
	}

	ip = cJSON_GetObjectItem(filter, "ip");
	if (!ip) {
		MON_ERROR("rule cJSON_Parse filter ip error\n");
		rule_filter->ip_num = 0;
	} else {
		if (get_rule_filter_ip(ip, rule_filter) < 0) {
			rule_filter->ip_num = 0;
		}
	}

	domain = cJSON_GetObjectItem(filter, "domain");
	if (!domain) {
		MON_ERROR("rule cJSON_Parse filter domain error\n");
		rule_filter->domain_num = 0;
	} else {
		if (get_rule_filter_domain(domain, rule_filter) < 0) {
			rule_filter->domain_num = 0;
		}
	}

	return 0;
}

static int get_rule_black_process(cJSON *process, struct _RULE_BLACK *rule_black)
{
	cJSON *process_name, *process_path, *process_commandline, *param;
	cJSON *md5, *process_user, *parent_process_name, *remote_ip;
	cJSON *event_names, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	num = cJSON_GetArraySize(process);
	rule_black->process_num = num;
	rule_black->process = (struct _BLACK_PROCESS *)sniper_malloc(sizeof(struct _BLACK_PROCESS)*num, POLICY_GET);
	if (rule_black->process == NULL) {
		MON_ERROR("rule cJSON_Parse black process malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(process, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem black rule_list[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		process_name = cJSON_GetObjectItem(arrayItem, "process_name");
		if (!process_name) {
			MON_ERROR("rule cJSON_Parse black process process_name error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_name);
		if (buf == NULL) {
			MON_ERROR("rule_black->process[%d].process_name malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}
		rule_black->process[i].process_name = buf;

		process_path = cJSON_GetObjectItem(arrayItem, "process_path");
		if (!process_path) {
			MON_ERROR("rule cJSON_Parse black process process_path error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_path);
		if (buf == NULL) {
			MON_ERROR("rule_black->process[%d].process_path malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}
		rule_black->process[i].process_path = buf;

		process_commandline = cJSON_GetObjectItem(arrayItem, "process_commandline");
		if (!process_commandline) {
			MON_ERROR("rule cJSON_Parse black process process_commandline error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_commandline);
		if (buf == NULL) {
			MON_ERROR("rule_black->process[%d].process_commandline malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}
		rule_black->process[i].process_commandline = buf;

		param = cJSON_GetObjectItem(arrayItem, "param");
		if (!param) {
			MON_ERROR("rule cJSON_Parse black process param error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(param);
		if (buf == NULL) {
			MON_ERROR("rule_black->process[%d].param malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}
		rule_black->process[i].param = buf;

		md5 = cJSON_GetObjectItem(arrayItem, "md5");
		if (!md5) {
			MON_ERROR("rule cJSON_Parse black process md5 error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			free_valuestring(rule_black->process[i].param);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(md5);
		if (buf == NULL) {
			MON_ERROR("rule_black->process[%d].md5 malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			free_valuestring(rule_black->process[i].param);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}
		rule_black->process[i].md5 = buf;

		process_user = cJSON_GetObjectItem(arrayItem, "process_user");
		if (!process_user) {
			MON_ERROR("rule cJSON_Parse black process process_user error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			free_valuestring(rule_black->process[i].param);
			free_valuestring(rule_black->process[i].md5);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(process_user);
		if (buf == NULL) {
			MON_ERROR("rule_black->process[%d].process_user malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			free_valuestring(rule_black->process[i].param);
			free_valuestring(rule_black->process[i].md5);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}
		rule_black->process[i].process_user = buf;

		parent_process_name = cJSON_GetObjectItem(arrayItem, "parent_process_name");
		if (!parent_process_name) {
			MON_ERROR("rule cJSON_Parse black process parent_process_name error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			free_valuestring(rule_black->process[i].param);
			free_valuestring(rule_black->process[i].md5);
			free_valuestring(rule_black->process[i].process_user);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(parent_process_name);
		if (buf == NULL) {
			MON_ERROR("rule_black->black.process[%d].parent_process_name malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			free_valuestring(rule_black->process[i].param);
			free_valuestring(rule_black->process[i].md5);
			free_valuestring(rule_black->process[i].process_user);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}
		rule_black->process[i].parent_process_name = buf;

		remote_ip = cJSON_GetObjectItem(arrayItem, "remote_ip");
		if (!remote_ip) {
			MON_ERROR("rule cJSON_Parse black process remote_ip error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			free_valuestring(rule_black->process[i].param);
			free_valuestring(rule_black->process[i].md5);
			free_valuestring(rule_black->process[i].process_user);
			free_valuestring(rule_black->process[i].parent_process_name);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(remote_ip);
		if (buf == NULL) {
			MON_ERROR("rule_black->process[%d].remote_ip malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			free_valuestring(rule_black->process[i].param);
			free_valuestring(rule_black->process[i].md5);
			free_valuestring(rule_black->process[i].process_user);
			free_valuestring(rule_black->process[i].parent_process_name);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}
		rule_black->process[i].remote_ip = buf;

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse black process event_names error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			free_valuestring(rule_black->process[i].param);
			free_valuestring(rule_black->process[i].md5);
			free_valuestring(rule_black->process[i].process_user);
			free_valuestring(rule_black->process[i].parent_process_name);
			free_valuestring(rule_black->process[i].remote_ip);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		count = cJSON_GetArraySize(event_names);
		rule_black->process[i].event_num = count;
		rule_black->process[i].event_names = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*count, POLICY_GET);
		if (rule_black->process[i].event_names == NULL) {
			MON_ERROR("rule_black->process[%d].event_names[%d].list malloc failed\n", i, j);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->process[m].process_name);
				free_valuestring(rule_black->process[m].process_path);
				free_valuestring(rule_black->process[m].process_commandline);
				free_valuestring(rule_black->process[m].param);
				free_valuestring(rule_black->process[m].md5);
				free_valuestring(rule_black->process[m].process_user);
				free_valuestring(rule_black->process[m].parent_process_name);
				free_valuestring(rule_black->process[m].remote_ip);
				for (n = 0; n < rule_black->process[m].event_num; n++) {
					free_valuestring(rule_black->process[m].event_names[n].list);
				}
				sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->process[i].process_name);
			free_valuestring(rule_black->process[i].process_path);
			free_valuestring(rule_black->process[i].process_commandline);
			free_valuestring(rule_black->process[i].param);
			free_valuestring(rule_black->process[i].md5);
			free_valuestring(rule_black->process[i].process_user);
			free_valuestring(rule_black->process[i].parent_process_name);
			free_valuestring(rule_black->process[i].remote_ip);
			sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < count; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("rule_black->process[%d].event_names[%d].list\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_black->process[m].process_name);
					free_valuestring(rule_black->process[m].process_path);
					free_valuestring(rule_black->process[m].process_commandline);
					free_valuestring(rule_black->process[m].param);
					free_valuestring(rule_black->process[m].md5);
					free_valuestring(rule_black->process[m].process_user);
					free_valuestring(rule_black->process[m].parent_process_name);
					free_valuestring(rule_black->process[m].remote_ip);
					for (n = 0; n < rule_black->process[m].event_num; n++) {
						free_valuestring(rule_black->process[m].event_names[n].list);
					}
					sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_black->process[i].process_name);
				free_valuestring(rule_black->process[i].process_path);
				free_valuestring(rule_black->process[i].process_commandline);
				free_valuestring(rule_black->process[i].param);
				free_valuestring(rule_black->process[i].md5);
				free_valuestring(rule_black->process[i].process_user);
				free_valuestring(rule_black->process[i].parent_process_name);
				free_valuestring(rule_black->process[i].remote_ip);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->process[i].event_names[n].list);
				}
				sniper_free(rule_black->process[i].event_names, sizeof(struct _POLICY_LIST)*count, POLICY_GET);
				sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_black->process[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_black->process[m].process_name);
					free_valuestring(rule_black->process[m].process_path);
					free_valuestring(rule_black->process[m].process_commandline);
					free_valuestring(rule_black->process[m].param);
					free_valuestring(rule_black->process[m].md5);
					free_valuestring(rule_black->process[m].process_user);
					free_valuestring(rule_black->process[m].parent_process_name);
					free_valuestring(rule_black->process[m].remote_ip);
					for (n = 0; n < rule_black->process[m].event_num; n++) {
						free_valuestring(rule_black->process[m].event_names[n].list);
					}
					sniper_free(rule_black->process[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->process[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_black->process[i].process_name);
				free_valuestring(rule_black->process[i].process_path);
				free_valuestring(rule_black->process[i].process_commandline);
				free_valuestring(rule_black->process[i].param);
				free_valuestring(rule_black->process[i].md5);
				free_valuestring(rule_black->process[i].process_user);
				free_valuestring(rule_black->process[i].parent_process_name);
				free_valuestring(rule_black->process[i].remote_ip);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->process[i].event_names[n].list);
				}
				sniper_free(rule_black->process[i].event_names, sizeof(struct _POLICY_LIST)*count, POLICY_GET);
				sniper_free(rule_black->process, sizeof(struct _BLACK_PROCESS)*rule_black->process_num, POLICY_GET);
				return -1;
			}
			rule_black->process[i].event_names[j].list = buf;
			rule_black->process[i].event_flags |= event2flag(arrayList->valuestring);
		}
	}

	return 0;
}

static int get_rule_black_file(cJSON *file, struct _RULE_BLACK *rule_black)
{
	cJSON *filename, *filepath, *extension, *md5;
	cJSON *event_names, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	num = cJSON_GetArraySize(file);
	rule_black->file_num = num;
	rule_black->file = (struct _BLACK_FILE *)sniper_malloc(sizeof(struct _BLACK_FILE)*num, POLICY_GET);
	if (rule_black->file == NULL) {
		MON_ERROR("rule cJSON_Parse black file malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(file, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem black rule_list[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}

		filename = cJSON_GetObjectItem(arrayItem, "filename");
		if (!filename) {
			MON_ERROR("rule cJSON_Parse black file filename error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(filename);
		if (buf == NULL) {
			MON_ERROR("rule_black->file[%d].filename malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}
		rule_black->file[i].filename = buf;

		filepath = cJSON_GetObjectItem(arrayItem, "filepath");
		if (!filepath) {
			MON_ERROR("rule cJSON_Parse black file filepath error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->file[i].filename);
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(filepath);
		if (buf == NULL) {
			MON_ERROR("rule_black->file[%d].filepath malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->file[i].filename);
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}
		rule_black->file[i].filepath = buf;

		extension = cJSON_GetObjectItem(arrayItem, "extension");
		if (!extension) {
			MON_ERROR("rule cJSON_Parse black file extension error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->file[i].filename);
			free_valuestring(rule_black->file[i].filepath);
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(extension);
		if (buf == NULL) {
			MON_ERROR("rule_black->file[%d].extension malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->file[i].filename);
			free_valuestring(rule_black->file[i].filepath);
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}
		rule_black->file[i].extension = buf;

		md5 = cJSON_GetObjectItem(arrayItem, "md5");
		if (!md5) {
			MON_ERROR("rule cJSON_Parse black file md5 error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->file[i].filename);
			free_valuestring(rule_black->file[i].filepath);
			free_valuestring(rule_black->file[i].extension);
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(md5);
		if (buf == NULL) {
			MON_ERROR("rule_black->file[%d].md5 malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->file[i].filename);
			free_valuestring(rule_black->file[i].filepath);
			free_valuestring(rule_black->file[i].extension);
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}
		rule_black->file[i].md5 = buf;

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse black file event_names error\n");
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->file[i].filename);
			free_valuestring(rule_black->file[i].filepath);
			free_valuestring(rule_black->file[i].extension);
			free_valuestring(rule_black->file[i].md5);
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}

		count = cJSON_GetArraySize(event_names);
		rule_black->file[i].event_num = count;
		rule_black->file[i].event_names = (struct _POLICY_LIST*)sniper_malloc(sizeof(struct _POLICY_LIST)*count, POLICY_GET);
		if (rule_black->file[i].event_names == NULL) {
			MON_ERROR("rule_black->file[%d].event_names[%d].list malloc failed\n", i, j);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_black->file[m].filename);
				free_valuestring(rule_black->file[m].filepath);
				free_valuestring(rule_black->file[m].extension);
				free_valuestring(rule_black->file[m].md5);
				for (n = 0; n < rule_black->file[m].event_num; n++) {
					free_valuestring(rule_black->file[m].event_names[n].list);
				}
				sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
			}
			free_valuestring(rule_black->file[i].filename);
			free_valuestring(rule_black->file[i].filepath);
			free_valuestring(rule_black->file[i].extension);
			free_valuestring(rule_black->file[i].md5);
			sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < count; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("rule_black->file[%d].event_names[%d].list\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_black->file[m].filename);
					free_valuestring(rule_black->file[m].filepath);
					free_valuestring(rule_black->file[m].extension);
					free_valuestring(rule_black->file[m].md5);
					for (n = 0; n < rule_black->file[m].event_num; n++) {
						free_valuestring(rule_black->file[m].event_names[n].list);
					}
					sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_black->file[i].filename);
				free_valuestring(rule_black->file[i].filepath);
				free_valuestring(rule_black->file[i].extension);
				free_valuestring(rule_black->file[i].md5);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->file[i].event_names[n].list);
				}
				sniper_free(rule_black->file[i].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[i].event_num, POLICY_GET);
				sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_black->file[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					free_valuestring(rule_black->file[m].filename);
					free_valuestring(rule_black->file[m].filepath);
					free_valuestring(rule_black->file[m].extension);
					free_valuestring(rule_black->file[m].md5);
					for (n = 0; n < rule_black->file[m].event_num; n++) {
						free_valuestring(rule_black->file[m].event_names[n].list);
					}
					sniper_free(rule_black->file[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[m].event_num, POLICY_GET);
				}
				free_valuestring(rule_black->file[i].filename);
				free_valuestring(rule_black->file[i].filepath);
				free_valuestring(rule_black->file[i].extension);
				free_valuestring(rule_black->file[i].md5);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->file[i].event_names[n].list);
				}
				sniper_free(rule_black->file[i].event_names, sizeof(struct _POLICY_LIST)*rule_black->file[i].event_num, POLICY_GET);
				sniper_free(rule_black->file, sizeof(struct _BLACK_FILE)*rule_black->file_num, POLICY_GET);
				return -1;
			}
			rule_black->file[i].event_names[j].list = buf;
			rule_black->file[i].event_flags |= event2flag(arrayList->valuestring);

		}
	}

	return 0;
}

static int get_rule_black_ip(cJSON *ip, struct _RULE_BLACK *rule_black)
{
	cJSON *event_names, *ip_list, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(ip);
	rule_black->ip_num = count;
	rule_black->ip = (struct _BLACK_IP *)sniper_malloc(sizeof(struct _BLACK_IP)*count, POLICY_GET);
        if (rule_black->ip == NULL) {
                MON_ERROR("rule cJSON_Parse black ip malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(ip, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem black ip[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->ip[m].ip_num; n++) {
					free_valuestring(rule_black->ip[m].ip_list[n].list);
				}
				sniper_free(rule_black->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_black->ip[m].event_num; n++) {
					free_valuestring(rule_black->ip[m].event_names[n].list);
				}
				sniper_free(rule_black->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->ip, sizeof(struct _BLACK_IP)*rule_black->ip_num, POLICY_GET);
                        return -1;
                }

		ip_list = cJSON_GetObjectItem(arrayItem, "ip_list");
		if (!ip_list) {
			MON_ERROR("rule cJSON_Parse black ip[%d] ip_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->ip[m].ip_num; n++) {
					free_valuestring(rule_black->ip[m].ip_list[n].list);
				}
				sniper_free(rule_black->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_black->ip[m].event_num; n++) {
					free_valuestring(rule_black->ip[m].event_names[n].list);
				}
				sniper_free(rule_black->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->ip, sizeof(struct _BLACK_IP)*rule_black->ip_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(ip_list);
		rule_black->ip[i].ip_num = num;
		rule_black->ip[i].ip_list = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_black->ip[i].ip_list == NULL) {
			MON_ERROR("rule cJSON_Parse black ip[%d] ip_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->ip[m].ip_num; n++) {
					free_valuestring(rule_black->ip[m].ip_list[n].list);
				}
				sniper_free(rule_black->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_black->ip[m].event_num; n++) {
					free_valuestring(rule_black->ip[m].event_names[n].list);
				}
				sniper_free(rule_black->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->ip, sizeof(struct _BLACK_IP)*rule_black->ip_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(ip_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem black ip[%d] ip_list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->ip[m].ip_num; n++) {
						free_valuestring(rule_black->ip[m].ip_list[n].list);
					}
					sniper_free(rule_black->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_black->ip[m].event_num; n++) {
						free_valuestring(rule_black->ip[m].event_names[n].list);
					}
					sniper_free(rule_black->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->ip[i].ip_list[n].list);
				}
				sniper_free(rule_black->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[i].ip_num, POLICY_GET);
				sniper_free(rule_black->ip, sizeof(struct _BLACK_IP)*rule_black->ip_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_black->ip[%d].ip_list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->ip[m].ip_num; n++) {
						free_valuestring(rule_black->ip[m].ip_list[n].list);
					}
					sniper_free(rule_black->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_black->ip[m].event_num; n++) {
						free_valuestring(rule_black->ip[m].event_names[n].list);
					}
					sniper_free(rule_black->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->ip[i].ip_list[n].list);
				}
				sniper_free(rule_black->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[i].ip_num, POLICY_GET);
				sniper_free(rule_black->ip, sizeof(struct _BLACK_IP)*rule_black->ip_num, POLICY_GET);
				return -1;
			}
			rule_black->ip[i].ip_list[j].list = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse black ip[%d] event_names error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->ip[m].ip_num; n++) {
					free_valuestring(rule_black->ip[m].ip_list[n].list);
				}
				sniper_free(rule_black->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_black->ip[m].event_num; n++) {
					free_valuestring(rule_black->ip[m].event_names[n].list);
				}
				sniper_free(rule_black->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_black->ip[i].ip_num; n++) {
				free_valuestring(rule_black->ip[i].ip_list[n].list);
			}
			sniper_free(rule_black->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[i].ip_num, POLICY_GET);
			sniper_free(rule_black->ip, sizeof(struct _BLACK_IP)*rule_black->ip_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_black->ip[i].event_num = num;
		rule_black->ip[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_black->ip[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse black ip[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->ip[m].ip_num; n++) {
					free_valuestring(rule_black->ip[m].ip_list[n].list);
				}
				sniper_free(rule_black->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_black->ip[m].event_num; n++) {
					free_valuestring(rule_black->ip[m].event_names[n].list);
				}
				sniper_free(rule_black->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_black->ip[i].ip_num; n++) {
				free_valuestring(rule_black->ip[i].ip_list[n].list);
			}
			sniper_free(rule_black->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[i].ip_num, POLICY_GET);
			sniper_free(rule_black->ip, sizeof(struct _BLACK_IP)*rule_black->ip_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem black ip[%d] event_names[%d]array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->ip[m].ip_num; n++) {
						free_valuestring(rule_black->ip[m].ip_list[n].list);
					}
					sniper_free(rule_black->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_black->ip[m].event_num; n++) {
						free_valuestring(rule_black->ip[m].event_names[n].list);
					}
					sniper_free(rule_black->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_black->ip[i].ip_num; n++) {
					free_valuestring(rule_black->ip[i].ip_list[n].list);
				}
				sniper_free(rule_black->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[i].ip_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->ip[i].event_names[n].list);
				}
				sniper_free(rule_black->ip[i].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[i].event_num, POLICY_GET);
				sniper_free(rule_black->ip, sizeof(struct _BLACK_IP)*rule_black->ip_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_black->ip[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->ip[m].ip_num; n++) {
						free_valuestring(rule_black->ip[m].ip_list[n].list);
					}
					sniper_free(rule_black->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_black->ip[m].event_num; n++) {
						free_valuestring(rule_black->ip[m].event_names[n].list);
					}
					sniper_free(rule_black->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_black->ip[i].ip_num; n++) {
					free_valuestring(rule_black->ip[i].ip_list[n].list);
				}
				sniper_free(rule_black->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_black->ip[i].ip_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->ip[i].event_names[n].list);
				}
				sniper_free(rule_black->ip[i].event_names, sizeof(struct _POLICY_LIST)*rule_black->ip[i].event_num, POLICY_GET);
				sniper_free(rule_black->ip, sizeof(struct _BLACK_IP)*rule_black->ip_num, POLICY_GET);
				return -1;
			}
			rule_black->ip[i].event_names[j].list = buf;
			rule_black->ip[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_black_domain(cJSON *domain, struct _RULE_BLACK *rule_black)
{
	cJSON *event_names, *domain_list, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(domain);
	rule_black->domain_num = count;
	rule_black->domain = (struct _BLACK_DOMAIN *)sniper_malloc(sizeof(struct _BLACK_DOMAIN)*count, POLICY_GET);
        if (rule_black->domain == NULL) {
                MON_ERROR("rule cJSON_Parse black domain malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(domain, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem black domain[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->domain[m].domain_num; n++) {
					free_valuestring(rule_black->domain[m].domain_list[n].list);
				}
				sniper_free(rule_black->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_black->domain[m].event_num; n++) {
					free_valuestring(rule_black->domain[m].event_names[n].list);
				}
				sniper_free(rule_black->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->domain, sizeof(struct _BLACK_DOMAIN)*rule_black->domain_num, POLICY_GET);
                        return -1;
                }

		domain_list = cJSON_GetObjectItem(arrayItem, "domain_list");
		if (!domain_list) {
			MON_ERROR("rule cJSON_Parse black domain[%d] domain_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->domain[m].domain_num; n++) {
					free_valuestring(rule_black->domain[m].domain_list[n].list);
				}
				sniper_free(rule_black->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_black->domain[m].event_num; n++) {
					free_valuestring(rule_black->domain[m].event_names[n].list);
				}
				sniper_free(rule_black->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->domain, sizeof(struct _BLACK_DOMAIN)*rule_black->domain_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(domain_list);
		rule_black->domain[i].domain_num = num;
		rule_black->domain[i].domain_list = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_black->domain[i].domain_list == NULL) {
			MON_ERROR("rule cJSON_Parse black domain[%d] domain_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->domain[m].domain_num; n++) {
					free_valuestring(rule_black->domain[m].domain_list[n].list);
				}
				sniper_free(rule_black->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_black->domain[m].event_num; n++) {
					free_valuestring(rule_black->domain[m].event_names[n].list);
				}
				sniper_free(rule_black->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->domain, sizeof(struct _BLACK_DOMAIN)*rule_black->domain_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(domain_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem black rule_list[%d] array error\n",i);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->domain[m].domain_num; n++) {
						free_valuestring(rule_black->domain[m].domain_list[n].list);
					}
					sniper_free(rule_black->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_black->domain[m].event_num; n++) {
						free_valuestring(rule_black->domain[m].event_names[n].list);
					}
					sniper_free(rule_black->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->domain[i].domain_list[n].list);
				}
				sniper_free(rule_black->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[i].domain_num, POLICY_GET);
				sniper_free(rule_black->domain, sizeof(struct _BLACK_DOMAIN)*rule_black->domain_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_black->domain[%d].domain_list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->domain[m].domain_num; n++) {
						free_valuestring(rule_black->domain[m].domain_list[n].list);
					}
					sniper_free(rule_black->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_black->domain[m].event_num; n++) {
						free_valuestring(rule_black->domain[m].event_names[n].list);
					}
					sniper_free(rule_black->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->domain[i].domain_list[n].list);
				}
				sniper_free(rule_black->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[i].domain_num, POLICY_GET);
				sniper_free(rule_black->domain, sizeof(struct _BLACK_DOMAIN)*rule_black->domain_num, POLICY_GET);
				return -1;
			}
			rule_black->domain[i].domain_list[j].list = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse black domain[%d] event_names error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->domain[m].domain_num; n++) {
					free_valuestring(rule_black->domain[m].domain_list[n].list);
				}
				sniper_free(rule_black->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_black->domain[m].event_num; n++) {
					free_valuestring(rule_black->domain[m].event_names[n].list);
				}
				sniper_free(rule_black->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_black->domain[i].domain_num; n++) {
				free_valuestring(rule_black->domain[i].domain_list[n].list);
			}
			sniper_free(rule_black->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[i].domain_num, POLICY_GET);
			sniper_free(rule_black->domain, sizeof(struct _BLACK_DOMAIN)*rule_black->domain_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_black->domain[i].event_num = num;
		rule_black->domain[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_black->domain[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse black domain[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->domain[m].domain_num; n++) {
					free_valuestring(rule_black->domain[m].domain_list[n].list);
				}
				sniper_free(rule_black->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_black->domain[m].event_num; n++) {
					free_valuestring(rule_black->domain[m].event_names[n].list);
				}
				sniper_free(rule_black->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_black->domain[i].domain_num; n++) {
				free_valuestring(rule_black->domain[i].domain_list[n].list);
			}
			sniper_free(rule_black->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[i].domain_num, POLICY_GET);
			sniper_free(rule_black->domain, sizeof(struct _BLACK_DOMAIN)*rule_black->domain_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem black domain[%d] event_names[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->domain[m].domain_num; n++) {
						free_valuestring(rule_black->domain[m].domain_list[n].list);
					}
					sniper_free(rule_black->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_black->domain[m].event_num; n++) {
						free_valuestring(rule_black->domain[m].event_names[n].list);
					}
					sniper_free(rule_black->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_black->domain[i].domain_num; n++) {
					free_valuestring(rule_black->domain[i].domain_list[n].list);
				}
				sniper_free(rule_black->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[i].domain_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->domain[i].event_names[n].list);
				}
				sniper_free(rule_black->domain[i].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[i].event_num, POLICY_GET);
				sniper_free(rule_black->domain, sizeof(struct _BLACK_DOMAIN)*rule_black->domain_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_black->domain[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->domain[m].domain_num; n++) {
						free_valuestring(rule_black->domain[m].domain_list[n].list);
					}
					sniper_free(rule_black->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_black->domain[m].event_num; n++) {
						free_valuestring(rule_black->domain[m].event_names[n].list);
					}
					sniper_free(rule_black->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_black->domain[i].domain_num; n++) {
					free_valuestring(rule_black->domain[i].domain_list[n].list);
				}
				sniper_free(rule_black->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_black->domain[i].domain_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->domain[i].event_names[n].list);
				}
				sniper_free(rule_black->domain[i].event_names, sizeof(struct _POLICY_LIST)*rule_black->domain[i].event_num, POLICY_GET);
				sniper_free(rule_black->domain, sizeof(struct _BLACK_DOMAIN)*rule_black->domain_num, POLICY_GET);
				return -1;
			}
			rule_black->domain[i].event_names[j].list = buf;
			rule_black->domain[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_black_user(cJSON *user, struct _RULE_BLACK *rule_black)
{
	cJSON *event_names, *user_list, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(user);
	rule_black->user_num = count;
	rule_black->user = (struct _BLACK_USER *)sniper_malloc(sizeof(struct _BLACK_USER)*count, POLICY_GET);
        if (rule_black->user == NULL) {
                MON_ERROR("rule cJSON_Parse black user malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(user, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem black user[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->user[m].user_num; n++) {
					free_valuestring(rule_black->user[m].user_list[n].list);
				}
				sniper_free(rule_black->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[m].user_num, POLICY_GET);
				for (n = 0; n < rule_black->user[m].event_num; n++) {
					free_valuestring(rule_black->user[m].event_names[n].list);
				}
				sniper_free(rule_black->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->user, sizeof(struct _BLACK_USER)*rule_black->user_num, POLICY_GET);
                        return -1;
                }

		user_list = cJSON_GetObjectItem(arrayItem, "user_list");
		if (!user_list) {
			MON_ERROR("rule cJSON_Parse black user[%d] user_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->user[m].user_num; n++) {
					free_valuestring(rule_black->user[m].user_list[n].list);
				}
				sniper_free(rule_black->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[m].user_num, POLICY_GET);
				for (n = 0; n < rule_black->user[m].event_num; n++) {
					free_valuestring(rule_black->user[m].event_names[n].list);
				}
				sniper_free(rule_black->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->user, sizeof(struct _BLACK_USER)*rule_black->user_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(user_list);
		rule_black->user[i].user_num = num;
		rule_black->user[i].user_list = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_black->user[i].user_list == NULL) {
			MON_ERROR("rule cJSON_Parse black user[%d] user_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->user[m].user_num; n++) {
					free_valuestring(rule_black->user[m].user_list[n].list);
				}
				sniper_free(rule_black->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[m].user_num, POLICY_GET);
				for (n = 0; n < rule_black->user[m].event_num; n++) {
					free_valuestring(rule_black->user[m].event_names[n].list);
				}
				sniper_free(rule_black->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->user, sizeof(struct _BLACK_USER)*rule_black->user_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(user_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem black user[%d] user_list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->user[m].user_num; n++) {
						free_valuestring(rule_black->user[m].user_list[n].list);
					}
					sniper_free(rule_black->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[m].user_num, POLICY_GET);
					for (n = 0; n < rule_black->user[m].event_num; n++) {
						free_valuestring(rule_black->user[m].event_names[n].list);
					}
					sniper_free(rule_black->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->user[i].user_list[n].list);
				}
				sniper_free(rule_black->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[i].user_num, POLICY_GET);
				sniper_free(rule_black->user, sizeof(struct _BLACK_USER)*rule_black->user_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_black->user[%d].user_list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->user[m].user_num; n++) {
						free_valuestring(rule_black->user[m].user_list[n].list);
					}
					sniper_free(rule_black->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[m].user_num, POLICY_GET);
					for (n = 0; n < rule_black->user[m].event_num; n++) {
						free_valuestring(rule_black->user[m].event_names[n].list);
					}
					sniper_free(rule_black->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->user[i].user_list[n].list);
				}
				sniper_free(rule_black->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[i].user_num, POLICY_GET);
				sniper_free(rule_black->user, sizeof(struct _BLACK_USER)*rule_black->user_num, POLICY_GET);
				return -1;
			}
			rule_black->user[i].user_list[j].list = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse black user event_names error\n");
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->user[m].user_num; n++) {
					free_valuestring(rule_black->user[m].user_list[n].list);
				}
				sniper_free(rule_black->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[m].user_num, POLICY_GET);
				for (n = 0; n < rule_black->user[m].event_num; n++) {
					free_valuestring(rule_black->user[m].event_names[n].list);
				}
				sniper_free(rule_black->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_black->user[i].user_num; n++) {
				free_valuestring(rule_black->user[i].user_list[n].list);
			}
			sniper_free(rule_black->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[i].user_num, POLICY_GET);
			sniper_free(rule_black->user, sizeof(struct _BLACK_USER)*rule_black->user_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_black->user[i].event_num = num;
		rule_black->user[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_black->user[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse black user[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->user[m].user_num; n++) {
					free_valuestring(rule_black->user[m].user_list[n].list);
				}
				sniper_free(rule_black->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[m].user_num, POLICY_GET);
				for (n = 0; n < rule_black->user[m].event_num; n++) {
					free_valuestring(rule_black->user[m].event_names[n].list);
				}
				sniper_free(rule_black->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_black->user[i].user_num; n++) {
				free_valuestring(rule_black->user[i].user_list[n].list);
			}
			sniper_free(rule_black->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[i].user_num, POLICY_GET);
			sniper_free(rule_black->user, sizeof(struct _BLACK_USER)*rule_black->user_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem black user[%d] event_names[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->user[m].user_num; n++) {
						free_valuestring(rule_black->user[m].user_list[n].list);
					}
					sniper_free(rule_black->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[m].user_num, POLICY_GET);
					for (n = 0; n < rule_black->user[m].event_num; n++) {
						free_valuestring(rule_black->user[m].event_names[n].list);
					}
					sniper_free(rule_black->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_black->user[i].user_num; n++) {
					free_valuestring(rule_black->user[i].user_list[n].list);
				}
				sniper_free(rule_black->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[i].user_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->user[i].event_names[n].list);
				}
				sniper_free(rule_black->user[i].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[i].event_num, POLICY_GET);
				sniper_free(rule_black->user, sizeof(struct _BLACK_USER)*rule_black->user_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_black->user[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->user[m].user_num; n++) {
						free_valuestring(rule_black->user[m].user_list[n].list);
					}
					sniper_free(rule_black->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[m].user_num, POLICY_GET);
					for (n = 0; n < rule_black->user[m].event_num; n++) {
						free_valuestring(rule_black->user[m].event_names[n].list);
					}
					sniper_free(rule_black->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_black->user[i].user_num; n++) {
					free_valuestring(rule_black->user[i].user_list[n].list);
				}
				sniper_free(rule_black->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_black->user[i].user_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->user[i].event_names[n].list);
				}
				sniper_free(rule_black->user[i].event_names, sizeof(struct _POLICY_LIST)*rule_black->user[i].event_num, POLICY_GET);
				sniper_free(rule_black->user, sizeof(struct _BLACK_USER)*rule_black->user_num, POLICY_GET);
				return -1;
			}
			rule_black->user[i].event_names[j].list = buf;
			rule_black->user[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_black_access_control(cJSON *access_control, struct _RULE_BLACK *rule_black)
{
	cJSON *event_names, *connect_list, *arrayItem, *arrayList;
	cJSON *direction, *protocol, *ip, *port;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	/* 默认连接连出黑名单的开关为空，检出有内容的时候再更改开关状态 */
	black_access_in_switch =  MY_TURNOFF;
	black_access_out_switch = MY_TURNOFF;

	count = cJSON_GetArraySize(access_control);
	rule_black->access_control_num = count;
	rule_black->access_control = (struct _BLACK_ACCESS_CONTROL *)sniper_malloc(sizeof(struct _BLACK_ACCESS_CONTROL)*count, POLICY_GET);
        if (rule_black->access_control == NULL) {
                MON_ERROR("rule cJSON_Parse black access_control malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(access_control, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem black access_control[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
					free_valuestring(rule_black->access_control[m].connect_list[n].direction);
					free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
					free_valuestring(rule_black->access_control[m].connect_list[n].ip);
					free_valuestring(rule_black->access_control[m].connect_list[n].port);
				}
				sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
				for (n = 0; n < rule_black->access_control[m].event_num; n++) {
					free_valuestring(rule_black->access_control[m].event_names[n].list);
				}
				sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
                        return -1;
                }

		connect_list = cJSON_GetObjectItem(arrayItem, "connect_list");
		if (!connect_list) {
			MON_ERROR("rule cJSON_Parse black access_control[%d] connect_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
					free_valuestring(rule_black->access_control[m].connect_list[n].direction);
					free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
					free_valuestring(rule_black->access_control[m].connect_list[n].ip);
					free_valuestring(rule_black->access_control[m].connect_list[n].port);
				}
				sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
				for (n = 0; n < rule_black->access_control[m].event_num; n++) {
					free_valuestring(rule_black->access_control[m].event_names[n].list);
				}
				sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(connect_list);
		rule_black->access_control[i].connect_num = num;
		rule_black->access_control[i].connect_list = (struct _CONNECT_LIST *)sniper_malloc(sizeof(struct _CONNECT_LIST)*num, POLICY_GET);
		if (rule_black->access_control[i].connect_list == NULL) {
			MON_ERROR("rule cJSON_Parse black access_control[%d] connect_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
					free_valuestring(rule_black->access_control[m].connect_list[n].direction);
					free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
					free_valuestring(rule_black->access_control[m].connect_list[n].ip);
					free_valuestring(rule_black->access_control[m].connect_list[n].port);
				}
				sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
				for (n = 0; n < rule_black->access_control[m].event_num; n++) {
					free_valuestring(rule_black->access_control[m].event_names[n].list);
				}
				sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
			}
			sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(connect_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem black access_control[%d] connect_list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}

			direction = cJSON_GetObjectItem(arrayList, "direction");
			if (!direction) {	
				MON_ERROR("cJSON_GetObjectItem black access_control[%d] connect_list[%d] array direction error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(direction);
			if (buf == NULL) {
				MON_ERROR("rule_black->access_control[%d].connect_list[%d].direction malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}
			rule_black->access_control[i].connect_list[j].direction = buf;

			protocol = cJSON_GetObjectItem(arrayList, "protocol");
			if (!protocol) {	
				MON_ERROR("cJSON_GetObjectItem black access_control[%d] connect_list[%d] array protocol error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->access_control[i].connect_list[n].direction);
				}
				sniper_free(rule_black->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(protocol);
			if (buf == NULL) {
				MON_ERROR("rule_black->access_control[%d].connect_list[%d].protocol malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->access_control[i].connect_list[n].direction);
				}
				sniper_free(rule_black->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}
			rule_black->access_control[i].connect_list[j].protocol = buf;

			ip = cJSON_GetObjectItem(arrayList, "ip");
			if (!ip) {	
				MON_ERROR("cJSON_GetObjectItem black access_control[%d] connect_list[%d] array ip error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->access_control[i].connect_list[n].direction);
					free_valuestring(rule_black->access_control[i].connect_list[n].protocol);
				}
				sniper_free(rule_black->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(ip);
			if (buf == NULL) {
				MON_ERROR("rule_black->access_control[%d].connect_list[%d].ip malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->access_control[i].connect_list[n].direction);
					free_valuestring(rule_black->access_control[i].connect_list[n].protocol);
				}
				sniper_free(rule_black->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}
			rule_black->access_control[i].connect_list[j].ip = buf;

			port = cJSON_GetObjectItem(arrayList, "port");
			if (!port) {	
				MON_ERROR("cJSON_GetObjectItem black access_control[%d] connect_list[%d] array port error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->access_control[i].connect_list[n].direction);
					free_valuestring(rule_black->access_control[i].connect_list[n].protocol);
					free_valuestring(rule_black->access_control[i].connect_list[n].ip);
				}
				sniper_free(rule_black->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(port);
			if (buf == NULL) {
				MON_ERROR("rule_black->access_control[%d].connect_list[%d].port malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->access_control[i].connect_list[n].direction);
					free_valuestring(rule_black->access_control[i].connect_list[n].protocol);
					free_valuestring(rule_black->access_control[i].connect_list[n].ip);
				}
				sniper_free(rule_black->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}
			rule_black->access_control[i].connect_list[j].port = buf;

			/*  连入有黑名单的时候控制白名单为空 */
			if (strcmp(rule_black->access_control[i].connect_list[j].direction, "in") == 0) {
				black_access_in_switch = MY_TURNON;
			}

			/*  连出有黑名单的时候控制白名单为空 */
			if (strcmp(rule_black->access_control[i].connect_list[j].direction, "out") == 0) {
				black_access_out_switch = MY_TURNON;
			}
		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse black access_control event_names error\n");
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
					free_valuestring(rule_black->access_control[m].connect_list[n].direction);
					free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
					free_valuestring(rule_black->access_control[m].connect_list[n].ip);
					free_valuestring(rule_black->access_control[m].connect_list[n].port);
				}
				sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
				for (n = 0; n < rule_black->access_control[m].event_num; n++) {
					free_valuestring(rule_black->access_control[m].event_names[n].list);
				}
				sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_black->access_control[i].connect_num; n++) {
				free_valuestring(rule_black->access_control[i].connect_list[n].direction);
				free_valuestring(rule_black->access_control[i].connect_list[n].protocol);
				free_valuestring(rule_black->access_control[i].connect_list[n].ip);
				free_valuestring(rule_black->access_control[i].connect_list[n].port);
			}
			sniper_free(rule_black->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[i].connect_num, POLICY_GET);
			sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_black->access_control[i].event_num = num;
		rule_black->access_control[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_black->access_control[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse black access_control[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
					free_valuestring(rule_black->access_control[m].connect_list[n].direction);
					free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
					free_valuestring(rule_black->access_control[m].connect_list[n].ip);
					free_valuestring(rule_black->access_control[m].connect_list[n].port);
				}
				sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
				for (n = 0; n < rule_black->access_control[m].event_num; n++) {
					free_valuestring(rule_black->access_control[m].event_names[n].list);
				}
				sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_black->access_control[i].connect_num; n++) {
				free_valuestring(rule_black->access_control[i].connect_list[n].direction);
				free_valuestring(rule_black->access_control[i].connect_list[n].protocol);
				free_valuestring(rule_black->access_control[i].connect_list[n].ip);
				free_valuestring(rule_black->access_control[i].connect_list[n].port);
			}
			sniper_free(rule_black->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[i].connect_num, POLICY_GET);
			sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem black access_control[%d] event_names[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_black->access_control[i].connect_num; n++) {
					free_valuestring(rule_black->access_control[i].connect_list[n].direction);
					free_valuestring(rule_black->access_control[i].connect_list[n].protocol);
					free_valuestring(rule_black->access_control[i].connect_list[n].ip);
					free_valuestring(rule_black->access_control[i].connect_list[n].port);
				}
				sniper_free(rule_black->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[i].connect_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->access_control[i].event_names[n].list);
				}
				sniper_free(rule_black->access_control[i].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[i].event_num, POLICY_GET);
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_black->access_control[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_black->access_control[m].connect_num; n++) {
						free_valuestring(rule_black->access_control[m].connect_list[n].direction);
						free_valuestring(rule_black->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_black->access_control[m].connect_list[n].ip);
						free_valuestring(rule_black->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_black->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_black->access_control[m].event_num; n++) {
						free_valuestring(rule_black->access_control[m].event_names[n].list);
					}
					sniper_free(rule_black->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_black->access_control[i].connect_num; n++) {
					free_valuestring(rule_black->access_control[i].connect_list[n].direction);
					free_valuestring(rule_black->access_control[i].connect_list[n].protocol);
					free_valuestring(rule_black->access_control[i].connect_list[n].ip);
					free_valuestring(rule_black->access_control[i].connect_list[n].port);
				}
				sniper_free(rule_black->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_black->access_control[i].connect_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_black->access_control[i].event_names[n].list);
				}
				sniper_free(rule_black->access_control[i].event_names, sizeof(struct _POLICY_LIST)*rule_black->access_control[i].event_num, POLICY_GET);
				sniper_free(rule_black->access_control, sizeof(struct _BLACK_ACCESS_CONTROL)*rule_black->access_control_num, POLICY_GET);
				return -1;
			}
			rule_black->access_control[i].event_names[j].list = buf;
			rule_black->access_control[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_black(cJSON *data, struct _RULE_BLACK *rule_black)
{
	cJSON *black;
	cJSON *process, *file, *ip, *domain, *user, *access_control;

	black = cJSON_GetObjectItem(data, "black");
	if (!black) {
		MON_ERROR("conf cJSON_Parse black error\n");
		return -1;
	}

	process = cJSON_GetObjectItem(black, "process");
	if (!process) {
		MON_ERROR("rule cJSON_Parse black process error\n");
		rule_black->process_num = 0;
	} else {
		if (get_rule_black_process(process, rule_black) < 0) {
			rule_black->process_num = 0;
		}
	}

	file = cJSON_GetObjectItem(black, "file");
	if (!file) {
		MON_ERROR("rule cJSON_Parse black file error\n");
		rule_black->file_num = 0;
	} else {
		if (get_rule_black_file(file, rule_black) < 0) {
			rule_black->file_num = 0;
		}
	}

	ip = cJSON_GetObjectItem(black, "ip");
	if (!ip) {
		MON_ERROR("rule cJSON_Parse black ip error\n");
		rule_black->ip_num = 0;
	} else {
		if (get_rule_black_ip(ip, rule_black) < 0) {
			rule_black->ip_num = 0;
		}
	}

	/* ip有黑名单的时候控制白名单为空 */
	if (rule_black->ip_num > 0) {
		black_ip_switch = MY_TURNON;
	} else {
		black_ip_switch = MY_TURNOFF;
	}

	domain = cJSON_GetObjectItem(black, "domain");
	if (!domain) {
		MON_ERROR("rule cJSON_Parse black domain error\n");
		rule_black->domain_num = 0;
	} else {
		if (get_rule_black_domain(domain, rule_black) < 0) {
			rule_black->domain_num = 0;
		}
	}

	/* domain有黑名单的时候控制白名单为空 */
	if (rule_black->domain_num > 0) {
		black_domain_switch = MY_TURNON;
	} else {
		black_domain_switch = MY_TURNOFF;
	}

	user = cJSON_GetObjectItem(black, "user");
	if (!user) {
		MON_ERROR("rule cJSON_Parse black user error\n");
		rule_black->user_num = 0;
	} else {
		if (get_rule_black_user(user, rule_black) < 0) {
			rule_black->user_num = 0;
		}
	}

	/* 用户有黑名单的时候控制白名单为空 */
	if (rule_black->user_num > 0) {
		black_user_switch = MY_TURNON;
	} else {
		black_user_switch = MY_TURNOFF;
	}

	access_control = cJSON_GetObjectItem(black, "access_control");
	if (!access_control) {
		MON_ERROR("rule cJSON_Parse black access_control error\n");
		rule_black->access_control_num = 0;
	} else {
		if (get_rule_black_access_control(access_control, rule_black) < 0) {
			rule_black->access_control_num = 0;
		}
	}
	return 0;
}

static int get_rule_white_ip(cJSON *ip, struct _RULE_WHITE *rule_white)
{
	cJSON *event_names, *ip_list, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(ip);
	rule_white->ip_num = count;
	rule_white->ip = (struct _WHITE_IP *)sniper_malloc(sizeof(struct _WHITE_IP)*count, POLICY_GET);
        if (rule_white->ip == NULL) {
                MON_ERROR("rule cJSON_Parse white ip malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(ip, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem white ip[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->ip[m].ip_num; n++) {
					free_valuestring(rule_white->ip[m].ip_list[n].list);
				}
				sniper_free(rule_white->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_white->ip[m].event_num; n++) {
					free_valuestring(rule_white->ip[m].event_names[n].list);
				}
				sniper_free(rule_white->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->ip, sizeof(struct _WHITE_IP)*rule_white->ip_num, POLICY_GET);
                        return -1;
                }

		ip_list = cJSON_GetObjectItem(arrayItem, "ip_list");
		if (!ip_list) {
			MON_ERROR("rule cJSON_Parse white ip[%d] ip_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->ip[m].ip_num; n++) {
					free_valuestring(rule_white->ip[m].ip_list[n].list);
				}
				sniper_free(rule_white->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_white->ip[m].event_num; n++) {
					free_valuestring(rule_white->ip[m].event_names[n].list);
				}
				sniper_free(rule_white->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->ip, sizeof(struct _WHITE_IP)*rule_white->ip_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(ip_list);
		rule_white->ip[i].ip_num = num;
		rule_white->ip[i].ip_list = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_white->ip[i].ip_list == NULL) {
			MON_ERROR("rule cJSON_Parse white ip[%d] ip_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->ip[m].ip_num; n++) {
					free_valuestring(rule_white->ip[m].ip_list[n].list);
				}
				sniper_free(rule_white->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_white->ip[m].event_num; n++) {
					free_valuestring(rule_white->ip[m].event_names[n].list);
				}
				sniper_free(rule_white->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->ip, sizeof(struct _WHITE_IP)*rule_white->ip_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(ip_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white ip[%d] ip_list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->ip[m].ip_num; n++) {
						free_valuestring(rule_white->ip[m].ip_list[n].list);
					}
					sniper_free(rule_white->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_white->ip[m].event_num; n++) {
						free_valuestring(rule_white->ip[m].event_names[n].list);
					}
					sniper_free(rule_white->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->ip[i].ip_list[n].list);
				}
				sniper_free(rule_white->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[i].ip_num, POLICY_GET);
				sniper_free(rule_white->ip, sizeof(struct _WHITE_IP)*rule_white->ip_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_white->ip[%d].ip_list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->ip[m].ip_num; n++) {
						free_valuestring(rule_white->ip[m].ip_list[n].list);
					}
					sniper_free(rule_white->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_white->ip[m].event_num; n++) {
						free_valuestring(rule_white->ip[m].event_names[n].list);
					}
					sniper_free(rule_white->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->ip[i].ip_list[n].list);
				}
				sniper_free(rule_white->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[i].ip_num, POLICY_GET);
				sniper_free(rule_white->ip, sizeof(struct _WHITE_IP)*rule_white->ip_num, POLICY_GET);
				return -1;
			}
			rule_white->ip[i].ip_list[j].list = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse white ip[%d] event_names error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->ip[m].ip_num; n++) {
					free_valuestring(rule_white->ip[m].ip_list[n].list);
				}
				sniper_free(rule_white->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_white->ip[m].event_num; n++) {
					free_valuestring(rule_white->ip[m].event_names[n].list);
				}
				sniper_free(rule_white->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_white->ip[i].ip_num; n++) {
				free_valuestring(rule_white->ip[i].ip_list[n].list);
			}
			sniper_free(rule_white->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[i].ip_num, POLICY_GET);
			sniper_free(rule_white->ip, sizeof(struct _WHITE_IP)*rule_white->ip_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_white->ip[i].event_num = num;
		rule_white->ip[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_white->ip[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse white ip[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->ip[m].ip_num; n++) {
					free_valuestring(rule_white->ip[m].ip_list[n].list);
				}
				sniper_free(rule_white->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[m].ip_num, POLICY_GET);
				for (n = 0; n < rule_white->ip[m].event_num; n++) {
					free_valuestring(rule_white->ip[m].event_names[n].list);
				}
				sniper_free(rule_white->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_white->ip[i].ip_num; n++) {
				free_valuestring(rule_white->ip[i].ip_list[n].list);
			}
			sniper_free(rule_white->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[i].ip_num, POLICY_GET);
			sniper_free(rule_white->ip, sizeof(struct _WHITE_IP)*rule_white->ip_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white ip[%d] event_names[%d]array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->ip[m].ip_num; n++) {
						free_valuestring(rule_white->ip[m].ip_list[n].list);
					}
					sniper_free(rule_white->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_white->ip[m].event_num; n++) {
						free_valuestring(rule_white->ip[m].event_names[n].list);
					}
					sniper_free(rule_white->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_white->ip[i].ip_num; n++) {
					free_valuestring(rule_white->ip[i].ip_list[n].list);
				}
				sniper_free(rule_white->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[i].ip_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->ip[i].event_names[n].list);
				}
				sniper_free(rule_white->ip[i].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[i].event_num, POLICY_GET);
				sniper_free(rule_white->ip, sizeof(struct _WHITE_IP)*rule_white->ip_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_white->ip[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->ip[m].ip_num; n++) {
						free_valuestring(rule_white->ip[m].ip_list[n].list);
					}
					sniper_free(rule_white->ip[m].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[m].ip_num, POLICY_GET);
					for (n = 0; n < rule_white->ip[m].event_num; n++) {
						free_valuestring(rule_white->ip[m].event_names[n].list);
					}
					sniper_free(rule_white->ip[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_white->ip[i].ip_num; n++) {
					free_valuestring(rule_white->ip[i].ip_list[n].list);
				}
				sniper_free(rule_white->ip[i].ip_list, sizeof(struct _POLICY_LIST)*rule_white->ip[i].ip_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->ip[i].event_names[n].list);
				}
				sniper_free(rule_white->ip[i].event_names, sizeof(struct _POLICY_LIST)*rule_white->ip[i].event_num, POLICY_GET);
				sniper_free(rule_white->ip, sizeof(struct _WHITE_IP)*rule_white->ip_num, POLICY_GET);
				return -1;
			}
			rule_white->ip[i].event_names[j].list = buf;
			rule_white->ip[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_white_domain(cJSON *domain, struct _RULE_WHITE *rule_white)
{
	cJSON *event_names, *domain_list, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n =0;
	char *buf = NULL;

	count = cJSON_GetArraySize(domain);
	rule_white->domain_num = count;
	rule_white->domain = (struct _WHITE_DOMAIN *)sniper_malloc(sizeof(struct _WHITE_DOMAIN)*count, POLICY_GET);
        if (rule_white->domain == NULL) {
                MON_ERROR("rule cJSON_Parse white domain malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(domain, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem white domain[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->domain[m].domain_num; n++) {
					free_valuestring(rule_white->domain[m].domain_list[n].list);
				}
				sniper_free(rule_white->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_white->domain[m].event_num; n++) {
					free_valuestring(rule_white->domain[m].event_names[n].list);
				}
				sniper_free(rule_white->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->domain, sizeof(struct _WHITE_DOMAIN)*rule_white->domain_num, POLICY_GET);
                        return -1;
                }

		domain_list = cJSON_GetObjectItem(arrayItem, "domain_list");
		if (!domain_list) {
			MON_ERROR("rule cJSON_Parse white domain[%d] domain_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->domain[m].domain_num; n++) {
					free_valuestring(rule_white->domain[m].domain_list[n].list);
				}
				sniper_free(rule_white->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_white->domain[m].event_num; n++) {
					free_valuestring(rule_white->domain[m].event_names[n].list);
				}
				sniper_free(rule_white->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->domain, sizeof(struct _WHITE_DOMAIN)*rule_white->domain_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(domain_list);
		rule_white->domain[i].domain_num = num;
		rule_white->domain[i].domain_list = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_white->domain[i].domain_list == NULL) {
			MON_ERROR("rule cJSON_Parse white domain[%d] domain_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->domain[m].domain_num; n++) {
					free_valuestring(rule_white->domain[m].domain_list[n].list);
				}
				sniper_free(rule_white->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_white->domain[m].event_num; n++) {
					free_valuestring(rule_white->domain[m].event_names[n].list);
				}
				sniper_free(rule_white->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->domain, sizeof(struct _WHITE_DOMAIN)*rule_white->domain_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(domain_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white rule_list[%d] array error\n",i);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->domain[m].domain_num; n++) {
						free_valuestring(rule_white->domain[m].domain_list[n].list);
					}
					sniper_free(rule_white->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_white->domain[m].event_num; n++) {
						free_valuestring(rule_white->domain[m].event_names[n].list);
					}
					sniper_free(rule_white->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->domain[i].domain_list[n].list);
				}
				sniper_free(rule_white->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[i].domain_num, POLICY_GET);
				sniper_free(rule_white->domain, sizeof(struct _WHITE_DOMAIN)*rule_white->domain_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_white->domain[%d].domain_list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->domain[m].domain_num; n++) {
						free_valuestring(rule_white->domain[m].domain_list[n].list);
					}
					sniper_free(rule_white->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_white->domain[m].event_num; n++) {
						free_valuestring(rule_white->domain[m].event_names[n].list);
					}
					sniper_free(rule_white->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->domain[i].domain_list[n].list);
				}
				sniper_free(rule_white->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[i].domain_num, POLICY_GET);
				sniper_free(rule_white->domain, sizeof(struct _WHITE_DOMAIN)*rule_white->domain_num, POLICY_GET);
				return -1;
			}
			rule_white->domain[i].domain_list[j].list = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse white domain[%d] event_names error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->domain[m].domain_num; n++) {
					free_valuestring(rule_white->domain[m].domain_list[n].list);
				}
				sniper_free(rule_white->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_white->domain[m].event_num; n++) {
					free_valuestring(rule_white->domain[m].event_names[n].list);
				}
				sniper_free(rule_white->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_white->domain[i].domain_num; n++) {
				free_valuestring(rule_white->domain[i].domain_list[n].list);
			}
			sniper_free(rule_white->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[i].domain_num, POLICY_GET);
			sniper_free(rule_white->domain, sizeof(struct _WHITE_DOMAIN)*rule_white->domain_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_white->domain[i].event_num = num;
		rule_white->domain[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_white->domain[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse white domain[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->domain[m].domain_num; n++) {
					free_valuestring(rule_white->domain[m].domain_list[n].list);
				}
				sniper_free(rule_white->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[m].domain_num, POLICY_GET);
				for (n = 0; n < rule_white->domain[m].event_num; n++) {
					free_valuestring(rule_white->domain[m].event_names[n].list);
				}
				sniper_free(rule_white->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_white->domain[i].domain_num; n++) {
				free_valuestring(rule_white->domain[i].domain_list[n].list);
			}
			sniper_free(rule_white->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[i].domain_num, POLICY_GET);
			sniper_free(rule_white->domain, sizeof(struct _WHITE_DOMAIN)*rule_white->domain_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white domain[%d] event_names[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->domain[m].domain_num; n++) {
						free_valuestring(rule_white->domain[m].domain_list[n].list);
					}
					sniper_free(rule_white->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_white->domain[m].event_num; n++) {
						free_valuestring(rule_white->domain[m].event_names[n].list);
					}
					sniper_free(rule_white->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_white->domain[i].domain_num; n++) {
					free_valuestring(rule_white->domain[i].domain_list[n].list);
				}
				sniper_free(rule_white->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[i].domain_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->domain[i].event_names[n].list);
				}
				sniper_free(rule_white->domain[i].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[i].event_num, POLICY_GET);
				sniper_free(rule_white->domain, sizeof(struct _WHITE_DOMAIN)*rule_white->domain_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_white->domain[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->domain[m].domain_num; n++) {
						free_valuestring(rule_white->domain[m].domain_list[n].list);
					}
					sniper_free(rule_white->domain[m].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[m].domain_num, POLICY_GET);
					for (n = 0; n < rule_white->domain[m].event_num; n++) {
						free_valuestring(rule_white->domain[m].event_names[n].list);
					}
					sniper_free(rule_white->domain[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_white->domain[i].domain_num; n++) {
					free_valuestring(rule_white->domain[i].domain_list[n].list);
				}
				sniper_free(rule_white->domain[i].domain_list, sizeof(struct _POLICY_LIST)*rule_white->domain[i].domain_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->domain[i].event_names[n].list);
				}
				sniper_free(rule_white->domain[i].event_names, sizeof(struct _POLICY_LIST)*rule_white->domain[i].event_num, POLICY_GET);
				sniper_free(rule_white->domain, sizeof(struct _WHITE_DOMAIN)*rule_white->domain_num, POLICY_GET);
				return -1;
			}
			rule_white->domain[i].event_names[j].list = buf;
			rule_white->domain[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_white_user(cJSON *user, struct _RULE_WHITE *rule_white)
{
	cJSON *event_names, *user_list, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(user);
	rule_white->user_num = count;
	rule_white->user = (struct _WHITE_USER *)sniper_malloc(sizeof(struct _WHITE_USER)*count, POLICY_GET);
        if (rule_white->user == NULL) {
                MON_ERROR("rule cJSON_Parse white user malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(user, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem white user[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->user[m].user_num; n++) {
					free_valuestring(rule_white->user[m].user_list[n].list);
				}
				sniper_free(rule_white->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[m].user_num, POLICY_GET);
				for (n = 0; n < rule_white->user[m].event_num; n++) {
					free_valuestring(rule_white->user[m].event_names[n].list);
				}
				sniper_free(rule_white->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->user, sizeof(struct _WHITE_USER)*rule_white->user_num, POLICY_GET);
                        return -1;
                }

		user_list = cJSON_GetObjectItem(arrayItem, "user_list");
		if (!user_list) {
			MON_ERROR("rule cJSON_Parse white user[%d] user_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->user[m].user_num; n++) {
					free_valuestring(rule_white->user[m].user_list[n].list);
				}
				sniper_free(rule_white->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[m].user_num, POLICY_GET);
				for (n = 0; n < rule_white->user[m].event_num; n++) {
					free_valuestring(rule_white->user[m].event_names[n].list);
				}
				sniper_free(rule_white->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->user, sizeof(struct _WHITE_USER)*rule_white->user_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(user_list);
		rule_white->user[i].user_num = num;
		rule_white->user[i].user_list = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_white->user[i].user_list == NULL) {
			MON_ERROR("rule cJSON_Parse white user[%d] user_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->user[m].user_num; n++) {
					free_valuestring(rule_white->user[m].user_list[n].list);
				}
				sniper_free(rule_white->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[m].user_num, POLICY_GET);
				for (n = 0; n < rule_white->user[m].event_num; n++) {
					free_valuestring(rule_white->user[m].event_names[n].list);
				}
				sniper_free(rule_white->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->user, sizeof(struct _WHITE_USER)*rule_white->user_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(user_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white user[%d] user_list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->user[m].user_num; n++) {
						free_valuestring(rule_white->user[m].user_list[n].list);
					}
					sniper_free(rule_white->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[m].user_num, POLICY_GET);
					for (n = 0; n < rule_white->user[m].event_num; n++) {
						free_valuestring(rule_white->user[m].event_names[n].list);
					}
					sniper_free(rule_white->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->user[i].user_list[n].list);
				}
				sniper_free(rule_white->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[i].user_num, POLICY_GET);
				sniper_free(rule_white->user, sizeof(struct _WHITE_USER)*rule_white->user_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_white->user[%d].user_list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->user[m].user_num; n++) {
						free_valuestring(rule_white->user[m].user_list[n].list);
					}
					sniper_free(rule_white->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[m].user_num, POLICY_GET);
					for (n = 0; n < rule_white->user[m].event_num; n++) {
						free_valuestring(rule_white->user[m].event_names[n].list);
					}
					sniper_free(rule_white->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->user[i].user_list[n].list);
				}
				sniper_free(rule_white->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[i].user_num, POLICY_GET);
				sniper_free(rule_white->user, sizeof(struct _WHITE_USER)*rule_white->user_num, POLICY_GET);
				return -1;
			}
			rule_white->user[i].user_list[j].list = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse white user event_names error\n");
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->user[m].user_num; n++) {
					free_valuestring(rule_white->user[m].user_list[n].list);
				}
				sniper_free(rule_white->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[m].user_num, POLICY_GET);
				for (n = 0; n < rule_white->user[m].event_num; n++) {
					free_valuestring(rule_white->user[m].event_names[n].list);
				}
				sniper_free(rule_white->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_white->user[i].user_num; n++) {
				free_valuestring(rule_white->user[i].user_list[n].list);
			}
			sniper_free(rule_white->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[i].user_num, POLICY_GET);
			sniper_free(rule_white->user, sizeof(struct _WHITE_USER)*rule_white->user_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_white->user[i].event_num = num;
		rule_white->user[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_white->user[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse white user[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->user[m].user_num; n++) {
					free_valuestring(rule_white->user[m].user_list[n].list);
				}
				sniper_free(rule_white->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[m].user_num, POLICY_GET);
				for (n = 0; n < rule_white->user[m].event_num; n++) {
					free_valuestring(rule_white->user[m].event_names[n].list);
				}
				sniper_free(rule_white->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_white->user[i].user_num; n++) {
				free_valuestring(rule_white->user[i].user_list[n].list);
			}
			sniper_free(rule_white->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[i].user_num, POLICY_GET);
			sniper_free(rule_white->user, sizeof(struct _WHITE_USER)*rule_white->user_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white user[%d] event_names[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->user[m].user_num; n++) {
						free_valuestring(rule_white->user[m].user_list[n].list);
					}
					sniper_free(rule_white->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[m].user_num, POLICY_GET);
					for (n = 0; n < rule_white->user[m].event_num; n++) {
						free_valuestring(rule_white->user[m].event_names[n].list);
					}
					sniper_free(rule_white->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_white->user[i].user_num; n++) {
					free_valuestring(rule_white->user[i].user_list[n].list);
				}
				sniper_free(rule_white->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[i].user_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->user[i].event_names[n].list);
				}
				sniper_free(rule_white->user[i].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[i].event_num, POLICY_GET);
				sniper_free(rule_white->user, sizeof(struct _WHITE_USER)*rule_white->user_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_white->user[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->user[m].user_num; n++) {
						free_valuestring(rule_white->user[m].user_list[n].list);
					}
					sniper_free(rule_white->user[m].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[m].user_num, POLICY_GET);
					for (n = 0; n < rule_white->user[m].event_num; n++) {
						free_valuestring(rule_white->user[m].event_names[n].list);
					}
					sniper_free(rule_white->user[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_white->user[i].user_num; n++) {
					free_valuestring(rule_white->user[i].user_list[n].list);
				}
				sniper_free(rule_white->user[i].user_list, sizeof(struct _POLICY_LIST)*rule_white->user[i].user_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->user[i].event_names[n].list);
				}
				sniper_free(rule_white->user[i].event_names, sizeof(struct _POLICY_LIST)*rule_white->user[i].event_num, POLICY_GET);
				sniper_free(rule_white->user, sizeof(struct _WHITE_USER)*rule_white->user_num, POLICY_GET);
				return -1;
			}
			rule_white->user[i].event_names[j].list = buf;
			rule_white->user[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_white_access_control(cJSON *access_control, struct _RULE_WHITE *rule_white)
{
	cJSON *event_names, *connect_list, *arrayItem, *arrayList;
	cJSON *direction, *protocol, *ip, *port;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(access_control);
	rule_white->access_control_num = count;
	rule_white->access_control = (struct _WHITE_ACCESS_CONTROL *)sniper_malloc(sizeof(struct _WHITE_ACCESS_CONTROL)*count, POLICY_GET);
        if (rule_white->access_control == NULL) {
                MON_ERROR("rule cJSON_Parse white access_control malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(access_control, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem white access_control[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
					free_valuestring(rule_white->access_control[m].connect_list[n].direction);
					free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
					free_valuestring(rule_white->access_control[m].connect_list[n].ip);
					free_valuestring(rule_white->access_control[m].connect_list[n].port);
				}
				sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
				for (n = 0; n < rule_white->access_control[m].event_num; n++) {
					free_valuestring(rule_white->access_control[m].event_names[n].list);
				}
				sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
                        return -1;
                }

		connect_list = cJSON_GetObjectItem(arrayItem, "connect_list");
		if (!connect_list) {
			MON_ERROR("rule cJSON_Parse white access_control[%d] connect_list error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
					free_valuestring(rule_white->access_control[m].connect_list[n].direction);
					free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
					free_valuestring(rule_white->access_control[m].connect_list[n].ip);
					free_valuestring(rule_white->access_control[m].connect_list[n].port);
				}
				sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
				for (n = 0; n < rule_white->access_control[m].event_num; n++) {
					free_valuestring(rule_white->access_control[m].event_names[n].list);
				}
				sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(connect_list);
		rule_white->access_control[i].connect_num = num;
		rule_white->access_control[i].connect_list = (struct _CONNECT_LIST *)sniper_malloc(sizeof(struct _CONNECT_LIST)*num, POLICY_GET);
		if (rule_white->access_control[i].connect_list == NULL) {
			MON_ERROR("rule cJSON_Parse white access_control[%d] connect_list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
					free_valuestring(rule_white->access_control[m].connect_list[n].direction);
					free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
					free_valuestring(rule_white->access_control[m].connect_list[n].ip);
					free_valuestring(rule_white->access_control[m].connect_list[n].port);
				}
				sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
				for (n = 0; n < rule_white->access_control[m].event_num; n++) {
					free_valuestring(rule_white->access_control[m].event_names[n].list);
				}
				sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
			}
			sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(connect_list, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white access_control[%d] connect_list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}

			direction = cJSON_GetObjectItem(arrayList, "direction");
			if (!direction) {	
				MON_ERROR("cJSON_GetObjectItem white access_control[%d] connect_list[%d] array direction error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(direction);
			if (buf == NULL) {
				MON_ERROR("rule_white->access_control[%d].connect_list[%d].direction malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}
			rule_white->access_control[i].connect_list[j].direction = buf;

			/* 访问控制黑白名单互斥涉及连入连出在同一个数组里，考虑释放空间的回收，字段改为倒序，在应用的时候判断许注意 */
			if (strcmp(rule_white->access_control[i].connect_list[j].direction, "in") == 0 &&
			    black_access_in_switch == MY_TURNON) {
				strcpy(rule_white->access_control[i].connect_list[j].direction, "ni");
			}
			if (strcmp(rule_white->access_control[i].connect_list[j].direction, "out") == 0 &&
			    black_access_out_switch == MY_TURNON) {
				strcpy(rule_white->access_control[i].connect_list[j].direction, "tuo");
			}

			protocol = cJSON_GetObjectItem(arrayList, "protocol");
			if (!protocol) {	
				MON_ERROR("cJSON_GetObjectItem white access_control[%d] connect_list[%d] array protocol error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->access_control[i].connect_list[n].direction);
				}
				sniper_free(rule_white->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(protocol);
			if (buf == NULL) {
				MON_ERROR("rule_white->access_control[%d].connect_list[%d].protocol malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->access_control[i].connect_list[n].direction);
				}
				sniper_free(rule_white->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}
			rule_white->access_control[i].connect_list[j].protocol = buf;

			ip = cJSON_GetObjectItem(arrayList, "ip");
			if (!ip) {	
				MON_ERROR("cJSON_GetObjectItem white access_control[%d] connect_list[%d] array ip error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->access_control[i].connect_list[n].direction);
					free_valuestring(rule_white->access_control[i].connect_list[n].protocol);
				}
				sniper_free(rule_white->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(ip);
			if (buf == NULL) {
				MON_ERROR("rule_white->access_control[%d].connect_list[%d].ip malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->access_control[i].connect_list[n].direction);
					free_valuestring(rule_white->access_control[i].connect_list[n].protocol);
				}
				sniper_free(rule_white->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}
			rule_white->access_control[i].connect_list[j].ip = buf;

			port = cJSON_GetObjectItem(arrayList, "port");
			if (!port) {	
				MON_ERROR("cJSON_GetObjectItem white access_control[%d] connect_list[%d] array port error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->access_control[i].connect_list[n].direction);
					free_valuestring(rule_white->access_control[i].connect_list[n].protocol);
					free_valuestring(rule_white->access_control[i].connect_list[n].ip);
				}
				sniper_free(rule_white->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(port);
			if (buf == NULL) {
				MON_ERROR("rule_white->access_control[%d].connect_list[%d].port malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->access_control[i].connect_list[n].direction);
					free_valuestring(rule_white->access_control[i].connect_list[n].protocol);
					free_valuestring(rule_white->access_control[i].connect_list[n].ip);
				}
				sniper_free(rule_white->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[i].connect_num, POLICY_GET);
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}
			rule_white->access_control[i].connect_list[j].port = buf;

		}

		event_names = cJSON_GetObjectItem(arrayItem, "event_names");
		if (!event_names) {
			MON_ERROR("rule cJSON_Parse white access_control event_names error\n");
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
					free_valuestring(rule_white->access_control[m].connect_list[n].direction);
					free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
					free_valuestring(rule_white->access_control[m].connect_list[n].ip);
					free_valuestring(rule_white->access_control[m].connect_list[n].port);
				}
				sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
				for (n = 0; n < rule_white->access_control[m].event_num; n++) {
					free_valuestring(rule_white->access_control[m].event_names[n].list);
				}
				sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_white->access_control[i].connect_num; n++) {
				free_valuestring(rule_white->access_control[i].connect_list[n].direction);
				free_valuestring(rule_white->access_control[i].connect_list[n].protocol);
				free_valuestring(rule_white->access_control[i].connect_list[n].ip);
				free_valuestring(rule_white->access_control[i].connect_list[n].port);
			}
			sniper_free(rule_white->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[i].connect_num, POLICY_GET);
			sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(event_names);
		rule_white->access_control[i].event_num = num;
		rule_white->access_control[i].event_names = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_white->access_control[i].event_names == NULL) {
			MON_ERROR("rule cJSON_Parse white access_control[%d] event_names malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
					free_valuestring(rule_white->access_control[m].connect_list[n].direction);
					free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
					free_valuestring(rule_white->access_control[m].connect_list[n].ip);
					free_valuestring(rule_white->access_control[m].connect_list[n].port);
				}
				sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
				for (n = 0; n < rule_white->access_control[m].event_num; n++) {
					free_valuestring(rule_white->access_control[m].event_names[n].list);
				}
				sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
			}
			for (n = 0; n < rule_white->access_control[i].connect_num; n++) {
				free_valuestring(rule_white->access_control[i].connect_list[n].direction);
				free_valuestring(rule_white->access_control[i].connect_list[n].protocol);
				free_valuestring(rule_white->access_control[i].connect_list[n].ip);
				free_valuestring(rule_white->access_control[i].connect_list[n].port);
			}
			sniper_free(rule_white->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[i].connect_num, POLICY_GET);
			sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(event_names, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white access_control[%d] event_names[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_white->access_control[i].connect_num; n++) {
					free_valuestring(rule_white->access_control[i].connect_list[n].direction);
					free_valuestring(rule_white->access_control[i].connect_list[n].protocol);
					free_valuestring(rule_white->access_control[i].connect_list[n].ip);
					free_valuestring(rule_white->access_control[i].connect_list[n].port);
				}
				sniper_free(rule_white->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[i].connect_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->access_control[i].event_names[n].list);
				}
				sniper_free(rule_white->access_control[i].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[i].event_num, POLICY_GET);
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_white->access_control[%d].event_names[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->access_control[m].connect_num; n++) {
						free_valuestring(rule_white->access_control[m].connect_list[n].direction);
						free_valuestring(rule_white->access_control[m].connect_list[n].protocol);
						free_valuestring(rule_white->access_control[m].connect_list[n].ip);
						free_valuestring(rule_white->access_control[m].connect_list[n].port);
					}
					sniper_free(rule_white->access_control[m].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[m].connect_num, POLICY_GET);
					for (n = 0; n < rule_white->access_control[m].event_num; n++) {
						free_valuestring(rule_white->access_control[m].event_names[n].list);
					}
					sniper_free(rule_white->access_control[m].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[m].event_num, POLICY_GET);
				}
				for (n = 0; n < rule_white->access_control[i].connect_num; n++) {
					free_valuestring(rule_white->access_control[i].connect_list[n].direction);
					free_valuestring(rule_white->access_control[i].connect_list[n].protocol);
					free_valuestring(rule_white->access_control[i].connect_list[n].ip);
					free_valuestring(rule_white->access_control[i].connect_list[n].port);
				}
				sniper_free(rule_white->access_control[i].connect_list, sizeof(struct _CONNECT_LIST)*rule_white->access_control[i].connect_num, POLICY_GET);
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->access_control[i].event_names[n].list);
				}
				sniper_free(rule_white->access_control[i].event_names, sizeof(struct _POLICY_LIST)*rule_white->access_control[i].event_num, POLICY_GET);
				sniper_free(rule_white->access_control, sizeof(struct _WHITE_ACCESS_CONTROL)*rule_white->access_control_num, POLICY_GET);
				return -1;
			}
			rule_white->access_control[i].event_names[j].list = buf;
			rule_white->access_control[i].event_flags |= event2flag(arrayItem->valuestring);

		}
	}

	return 0;
}

static int get_rule_white_risk_weak_passwd(cJSON *weak_passwd, struct _RULE_WHITE *rule_white)
{
	cJSON *id, *rule, *app_type, *username, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(weak_passwd);
	rule_white->risk.weak_passwd_num = count;
	rule_white->risk.weak_passwd = (struct _RISK_PASSWD *)sniper_malloc(sizeof(struct _RISK_PASSWD)*count, POLICY_GET);
        if (rule_white->risk.weak_passwd == NULL) {
                MON_ERROR("rule cJSON_Parse white risk weak_passwd malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(weak_passwd, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem white risk weak_passwd[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				sniper_free(rule_white->risk.weak_passwd[m].rule.app_type, sizeof(struct _POLICY_INT_LIST)*rule_white->risk.weak_passwd[m].rule.type_num, POLICY_GET);
				for (n = 0; n < rule_white->risk.weak_passwd[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.weak_passwd[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.weak_passwd[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.weak_passwd, sizeof(struct _RISK_PASSWD)*rule_white->risk.weak_passwd_num, POLICY_GET);
                        return -1;
                }

		id = cJSON_GetObjectItem(arrayItem, "id");
		if (!id) {
			MON_ERROR("rule cJSON_Parse white risk weak_passwd[%d] id error\n", i);
			for (m = 0; m < i; m++) {
				sniper_free(rule_white->risk.weak_passwd[m].rule.app_type, sizeof(struct _POLICY_INT_LIST)*rule_white->risk.weak_passwd[m].rule.type_num, POLICY_GET);
				for (n = 0; n < rule_white->risk.weak_passwd[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.weak_passwd[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.weak_passwd[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.weak_passwd, sizeof(struct _RISK_PASSWD)*rule_white->risk.weak_passwd_num, POLICY_GET);
			return -1;
		}
		rule_white->risk.weak_passwd[i].id = id->valueint;

		rule = cJSON_GetObjectItem(arrayItem, "rule");
		if (!rule) {
			MON_ERROR("rule cJSON_Parse white risk weak_passwd[%d] rule error\n", i);
			for (m = 0; m < i; m++) {
				sniper_free(rule_white->risk.weak_passwd[m].rule.app_type, sizeof(struct _POLICY_INT_LIST)*rule_white->risk.weak_passwd[m].rule.type_num, POLICY_GET);
				for (n = 0; n < rule_white->risk.weak_passwd[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.weak_passwd[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.weak_passwd[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.weak_passwd, sizeof(struct _RISK_PASSWD)*rule_white->risk.weak_passwd_num, POLICY_GET);
			return -1;
		}

		app_type = cJSON_GetObjectItem(rule, "app_type");
		if (!app_type) {
			MON_ERROR("rule cJSON_Parse white risk weak_passwd[%d] app_type error\n", i);
			for (m = 0; m < i; m++) {
				sniper_free(rule_white->risk.weak_passwd[m].rule.app_type, sizeof(struct _POLICY_INT_LIST)*rule_white->risk.weak_passwd[m].rule.type_num, POLICY_GET);
				for (n = 0; n < rule_white->risk.weak_passwd[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.weak_passwd[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.weak_passwd[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.weak_passwd, sizeof(struct _RISK_PASSWD)*rule_white->risk.weak_passwd_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(app_type);
		rule_white->risk.weak_passwd[i].rule.type_num = num;
		rule_white->risk.weak_passwd[i].rule.app_type= (struct _POLICY_INT_LIST *)sniper_malloc(sizeof(struct _POLICY_INT_LIST)*num, POLICY_GET);
		if (rule_white->risk.weak_passwd[i].rule.app_type == NULL) {
			MON_ERROR("rule cJSON_Parse white risk weak_passwd[%d] rule app_type  malloc failed\n", i);
			for (m = 0; m < i; m++) {
				sniper_free(rule_white->risk.weak_passwd[m].rule.app_type, sizeof(struct _POLICY_INT_LIST)*rule_white->risk.weak_passwd[m].rule.type_num, POLICY_GET);
				for (n = 0; n < rule_white->risk.weak_passwd[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.weak_passwd[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.weak_passwd[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.weak_passwd, sizeof(struct _RISK_PASSWD)*rule_white->risk.weak_passwd_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(app_type, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white risk weak_passwd[%d] rule app_type[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					sniper_free(rule_white->risk.weak_passwd[m].rule.app_type, sizeof(struct _POLICY_INT_LIST)*rule_white->risk.weak_passwd[m].rule.type_num, POLICY_GET);
					for (n = 0; n < rule_white->risk.weak_passwd[m].rule.list_num; n++) {
						free_valuestring(rule_white->risk.weak_passwd[m].rule.list[n].list);
					}
					sniper_free(rule_white->risk.weak_passwd[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[m].rule.list_num, POLICY_GET);
				}
				sniper_free(rule_white->risk.weak_passwd[i].rule.app_type, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[i].rule.type_num, POLICY_GET);
				sniper_free(rule_white->risk.weak_passwd, sizeof(struct _RISK_PASSWD)*rule_white->risk.weak_passwd_num, POLICY_GET);
				return -1;
			}
			rule_white->risk.weak_passwd[i].rule.app_type[j].list = arrayList->valueint;

		}

		username = cJSON_GetObjectItem(rule, "username");
		if (!username) {
			MON_ERROR("rule cJSON_Parse white risk weak_passwd[%d] username error\n", i);
			for (m = 0; m < i; m++) {
				sniper_free(rule_white->risk.weak_passwd[m].rule.app_type, sizeof(struct _POLICY_INT_LIST)*rule_white->risk.weak_passwd[m].rule.type_num, POLICY_GET);
				for (n = 0; n < rule_white->risk.weak_passwd[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.weak_passwd[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.weak_passwd[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.weak_passwd[i].rule.app_type, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[i].rule.type_num, POLICY_GET);
			sniper_free(rule_white->risk.weak_passwd, sizeof(struct _RISK_PASSWD)*rule_white->risk.weak_passwd_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(username);
		rule_white->risk.weak_passwd[i].rule.list_num = num;
		rule_white->risk.weak_passwd[i].rule.list= (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_white->risk.weak_passwd[i].rule.list == NULL) {
			MON_ERROR("rule cJSON_Parse white risk weak_passwd[%d] rule.list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				sniper_free(rule_white->risk.weak_passwd[m].rule.app_type, sizeof(struct _POLICY_INT_LIST)*rule_white->risk.weak_passwd[m].rule.type_num, POLICY_GET);
				for (n = 0; n < rule_white->risk.weak_passwd[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.weak_passwd[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.weak_passwd[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.weak_passwd[i].rule.app_type, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[i].rule.type_num, POLICY_GET);
			sniper_free(rule_white->risk.weak_passwd, sizeof(struct _RISK_PASSWD)*rule_white->risk.weak_passwd_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(username, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white risk weak_passwd[%d] rule list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					sniper_free(rule_white->risk.weak_passwd[m].rule.app_type, sizeof(struct _POLICY_INT_LIST)*rule_white->risk.weak_passwd[m].rule.type_num, POLICY_GET);
					for (n = 0; n < rule_white->risk.weak_passwd[m].rule.list_num; n++) {
						free_valuestring(rule_white->risk.weak_passwd[m].rule.list[n].list);
					}
					sniper_free(rule_white->risk.weak_passwd[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[m].rule.list_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->risk.weak_passwd[i].rule.list[n].list);
				}
				sniper_free(rule_white->risk.weak_passwd[i].rule.app_type, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[i].rule.type_num, POLICY_GET);
				sniper_free(rule_white->risk.weak_passwd[i].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[i].rule.list_num, POLICY_GET);
				sniper_free(rule_white->risk.weak_passwd, sizeof(struct _RISK_PASSWD)*rule_white->risk.weak_passwd_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_white->risk.weak_passwd[%d].rule.list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					sniper_free(rule_white->risk.weak_passwd[m].rule.app_type, sizeof(struct _POLICY_INT_LIST)*rule_white->risk.weak_passwd[m].rule.type_num, POLICY_GET);
					for (n = 0; n < rule_white->risk.weak_passwd[m].rule.list_num; n++) {
						free_valuestring(rule_white->risk.weak_passwd[m].rule.list[n].list);
					}
					sniper_free(rule_white->risk.weak_passwd[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[m].rule.list_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->risk.weak_passwd[i].rule.list[n].list);
				}
				sniper_free(rule_white->risk.weak_passwd[i].rule.app_type, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[i].rule.type_num, POLICY_GET);
				sniper_free(rule_white->risk.weak_passwd[i].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.weak_passwd[i].rule.list_num, POLICY_GET);
				sniper_free(rule_white->risk.weak_passwd, sizeof(struct _RISK_PASSWD)*rule_white->risk.weak_passwd_num, POLICY_GET);
				return -1;
			}
			rule_white->risk.weak_passwd[i].rule.list[j].list = buf;

		}
	}

	return 0;
}

static int get_rule_white_risk_account(cJSON *account, struct _RULE_WHITE *rule_white)
{
	cJSON *id, *rule, *username, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(account);
	rule_white->risk.account_num = count;
	rule_white->risk.account = (struct _RISK_LIST *)sniper_malloc(sizeof(struct _RISK_LIST)*count, POLICY_GET);
        if (rule_white->risk.account == NULL) {
                MON_ERROR("rule cJSON_Parse white risk account malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(account, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem white risk account[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->risk.account[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.account[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.account[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.account[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.account, sizeof(struct _RISK_LIST)*rule_white->risk.account_num, POLICY_GET);
                        return -1;
                }

		id = cJSON_GetObjectItem(arrayItem, "id");
		if (!id) {
			MON_ERROR("rule cJSON_Parse white risk account[%d] id error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->risk.account[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.account[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.account[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.account[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.account, sizeof(struct _RISK_LIST)*rule_white->risk.account_num, POLICY_GET);
			return -1;
		}
		rule_white->risk.account[i].id = id->valueint;

		rule = cJSON_GetObjectItem(arrayItem, "rule");
		if (!rule) {
			MON_ERROR("rule cJSON_Parse white risk account[%d] rule error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->risk.account[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.account[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.account[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.account[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.account, sizeof(struct _RISK_LIST)*rule_white->risk.account_num, POLICY_GET);
			return -1;
		}

		username = cJSON_GetObjectItem(rule, "username");
		if (!username) {
			MON_ERROR("rule cJSON_Parse white risk account[%d] username error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->risk.account[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.account[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.account[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.account[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.account, sizeof(struct _RISK_LIST)*rule_white->risk.account_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(username);
		rule_white->risk.account[i].rule.list_num = num;
		rule_white->risk.account[i].rule.list= (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_white->risk.account[i].rule.list == NULL) {
			MON_ERROR("rule cJSON_Parse white risk account[%d] rule.list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->risk.account[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.account[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.account[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.account[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.account, sizeof(struct _RISK_LIST)*rule_white->risk.account_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(username, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white risk account[%d] rule list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->risk.account[m].rule.list_num; n++) {
						free_valuestring(rule_white->risk.account[m].rule.list[n].list);
					}
					sniper_free(rule_white->risk.account[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.account[m].rule.list_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->risk.account[i].rule.list[n].list);
				}
				sniper_free(rule_white->risk.account[i].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.account[i].rule.list_num, POLICY_GET);
				sniper_free(rule_white->risk.account, sizeof(struct _RISK_LIST)*rule_white->risk.account_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_white->risk.account[%d].rule.list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->risk.account[m].rule.list_num; n++) {
						free_valuestring(rule_white->risk.account[m].rule.list[n].list);
					}
					sniper_free(rule_white->risk.account[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.account[m].rule.list_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->risk.account[i].rule.list[n].list);
				}
				sniper_free(rule_white->risk.account[i].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.account[i].rule.list_num, POLICY_GET);
				sniper_free(rule_white->risk.account, sizeof(struct _RISK_LIST)*rule_white->risk.account_num, POLICY_GET);
				return -1;
			}
			rule_white->risk.account[i].rule.list[j].list = buf;
		}
	}
	return 0;
}

static int get_rule_white_risk_sys(cJSON *sys, struct _RULE_WHITE *rule_white)
{
	cJSON *id, *rule, *rule_keys, *arrayItem, *arrayList;
	int num = 0, count = 0;
	int i = 0, j = 0, m = 0, n = 0;
	char *buf = NULL;

	count = cJSON_GetArraySize(sys);
	rule_white->risk.sys_num = count;
	rule_white->risk.sys = (struct _RISK_LIST *)sniper_malloc(sizeof(struct _RISK_LIST)*count, POLICY_GET);
        if (rule_white->risk.sys == NULL) {
                MON_ERROR("rule cJSON_Parse white risk sys malloc failed\n");
                return -1;
        }
	for (i = 0; i < count; i++) {
		arrayItem = cJSON_GetArrayItem(sys, i);
                if (!arrayItem) {
                        MON_ERROR("cJSON_GetObjectItem white risk sys[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->risk.sys[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.sys[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.sys[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.sys[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.sys, sizeof(struct _RISK_LIST)*rule_white->risk.sys_num, POLICY_GET);
                        return -1;
                }

		id = cJSON_GetObjectItem(arrayItem, "id");
		if (!id) {
			MON_ERROR("rule cJSON_Parse white risk sys[%d] id error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->risk.sys[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.sys[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.sys[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.sys[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.sys, sizeof(struct _RISK_LIST)*rule_white->risk.sys_num, POLICY_GET);
			return -1;
		}
		rule_white->risk.sys[i].id = id->valueint;

		rule = cJSON_GetObjectItem(arrayItem, "rule");
		if (!rule) {
			MON_ERROR("rule cJSON_Parse white risk sys[%d] rule error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->risk.sys[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.sys[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.sys[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.sys[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.sys, sizeof(struct _RISK_LIST)*rule_white->risk.sys_num, POLICY_GET);
			return -1;
		}

		rule_keys = cJSON_GetObjectItem(rule, "rule_keys");
		if (!rule_keys) {
			MON_ERROR("rule cJSON_Parse white risk sys[%d] rule_keys error\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->risk.sys[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.sys[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.sys[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.sys[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.sys, sizeof(struct _RISK_LIST)*rule_white->risk.sys_num, POLICY_GET);
			return -1;
		}

		num = cJSON_GetArraySize(rule_keys);
		rule_white->risk.sys[i].rule.list_num = num;
		rule_white->risk.sys[i].rule.list= (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
		if (rule_white->risk.sys[i].rule.list == NULL) {
			MON_ERROR("rule cJSON_Parse white risk sys[%d] rule.list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				for (n = 0; n < rule_white->risk.sys[m].rule.list_num; n++) {
					free_valuestring(rule_white->risk.sys[m].rule.list[n].list);
				}
				sniper_free(rule_white->risk.sys[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.sys[m].rule.list_num, POLICY_GET);
			}
			sniper_free(rule_white->risk.sys, sizeof(struct _RISK_LIST)*rule_white->risk.sys_num, POLICY_GET);
			return -1;
		}

		for (j = 0; j < num; j++) {
			arrayList = cJSON_GetArrayItem(rule_keys, j);
			if (!arrayList) {
				MON_ERROR("cJSON_GetObjectItem white risk sys[%d] rule list[%d] array error\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->risk.sys[m].rule.list_num; n++) {
						free_valuestring(rule_white->risk.sys[m].rule.list[n].list);
					}
					sniper_free(rule_white->risk.sys[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.sys[m].rule.list_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->risk.sys[i].rule.list[n].list);
				}
				sniper_free(rule_white->risk.sys[i].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.sys[i].rule.list_num, POLICY_GET);
				sniper_free(rule_white->risk.sys, sizeof(struct _RISK_LIST)*rule_white->risk.sys_num, POLICY_GET);
				return -1;
			}

			buf = get_my_valuestring(arrayList);
			if (buf == NULL) {
				MON_ERROR("rule_white->risk.sys[%d].rule.list[%d].list malloc failed\n", i, j);
				for (m = 0; m < i; m++) {
					for (n = 0; n < rule_white->risk.sys[m].rule.list_num; n++) {
						free_valuestring(rule_white->risk.sys[m].rule.list[n].list);
					}
					sniper_free(rule_white->risk.sys[m].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.sys[m].rule.list_num, POLICY_GET);
				}
				for (n = 0; n < j; n++) {
					free_valuestring(rule_white->risk.sys[i].rule.list[n].list);
				}
				sniper_free(rule_white->risk.sys[i].rule.list, sizeof(struct _POLICY_LIST)*rule_white->risk.sys[i].rule.list_num, POLICY_GET);
				sniper_free(rule_white->risk.sys, sizeof(struct _RISK_LIST)*rule_white->risk.sys_num, POLICY_GET);
				return -1;
			}
			rule_white->risk.sys[i].rule.list[j].list = buf;
		}
	}

	return 0;
}

static int get_rule_white_risk(cJSON *risk, struct _RULE_WHITE *rule_white)
{
	cJSON *weak_passwd, *account, *sys;

	weak_passwd = cJSON_GetObjectItem(risk, "weak_passwd");
	if (!weak_passwd) {
		MON_ERROR("rule cJSON_Parse white risk weak_passwd error\n");
		rule_white->risk.weak_passwd_num = 0;
	} else {
		if (get_rule_white_risk_weak_passwd(weak_passwd, rule_white) < 0) {
			rule_white->risk.weak_passwd_num = 0;
		}
	}

	account = cJSON_GetObjectItem(risk, "account");
	if (!account) {
		MON_ERROR("rule cJSON_Parse white risk account error\n");
		rule_white->risk.account_num = 0;
	} else {
		if (get_rule_white_risk_account(account, rule_white) < 0) {
			rule_white->risk.account_num = 0;
		}
	}

	sys = cJSON_GetObjectItem(risk, "sys");
	if (!sys) {
		MON_ERROR("rule cJSON_Parse white risk sys error\n");
		rule_white->risk.sys_num = 0;
	} else {
		if (get_rule_white_risk_sys(sys, rule_white) < 0) {
			rule_white->risk.sys_num = 0;
		}
	}

	return 0;
}

static int get_rule_white(cJSON *data, struct _RULE_WHITE *rule_white)
{
	cJSON *white;
	cJSON *ip, *domain, *user, *access_control, *risk;

	white = cJSON_GetObjectItem(data, "white");
	if (!white) {
		MON_ERROR("conf cJSON_Parse white error\n");
		return -1;
	}

	if (black_ip_switch == MY_TURNON) {
		rule_white->ip_num = 0;
	} else {
		ip = cJSON_GetObjectItem(white, "ip");
		if (!ip) {
			MON_ERROR("rule cJSON_Parse white ip error\n");
			rule_white->ip_num = 0;
		} else {
			if (get_rule_white_ip(ip, rule_white) < 0) {
				rule_white->ip_num = 0;
			}
		}
	}

	if (black_domain_switch == MY_TURNON) {
		rule_white->domain_num = 0;
	} else {
		domain = cJSON_GetObjectItem(white, "domain");
		if (!domain) {
			MON_ERROR("rule cJSON_Parse white domain error\n");
			rule_white->domain_num = 0;
		} else {
			if (get_rule_white_domain(domain, rule_white) < 0) {
				rule_white->domain_num = 0;
			}
		}
	}

	if (black_user_switch == MY_TURNON) {
		rule_white->user_num = 0;
	} else {
		user = cJSON_GetObjectItem(white, "user");
		if (!user) {
			MON_ERROR("rule cJSON_Parse white user error\n");
			rule_white->user_num = 0;
		} else {
			if (get_rule_white_user(user, rule_white) < 0) {
				rule_white->user_num = 0;
			}
		}
	}

	access_control = cJSON_GetObjectItem(white, "access_control");
	if (!access_control) {
		MON_ERROR("rule cJSON_Parse white access_control error\n");
		rule_white->access_control_num = 0;
	} else {
		if (get_rule_white_access_control(access_control, rule_white) < 0) {
			rule_white->access_control_num = 0;
		}
	}

	risk = cJSON_GetObjectItem(white, "risk");
	if (!risk) {
		MON_ERROR("rule cJSON_Parse white risk error\n");
	} else {
		get_rule_white_risk(risk, rule_white);
	}

	return 0;
}

static int get_rule_global_trust(cJSON *trust, struct _RULE_GLOBAL *rule_global)
{
	cJSON *sign, *company, *fingerprint, *arrayItem;
	int num = 0;
	int i = 0, m = 0;
	char *buf = NULL;

	sign = cJSON_GetObjectItem(trust, "sign");
	if (!sign) {
		MON_ERROR("rule cJSON_Parse global trust sign error\n");
		return -1;
	}

	num = cJSON_GetArraySize(sign);
	rule_global->trust.sign_num = num;
	rule_global->trust.sign = (struct _TRUST_SIGN *)sniper_malloc(sizeof(struct _TRUST_SIGN)*num, POLICY_GET);
	if (rule_global->trust.sign == NULL) {
		MON_ERROR("rule cJSON_Parse global trust sign malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(sign, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem global trust sign[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_global->trust.sign[m].company);
				free_valuestring(rule_global->trust.sign[m].fingerprint);
			}
			sniper_free(rule_global->trust.sign, sizeof(struct _TRUST_SIGN)*rule_global->trust.sign_num, POLICY_GET);
			return -1;
		}

		company = cJSON_GetObjectItem(arrayItem, "company");
		if (!company) {
			MON_ERROR("rule cJSON_Parse global trust sign[%d] company error\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_global->trust.sign[m].company);
				free_valuestring(rule_global->trust.sign[m].fingerprint);
			}
			sniper_free(rule_global->trust.sign, sizeof(struct _TRUST_SIGN)*rule_global->trust.sign_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(company);
		if (buf == NULL) {
			MON_ERROR("rule_global->trust.sign[%d].company malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_global->trust.sign[m].company);
				free_valuestring(rule_global->trust.sign[m].fingerprint);
			}
			sniper_free(rule_global->trust.sign, sizeof(struct _TRUST_SIGN)*rule_global->trust.sign_num, POLICY_GET);
			return -1;
		}
		rule_global->trust.sign[i].company = buf;

		fingerprint = cJSON_GetObjectItem(arrayItem, "fingerprint");
		if (!fingerprint) {
			MON_ERROR("rule cJSON_Parse global trust sign[%d] fingerprint error\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_global->trust.sign[m].company);
				free_valuestring(rule_global->trust.sign[m].fingerprint);
			}
			free_valuestring(rule_global->trust.sign[i].company);
			sniper_free(rule_global->trust.sign, sizeof(struct _TRUST_SIGN)*rule_global->trust.sign_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(fingerprint);
		if (buf == NULL) {
			MON_ERROR("rule_global->trust.sign[%d].fingerprint malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_global->trust.sign[m].company);
				free_valuestring(rule_global->trust.sign[m].fingerprint);
			}
			free_valuestring(rule_global->trust.sign[i].company);
			sniper_free(rule_global->trust.sign, sizeof(struct _TRUST_SIGN)*rule_global->trust.sign_num, POLICY_GET);
			return -1;
		}
		rule_global->trust.sign[i].fingerprint = buf;

	}

	return 0;
}

static int get_rule_global_black(cJSON *black, struct _RULE_GLOBAL *rule_global)
{
	cJSON *minner, *domain, *arrayItem;
	int num = 0;
	int i = 0, m = 0;
	char *buf = NULL;

	domain = cJSON_GetObjectItem(black, "domain");
	if (!domain) {
		MON_ERROR("rule cJSON_Parse global black domain error\n");
		return -1;
	}

	num = cJSON_GetArraySize(domain);
	rule_global->black.domain_num = num;
	rule_global->black.domain = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (rule_global->black.domain == NULL) {
		MON_ERROR("rule cJSON_Parse global black domain malloc failed\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(domain, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem global black domain[%d] array error\n",i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_global->black.domain[m].list);
			}
			sniper_free(rule_global->black.domain, sizeof(struct _POLICY_LIST)*rule_global->black.domain_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("rule_global->black.domain[%d].list malloc failed\n", i);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_global->black.domain[m].list);
			}
			sniper_free(rule_global->black.domain, sizeof(struct _POLICY_LIST)*rule_global->black.domain_num, POLICY_GET);
			return -1;
		}
		rule_global->black.domain[i].list = buf;

	}

	minner = cJSON_GetObjectItem(black, "minner");
	if (!minner) {
		MON_ERROR("rule cJSON_Parse global black minner error\n");
		for (m = 0; m < rule_global->black.domain_num; m++) {
			free_valuestring(rule_global->black.domain[m].list);
		}
		free_valuestring(rule_global->black.domain[i].list);
		sniper_free(rule_global->black.domain, sizeof(struct _POLICY_LIST)*rule_global->black.domain_num, POLICY_GET);
		return -1;
	}

	num = cJSON_GetArraySize(minner);
	rule_global->black.minner_num = num;
	rule_global->black.minner = (struct _POLICY_LIST *)sniper_malloc(sizeof(struct _POLICY_LIST)*num, POLICY_GET);
	if (rule_global->black.minner == NULL) {
		MON_ERROR("rule cJSON_Parse global black minner malloc failed\n");
		for (m = 0; m < rule_global->black.domain_num; m++) {
			free_valuestring(rule_global->black.domain[m].list);
		}
		free_valuestring(rule_global->black.domain[i].list);
		sniper_free(rule_global->black.domain, sizeof(struct _POLICY_LIST)*rule_global->black.domain_num, POLICY_GET);
		return -1;
	}

	for (i = 0; i < num; i++) {
		arrayItem = cJSON_GetArrayItem(minner, i);
		if (!arrayItem) {
			MON_ERROR("cJSON_GetObjectItem global black minner[%d] array error\n",i);
			for (m = 0; m < rule_global->black.domain_num; m++) {
				free_valuestring(rule_global->black.domain[m].list);
			}
			free_valuestring(rule_global->black.domain[i].list);
			sniper_free(rule_global->black.domain, sizeof(struct _POLICY_LIST)*rule_global->black.domain_num, POLICY_GET);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_global->black.minner[m].list);
			}
			sniper_free(rule_global->black.minner, sizeof(struct _POLICY_LIST)*rule_global->black.minner_num, POLICY_GET);
			return -1;
		}

		buf = get_my_valuestring(arrayItem);
		if (buf == NULL) {
			MON_ERROR("rule_global->black.minner[%d].list malloc failed\n", i);
			for (m = 0; m < rule_global->black.domain_num; m++) {
				free_valuestring(rule_global->black.domain[m].list);
			}
			free_valuestring(rule_global->black.domain[i].list);
			sniper_free(rule_global->black.domain, sizeof(struct _POLICY_LIST)*rule_global->black.domain_num, POLICY_GET);
			for (m = 0; m < i; m++) {
				free_valuestring(rule_global->black.minner[m].list);
			}
			sniper_free(rule_global->black.minner, sizeof(struct _POLICY_LIST)*rule_global->black.minner_num, POLICY_GET);
			return -1;
		}
		rule_global->black.minner[i].list = buf;

	}

	return 0;
}

static int get_rule_global(cJSON *data, struct _RULE_GLOBAL *rule_global)
{
	cJSON *global;
	cJSON *trust, *black;

	global = cJSON_GetObjectItem(data, "global");
	if (!global) {
		MON_ERROR("conf cJSON_Parse global error\n");
		return -1;
	}

	trust = cJSON_GetObjectItem(global, "trust");
	if (!trust) {
		MON_ERROR("rule cJSON_Parse global trust error\n");
		rule_global->trust.sign_num = 0;
	} else {
		if (get_rule_global_trust(trust, rule_global) < 0) {
			rule_global->trust.sign_num = 0;
		}
	}

	black = cJSON_GetObjectItem(global, "black");
	if (!black) {
		MON_ERROR("rule cJSON_Parse global black error\n");
		rule_global->black.domain_num = 0;
		rule_global->black.minner_num = 0;
	} else {
		if (get_rule_global_black(black, rule_global) < 0) {
			rule_global->black.domain_num = 0;
			rule_global->black.minner_num = 0;
		}
	}

	return 0;
}

int parse_rule_resp(char *string)
{
	cJSON *json, *data;

	RULE_TRUST rule_trust = {0};
	RULE_FILTER rule_filter = {0};
	RULE_BLACK rule_black = {0};
	RULE_WHITE rule_white = {0};
	RULE_GLOBAL rule_global = {0};

	json = cJSON_Parse(string);
        if (!json) {
		MON_ERROR("parse rule reply fail: %s\n", cJSON_GetErrorPtr());
		return -1;
	}

	data = cJSON_GetObjectItem(json, "data");
	if (!data) {
		MON_ERROR("rule reply get data error: %s\n", cJSON_GetErrorPtr());
		cJSON_Delete(json);
		return -1;
	}

	/* 规则的优先级为黑->白->过滤-可信 */
	/* 赋值到全局变量中 */
	get_rule_black(data, &rule_black);
	save_old_black_rule();
        pthread_rwlock_wrlock(&rule_black_global.lock);
        get_black_rule(&rule_black);
        pthread_rwlock_unlock(&rule_black_global.lock);

	get_rule_white(data, &rule_white);
	save_old_white_rule();
        pthread_rwlock_wrlock(&rule_white_global.lock);
        get_white_rule(&rule_white);
        pthread_rwlock_unlock(&rule_white_global.lock);

	get_rule_filter(data, &rule_filter);
	save_old_filter_rule();
        pthread_rwlock_wrlock(&rule_filter_global.lock);
        get_filter_rule(&rule_filter);
        pthread_rwlock_unlock(&rule_filter_global.lock);

	get_rule_trust(data, &rule_trust);
	save_old_trust_rule();
        pthread_rwlock_wrlock(&rule_trust_global.lock);
        get_trust_rule(&rule_trust);
        pthread_rwlock_unlock(&rule_trust_global.lock);

	get_rule_global(data, &rule_global);
	save_old_global_rule();
        pthread_rwlock_wrlock(&rule_global_global.lock);
        get_global_rule(&rule_global);
        pthread_rwlock_unlock(&rule_global_global.lock);

	/* 规则信息记录到文件当中 */
	dump_rule();

	INFO("update rule success\n");

	/* 发送所有内核需要的规则 */
	update_kernel_rule();

	cJSON_Delete(json);
	return 0;
}

int get_rule(char *reason)
{
	cJSON *object = NULL;
	char *string = NULL;
	int ret = 0;

	INFO("get rule info\n");

	buffer_t buffer = {0};
	buffer.len = RULE_MAX;
	buffer.data = sniper_malloc(RULE_MAX, POLICY_GET);
	buffer.pos = 0;
	if (!buffer.data) {
		strncpy(reason, "malloc rule buffer failed!", S_LINELEN);
		reason[S_LINELEN - 1] = '\0';
		MON_ERROR("malloc rule buffer failed!\n");
		return -1;
	}

	object = cJSON_CreateObject();
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	string = cJSON_PrintUnformatted(object);

	if (get_large_data_resp(RULE_URL, string,  &buffer) < 0) {
		strncpy(reason, "get rule resp failed!", S_LINELEN);
		reason[S_LINELEN - 1] = '\0';
		MON_ERROR("get rule resp failed!\n");
		cJSON_Delete(object);
		free(string);
		sniper_free(buffer.data, RULE_MAX, POLICY_GET);
                return -1;
        }

	DBG("rule:%s\n", buffer.data);
	if (strstr(buffer.data, "\"code\":0") != NULL) {

		dbg_record_to_file(DBGFLAG_POLICY, RULE_JSON, buffer.data, strlen(buffer.data));

		ret = parse_rule_resp(buffer.data);
		if (ret < 0) {
			strncpy(reason, "rule date error", S_LINELEN);
			reason[S_LINELEN - 1] = '\0';
		}
	} else {
		ret = -1;
		strncpy(reason, "get rule info failed!", S_LINELEN);
		reason[S_LINELEN - 1] = '\0';
		MON_ERROR("get rule info failed:%s\n", buffer.data);
	}

	cJSON_Delete(object);
	free(string);
	sniper_free(buffer.data, RULE_MAX, POLICY_GET);
	return ret;
}

void update_rule_my(task_recv_t *msg)
{
	char reason[S_LINELEN] = {0};
	int ret = 0;

	pthread_mutex_lock(&rule_update_lock);
	ret = get_rule(reason);
	pthread_mutex_unlock(&rule_update_lock);
	if (ret < 0) {
		send_task_resp(msg, RESULT_FAIL, reason);
	} else {
		send_task_resp(msg, RESULT_OK, "Rule Update");
	}
}

void init_rule(void)
{
	pthread_rwlock_init(&rule_trust_global.lock, 0);
	pthread_rwlock_init(&rule_filter_global.lock, 0);
	pthread_rwlock_init(&rule_black_global.lock, 0);
	pthread_rwlock_init(&rule_white_global.lock, 0);
	pthread_rwlock_init(&rule_global_global.lock, 0);

	pthread_mutex_init(&rule_update_lock, NULL);
}

void fini_rule(void)
{
	pthread_rwlock_destroy(&rule_trust_global.lock);
	pthread_rwlock_destroy(&rule_filter_global.lock);
	pthread_rwlock_destroy(&rule_black_global.lock);
	pthread_rwlock_destroy(&rule_white_global.lock);
	pthread_rwlock_destroy(&rule_global_global.lock);

	pthread_mutex_destroy(&rule_update_lock);
}
