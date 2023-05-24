#include "header.h"

long serv_timeoff = 0;
sqlite3* virus_db = NULL;
int force_flag = 0;
int force_number = 0;
int log_flag = 0;
FILE *logfp;
char logname[LOGNAME_MAX];
uid_t exec_uid = 0;
// struct passwd *my_info;

char crt_virus_tbl_sql[1024] =
{
    "CREATE TABLE IF NOT EXISTS virus( "
    "id integer PRIMARY KEY AUTOINCREMENT,"
    "mtime int,"                               //备份时间
    "md5   varchar(4096),"                     //备份新文件名
    "path  varchar(4096),"                     //备份原文件名
    "uid   int,"                      	       //备份原文件uid
    "gid   int,"                               //备份原文件gid
    "mode  int);"                              //备份原文件属性
};

void show_usage(void)
{
	printf("Usage:  sniper_antivirus [options]\n\n");
	printf("  -v, --version         Print Antivirus Version.\n");
	printf("\n");

	printf("  -s, --scan            Scan Virus.\n");
	printf("\tExample:\n");
	printf("\t\t\tfull mode:                       sniper_antivirus -s all\n");
	printf("\t\t\tfast mode:                       sniper_antivirus -s quick\n");
	printf("\t\t\tcustom mode:                     sniper_antivirus -s custom dir1 file2 ...\n");
	printf("\n");

	printf("  -t, --trust           Trust Zone Operations.\n");
	printf("\tExample:\n");
	printf("\t\t\tquery trust zone:                sniper_antivirus -t query\n");
	printf("\t\t\tclean trust zone:                sniper_antivirus -t clean\n");
	printf("\t\t\tadd trust path:                  sniper_antivirus -t add path1 path2 ...\n");
	printf("\t\t\tdelete trust path:               sniper_antivirus -t delete path1 path2 ...\n");
	printf("\n");

	printf("  -q, --quarantine      Quarantine Operations.\n");
	printf("\tExample:\n");
	printf("\t\t\tquery quarantined files:         sniper_antivirus -q query\n");
	printf("\t\t\trecover quarantined files:       sniper_antivirus -q recover file1 file2 ...\n");
	printf("\t\t\tdelete quarantined files:        sniper_antivirus -q delete file1 file2 ...\n");
	printf("\t\t\textract quarantined file:        sniper_antivirus -q extract original_file extract_file\n");
	printf("\n");

	printf("  -f, --force           Do not prompt before overwriting when operating quarantined files.(optional action)\n");
	printf("\tExample:\n");
	printf("\t\t\trecover quarantined files force: sniper_antivirus -q recover file1 file2 ... -f\n");

	fflush(stdout);

	check_clean_log();
	exit(2);
}

int main(int argc, char *argv[])
{
	int next_option = 0;
	const char *short_option = "hvlstqf";
	int i = 0;

	struct option long_option[] = {
		{"help",        0, NULL, 'h'},
		{"version",     0, NULL, 'v'},
		{"list",        0, NULL, 'l'},
		{"scan",        1, NULL, 's'},
		{"trust",       1, NULL, 't'},
		{"quarantine",  1, NULL, 'q'},
		{"force",       0, NULL, 'f'},
		{NULL,          0, NULL, 0}
	};

	if (access(AVIRA_ENABLE, F_OK) < 0) {
		printf("No antivirus license...\n");
		return 0;
	}

	/*
	 * 不预分虚拟空间，以免线程起来后虚拟内存飙升,
	 * 预分的虚拟空间实际上没使用，不影响，但不好看
	 */
	mallopt(M_ARENA_MAX, 1);

	moni_log_init(&g_moni_log, ANTIVIRUS_LOGFILE);

	/* set timezone to China */
	setenv("TZ", "GMT-8", 1);
	tzset();

	/* Set the locale so the program will use the system locale */
        /* 不设置时遇到中文路径, 会报转码错误 */
        setlocale(LC_ALL, "");

	virus_msg_queue_init();
	handle_msg_queue_init();

	/* 临时log文件用于记录操作的详细日志 */
	get_log_name(logname, sizeof(logname));
	logfp = fopen(logname, "w+");

	exec_uid = getuid();

	/* 获取执行的用户名*/
	my_info = getpwuid(exec_uid);
        if (!my_info || !my_info->pw_name) {
                printf("Get process user error\n");
		return 0;
        }

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-f") == 0 ||
		    strcmp(argv[i], "--force") == 0) {
			force_flag = 1;
			force_number = i;
		} else if (strcmp(argv[i], "-qf") == 0) {
			force_flag = 1;
		}
	}

	do {
		next_option = getopt_long(argc, argv,
			short_option, long_option, NULL);

		switch (next_option) {
			case 'v':
				printf("%s\n", ANTIVIRUS_VER);
				check_clean_log();
				exit(0);
			case 'l':
				load_local_policy();
				load_local_conf();
				dump_policy_antivirus();
				check_clean_log();
				exit(0);
			case 's':
				if (scan_mode(argc, argv) < 0) {
					check_clean_log();
					exit(1);
				}
				check_clean_log();
				exit(0);
			case 't':
				if (trust_path_operate(argc, argv) < 0) {
					check_clean_log();
					exit(1);
				}
				check_clean_log();
				exit(0);
			case 'q':
				if (quarantine_files_operate(argc, argv) < 0) {
					check_clean_log();
					exit(1);
				}
				check_clean_log();
				exit(0);
			case 'f':
				break;
			case 'h':
			case '?':
				show_usage();
				check_clean_log();
				exit(0);
			default:
				show_usage();
				check_clean_log();
				exit(1);
		}
	} while (next_option != -1);


	virus_msg_queue_destroy();
	handle_msg_queue_destroy();

	if (logfp) {
		fclose(logfp);
	}
	check_clean_log();
	moni_log_destroy(&g_moni_log);
	return 0;
}
