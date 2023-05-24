#ifndef _FILE_MONI_H
#define _FILE_MONI_H

#include <linux/limits.h>
#include <pwd.h>
#include <grp.h>

#include "common.h"
#define OP_LEN_MAX	20
#define LOG_NAME_MAX	40
#define EVENT_NAME_MAX	40

#define ACTION_MAX	16
#define USER_MAX	64
#define OTHER_MAX	16
#define PASSWD_MAX	128
#define RECORD_PASSWD_NUMBER    1000

#define S_COMMLEN 16
#define S_COMMAX  (S_COMMLEN*2+2)

#define MID_ON 0x1

#define USB_PATH "/proc/scsi/usb-storage/"
#define SCSI_PATH "/sys/class/scsi_device/"
#define MOUNT_PATH "/etc/mtab"
#define UTAB_PATH "/run/mount/utab"
#define USB_STRING_MAX  PATH_MAX*8

#define LP_PATH "/var/log/cups/access_log"

#define LOGIN_MAX       64
#define REALNAEM_MAX    128
#define USERNUM_MAX	100
#define GROUPNUM_MAX	100
#define CRON_MAX	100
#define START_MAX	200

#define START_PATHMAX	S_SHORTPATHLEN
#define JOB_MAX		100
#define MAXLINE		256

#define PRINTERNAME_MAX 64
#define RESULT_MAX      16

#define UNKNOWN		0	/* No file type */
#define DATA_FILE	1	/* Relocatable file */
#define EXEC_FILE	2	/* Executable file */
#define SCRIPT_FILE	3	/* Shared object file */
#define NORMAL_FILE	4	/* Core file */

#define WEBSHELL_HIGH_LEVEL	5

/* Should same as kern/file_moni.h */

#define monfilesize hdr.last_open_time
/* -- */

#define F_NAME_MAX (S_NAMELEN+4)

#define ANTIVIRUS_PROGRAM_TYPE          13298
#define ANTIVIRUS_ENGINE_DIRPATH        "/opt/snipercli/bin"
#define ANTIVIRUS_VDFS_DIRPATH          "/opt/snipercli/vdf"
#define ANTIVIRUS_VDFS_DIRPATH_BAK      "/opt/snipercli/vdf.bak"
#define ANTIVIRUS_AVLL_DIRPATH          ANTIVIRUS_ENGINE_DIRPATH
#define ANTIVIRUS_KEY_FILENAME          "/opt/snipercli/bin/hbedv.key"
#define ANTIVIRUS_PATH                  "/bin/sniper_antivirus"
#define ANTIVIRUS_PATH_BAK              "/bin/sniper_antivirus.bak"

struct file_msg_args {
	pid_t pid;
	loff_t file_size;
	unsigned char midware_flag;
	unsigned char webshell_rule_id;
	unsigned char webshell_rule_level;
	unsigned short  is_trust;
	unsigned short  op_type;
	unsigned long long proctime;
	struct timeval  start_tv;
	char pathname[PATH_MAX];
	char pathname_new[PATH_MAX];
	char cmdname[S_CMDLEN];
	char p_cmdname[S_COMMLEN];
	char username[USER_MAX];
	char action[ACTION_MAX];
	char ip[S_IPLEN];
	char midware[S_COMMLEN];
	char taskuuid[S_UUIDLEN];
	char cmd[S_CMDLEN];
	char args[S_ARGSLEN];
	char tty[S_TTYLEN];
	char session_uuid[S_UUIDLEN];
	char webshell_rule_desc[STRLEN_MAX];
	char webshell_rule_regex[STRLEN_MAX];
	char webshell_match_content[STRLEN_MAX];
};

struct virus_msg_args {
	pid_t pid;
	loff_t file_size;
	unsigned short  op_type;
	unsigned long long proctime;
	struct timeval  start_tv;
	char pathname[PATH_MAX];
	char pathname_new[PATH_MAX];
	char cmdname[S_CMDLEN];
	char p_cmdname[S_COMMLEN];
	char username[USER_MAX];
	char action[ACTION_MAX];
	char taskuuid[S_UUIDLEN];
	char cmd[S_CMDLEN];
	char args[S_ARGSLEN];
	char tty[S_TTYLEN];
	char session_uuid[S_UUIDLEN];
};

struct _file_stat {
	mode_t mode;
	uid_t uid;
	gid_t gid;
	int  mtime;
	char md5[S_MD5LEN];
	char path[PATH_MAX];
};

struct _print_job{
        int job;
        int size;
        char user[S_NAMELEN];
        char file[S_PATHLEN];
};

struct _print_msg{
	int event_id;
	int behavior_id;
	int level;
	int terminate;
	char action[20];
	char device_name[PRINTERNAME_MAX];
	char result[RESULT_MAX];
};

extern int check_to_report(char *path, filereq_t *req);

extern int virus_msg_queue_init(void);
extern int virus_msg_queue_full(void);
extern void print_droped_virus_msgs(void);
extern void virus_msg_queue_push(struct virus_msg_args *req);
extern void virus_msg_queue_destroy(void);
#endif /* _FILE_MONI_H */
