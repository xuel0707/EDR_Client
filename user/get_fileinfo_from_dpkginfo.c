#include "header.h"

//static int match = 0;
//static int fileseq = -1;
//static int diridx = -1;
static char _pkgname[S_NAMELEN] = {0};
static char _version[S_NAMELEN] = {0};
//static char _release[S_NAMELEN] = {0};
static char _arch[S_NAMELEN] = {0};
static char *_vendor = NULL;
static char *_product = NULL;
static char *_digest = NULL;
static char *_cmd = NULL;
static char *_pkgsize = NULL;
//static char *_cmdname = NULL;
//static int dirlen = 0;
//static char *_username = NULL;
//static char *_groupname = NULL;
//static off_t *_fsize = NULL;
//static mode_t *_fmode = NULL;
//static time_t *_mtime = NULL;
//static time_t *_pkginstalltime = NULL;
//static ino_t _inode = 0;

#define DPKG_INFO "/var/lib/dpkg/info"
#define DPKG_NUM 5
char dpkg[DPKG_NUM][32] = {
	"/var/lib/dpkg/status",
	"/var/lib/dpkg/status-old",
	"/var/backups/dpkg.status.0",
	"/var/lib/dpkg/available",
	"/var/lib/dpkg/available-old"
};

static int search_dpkg_info(void)
{
	DIR *dirp = NULL;
	struct dirent *ent = NULL;
	FILE *fp = NULL;
	char path[S_LINELEN] = {0};
	char line[S_LINELEN] = {0};
	char md5[S_MD5LEN] = {0};
	int i = 0, namelen = 0, found = 0, reported = 0;
	char pkgname[256] = {0}, *ptr = NULL, *key = NULL, *value = NULL;
	char architecture[S_NAMELEN] = {0};

	dirp = sniper_opendir(DPKG_INFO, PROCESS_GET);
	if (!dirp) {
		MON_ERROR("search_dpkg_info fail, open %s fail: %s\n",
			DPKG_INFO, strerror(errno));
		return -1;
	}

	/* 找文件所属的软件包 */
	while ((ent = readdir(dirp))) {
		namelen = strlen(ent->d_name);
		if (strcmp(ent->d_name + namelen - 5, ".list") != 0) {
			continue;
		}

		snprintf(path, S_LINELEN, "%s/%s", DPKG_INFO, ent->d_name);
		fp = sniper_fopen(path, "r", PROCESS_GET);
		if (!fp) {
			continue;
		}

		while (fgets(line, S_LINELEN, fp)) {
			delete_tailspace(line);

			if (strcmp(line, _cmd) == 0) {
				found = 1;
				memcpy(pkgname, ent->d_name, namelen-5);
				pkgname[namelen-5] = 0;
				break;
			}
		}
		sniper_fclose(fp, PROCESS_GET);

		if (found) {
			break;
		}
	}
	sniper_closedir(dirp, PROCESS_GET);

	if (!found) {
		/* 对于bin包安装的sniper，设置本厂家名 */
		if (strncmp(_cmd, "/opt/snipercli/", strlen("/opt/snipercli/")) == 0) {
			strncpy(_vendor, SNIPER_VENDOR, S_NAMELEN-1);
		}
		return -1;
	}

	/* 取md5 */
	snprintf(path, S_LINELEN, "%s/%s.md5sums", DPKG_INFO, pkgname);
	fp = sniper_fopen(path, "r", PROCESS_GET);
	if (!fp) {
		MON_ERROR("open %s fail: %s\n", path, strerror(errno));
	} else {
		while (fgets(line, S_LINELEN, fp) != NULL) {
			char filename[PATH_MAX] = {0};

			if (sscanf(line, "%s %s", md5, filename) != 2) {
				continue;
			}

			delete_tailspace(filename);

			/* filename取消了开头的/ */
			if (strcmp(filename, _cmd+1) == 0) {
				strncpy(_digest, md5, S_MD5LEN-1);
				break;
			}
		}
		sniper_fclose(fp, PROCESS_GET);
	}

	ptr = strrchr(pkgname, ':');
	if (ptr) {
		snprintf(_arch, S_NAMELEN, "%s", ptr+1);
		*ptr = 0;
	}
	strncpy(_pkgname, pkgname, S_NAMELEN-1);

	/* 打开安装包信息文件 */
	for (i = 0; i < DPKG_NUM; i++) {
		fp = sniper_fopen(dpkg[i], "r", PROCESS_GET);
		if (fp) {
			reported = i + 1;
			break;
		}
		/* 不反复报dpkg文件不存在 */
		if (reported <= i) {
			MON_ERROR("open %s fail: %s\n", dpkg[i], strerror(errno));
		}
	}
	if (!fp) {
		return -1;
	}

	found = 0;
	while (fgets(line, S_LINELEN, fp) != NULL) {
		ptr = strchr(line, ':');
		if (ptr == NULL) {
			continue;
		}
		*ptr = 0;

		key = skip_headspace(line);
		delete_tailspace(key);

		if (strcmp(key, "Package") != 0) {
			continue;
		}

		value = skip_headspace(ptr+1);
		delete_tailspace(value);

		if (strcmp(value, _pkgname) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		sniper_fclose(fp, PROCESS_GET);
		return -1;
	}

	found = 0;
	while (fgets(line, S_LINELEN, fp) != NULL) {
		ptr = strchr(line, ':');
		if (ptr == NULL) {
			continue;
		}
		*ptr = 0;

		key = skip_headspace(line);
		delete_tailspace(key);

		value = skip_headspace(ptr+1);
		delete_tailspace(value);

		if (strcmp(key, "Package") == 0) { //当前包的信息解析完毕，到下一个了
			break;
		}

		if (strcmp(key, "Maintainer") == 0) {
			if (strstr(value, "Ubuntu") ||
			    strstr(value, "ubuntu.com") ||
			    strstr(value, "canonical.com")) {
				strncpy(_vendor, "Ubuntu", S_NAMELEN-1);
			} else if (strstr(value, "debian.org") ||
				   strstr(value, "smarden.org")) {
				strncpy(_vendor, "Debian", S_NAMELEN-1);
			} else { //其他机构和个人照抄
				strncpy(_vendor, value, S_NAMELEN-1);
			}
			found++;
		} else if (strcmp(key, "Architecture") == 0) {
			strncpy(architecture, value, S_NAMELEN-1);
			found++;
		} else if (strcmp(key, "Version") == 0) {
			strncpy(_version, value, S_NAMELEN-1);
			found++;
		} else if (strcmp(key, "Installed-Size") == 0) {
			snprintf(_pkgsize, S_NAMELEN, "%s KB", value);
			found++;
		}
		if (found == 4) {
			break;
		}
	}
	sniper_fclose(fp, PROCESS_GET);

	if (architecture[0] && strcmp(architecture, "all") != 0) {
		snprintf(_product, S_NAMELEN, "%s-%s.%s", thestring(_pkgname), thestring(_version), thestring(architecture));
	} else if (_arch[0]){
		snprintf(_product, S_NAMELEN, "%s-%s.%s", thestring(_pkgname), thestring(_version), thestring(_arch));
	}

	return 0;
}

int get_fileinfo_from_dpkginfo(char *cmd, exeinfo_t *exeinfo)
{
	struct stat st = {0};
	char path[PATH_MAX] = {0};

	if (!cmd || !exeinfo) {
		MON_ERROR("invalid arguments: cmd %p exeinfo %p\n", cmd, exeinfo);
		return -1;
	}

	_cmd = cmd;
	/*
	 * realpath处理符号链接和./和../，这里不能用readlink，可能有多级链接，如
	 * /usr/sbin/sendmail -> /etc/alternatives/mta -> /usr/sbin/sendmail.postfix
	 */
	if (lstat(cmd, &st) == 0 && S_ISLNK(st.st_mode) && realpath(cmd, path)) {
		_cmd = path;
printf("%s linkto %s\n", cmd, _cmd);
	}
	if (stat(_cmd, &st) == 0) {
		/* dpkg没保存安装时的文件size/mode/mtime，就用当前的 */
		exeinfo->install_fsize = st.st_size;
		exeinfo->install_fmode = st.st_mode;
		exeinfo->install_mtime = st.st_mtime;
	//	_inode = st.st_ino;
	}

	_vendor = exeinfo->vendor;
	_product = exeinfo->product;
	_digest = exeinfo->install_digest;
	_pkgsize = exeinfo->pkginstallsize;
	//_username = exeinfo->username;
	//_groupname = exeinfo->groupname;
	//_fsize = &(exeinfo->fsize);
	//_fmode = &(exeinfo->fmode);
	//_mtime = &(exeinfo->mtime);
	//_pkginstalltime = &(exeinfo->pkginstalltime);

	return search_dpkg_info();
}
