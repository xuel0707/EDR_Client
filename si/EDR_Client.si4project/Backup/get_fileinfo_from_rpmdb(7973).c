#include <db.h>
#include "header.h"

static int match = 0;
static int fileseq = -1;
static int diridx = -1;
static char _pkgname[S_NAMELEN] = {0};
static char _version[S_NAMELEN] = {0};
static char _release[S_NAMELEN] = {0};
static char _arch[S_NAMELEN] = {0};
static char *_vendor = NULL;
static char *_product = NULL;
static char *_digest = NULL;
static char *_cmd = NULL;
static char *_cmdname = NULL;
static int dirlen = 0;
static char *_username = NULL;
static char *_groupname = NULL;
static off_t *_fsize = NULL;
static mode_t *_fmode = NULL;
static time_t *_mtime = NULL;
static time_t *_pkginstalltime = NULL;
static ino_t _inode = 0;
static char *_md5 = NULL;
static char *_sha256 = NULL;

#define RPM_PACKAGE_DB    "/var/lib/rpm/Packages"
#define RPM_BASENAME_DB    "/var/lib/rpm/Basenames"

typedef enum rpmTag_e {
    RPMTAG_NAME  		= 1000,	/* s */
    RPMTAG_VERSION		= 1001,	/* s */
    RPMTAG_RELEASE		= 1002,	/* s */
    RPMTAG_EPOCH   		= 1003,	/* i */
    RPMTAG_SUMMARY		= 1004,	/* s{} */
    RPMTAG_DESCRIPTION		= 1005,	/* s{} */
    RPMTAG_INSTALLTIME		= 1008,	/* i */
    RPMTAG_SIZE			= 1009,	/* i */
    RPMTAG_DISTRIBUTION		= 1010,	/* s */
    RPMTAG_VENDOR		= 1011,	/* s */
    RPMTAG_OS			= 1021,	/* s legacy used int */
    RPMTAG_ARCH			= 1022,	/* s legacy used int */
    RPMTAG_FILESIZES		= 1028,	/* i[] */
    RPMTAG_FILESTATES		= 1029, /* c[] */
    RPMTAG_FILEMODES		= 1030,	/* h[] */
    RPMTAG_FILEUIDS		= 1031, /* i[] internal - obsolete */
    RPMTAG_FILEGIDS		= 1032, /* i[] internal - obsolete */
    RPMTAG_FILERDEVS		= 1033,	/* h[] */
    RPMTAG_FILEMTIMES		= 1034, /* i[] */
    RPMTAG_FILEDIGESTS		= 1035,	/* s[] */
    RPMTAG_FILELINKTOS		= 1036,	/* s[] */
    RPMTAG_FILEFLAGS		= 1037,	/* i[] */
    RPMTAG_FILEUSERNAME		= 1039,	/* s[] */
    RPMTAG_FILEGROUPNAME	= 1040,	/* s[] */
    RPMTAG_INSTALLPREFIX	= 1058, /* s internal - deprecated */
    RPMTAG_RPMVERSION		= 1064,	/* s */
    RPMTAG_CHANGELOGTIME	= 1080,	/* i[] */
    RPMTAG_CHANGELOGNAME	= 1081,	/* s[] */
    RPMTAG_CHANGELOGTEXT	= 1082,	/* s[] */
    RPMTAG_FILEDEVICES		= 1095,	/* i[] */
    RPMTAG_FILEINODES		= 1096,	/* i[] */
    RPMTAG_FILELANGS		= 1097,	/* s[] */
    RPMTAG_DIRINDEXES		= 1116,	/* i[] */
    RPMTAG_BASENAMES		= 1117,	/* s[] */
    RPMTAG_DIRNAMES		= 1118,	/* s[] */
    RPMTAG_END_TAG
} rpmTag;

typedef struct rpm_tag_info {
    int tag;
    int type;
    int offset;
    int count;
} rpmTagInfo;

typedef enum rpmTagType_e {
#define	RPM_MIN_TYPE		0
    RPM_NULL_TYPE		=  0,
    RPM_CHAR_TYPE		=  1,
    RPM_INT8_TYPE		=  2,
    RPM_INT16_TYPE		=  3,
    RPM_INT32_TYPE		=  4,
    RPM_INT64_TYPE		=  5,
    RPM_STRING_TYPE		=  6,
    RPM_BIN_TYPE		=  7,
    RPM_STRING_ARRAY_TYPE	=  8,
    RPM_I18NSTRING_TYPE		=  9,
#define	RPM_MAX_TYPE		9
#define RPM_FORCEFREE_TYPE	0xff
#define RPM_MASK_TYPE		0x0000ffff
} rpmTagType;

static char *tag2str(int tag)
{
    switch(tag) {
    case RPMTAG_NAME:
	return "name";
    case RPMTAG_VERSION:
	return "version";
    case RPMTAG_RELEASE:
	return "release";
    case RPMTAG_EPOCH:
	return "epoch";
    case RPMTAG_INSTALLTIME:
	return "installtime";
#if 0
    case RPMTAG_SUMMARY:
	return "summary";
    case RPMTAG_DESCRIPTION:
	return "description";
    case RPMTAG_SIZE:
	return "size";
    case RPMTAG_DISTRIBUTION:
	return "distribution";
    case RPMTAG_OS:
	return "os";
#endif
    case RPMTAG_VENDOR:
	return "vendor";
    case RPMTAG_ARCH:
	return "arch";
    case RPMTAG_FILESIZES:
	return "filesizes";
    case RPMTAG_FILEMODES:
	return "filemodes";
#if 0
    case RPMTAG_FILESTATES:
	return "filestates";
    case RPMTAG_FILEUIDS:
	return "fileuids";
    case RPMTAG_FILEGIDS:
	return "filegids";
    case RPMTAG_FILERDEVS:
	return "filerdevs";
#endif
    case RPMTAG_FILEMTIMES:
	return "filemtimes";
    case RPMTAG_FILEDIGESTS:
	return "filedigests";
#if 0
    case RPMTAG_FILELINKTOS:
	return "filelinktos";
    case RPMTAG_FILEFLAGS:
	return "fileflags";
#endif
    case RPMTAG_FILEUSERNAME:
	return "fileusername";
    case RPMTAG_FILEGROUPNAME:
	return "filegroupname";
    case RPMTAG_INSTALLPREFIX:
	return "installprefix";
#if 0
    case RPMTAG_RPMVERSION:
	return "rpmversion";
    case RPMTAG_CHANGELOGTIME:
	return "changelogtime";
    case RPMTAG_CHANGELOGNAME:
	return "changelogname";
    case RPMTAG_CHANGELOGTEXT:
	return "changelogtext";
    case RPMTAG_FILEDEVICES:
	return "filedevices";
    case RPMTAG_FILEINODES:
	return "fileinodes";
    case RPMTAG_FILELANGS:
	return "filelangs";
#endif
    case RPMTAG_DIRINDEXES:
	return "dirindexes";
    case RPMTAG_BASENAMES:
	return "basenames";
    case RPMTAG_DIRNAMES:
	return "dirnames";
    default:
	return NULL;
    }
}

static int two_bytes_to_int16(u_int8_t* bytes)
{
    return ((int)bytes[1] | (int)bytes[0] << 8);
}

// Read four bytes and retrieve its decimal value
static int four_bytes_to_int32(u_int8_t* bytes)
{
    return ((int)bytes[3] | (int)bytes[2] << 8 | (int)bytes[1] << 16 | (int)bytes[0] << 24);
}

#if 0
static void read_chars(u_int8_t *bytes, int tag, int count)
{
	int i = 0;
	char *u_int8_t = bytes;

	for (i = 0; i < count; i++) {
		//printf("%d\n", *ptr);
		ptr += 1;
	}
}
#endif

static void read_shorts(u_int8_t *bytes, int tag, int count)
{
	int i = 0;
	u_int8_t *ptr = bytes;

	for (i = 0; i < count; i++) {
		if (tag == RPMTAG_FILEMODES && i == fileseq) {
			*_fmode = two_bytes_to_int16(ptr);
			return;
		}
		//printf("%o\n", two_bytes_to_int16(ptr));
		ptr += 2;
	}
}

static void read_ints(u_int8_t *bytes, int tag, int count)
{
	int i = 0, num = 0;
	u_int8_t *ptr = bytes;

	for (i = 0; i < count; i++) {
		num = four_bytes_to_int32(ptr);
		if (tag == RPMTAG_INSTALLTIME) {
			*_pkginstalltime = num;
			return;
		}
		if (tag == RPMTAG_DIRINDEXES && i == fileseq) {
			diridx = num;
			return;
		}
		if (tag == RPMTAG_FILEMTIMES && i == fileseq) {
			*_mtime = num;
			return;
		}
		if (tag == RPMTAG_FILESIZES && i == fileseq) {
			*_fsize = num;
			return;
		}
		//printf("%d\n", num);
		ptr += 4;
	}
}

static void read_strings(u_int8_t *bytes, int tag, int count)
{
	int i = 0, len = 0;
	char *ptr = (char *)bytes;

	for (i = 0; i < count; i++) {
		//printf("%s\n", ptr);
		switch(tag) {
		case RPMTAG_NAME:
			strncpy(_pkgname, ptr, S_NAMELEN);
			return;
		case RPMTAG_VERSION:
			strncpy(_version, ptr, S_NAMELEN);
			return;
		case RPMTAG_RELEASE:
			strncpy(_release, ptr, S_NAMELEN);
			return;
		case RPMTAG_ARCH:
			strncpy(_arch, ptr, S_NAMELEN);
			return;
		case RPMTAG_VENDOR:
			strncpy(_vendor, ptr, S_NAMELEN);
			return;
		case RPMTAG_FILEDIGESTS:
			if (i == fileseq) {
				strncpy(_digest, ptr, S_SHALEN);
				return;
			}
			break;
		case RPMTAG_FILEUSERNAME:
			if (i == fileseq) {
				strncpy(_username, ptr, S_NAMELEN);
				return;
			}
			break;
		case RPMTAG_FILEGROUPNAME:
			if (i == fileseq) {
				strncpy(_groupname, ptr, S_NAMELEN);
				return;
			}
			break;
		case RPMTAG_DIRNAMES:
			if (i == diridx) {
				if (strncmp(ptr, _cmd, dirlen) == 0) {
					match = 1;
					return;
				} else {
					/*
					 * 处理目录中间有链接的情况，比如
					 * /usr/libexec/gcc/x86_64-redhat-linux/4.4.7/collect2
					 * 4.4.7->4.4.4，DIRNAMES里只有4.4.4
					 */
					char path[PATH_MAX] = {0};
					struct stat st = {0};

					snprintf(path, PATH_MAX, "%s/%s", ptr, _cmdname);
					if (stat(path, &st) == 0 && st.st_ino == _inode) {
						match = 1;
						return;
					}
				}
			}
			break;
		default:
			break;
		}

		len = strlen(ptr) + 1;
		ptr += len;
	}
}

// Read index entry from a RPM header
static void read_entry(u_int8_t *bytes, rpmTagInfo *info)
{
    u_int8_t *entry = NULL;

    // Read 4 first bytes looking for a known tag
    info->tag = four_bytes_to_int32(bytes);

    // Read next 4 bytes (type)
    entry = &bytes[4];
    info->type = four_bytes_to_int32(entry);

    // Read next 4 bytes (offset)
    entry = &bytes[8];
    info->offset = four_bytes_to_int32(entry);

    // Last 4 bytes (count of elements of the entry)
    entry = &bytes[12];
    info->count = four_bytes_to_int32(entry);
}

int get_fileinfo_from_package_db(u_int8_t *data)
{
    int i = 0;
    int index = 0;
    u_int8_t *bytes = data;
    u_int8_t *tagdata = NULL;
    rpmTagInfo *info = NULL;
    rpmTagInfo *taginfo = NULL;
    char *str = NULL;

    match = 0;

    // Read number of index entries (First 4 bytes)
    index = four_bytes_to_int32(bytes);
    //printf("index %d\n", index);

    // Set offset to first index entry
    bytes += 8;

    taginfo = calloc(index, sizeof(rpmTagInfo));
    if (!taginfo) {
	MON_ERROR("NO memory!\n");
	return -1;
    }
    info = taginfo;

    // Read all indexes
    for (i = 0; i < index; i++) {
	read_entry(bytes, &info[i]);
	bytes += 16;
    }

    // Start reading the data
    tagdata = bytes;

    for (i = 0; i < index; i++) {
	info = &taginfo[i];
	bytes = &tagdata[info->offset];

	if (!(str = tag2str(info->tag))) {
	    continue;
	}

	//printf("\ntag %s(%d), type %d, count %d\n", str, info->tag, info->type, info->count);
        switch(info->type) {
                case 0:
                case 1:
                case 2:
                case 5:
                case 7:
                case 9:
                    break;

                case 3:   // int16
		    read_shorts(bytes, info->tag, info->count);
		    break;

                case 4:   // int32
		    read_ints(bytes, info->tag, info->count);
                    break;

                case 6:   // String
                    read_strings(bytes, info->tag, info->count);
                    break;

                case 8:   // Vector of strings
                    read_strings(bytes, info->tag, info->count);
		    break;

                default:
                    MON_ERROR("tag %s(%d) Unknown type: %d\n",
				str, info->tag, info->type);
		    break;
            }
        }

        // Free resources
	free(taginfo);

	return match;
}

typedef enum dbiIndexType_e {
    DBI_PRIMARY 	= (1 * sizeof(int32_t)),
    DBI_SECONDARY	= (2 * sizeof(int32_t)),
} dbiIndexType;

int search_basename_db(void)
{
    DBT key, data;
    DBT skey, sdata = {0};
    DB *dbp = NULL, *sdbp = NULL;
    int ret = 0, i = 0, count = 0, retval = -1;
    unsigned int hdrNum = 0, tagNum = 0;
    char *ptr = NULL;

    /* 打开主表Packages */

    if ((ret = db_create(&dbp, NULL, 0)) != 0) {
        MON_ERROR("initialize DB handler fail: %s", db_strerror(ret));
        return -1;
    }

    // Set Little-endian order by default
    if ((ret = dbp->set_lorder(dbp, 1234)) != 0) {
        MON_ERROR("set DB byte-order fail: %s", db_strerror(ret));
    }

    if ((ret = dbp->open(dbp, NULL, RPM_PACKAGE_DB, NULL, DB_UNKNOWN, DB_RDONLY, 0)) != 0) {
        MON_ERROR("open DB %s fail: %s\n", RPM_PACKAGE_DB, db_strerror(ret));
        dbp->close(dbp, 0);
        return -1;
    }

    /* 打开从表Basenames */

    if ((ret = db_create(&sdbp, NULL, 0)) != 0) {
        MON_ERROR("initialize DB handler fail: %s", db_strerror(ret));
        dbp->close(dbp, 0);
        return -1;
    }

    // Set Little-endian order by default
    if ((ret = sdbp->set_lorder(sdbp, 1234)) != 0) {
        MON_ERROR("set DB byte-order fail: %s", db_strerror(ret));
    }

    /* centos7.5 /var/lib/rpm/Basenames是DB_BTREE类型，之前是DB_HASH，用DB_UNKNOWN让open自己决定类型 */
    if (sdbp->open(sdbp, NULL, RPM_BASENAME_DB, NULL, DB_UNKNOWN, DB_RDONLY, 0) != 0) {
        MON_ERROR("open DB %s fail: %s\n", RPM_BASENAME_DB, db_strerror(ret));
        dbp->close(dbp, 0);
        sdbp->close(sdbp, 0);
        return -1;
    }

    memset(&skey, 0, sizeof(DBT));
    memset(&sdata, 0, sizeof(DBT));

    skey.data = _cmdname;
    skey.size = strlen(_cmdname);

    /* 文件不是rpm安装的 */
    if ((sdbp->get(sdbp, NULL, &skey, &sdata, 0)) != 0) {
        //printf("sdbp get fail %s", db_strerror(ret));
        dbp->close(dbp, 0);
        sdbp->close(sdbp, 0);
        return -1;
    }

    ptr = sdata.data;
    count = sdata.size / DBI_SECONDARY;
    //printf("sdata.size %d. count %d\n", sdata.size, count);

    /* 遍历sdata，如果多个软件包包含该命令，用校验值决定所属，
       如果校验值都不匹配，选用最后一个软件包 */
    for (i = 0; i < count; i++) {
        memcpy(&hdrNum, ptr, sizeof(hdrNum));
        ptr += sizeof(hdrNum);

        memcpy(&tagNum, ptr, sizeof(tagNum));
        ptr += sizeof(tagNum);

        //printf("hdrNum %u, tagNum %u\n", hdrNum, tagNum);

        fileseq = tagNum;

        memset(&key, 0, sizeof(DBT));
        memset(&data, 0, sizeof(DBT));

        key.data = &hdrNum;
        key.size = sizeof(hdrNum);

        if ((dbp->get(dbp, NULL, &key, &data, 0)) != 0) {
            MON_ERROR("dbp get fail: %s", db_strerror(ret));
            continue;
        }

        //printf("data.size %u\n", data.size);
        if (get_fileinfo_from_package_db(data.data)) {
            snprintf(_product, S_NAMELEN, "%s-%s-%s.%s",
                    thestring(_pkgname), thestring(_version),
                    thestring(_release), thestring(_arch));

            retval = 0; //找到软件包

            /* 检查校验值是否匹配，如果不匹配，继续查是否还有安装记录 */
            /* CentOS5是MD5, 6/7是SHA256 */
            if (strcmp(_digest, _sha256) == 0 || strcmp(_digest, _md5) == 0) {
                break;
            }
        }
    }

    dbp->close(dbp, 0);
    sdbp->close(sdbp, 0);
    return retval;
}

int get_fileinfo_from_rpmdb(char *cmd, exeinfo_t *exeinfo, char *md5, char *sha256)
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
        printf("%s linkto %s@%s line:%d\n", cmd, _cmd,__FILE__,__LINE__);
	}
	if (stat(_cmd, &st) == 0) {
		_inode = st.st_ino;
	}

	_md5 = md5;
	_sha256 = sha256;
	_vendor = exeinfo->vendor;
	_product = exeinfo->product;
	_digest = exeinfo->install_digest;
	_cmdname = safebasename(_cmd);
	dirlen = _cmdname - _cmd;
	_username = exeinfo->username;
	_groupname = exeinfo->groupname;
	_fsize = &(exeinfo->install_fsize);
	_fmode = &(exeinfo->install_fmode);
	_mtime = &(exeinfo->install_mtime);
	_pkginstalltime = &(exeinfo->pkginstalltime);

	return search_basename_db();
}
