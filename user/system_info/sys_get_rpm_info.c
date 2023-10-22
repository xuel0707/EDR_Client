#include "sys_info.h"
#ifndef SNIPER_FOR_DEBIAN

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

typedef struct rpm_data {
    char *tag;
    int type;
    int offset;
    int count;
    struct rpm_data *next;
} rpm_data;

static int four_bytes_to_int32(u_int8_t* bytes)
{
    int result = (int)bytes[3] | (int)bytes[2] << 8 | (int)bytes[1] << 16 | (int)bytes[0] << 24;
    return result;
}

/* 需要其它项，把注释打开即可 */
static int read_entry(u_int8_t* bytes, rpm_data *info)
{
    u_int8_t* entry = NULL;
    char* tag_name = NULL;
    int tag = 0;

    tag = four_bytes_to_int32(bytes);
    switch(tag) {
        case RPMTAG_NAME:
            tag_name = "software_name";
            break;
        case RPMTAG_VERSION:
            tag_name = "version";
            break;
        case RPMTAG_RELEASE:
            tag_name = "release";
            break;
        case RPMTAG_EPOCH:
            tag_name = "epoch";
            break;
        case RPMTAG_INSTALLTIME:
            tag_name = "install_time";
            break;
        case RPMTAG_SUMMARY:
            tag_name = "pkg_desc";
            break;
        // 有的包太长了暂时只获取包的摘要信息
        // case RPMTAG_DESCRIPTION:
        //     tag_name = "description";
        //     break;
        case RPMTAG_SIZE:
            tag_name = "size";
            break;
        case RPMTAG_DISTRIBUTION:
            tag_name = "distribution";
            break;
        // case RPMTAG_OS:
        //     tag_name = "os";
        //     break;
        case RPMTAG_VENDOR:
            tag_name = "publisher";
            break;
        // case RPMTAG_ARCH:
        //     tag_name = "arch";
        //     break;
        // case RPMTAG_FILESIZES:
        //     tag_name = "filesizes";
        //     break;
        // case RPMTAG_FILEMODES:
        //     tag_name = "filemodes";
        //     break;
        // case RPMTAG_FILESTATES:
        //     tag_name = "filestates";
        //     break;
        // case RPMTAG_FILEUIDS:
        //     tag_name = "fileuids";
        //     break;
        // case RPMTAG_FILEGIDS:
        //     tag_name = "filegids";
        //     break;
        // case RPMTAG_FILERDEVS:
        //     tag_name = "filerdevs";
        //     break;
        // case RPMTAG_FILEMTIMES:
        //     tag_name = "filemtimes";
        //     break;
        // case RPMTAG_FILEDIGESTS:
        //     tag_name = "filedigests";
        //     break;
        // case RPMTAG_FILELINKTOS:
        //     tag_name = "filelinktos";
        //     break;
        // case RPMTAG_FILEFLAGS:
        //     tag_name = "fileflags";
        //     break;
        // case RPMTAG_FILEUSERNAME:
        //     tag_name = "fileusername";
        //     break;
        // case RPMTAG_FILEGROUPNAME:
        //     tag_name = "filegroupname";
        //     break;
        // case RPMTAG_INSTALLPREFIX:
        //     tag_name = "installprefix";
        //     break;
        // case RPMTAG_RPMVERSION:
        //     tag_name = "rpmversion";
        //     break;
        // case RPMTAG_CHANGELOGTIME:
        //     tag_name = "changelogtime";
        //     break;
        // case RPMTAG_CHANGELOGNAME:
        //     tag_name = "changelogname";
        //     break;
        // 有的太长会段错误
        // case RPMTAG_CHANGELOGTEXT:
        //     tag_name = "changelogtext";
        //     break;
        // case RPMTAG_FILEDEVICES:
        //     tag_name = "filedevices";
        //     break;
        // case RPMTAG_FILEINODES:
        //     tag_name = "fileinodes";
        //     break;
        // case RPMTAG_FILELANGS:
        //     tag_name = "filelangs";
        //     break;
        // case RPMTAG_DIRINDEXES:
        //     tag_name = "dirindexes";
        //     break;
        // case RPMTAG_BASENAMES:
        //     tag_name = "basenames";
        //     break;
        case RPMTAG_DIRNAMES:
            tag_name = "install_path";
            break;
        default:
            return -1;
    }

    info->tag = strdup(tag_name);
    entry = &bytes[4];
    info->type = four_bytes_to_int32(entry);
    entry = &bytes[8];
    info->offset = four_bytes_to_int32(entry);
    entry = &bytes[12];
    info->count = four_bytes_to_int32(entry);

    return 0;
}

static char* read_string(u_int8_t* bytes)
{
    char * data;
    char hex[10];
    int i = 0;

    data = (char*)calloc(1024, sizeof(char));
    if (!data) {
        return NULL;
    }

    while (bytes[i]) {
        sprintf(hex, "%c", bytes[i]);
        strcat(data, hex);
        i++;
    }

    return data;

}

static char *get_timestamp(time_t time)
{
    struct tm localtm;
    char *timestamp;

    localtime_r(&time, &localtm);
    timestamp = (char*)calloc(128, sizeof(char));
    snprintf(timestamp, 128, "%d-%02d-%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    return timestamp;
}
int sys_rpm_packages(sys_info_t *sys_data)
{
    char release[256];
    char final_version[256];
    char pkg_name[256];
    char version[64];
    const char *RPM_DATABASE = "/var/lib/rpm/Packages";
    DBT key, data;
    cJSON *object = NULL;
    cJSON *package = NULL;
    DBC *cursor;
    DB *dbp;
    u_int8_t* bytes;
    u_int8_t* store;
    rpm_data *info;
    rpm_data *next_info;
    rpm_data *head;
    int ret = 0;
    int i;
    int j;
    int index, offset;
    int epoch;

    if (sys_data == NULL || sys_data->object == NULL || sys_data->db == NULL) return -1;

    object = sys_data->object;
    // Define time to sleep between messages sent
    if ((ret = db_create(&dbp, NULL, 0)) != 0) {
        return -1;
    }

    if (ret = dbp->set_lorder(dbp, 1234), ret != 0) {
        elog("Error setting byte-order.\n");
    }
    if ((ret = dbp->open(dbp, NULL, RPM_DATABASE, NULL, DB_HASH, DB_RDONLY, 0)) != 0) {
        elog("Failed to open database '%s': %s\n", RPM_DATABASE, db_strerror(ret));
        return -1;
    }

    if ((ret = dbp->cursor(dbp, NULL, &cursor, 0)) != 0) {
        elog("Error creating cursor: %s\n", db_strerror(ret));
        return -1;
    }

    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));
    for (j=0; ret=cursor->c_get(cursor, &key, &data, DB_NEXT), ret==0; j++) {
        if (j == 0) {
            continue;
        }
        bytes = (u_int8_t*)data.data;
        index = four_bytes_to_int32(bytes);
        offset = 8;
        bytes = &bytes[offset];

        info = (rpm_data*)calloc(1, sizeof(rpm_data));
        if (!info) {
            goto END;
        }
        head = info;

        for (i = 0; i < index; i++) {
            offset = 16;
            if ((ret = read_entry(bytes, info)), ret == 0) {
                info->next = (rpm_data*)calloc(1, sizeof(rpm_data));
                if (!info->next) {
                    goto END;
                }
                info = info->next;
            }
            bytes = &bytes[offset];
        }

        store = bytes;
        epoch = 0;
        package = cJSON_CreateObject();
        cJSON_AddItemToArray(object, package);

        for (info = head; info; info = next_info) {
            next_info = info->next;
            bytes = &store[info->offset];
            char * read;
            long result;

            switch(info->type) {
                case 0:
                    break;
                case 1:
                    break;
                case 3:
                    // RPMTAG_FILEMODES
                    break;
                case 6:   // String
                    read = read_string(bytes);
                    if (!strncmp(info->tag, "version", 7)) {
                        snprintf(version, sizeof(version) - 1, "%s", read);
                    } else if (!strncmp(info->tag, "release", 7)) {
                        snprintf(release, sizeof(release) - 1, "%s", read);
                    } else {
                        if (!strncmp(info->tag, "software_name", 13)) {
                            memset(pkg_name, 0x00, sizeof(pkg_name));
                            snprintf(pkg_name, sizeof(pkg_name), "%s", read);
                            cJSON_AddStringToObject(package, "pkg_name", read);
                        }
                        cJSON_AddStringToObject(package, info->tag, read);
                    }
                    free(read);
                    break;
                case 4:   // int32
                    result = four_bytes_to_int32(bytes);
                    if (!strncmp(info->tag, "size", 4)) {
                        result = result / 1024;   // KB
                        char size_str[64] = {0};
                        snprintf(size_str, sizeof(size_str), "%ldKB", result);
                        cJSON_AddStringToObject(package, info->tag, size_str);
                        break;
                    }
                    if (!strncmp(info->tag, "install_time", 12)) {    // Format date
                        char *installt = get_timestamp(result);
                        cJSON_AddStringToObject(package, info->tag, installt);
                        free(installt);
                        if (result < get_os_install_time()) {
                            set_os_install_time(result);
                        }
                    } else if (!strncmp(info->tag, "epoch", 5)) {
                        epoch = result;
                    } else {
                        cJSON_AddNumberToObject(package, info->tag, result);
                    }
                    break;
                case 8:
                case 9:   // Vector of strings
                    read = read_string(bytes);
                    cJSON_AddStringToObject(package, info->tag, read);
                    free(read);
                    break;
                default:
                    elog("Unknown type of data: %d \n", info->type);
            }
        }

        /*
         * 如dpkg -l所示，deb包的版本，按epoch:version-release的格式展示
         * 而rpm包，则默认按version-release的格式展示，如rpm -qa所示
         * 显示epoch反而可能会给CentOS用户带来困扰，干脆不显示，免得还费口舌解释
         */
        snprintf(final_version, sizeof(final_version), "%s-%s", version, release);
        cJSON_AddStringToObject(package, "version", final_version);
        cJSON_AddStringToObject(package, "pkg_type", "rpm");
        cJSON_AddNumberToObject(package, "software_status", software_service_state(pkg_name, sys_data));

        for (info = head; info; info = next_info) {
            next_info = info->next;
            free(info->tag);
            free(info);
        }
    }

    if (ret == DB_NOTFOUND && j <= 1) {
        elog("Not found any record in database '%s'\n", RPM_DATABASE);
    }

    cursor->c_close(cursor);
    dbp->close(dbp, 0);

    return 0;
END:
    for (info = head; info; info = next_info) {
        next_info = info->next;
        if (info->tag) {
            free(info->tag);
        }
        free(info);
    }
    return -1;
}

#endif
