#include "sys_info.h"
#ifdef SNIPER_FOR_DEBIAN

/* 从vendorstr的头部取安装包的arch。返回安装时间 */
time_t stat_dpkglist(char *name, char *vendorstr)
{
	char path[512];
    struct stat st;
    char *ptr = NULL;

    if (name == NULL || vendorstr == NULL) {
        return 0;
    }

    char *arch = vendorstr;

    memset(path, 0x00, sizeof(path));
    memset(&st, 0x00, sizeof(st));

	snprintf(path, 512, "/var/lib/dpkg/info/%s.list", name);
	if (stat(path, &st) == 0) {
		return st.st_mtime;
	}

	/* name.list没有，尝试name:arch.list */
	ptr = strchr(arch, ' ');
	if (!ptr) {
        memset(path, 0x00, sizeof(path));
		snprintf(path, 512, "/var/lib/dpkg/info/%s:%s.list", name, arch);
		if (stat(path, &st) == 0) {
			return st.st_mtime;
		}
		return 0;
	}

	*ptr = 0;
    memset(path, 0x00, sizeof(path));
	snprintf(path, 512, "/var/lib/dpkg/info/%s:%s.list", name, arch);
	*ptr = ' ';
	if (stat(path, &st) == 0) {
		return st.st_mtime;
	}

	return 0;
}

static char *software_install_path(const char *name)
{
    char cmd[PATH_MAX];
    char line[PATH_MAX];
    char install_path[PATH_MAX];
    char *default_path[] = {"/bin/",
                            "/sbin/",
                            "/usr/bin/",
                            "/usr/sbin",
                            "/usr/local/bin/",
                            "/usr/libexec/",
                            "/usr/lib64/",
                            /* for Ubuntu */
                            "/usr/lib/",
                            "/lib/x86_64-linux-gnu/",
                            "/usr/share/",
                            NULL
    };
    int default_len[] = {5, 6, 9, 9, 15, 13, 11, 9, 22, 11};
    int default_flag[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    FILE *fp = NULL;
    int i = 0;
    int offset = 0;

    if (name == NULL) return "None";
    
    memset(cmd, 0x00, sizeof(cmd));
#ifdef SNIPER_FOR_DEBIAN
    snprintf(cmd, sizeof(cmd), "dpkg -L %s", name);
#else
    snprintf(cmd, sizeof(cmd), "rpm -ql %s", name);
#endif
    if ((fp = popen(cmd, "r")) == NULL) {
        return "None";
    }

    memset(line, 0x00, sizeof(line));
    memset(install_path, 0x00, sizeof(install_path));

    while (fgets(line, sizeof(line), fp) != NULL) {
        i = 0;
        while (default_path[i]) {
            if (strncmp(line, default_path[i], default_len[i]) == 0) {
                if (offset) {
                    if (default_flag[i]) {
                        default_flag[i] = 0;
                        snprintf(install_path+offset, sizeof(install_path)-offset, ",%s", default_path[i]);
                        offset += default_len[i]+1;
                    }
                }
                else {
                    if (default_flag[i]) {
                        default_flag[i] = 0;
                    }
                    snprintf(install_path, sizeof(install_path)-offset, "%s", default_path[i]);
                    offset += default_len[i];
                }
            }
            ++i;
        }
    }
    fclose(fp);

    if (!offset) {
        snprintf(install_path, sizeof(install_path), "%s", "None");
    }

    return strdup(install_path);
}

static char **str_break(char match, const char *str, size_t size)
{
    size_t count = 0;
    size_t i = 0;
    const char *tmp_str = str;
    char **ret;

    /* We can't do anything if str is null */
    if (str == NULL) {
        return (NULL);
    }

    ret = (char **)calloc(size + 1, sizeof(char *));

    if (ret == NULL) {
        /* Memory error. Should provide a better way to detect it */
        return (NULL);
    }

    /* Allocate memory to null */
    while (i <= size) {
        ret[i] = NULL;
        i++;
    }
    i = 0;

    while (*str != '\0') {
        i++;
        if ((count < size - 1) && (*str == match)) {
            ret[count] = (char *)calloc(i, sizeof(char));

            if (ret[count] == NULL) {
                goto error;
            }

            /* Copy the string */
            ret[count][i - 1] = '\0';
            strncpy(ret[count], tmp_str, i - 1);

            tmp_str = ++str;
            count++;
            i = 0;

            continue;
        }
        str++;
    } /* leave from here when *str == \0 */


    /* Just do it if count < size */
    if (count < size) {
        ret[count] = (char *)calloc(i + 1, sizeof(char));

        if (ret[count] == NULL) {
            goto error;
        }

        /* Copy the string */
        ret[count][i] = '\0';
        strncpy(ret[count], tmp_str, i);

        count++;

        /* Make sure it is null terminated */
        ret[count] = NULL;

        return (ret);
    }

    /* We shouldn't get to this point
     * Just let "error" handle that
     */

error:
    i = 0;

    while (i < count) {
        free(ret[i]);
        i++;
    }

    free(ret);
    return (NULL);

}

int sys_deb_packages(sys_info_t *sys_data)
{
    char read_buff[PATH_MAX];
    char file[PATH_MAX] = "/var/lib/dpkg/status";
    char name[255] = {0};
    char arch[64] = {0};
    FILE *fp;
    cJSON *object = NULL;
    cJSON *package = NULL;
    size_t length;
    int i, installed = 1;

    if (sys_data == NULL || sys_data->object == NULL || sys_data->db == NULL) return -1;

    object = sys_data->object;

    memset(read_buff, 0, sizeof(read_buff));

    if ((fp = fopen(file, "r"))) {
        while(fgets(read_buff, sizeof(read_buff), fp) != NULL){
            // Remove '\n' from the read line
            length = strlen(read_buff);
            read_buff[length - 1] = '\0';
            /* 这里采用strncmp，只要开始匹配即可，为了获取当前行后面的内容 */
            if (strncmp(read_buff, "Package: ", 9) == 0) {
                package = cJSON_CreateObject();
                cJSON_AddItemToArray(object, package);

                char ** parts = NULL;
                parts = str_break(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "software_name", parts[1]);
                cJSON_AddStringToObject(package, "pkg_name", parts[1]);
                snprintf(name, sizeof(name), "%s", parts[1]);
                cJSON_AddNumberToObject(package, "software_status", software_service_state(parts[1], sys_data));
                char *tmp = software_install_path(parts[1]);
                cJSON_AddStringToObject(package, "install_path", tmp);
                free(tmp);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);
            } else if (strncmp(read_buff, "Status: ", 8) == 0) {
                if (strstr(read_buff, "install ok installed")){
                    installed = 1;
                } else {
                    installed = 0;
                }
            // } else if (strncmp(read_buff, "Priority: ", 10) == 0) {
            //     char ** parts = NULL;
            //     parts = str_break(' ', read_buff, 2);
            //     cJSON_AddStringToObject(package, "priority", parts[1]);
            //     for (i=0; parts[i]; i++){
            //         free(parts[i]);
            //     }
            //     free(parts);
            // } else if (strncmp(read_buff, "Section: ", 9) == 0) {
            //     char ** parts = NULL;
            //     parts = str_break(' ', read_buff, 2);
            //     cJSON_AddStringToObject(package, "group", parts[1]);
            //     for (i=0; parts[i]; i++){
            //         free(parts[i]);
            //     }
            //     free(parts);
            } else if (strncmp(read_buff, "Installed-Size: ", 16) == 0) {
                char ** parts = NULL;
                parts = str_break(' ', read_buff, 2);
                char size_str[64] = {0};
                snprintf(size_str, sizeof(size_str), "%sKB", parts[1]);
                cJSON_AddStringToObject(package, "size", size_str);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);
            } else if (strncmp(read_buff, "Maintainer: ", 12) == 0) {
                char ** parts = NULL;
                parts = str_break(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "publisher", parts[1]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);
            } else if (strncmp(read_buff, "Architecture: ", 14) == 0) {
                char ** parts = NULL;
                parts = str_break(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "architecture", parts[1]);
                snprintf(arch, sizeof(arch), "%s", parts[1]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);
            // } else if (strncmp(read_buff, "Multi-Arch: ", 12) == 0) {
            //     char ** parts = NULL;
            //     parts = str_break(' ', read_buff, 2);
            //     cJSON_AddStringToObject(package, "multi-arch", parts[1]);
            //     for (i=0; parts[i]; i++){
            //         free(parts[i]);
            //     }
            //     free(parts);
            // } else if (strncmp(read_buff, "Source: ", 8) == 0) {
            //     char ** parts = NULL;
            //     parts = str_break(' ', read_buff, 2);
            //     cJSON_AddStringToObject(package, "source", parts[1]);
            //     for (i=0; parts[i]; i++){
            //         free(parts[i]);
            //     }
            //     free(parts);
            } else if (strncmp(read_buff, "Version: ", 9) == 0) {
                char ** parts = NULL;
                parts = str_break(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "version", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);
            } else if (strncmp(read_buff, "Description: ", 13) == 0) {
                char ** parts = NULL;
                parts = str_break(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "description", parts[1]);
                cJSON_AddStringToObject(package, "pkg_desc", parts[1]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);
                // Send message to the queue
                if (installed) {
                    installed = 0;
                } else {
                    continue;
                }
            }

            if (name[0] && arch[0]) {
                char idate[64];
                struct tm t;
                char *vendor = trim_space(arch);
                time_t install_time = stat_dpkglist(name, vendor);
                localtime_r(&install_time, &t);
                memset(idate, 0x00, sizeof(idate));
                strftime(idate, sizeof(idate), "%Y-%m-%d %H:%M:%S", &t);
                if (install_time < get_os_install_time()) {
                    set_os_install_time(install_time);
                }
                cJSON_AddStringToObject(package, "install_time", idate);
                cJSON_AddStringToObject(package, "pkg_type", "dpkg");
                memset (arch, 0x00, sizeof(arch));
                memset (name, 0x00, sizeof(name));
            }
        }
        fclose(fp);
    } else {
        elog("Unable to open the file '%s'", file);
        return -1;
    }

    return 0;
}
#endif
