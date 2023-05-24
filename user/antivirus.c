/* std */
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <locale.h>

#include "miniunz.h"
#include "header.h"
#include "file.h"
#include "lst.h"
#include "savapi_unix.h"

#define SQLITE_OPEN_MODE SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_SHAREDCACHE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE

pthread_mutex_t virus_datebase_update_lock;

static int savapi_on = 0;

static struct virus_msg_args *msg = NULL;
static int first_virus_check = 0;
static sqlite3* virus_db = NULL;

static SAVAPI_GLOBAL_INIT global_init = {0};
static SAVAPI_FD instance_handle = NULL;
static SAVAPI_INSTANCE_INIT instance_init = {0};
static int savapi_inited = -1;
static int instance_created = -1;
static int callbacks_registered = -1;

/* 小红伞引擎需要的内存 */
#define SAVAPI_INIT_MEM         290 //加载引擎内存多占用了290M
#define SAVAPI_FINI_MEM         90  //引擎回收资源后仍有90M资源无法释放

const char crt_virus_tbl_sql[1024] =
{
	"CREATE TABLE IF NOT EXISTS virus( "
	"id integer PRIMARY KEY AUTOINCREMENT,"
	"mtime int,"                               //备份时间
	"md5   varchar(4096),"                     //备份新文件名
	"path  varchar(4096),"                     //备份原文件名
	"uid   int,"                               //备份原文件uid
	"gid   int,"                               //备份原文件gid
	"mode  int);"                              //备份原文件属性
};

const char* virus_new_sql = "INSERT INTO virus VALUES(NULL,?,?,?,?,?,?);";
const char* virus_update_sql = "UPDATE virus SET mtime=?,uid=?,gid=?,mode=? WHERE path=?;";
const char* virus_delete_md5_sql = "DELETE from virus WHERE md5=?;";
const char* virus_select_md5_sql = "SELECT md5 from virus order by mtime;";

static sqlite3_stmt* virus_new_stmt = NULL;
static sqlite3_stmt* virus_update_stmt = NULL;
static sqlite3_stmt* virus_delete_md5_stmt = NULL;
static sqlite3_stmt* virus_select_md5_stmt = NULL;

/* 初始化隔离病毒的数据库 */
void init_virus_db(void)
{
	char dbname[140] = {0};

	snprintf(dbname, sizeof(dbname), "%s/%s/virus.db", WORKDIR, VIRUSDB);
	virus_db = connectDb(dbname, crt_virus_tbl_sql, NULL, &first_virus_check);
	if (virus_db == NULL) {
		MON_ERROR("connect virus db failed\n");
		return;
	}
	chmod(dbname, 0666);

	sqlite3_busy_handler(virus_db, db_busy_callback, NULL );
	sqlite3_prepare_v2(virus_db, virus_new_sql, -1, &virus_new_stmt, NULL);
	sqlite3_prepare_v2(virus_db, virus_update_sql, -1, &virus_update_stmt, NULL);
	sqlite3_prepare_v2(virus_db, virus_delete_md5_sql, -1, &virus_delete_md5_stmt, NULL);
	sqlite3_prepare_v2(virus_db, virus_select_md5_sql, -1, &virus_select_md5_stmt, NULL);
}

/* 回收隔离病毒数据库的资源 */
void fini_virus_db(void)
{
	if (virus_db == NULL) {
		return;
	}

	sqlite3_finalize(virus_new_stmt);
	sqlite3_finalize(virus_update_stmt);
	sqlite3_finalize(virus_delete_md5_stmt);
	sqlite3_finalize(virus_select_md5_stmt);
	sqlite3_close_v2(virus_db);
}

/* 调用小红伞引擎的错误代码转换成提示信息 */
static char* scan_error_to_string(int error_code)
{
	switch(error_code) {
		case SAVAPI_E_INVALID_PARAMETER:
			return "Invalid parameter";
		case SAVAPI_E_NO_MEMORY:
			return "Out of memory";
		case SAVAPI_E_INTERNAL:
			return "Internal error";
		case SAVAPI_E_HIT_MAX_REC:
			return "Maximum archive recursion reached!";
		case SAVAPI_E_HIT_MAX_SIZE:
			return "Maximum archive size reached!";
		case SAVAPI_E_HIT_MAX_RATIO:
			return "Maximum archive ratio reached!";
		case SAVAPI_E_HIT_MAX_COUNT:
			return "Maximum archive number of files in archive reached!";
		case SAVAPI_E_ENCRYPTED_MIME:
			return "Encrypted content found!";
		case SAVAPI_E_ENCRYPTED:
			return "Encrypted content found!";
		case SAVAPI_E_UNSUPPORTED:
			return "Archive type unsupported!";
		case SAVAPI_E_UNSUPPORTED_COMPRESSION:
			return "Compression method unsupported!";
		case SAVAPI_E_PROC_INCOMPLETE_BLOCK_READ:
			return "Read block unexpected end!";
		case SAVAPI_E_PROC_BAD_HEADER:
			return "Invalid archive header!";
		case SAVAPI_E_PROC_INVALID_COMPRESSED_DATA:
			return "Invalid compressed data!";
		case SAVAPI_E_PROC_OBSOLETE:
			return "Obsolete information!";
		case SAVAPI_E_PROC_BAD_FORMAT:
			return "Invalid specified format!";
		case SAVAPI_E_PROC_HEADER_CRC:
			return "Invalid header signature!";
		case SAVAPI_E_PROC_DATA_CRC:
			return "Invalid data signature!";
		case SAVAPI_E_PROC_FILE_CRC:
			return "Invalid file signature!";
		case SAVAPI_E_PROC_BAD_TABLE:
			return "Invalid decompression table!";
		case SAVAPI_E_PROC_UNEXPECTED_EOF:
			return "Unexpected end of file reached!";
		case SAVAPI_E_PROC_ARCHIVE_HANDLE:
			return "Archive handle not initialized!";
		case SAVAPI_E_PROC_NO_FILES_TO_EXTRACT:
			return "Archive invalid or corrupted!";
		case SAVAPI_E_PROC_CALLBACK:
			return "Callback invalid or causes an error!";
		case SAVAPI_E_PROC_TOTAL_LOSS:
			return "Archive contents cannot be extracted!";
		case SAVAPI_E_PROC_ERROR:
			return "Error while processing file!";
		case SAVAPI_E_INCOMPLETE:
			return "Not all file contents could be scanned!";
		case SAVAPI_E_PARTIAL:
			return "File is part of a multi-volume archive!";
		case SAVAPI_E_ABORTED:
			return "Scan aborted (requested by user)!";
		case SAVAPI_E_TIMEOUT:
			return "Scan aborted (timeout reached)!";
		case SAVAPI_E_MATCHED:
			return "matched!";
		case SAVAPI_E_LICENSE_RESTRICTION:
			return "Operation not allowed (license restriction)!";
		case SAVAPI_E_REPAIR_FAILED:
			return "Failed to repair file!";
		case SAVAPI_E_CONVERSION_FAILED:
			return "Conversion failed";
		case SAVAPI_E_UNKNOWN:
			return "Unknown engine error occurred";
		case SAVAPI_E_NON_ADDRESSABLE:
			return "Memory area not addressable";
		case SAVAPI_E_MEMORY_LIMIT:
			return "Internal memory limit reached";
		case SAVAPI_E_BUFFER_TOO_SMALL:
			return "Buffer too small";
		case SAVAPI_E_VDF_NOT_FOUND:
			return "One or more VDF files not found";
		case SAVAPI_E_VDF_READ:
			return "Failed to read VDF file";
		case SAVAPI_E_VDF_CRC:
			return "Failed to check VDF file signature";
		case SAVAPI_E_ENGINE_NOT_FOUND:
			return "One or more engine files not found";
		case SAVAPI_E_KEYFILE:
			return "Invalid key file (CRC error)";
		case SAVAPI_E_NOT_SUPPORTED:
			return "Unsupported feature";
		case SAVAPI_E_OPTION_NOT_SUPPORTED:
			return "Unsupported option";
		case SAVAPI_E_FILE_OPEN:
			return "File open error";
		case SAVAPI_E_FILE_READ:
			return "File read error";
		case SAVAPI_E_FILE_WRITE:
			return "File write error";
		case SAVAPI_E_NOT_ABSOLUTE_PATH:
			return "Not an absolute path";
		case SAVAPI_E_FILE_CREATE:
			return "Failed to create file";
		case SAVAPI_E_FILE_DELETE:
			return "Failed to delete file";
		case SAVAPI_E_FILE_CLOSE:
			return "Failed to close file";
		case SAVAPI_E_PREFIX_SET:
			return "Failed to set a detect type option";
		case SAVAPI_E_PREFIX_GET:
			return "Failed to retrieve a detect type option";
		case SAVAPI_E_INVALID_QUERY:
			return "Invalid query for SAVAPI Service";
		case SAVAPI_E_KEY_NO_KEYFILE:
			return "Keyfile has not been found";
		case SAVAPI_E_KEY_ACCESS_DENIED:
			return "Access to key file has been denied";
		case SAVAPI_E_KEY_INVALID_HEADER:
			return "Invalid header has been found";
		case SAVAPI_E_KEY_KEYFILE_VERSION:
			return "Invalid keyfile version number";
		case SAVAPI_E_KEY_NO_LICENSE:
			return "No valid license found";
		case SAVAPI_E_KEY_FILE_INVALID:
			return "Key file is invalid (invalid CRC)";
		case SAVAPI_E_KEY_RECORD_INVALID:
			return "Invalid license record detected";
		case SAVAPI_E_KEY_EVAL_VERSION:
			return "Application is evaluation version";
		case SAVAPI_E_KEY_DEMO_VERSION:
			return "Application is demo version";
		case SAVAPI_E_KEY_ILLEGAL_LICENSE:
			return "Illegal (cracked) license in keyfile";
		case SAVAPI_E_KEY_EXPIRED:
			return "This key has expired";
		case SAVAPI_E_KEY_READ:
			return "Failed to reading from key file";
		case SAVAPI_E_BUSY:
			return "Operation could not be performed (resource is busy)";
		case SAVAPI_E_APC_CONNECTION:
			return "Communication with cloud server failed";
		case SAVAPI_E_APC_NOT_SUPPORTED:
			return "APC protocol is not supported";
		case SAVAPI_E_APC_ERROR:
			return "APC error occurred";
		case SAVAPI_E_APC_TIMEOUT:
			return "APC timeout occurred";
		case SAVAPI_E_APC_TEMPORARILY_DISABLED:
			return "APC declared unreachable (too many failed scans with APC)";
		case SAVAPI_E_APC_INCOMPLETE:
			return "Not all objects could be scanned with APC";
		case SAVAPI_E_APC_NO_LICENSE:
			return "No valid APC license found";
		case SAVAPI_E_APC_AUTHENTICATION:
			return "APC authentication failed";
		case SAVAPI_E_APC_AUTH_RETRY_LATER:
			return "APC authentication was not successful. Retry later";
		case SAVAPI_E_APC_RANDOM_ID:
			return "APC random id is invalid, not accesible or not computable";
		case SAVAPI_E_APC_DISABLED:
			return "APC is permanently disabled";
		case SAVAPI_E_APC_TIMEOUT_RESTRICTION:
			return "APC timeout restrictions not met: APCConnectionTimeout < APCScanTimeout < ScanTimeout";
		case SAVAPI_E_APC_UNKNOWN_CATEGORY:
			return "Could not determine category for object scanned with APC";
		case SAVAPI_E_APC_QUOTA:
			return "APC quota limit reached";
		default:
			return "Unknown error code!";
	}
}

/* 获取antivirus线程消耗的内存大小 */
int get_antivirus_mem(void)
{

	/*
	 * antivirus线程占用内存分为三种情况
	 * 1.没有开过实时检测的开关，内存占用为0
	 * 2.实时检测打开，加载了资源，消耗290M内存
	 * 3.实时检测关闭，释放了资源，仍然消耗90M内存
	 */

	if (savapi_on == 0) {
		return 0;
	}

	if (savapi_inited == SAVAPI_S_OK) {
		return SAVAPI_INIT_MEM;
	} else {
		return SAVAPI_FINI_MEM;
	}
}

/* 发送病毒程序升级信息给管控 */
static void send_antivirus_update_msg(task_recv_t *msg, int result)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	char log_name[LOG_NAME_MAX] = {0};
	unsigned long event_time = 0;
	struct timeval tv = {0};
	int level = MY_LOG_KEY;

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	gettimeofday(&tv, NULL);
	snprintf(log_name, sizeof(log_name), "%s", "VirusLibraryUpgrade");
	event_time = (tv.tv_sec + serv_timeoff) * 1000 + (int)tv.tv_usec / 1000;

	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "Client");
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", "root");
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddStringToObject(arguments, "old_version", msg->old_version);
	cJSON_AddStringToObject(arguments, "new_version", msg->new_version);
	cJSON_AddNumberToObject(arguments, "upgrade_type", msg->upgrade_type);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "task");
	DBG2(DBGFLAG_TASK, "post:%s, reply:%s\n", post, reply);
//	printf("post:%s, reply:%s\n", post, reply);

	cJSON_Delete(object);
	free(post);
}

/* 安装或更新病毒库, 成功返回0，失败返回-1 */
int update_virus_lib(char *lib_version, char *lib_md5)
{
	int ret = 0;
	char *lib_name = NULL;
	char unzip_dir[PATH_MAX] = {0};
	char vdf_dir[PATH_MAX] = {0};
	char filename[S_FILENAMELEN] = {0};
	char check_file[PATH_MAX] = {0};
	int len_all = 0, len = 0;
	int match = 0, i = 0;
	char md5[S_MD5LEN] = {0};
	struct stat st = {0};

	/* 下载病毒库的压缩包 */
	snprintf(filename, sizeof(filename), "anti-%s-lib.zip", lib_version);
	INFO("download virus lib %s\n", filename);
	ret = download_rule_file(DOWNLOAD_VIRUS_URL, filename, VIRUS_LIB_FILE);
	if (ret < 0) {
		MON_ERROR("download virus lib Failed\n");
		return ret;
	}
	INFO("download virus lib ok\n");

	if (stat(VIRUS_LIB_FILE, &st) < 0) {
		MON_ERROR("%s get stat failed\n", VIRUS_LIB_FILE);
		return -1;
	}

	ret = md5_file(VIRUS_LIB_FILE, md5);
	if (ret < 0) {
		MON_ERROR("virus lib get md5 failed\n");
		return -1;
	}

	/* 下载的地址不对，返回的错误信息会生成文件 */
	if (strcmp(md5, "597ba0d4396e9c906225140ce907092c") == 0) {
		MON_ERROR("download virus lib url error\n");
		return -1;
	}

	/* 下载的文件小于200字节, 远小于病毒库，说明不是真正的库文件 */
	if (st.st_size < 200) {
		MON_ERROR("incorrect virus lib downloaded\n");
		return -1;
	}

	if (strcmp(md5, lib_md5) != 0) {
		MON_ERROR("virus lib md5(%s) check error\n", md5);
		return -1;
	}

	/* 获取解压后的目录路径 */
	len_all = strlen(filename);
	lib_name = strrchr(filename, '.');
	if (!lib_name) {
		return -1;
	}
	len = len_all - strlen(lib_name);
	filename[len] = 0;
	snprintf(unzip_dir, sizeof(unzip_dir), "%s%s", DOWNLOAD_DIR, filename);
	snprintf(vdf_dir, sizeof(vdf_dir), "%s/linux/vdf", thestring(unzip_dir));
	snprintf(check_file, sizeof(check_file), "%s/linux/vdf/xvdfmerge_example", thestring(unzip_dir));

	/* 删除之前残留的解压目录 */
	if (access(unzip_dir, F_OK) == 0) {
		if (remove_dir(unzip_dir) < 0) {
			MON_ERROR("remove virus lib unzip dir failed\n");
			return -1;
		}
	}

	#if 0 
	/* 解压病毒库文件, -o表示解压时不询问是否替换 */
	snprintf(cmd, sizeof(cmd), "unzip -o -d %s %s > /dev/null 2>&1", DOWNLOAD_DIR,  VIRUS_LIB_FILE);
	pp = popen(cmd, "r");
	if (!pp) {
		MON_ERROR("virus lib unzip failed\n");

		/*把残留的解压目录删除*/
		remove_dir(unzip_dir);

		return -1;
	}
	pclose(pp);
	#endif

	if ((ret = unzip_to_dir(VIRUS_LIB_FILE, DOWNLOAD_DIR, NULL)) < 0) {
                MON_ERROR("uncompress the virus files failed.\n");
                return ret;
        }

	/* 通过确认特殊文件是否存在判断解压是否结束 */
	for (i = 0; i < 10; i++) {
		if (access(check_file, F_OK) == 0) {
			match = 1;
			break;
		}
		sleep(1);
	}

	if (match == 0) {
		MON_ERROR("virus lib unzip error\n");

		/*把残留的解压目录删除*/
		remove_dir(unzip_dir);

		return -1;
	}

	/* 删除病毒库备份残留目录 */
	if (access(ANTIVIRUS_VDFS_DIRPATH_BAK, F_OK) == 0) {
		if (remove_dir(ANTIVIRUS_VDFS_DIRPATH_BAK) < 0) {
			MON_ERROR("remove virus vdfs backup dir failed\n");

			/*把残留的解压目录删除*/
			remove_dir(unzip_dir);

			return -1;
		}
	}

	/* 备份原来的病毒库 */
	if (access(ANTIVIRUS_VDFS_DIRPATH, F_OK) == 0) {
		if (rename(ANTIVIRUS_VDFS_DIRPATH, ANTIVIRUS_VDFS_DIRPATH_BAK) < 0) {
			/*把残留的解压目录删除*/
			remove_dir(unzip_dir);

			return -1;
		}
	}

	/* 拷贝新下载的病毒库到指定位置 */
	if (rename(vdf_dir, ANTIVIRUS_VDFS_DIRPATH) < 0) {
		rename(ANTIVIRUS_VDFS_DIRPATH_BAK, ANTIVIRUS_VDFS_DIRPATH);
		/*把残留的解压目录删除*/
		remove_dir(unzip_dir);

		return -1;
	}

	/* 删除病毒库备份残留目录 */
	if (access(ANTIVIRUS_VDFS_DIRPATH_BAK, F_OK) == 0) {
		if (remove_dir(ANTIVIRUS_VDFS_DIRPATH_BAK) < 0) {
			MON_ERROR("remove virus vdfs backup dir failed\n");

			/*把残留的解压目录删除*/
			remove_dir(unzip_dir);

			return -1;
		}
	}

	/* 删除新下载解压后的病毒库目录 */
	if (access(unzip_dir, F_OK) == 0) {
		if (remove_dir(unzip_dir) < 0) {
			MON_ERROR("remove virus lib unzip dir failed\n");
			return -1;
		}
	}

	/* 更新病毒库版本号 */
	save_lib_version(VIRUSLIB_VERSION_FILE, lib_version);
	snprintf(virus_lib_ver_global, sizeof(virus_lib_ver_global), "%s", lib_version);

	return ret;
}

/* 更新防病毒程序, 成功返回0，失败返回-1 */
static int update_antivirus(char *antivirus_version, char *antivirus_md5)
{
	int ret = 0;
	FILE *pp = NULL;
	char cmd[S_CMDLEN] = {0};
	char *lib_name = NULL;
	char unzip_dir[PATH_MAX] = {0};
	char file[PATH_MAX] = {0};
	char filename[S_FILENAMELEN] = {0};
	int len_all = 0, len = 0;
	int match = 0, i = 0;
	char md5[S_MD5LEN] = {0};
	struct stat st = {0};

	/* 下载防病毒程序的压缩包 */
	snprintf(filename, sizeof(filename), "anti-%s-linux.zip", antivirus_version);
	INFO("download antivirus %s\n", filename);
	ret = download_rule_file(DOWNLOAD_ANTIVIRUS_URL, filename, ANTIVIRUS_FILE);
	if (ret < 0) {
		MON_ERROR("download antivirus Failed\n");
		return ret;
	}
	INFO("download antivirus ok\n");

	if (stat(ANTIVIRUS_FILE, &st) < 0) {
		MON_ERROR("%s get stat failed\n", ANTIVIRUS_FILE);
		return -1;
	}

	ret = md5_file(ANTIVIRUS_FILE, md5);
	if (ret < 0) {
		MON_ERROR("antivirus get md5 failed\n");
		return -1;
	}

	/* 下载的地址不对，返回的错误信息会生成文件 */
	if (strcmp(md5, "597ba0d4396e9c906225140ce907092c") == 0) {
		MON_ERROR("download antivirus url error\n");
		return -1;
	}

	/* 下载的文件小于200字节, 远小于病毒程序，说明不是真正的病毒程序文件 */
	if (st.st_size < 200) {
		MON_ERROR("incorrect antivirus downloaded\n");
		return -1;
	}

	if (strcmp(md5, antivirus_md5) != 0) {
		MON_ERROR("antivirus md5(%s) check error\n", md5);
		return -1;
	}

	/* 获取解压后的目录路径 */
	len_all = strlen(filename);
	lib_name = strrchr(filename, '.');
	if (!lib_name) {
		return -1;
	}
	len = len_all - strlen(lib_name);
	filename[len] = 0;
	snprintf(unzip_dir, sizeof(unzip_dir), "%s%s", DOWNLOAD_DIR, filename);
	snprintf(file, sizeof(file), "%s/%s/sniper_antivirus", thestring(unzip_dir), OS_DIR);

	/* 删除之前残留的解压目录 */
	if (access(unzip_dir, F_OK) == 0) {
		if (remove_dir(unzip_dir) < 0) {
			MON_ERROR("remove antivirus unzip dir failed\n");
			return -1;
		}
	}

	/* 解压防病毒程序压缩包 */
	snprintf(cmd, sizeof(cmd), "unzip -d %s %s > /dev/null 2>&1", DOWNLOAD_DIR,  ANTIVIRUS_FILE);
	pp = popen(cmd, "r");
	if (!pp) {
		MON_ERROR("antivirus unzip failed\n");
		return -1;
	}
	pclose(pp);

	/* 通过确认防病毒文件是否存在判断解压是否结束 */
	for (i = 0; i < 10; i++) {
		if (access(file, F_OK) == 0) {
			match = 1;
			break;
		}
		sleep(1);
	}

	if (match == 0) {
		MON_ERROR("antivirus unzip error\n");
		return -1;
	}

	/* 删除防病毒程序备份残留文件 */
	if (access(ANTIVIRUS_PATH_BAK, F_OK) == 0) {
		if (unlink(ANTIVIRUS_PATH_BAK) < 0) {
			MON_ERROR("remove antivirus backup file failed\n");

			/*把残留的解压目录删除*/
			remove_dir(unzip_dir);

			return -1;
		}
	}

	/* 备份原来的防病毒程序 */
	if (access(ANTIVIRUS_PATH, F_OK) == 0) {
		if (rename(ANTIVIRUS_PATH, ANTIVIRUS_PATH_BAK) < 0) {

			/*把残留的解压目录删除*/
			remove_dir(unzip_dir);

			return -1;
		}
	}

	/* 拷贝新下载的防病毒程序到指定位置 */
	if (rename(file, ANTIVIRUS_PATH) < 0) {
		rename(ANTIVIRUS_PATH_BAK, ANTIVIRUS_PATH);

		/*把残留的解压目录删除*/
		remove_dir(unzip_dir);

		return -1;
	}

	/* 删除防病毒程序备份残留文件 */
	if (access(ANTIVIRUS_PATH_BAK, F_OK) == 0) {
		if (unlink(ANTIVIRUS_PATH_BAK) < 0) {
			MON_ERROR("remove antivirus backup file failed\n");

			/*把残留的解压目录删除*/
			remove_dir(unzip_dir);

			return -1;
		}
	}

	/* 删除新下载解压后的防病毒目录 */
	if (access(unzip_dir, F_OK) == 0) {
		if (remove_dir(unzip_dir) < 0) {
			MON_ERROR("remove antivirus unzip dir failed\n");
			return -1;
		}
	}

	/* 更新防病毒程序版本号 */
	save_lib_version(ANTIVIRUS_VERSION_FILE, antivirus_version);
	snprintf(antivirus_ver_global, sizeof(antivirus_ver_global), "%s", antivirus_version);
	return ret;
}

/* 区分病毒库或者防病毒程序的升级任务并更新 */
static int update_virus_database(task_recv_t *msg)
{
	int ret;

	if (msg->upgrade_type == UPDATE_VIRUS_LIB) {
		ret = update_virus_lib(msg->new_version, msg->md5);
	} else {
		ret = update_antivirus(msg->new_version, msg->md5);
	}

	return ret;
}

/* 更新病毒库或者防病毒程序的任务接口 */
void update_virus_database_my(task_recv_t *msg)
{
	int ret = 0;

	pthread_mutex_lock(&virus_datebase_update_lock);
	/* 多个病毒库升级任务同时下发，后面的任务通过版本号无需重复升级 */
	if ((msg->upgrade_type == UPDATE_VIRUS_LIB &&
	    strcmp(virus_lib_ver_global, msg->new_version) == 0) ||
	    (msg->upgrade_type == UPDATE_VIRUS_PRO &&
	    strcmp(antivirus_ver_global, msg->new_version) == 0)) {
		send_update_virus_database_task_resp(msg, RESULT_OK, msg->new_version, msg->new_version);
		pthread_mutex_unlock(&virus_datebase_update_lock);
		return;
	}

	ret = update_virus_database(msg);
	pthread_mutex_unlock(&virus_datebase_update_lock);
	if (ret < 0) {
		send_antivirus_update_msg(msg, MY_RESULT_FAIL);
		send_update_virus_database_task_resp(msg, RESULT_FAIL, msg->old_version, msg->new_version);
	} else {
		send_antivirus_update_msg(msg, MY_RESULT_OK);
		send_update_virus_database_task_resp(msg, RESULT_OK, msg->old_version, msg->new_version);
	}
	return;
}

/* 检测是否匹配策略设置的可信区，返回1表示匹配，小于等于0表示不匹配 */
int check_policy_trust_path(char *path)
{
	int len = 0, match = 0, i = 0;
	char *list = NULL;
	if (!path) {
		return -1;
	}

	pthread_rwlock_rdlock(&antivirus_policy_global.lock);
	for (i = 0; i < antivirus_policy_global.list_num; i++) {
		list = antivirus_policy_global.trust_list[i].list;
		len = strlen(list);
		/* 可信路径如果是文件就绝对匹配, 是目录就匹配到path长度 */
		if (list[len-1] != '/') {
			if (strcmp(list, path) == 0) {
				match = 1;
				break;
			}
		} else {
			if (strncmp(list, path, len) == 0) {
				match = 1;
				break;
			}
		}
	}
	pthread_rwlock_unlock(&antivirus_policy_global.lock);

	return match;
}

/* 获取文件权限,属主, 属组 */
static int get_file_stat(char *path, struct _file_stat *f_st)
{
	struct stat st = {0};

	if (stat(path, &st) < 0) {
		return -1;
	}

	f_st->mode = st.st_mode;
	f_st->uid = st.st_uid;
	f_st->gid = st.st_gid;

	return 0;
}

/*
 * 查询数据库中有没有这条路径的记录
 * 返回-1，执行错误;返回0，没有该条记录;返回1，有这条路径记录
 */
static int query_db_path_record(char *path)
{
	char buf[1024] = {0};
	int rc = 0, nrow = 0, ncolumn = 0;
	char **azResult = NULL;
	int ret = 0;

	snprintf(buf, sizeof(buf), "SELECT id FROM virus WHERE path='%s';", path);
	rc = sqlite3_get_table(virus_db, buf, &azResult, &nrow, &ncolumn, NULL);
	if (rc != SQLITE_OK) {
		MON_ERROR("get sqlite3 virus table error:%s(%d)\n", sqlite3_errstr(rc), rc);
		return -1;
	}
	sqlite3_free_table(azResult);

	if (nrow == 0) {
		ret = 0;
	} else {
		ret = 1;
	}

	return ret;
}

/* 添加隔离病毒的记录到数据库 返回-1表示添加失败 */
static int add_record_to_virus_db(struct _file_stat *f_st, char *record_path, char *md5_path)
{
	int rc = 0;

	sqlite3_reset(virus_new_stmt);
	sqlite3_bind_int(virus_new_stmt, 1, f_st->mtime);
	sqlite3_bind_text(virus_new_stmt, 2, md5_path, -1, SQLITE_STATIC);
	sqlite3_bind_text(virus_new_stmt, 3, record_path, -1, SQLITE_STATIC);
	sqlite3_bind_int(virus_new_stmt, 4, f_st->uid);
	sqlite3_bind_int(virus_new_stmt, 5, f_st->gid);
	sqlite3_bind_int(virus_new_stmt, 6, f_st->mode);
	rc = sqlite3_step(virus_new_stmt);
	if (rc != SQLITE_DONE) {
		MON_ERROR("sql insert new virus %s fail: %s(%d)\n", f_st->path, sqlite3_errstr(rc), rc);
		return -1;
	}

	return 0;
}

/* 隔离文件 */
static int quarantine_file(char *path, char *record_path, char *newpath, struct _file_stat *f_st)
{
	int ret = 0;
	int rename_ok = 0;

	/* 同一个文件系统可以用rename,失败再尝试复制文件更改属性 */
	ret = rename(path, newpath);
	if (ret < 0) {
		ret = copy_file(path, newpath);
	} else {
		rename_ok = 1;
	}

	if (ret < 0) {
		return -1;
	}

	/* rename成功的隔离文件属性信息不用修改, 修改失败的适合当隔离失败处理 */
	if (rename_ok != 1) {
		ret = chmod(newpath, f_st->mode);
		if (ret < 0) {
			MON_ERROR("quarantine file:%s chmod %s error:%s\n", path, newpath, strerror(errno));
			unlink(newpath);
			return -1;
		}

		ret = chown(newpath, f_st->uid, f_st->gid);
		if (ret < 0) {
			MON_ERROR("quarantine file:%s chown %s error:%s\n", path, newpath, strerror(errno));
			unlink(newpath);
			return -1;
		}
	}

	/* 记录到数据库, 修改失败的适合当隔离失败处理 */
	ret = add_record_to_virus_db(f_st, record_path, newpath);
	if (ret < 0) {
		unlink(newpath);
		return -1;
	}

	/* 隔离成功删除原文件,rename成功这边unlink就会失败,需要先判断path存不存在 */
	if (access(path, F_OK) == 0) {
		unlink(path);

		/* 如果删除原文件失败, 删除隔离文件和隔离记录 */
		if (ret < 0) {
			unlink(newpath);
			sqlite3_reset(virus_delete_md5_stmt);
			sqlite3_bind_text(virus_delete_md5_stmt, 1, newpath, -1, SQLITE_STATIC);
			sqlite3_step(virus_delete_md5_stmt);
		}
	}
	return 0;
}

/* 删除旧的隔离文件，直到空间足够存放新病毒文件，失败返回0，成功返回1 */
static int delete_old_quarantine_file(unsigned long dir_size, unsigned long path_size)
{
	unsigned long size = 0;
	struct stat st;
	int ret = 0;
	int rc = 0;

	sqlite3_reset(virus_select_md5_stmt);
	while (sqlite3_step(virus_select_md5_stmt) == SQLITE_ROW) {
		const char *md5 = (const char *)sqlite3_column_text(virus_select_md5_stmt, 0);
		if (stat(md5, &st) < 0) {
			continue;
		}
		size += st.st_size;

		/* 删除隔离区的文件和数据库记录 */
		if (unlink(md5) < 0) {
			ret = 0;
			break;
		}
		sqlite3_reset(virus_delete_md5_stmt);
		sqlite3_bind_text(virus_delete_md5_stmt, 1, md5, -1, SQLITE_STATIC);
		rc = sqlite3_step(virus_delete_md5_stmt);
		if (rc != SQLITE_DONE) {
			DBG2(DBGFLAG_VIRUS, "sql delete path %s fail: %s(%d)\n", md5, sqlite3_errstr(rc), rc);
			ret = 0;
			break;
		}

		/* 删除的空间大小超过病毒文件就不用再删了 */
		if (size >= path_size) {
			ret = 1;
			break;
		}
	}

	/* 全部删除了仍然比病毒文件的大小还小, 依然认为成功了 */
	if (size == dir_size) {
		ret = 1;
	}

	return ret;
}

/* 根据隔离区设置剩余空间大小和隔离区情况, 是否隔离病毒文件*/
static int check_quarantine_file(char *path, char *record_path, char *newpath, struct _file_stat *f_st)
{
	struct stat st = {0};
	unsigned long path_size = 0;
	unsigned long dir_size = 0;
	unsigned long disk_size = 0;
	unsigned long policy_size = 0;
	int ret = 0;

	if (stat(path, &st) < 0) {
		return -1;
	}
	path_size = st.st_size;
	policy_size = (unsigned long)antivirus_policy_global.reserved_space * (unsigned long)GB_SIZE;

	disk_size = get_path_disk_size(QUARANTINE_DIR);

	/* 实时检测是root用户,获取总的隔离区目录内的大小 */
	dir_size = get_dir_size(QUARANTINE_DIR);

	/*
	 * 之前没有隔离过文件时，比较分区剩余空间和策略设置的大小+path大小的总和
	 * 分区空间>= 策略设置大小+病毒大小，隔离病毒。
	 * 否则直接忽略, 同时返回-1做隔离失败处理
	 */
	DBG2(DBGFLAG_VIRUSDEBUG, "disk_size:%lu, dir_size:%lu, policy_size:%lu, path_size:%lu\n",
			disk_size, dir_size, policy_size, path_size);
	if (dir_size == 0) {
		if (disk_size < policy_size + path_size) {
			return -1;
		}

		ret = quarantine_file(path, record_path, newpath, f_st);
		return ret;
	}

	/* 有隔离区且其中有隔离文件的情况下 */

	/*
	 * 如果分区空间 >= 策略设置大小+病毒大小
	 * 直接隔离
	 */
	if (disk_size >= policy_size + path_size) {
		ret = quarantine_file(path, record_path, newpath, f_st);
		return ret;
	}

	/*
	 * 其他情况下
	 * 2种情况会去删除旧隔离文件，隔离新病毒文件
	 * 1.分区空间-隔离空间+新病毒文件大小 大于 策略设置的大小
	 * 2.隔离区的大小比新病毒文件大
	 * 否则直接忽略, 返回-1，当作隔离失败
	 */
	if ((disk_size + path_size - dir_size <  policy_size) &&
	    (dir_size <  path_size)) {
		return -1;
	}

	if (delete_old_quarantine_file(dir_size, path_size) == 0) {
		return -1;
	}

	ret = quarantine_file(path, record_path, newpath, f_st);
	return ret;
}

/* 隔离病毒文件 */
static int quarantine_virus_file(char *path, char *dir)
{
	struct _file_stat st = {0};
	int ret = 0;
	char md5[S_MD5LEN] = {0};
	char newpath[PATH_MAX] = {0};
	char record_path[PATH_MAX] = {0};
	struct timeval tv = {0};
	int i = 0;

	snprintf(st.path, sizeof(st.path), "%s", path);

	/* 获取文件权限,属主, 属组*/
	ret = get_file_stat(path, &st);
	if (ret < 0) {
		MON_ERROR("quarantine file:%s get stat error:%s\n", path, strerror(errno));
		return -1;
	}

	/*
	 * 如果数据库中已经备份了该路径的文件(例如/tmp/1.txt),
	 * 文件名后面拼接"(数字).sniper"到原文件后的后面(例如/tmp/1.txt(1).sniper)
	 * 拼接后的路径如果在数据库中也存在了，括号中的数字递增+1
	 * 同一路径的文件最多可以存放10000条
	 * 有.sniper表示这条路径是副本拼接的路径，没有则说明是原路径
	 * 显示的时候只显示/tmp/1.txt(1)
	 */

	ret = query_db_path_record(path);
	if (ret < 0) {
		return -1;
	}

	if (ret == 0) {
		snprintf(record_path, sizeof(record_path), "%s", thestring(path));
	} else {
		for (i = 1; i < MAX_WHILE; i++) {
			snprintf(record_path, sizeof(record_path), "%s(%d).sniper", path, i);
			ret = query_db_path_record(record_path);
			if (ret < 0) {
				return -1;
			} else if (ret == 0){
				break;
			}
		}
	}

	/* 用文件路径计算唯一值用来存放在隔离区 */
	md5_string(record_path, md5);
	if (md5[0] == 0) {
		MON_ERROR("quarantine file:%s get md5 error\n", path);
		return -1;
	}
	snprintf(st.md5, sizeof(st.md5), "%s", md5);
	snprintf(newpath, sizeof(newpath), "%s/%s", dir, md5);

	gettimeofday(&tv, NULL);
	st.mtime = tv.tv_sec;

	/* 检查文件是隔离还是忽略 */
	ret = check_quarantine_file(path, record_path, newpath, &st);

	return ret;
}

static void send_virus_upload_sample_log(struct virus_msg_args *msg, char *pathname, char *log_name, char *log_id, int result, char*md5)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	char size_str[64] = {0};
	unsigned long event_time = 0;
	struct stat st = {0};

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}

	event_time = (msg->start_tv.tv_sec + serv_timeoff) * 1000 + msg->start_tv.tv_usec / 1000;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", "ClientSimpleUpload");
	cJSON_AddStringToObject(object, "event_category", "");
	cJSON_AddStringToObject(object, "log_category", "Client");
	  cJSON_AddBoolToObject(object, "event", false);
	cJSON_AddNumberToObject(object, "level", 1);
	cJSON_AddNumberToObject(object, "behavior", 0);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", "Upload");
	cJSON_AddNumberToObject(object, "terminate", 0);
	cJSON_AddNumberToObject(object, "timestamp", event_time);

	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", msg->username);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddStringToObject(object, "source", "Agent");
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);

	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);

	cJSON_AddStringToObject(arguments, "client_version", SNIPER_VERSION);
	cJSON_AddStringToObject(arguments, "client_dir", WORKDIR);
	cJSON_AddStringToObject(arguments, "policy_id", policy_id_cur);
	cJSON_AddStringToObject(arguments, "policy_name", policy_name_cur);
	cJSON_AddStringToObject(arguments, "policy_time", policy_time_cur);
	cJSON_AddStringToObject(arguments, "md5", md5);
	cJSON_AddStringToObject(arguments, "file_path", pathname);
	cJSON_AddStringToObject(arguments, "file_name", safebasename(pathname));
	cJSON_AddStringToObject(arguments, "process_uuid", "");
	cJSON_AddStringToObject(arguments, "log_name", log_name);
	cJSON_AddStringToObject(arguments, "log_id", log_id);

	if (stat(pathname, &st) < 0) {
		cJSON_AddBoolToObject(arguments, "file_exists", false);
		cJSON_AddStringToObject(arguments, "size", "0");
	} else {
		cJSON_AddBoolToObject(arguments, "file_exists", true);
		snprintf(size_str, sizeof(size_str), "%ld", st.st_size);
		cJSON_AddStringToObject(arguments, "size", size_str);
	}

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);

	client_send_msg(post, reply, sizeof(reply), LOG_URL, "antivirus");
//	printf("file send upload sample:%s, reply:%s\n", post, reply);

	cJSON_Delete(object);
	free(post);
}

/* return 0，不上传；1，上传成功；-1，上传失败 */
static int upload_virus_sample(struct virus_msg_args *msg, char *log_id, char*md5)
{
	int ret = 0, result = MY_RESULT_OK;
	char *pathname = NULL;

	if (conf_global.allow_upload_sample != 1) {
		return 0;
	}

	if (!msg) {
		return 0;
	}

	if (msg->op_type == OP_RENAME) {
		pathname = msg->pathname_new;
	} else {
		pathname = msg->pathname;
	}

	ret = http_upload_sample(pathname, msg->start_tv.tv_sec, "AntivirusProtection", log_id, msg->username, md5);
	if (ret < 0) {
		result = MY_RESULT_FAIL;
	}

	send_virus_upload_sample_log(msg, pathname, "AntivirusProtection", log_id, result, md5);

	return ret;
}

/* 发送实时检测的消息给管控 */
static void send_antivirus_msg(SAVAPI_FILE_STATUS_DATA *data, struct virus_msg_args *msg)
{
	cJSON *object = NULL, *arguments = NULL;
	char uuid[S_UUIDLEN] = {0}, reply[REPLY_MAX] = {0}, *post = NULL;
	bool event = false;
	char log_name[LOG_NAME_MAX] = {0};
	char event_category[EVENT_NAME_MAX] = {0};
	int behavior = 0, level = 0, result = MY_RESULT_ZERO;
	char operating[OP_LEN_MAX] = {0};
	int terminate = 0;
	unsigned long event_time = 0;
	char md5[S_MD5LEN] = {0};
	char process_md5[S_MD5LEN] = {0};
	char *path = NULL;
	int check_way = 0;
	struct defence_msg defmsg = {0};
	int defence_result = MY_RESULT_OK;
	char file_tmp[PATH_MAX] = {0};

	get_random_uuid(uuid);
	if (uuid[0] == 0) {
		return;
	}

	if (msg->op_type == OP_RENAME) {
		path = msg->pathname_new;
	} else {
		path = msg->pathname;
	}

	snprintf(log_name, sizeof(log_name), "%s", "AntivirusProtection");
	snprintf(event_category, sizeof(event_category), "%s", "AntivirusProtection");
	event = true;
	behavior = MY_BEHAVIOR_ABNORMAL;
	level = MY_LOG_HIGH_RISK;
	result = MY_RESULT_ZERO;
	terminate = MY_HANDLE_WARNING;
	event_time = (msg->start_tv.tv_sec + serv_timeoff) * 1000 + (int)msg->start_tv.tv_usec / 1000;

	if (md5_filter_large_file(path, md5) < 0) {
		memset(md5, 0, S_MD5LEN);
	}

	/* 计算进程的md5, 用于匹配进程过滤规则 */
	md5_filter_large_file(msg->cmd, process_md5);

	/* 匹配过滤规则 */
	if (check_filter_after(path, md5, msg->cmd) == 0 ||
	    check_process_filter_pro(msg->cmd, process_md5)) {
		return;
	}

	object = cJSON_CreateObject();
	if (object == NULL) {
		return;
	}
	arguments = cJSON_CreateObject();
	if (arguments == NULL) {
		cJSON_Delete(object);
		return;
	}
	check_way = 2;

	cJSON_AddStringToObject(object, "id", uuid);
	cJSON_AddStringToObject(object, "log_name", log_name);
	cJSON_AddStringToObject(object, "log_category", "AntivirusProtection");
	  cJSON_AddBoolToObject(object, "event", event);
	cJSON_AddStringToObject(object, "event_category", event_category);
	cJSON_AddNumberToObject(object, "level", level);
	cJSON_AddNumberToObject(object, "behavior", behavior);
	cJSON_AddNumberToObject(object, "result", result);
	cJSON_AddStringToObject(object, "operating", operating);
	cJSON_AddNumberToObject(object, "terminate", terminate);
	cJSON_AddStringToObject(object, "host_name", Sys_info.hostname);
	cJSON_AddStringToObject(object, "ip_address", If_info.ip);
	cJSON_AddStringToObject(object, "mac", If_info.mac);
	cJSON_AddStringToObject(object, "uuid", Sys_info.sku);
	cJSON_AddStringToObject(object, "user", msg->username);
	cJSON_AddNumberToObject(object, "os_type", OS_LINUX);
	cJSON_AddStringToObject(object, "os_version", Sys_info.os_dist);
	cJSON_AddNumberToObject(object, "timestamp", event_time);
	cJSON_AddStringToObject(object, "policy_id", policy_id_cur);
	cJSON_AddNumberToObject(object, "operation_mode", client_mode_global);
	cJSON_AddStringToObject(object, "source", "Agent");

	cJSON_AddStringToObject(arguments, "virus_name", data->malware_info.name);
	cJSON_AddStringToObject(arguments, "virus_type", data->malware_info.type);
	cJSON_AddStringToObject(arguments, "filename", safebasename(path));
	cJSON_AddStringToObject(arguments, "filepath", path);
	cJSON_AddStringToObject(arguments, "file_md5", md5);
//	cJSON_AddNumberToObject(arguments, "scan_type", 2);
	cJSON_AddNumberToObject(arguments, "automate", antivirus_policy_global.automate);
	cJSON_AddNumberToObject(arguments, "check_way", check_way);

	cJSON_AddItemToObject(object, "arguments", arguments);

	post = cJSON_PrintUnformatted(object);
	DBG2(DBGFLAG_VIRUS, "antivirus post:%s\n", post);
	client_send_msg(post, reply, sizeof(reply), LOG_URL, "antivirus");
//	printf("antivirus post:%s, reply:%s\n", post, reply);

	cJSON_Delete(object);
	free(post);

	upload_virus_sample(msg, uuid, md5);

	/* 实时检测自动处理时,运维模式下不自动隔离,否则自动隔离 */
	if (antivirus_policy_global.automate == AUTO_PROCESS &&
	    client_mode_global != OPERATION_MODE) {
		if (quarantine_virus_file(path, ROOT_QUARANTINE_DIR) < 0) {
			defence_result = MY_RESULT_FAIL;
		} else {
			defence_result = MY_RESULT_OK;
		}

		defmsg.event_tv.tv_sec = msg->start_tv.tv_sec;
		defmsg.event_tv.tv_usec = msg->start_tv.tv_usec;
		defmsg.operation = qurstr;
		defmsg.result = defence_result;

		defmsg.virus_name = data->malware_info.name;
		defmsg.virus_type = data->malware_info.type;
		defmsg.user = msg->username;
		defmsg.log_name = log_name;
		defmsg.log_id = uuid;
		if (msg->op_type == OP_RENAME) {
			snprintf(file_tmp, sizeof(file_tmp), "%s->%s", thestring(msg->pathname), thestring(msg->pathname_new));
			defmsg.object = file_tmp;
		} else {
			defmsg.object = msg->pathname;
		}

		send_defence_msg(&defmsg, "antivirus");
	}

	return;
}

/* 扫描的callback中获取文件的信息 */
static int file_status_callback(SAVAPI_CALLBACK_DATA *data)
{
	SAVAPI_FILE_STATUS_DATA *file_status_data = data->callback_data.file_status_data;

	if (file_status_data->scan_answer == SAVAPI_SCAN_STATUS_INFECTED) {
		send_antivirus_msg(file_status_data, msg);
	}

	return 0;
}

/* 注册callback函数 */
static SAVAPI_STATUS register_instance_callbacks(SAVAPI_FD instance_handle)
{
	SAVAPI_STATUS ret = SAVAPI_S_OK;

	ret = SAVAPI_register_callback(instance_handle, SAVAPI_CALLBACK_REPORT_FILE_STATUS, file_status_callback);

	return ret;
}

/* 注销callback函数 */
static SAVAPI_STATUS unregister_instance_callbacks(SAVAPI_FD instance_handle)
{
	SAVAPI_STATUS ret = SAVAPI_S_OK;

	ret = SAVAPI_unregister_callback(instance_handle, SAVAPI_CALLBACK_REPORT_FILE_STATUS, file_status_callback);

	return ret;
}

/* 扫描前的准备工作，包括初始化，创建实例，注册callback */
static void prepare_savapi(void)
{
	global_init.api_major_version = SAVAPI_API_MAJOR_VERSION;
	global_init.api_minor_version = SAVAPI_API_MINOR_VERSION;
	global_init.program_type = ANTIVIRUS_PROGRAM_TYPE;
	global_init.engine_dirpath = ANTIVIRUS_ENGINE_DIRPATH;
	global_init.vdfs_dirpath = ANTIVIRUS_VDFS_DIRPATH;
	global_init.avll_dirpath = ANTIVIRUS_AVLL_DIRPATH;
	global_init.key_file_name = ANTIVIRUS_KEY_FILENAME;

	if (savapi_inited != SAVAPI_S_OK) {
		savapi_inited = SAVAPI_initialize(&global_init);
	}
	if (savapi_inited == SAVAPI_S_OK) {
		if (instance_created != SAVAPI_S_OK) {
			instance_created = SAVAPI_create_instance(&instance_init, &instance_handle);
		}
		if (instance_created == SAVAPI_S_OK) {
			if (callbacks_registered != SAVAPI_S_OK) {
				callbacks_registered = register_instance_callbacks(instance_handle);
			}
			if (callbacks_registered != SAVAPI_S_OK) {
				MON_ERROR("antivirus register instance callback error(%d): %s\n",
						callbacks_registered, scan_error_to_string(callbacks_registered));
			}
		} else {
			MON_ERROR("antivirus create instance error(%d): %s\n",
					instance_created, scan_error_to_string(instance_created));
		}
	} else {
		MON_ERROR("antivirus initialize error(%d): %s\n",
				savapi_inited, scan_error_to_string(savapi_inited));
	}
}

/* 回收savapi的资源，和prepare_savapi成对使用 */
void finish_savapi(void)
{
	SAVAPI_STATUS ret = -1;
	if (callbacks_registered == SAVAPI_S_OK) {
		ret = unregister_instance_callbacks(instance_handle);
		if (ret != SAVAPI_S_OK) {
			MON_ERROR("antivirus unregistering callbacks failed with error code(%d): %s\n",
					ret, scan_error_to_string(ret));
		} else {
			callbacks_registered = -1;
		}
	}

	if (instance_handle != NULL) {
		ret = SAVAPI_release_instance(&instance_handle);
		if (ret != SAVAPI_S_OK) {
			MON_ERROR("antivirus release instance failed with error code(%d): %s\n",
					ret, scan_error_to_string(ret));
		} else {
			instance_handle = NULL;
			instance_created = -1;
		}
	}

	if (savapi_inited == SAVAPI_S_OK) {
		ret = SAVAPI_uninitialize();
		if (ret != SAVAPI_S_OK) {
			MON_ERROR("antivirus uninitialize failed with error code(%d): %s\n",
					ret, scan_error_to_string(ret));
		} else {
			savapi_inited = -1;
		}

	}
}

#ifdef USE_AVIRA
/* 实时病毒监控 */
void *antivirus_monitor(void *ptr)
{
	virus_msg_t *virus_msg = NULL;
	SAVAPI_STATUS ret = -1;
	char *path = NULL;
	char version[VER_LEN_MAX] = {0};

	prctl(PR_SET_NAME, "antivirus");
	save_thread_pid("antivirus", SNIPER_THREAD_ANTIVIRUS);

	/* Set the locale so the program will use the system locale */
	/* 不设置时遇到中文路径, 会报转码错误 */
	setlocale(LC_ALL, "");

	while (1) {
		sleep(1);

		/* 病毒库下载失败时不做后面的流程 */
		if (virus_lib_ver_global[0] == 0) {
			continue;
		}

		/* 实时检测开关没开时，无需准备加载savapi资源 */
		if (antivirus_policy_global.real_time_check.enable == TURN_MY_ON) {
			prepare_savapi();
			break;
		}
	}
	snprintf(version, sizeof(version), "%s", virus_lib_ver_global);
	savapi_on = 1;


	while (Online) {
		if (virus_msg) {
			sniper_free(virus_msg->data, virus_msg->datalen, FILE_GET);
			sniper_free(virus_msg, sizeof(struct virus_msg), FILE_GET);
		}

		/* 检查待转储的日志文件 */
		check_log_to_send("antivirus");

		if (sniper_file_loadoff == TURN_MY_ON ||
		    antivirus_policy_global.real_time_check.enable == TURN_MY_OFF) {
			/* get_virus_msg里不睡眠，所以此处要睡1秒，否则会显示CPU一直忙 */
			finish_savapi();
			sleep(1);
			virus_msg = (virus_msg_t *)get_virus_msg();
			continue;
		}

		/* 如果过期了/停止防护了，什么也不做 */
		if (conf_global.licence_expire || client_disable == TURN_MY_ON) {

			finish_savapi();

			sleep(STOP_WAIT_TIME);

			/* 扔掉msg queue中的数据 */
			while(1) {
				virus_msg = (virus_msg_t *)get_virus_msg();
				if (!virus_msg) {
					break;
				}

				sniper_free(virus_msg->data, virus_msg->datalen, FILE_GET);
				sniper_free(virus_msg, sizeof(struct virus_msg), FILE_GET);
			}

			continue;
		}

		/* 病毒库升级完成之后需要释放资源再重新加载savapi接口 */
		if (strcmp(version, virus_lib_ver_global) != 0) {
			finish_savapi();
			prepare_savapi();
			snprintf(version, sizeof(version), "%s", virus_lib_ver_global);
		}

		/* 之前关闭的重新启动 */
		if (callbacks_registered != SAVAPI_S_OK) {
			prepare_savapi();
		}

		/* 仍然没有开启的不做检测，数据丢弃 */
		if (callbacks_registered != SAVAPI_S_OK) {
			finish_savapi();
			sleep(60);
			virus_msg = (virus_msg_t *)get_virus_msg();
			continue;
		}

		virus_msg = (virus_msg_t *)get_virus_msg();
		if (!virus_msg) {
			sleep(1);
			continue;
		}

		msg = (struct virus_msg_args *)virus_msg->data;
		if (msg == NULL) {
			continue;
		}

		DBG2(DBGFLAG_VIRUSDEBUG, "antivirus msg pid:%d, process:%s, path:%s, op_type:%d\n",
			msg->pid, msg->cmd, msg->pathname, msg->op_type);

		if (msg->op_type == OP_RENAME) {
			path = msg->pathname_new;
		} else {
			path = msg->pathname;
		}
		ret = SAVAPI_scan(instance_handle, path);
		if (ret != SAVAPI_S_OK) {
			DBG2(DBGFLAG_VIRUSDEBUG, "antivirus sacn failed with error code:%d\n", ret);
		}

	}

	finish_savapi();
	INFO("antivirus thread exit\n");

	return NULL;
}
#endif
