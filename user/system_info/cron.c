#include "sys_info.h"

char hourly[512]  = "每小时";
char daily[512]   = "每日";
char weekly[512]  = "每周";
char monthly[512] = "每月";

/* 检测是否文本行：全是可打印字符或空格符 */
static int is_text_line(char *line)
{
	int i = 0;

	if (!line) {
		return 0;
	}

	while (*line) {
		if (!isprint(*line) && !isspace(*line)) {
			return 0;
		}
		line++;
	}

	return 1;
}

/* 检测/etc/crontab中的任务条目是否缺了用户名项或填了本机不存在的用户 */
static void check_valid_user(char *user, int user_len)
{
	int len = 0;
	struct passwd pwd = {0};
	struct passwd *result = NULL;
	char buf[4096] = {0};

	if (!user || strcmp(user, "root") == 0) {
		return;
	}
	getpwnam_r(user, &pwd, buf, sizeof(buf), &result);
	if (!result) {
		len = strlen(user);
		snprintf(user+len, user_len-len, " (bad username)");
	}
}

/*
 * 检测是否为环境变量，如
 * SHELL=/bin/sh
 * PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
 *
 * xx = yy zz这样的形式cron也接受
 */
static int is_environment_keyvalue(char *str)
{
	char key[256] = {0}, value[256] = {0}, *ptr = NULL;

	if (str && sscanf(str, "%255[^=]=%255s", key, value) == 2) {
		ptr = skip_headspace(key);
		delete_tailspace(key);

		while (*ptr) {
			if (isspace(*ptr)) {
				return 0;
			}
			ptr++;
		}
		return 1;
	}
	return 0;
}

/*
 * 考察下列对象：
 * /etc/crontab, /etc/anacrontab,
 * /etc/cron.d/, /etc/cron.hourly/, /etc/cron.daily/, /etc/cron.weekly/, /etc/cron.monthly/,
 * /var/spool/cron/crontabs/USERNAME, /var/spool/cron/USERNAME, /var/spool/tabs/USERNAME
 * /var/cron/tabs/USERNAME
 */

static void get_period_by_string(char *str, char *period, int period_len)
{
	if (!str || !period) {
		return;
	}

	if (strcmp(str, "@reboot") == 0) {
		snprintf(period, period_len, "开机时做一次");
	} else if (strcmp(str, "@yearly") == 0 || strcmp(str, "@annually") == 0) {
		snprintf(period, period_len, "每年1月1日0点");
	} else if (strcmp(str, "@monthly") == 0) {
		snprintf(period, period_len, "每月1日0点");
	} else if (strcmp(str, "@weekly") == 0) {
		snprintf(period, period_len, "周日0点");
	} else if (strcmp(str, "@dayliy") == 0 || strcmp(str, "@midnight") == 0) {
		snprintf(period, period_len, "每日0点");
	} else if (strcmp(str, "@hourly") == 0) {
		snprintf(period, period_len, "每个整点");
	} else {
		snprintf(period, period_len, "%s", str); //无法解析的字符串
	}
}

#define TYPE_MINUTE   1
#define TYPE_HOUR     2
#define TYPE_MONTHDAY 3
#define TYPE_MONTH    4
#define TYPE_WEEKDAY  5
#define TYPE_STEP     6
static char *get_num(char *str, char *period, int period_len, char *unit, int type)
{
	int tmp = 0, num = 0, len = 0;
	char *ptr = str;
	char weekday_cn[8][4] = { "日", "一", "二", "三", "四", "五", "六", "日" };

	if (!str || !period || !unit) {
		return NULL;
	}

	/* 获取数字值 */
	while (isdigit(*ptr)) {
		tmp = *ptr - '0';
		num = num * 10 + tmp;
		ptr++;
	}

	/*
	 * 检查数值合法性
	 * field的有效值区间如下
	 *            field          allowed values
	 *            -----          --------------
	 *            minute         0-59
	 *            hour           0-23
	 *            day of month   1-31
	 *            month          1-12 (or names, see below)
	 *            day of week    0-7 (0 or 7 is Sun, or use names)
	 */
	switch (type) {
	case TYPE_MINUTE:
		if (num < 0 || num > 59) {
			return NULL;
		}
		break;
	case TYPE_HOUR:
		if (num < 0 || num > 23) {
			return NULL;
		}
		break;
	case TYPE_MONTHDAY:
		if (num < 1 || num > 31) {
			return NULL;
		}
		break;
	case TYPE_MONTH:
		if (num < 1 || num > 12) {
			return NULL;
		}
		break;
	case TYPE_WEEKDAY:
		if (num < 0 || num > 7) {
			return NULL;
		}
		break;
	case TYPE_STEP:
		if (num == 0) {
			return NULL;
		}
		break;
	default:
		break;
	}

	len = strlen(period);
	if (type == TYPE_WEEKDAY) {
		snprintf(period+len, period_len-len, "周%s", weekday_cn[num]);
	} else if (type == TYPE_MINUTE) {
		snprintf(period+len, period_len-len, "%02d分", num);
	} else {
		snprintf(period+len, period_len-len, "%d%s", num, unit);
	}

	if (*ptr == 0) {
		return ptr;
	}

	if (*ptr == ',') { //本value解析完毕，将解析下一个value
		if (*(ptr+1) == 0) { //,后没有了，视为错误
			return NULL;
		}

		len = strlen(period);
		snprintf(period+len, period_len-len, ",");
	}

	return ptr;
}

static char *get_strnum(char *str, char *period, int period_len, char *unit, int type)
{
	int i = 0, num = 0, len = 0;
	char *ptr = str;
	char weekday[7][4] = { "mon", "tue", "wed", "thu", "fri", "sat", "sun" };
	char weekday_cn[8][4] = { "日", "一", "二", "三", "四", "五", "六", "日" };
	char mon[12][4] = { "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };

	if (!str || !period || !unit) {
		return NULL;
	}

	if (type == TYPE_MONTH) {
		for (i = 0; i < 12; i++) {
			if (strncasecmp(ptr, mon[i], 3) == 0) {
				num = i + 1;
				break;
			}
		}

		if (num == 0) {
			return NULL;
		}

		ptr += 3;
		len = strlen(period);
		snprintf(period+len, period_len-len, "%d%s", num, unit);

	} else if (type == TYPE_WEEKDAY) {
		for (i = 0; i < 7; i++) {
			if (strncasecmp(ptr, weekday[i], 3) == 0) {
				num = i + 1;
				break;
			}
		}

		if (num == 0) {
			return NULL;
		}

		ptr += 3;
		len = strlen(period);
		snprintf(period+len, period_len-len, "周%s", weekday_cn[num]);

	} else {
		return NULL;
	}

	if (*ptr == 0) {
		return ptr;
	}

	if (*ptr == ',') { //本value解析完毕，将解析下一个value
		if (*(ptr+1) == 0) { //,后没有了，视为错误
			return NULL;
		}

		len = strlen(period);
		snprintf(period+len, period_len-len, ",");
	}

	return ptr;
}

// field的value形式包括：*，*/n，i，i-j，i-j/n，xxx，xxx-yyy，xxx-yyy/n
// filed的值可以是value1,value2这样的多个value的组合，如1-3,4
static int handle_field(char *field, char *period, int period_len, char *unit, char *step_unit, int type)
{
	int len = 0;
	char *ptr = field;

	if (!field || !period || !unit || !step_unit) {
		return -1;
	}
	if (type < TYPE_MINUTE || type > TYPE_WEEKDAY) {
		return -1;
	}

	while (*ptr) {
		// 处理*/n
		if (*ptr == '*') {
			ptr++;
			if (*ptr == '/') {
				ptr++;
				if (!isdigit(*ptr)) { // /之后必须是数字步长
					return -1;
				}

				len = strlen(period);
				snprintf(period+len, period_len-len, "每");

				ptr = get_num(ptr, period, period_len, step_unit, TYPE_STEP);
				if (!ptr) { //非法数字步长
					return -1;
				}

				if (*ptr == 0) { //field解析完毕
					return 0;
				}

				if (*ptr == ',') { //本value解析完毕，将解析下一个value
					ptr++;
					continue;
				}
			}

			return -1; //非法value
		}

		/* 处理i，i-j，i-j/n */
		if (isdigit(*ptr)) {
			ptr = get_num(ptr, period, period_len, unit, type);
			if (!ptr) { //非法value
				return -1;
			}

			if (*ptr == 0) { //field解析完毕
				return 0;
			}

			if (*ptr == ',') { //本value解析完毕，将解析下一个value
				ptr++;
				continue;
			}

			if (*ptr == '-') { //处理i-j
				ptr++;
				if (!isdigit(*ptr)) { // 数字-之后必须还是数字
					return -1;
				}

				len = strlen(period);
				snprintf(period+len, period_len-len, "至");

				ptr = get_num(ptr, period, period_len, unit, type);
				if (!ptr) { //非法value
					return -1;
				}

				if (*ptr == 0) { //field解析完毕
					return 0;
				}

				if (*ptr == ',') { //本value解析完毕，将解析下一个value
					ptr++;
					continue;
				}

				if (*ptr == '/') { //处理i-j/n
					ptr++;
					if (!isdigit(*ptr)) { // /之后必须是数字步长
						return -1;
					}

					len = strlen(period);
					snprintf(period+len, period_len-len, "每");

					ptr = get_num(ptr, period, period_len, step_unit, TYPE_STEP);
					if (!ptr) { //非法数字步长
						return -1;
					}

					if (*ptr == 0) { //field解析完毕
						return 0;
					}

					if (*ptr == ',') { //本value解析完毕，将解析下一个value
						ptr++;
						continue;
					}
				}
			}

			return -1; //非法value
		}

		/* 处理xxx，xxx-yyy，xxx-yyy/n */
		if (isalpha(*ptr)) {
			ptr = get_strnum(ptr, period, period_len, unit, type);
			if (!ptr) { //非法value
				return -1;
			}

			if (*ptr == 0) { //field解析完毕
				return 0;
			}

			if (*ptr == ',') { //本value解析完毕，将解析下一个value
				ptr++;
				continue;
			}

			if (*ptr == '-') { //处理xxx-yyy
				ptr++;
				if (!isalpha(*ptr)) { // 字母-之后必须还是字母
					return -1;
				}

				len = strlen(period);
				snprintf(period+len, period_len-len, "至");

				ptr = get_strnum(ptr, period, period_len, unit, type);
				if (!ptr) { //非法value
					return -1;
				}

				if (*ptr == 0) { //field解析完毕
					return 0;
				}

				if (*ptr == ',') { //本value解析完毕，将解析下一个value
					ptr++;
					continue;
				}

				if (*ptr == '/') { //处理xxx-yyy/n
					if (!isdigit(*ptr)) { // /之后必须是数字步长
						return -1;
					}

					len = strlen(period);
					snprintf(period+len, period_len-len, "每");

					ptr = get_num(ptr, period, period_len, step_unit, TYPE_STEP);
					if (!ptr) { //非法数字步长
						return -1;
					}

					if (*ptr == 0) { //field解析完毕
						return 0;
					}

					if (*ptr == ',') { //本value解析完毕，将解析下一个value
						ptr++;
						continue;
					}
				}
			}

			return -1; //非法value
		}

		return -1; //非法value
	}

	return 0;
}

/* 解析“minute hour day-of-month month day-of-week”代表的定时任务周期 */
static void get_period_by_fields(char *minute, char *hour, char *monthday,
		char *month, char *weekday, char *period, int period_len)
{
	int len = 0;

	if (!minute || !hour || !monthday || !month || !weekday || !period) {
		return;
	}

	if (strcmp(month, "*") != 0) {
		snprintf(period, period_len, "每年");

		if (handle_field(month, period, period_len, "月", "个月", TYPE_MONTH) < 0) {
			snprintf(period, period_len, "%s %s %s %s %s (bad month)",
				minute, hour, monthday, month, weekday);
			return;
		}
	}

	if (strcmp(monthday, "*") != 0) {
		if (strcmp(month, "*") == 0) {
			snprintf(period, period_len, "每月");
		}

		if (handle_field(monthday, period, period_len, "日", "天", TYPE_MONTHDAY) < 0) {
			snprintf(period, period_len, "%s %s %s %s %s (bad day of month)",
				minute, hour, monthday, month, weekday);
			return;
		}
	}

	if (strcmp(weekday, "*") != 0) {
		if (handle_field(weekday, period, period_len, "周", "天", TYPE_WEEKDAY) < 0) {
			snprintf(period, period_len, "%s %s %s %s %s (bad day of week)",
				minute, hour, monthday, month, weekday);
			return;
		}
	}

	if (strcmp(hour, "*") != 0) {
		// * */n * * *这样的形式不需要加每日，直接说每几小时
		if (strcmp(monthday, "*") == 0 && strcmp(weekday, "*") == 0 && isdigit(hour[0])) {
			snprintf(period, period_len, "每日");
		}

		if (handle_field(hour, period, period_len, "点", "小时", TYPE_HOUR) < 0) {
			snprintf(period, period_len, "%s %s %s %s %s (bad hour)",
				minute, hour, monthday, month, weekday);
			return;
		}
	}

	if (strcmp(month, "*") == 0 && strcmp(monthday, "*") == 0 &&
	     strcmp(hour, "*") == 0 && strcmp(weekday, "*") == 0) {
		memset(period, 0, period_len);
	}

	if (strcmp(minute, "*") == 0) {
		snprintf(period, period_len, "每分钟");
		return;
	}

	if (strcmp(minute, "0") == 0) {
		if (strcmp(hour, "*") == 0) {
			len = strlen(period);
			snprintf(period+len, period_len-len, "每个整点");
		}
		return;
	}

	if (strcmp(hour, "*") == 0) {
		// */n * * * *这样的形式不需要加每小时，直接说每几分钟
		if (isdigit(minute[0])) {
			len = strlen(period);
			snprintf(period+len, period_len-len, "每小时");
		}
	}
	if (handle_field(minute, period, period_len, "分", "分钟", TYPE_MINUTE) < 0) {
		snprintf(period, period_len, "%s %s %s %s %s (bad minute)",
			minute, hour, monthday, month, weekday);
		return;
	}
}

static void check_anacrontab(char *file, cJSON *cron)
{
	FILE *fp = NULL;
	char line[512] = {0}, *ptr = NULL;

	if (!file || !cron) {
		return;
	}

	fp = fopen(file, "r");
	if (!fp) {
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		int ret = 0, txtfile = 1;
		char cycle[64] = {0}, delay[64] = {0}, cmdline[256] = {0}, name[64] = {0}, period[1024] = {0};

		ptr = skip_headspace(line); //消除行首的空格符

		/* 忽略空行和注释行 */
		if (*ptr == '#' || *ptr == 0) {
			continue;
		}

		ret = sscanf(ptr, "%63s %63s %63s %255[^\n]s", cycle, delay, name, cmdline);
		if (ret != 4) {
			if (is_environment_keyvalue(cycle)) {
				continue; //忽略环境变量行
			}
		} else {
			/* 取每小时/每日/每周/每月定时任务的周期 */
			if (strstr(ptr, "cron.hourly")) {
				snprintf(period, sizeof(period), "%s", hourly);
				snprintf(name, sizeof(name), "anacron.hourly");
			} else if (strstr(ptr, "cron.daily")) {
				snprintf(period, sizeof(period), "%s", daily);
				snprintf(name, sizeof(name), "anacron.daily");
			} else if (strstr(ptr, "cron.weekly")) {
				snprintf(period, sizeof(period), "%s", weekly);
				snprintf(name, sizeof(name), "anacron.weekly");
			} else if (strstr(ptr, "cron.monthly")) {
				snprintf(period, sizeof(period), "%s", monthly);
				snprintf(name, sizeof(name), "anacron.monthly");
			}
		}

		if (period[0] == 0) { //错误的行
			txtfile = is_text_line(line);

			snprintf(name, sizeof(name), "Bad Anacron Task");
			delete_tailspace(ptr);
			snprintf(cmdline, sizeof(cmdline), "%s", ptr);
		}

		cJSON *object = cJSON_CreateObject();
		cJSON_AddStringToObject(object, "task_name", name);
		cJSON_AddStringToObject(object, "execute_cycle", period);
		cJSON_AddStringToObject(object, "command_line", cmdline);
		cJSON_AddStringToObject(object, "task_path", file);
		cJSON_AddStringToObject(object, "task_user", "root");

		cJSON_AddItemToArray(cron, object);

		if (!txtfile) {
			break; //非text文件不是有效的计划任务，不再继续解析
		}
	}
	fclose(fp);
}

int taski = 1; //全局的定时任务编号
static void check_crontab(char *file, char *inname, char *inuser, cJSON *cron)
{
	int tmpi = 1; // /etc/cron.d下的定时任务里可能有多个任务，按name,name2,name3,...编号
	FILE *fp = NULL;
	char line[512] = {0};

	if (!file || !cron) {
		return;
	}

	fp = fopen(file, "r");
	if (!fp) {
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		int ret = 0, txtfile = 1;
		char *ptr = NULL;
		char period[512] = {0};
		char str[64] = {0}, user[64] = {0}, cmdline[256] = {0}, name[64] = {0};
		char minute[256] = {0}, hour[256] = {0}, monthday[256] = {0}, month[256] = {0}, weekday[256] = {0};

		/* 消除行首的空格符 */
		ptr = line;
		while (isspace(*ptr)) {
			ptr++;
		}

		/* 忽略空行和注释行 */
		if (*ptr == '#' || *ptr == 0) {
			continue;
		}

		// suse系统上/etc/crontab有
		// -*/15 * * * *   root  test -x /usr/lib/cron/run-crons && /usr/lib/cron/run-crons >/dev/null 2>&1
		// 这个开头的-，似乎是静默的作用，即做这个任务，但在cron日志里不记录
		if (*ptr == '-') {
			ptr++;
		}

		//TODO 上报错误的行信息
		if (*ptr == '@') {
			if (inuser) {
				snprintf(user, sizeof(user), "%s", inuser);
				ret = sscanf(ptr, "%63s %255[^\n]s", str, cmdline);
				if (ret != 2) {
					if (is_environment_keyvalue(str)) {
						continue; //忽略环境变量行
					}
					goto report; //报告错误行
				}
			} else {
				ret = sscanf(ptr, "%63s %63s %255[^\n]s", str, user, cmdline);
				if (ret != 3) {
					if (is_environment_keyvalue(str)) {
						continue; //忽略环境变量行
					}
					goto report; //报告错误行
				}
			}

			get_period_by_string(str, period, sizeof(period));
		} else {
			if (inuser) {
				snprintf(user, sizeof(user), "%s", inuser);
				ret = sscanf(ptr, "%255s %255s %255s %255s %255s %255[^\n]s",
					minute, hour, monthday, month, weekday, cmdline);
				if (ret != 6) {
					if (is_environment_keyvalue(minute)) {
						continue; //忽略环境变量行
					}
					goto report; //报告错误行
				}
			} else {
				ret = sscanf(ptr, "%255s %255s %255s %255s %255s %63s %255[^\n]s",
					minute, hour, monthday, month, weekday, user, cmdline);
				if (ret != 7) {
					if (is_environment_keyvalue(minute)) {
						continue; //忽略环境变量行
					}
					goto report; //报告错误行
				}
			}

			get_period_by_fields(minute, hour, monthday, month, weekday, period, sizeof(period));
		}

		check_valid_user(user, sizeof(user));

		/* 取每小时/每日/每周/每月定时任务的周期 */
		if (strstr(cmdline, "cron.hourly")) {
			snprintf(hourly, sizeof(hourly), "%s", period);
			snprintf(name, sizeof(name), "cron.hourly");
		} else if (strstr(cmdline, "cron.daily")) {
			snprintf(daily, sizeof(daily), "%s", period);
			snprintf(name, sizeof(name), "cron.daily");
		} else if (strstr(cmdline, "cron.weekly")) {
			snprintf(weekly, sizeof(weekly), "%s", period);
			snprintf(name, sizeof(name), "cron.weekly");
		} else if (strstr(cmdline, "cron.monthly")) {
			snprintf(monthly, sizeof(monthly), "%s", period);
			snprintf(name, sizeof(name), "cron.monthly");
		} else if (inname) {
			if (tmpi == 1) {
				snprintf(name, sizeof(name), "%s", inname);
			} else {
				snprintf(name, sizeof(name), "%s%d", inname, tmpi);
			}
			tmpi++;
		} else {
			snprintf(name, sizeof(name), "crontask%d", taski);
			taski++;
		}

report:
		if (period[0] == 0) { //错误的行
			txtfile = is_text_line(line);

			snprintf(name, sizeof(name), "Bad Cron Task");
			delete_tailspace(ptr);
			snprintf(cmdline, sizeof(cmdline), "%s", ptr);
		}

		cJSON *object = cJSON_CreateObject();
		cJSON_AddStringToObject(object, "task_name", name);
		cJSON_AddStringToObject(object, "execute_cycle", period);
		cJSON_AddStringToObject(object, "command_line", cmdline);
		cJSON_AddStringToObject(object, "task_path", file);
		cJSON_AddStringToObject(object, "task_user", user);

		cJSON_AddItemToArray(cron, object);

		if (!txtfile) {
			break; //非text文件不是有效的计划任务，不再继续解析
		}
	}
	fclose(fp);
}

static void check_crontab_spool(char *dir, cJSON *cron)
{
	DIR *dirp = NULL;
	char file[512] = {0};
	struct dirent *ent = NULL;

	dirp = opendir(dir);
	if (!dirp) {
		return;
	}

	while ((ent = readdir(dirp))) {
		if (ent->d_name[0] == '.') {
			continue;
		}
		snprintf(file, sizeof(file), "%s/%s", dir, ent->d_name);
		check_crontab(file, NULL, ent->d_name, cron);
	}
	closedir(dirp);
}

static void check_crond(cJSON *cron)
{
	DIR *dirp = NULL;
	char file[512] = {0};
	struct dirent *ent = NULL;

	dirp = opendir("/etc/cron.d");
	if (!dirp) {
		return;
	}

	while ((ent = readdir(dirp))) {
		if (ent->d_name[0] == '.') {
			continue;
		}
		snprintf(file, sizeof(file), "/etc/cron.d/%s", ent->d_name);
		check_crontab(file, ent->d_name, NULL, cron);
	}
	closedir(dirp);
}

static void check_cronly(char *dir, char *period, cJSON *cron)
{
	DIR *dirp = NULL;
	char file[512] = {0}, name[512] = {0};
	struct dirent *ent = NULL;

	if (!dir || !period || !cron) {
		return;
	}

	dirp = opendir(dir);
	if (!dirp) {
		return;
	}

	while ((ent = readdir(dirp))) {
		if (ent->d_name[0] == '.') {
			continue;
		}

		snprintf(file, sizeof(file), "%s/%s", dir, ent->d_name);

		if (period == hourly) {
			snprintf(name, sizeof(name), "%s.hourly", ent->d_name);
		} else if (period == daily) {
			snprintf(name, sizeof(name), "%s.daily", ent->d_name);
		} else if (period == weekly) {
			snprintf(name, sizeof(name), "%s.weekly", ent->d_name);
		} else if (period == monthly) {
			snprintf(name, sizeof(name), "%s.monthly", ent->d_name);
		} else {
			snprintf(name, sizeof(name), "%s", ent->d_name);
		}

		cJSON *object = cJSON_CreateObject();
		cJSON_AddStringToObject(object, "task_name", name);
		cJSON_AddStringToObject(object, "execute_cycle", period);
		cJSON_AddStringToObject(object, "command_line", file);
		cJSON_AddStringToObject(object, "task_path", file);
		cJSON_AddStringToObject(object, "task_user", "root");

		cJSON_AddItemToArray(cron, object);
	}
	closedir(dirp);
}

/*
 * 用mtime来算anacron的周期，几个周期文件的ctime可能是相同的，如
 * root@debian9:/var/spool/anacron# stat *
 *   File: cron.daily
 * Access: 2022-02-12 21:04:45.824502015 +0800
 * Modify: 2022-02-12 00:09:10.305791892 +0800
 * Change: 2022-02-12 21:04:45.824502015 +0800
 *   File: cron.monthly
 * Access: 2022-02-12 21:04:45.824502015 +0800
 * Modify: 2022-02-07 15:37:44.691156830 +0800
 * Change: 2022-02-12 21:04:45.824502015 +0800
 *   File: cron.weekly
 * Access: 2022-02-12 21:04:45.824502015 +0800
 * Modify: 2022-02-07 15:32:45.455030643 +0800
 * Change: 2022-02-12 21:04:45.824502015 +0800
 */
static void get_anacron_period(char *dir)
{
	char path[4096] = {0};
	struct stat st = {0};
	struct tm t = {0};
	char weekday_cn[8][4] = { "日", "一", "二", "三", "四", "五", "六", "日" };

	if (!dir) {
		return;
	}

	snprintf(path, sizeof(path), "%s/cron.hourly", dir);
	if (stat(path, &st) == 0) {
		localtime_r(&st.st_mtime, &t);
		if (t.tm_min == 0) {
			snprintf(hourly, sizeof(hourly), "每个整点");
		} else {
			snprintf(hourly, sizeof(hourly), "每小时%02d分", t.tm_min);
		}
	}

	snprintf(path, sizeof(path), "%s/cron.daily", dir);
	if (stat(path, &st) == 0) {
		localtime_r(&st.st_mtime, &t);
		if (t.tm_min == 0) {
			snprintf(daily, sizeof(daily), "每日%d点", t.tm_hour);
		} else {
			snprintf(daily, sizeof(daily), "每日%d点%02d分", t.tm_hour, t.tm_min);
		}
	}

	snprintf(path, sizeof(path), "%s/cron.monthly", dir);
	if (stat(path, &st) == 0) {
		localtime_r(&st.st_mtime, &t);
		if (t.tm_min == 0) {
			snprintf(monthly, sizeof(monthly), "每月%d日%d点", t.tm_mday, t.tm_hour);
		} else {
			snprintf(monthly, sizeof(monthly), "每月%d日%d点%02d分", t.tm_mday, t.tm_hour, t.tm_min);
		}
	}

	snprintf(path, sizeof(path), "%s/cron.weekly", dir);
	if (stat(path, &st) == 0) {
		localtime_r(&st.st_mtime, &t);
		if (t.tm_min == 0) {
			snprintf(weekly, sizeof(weekly), "周%s%d点", weekday_cn[t.tm_wday], t.tm_hour);
		} else {
			snprintf(weekly, sizeof(weekly), "周%s%d点%02d分", weekday_cn[t.tm_wday], t.tm_hour, t.tm_min);
		}
	}
}

void get_cron_list(cJSON *cron)
{
	check_crontab("/etc/crontab", NULL, NULL, cron);

	get_anacron_period("/var/spool/anacron"); // centos/debian/ubuntu
	get_anacron_period("/var/spool/cron/lastrun"); // suse

	check_anacrontab("/etc/anacrontab", cron);

	check_crond(cron);

	check_cronly("/etc/cron.hourly",  hourly,  cron);
	check_cronly("/etc/cron.daily",   daily,   cron);
	check_cronly("/etc/cron.weekly",  weekly,  cron);
	check_cronly("/etc/cron.monthly", monthly, cron);

	check_crontab_spool("/var/spool/cron/tabs", cron);
	check_crontab_spool("/var/spool/cron/crontabs", cron);
	check_crontab_spool("/var/spool/cron", cron);
	check_crontab_spool("/var/spool/tabs", cron);

#if 0 //debug
	char *post = cJSON_Print(cron);
	printf("hourly %s\n", hourly);
	printf("daily %s\n", daily);
	printf("monthly %s\n", monthly);
	printf("weekly %s\n", weekly);
	printf("%s\n", post);
	free(post);
#endif
}
