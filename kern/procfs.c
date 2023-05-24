/*
 * 通过procfs修改内核变量，打开调试开关，查看监控策略
 * Author: zhengxiang
 */

#include "interface.h"

#include <linux/proc_fs.h>
#include <linux/sysctl.h>

#ifdef CONFIG_SYSCTL

static char *procfs_procbuf = NULL;
static char *procfs_procbuf_off = NULL;
static char *procfs_procbuf_end = NULL;

static char *procfs_filebuf = NULL;
static char *procfs_filebuf_off = NULL;
static char *procfs_filebuf_end = NULL;

static char *procfs_netbuf = NULL;
static char *procfs_netbuf_off = NULL;
static char *procfs_netbuf_end = NULL;

static char *procfs_midbuf = NULL;
static char *procfs_midbuf_off = NULL;
static char *procfs_midbuf_end = NULL;

/* 打印到进程策略缓存中 */
static void process_printk(const char *fmt, ...)
{
	va_list args;
	int len = 0, ret = 0;

	if (procfs_procbuf == NULL) { //无缓存空间
		return;
	}

	len = procfs_procbuf_end - procfs_procbuf_off;
	if (len == 0) { //缓存已满
		return;
	}

	/* 打印到进程策略缓存中 */
	va_start(args, fmt);
	ret = vsnprintf(procfs_procbuf_off, len, fmt, args);
	va_end(args);

	if (ret < 0) { //打印失败
		return;
	}
	if (ret >= len) {
		procfs_procbuf_off += len; //缓存偏移len，缓存已满
	} else {
		procfs_procbuf_off += ret; //缓存偏移ret
	}
}

/* 打印到文件策略缓存中 */
static void file_printk(const char *fmt, ...)
{
	va_list args;
	int len = 0, ret = 0;

	if (procfs_filebuf == NULL) { //无缓存空间
		return;
	}

	len = procfs_filebuf_end - procfs_filebuf_off;
	if (len == 0) { //缓存已满
		return;
	}

	/* 打印到文件策略缓存中 */
	va_start(args, fmt);
	ret = vsnprintf(procfs_filebuf_off, len, fmt, args);
	va_end(args);

	if (ret < 0) { //打印失败
		return;
	}
	if (ret >= len) {
		procfs_filebuf_off += len; //缓存偏移len，缓存已满
	} else {
		procfs_filebuf_off += ret; //缓存偏移ret
	}
}

/* 打印到网络策略缓存中 */
static void net_printk(const char *fmt, ...)
{
	va_list args;
	int len = 0, ret = 0;

	if (procfs_netbuf == NULL) { //无缓存空间
		return;
	}

	len = procfs_netbuf_end - procfs_netbuf_off;
	if (len == 0) { //缓存已满
		return;
	}

	/* 打印到网络策略缓存中 */
	va_start(args, fmt);
	ret = vsnprintf(procfs_netbuf_off, len, fmt, args);
	va_end(args);

	if (ret < 0) { //打印失败
		return;
	}
	if (ret >= len) {
		procfs_netbuf_off += len; //缓存偏移len，缓存已满
	} else {
		procfs_netbuf_off += ret; //缓存偏移ret
	}
}

/* 打印进程策略 */
static void print_prule(void)
{
	process_printk("client_mode            %d\n", client_mode);  //普通、学习、运维
	process_printk("\n==process strategy [ver%u]==\n",   sniper_prule_ver);
	process_printk("process_loadoff        %d\n", sniper_exec_loadoff);
	process_printk("process_engine_on      %d\n", sniper_prule.process_engine_on);
	process_printk("mbr_on                 %d\n", sniper_prule.mbr_on);
	process_printk("miner_on               %d\n", sniper_prule.miner_on);
	process_printk("danger_on              %d\n", sniper_prule.danger_on);
	process_printk("abnormal_on            %d\n", sniper_prule.abnormal_on);
	process_printk("privilege_on           %d\n", sniper_prule.privilege_on);
	process_printk("remote_execute_on      %d\n", sniper_prule.remote_execute_on);
	process_printk("webshell_on            %d\n", sniper_prule.webshell_on);
//	process_printk("webexecute_on          %d\n", sniper_prule.webexecute_on);
//	process_printk("normal_webexecute_on   %d\n", sniper_prule.normal_webexecute_on);
	process_printk("danger_webexecute_on   %d\n", sniper_prule.danger_webexecute_on);
	process_printk("port_forward_on        %d\n", sniper_prule.port_forward_on);

	process_printk("mbr_kill               %d\n", sniper_prule.mbr_kill);
	process_printk("miner_kill             %d\n", sniper_prule.miner_kill);
	process_printk("danger_kill            %d\n", sniper_prule.danger_kill);
	process_printk("abnormal_kill          %d\n", sniper_prule.abnormal_kill);
	process_printk("black_kill             %d\n", sniper_prule.black_kill);
	process_printk("privilege_kill         %d\n", sniper_prule.privilege_kill);
	process_printk("remote_execute_kill    %d\n", sniper_prule.remote_execute_kill);
//	process_printk("webshell_kill          %d\n", sniper_prule.webshell_kill);
//	process_printk("normal_webexecute_kill %d\n", sniper_prule.normal_webexecute_kill);
	process_printk("danger_webexecute_kill %d\n", sniper_prule.danger_webexecute_kill);
	process_printk("port_forward_kill      %d\n", sniper_prule.port_forward_kill);

	process_printk("remote_execute_lockip  %d\n", sniper_prule.remote_execute_lockip);
	process_printk("webshell_lockip        %d\n", sniper_prule.webshell_lockip);
	process_printk("miner_lockip           %d\n", sniper_prule.miner_lockip);

	process_printk("remote_execute_lockip_seconds  %d\n", sniper_prule.remote_execute_lockip_seconds);
	process_printk("miner_lockip_seconds   %d\n", sniper_prule.miner_lockip_seconds);

	process_printk("webmiddle_count        %d\n", sniper_prule.webmiddle_count);
	process_printk("command_count          %d\n", sniper_prule.command_count);
	process_printk("minepool_count         %d\n", sniper_prule.minepool_count);
	process_printk("black_count            %d\n", sniper_prule.black_count);
	process_printk("trust_count            %d\n", sniper_prule.trust_count);

	if (exec_debug == PDEBUG_DEVELOP) { //开发调试时，查看taskreq_t数据结构的大小，尽量减小规模
		taskreq_t req;
		process_printk("sizeof(taskreq_t)      %d\n", sizeof(taskreq_t));
		process_printk("&req.args - &req       %lu\n", (unsigned long)&req.args - (unsigned long)&req);
	}
}

/* 打印敏感命令列表 */
static void print_pcommand(void)
{
	int i = 0, count = sniper_pcommand_count;
	sniper_cmdtbl_t *pcommand = (sniper_cmdtbl_t *)sniper_pcommand;

	if (count == 0 || pcommand == NULL) {
		return;
	}

	process_printk("\nprocess command table  [ver%u, total %d]:\n", sniper_pcommand_ver, count);
	for (i = 0; i < count; i++) {
		process_printk("%d: %s\n", i, pcommand->command);
		pcommand++;
	}
}

/* 打印矿池 */
static void print_pminepool(void)
{
	int i = 0, count = sniper_pminepool_count, n = count - 1;

	if (count == 0 || sniper_pminepool == NULL) {
		return;
	}

	process_printk("\nmine pool  [ver%u, total %d]:\n", sniper_pminepool_ver, count);
	for (i = 0; i < n; i++) {
		process_printk("%s;", sniper_pminepool[i].domain);
	}
	process_printk("%s\n", sniper_pminepool[i].domain);
}

/* 打印进程黑名单 */
static void print_pblack(void)
{
	int i = 0, count = sniper_pblack_count;
	sniper_plist_t *pblack = (sniper_plist_t *)sniper_pblack;

	if (count == 0 || pblack == NULL) {
		return;
	}

	process_printk("\nblack process  [ver%u, total %d]:\n", sniper_pblack_ver, count);
	for (i = 0; i < count; i++) {
		process_printk("%d: %s, %s, %s, %s, %s, %s, %#x, %u, %#x\n", i,
				pblack->cmdname, pblack->cmdpath, pblack->cmdline,
				pblack->md5, pblack->pcmdname, pblack->rip,
				pblack->flag, pblack->uid, pblack->event_flag);
		pblack++;
	}
}

/* 打印进程过滤名单 */
static void print_pfilter(void)
{
	int i = 0, count = sniper_pfilter_count;
	sniper_plist_t *pfilter = (sniper_plist_t *)sniper_pfilter;

	if (count == 0 || pfilter == NULL) {
		return;
	}

	process_printk("\nfilter process  [ver%u, total %d]:\n", sniper_pfilter_ver, count);
	for (i = 0; i < count; i++) {
		process_printk("%d: %s, %s, %s, %s, %s, %s, %#x, %u, %#x\n", i,
				pfilter->cmdname, pfilter->cmdpath, pfilter->cmdline,
				pfilter->md5, pfilter->pcmdname, pfilter->rip,
				pfilter->flag, pfilter->uid, pfilter->event_flag);
		pfilter++;
	}
}

/* 打印进程可信名单 */
static void print_ptrust(void)
{
	int i = 0, count = sniper_ptrust_count;
	sniper_plist_t *ptrust = (sniper_plist_t *)sniper_ptrust;

	if (count == 0 || ptrust == NULL) {
		return;
	}

	process_printk("\ntrust process  [ver%u, total %d]:\n", sniper_ptrust_ver, count);
	for (i = 0; i < count; i++) {
		process_printk("%d: %s, %s, %s, %s, %s, %s, %#x, %u, %#x\n", i,
				ptrust->cmdname, ptrust->cmdpath, ptrust->cmdline,
				ptrust->md5, ptrust->pcmdname, ptrust->rip,
				ptrust->flag, ptrust->uid, ptrust->event_flag);
		ptrust++;
	}
}

/* 打印敏感文件列表 */
static void print_fsensitive(void)
{
	int i = 0, count = sniper_fsensitive_count;
	struct sniper_my_file_list *fsensitive = (struct sniper_my_file_list *)sniper_fsensitive;

	if (count == 0 || fsensitive == NULL) {
		return;
	}

	file_printk("\nsensitive file  [ver%u, total %d]:\n", sniper_fsensitive_ver, count);
	for (i = 0; i < count; i++) {
		file_printk("%d: file:%s\n", i, fsensitive->file);

		fsensitive ++;
	}
}

/* 打印监控删除动作的日志文件列表 */
static void print_flog_delete(void)
{
	int i = 0, count = sniper_flog_delete_count;
	struct sniper_my_file_list *flog_delete = (struct sniper_my_file_list *)sniper_flog_delete;

	if (count == 0 || flog_delete == NULL) {
		return;
	}

	file_printk("\nlog_delete file  [ver%u, total %d]:\n", sniper_flog_delete_ver, count);
	for (i = 0; i < count; i++) {
		file_printk("%d: file:%s\n", i, flog_delete->file);

		flog_delete ++;
	}
}

/* 打印防篡改文件列表，允许什么进程操作什么文件 */
static void print_fsafe(void)
{
	int i = 0, count = sniper_fsafe_count;
	struct sniper_file_safe *fsafe = (struct sniper_file_safe *)sniper_fsafe;

	if (count == 0 || fsafe == NULL) {
		return;
	}

	file_printk("\nsafe file  [ver%u, total %d]:\n", sniper_fsafe_ver, count);
	for (i = 0; i < count; i++) {
		if (fsafe->real_path[0] != '\0') {
			file_printk("%d: path:(%s->%s)\n", i, fsafe->path, fsafe->real_path);
		} else {
			file_printk("%d: path:%s\n", i, fsafe->path);
		}

		file_printk("%d: name:%s\n", i, fsafe->name);
		file_printk("%d: process:%s\n", i, fsafe->process);
		file_printk("%d: operation:%s\n", i, fsafe->operation);
		file_printk("%d: status:%d\n", i, fsafe->status);
		fsafe ++;
	}
}

/* 打印文件日志行为采集监控的文件列表: 监控目录，文件类型 */
static void print_flogcollector(void)
{
	int i = 0, count = sniper_flogcollector_count;
	struct sniper_file_logcollector *flogcollector = (struct sniper_file_logcollector *)sniper_flogcollector;

	if (count == 0 || flogcollector == NULL) {
		return;
	}

	file_printk("\nlogcollector file  [ver%u, total %d]:\n", sniper_flogcollector_ver, count);
	for (i = 0; i < count; i++) {
		if (flogcollector->real_path[0] != '\0') {
			file_printk("%d: filepath:(%s->%s)\n", i, flogcollector->filepath, flogcollector->real_path);
		} else {
			file_printk("%d: filepath:%s\n", i, flogcollector->filepath);
		}

		file_printk("%d: extension:%s\n", i, flogcollector->extension);

		flogcollector ++;
	}
}

/* 打印中间件进程列表 */
static void print_fmiddle_target(void)
{
	if (sniper_fmiddle_target == NULL) {
		return;
	}

	file_printk("\nmiddle_target file  [ver%u]:\n", sniper_fmiddle_target_ver);
	file_printk("target:%s\n", sniper_fmiddle_target);
}

/* 打印被监控的中间件进程所操作的二进制文件的过滤类型 */
static void print_fmiddle_binary(void)
{
	if (sniper_fmiddle_binary == NULL) {
		return;
	}

	file_printk("\nmiddle_binary file  [ver%u]:\n", sniper_fmiddle_binary_ver);
	file_printk("binary:%s\n", sniper_fmiddle_binary);
}

/* 打印被监控的中间件进程所操作的脚本文件的类型 */
static void print_fmiddle_script(void)
{
	if (sniper_fmiddle_script == NULL) {
		return;
	}

	file_printk("\nmiddle_script file  [ver%u]:\n", sniper_fmiddle_script_ver);
	file_printk("script:%s\n", sniper_fmiddle_script);
}

/* 打印非法脚本监控策略：监控目录，文件类型 */
static void print_fillegal_script(void)
{
	int i = 0, count = sniper_fillegal_script_count;
	struct sniper_file_illegal_script *fillegal_script = (struct sniper_file_illegal_script *)sniper_fillegal_script;

	if (count == 0 || fillegal_script == NULL) {
		return;
	}

	file_printk("\nillegal_script file  [ver%u, total %d]:\n", sniper_fillegal_script_ver, count);
	for (i = 0; i < count; i++) {
		if (fillegal_script->real_path[0] != '\0') {
			file_printk("%d: filepath:(%s->%s)\n", i, fillegal_script->filepath, fillegal_script->real_path);
		} else {
			file_printk("%d: filepath:%s\n", i, fillegal_script->filepath);
		}

		file_printk("%d: extension:%s\n", i, fillegal_script->extension);

		fillegal_script ++;
	}
}

/* 打印webshell监控策略：监控目录，文件类型。宽松检测和严格检测不在内核里，在用户层判 */
static void print_fwebshell_detect(void)
{
	int i = 0, count = sniper_fwebshell_detect_count;
	struct sniper_file_webshell_detect *fwebshell_detect = (struct sniper_file_webshell_detect *)sniper_fwebshell_detect;

	if (count == 0 || fwebshell_detect == NULL) {
		return;
	}

	file_printk("\nwebshell_detect file  [ver%u, total %d]:\n", sniper_fwebshell_detect_ver, count);
	for (i = 0; i < count; i++) {
		if (fwebshell_detect->real_path[0] != '\0') {
			file_printk("%d: filepath:(%s->%s)\n", i, fwebshell_detect->filepath, fwebshell_detect->real_path);
		} else {
			file_printk("%d: filepath:%s\n", i, fwebshell_detect->filepath);
		}

		file_printk("%d: extension:%s\n", i, fwebshell_detect->extension);

		fwebshell_detect ++;
	}
}

/* 打印黑名单文件 */
static void print_fblack(void)
{
	int i = 0, count = sniper_fblack_count;
	struct sniper_file_black *fblack = (struct sniper_file_black *)sniper_fblack;

	if (count == 0 || fblack == NULL) {
		return;
	}

	file_printk("\nblack file  [ver%u, total %d]:\n", sniper_fblack_ver, count);
	for (i = 0; i < count; i++) {

		file_printk("%d: filename:%s\n", i, fblack->filename);
		file_printk("%d: filepath:%s\n", i, fblack->filepath);
		file_printk("%d: md5:%s\n", i, fblack->md5);

		fblack ++;
	}
}

/* 打印过滤文件名单 */
static void print_ffilter(void)
{
	int i = 0, count = sniper_ffilter_count;

	struct sniper_file_filter *ffilter = (struct sniper_file_filter *)sniper_ffilter;

	if (count == 0 || ffilter == NULL) {
		return;
	}

	file_printk("\nfilter file  [ver%u, total %d]:\n", sniper_ffilter_ver, count);

	for (i = 0; i < count; i++) {

		file_printk("%d: filename:%s\n", i, ffilter->filename);
		file_printk("%d: filepath:%s\n", i, ffilter->filepath);
		file_printk("%d: md5:%s\n", i, ffilter->md5);

		ffilter ++;
	}

}

/* 打印u盘设备号，及监控的文件类型 */
static void print_fusb(void)
{
	int i = 0, count = sniper_fusb_count;

	struct sniper_file_usb *fusb = (struct sniper_file_usb *)sniper_fusb;

	if (count == 0 || fusb == NULL) {
		return;
	}

	file_printk("\nusb file  [ver%u, total %d]:\n", sniper_fusb_ver, count);

	for (i = 0; i < count; i++) {

		file_printk("%d: major:%d, minor:%d\n", i, fusb->major, fusb->minor);
		file_printk("%d: extension:%s\n", i, fusb->extension);

		fusb ++;
	}

}

/* 打印防勒索的文件类型 */
static void print_fencrypt(void)
{
	struct sniper_file_encrypt *fencrypt = (struct sniper_file_encrypt *)sniper_fencrypt;

	if (fencrypt == NULL) {
		return;
	}

	file_printk("\nencrypt file  [ver%u]:\n", sniper_fencrypt_ver);
	file_printk("extension:%s\n", fencrypt->extension);
}

/* 打印文件监控策略 */
static void print_fpolicy(void)
{
	file_printk("client_mode           %d\n",       client_mode);
	file_printk("\n==file policy [ver %u]==\n",	sniper_fpolicy_ver);
	file_printk("file_engine_on:       %d\n",       sniper_fpolicy.file_engine_on);
	file_printk("file_sensitive_on:    %d\n",	sniper_fpolicy.file_sensitive_on);
	file_printk("file_sensitive_kill:  %d\n",	sniper_fpolicy.file_sensitive_kill);
	file_printk("file_log_delete:      %d\n",	sniper_fpolicy.file_log_delete);
	file_printk("file_safe_on:         %d\n",	sniper_fpolicy.file_safe_on);
	file_printk("file_logcollector_on: %d\n",       sniper_fpolicy.file_logcollector_on);
	file_printk("file_middle_on:       %d\n",       sniper_fpolicy.file_middle_on);
	file_printk("file_middle_binary_on:%d\n",       sniper_fpolicy.file_middle_binary_on);
	file_printk("file_middle_binary_exclude: %d\n", sniper_fpolicy.file_middle_binary_exclude);
	file_printk("file_middle_binary_terminate:%d\n",sniper_fpolicy.file_middle_binary_terminate);
	file_printk("file_middle_script_on:%d\n",       sniper_fpolicy.file_middle_script_on);
	file_printk("file_middle_script_terminate:%d\n",sniper_fpolicy.file_middle_script_terminate);
	file_printk("file_illegal_script_on: %d\n",     sniper_fpolicy.file_illegal_script_on);
	file_printk("file_illegal_script_terminate: %d\n",sniper_fpolicy.file_illegal_script_terminate);
	file_printk("file_webshell_detect_on: %d\n",    sniper_fpolicy.file_webshell_detect_on);
	file_printk("file_webshell_detect_terminate: %d\n",sniper_fpolicy.file_webshell_detect_terminate);
	file_printk("printer_on:           %d\n",       sniper_fpolicy.printer_on);
	file_printk("printer_terminate:    %d\n",       sniper_fpolicy.printer_terminate);
	file_printk("cdrom_on:             %d\n",       sniper_fpolicy.cdrom_on);
	file_printk("cdrom_terminate:      %d\n",       sniper_fpolicy.cdrom_terminate);
	file_printk("encrypt_on:           %d\n",       sniper_fpolicy.encrypt_on);
	file_printk("encrypt_terminate:    %d\n",       sniper_fpolicy.encrypt_terminate);
	file_printk("encrypt_backup_on:    %d\n",       sniper_fpolicy.encrypt_backup_on);
	file_printk("encrypt_space_full:   %d\n",       sniper_fpolicy.encrypt_space_full);
	file_printk("encrypt_hide_on:      %d\n",       sniper_fpolicy.encrypt_hide_on);
	file_printk("usb_file_on:          %d\n",       sniper_fpolicy.usb_file_on);
	file_printk("antivirus_on:         %d\n",       sniper_fpolicy.antivirus_on);

	file_printk("sensitive_count:      %d\n",       sniper_fpolicy.sensitive_count);
	file_printk("log_delete_count:     %d\n",       sniper_fpolicy.log_delete_count);
	file_printk("safe_count:           %d\n",	sniper_fpolicy.safe_count);
	file_printk("logcollector_count:   %d\n",       sniper_fpolicy.logcollector_count);
	file_printk("illegal_script_count: %d\n",       sniper_fpolicy.illegal_script_count);
	file_printk("webshell_detect_count:%d\n",       sniper_fpolicy.webshell_detect_count);
	file_printk("printer_count:        %d\n",       sniper_fpolicy.printer_count);
	file_printk("cdrom_count:          %d\n",       sniper_fpolicy.cdrom_count);
	file_printk("black_count:          %d\n",       sniper_fpolicy.black_count);
	file_printk("filter_count:         %d\n",       sniper_fpolicy.filter_count);
	file_printk("usb_count:            %d\n",       sniper_fpolicy.usb_count);
	file_printk("neglect_min:          %d\n",       sniper_fpolicy.neglect_min);
	file_printk("neglect_size:         %d\n",       sniper_fpolicy.neglect_size);
}

/* 打印网络监控策略 */
static void print_nrule(void)
{
	net_printk("client_mode               %d\n",	client_mode);
	net_printk("\n===net strategy [ver%u]===\n",    sniper_nrule_ver);
	net_printk("net_loadoff               %d\n",	sniper_net_loadoff);
	net_printk("net_engine_on             %d\n",	sniper_nrule.net_engine_on);
	net_printk("dns_watch                 %d\n",	sniper_nrule.dns_watch);
	net_printk("internet_watch            %d\n",	sniper_nrule.internet_watch);
	net_printk("connection_watch          %d\n",	sniper_nrule.connection_watch);
	net_printk("dns_reject                %d\n",	sniper_nrule.dns_reject);
	net_printk("internet_reject           %d\n",	sniper_nrule.internet_reject);
	net_printk("honeyport_reject          %d\n",    sniper_nrule.honeyport_reject);
	net_printk("blackwhite_reject         %d\n",	sniper_nrule.blackwhite_reject);
	net_printk("honeyport_lockip          %d\n",	sniper_nrule.honeyport_lockip);
	net_printk("connection_filterip_count %d\n",	sniper_nrule.connection_filterip_count);
	net_printk("lanip_count               %d\n",	sniper_nrule.lanip_count);
	net_printk("honeyport_count           %d\n",	sniper_nrule.honeyport_count);
	net_printk("honeyport_filterip_count  %d\n",	sniper_nrule.honeyport_filterip_count);
	net_printk("honeyport_trustip_count   %d\n",	sniper_nrule.honeyport_trustip_count);
	net_printk("dnsfilter_count           %d\n",	sniper_nrule.dnsfilter_count);
	net_printk("dnsblack_count            %d\n",	sniper_nrule.dnsblack_count);
	net_printk("whitein_count             %d\n",	sniper_nrule.whitein_count);
	net_printk("whiteout_count            %d\n",	sniper_nrule.whiteout_count);
	net_printk("blackin_count             %d\n",	sniper_nrule.blackin_count);
	net_printk("blackout_count            %d\n",	sniper_nrule.blackout_count);
	net_printk("server_count              %d\n",	sniper_nrule.server_count);
	net_printk("honey_lockip_seconds      %d\n",	sniper_nrule.honey_lockip_seconds);
	net_printk("portscan_max              %d\n",	sniper_nrule.portscan_max);
	net_printk("portscan_time             %d\n",	sniper_nrule.portscan_time);
	net_printk("portscan_lock_time        %d\n",	sniper_nrule.portscan_lock_time);
}

/* 打印诱捕端口列表 */
static void print_nhoneyport(void)
{
	int i = 0, count = sniper_nhoneyport_count;
	unsigned short *port = (unsigned short *)sniper_nhoneyport;

	if (count == 0 || port == NULL) {
		return;
	}

	net_printk("\nhoneyport  [ver%u, total %d]:\n", sniper_nhoneyport_ver, count);
	for (i = 0; i < count; i++) {
		net_printk("%d: %d\n", i, port[i]);
	}
}

/* 打印ip或ip范围 */
static void iprange2str(char *ip, int ip_len, struct sniper_iprange *ipr)
{
	if (sniper_badptr(ip) || sniper_badptr(ipr)) {
		return;
	}

	if (ipr->toip.ip[0] != 0) { //ip范围
		snprintf(ip, ip_len, "%u.%u.%u.%u-%u.%u.%u.%u",
			ipr->fromip.ip[0], ipr->fromip.ip[1],
			ipr->fromip.ip[2], ipr->fromip.ip[3],
			ipr->toip.ip[0], ipr->toip.ip[1],
			ipr->toip.ip[2], ipr->toip.ip[3]);
	} else if (ipr->sniper_ipmask == 0) { //单个ip
		snprintf(ip, ip_len, "%u.%u.%u.%u",
			ipr->fromip.ip[0], ipr->fromip.ip[1],
			ipr->fromip.ip[2], ipr->fromip.ip[3]);
	} else { //ip网段
		snprintf(ip, ip_len, "%u.%u.%u.%u/%u",
			ipr->fromip.ip[0], ipr->fromip.ip[1],
			ipr->fromip.ip[2], ipr->fromip.ip[3],
			ipr->sniper_ipmask);
	}
}
static void print_iprange(int count, char *data, char *desc, int version)
{
	int i = 0, size = sizeof(struct sniper_iprange);
	struct sniper_iprange *ipr = (struct sniper_iprange *)data;
	char ip[S_IPLEN] = {0};

	if (count == 0 || sniper_badptr(ipr) || sniper_badptr(desc)) {
		return;
	}

	net_printk("\n%s  [ver%u, total %d]:\n", desc, version, count);
	for (i = 0; i < count; i++) {
		iprange2str(ip, sizeof(ip), ipr);
		net_printk("%d: %s\n", i, ip);
		ipr += size;
	}
}
/* 打印特殊局域网网段 */
static void print_nlanip(void)
{
	print_iprange(sniper_nlanip_count, sniper_nlanip, "LAN ip", sniper_nlanip_ver);
}
/* 打印网络连接过滤ip */
static void print_nconnection_filterip(void)
{
	print_iprange(sniper_nconnection_filterip_count, sniper_nconnection_filterip,
		      "connection filterip", sniper_nconnection_filterip_ver);
}
/* 打印端口扫描过滤ip */
static void print_nhoneyport_filterip(void)
{
	print_iprange(sniper_nhoneyport_filterip_count, sniper_nhoneyport_filterip,
		      "honeyport filterip", sniper_nhoneyport_filterip_ver);
}
/* 打印端口扫描可信ip */
static void print_nhoneyport_trustip(void)
{
	print_iprange(sniper_nhoneyport_trustip_count, sniper_nhoneyport_trustip,
		      "honeyport trustip", sniper_nhoneyport_trustip_ver);
}

/* 打印当前被锁的ip */
static void print_nlockip(void)
{
	int i = 0, j = 0;
	lockipinfo_t *info = NULL, *tmp = NULL;
	iplist_t *iplist = lockiplist;
	time_t now = sniper_uptime();

	net_printk("locked ip:\n");
	for (i = 0; i < IPLISTNUM; i++, iplist++) {
		read_lock(&iplist->lock);
		list_for_each_entry_safe(info, tmp, &iplist->queue, list) {
			/* 有过期的ip未被自动解锁，这里不自动清理，降低代码复杂度
			   手工做sniper -i命令解锁清理 */
			if (info->time_unlock > now) {
				net_printk("%d: %u.%u.%u.%u lock reason %d, term %lds\n",
					   j, IPSTR(&info->ip), info->reason,
					   info->time_unlock - now);
			} else {
				net_printk("%d: %u.%u.%u.%u lock reason %d, term %lds "
					   "[invalid record, sniper -i %u.%u.%u.%u clean it]\n",
					   j, IPSTR(&info->ip), info->reason,
					   info->time_unlock - now);
			}

			j++;
		}
		read_unlock(&iplist->lock);
	}
	if (j == 0) {
		net_printk("    no ip locked\n");
	}
}

/* 打印管控服务器列表 */
static void print_nserver(void)
{
	int i = 0, count = sniper_nserver_count;
	struct sniper_server *server = (struct sniper_server *)sniper_nserver;

	if (count == 0 || server == NULL) {
		return;
	}

	net_printk("\nserver ip  [ver%u, total %d]:\n", sniper_nserver_ver, count);
	for (i = 0; i < count; i++) {
		net_printk("%d: %d.%d.%d.%d:%d/%d, %s\n", i,
			   IPSTR(&server[i].ip), server[i].port, server[i].wsport,
			   server[i].active ? "inuse" : "standby");
	}
}

static void print_domain(int count, domaintbl_t *tbl, char *desc, int version)
{
	int i = 0, n = count - 1;

	if (count == 0 || tbl == NULL) {
		return;
	}

	net_printk("\n%s  [ver%u, total %d]:\n", desc, version, count);
	for (i = 0; i < n; i++) {
		net_printk("%s;", tbl[i].domain);
	}
	net_printk("%s\n", tbl[i].domain);
}

/* 打印过滤域名 */
static void print_ndnsfilter(void)
{
	print_domain(sniper_ndnsfilter_count, sniper_ndnsfilter, "filter domain", sniper_ndnsfilter_ver);
}
/* 打印黑域名 */
static void print_ndnsblack(void)
{
	print_domain(sniper_ndnsblack_count, sniper_ndnsblack, "black domain", sniper_ndnsblack_ver);
}

/* 打印连入连出黑白名单 */
static void print_nblackwhite(int count, char *data, char *desc, char *portdesc, int version)
{
	int i = 0;
	char ip[S_IPLEN] = {0};
	struct sniper_connrule *rule = (struct sniper_connrule *)data;

	if (count == 0 || rule == NULL) {
		return;
	}

	net_printk("\n%s  [ver%u, total %d]:\n", desc, version, count);
	for (i = 0; i < count; i++) {
		iprange2str(ip, sizeof(ip), &rule[i].ipr);
		net_printk("%d: tcp%d/udp%d, %s, %s %d-%d\n",
			   i, rule[i].tcp, rule[i].udp,
			   ip, portdesc, rule[i].fromport, rule[i].toport);
	}
}
static void print_nwhitein(void)
{
	print_nblackwhite(sniper_nwhitein_count, sniper_nwhitein,
			  "connect-in whitelist", "local port",
			  sniper_nwhitein_ver);
}
static void print_nwhiteout(void)
{
	print_nblackwhite(sniper_nwhiteout_count, sniper_nwhiteout,
			  "connect-out whitelist", "remote port",
			  sniper_nwhiteout_ver);
}
static void print_nblackin(void)
{
	print_nblackwhite(sniper_nblackin_count, sniper_nblackin,
			  "connect-in blacklist", "local port",
			  sniper_nblackin_ver);
}
static void print_nblackout(void)
{
	print_nblackwhite(sniper_nblackout_count, sniper_nblackout,
			  "connect-out blacklist", "remote port",
			  sniper_nblackout_ver);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define FUNCTION_ARGS struct ctl_table *table, int write, struct file *filp, void __user *buffer, size_t *lenp, loff_t *ppos
#define DOSTRING_ARGS table, write, filp, buffer, lenp, ppos
#else
#define FUNCTION_ARGS struct ctl_table *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos
#define DOSTRING_ARGS table, write, buffer, lenp, ppos
#endif

#define LOCKPRINT(name)   read_lock(&sniper_##name##_lock); print_##name(); read_unlock(&sniper_##name##_lock)

/* 有些策略不默认显示，以免被友商在客户端轻易获得，如矿池、非法脚本关键字 */
#define PRINT_PMINEPOOL 12580
/* 敏感命令列表 */
#define PRINT_PCOMMAND  12581
/*
 * cat /proc/sys/sniper/process_stragety会调用两次或多次sniper_print_process_strategy()，
 * 这是正常的。每次的ppos不同。最后一次通常啥也不显示，因为前面都显示完了。
 *
 * 多次填充procfs_procbuf没关系
 * 通常的做法是在策略更新时，更新procfs_procbuf，
 * 放这里的目的是减少对策略更新的打扰，如果代码有问题，也只是看proc的时候有影响
 */
static int sniper_print_process_strategy(FUNCTION_ARGS)
{
	int ret = 0;

	/* 分配了无效的procfs_procbuf，或上次查看时分配的没释放。不太可能发生 */
	if (procfs_procbuf != NULL) {
		myprintk("Warning: procfs_procbuf %p, should NULL\n", procfs_procbuf);
	}

	/* 分配空间，增加占用内存的统计值 */
	procfs_procbuf = sniper_vmalloc(SNIPER_PROCFS_BUFSIZE, VMALLOC_PROCFS_PROC);
	if (sniper_badptr(procfs_procbuf)) {
		if (procfs_procbuf != NULL) {
			myprintk("Warning: invalid procfs_procbuf %p\n", procfs_procbuf);
		}
		return -ENOMEM;
	}

	memset(procfs_procbuf, 0, SNIPER_PROCFS_BUFSIZE);
	procfs_procbuf_off = procfs_procbuf;
	procfs_procbuf_end = procfs_procbuf + SNIPER_PROCFS_BUFSIZE - 1;

	/* 填写进程策略信息 */

	if (sniper_dump == PRINT_PMINEPOOL) {
		LOCKPRINT(pminepool);
	} else if (sniper_dump == PRINT_PCOMMAND) {
		LOCKPRINT(pcommand);
	} else {
		LOCKPRINT(prule);
		LOCKPRINT(pblack);
		LOCKPRINT(pfilter);
		LOCKPRINT(ptrust);
	}

	/* 输出结果 */
	table->data = procfs_procbuf;
	ret = proc_dostring(DOSTRING_ARGS);

	/* 释放空间，减少占用内存的统计值，并置procfs_procbuf为NULL */
	sniper_vfree(procfs_procbuf, SNIPER_PROCFS_BUFSIZE, VMALLOC_PROCFS_PROC);

	table->data = NULL;

	return ret;
}

/* 打印文件监控策略 */
static int sniper_print_file_strategy(FUNCTION_ARGS)
{
	int ret = 0;

	/* 分配了无效的procfs_filebuf，或上次查看时分配的没释放。不太可能发生 */
	if (procfs_filebuf != NULL) {
		myprintk("Warning: procfs_filebuf %p, should NULL\n", procfs_filebuf);
	}

	/* 分配空间，增加占用内存的统计值 */
	procfs_filebuf = sniper_vmalloc(SNIPER_PROCFS_BUFSIZE, VMALLOC_PROCFS_FILE);
	if (sniper_badptr(procfs_filebuf)) {
		if (procfs_filebuf != NULL) {
			myprintk("Warning: invalid procfs_filebuf %p\n", procfs_filebuf);
		}
		return -ENOMEM;
	}

	memset(procfs_filebuf, 0, SNIPER_PROCFS_BUFSIZE);
	procfs_filebuf_off = procfs_filebuf;
	procfs_filebuf_end = procfs_filebuf + SNIPER_PROCFS_BUFSIZE - 1;

	/* 填写文件策略信息 */

	LOCKPRINT(fpolicy);
	LOCKPRINT(fsensitive);
	LOCKPRINT(flog_delete);
	LOCKPRINT(fsafe);
	LOCKPRINT(flogcollector);
	LOCKPRINT(fmiddle_target);
	LOCKPRINT(fmiddle_binary);
	LOCKPRINT(fmiddle_script);
	LOCKPRINT(fillegal_script);
	LOCKPRINT(fwebshell_detect);
	LOCKPRINT(fblack);
	LOCKPRINT(ffilter);
	LOCKPRINT(fusb);
	LOCKPRINT(fencrypt);

	/* 输出结果 */
	table->data = procfs_filebuf;
	ret = proc_dostring(DOSTRING_ARGS);

	/* 释放空间，减少占用内存的统计值，并置procfs_filebuf为NULL */
	sniper_vfree(procfs_filebuf, SNIPER_PROCFS_BUFSIZE, VMALLOC_PROCFS_FILE);

	table->data = NULL;

	return ret;
}

/* 打印网络监控策略 */
static int sniper_print_net_strategy(FUNCTION_ARGS)
{
	int ret = 0;

	/* 分配了无效的procfs_netbuf，或上次查看时分配的没释放。不太可能发生 */
	if (procfs_netbuf != NULL) {
		myprintk("Warning: procfs_netbuf %p, should NULL\n", procfs_netbuf);
	}

	/* 分配空间，增加占用内存的统计值 */
	procfs_netbuf = sniper_vmalloc(SNIPER_PROCFS_BUFSIZE, VMALLOC_PROCFS_NET);
	if (sniper_badptr(procfs_netbuf)) {
		if (procfs_netbuf != NULL) {
			myprintk("Warning: invalid procfs_netbuf %p\n", procfs_netbuf);
		}
		return -ENOMEM;
	}

	memset(procfs_netbuf, 0, SNIPER_PROCFS_BUFSIZE);
	procfs_netbuf_off = procfs_netbuf;
	procfs_netbuf_end = procfs_netbuf + SNIPER_PROCFS_BUFSIZE - 1;

	/* 填写网络策略信息 */

	LOCKPRINT(nrule);
	LOCKPRINT(nlanip);
	LOCKPRINT(nserver);
	LOCKPRINT(nwhitein);
	LOCKPRINT(nwhiteout);
	LOCKPRINT(nblackin);
	LOCKPRINT(nblackout);

	print_nlockip();

	read_lock(&sniper_nconnection_lock);
	print_nconnection_filterip();
	read_unlock(&sniper_nconnection_lock);

	read_lock(&sniper_nhoneyport_lock);
	print_nhoneyport();
	print_nhoneyport_filterip();
	print_nhoneyport_trustip();
	read_unlock(&sniper_nhoneyport_lock);

	read_lock(&sniper_ndns_lock);
	print_ndnsblack();
	print_ndnsfilter();
	read_unlock(&sniper_ndns_lock);

	/* 输出结果 */
	table->data = procfs_netbuf;
	ret = proc_dostring(DOSTRING_ARGS);

	/* 释放空间，减少占用内存的统计值，并置procfs_netbuf为NULL */
	sniper_vfree(procfs_netbuf, SNIPER_PROCFS_BUFSIZE, VMALLOC_PROCFS_NET);

	table->data = NULL;

	return ret;
}

/* 打印中间件进程列表，这个没有指定的名单，是将所有listen的进程视为中间件进程 */
static void middleware_printk(const char *fmt, ...)
{
	va_list args;
	int len = 0, ret = 0;

	if (procfs_midbuf == NULL) { //无缓存空间
		return;
	}

	len = procfs_midbuf_end - procfs_midbuf_off;
	if (len == 0) { //缓存已满
		return;
	}

	/* 打印到中间件缓存中 */
	va_start(args, fmt);
	ret = vsnprintf(procfs_midbuf_off, len, fmt, args);
	va_end(args);

	if (ret < 0) { //打印失败
		return;
	}
	if (ret >= len) {
		procfs_midbuf_off += len; //缓存偏移len，缓存已满
	} else {
		procfs_midbuf_off += ret; //缓存偏移ret
	}
}
static void print_middleware(void)
{
	int i = 0, j = 0, count = sniper_pmiddleware_count;
	struct sniper_middleware *mid = (struct sniper_middleware *)sniper_pmiddleware;

	if (count == 0 || mid == NULL) {
		return;
	}

	middleware_printk("middleware [ver%u, total %d]:\n", sniper_pmiddleware_ver, count);
	for (i = 0; i < SNIPER_MIDDLEWARE_NUM; i++, mid++) {
		if (mid->pid > 0) {
			middleware_printk("%02d: %-15s %-8d port %-5d fd %-4d ino %lu\n",
				j, mid->name, mid->pid, mid->port, mid->fd, mid->ino);
			j++; //用j来使得序号连续
		}
	}
}
static int sniper_print_middleware(FUNCTION_ARGS)
{
	int ret = 0;

	/* 分配了无效的procfs_midbuf，或上次查看时分配的没释放。不太可能发生 */
	if (procfs_midbuf != NULL) {
		myprintk("Warning: procfs_midbuf %p, should NULL\n", procfs_midbuf);
	}

	/* 分配空间，增加占用内存的统计值 */
	procfs_midbuf = sniper_vmalloc(SNIPER_PROCFS_BUFSIZE, VMALLOC_PROCFS_MID);
	if (sniper_badptr(procfs_midbuf)) {
		if (procfs_midbuf != NULL) {
			myprintk("Warning: invalid procfs_midbuf %p\n", procfs_midbuf);
		}
		return -ENOMEM;
	}

	memset(procfs_midbuf, 0, SNIPER_PROCFS_BUFSIZE);
	procfs_midbuf_off = procfs_midbuf;
	procfs_midbuf_end = procfs_midbuf + SNIPER_PROCFS_BUFSIZE - 1;

	/* 填写中间件信息 */
	read_lock(&sniper_pmiddleware_lock);
	print_middleware();
	read_unlock(&sniper_pmiddleware_lock);

	/* 输出结果 */
	table->data = procfs_midbuf;
	ret = proc_dostring(DOSTRING_ARGS);

	/* 释放空间，减少占用内存的统计值，并置procfs_midbuf为NULL */
	sniper_vfree(procfs_midbuf, SNIPER_PROCFS_BUFSIZE, VMALLOC_PROCFS_MID);

	table->data = NULL;

	return ret;
}

static int sniper_print_memusage(FUNCTION_ARGS)
{
	int ret = 0;
	char *sniper_memusage_buf = NULL;

	/* 分配空间，增加占用内存的统计值 */
	sniper_memusage_buf = sniper_vmalloc(SNIPER_PROCFS_BUFSIZE, VMALLOC_PROCFS_MEM);
	if (sniper_badptr(sniper_memusage_buf)) {
		if (sniper_memusage_buf != NULL) {
			myprintk("Warning: invalid sniper_memusage_buf %p\n", sniper_memusage_buf);
		}
		return -ENOMEM;
	}

	memset(sniper_memusage_buf, 0, SNIPER_PROCFS_BUFSIZE);

	/* 填写内存使用情况 */
	print_memusage(sniper_memusage_buf, SNIPER_PROCFS_BUFSIZE);

	/* 输出结果 */
	table->data = sniper_memusage_buf;
	ret = proc_dostring(DOSTRING_ARGS);

	/* 释放空间，减少占用内存的统计值，并置sniper_memusage_buf为NULL */
	sniper_vfree(sniper_memusage_buf, SNIPER_PROCFS_BUFSIZE, VMALLOC_PROCFS_MEM);

	table->data = NULL;

	return ret;
}

static struct ctl_table_header *sniper_table_header = NULL;

static struct ctl_table sniper_table[] = {
	/*
	 * NB No .strategy entries have been provided since sysctl(8) prefers
	 * to go via /proc for portability.
	 */
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 1,
#endif
		.procname	= "netlink", //查看使用的netlink号
		.data		= &sniper_netlink,
		.maxlen		= sizeof(int),
		.mode		= 0400,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 2,
#endif
		.procname	= "exec_debug",
		.data		= &exec_debug, //进程调试开关
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 3,
#endif
		.procname	= "file_debug",
		.data		= &file_debug, //文件调试开关
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 4,
#endif
		.procname	= "virus_debug", //杀毒调试开关
		.data		= &virus_debug,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 5,
#endif
		.procname	= "net_debug", //网络调试开关
		.data		= &net_debug,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 6,
#endif
		/* 控制输出的监控策略内容，目前用于查看矿池列表和敏感命令列表 */
		.procname	= "print_strategy",
		.data		= &sniper_dump,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 7,
#endif
		.procname	= "process_strategy", //用于查看进程监控策略
		.maxlen		= SNIPER_PROCFS_BUFSIZE,
		.mode		= 0400,
		.proc_handler	= &sniper_print_process_strategy,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 8,
#endif
		.procname	= "file_strategy", //用于查看文件监控策略
		.maxlen		= SNIPER_PROCFS_BUFSIZE,
		.mode		= 0400,
		.proc_handler	= &sniper_print_file_strategy,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 9,
#endif
		.procname	= "net_strategy", //用于查看网络监控策略
		.maxlen		= SNIPER_PROCFS_BUFSIZE,
		.mode		= 0400,
		.proc_handler	= &sniper_print_net_strategy,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 10,
#endif
		/* 用于研究大文件的写，设置大文件的阈值大小，默认30M
		   file_debug值为20时，打印大文件的写动作 */
		.procname	= "filesize_threshold",
		.data		= &filesize_threshold,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 11,
#endif
		.procname	= "middleware", //用于查看中间件列表
		.maxlen		= SNIPER_PROCFS_BUFSIZE,
		.mode		= 0400,
		.proc_handler	= &sniper_print_middleware,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 12,
#endif
		.procname	= "mem_debug", //内存调试开关
		.data		= &mem_debug,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 13,
#endif
		.procname	= "mem_usage", //查看内存使用情况
		.maxlen		= SNIPER_PROCFS_BUFSIZE,
		.mode		= 0400,
		.proc_handler	= &sniper_print_memusage,
	},
	{  }
};

static struct ctl_table top_table[] = {
	{
/* 2.6.19之前，An entry with zero ctl_name terminates the table
   2.6.19开始，An entry with zero ctl_name and NULL procname terminates the table */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
		.ctl_name	= 12, //内核已经定义了10个，如CTL_FS, CTL_CPU
#endif
		.procname	= "sniper",
		.mode		= 0555,
		.data		= NULL,
		.maxlen		= 0,
		.child		= sniper_table,
	},
	{  }
};

int procfs_init(void)
{
	if (sniper_table_header == NULL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
		sniper_table_header = register_sysctl_table(top_table, 0);
#else
		sniper_table_header = register_sysctl_table(top_table);
#endif
	}

	return 0;
}

void procfs_exit(void)
{
	if (sniper_table_header != NULL) {
		unregister_sysctl_table(sniper_table_header);
		sniper_table_header = NULL;
	}
}
#else //no CONFIG_SYSCTL
int procfs_init(void)
{
	return 0;
}

void procfs_exit(void)
{
}
#endif
