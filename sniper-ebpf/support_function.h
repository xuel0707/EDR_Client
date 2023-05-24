#define ARGS_LEN 4096
#define PDEBUG_DEVELOP 99

#define PSR_EXEC 0x8

#define PATH_MAX 4096 // need this bc we aren't including linux/limits.h
#define S_CMDLEN 400
#define P_GEN 4  // The Max Recursion times to get parent info

#include "support_function.c"

// Rewritten Standard Functions
// int my_strlen(char *str);
// int my_strcmp(char *str_1, char *str_2);
// int my_strrchr(char *str1, char str2);
// bool my_strstr(char* haystack, char* needle);
// void my_strncpy(char* dest, char* src, int n);

// Ming Yan logic functions
// int safebasename(char *dst, int size, char *path);
// int get_absolute_path(char *realpath);
// int skip_current(struct parent_info *pinfo);
// int get_args_argc(char **argv, struct taskreq_t *req);
// int get_base_info_req(struct taskreq_t *req);
// int count_files_num(struct files_struct *files);
// int check_if_print(struct kern_file_policy *sniper_fpolicy);
// static int parse_cmd(char *cmd, struct linux_binprm *bprm, char* fname);
