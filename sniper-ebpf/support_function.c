#define CHAR_MAX 64
#define S_CMDLEN 400
#define PATH_MAX 4096
#define MAX_ERRNO 4095

#define unlikely(cond) (cond)
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline bool IS_ERR(const void* ptr) {
	if (ptr != NULL) {
		return IS_ERR_VALUE((unsigned long)ptr);
	}
	return true;
}


int my_strlen(char *str){
    if(str == NULL) {
		return 0;
    }
    int len = 0;
    for (int index=0; index<CHAR_MAX; index++){
		if (str[index]!='\0'){
			len++;
		}
		else
			break;
	}
	return len;
}

int my_strcmp(char *str1, char *str2) {
    if (!str1 || !str2) 
		return -1;

    int len1 = my_strlen(str1);
    int len2 = my_strlen(str2);
    if (len1 != len2) {
        return -1;
    }
    for (int i = 0; i < len1; i++) {
        if (str1[i] != str2[i]) {
            return -1;
        }
    }
    return 0;
}

bool my_strstr(char* haystack, char* needle) {
	if(!needle || !haystack) {
		return false;
	}
	bpf_printk("needle: %s", needle);
	bpf_printk("haystack: %s", haystack);
	
	int haystack_size = my_strlen(haystack);
	int needle_size   = my_strlen(needle);

	if (needle_size > haystack_size) { return false; }

	// int haystack_index = 0;
	// int needle_index = 0;
	// int offset = 0;

	// while (haystack_index < haystack_size){
		
	// 	offset = haystack_index;

	// 	if (haystack[offset] == needle[needle_index]){
	// 		if (needle_index == needle_size){
	// 			return true;
	// 		}
	// 		else {
	// 			needle_index += 1;
	// 			offset += 1;
	// 		}
	// 	}
	// 	else{
	// 		haystack_index += 1;
	// 		needle_index = 0;
	// 	}
	// }

	// return false;



	int index = 0;
	int tally = 0;
	int needle_index = 0;

	while(needle_index < needle_size) {

		if(haystack[index] == '\0') {
			return false; 
		}

		if(haystack[index] == needle[needle_index]) {
			tally++;
			needle_index++;
		}
		else { 
			if(tally == needle_size) { return true; }
			index-=tally;
			tally = 0;
	       	needle_index = 0;	
		}
		index++;
	}
	if(tally == needle_size) { return true; }
	
	return false;
}

int my_strncmp(char *str1, char *str2, int n) {
	for (int i=0;i<n;i++) {
		if (str1[i] != str2[i])
			return -1;
		if (str1[i] == '\0')
			return 0;
	}
	return 0;
}

// static inline void my_strncpy(char* dest, char* src, int n) {

// 	__builtin_memset(dest, 0, my_strlen(dest));
// 	__builtin_memcpy(dest, src, n);

// }

// Ming Yan logic

/* Return the index of last occurrence of the Char str2 in String str1*/
int my_strrchr(char *str1, char str2) {
	/*
	@Args Info:
	str1 : A pointer points to the source string.
	len  : The length of the str1.
	str2 : The Char to be detected.
	*/
    if (!str1) {
        return -1;
    }

	int len = my_strlen(str1);
    int index = len - 1;
    while (index >= 0) {
        if (str1[index] == str2) {
            break;
        }
        index--;
    }
    return index;
}

// return length of dst
int safebasename(char *dst, int size, char *path) {
    if (!path || !dst) {
        return 0;
    }
    // int len = my_strlen(path);
    int offset = my_strrchr(path, '/');
    if (offset < 0) {
        return 0;
    }
    offset++;
    dst[size] = '\0';

    // my_strncpy(dst, path + offset, size);
    // int n = len - offset;
    // n = n < size ? n : size;
    // __builtin_memcpy(dst, path + offset, n);
    // int j = offset;
    // for (int i = 0; i < n; i++) {
    //     dst[i] = path[j] + 1;
    //     j++;
    // }
	// for (int i = 0; i < n; i++) {
    //     dst[i]--;
    // }
	// return n;

    return bpf_probe_read_kernel_str(dst, size, path + offset);
}

/* Get the Absolute Path */
/*
@Args Info:
realpath : Used to store the absolute path. The length of the realpath is "CHAR_MAX"
file_dentry : A pointer point to current struct dentry.
len : the length of the current d_iname.
temp : a temporary String.
*/
static inline int get_absolute_path(char *realpath) {

	struct task_struct *current_task = bpf_get_current_task_btf();	
	struct dentry *file_dentry= NULL;
	int len = 0;
	char temp[CHAR_MAX] = {0};
	char realpath_backup[CHAR_MAX] = {0};

	// file_dentry = bprm->file->f_path.dentry;
	file_dentry = current_task->fs->pwd.dentry;

	// The Logic is :
	// We could get the current dir or file name by d_iname.
	// Get the superior dir in "d_parent" by recursion.
	// We set The Max Recursion Time to 8.
	for (int i=0;i<8;i++){
		bpf_probe_read_str(realpath_backup, sizeof(realpath_backup), realpath);
		bpf_probe_read_kernel_str(temp, sizeof(file_dentry->d_iname), file_dentry->d_iname);
		// temp[CHAR_MAX-1] = 0;
		len = my_strlen(temp);

		// bpf_printk("the length of current dentry is :%d", len);  // Debug code, Delete/Annotate it when make it through.
		// bpf_printk("current temp is %s", temp);
		// bpf_printk("current filename is %s", realpath);

		// If the length of the d_iname is 1, the current dir or file name is NULL, meaning our recursion reached a ending.
		if (len==1)
			break;

		// Move the original String "len + 1" chars Afterwords, And Load the parent d_iname into the "realpath"
		bpf_probe_read_str(realpath+len+1, CHAR_MAX-len-1, realpath_backup);
		bpf_probe_read_kernel(realpath + 1, len, temp);
		realpath[0] = '/';
		realpath[CHAR_MAX-1] = 0;   // Ensure there is a ending char in realpath.

		file_dentry = file_dentry->d_parent;  // Recursion
	}

	bpf_printk("cwd is %s", realpath);
	len = my_strlen(realpath);
	return len;
}

/*
Get the absolute path of a dentry into var "realpath"

@Args:
dentry: struct dentry.
realpath : A pointer pointing to a string.
temp : A temporary string.
len : used to store current length of the string.
*/
static inline int get_absolute_path_from_dentry(struct dentry *dentry, char *realpath) {
	int len = 0;
	char temp[CHAR_MAX] = {0};
	char realpath_backup[CHAR_MAX] = {};
	struct dentry *file_dentry= NULL;
	file_dentry = dentry;
	// The Logic is :
	// We could get the current dir or file name by d_iname.
	// Get the superior dir in "d_parent" by recursion.
	// We set The Max Recursion Time to 8.
	for (int i=0;i<8;i++){
		bpf_probe_read_str(realpath_backup, sizeof(realpath_backup), realpath);
		bpf_probe_read_kernel_str(temp, sizeof(file_dentry->d_iname), file_dentry->d_iname);
		// temp[CHAR_MAX-1] = 0;
		len = my_strlen(temp);

		// bpf_printk("the length of current dentry is :%d", len);  // Debug code, Delete/Annotate it when make it through.
		// If the length of the d_iname is 1, representing the current dir or file name is "/", meaning our recursion reached a ending.
		if (len==1)
			break;

		// Move the original String "len + 1" chars Afterwards, And Load the parent d_iname into the "realpath"

		bpf_probe_read_str(realpath+len+1, CHAR_MAX-len-1, realpath_backup);
		bpf_probe_read_kernel(realpath + 1, len, temp);
		realpath[0] = '/';
		realpath[CHAR_MAX-1] = 0;   // Ensure there is a ending char in realpath.

		bpf_probe_read(&file_dentry, sizeof(file_dentry), &file_dentry->d_parent);  // Recursion
		// file_dentry = file_dentry->d_parent;  // Recursion
	}

	bpf_printk("absolute path is %s", realpath);
	len = my_strlen(realpath);
	return len;
}

/*
Get the Parents info of the process.

@Args:
pinfo: A Struct to store the parents information

Logic is simple, Through current->real_parent to get the parent information Repeatedly.
If real_parent is NULL, Then we terminate the Recursion.

Now we temporarily stopped the "strcmp" function, only get the arguments.
*/
static inline int skip_current(struct parent_info *pinfo) {

	struct task_struct *task = NULL, *parent = NULL;
	task = bpf_get_current_task_btf();
	int pid = task->pid; // pid is the current process id

	char temp[CHAR_MAX] = {0};
	bpf_probe_read_kernel_str(temp, sizeof(temp), task->comm);

	// if (my_strcmp(temp, "sniper_chk") == 0)
	// 	return 1;
	// if (my_strcmp(temp, "assist_sniper_chk") == 0)
	// 	return 1;
	// if (my_strcmp(temp, "webshell_detector") == 0 )
	// 	return 1;

	parent = task->real_parent;
	if (!parent)
		return 0;

	task = parent;

	for (int i = 0; i < P_GEN; i++) {
		if (task->pid == 0)
			return 0;
		if (task->pid == 1)
			return 1;
		if (task->pid == pid)	// If parent process is current process, break.	
			return 0;

		pinfo->task[i].pid = task->pid;
		pinfo->task[i].uid = bpf_get_current_uid_gid();
		pinfo->task[i].proctime = task->start_boottime;
		bpf_probe_read_kernel_str(pinfo->task[i].comm, sizeof(pinfo->task[i].comm), task->comm);
		// if (task->__state >= 32) // __state >= 32, which meaning the process is dead.
		// 	pinfo->task[i].did_exec = 1;
		// else
		// 	pinfo->task[i].did_exec = 0;


		parent = task->real_parent;

		if (!parent)
			return 0;

		bpf_probe_read_kernel_str(temp, sizeof(temp), parent->comm);

		// if (my_strcmp(temp, "sniper_chk") == 0)
		// 	return 1;
		// if (my_strcmp(temp, "assist_sniper_chk")==0)
		// 	return 1;
		// if (my_strcmp(temp, "webshell_detector") == 0 )
		// 	return 1;

		task = parent;
	}

	return 0;
}

/* 
Get the arguments "args", "argc" and "options" of the process. 
	@Args:
	argv : A two-dimension pointer points to the args of the process.
	req  : Struct taskreq_t.
		args : the arguments of the process.
		argc : the number of the arguments.
		options : the number of the arguments starting with "-".

	Logic: We use a pointer *p to get the "arg" one by one.
	Get the next "arg" by "p += sizeof(char *)"
	Then count the number of the arguemnts and the arguments starting with "-".
*/
static inline int get_args_argc(const char **argv, struct taskreq_t *req) {
	int i;
	int n;
	void* p = argv;
	char *args = NULL;
	int argc = 0;     // Init the value of "argc".
	int options = 0;  // Init the value of "options".

	for (i = 0; i < MAX_ARGS; i++) {
		args = NULL;
		bpf_probe_read_user(&args, sizeof(args), p);
		if (args==NULL)    // The termination condition.
			break;
		n = bpf_probe_read_str(req->args[i], sizeof(req->args[i]), args);
		if (n < 0)    // If the length of the args less than 0, break.
			break;
		argc++;
		if (req->args[i][0] == '-')
			options++;
			
		p += sizeof(char *);
	}

	for (i = 0; i < 8; i++) {
		if (req->args[i][0] == 0) {
			bpf_printk("No args from %d", i);
			break;
		}
		bpf_printk("current %d arg is: %s", i, req->args[i]);
	}

	req->argc = argc;
	req->options = options;

	return 0;
}

static inline int get_base_info_taskreq(struct taskreq_t *req) {
	struct task_struct *current = bpf_get_current_task_btf();

	req->pid = bpf_get_current_pid_tgid();
	req->ppid = current->real_parent->pid;
	req->tgid = bpf_get_current_pid_tgid() >> 32 ;
	req->uid = bpf_get_current_uid_gid();
	req->euid = current->real_cred->euid.val;
	req->proctime = current->start_boottime;

	// bpf_printk("pid is :%d", req->pid);
	// bpf_printk("tgid is :%d", req->tgid);
	// bpf_printk("proctime is :%d", req->proctime);
	// bpf_printk("uid is :%d", req->uid);

	struct file *file0 = current->files->fd_array[0];
	struct file *file1 = current->files->fd_array[1];
	req->pipein = file0->f_path.dentry->d_inode->i_ino;
	req->pipeout = file1->f_path.dentry->d_inode->i_ino;
	// bpf_printk("i_ino_0 %d", file0->f_inode->i_ino);
	// bpf_printk("i_ino_1 %d", file1->f_inode->i_ino);

	req->exe_file = current->mm->exe_file;
	req->exeino = req->exe_file->f_path.dentry->d_inode->i_ino;
	// bpf_printk("exe_ino_1 %d", file1->f_inode->i_ino);

	return 0;
}

static inline int get_base_info_filereq(struct filereq_t *req) {
	struct task_struct *current = bpf_get_current_task_btf();

	req->pid = bpf_get_current_pid_tgid();
	req->tgid = bpf_get_current_pid_tgid() >> 32 ;
	req->proctime = current->start_boottime;
	req->uid = bpf_get_current_uid_gid();

	bpf_printk("pid is :%d", req->pid);
	bpf_printk("tgid is :%d", req->tgid);
	bpf_printk("proctime is :%lu", req->proctime);
	bpf_printk("uid is :%d", req->uid);

	// struct file *file0 = current->files->fd_array[0];
	// struct file *file1 = current->files->fd_array[1];
	// req->pipein = file0->f_path.dentry->d_inode->i_ino;
	// req->pipeout = file1->f_path.dentry->d_inode->i_ino;
	// bpf_printk("i_ino_0 %d", file0->f_inode->i_ino);
	// bpf_printk("i_ino_1 %d", file1->f_inode->i_ino);

	// req->exe_file = current->mm->exe_file;
	// req->exeino = req->exe_file->f_path.dentry->d_inode->i_ino;
	// bpf_printk("exe_ino_1 %d", file1->f_inode->i_ino);

	return 0;
}

static inline int count_files_num(struct files_struct *files) {
	int number;

	for (number=0;number<64;number++){
		if (files->fd_array[number] == NULL){
			bpf_printk("file stop at index %d", number);
			break;
		}
	}

	return number;
}

static inline unsigned int get_mnt_id() {
    struct task_struct *current = bpf_get_current_task_btf();
    return current->nsproxy->mnt_ns->ns.inum;
}

static inline char *get_uts_name() {
    struct task_struct *current = bpf_get_current_task_btf();
    return current->nsproxy->uts_ns->name.nodename;
}

/*
Get arguments from "current->mm"
*/
int get_args_from_mm(struct filereq_t *req) {
	if (!req)
		return -1;
	struct mm_struct *mm = bpf_get_current_task_btf()->mm;
    if (!mm) {
        return 0;
    }
	// struct vm_area_struct *vma = mm->mmap;
    // char argv[MAX_ARGS][32];
	void *p = (void *)mm->arg_start;
    int argc = 0;       // Init the value of "argc".
    int i, len;

	for (i = 0; i < MAX_ARGS; i++) {
		// len = bpf_probe_read_str(&argv[i], sizeof(argv[i]), p);
		len = bpf_probe_read_str(req->args[i], sizeof(req->args[i]), p);
		
		bpf_printk("current arg is %s(lengrh %d)", p, len);

		if (len <= 0)
			break;
		argc++;

		p += len;
		if (p > (void *)mm->arg_end)
			break;
	}
	req->argc = argc;
	return 0;
}