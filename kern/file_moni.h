#ifndef _FILE_MONI_H
#define _FILE_MONI_H

#define F_NAME_MAX (S_NAMELEN+4)
#define F_CMD_MAX	80
#define F_OP_MAX	20

typedef struct _usb_dev {
	int major;
	int minor;
	int new_major;
	int new_minor;
}usb_dev_t;

extern unsigned long last_deny_printer_time;
extern unsigned long last_deny_burning_time;

extern int skip_file(const char *filename);
extern int check_vim_change(char *oldfile, char*newfile);

extern int check_sensitive_file(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int check_log_delete(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int check_safe(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int check_logcollector(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int check_usb_path(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode, struct _usb_dev *dev);
extern int check_middle_target(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int check_illegal_script(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int check_webshell_detect(char *pathname, char *new_pathname, struct parent_info *pinfo, int op_type, struct inode *inode);
extern int check_cdrom(struct file *file, char *pathname, struct parent_info *pinfo, int op_type);
extern int check_printer(struct file *file, char *pathname, struct parent_info *pinfo, int op_type);

extern void report_illegal_printer(void);
extern void report_illegal_burning(void);

/* get_vfsmount.c */
extern unsigned long mount_lock_addr;
extern struct vfsmount *get_vfsmount(struct inode *inode);
extern int sniper_lookuppath(struct inode *inode, struct dentry *dentry, char *buf, int buflen, int op);

/* open_hook.c */
extern int open_hook_init(void);
extern void open_hook_exit(void);
extern int check_open_write(char *pathname, struct parent_info *pinfo, int op_type, struct inode *inode, struct _usb_dev *dev);

/* open_create.c */
extern int create_hook_init(void);
extern void create_hook_exit(void);

/* rename_hook.c */
extern int rename_hook_init(void);
extern void rename_hook_exit(void);

/* symlink_hook.c */
extern int symlink_hook_init(void);
extern void symlink_hook_exit(void);

/* unlink_hook.c */
extern int unlink_hook_init(void);
extern void unlink_hook_exit(void);

#endif /* _FILE_MONI_H */
