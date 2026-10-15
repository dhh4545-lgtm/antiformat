#define __GENKSYMS__
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/path.h>

/* 待计算的导出符号原型 */
int printk(const char *fmt, ...);
long strncpy_from_user(char *dst, const char __user *src, long count);
struct proc_dir_entry *proc_create(const char *name, umode_t mode,
                                   struct proc_dir_entry *parent,
                                   const struct proc_ops *proc_ops);
struct proc_dir_entry *proc_mkdir(const char *name, struct proc_dir_entry *parent);
int register_kprobe(struct kprobe *p);
void unregister_kprobe(struct kprobe *p);
char *d_path(const struct path *path, char *buf, int buflen);

static const void *__uses[] = {
    (void*)printk, (void*)strncpy_from_user, (void*)proc_create,
    (void*)proc_mkdir, (void*)register_kprobe, (void*)unregister_kprobe,
    (void*)d_path
};