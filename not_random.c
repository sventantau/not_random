/*
During a reverse engineering challenge, I needed getrandom to be less random.

As I could not find any ready to use modules.
Here is mine.

Tested on:
Linux debian 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 GNU/Linux

To use:
Copy the
Makefile and not_random.c
file into a directory.

Execute 'make'
This should build not_random.ko for you.

To load this module:
insmod not_random.ko
To remove:
rmmod not_random

ATTENTION:
Assume your system will crash! If not, that is by pure accident.
Use with care and perhaps not via ssh :)

Have fun!


Thanks to:
GoldenOak for writing a nice overview on the topic of:
"Linux Kernel Module Rootkit — Syscall Table Hijacking"
https://medium.com/bugbountywriteup/linux-kernel-module-rootkit-syscall-table-hijacking-8f1bc0bd099c

Vincent Kob and his
https://github.com/vkobel/linux-syscall-hook-rootkit/blob/master/syscall_hook_rootkit.c
which I could use as a template.

*/

//#include <linux/cred.h>
//#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/random.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sven Tantau");
MODULE_DESCRIPTION("In case you need getrandom to be not so random.");

/*
In my specific use case I needed the subsequent calls to getrandom to be different each time.
A global variable is used to introduce something predictable.
*/
int nearly_random;
EXPORT_SYMBOL(nearly_random);


typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs*);
static sys_call_ptr_t *my_sys_call_table;
static sys_call_ptr_t old_execve;



static asmlinkage ssize_t my_getrandom(const struct pt_regs *regs)
{
  char __user *buf = (char *) regs->di;
  size_t count	= (size_t) regs->si;
  // unsigned int flags = (unsigned int) regs->dx;


  // at this point you are free to implement whatever you need.
  // I needed this:
  nearly_random = nearly_random % 15;
  buf[0] = nearly_random;
  buf[1] = 0xa1;
  buf[2] = 0xa2;
  buf[3] = 0xa3;
  buf[4] = 0xa4;
  buf[5] = 0xa5;
  buf[6] = 0xa6;
  buf[7] = 0xa7;
  nearly_random++;
	return count;
}


// coming from: arch/x86/kernel/cpu/common.c
//   > void native_write_cr0(unsigned long val)
inline void mywrite_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0": "+r" (val), "+m" (__force_order));
}

static void enable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  mywrite_cr0(cr0);
}

static void disable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  mywrite_cr0(cr0);
}


static int __init syscall_not_random_init(void)
{
    my_sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    old_execve = my_sys_call_table[__NR_getrandom];
    disable_write_protection();
    my_sys_call_table[__NR_getrandom] = my_getrandom;
    enable_write_protection();
    printk(KERN_INFO "WARNING! GETRANDOM GOT PATCHED\n");
    return 0;
}

static void __exit syscall_not_random_exit(void)
{
    disable_write_protection();
    my_sys_call_table[__NR_getrandom] = old_execve;
    enable_write_protection();
}

module_init(syscall_not_random_init);
module_exit(syscall_not_random_exit);
