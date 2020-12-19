# not_random
Linux kernel module to get getrandom syscalls to be less random

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

