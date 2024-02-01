#ifndef __SYSCALL_DEF_H__
#define __SYSCALL_DEF_H__

#include "hookframe/khookframe.h"

#define SYS_OPEN_INDEX      KHF_SYSCALL_INDEX(__NR_open)
#define SYS_OPENAT_INDEX    KHF_SYSCALL_INDEX(__NR_openat)

#define SYS_CLOSE_INDEX     KHF_SYSCALL_INDEX(__NR_close)

#define SYS_TRUNCATE_INDEX  KHF_SYSCALL_INDEX(__NR_truncate)
#define SYS_FTRUNCATE_INDEX  KHF_SYSCALL_INDEX(__NR_ftruncate)

#define SYS_LINK_INDEX      KHF_SYSCALL_INDEX(__NR_link)
#define SYS_LINKAT_INDEX    KHF_SYSCALL_INDEX(__NR_linkat)

#define SYS_UNLINK_INDEX    KHF_SYSCALL_INDEX(__NR_unlink)
#define SYS_UNLINKAT_INDEX  KHF_SYSCALL_INDEX(__NR_unlinkat)

#define SYS_CHMOD_INDEX     KHF_SYSCALL_INDEX(__NR_chmod)
#define SYS_FCHMOD_INDEX    KHF_SYSCALL_INDEX(__NR_fchmod)
#define SYS_FCHMODAT_INDEX  KHF_SYSCALL_INDEX(__NR_fchmodat)

#define SYS_CHOWN_INDEX     KHF_SYSCALL_INDEX(__NR_chown)
#define SYS_LCHOWN_INDEX    KHF_SYSCALL_INDEX(__NR_lchown)
#define SYS_FCHOWN_INDEX    KHF_SYSCALL_INDEX(__NR_fchown)
#define SYS_FCHOWNAT_INDEX  KHF_SYSCALL_INDEX(__NR_fchownat)

#define SYS_MKDIR_INDEX     KHF_SYSCALL_INDEX(__NR_mkdir)
#define SYS_MKDIRAT_INDEX   KHF_SYSCALL_INDEX(__NR_mkdirat)

#define SYS_RENAME_INDEX    KHF_SYSCALL_INDEX(__NR_rename)
#define SYS_RENAMEAT_INDEX  KHF_SYSCALL_INDEX(__NR_renameat)
#define SYS_RENAMEAT2_INDEX KHF_SYSCALL_INDEX(__NR_renameat2)

#define SYS_MOUNT_INDEX     KHF_SYSCALL_INDEX(__NR_mount)
//此处要使用__NR_umount2，2.6.18以后的内核上全部采用的它
#define SYS_UMOUNT_INDEX    KHF_SYSCALL_INDEX(__NR_umount2)
#define SYS_OLDUMOUNT_INDEX KHF_SYSCALL_INDEX(__NR_umount)

#define SYS_KILL_INDEX      KHF_SYSCALL_INDEX(__NR_kill)
#define SYS_PTRACE_INDEX    KHF_SYSCALL_INDEX(__NR_ptrace)


#define SYS_IOCTL_INDEX     KHF_SYSCALL_INDEX(__NR_ioctl)

#define SYS_UTIMENSAT_INDEX KHF_SYSCALL_INDEX(__NR_utimensat)

#define SYS_FUTIMESAT_INDEX KHF_SYSCALL_INDEX(__NR_futimesat) 
#define SYS_UTIMES_INDEX    KHF_SYSCALL_INDEX(__NR_utimes) 
#define SYS_MMAP_INDEX      KHF_SYSCALL_INDEX(__NR_mmap)
#define SYS_MMAP2_INDEX      KHF_SYSCALL_INDEX(__NR_mmap2)

#define SYS_GETDENTS_INDEX      KHF_SYSCALL_INDEX(__NR_getdents)
#define SYS_GETDENTS64_INDEX    KHF_SYSCALL_INDEX(__NR_getdents64)
//在mips和arm64上发现__NR_socketcall，所以在非i386上面，定义系统编号为-1
#if defined(__i386__) && defined(__ARCH_WANT_SYS_SOCKETCALL)
#define SYS_SOCKETCALL_INDEX     KHF_SYSCALL_INDEX(__NR_socketcall)
#else 
#define SYS_SOCKETCALL_INDEX     -1
#endif
#define SYS_ACCEPT_INDEX        KHF_SYSCALL_INDEX(__NR_accept)
#define SYS_BIND_INDEX          KHF_SYSCALL_INDEX(__NR_bind)
#define SYS_CONNECT_INDEX       KHF_SYSCALL_INDEX(__NR_connect)
#define SYS_SOCKET_INDEX        KHF_SYSCALL_INDEX(__NR_socket)
#define SYS_ACCEPT4_INDEX       KHF_SYSCALL_INDEX(__NR_accept4) 
#define SYS_DELETE_MODULE_INDEX  KHF_SYSCALL_INDEX(__NR_delete_module)

#endif  /* __SYSCALL_DEF_H__ */
