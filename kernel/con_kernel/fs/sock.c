#include "syscall_def.h"


KHF_FTRACE_HOOK_SYSCALL_DEFINE2(sys_socketcall,SYS_SOCKETCALL_INDEX,
        int, call, unsigned long __user *, args);

/////////////////////////////////////////////////////////////////////////////////////////////////////////
//sys_bind

// KHF_FTRACE_HOOK_SYSCALL_DEFINE3(sys_bind, SYS_BIND_INDEX,
//     int, fd, struct sockaddr __user*, uservaddr, int, addrlen);


///////////////////////////////////////////////////////////////////////////////////////////////////////
//sys_connect
KHF_FTRACE_HOOK_SYSCALL_DEFINE3(sys_connect, SYS_CONNECT_INDEX,
    int, fd, struct sockaddr __user*, uservaddr, int, addrlen);


//////////////////////////////////////////////////////////////////////////////////////////////////////
KHF_FTRACE_HOOK_SYSCALL_DEFINE3(sys_socket, SYS_SOCKET_INDEX,
    int, domain, int, type, int, protocol);
/////////////////////////////////////////////////////////////////////////////////////////////////
//sys_accept

KHF_FTRACE_HOOK_SYSCALL_DEFINE3(sys_accept, SYS_ACCEPT_INDEX,
    int, fd, struct sockaddr __user*, uservaddr, int __user *,addrlen);

KHF_FTRACE_HOOK_SYSCALL_DEFINE4(sys_accept4, SYS_ACCEPT4_INDEX,
    int, fd, struct sockaddr __user*, uservaddr,int __user *,addrlen,int, flags);


void do_hook_sock_syscalls(void)
{
    KHF_REGISTER_SC_FTRACE_HOOK(socketcall,SYS_SOCKETCALL_INDEX);
    KHF_REGISTER_SC_FTRACE_HOOK(connect,SYS_CONNECT_INDEX);
    //KHF_REGISTER_SC_FTRACE_HOOK(bind,SYS_BIND_INDEX); //现阶段没有人用，暂不hook
    KHF_REGISTER_SC_FTRACE_HOOK(socket,SYS_SOCKET_INDEX);
    KHF_REGISTER_SC_FTRACE_HOOK(accept,SYS_ACCEPT_INDEX);
    KHF_REGISTER_SC_FTRACE_HOOK(accept4,SYS_ACCEPT4_INDEX);

}
