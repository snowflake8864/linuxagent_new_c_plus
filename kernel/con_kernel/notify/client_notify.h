/*
 *client_notify.h: 2019-07-9 created by qudreams
 *notify user-client-process
 */

#ifndef CLIENT_NOTIFY_H
#define CLIENT_NOTIFY_H

#include <linux/types.h>
#include <linux/list.h>

typedef struct {
    struct list_head lh;
    const char* name;
    int (*notify)(u16,void*,u32);
}client_notifier_t;

int ktq_notify_client(u16 cmd,void* data,u32 len);
int ktq_register_client_notifier(client_notifier_t* notifier);
int ktq_unregister_client_notifier(client_notifier_t* notifier);

void ktq_init_client_notifer(void);
void ktq_uninit_client_notifier(void);

#endif //end define
