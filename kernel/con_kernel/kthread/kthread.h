#ifndef KTQ_KTHREAD_H
#define KTQ_KTHREAD_H

int  ktq_kthread_init(void);
void ktq_kthread_exit(void);

int register_kthread_notifier(struct notifier_block* notifier);
void unregister_kthread_notifier(struct notifier_block* notifier);

#endif
