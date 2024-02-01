/*
 *cdev.h: 2019-07-05 created by qudreams
 *support character device
 */
#ifndef KTQ_CDEV_H
#define KTQ_CDEV_H

int ktq_cdev_init(const char* cdev_name);
void ktq_cdev_uninit(void);
const char* ktq_cdev_name(void);

struct ktq_pack_stats;
int ktq_cdev_get_stats(struct ktq_pack_stats* st_in,
					struct ktq_pack_stats* st_out);

#endif
