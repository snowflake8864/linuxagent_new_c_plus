#ifndef KTQ_MM_CDEV_H
#define KTQ_MM_CDEV_H

/*
 *kernel tian qing mmap char-device
 *mmc is a short-name for mmap char-device
 */

#include <linux/in6.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/version.h>


/* *********************************** */


/*
 * packet socket options
 */
typedef struct ktq_mmc_s {
    void* priv;//Note: must be first member

	atomic_t		ref;
	/* Ring  page block */
	struct mutex	pg_vec_lock;
	spinlock_t		lock;
	struct ktq_pack_stats st_in; //from user-space
	struct ktq_pack_stats st_out; //to user-space
	wait_queue_head_t waits;
	char **			pg_vec;
	unsigned int	head;
	unsigned int    frames_per_block;
	unsigned int	frame_size;
	unsigned int	frame_max;

	unsigned int    pg_vec_order;
	unsigned int	pg_vec_pages;
	unsigned int	pg_vec_len;
}ktq_mmc_t;


void ktq_mmc_init(void);
void ktq_mmc_exit(void);
const char* ktq_mmc_name(void);
int ktq_mmc_get_stats(struct ktq_pack_stats* st_in,
				struct ktq_pack_stats* st_out);

#endif /* KTQ_MM_CDEV_H */
