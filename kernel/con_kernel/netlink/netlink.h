/*
 *netlink.h: 2019-07-04 created by qudreams
 *process netlink message for skylar kernel
 */
#ifndef NET_LINK_H
#define NET_LINK_H

int init_netlink(int protocol);
void uninit_netlink(void);

int get_netlink_group(void);

struct ktq_pack_stats;
int ktq_netlink_get_stats(struct ktq_pack_stats* st_in,
					struct ktq_pack_stats* st_out);

#endif
