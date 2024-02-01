#ifndef KTQ_MD5_H
#define KTQ_MD5_H

#include <linux/types.h>

typedef struct {
	uint64_t bytes;
	uint32_t a, b, c, d;
	u_char buffer[64];
} ktq_md5_t;

void ktq_md5_init(ktq_md5_t *ctx);
void ktq_md5_update(ktq_md5_t *ctx, const void *data, size_t size);
void ktq_md5_final(u_char result[16], ktq_md5_t *ctx);
/*
 *计算数据的MD5值，计算出来的MD5值不转化为16进制
 */
void ktq_md5_data(u_char *md5, const void *data, u_int len);

#endif