#include <sys/types.h>
#include "types.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

int checksum(const u8 *buf, size_t len);
void *mem_chunk(size_t base, size_t len, const char *devmem);
u64 u64_range(u64 start, u64 end);
int IsMemoryType(const u8 type);
int IsBiosType(const u8 type);
int IsBaseBoardType(const u8 type);
int IsSystemType(const u8 type);
int IsProcessorType(const u8 type);
