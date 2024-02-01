/*
 *khf_memcache.h: 2019-06-07 created by qudreams
 *a wrapper for kernel slab cache
 *khf is a short name for kernel hook frame
 */
#ifndef KHF_MEM_CACHE_H
#define KHF_MEM_CACHE_H

#include <linux/slab.h>

struct kmem_cache *khf_mem_cache_create(const char* name,size_t size, size_t align);
#define khf_mem_cache_destroy kmem_cache_destroy
#define khf_mem_cache_zalloc kmem_cache_zalloc
#define khf_mem_cache_free   kmem_cache_free

#endif
