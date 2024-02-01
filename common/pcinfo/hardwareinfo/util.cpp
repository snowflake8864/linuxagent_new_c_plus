/*
 * Common "util" functions
 * This file is part of the dmidecode project.
 *
 *   Copyright (C) 2002-2010 Jean Delvare <khali@linux-fr>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 *   For the avoidance of doubt the "preferred form" of this code is one which
 *   is in an open unpatent encumbered format. Where cryptographic key signing
 *   forms part of the process of creating an executable the information
 *   including keys needed to generate an equivalently functional executable
 *   are deemed to be part of the source code.
 */

#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"

#ifdef USE_MMAP
#include <sys/mman.h>
#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif /* !MAP_FAILED */
#endif /* USE MMAP */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "types.h"
#include "util.h"

static int myread(int fd, u8 *buf, size_t count, const char *prefix) {
    ssize_t r = 1;
    size_t r2 = 0;

    while (r2 != count && r != 0) {
        r = read(fd, buf + r2, count - r2);
        if (r == -1) {
            if (errno != EINTR) {
                close(fd);
                perror(prefix);
                return -1;
            }
        } else
            r2 += r;
    }

    if (r2 != count) {
        close(fd);
        fprintf(stderr, "%s: Unexpected end of file\n", prefix);
        return -1;
    }

    return 0;
}

int checksum(const u8 *buf, size_t len) {
    u8 sum = 0;
    size_t a;

    for (a = 0; a < len; a++) sum += buf[a];
    return (sum == 0);
}

/*
 * Copy a physical memory chunk into a memory buffer.
 * This function allocates memory.
 */
void *mem_chunk(size_t base, size_t len, const char *devmem) {
    void *p;
    int fd;
#ifdef USE_MMAP
    size_t mmoffset;
    void *mmp;
#endif

    if ((fd = open(devmem, O_RDONLY)) == -1) {
        perror(devmem);
        return NULL;
    }

    if ((p = malloc(len)) == NULL) {
        perror("malloc");
        return NULL;
    }

#ifdef USE_MMAP
#ifdef _SC_PAGESIZE
    mmoffset = base % sysconf(_SC_PAGESIZE);
#else
    mmoffset = base % getpagesize();
#endif /* _SC_PAGESIZE */
       /*
        * Please note that we don't use mmap() for performance reasons here,
        * but to workaround problems many people encountered when trying
        * to read from /dev/mem using regular read() calls.
        */
    mmp = mmap(0, mmoffset + len, PROT_READ, MAP_SHARED, fd, base - mmoffset);
    if (mmp == MAP_FAILED) goto try_read;

    memcpy(p, (u8 *)mmp + mmoffset, len);

    if (munmap(mmp, mmoffset + len) == -1) {
        fprintf(stderr, "%s: ", devmem);
        perror("munmap");
    }

    goto out;

#endif /* USE_MMAP */

try_read:
    if (lseek(fd, base, SEEK_SET) == -1) {
        fprintf(stderr, "%s: ", devmem);
        perror("lseek");
        free(p);
        return NULL;
    }

    if (myread(fd, (u8 *)p, len, devmem) == -1) {
        free(p);
        return NULL;
    }

out:
    if (close(fd) == -1) perror(devmem);

    return p;
}

/* Returns end - start + 1, assuming start < end */
u64 u64_range(u64 start, u64 end) {
    u64 res;

    res.h = end.h - start.h;
    res.l = end.l - start.l;

    if (end.l < start.l) res.h--;
    if (++res.l == 0) res.h++;

    return res;
}

struct type_keyword {
    const char *keyword;
    const u8 *type;
};

static const u8 opt_type_bios[] = {0, 13, 255};
static const u8 opt_type_system[] = {1, 12, 15, 23, 32, 255};
static const u8 opt_type_baseboard[] = {2, 10, 41, 255};
static const u8 opt_type_chassis[] = {3, 255};
static const u8 opt_type_processor[] = {4, 255};
static const u8 opt_type_memory[] = {5, 6, 16, 17, 255};
static const u8 opt_type_cache[] = {7, 255};
static const u8 opt_type_connector[] = {8, 255};
static const u8 opt_type_slot[] = {9, 255};

static const struct type_keyword opt_type_keyword[] = {
    {"bios", opt_type_bios},           {"system", opt_type_system},
    {"baseboard", opt_type_baseboard}, {"chassis", opt_type_chassis},
    {"processor", opt_type_processor}, {"memory", opt_type_memory},
    {"cache", opt_type_cache},         {"connector", opt_type_connector},
    {"slot", opt_type_slot},
};

int IsProcessorType(const u8 type) {
    size_t i = 0;
    size_t sz = sizeof(opt_type_processor) / sizeof(opt_type_processor[0]);
    for (i = 0; i < sz; i++) {
        if (opt_type_processor[i] == type) {
            return 1;
        }
    }

    return 0;
}

int IsMemoryType(const u8 type) {
    size_t i = 0;
    size_t sz = sizeof(opt_type_memory) / sizeof(opt_type_memory[0]);
    for (i = 0; i < sz; i++) {
        if (opt_type_memory[i] == type) {
            return 1;
        }
    }

    return 0;
}

int IsBiosType(const u8 type) {
    size_t i = 0;
    size_t sz = sizeof(opt_type_bios) / sizeof(opt_type_bios[0]);
    for (i = 0; i < sz; i++) {
        if (opt_type_bios[i] == type) {
            return 1;
        }
    }

    return 0;
}

int IsBaseBoardType(const u8 type) {
    size_t i = 0;
    size_t sz = sizeof(opt_type_baseboard) / sizeof(opt_type_baseboard[0]);
    for (i = 0; i < sz; i++) {
        if (opt_type_baseboard[i] == type) {
            return 1;
        }
    }

    return 0;
}

int IsSystemType(const u8 type) {
    size_t i = 0;
    size_t sz = sizeof(opt_type_system) / sizeof(opt_type_system[0]);
    for (i = 0; i < sz; i++) {
        if (opt_type_system[i] == type) {
            return 1;
        }
    }

    return 0;
}
