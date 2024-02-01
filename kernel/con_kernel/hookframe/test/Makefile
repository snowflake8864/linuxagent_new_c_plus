
.PHONY: all clean

DEBUG = 0
PWD := $(shell pwd)
PDIR := $(shell realpath $(PWD)/../)
VER := 1.0.0.0000

ifeq ($(KVER), )
	KVER = $(shell uname -r)
endif

ifeq ($(KPATH), )
	KPATH = /lib/modules/$(KVER)/build
endif

ifeq ($(MACHINE), )
	MACHINE = $(shell uname -m)
endif

#指定模块名
KO_NAME := khookframe
ifneq ($(NAME), )
	KO_NAME := $(NAME)
endif

NOW_TIME = $(shell date +'%Y-%m-%d %H:%M:%S %Z')

EXTRA_CFLAGS := -DDEVICE_VERSION="\"${VER}\""
#全局debug_flag标识,用于控制在运行时开启debug日志
#EXTRA_CFLAGS += -DDEBUG_FLAG
EXTRA_CFLAGS += -DKMOD_NAME="\"${KO_NAME}\""
EXTRA_CFLAGS += -DBUILD_TIME="\"${NOW_TIME}\""
EXTRA_CFLAGS += -DCOMPILER="\"${CC}\""
# EXTRA_CFLAGS += -I$(PWD)/
EXTRA_CFLAGS += -I$(src)/../

ifeq ($(DEBUG), 1)
	EXTRA_CFLAGS += -DDEBUG=1
endif

EXTRA_CFLAGS += -Wno-multichar
EXTRA_CFLAGS += $(PC_DEFINE)


khf_kernel-objs += main.o
khf_test-objs += fake_test.o 
khf_test-objs += syscall_test.o 
#khf_test-objs += sysfs_test.o 

khf-objs += ../hook/khf_hook.o 

khf-objs += ../hook/ksyscall_hook.o 
khf-objs +=  ../hook/hook_ksyms.o 
khf-objs +=  ../hook/sysmap.o
khf-objs +=  ../hook/syscall_name.o
khf-objs +=  ../hook/arch/hook_arch.o

khf_core-objs += ../core/khf_version.o 
khf_core-objs += ../core/hook_ops.o
khf_core-objs += ../core/khf_blm.o
khf_core-objs += ../core/khf_memcache.o 
khf_core-objs += ../core/khf_syscalls.o 
khf_core-objs += ../core/khf_core.o 
khf_core-objs += ../core/khookframe.o 


khf_lsm-objs += ../lsm/khf_lsm.o
khf_exec-objs += ../exec/exec_fake.o

khf_kernel-objs += $(khf-objs)
khf_kernel-objs += $(khf_test-objs)

khf_kernel-objs += $(khf_lsm-objs)
khf_kernel-objs += $(khf_core-objs)
khf_kernel-objs += $(khf_sysfs-objs)

khf_kernel-objs += $(khf_lsm-objs)
khf_kernel-objs += $(khf_exec-objs)
khf_kernel-objs += $(khf_fs-objs)

$(KO_NAME)-objs = $(khf_kernel-objs)
obj-m += $(KO_NAME).o

all:
	make -C $(KPATH) M=$(PWD) modules
	-strip --strip-debug $(KO_NAME).ko
	-mv $(KO_NAME).ko $(KO_NAME).ko_$(KVER)
clean:
	make -C $(KPATH) M=$(PWD) clean
	-rm -f $(KO_NAME).ko_$(KVER)
	-find ../ -name '*.o' -o -name '*.cmd' | xargs rm -f

