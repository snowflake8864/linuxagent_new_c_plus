# 声明模块名称
MODULE_NAME :=test
# 声明内核源码路径
KERNEL_SOURCE := /lib/modules/$(shell uname -r)/build
# 声明模块源文件
SRC := zcopy.c
# 声明编译标志
EXTRA_CFLAGS += -Wall
# 构建模块
#obj-m += $(MODULE_NAME).o
obj-m +=zcopy.o
# 指定源文件
$(MODULE_NAME)-y := $(SRC)
# all 是默认的目标，即直接执行 make 命令时的目标
all:
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) modules
# 清理生成的文件
clean:
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) clean
