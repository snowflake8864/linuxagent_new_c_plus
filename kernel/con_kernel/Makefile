
.PHONY: all clean

DEBUG = 0
VER = 2.0.0.4685
PWD = $(shell pwd)
KHFDIR=hookframe
KHF_MKF=$(KHFDIR)/Makefile.in

ifeq ($(KVER), )
	KVER = $(shell uname -r)
endif

ifeq ($(KPATH), )
	KPATH = /lib/modules/$(KVER)/build
else
	segments := $(patsubst %/build,%,$(KPATH))
	KVER = $(lastword $(subst /, ,$(segments)))
endif
ifeq ($(MACHINE), )
	MACHINE = $(shell uname -m)
endif

NOW_TIME = $(shell date +'%Y-%m-%d %H:%M:%S %Z')

EXTRA_CFLAGS := -DDEVICE_VERSION="\"${VER}\""
EXTRA_CFLAGS += -DDEBUG_FLAG
EXTRA_CFLAGS += -DBUILD_TIME="\"${NOW_TIME}\""
EXTRA_CFLAGS += -DCOMPILER="\"${CC}\""
EXTRA_CFLAGS += -I$(src)/
EXTRA_CFLAGS += -I$(src)/$(KHFDIR)/
EXTRA_CFLAGS += -I$(src)/../common/kernel/

ifeq ($(DEBUG), 1)
	EXTRA_CFLAGS += -DDEBUG=1
endif


#指定模块名
KO_NAME := osec_base
ifneq ($(NAME), )
	KO_NAME := $(NAME)
endif


EXTRA_CFLAGS += -pie -Wno-multichar
EXTRA_CFLAGS += $(PC_DEFINE)


tq_kernel-objs += main.o
tq_kernel-objs += stack/stack.o

include abnormal/Makefile.in
include kthread/Makefile.in
include hook/Makefile.in
include notify/Makefile.in
include utils/Makefile.in
include core/Makefile.in
include clientexit/Makefile.in
include netlink/Makefile.in
include cdev/Makefile.in
include sysfs/Makefile.in
include fs/Makefile.in
include defense/Makefile.in
include acsm/Makefile.in
include dpi/Makefile.in
include rules/Makefile.in
include iptree/Makefile.in

include $(KHF_MKF)

$(KO_NAME)-objs = $(tq_kernel-objs) $(khf_kernel-objs) 
obj-m += $(KO_NAME).o

JOBS=-j$(shell awk 'BEGIN{print ('2'*'$(shell nproc)')}')

all:
	# -make $(JOBS) -C ad_fake/
	echo "$(KVER)"
	make $(JOBS) -I$(PWD) -C $(KPATH) M=$(PWD) modules
#针对内核有些符号未导出，驱动编译只报警告，用户现场加载不上，又得重新适配，
#拿到警告放在symbols.txt中，查找WARNING,有WARNING,直接当错误处理,scripts/mod/modpost的-w参数去掉，x86上面没有-s -w参数，其余平台无影响
	-rm symbols.txt
	-$(KPATH)/scripts/mod/modpost -m -a -i $(KPATH)/Module.symvers -I $(PWD)/Module.symvers  -o $(PWD)/Module.symvers   $(PWD)/$(KO_NAME).o 2>symbols.txt
	-awk '{print $0}' $(PWD)/symbols.txt
	a=`awk '{print $0}' $(PWD)/symbols.txt  | grep "undefined" | grep -v "module_layout" | grep -v "struct_module" |wc -l`;echo $${a};\
	if [ $${a} -gt 0 ];\
	then\
        echo "kernel Symbol not exported";\
        exit 1;\
	fi
	-strip --strip-debug $(KO_NAME).ko
	#-cp $(KO_NAME).ko $(KO_NAME).ko_$(KVER)
	-nm $(KO_NAME).ko | awk '{if ($$2 == "t" || $$2 == "b" || $$2 == "d" || $$2 == "r") {print $$3}}' | egrep -v '^\..*' > static.txt
	-nm $(KO_NAME).ko | awk '{if ($$2 == "B" || $$2 == "T" || $$2 == "D" || $$2 == "R") {print $$3}}' | egrep -v '^\..*' | xargs -I {} bash -c 'printf {}" ";echo {} | md5sum | egrep -o "^.{16}" | head -n 1' | awk '{print $$1" "$$2}' > syms.txt
#驱动加密,去除符号时,做了出错处理,加密成功,生成目标加密驱动osec_tq_base.ko_xxx
#如果判断目标文件osec_tq_base.ko_xxx文件不存在,加密失败,错误处理,再加密
#在Ubuntu10.10-2.6.35-22-server上,trace_kmalloc等几个符号去除报错,对这几个符号不再去除
	-objcopy --strip-symbols=static.txt --redefine-syms=syms.txt $(KO_NAME).ko $(KO_NAME).ko-$(KVER) 2>errors.txt
	-if [ ! -f $(PWD)/$(KO_NAME).ko-$(KVER) ];\
	then\
		echo "$(KO_NAME).ko-$(KVER) Encryption failed,again";\
		awk -F '`' '{print $$2}'  $(PWD)/errors.txt | awk -F "'" '{print $$1'} | xargs -I {} sed -r -i 's/^{}$///g' static.txt ;\
		objcopy --strip-symbols=static.txt --redefine-syms=syms.txt $(KO_NAME).ko $(KO_NAME).ko-$(KVER);\
	else\
		echo "$(KO_NAME).ko-$(KVER) Encrypted successfully";\
	fi
	-rm static.txt syms.txt errors.txt symbols.txt
clean:
	# -make -C ad_fake/ clean
	make -I$(PWD) -C $(KPATH) M=$(PWD) clean
	-rm -f $(KO_NAME).ko-$(KVER)
