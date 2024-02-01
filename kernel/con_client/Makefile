DEBUG=0
TEST=0
STATIC=0
CC=gcc
CXX=g++
OSECMJBZ=1

CPPFLAGS+=-Wall -fPIC
CPPFLAGS += -ffunction-sections -fdata-sections -fvisibility=hidden -fno-strict-aliasing
CPPFLAGS += -fvisibility-inlines-hidden
LIBS += -Wl,--as-needed -Wl,-Bsymbolic -Wl,--gc-sections 
LIBS += -Wl,--hash-style=sysv
###########################################################

#这个地方是必须要有，不然程序会直接崩溃掉
#是因为编译成可执行程序时-shared这个编译标记导致的
ifeq ($(TEST),1)
	CPPFLAGS += -DTEST
else
	CPPFLAGS += -shared
endif

ifeq ($(DEBUG), 1)
	CPPFLAGS += -g3 -ggdb3 -DDEBUG
else
	CPPFLAGS += -g3 -O3 -Os -DNDEBUG
endif

ifneq ($(DRIVER_NAME), )
	CPPFLAGS += -DDRIVER_NAME="\"$(DRIVER_NAME)\""
endif

###########################################################

###########################################################
ROOTDIR = ../../

###########################################################
INCPATH += -I${ROOTDIR}/
INCPATH += -I${ROOTDIR}/common
INCPATH += -I${ROOTDIR}/common/ASFramework
INCPATH += -I${ROOTDIR}/common/kernel
INCPATH += -I${ROOTDIR}/common/dependlibs
INCPATH += -I${ROOTDIR}/common/dependlibs/libjsoncpp/include
INCPATH += -I${ROOTDIR}/common/dependlibs/libjsoncpp/include/jsoncpp
INCPATH += -I${ROOTDIR}/common/dependlibs/minizip
CPPFLAGS += $(INCPATH)

###########################################################
LIBS += -Wl,--as-needed
LIBDIR = none

LIBS += ${ROOTDIR}/common/dependlibs/minizip/libminizip.a
LIBS+=-lrt -lpthread -ldl -lz

ifeq ($(STATIC), 1)
	LIBS += -static-libgcc
endif

###########################################################
COMMON_OBJS += ${ROOTDIR}/common/ASFramework/util/ASLogImpl.o
COMMON_OBJS += ${ROOTDIR}/common/log/log.o
COMMON_OBJS += ${ROOTDIR}/common/utils/file_utils.o
COMMON_OBJS += ${ROOTDIR}/common/utils/proc_info_utils.o
COMMON_OBJS += ${ROOTDIR}/common/cpu_limit/cpu_limit_mgr.o
COMMON_OBJS += ${ROOTDIR}/common/cpu_limit/src/cpu_limit.o
COMMON_OBJS += ${ROOTDIR}/common/cpu_limit/src/process.o
COMMON_OBJS += ${ROOTDIR}/common/cpu_limit/src/actor.o
COMMON_OBJS += ${ROOTDIR}/common/ini_parser.o
COMMON_OBJS += ${ROOTDIR}/common/qh_thread/multi_thread.o
COMMON_OBJS += ${ROOTDIR}/common/qh_thread/thread.o
COMMON_OBJS += ${ROOTDIR}/common/json/cJSON.o

KCONNECTOR_OBJS += CKoHelper.o CKernelConnector.o CKernelMsg.o 
KCONNECTOR_OBJS += CKConnectorLog.o netlink_func.o epoll_func.o
KCONNECTOR_OBJS += CKCmdHandlers.o CKTransferProxy.o
KCONNECTOR_OBJS += cdev.o CKComm.o

TEST_CLIENT_OBJS+= test_client.o
TEST_KERN_OBJS += test.o netlink_func.o epoll_func.o CKComm.o
TEST_AV_OBJS += test_av.o netlink_func.o epoll_func.o CKComm.o


TARGET_OBJS += $(COMMON_OBJS) $(KCONNECTOR_OBJS)
###########################################################

.PHONY:all
all: libOsecKernel.so

libOsecKernel.so: $(TARGET_OBJS)
	$(CXX) $(CPPFLAGS) -o ${ROOTDIR}/kernel/con_client/libOsecKernel.so $(TARGET_OBJS) $(LIBS)


#编译测试用例前需要先将测试用例信赖的.o全部clean一下
#因为test_kern这个测试用例不想信赖日志b函数库代码
.PHONY:clean_test
clean_test:
	rm -f $(TEST_CLIENT_OBJS) 
	rm -f $(TEST_KERN_OBJS)
	rm -f $(TEST_AV_OBJS)

test_client: clean_test $(TEST_CLIENT_OBJS)
	$(CXX) $(CPPFLAGS) -o test_client $(TEST_CLIENT_OBJS) -ldl

test_kern: clean_test $(TEST_KERN_OBJS)
	$(CXX) $(CPPFLAGS) -o test_kern $(TEST_KERN_OBJS) -lpthread
	make clean_test

test_av: clean_test $(TEST_AV_OBJS)
	$(CXX) $(CPPFLAGS) -o test_av $(TEST_AV_OBJS) -lpthread
	make clean_test

SECDOC_TEST_OBJS += secdoctest.o
secdoctest:$(SECDOC_TEST_OBJS)
	$(CC) $(CFLAGS) -o secdoctest $(SECDOC_TEST_OBJS)

###########################################################


.PHONY:clean
clean:
	rm -f $(TARGET_OBJS) $(TEST_OBJS) $(SECDOC_TEST_OBJS)
	rm -f test_kern test_client secdoctest test_av
	rm -f ${ROOTDIR}/con_client/libOsecKernel.so

###########################################################
