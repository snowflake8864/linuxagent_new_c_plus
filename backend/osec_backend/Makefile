DEBUG=0
STATIC=0
CC=gcc
CXX=g++
ARCH=$(shell uname -m)
LOW_VERSION_UDEV=0

###########################################################
#CPPFLAGS += -Werror
CPPFLAGS += -Wno-deprecated-declarations
CPPFLAGS += -fPIC -Wall

ifeq ($(DEBUG), 1)
	CPPFLAGS += -g3 -ggdb3 -DDEBUG
else
	CPPFLAGS += -g3 -O3 -Os -DNDEBUG
endif
ifeq ($(LOW_VERSION_UDEV), 1)
	CPPFLAGS += -DLOW_VERSION_UDEV -ludev
endif


###########################################################
###########################################################
ROOTDIR = ../../

###########################################################
INCPATH += -I${ROOTDIR}/
INCPATH += -I${ROOTDIR}/net_agent/
INCPATH += -I${ROOTDIR}/backend/
INCPATH += -I${ROOTDIR}/common
INCPATH += -I${ROOTDIR}/common/ASFramework
# INCPATH += -I${ROOTDIR}/common/dependlibs/libudev/include/
# INCPATH += -I${ROOTDIR}/common/dependlibs/libjsoncpp/include/
# INCPATH += -I${ROOTDIR}/common/dependlibs/libopenssl/include/
# INCPATH += -I${ROOTDIR}/common/dependlibs/libjsoncpp/include/
# INCPATH += -I${ROOTDIR}/common/dependlibs/libjsoncpp/include/jsoncpp

INCPATH += -I${ROOTDIR}/common/dependlibs/Ubuntu_curl/include/
ifeq ($(LOW_VERSION_UDEV), 1)
INCPATH += -I${ROOTDIR}/common/dependlibs/com_udev/include/
else
INCPATH += -I${ROOTDIR}/common/dependlibs/Ubuntu_udev/include/
endif
INCPATH += -I${ROOTDIR}/common/dependlibs/Ubuntu_jsoncpp/include/
INCPATH += -I${ROOTDIR}/common/dependlibs/Ubuntu_openssl/include/
INCPATH += -I${ROOTDIR}/common/dependlibs/Ubuntu_jsoncpp/include/jsoncpp
INCPATH += -I${ROOTDIR}/common/dependlibs/sqlite3aes
INCPATH += -I${ROOTDIR}/common/dependlibs/minizip
CPPFLAGS += $(INCPATH)

###########################################################
LIBS += -Wl,--as-needed

LIBDIR = none

LIBS += ${ROOTDIR}/common/libcommon.a
LIBS += ${ROOTDIR}/common/dependlibs/Ubuntu_curl/lib/libcurl.a
LIBS += ${ROOTDIR}/common/dependlibs/Ubuntu_cares/lib/libcares.a
LIBS += ${ROOTDIR}/common/dependlibs/Ubuntu_openssl/lib/libssl.a
LIBS += ${ROOTDIR}/common/dependlibs/Ubuntu_openssl/lib/libcrypto.a
LIBS += ${ROOTDIR}/common/dependlibs/minizip/libminizip.a
LIBS += ${ROOTDIR}/common/dependlibs/sqlite3aes/libsqlite3.a
LIBS += ${ROOTDIR}/common/dependlibs/Ubuntu_jsoncpp/libjsoncpp.a
ifeq ($(LOW_VERSION_UDEV), 0)
LIBS += ${ROOTDIR}/common/dependlibs/Ubuntu_udev/lib/libudev.a
else
LIBS += -L/opt/osec/libudev.so
endif

#LIBS += ${ROOTDIR}/common/dependlibs/libcurl/lib/libcurl.a
#LIBS += ${ROOTDIR}/common/dependlibs/libcares/lib/libcares.a
#LIBS += ${ROOTDIR}/common/dependlibs/libopenssl/lib/libssl.a
#LIBS += ${ROOTDIR}/common/dependlibs/libopenssl/lib/libcrypto.a
#LIBS += ${ROOTDIR}/common/dependlibs/minizip/libminizip.a
#LIBS += ${ROOTDIR}/common/dependlibs/sqlite3aes/libsqlite3.a
#LIBS += ${ROOTDIR}/common/dependlibs/libjsoncpp/libjsoncpp.a
#LIBS += ${ROOTDIR}/common/dependlibs/libudev/lib/libudev.a

LIBS += -lrt -lpthread -ldl -lz

ifeq ($(STATIC), 1)
	LIBS += -static-libgcc
endif

###########################################################

OSEC_COMMON_OBJS += ${ROOTDIR}/osec_common/osec_pathmanager.o
OSEC_COMMON_OBJS += ${ROOTDIR}/osec_common/osec_socket_utils.o
OSEC_COMMON_OBJS += ${ROOTDIR}/osec_common/log_helper.o

NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/net_status.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/policy_recv.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/ent_client_net_agent.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/data_operation/build_json.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/data_operation/parse_json.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/procInfo.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/procRes.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/BrowseDir_linux.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/dir_info.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/cpuinfo.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/meminfo.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/performance.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/net_mgr/port_mgr.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/net_mgr/net_mgr.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/net_mgr/netstate.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/device_mgr/udisk_monitor_mgr.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/netlog_mgr.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/netlog_mgr_db.o
#NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/sshguard.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/system_login.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/zcopy_mgr.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/conn_block_mgr.o
NET_AGENT_OBJS += ${ROOTDIR}/backend/net_agent/pattern_rules_mgr.o
COMMON_OBJS += $(OSEC_COMMON_OBJS)


OSEC_GN_OBJS += main.o label_mgr.o kernel_event_handler.o backend_mgr.o report_mgr.o report_db_helper.o CPidFile.o CSimpleMonitor.o thread_proc.o process_md5_mgr.o thread_open_port.o
OSEC_MONITOR_OBJS += main_monitor.o CSimpleMonitor.o  CPidFile.o
OSEC_TEST_OBJS += test.o ${ROOTDIR}/backend/net_agent/BrowseDir_linux.o  ${ROOTDIR}/backend/net_agent/dir_info.o

TARGET_OBJS += $(OSEC_GN_OBJS) $(COMMON_OBJS) $(NET_AGENT_OBJS)
TARGET_MONITOR_OBJS += $(OSEC_MONITOR_OBJS) $(COMMON_OBJS)
TEST_OBJS += $(OSEC_TEST_OBJS) $(COMMON_OBJS)
###########################################################

TARGET: $(TARGET_OBJS)  $(TARGET_MONITOR_OBJS) $(TEST_OBJS)
ifeq ($(LOW_VERSION_UDEV), 1)
	$(CXX) $(CPPFLAGS) -o ${ROOTDIR}/backend/MagicArmor_Centos6 $(TARGET_OBJS) $(LIBS) 
else
	$(CXX) $(CPPFLAGS) -o ${ROOTDIR}/backend/MagicArmor_0 $(TARGET_OBJS) $(LIBS) 
endif
#	$(CXX) $(CPPFLAGS) -o ${ROOTDIR}/backend/MagicArmor_1 $(TARGET_MONITOR_OBJS) $(LIBS)
#	$(CXX) -o ${ROOTDIR}/backend/MagicArmor_2 ${ROOTDIR}/backend/osec_backend/osec_main.cpp
#	$(CXX) $(CPPFLAGS) -o ${ROOTDIR}/backend/test $(TEST_OBJS) $(LIBS) 

.PHONY:all
all: $(TARGET)


.PHONY:clean distclean
clean: 
	rm -f $(TARGET_OBJS)
ifeq ($(LOW_VERSION_UDEV), 1)
	rm -f ${ROOTDIR}/backend/MagicArmor_Centos6 
else
	rm -f ${ROOTDIR}/backend/MagicArmor_0 
endif

distclean:
	rm -f $(TARGET_OBJS)
	rm -f ${ROOTDIR}/backend/MagicArmor_1
	rn -f ${ROOTDIR}/backend/test
###########################################################
