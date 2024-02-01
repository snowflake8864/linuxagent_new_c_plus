CC=gcc
CXX=g++
AR=ar
DEBUG=1

###########################################################
CPPFLAGS += -D__OSECVERSION__="\"${VER}\""
CPPFLAGS += -D__REVISION__="\"${REVISION}\""
CPPFLAGS += -Werror -Wno-deprecated-declarations -fPIC -pthread

ifeq ($(DEBUG), 1)
    CPPFLAGS += -g3 -ggdb3 -DDEBUG
else
    CPPFLAGS += -g3 -O3 -Os -DNDEBUG
endif

###########################################################
COMMONDIR = ./
DEPENDLIBSDIR = ./dependlibs/
INCPATH += -I${COMMONDIR}/
INCPATH += -I${COMMONDIR}/../
INCPATH += -I${COMMONDIR}/dependlibs/
INCPATH += -I${COMMONDIR}/ASFramework/
INCPATH += -I${COMMONDIR}/socket
INCPATH += -I${DEPENDLIBSDIR}/minizip/
INCPATH += -I${DEPENDLIBSDIR}/libjsoncpp/include/
INCPATH += -I${DEPENDLIBSDIR}/libjsoncpp/include/jsoncpp/
INCPATH += -I${DEPENDLIBSDIR}/libcurl/include/
INCPATH += -I${DEPENDLIBSDIR}/libopenssl/include/
INCPATH += -I${DEPENDLIBSDIR}/libcares/include/
INCPATH += -I${DEPENDLIBSDIR}/sqlite3aes/

CPPFLAGS += $(INCPATH)
###########################################################
VERSION_OBJS = compile_info.o

ALL_OBJS += $(VERSION_OBJS)

COMMON_OBJS += ${COMMONDIR}/ASFramework/action/ASCmdAction.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/action/ASFileAction_linux.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/action/ASIpcAction.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/action/ASRunAction_linux.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/action/CActionFunc_linux.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/util/ASBase64.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/util/ASCodeHelper.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/util/ASLogImpl.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/util/ASPcInfo_unix.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/util/ASSysInfo_unix.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/util/ASTrustVerify_unix.o
COMMON_OBJS += ${COMMONDIR}/ASFramework/util/CStrCvt.o
COMMON_OBJS += ${COMMONDIR}/cpu_limit/cpu_limit_mgr.o
COMMON_OBJS += ${COMMONDIR}/cpu_limit/src/actor.o
COMMON_OBJS += ${COMMONDIR}/cpu_limit/src/cpu_limit.o
COMMON_OBJS += ${COMMONDIR}/cpu_limit/src/process.o
COMMON_OBJS += ${COMMONDIR}/debug/time_debug.o
COMMON_OBJS += ${COMMONDIR}/json/cJSON.o
COMMON_OBJS += ${COMMONDIR}/log/log.o
COMMON_OBJS += ${COMMONDIR}/pcinfo/pc_base_info.o
COMMON_OBJS += ${COMMONDIR}/pcinfo/system_info.o
COMMON_OBJS += ${COMMONDIR}/pcinfo/pc_soc_id.o
COMMON_OBJS += ${COMMONDIR}/pcinfo/hardwareinfo/dmidecode.o
COMMON_OBJS += ${COMMONDIR}/pcinfo/hardwareinfo/util.o
COMMON_OBJS += ${COMMONDIR}/qh_thread/multi_thread.o
COMMON_OBJS += ${COMMONDIR}/qh_thread/thread.o
COMMON_OBJS += ${COMMONDIR}/timer/timer.o
COMMON_OBJS += ${COMMONDIR}/utils/file_utils.o
COMMON_OBJS += ${COMMONDIR}/utils/net_utils.o
COMMON_OBJS += ${COMMONDIR}/utils/proc_info_utils.o
COMMON_OBJS += ${COMMONDIR}/utils/sqlite3_utils.o
COMMON_OBJS += ${COMMONDIR}/aes_coder.o
COMMON_OBJS += ${COMMONDIR}/deamon.o
COMMON_OBJS += ${COMMONDIR}/ini_parser.o
COMMON_OBJS += ${COMMONDIR}/md5sum.o
COMMON_OBJS += ${COMMONDIR}/openssl_thread_safe.o
COMMON_OBJS += ${COMMONDIR}/pid_file.o
COMMON_OBJS += ${COMMONDIR}/signal_handle.o
COMMON_OBJS += ${COMMONDIR}/uuid.o
COMMON_OBJS += ${COMMONDIR}/socket/socket_utils.o

ALL_OBJS += $(COMMON_OBJS)
###########################################################
.PHONY:all
all: $(ALL_OBJS)
	ar cr libcommon.a $(COMMON_OBJS)

###########################################################
.PHONY:clean
clean:
	rm -f $(ALL_OBJS)
