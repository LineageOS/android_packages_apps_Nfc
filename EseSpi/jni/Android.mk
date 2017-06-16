LOCAL_PATH:= $(call my-dir)


include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

# This is the target being built.
LOCAL_MODULE:= libese_spi_jni

#Select NXP_ESE_CHIP_TYPE
P61 := 1
P73 := 2
LOCAL_CFLAGS += -DNXP_LDR_SVC_VER_2
LOCAL_CFLAGS += -DP61=$(P61)
LOCAL_CFLAGS += -DP73=$(P73)
NXP_ESE_CHIP_TYPE = $(P61)
LOCAL_CFLAGS += -DNXP_ESE_CHIP_TYPE=$(NXP_ESE_CHIP_TYPE)

# Set ESE_DEBUG_UTILS_INCLUDED TRUE to enable debug utils
ESE_DEBUG_UTILS_INCLUDED := TRUE
ifeq ($(ESE_DEBUG_UTILS_INCLUDED), TRUE)
LOCAL_CFLAGS += -Wall -Wextra -DESE_DEBUG_UTILS_INCLUDED
#LOCAL_SRC_FILES := /utils/phNxpConfig.cpp
else
LOCAL_CFLAGS += -Wall -Wextra
endif
# All of the source files that we will compile.
LOCAL_SRC_FILES += NativeEseManager.cpp \
    NativeEseAla.cpp \
    SpiJniUtil.cpp \
    SpiChannel.cpp \
    Mutex.cpp \
    CondVar.cpp


# Also need the JNI headers.
LOCAL_C_INCLUDES += \
    libcore/include \
    frameworks/native/include \
    external/p61-jcop-kit/inc \
    external/p61-jcop-kit/include
ifeq ($(NXP_ESE_CHIP_TYPE),$(P73))
LOCAL_C_INCLUDES += \
    external/libese-spi/p73/inc \
    external/libese-spi/p73/common \
    external/libese-spi/p73/include\
    external/libese-spi/p73/pal\
    external/libese-spi/p73/utils
else ifeq ($(NXP_ESE_CHIP_TYPE),$(P61))
LOCAL_C_INCLUDES += \
    external/libese-spi/p61/inc \
    external/libese-spi/p61/common\
    external/libese-spi/p61/utils 
endif
    
LOCAL_SHARED_LIBRARIES := \
    libicuuc \
    libnativehelper \
    libcutils \
    libutils \
    libese-spi \
    libp61-jcop-kit


#### Select the JCOP OS Version ####
JCOP_VER_3_0 := 1
JCOP_VER_3_1_1 := 2
JCOP_VER_3_1_2 := 3
JCOP_VER_3_2 := 4
JCOP_VER_3_3 := 5
JCOP_VER_4_0 := 6

LOCAL_CFLAGS += -DJCOP_VER_3_0=$(JCOP_VER_3_0)
LOCAL_CFLAGS += -DJCOP_VER_3_1_1=$(JCOP_VER_3_1_1)
LOCAL_CFLAGS += -DJCOP_VER_3_1_2=$(JCOP_VER_3_1_2)
LOCAL_CFLAGS += -DJCOP_VER_3_2=$(JCOP_VER_3_2)
LOCAL_CFLAGS += -DJCOP_VER_3_3=$(JCOP_VER_3_3)
LOCAL_CFLAGS += -DJCOP_VER_4_0=$(JCOP_VER_4_0)

LOCAL_CFLAGS += -DNFC_NXP_ESE_VER=$(JCOP_VER_4_0)

#LOCAL_CFLAGS += -DISO7816_4_APDU_PARSER_ENABLE
include $(BUILD_SHARED_LIBRARY)
