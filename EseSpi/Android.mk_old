LOCAL_PATH:= $(call my-dir)

########################################
# SPI Configuration
########################################
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_STATIC_JAVA_LIBRARIES := guava 

# Only compile source java files in this apk.
LOCAL_SRC_FILES := $(call all-java-files-under, src)

LOCAL_CERTIFICATE := platform

LOCAL_PACKAGE_NAME := EseSpi

LOCAL_REQUIRED_MODULES := libese_spi_jni

#LOCAL_SDK_VERSION := current

include $(BUILD_PACKAGE)

include $(call all-makefiles-under,$(LOCAL_PATH))
