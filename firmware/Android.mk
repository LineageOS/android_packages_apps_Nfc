
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
$(shell mkdir -p $(TARGET_OUT)/vendor/firmware)
LOCAL_MODULE       := libpn553_fw.so
LOCAL_MODULE_TAGS  := optional eng
LOCAL_MODULE_CLASS := VENDOR
LOCAL_MODULE_PATH := $(TARGET_OUT)/vendor/firmware
LOCAL_SRC_FILES    := ./firmware/libpn553_fw.so

include $(BUILD_PREBUILT)

