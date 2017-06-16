/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/******************************************************************************
 *
 *  The original Work has been changed by NXP Semiconductors.
 *
 *  Copyright (C) 2013-2014 NXP Semiconductors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#pragma once
#undef LOG_TAG
#define LOG_TAG "NxpEseJni"
#include <JNIHelp.h>
#include <jni.h>
#include <pthread.h>
#include <sys/queue.h>
#include <semaphore.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <cutils/log.h>



#define STATUS_SUCCESS    0x00
#define STATUS_FAILED     0x03
#define false 0
#define true 1

typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned long   UINT32;
typedef unsigned long long int UINT64;
typedef signed   long   INT32;
typedef signed   char   INT8;
typedef signed   short  INT16;
typedef unsigned char   BOOLEAN;

//default general trasceive timeout in millisecond
#define DEFAULT_GENERAL_TRANS_TIMEOUT  2000


struct ese_jni_native_data
{
   /* Thread handle */
   pthread_t thread;
   int running;

   /* Our VM */
   JavaVM *vm;
   jobject manager;

};

class ScopedAttach
{
public:
    ScopedAttach(JavaVM* vm, JNIEnv** env) : vm_(vm)
    {
#if(NXP_ESE_CHIP_TYPE == P73)
        isAttached = false;
        if(0 == vm_->GetEnv((void **) env, JNI_VERSION_1_6))
        {
          ALOGD ("%s: Already attached, so don't detach", __FUNCTION__);
          isAttached = true;
        }
        else
        {
          ALOGD ("%s: Unattached, so attach then detach", __FUNCTION__);
        }
#endif
        vm_->AttachCurrentThread(env, NULL);
    }

    ~ScopedAttach()
    {
#if(NXP_ESE_CHIP_TYPE == P73)
        if(false == isAttached)
        {
          ALOGD ("%s: Detaching", __FUNCTION__);
          vm_->DetachCurrentThread();
        }
#elif(NXP_ESE_CHIP_TYPE == P61)
        vm_->DetachCurrentThread();
#endif
    }

private:
        JavaVM* vm_;
#if(NXP_ESE_CHIP_TYPE == P73)
        BOOLEAN isAttached;
#endif
};


extern "C"
{
    jint JNI_OnLoad(JavaVM *jvm, void *reserved);
}

namespace android
{
    int register_com_android_ese_NativeEseManager(JNIEnv* env);
    int register_com_android_ese_NativeEseAla(JNIEnv* env);
} // namespace android
