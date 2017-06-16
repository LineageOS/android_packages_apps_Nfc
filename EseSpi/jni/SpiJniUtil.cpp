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

#include "SpiJniUtil.h"

#include <cutils/log.h>
#include <errno.h>
#include <JNIHelp.h>


/*******************************************************************************
**
** Function:        JNI_OnLoad
**
** Description:     Register all JNI functions with Java Virtual Machine.
**                  jvm: Java Virtual Machine.
**                  reserved: Not used.
**
** Returns:         JNI version.
**
*******************************************************************************/
jint JNI_OnLoad (JavaVM *jvm, void *reserved)
{
    (void)reserved;
    ALOGD ("%s: enter", __FUNCTION__);
    JNIEnv *e = NULL;

    ALOGI("SPI Service: loading SPI JNI");

    // Check JNI version
    if (jvm->GetEnv ((void **) &e, JNI_VERSION_1_6))
    {
        ALOGE ("%s: GET_ENV failed", __FUNCTION__);
        return JNI_ERR;
    }

    if (android::register_com_android_ese_NativeEseManager(e) == -1) {
        ALOGE("ERROR: registerNatives failed\n");
        return JNI_ERR;
    }
    if(android::register_com_android_ese_NativeEseAla(e) == -1)
    {
        ALOGE("ERROR: registerNativeEseAla failed\n");
        return JNI_ERR;
    }
    ALOGD ("%s: exit", __FUNCTION__);
    return JNI_VERSION_1_6;
}
