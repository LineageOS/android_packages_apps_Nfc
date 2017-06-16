/*
 * Copyright (C) 2012-2014 NXP Semiconductors
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
#include "SpiJniUtil.h"
#include "SyncEvent.h"
#include "SpiChannel.h"
#include <ScopedPrimitiveArray.h>

extern "C"
{
    #include "AlaLib.h"
    #include "IChannel.h"
}
extern "C"
{
#if(NXP_ESE_CHIP_TYPE == P61)
#include "phNxpEseHal_Api.h"
#include "phNxpEseHal_Apdu.h"
#elif(NXP_ESE_CHIP_TYPE == P73)
#include "phNxpEse_Api.h"
#include "phNxpEse_Apdu_Api.h"
#else
#error "Define chip type macro"
#endif
#include "phNxpConfig.h"
}
#define LS_DEFAULT_VERSION 0x20
#define NAME_NXP_LOADER_SERICE_VERSION "NXP_LOADER_SERICE_VERSION"
namespace android
{

static bool sRfEnabled;
jbyteArray eSEManager_lsExecuteScript(JNIEnv* e, jobject o, jstring src, jstring dest, jbyteArray);
jbyteArray eSEManager_lsGetVersion(JNIEnv* e, jobject o);
int eSEManager_doAppletLoadApplet(JNIEnv* e, jobject o, jstring choice, jbyteArray);
int eSEManager_GetAppletsList(JNIEnv* e, jobject o, jobjectArray list);
jbyteArray eSEManager_GetCertificateKey(JNIEnv* e, jobject);
int eSEManager_getLSConfigVer(JNIEnv* e, jobject o);
const char    *gNativeNfcAlaClassName = "com/nxp/ese/dhimpl/NativeEseAla";
extern bool          gJcopDwnldinProgress;
extern IChannel_t Dwp;
extern bool Spichannel_init(IChannel_t *swp, seClient_t mHandle);
#ifndef NXP_LDR_SVC_VER_2
/*******************************************************************************
**
** Function:        eSEManager_GetListofApplets
**
** Description:     provides the list of applets present in the directory.
**                  e: JVM environment.
**                  o: Java object.
**
** Returns:         None.
**
*******************************************************************************/
int eSEManager_GetAppletsList(JNIEnv* e, jobject o, jobjectArray list)
{
    (void)e;
    (void)o;
    (void)list;
    char *name[10];
    UINT8 num =0, xx=0;
    UINT8 list_len = e->GetArrayLength(list);
    ALOGD ("%s: enter", __FUNCTION__);
    ALOGD("%s: list_len=0x%x", __FUNCTION__, list_len);
    ALA_GetlistofApplets(name, &num);

    if((num != 0) &&
       (list_len >= num))
    {
        while(num > 0)
        {
            jstring tmp = e->NewStringUTF(name[xx]);
            e->SetObjectArrayElement(list, xx, tmp);
            if(name[xx] != NULL)
            {
                free(name[xx]);
            }
            xx++;
            num--;
        }
    }
    else
    {
        ALOGE("%s: No applets found",__FUNCTION__);
    }
    ALOGD ("%s: exit; num_applets =0x%X", __FUNCTION__,xx);
    return xx;
}

/*******************************************************************************
**
** Function:        eSEManager_doAppletLoadApplet
**
** Description:     start jcos download.
**                  e: JVM environment.
**                  o: Java object.
**                  name: path of the ALA script file located
**                  data: SHA encrypted package name
**
** Returns:         True if ok.
**
*******************************************************************************/

int eSEManager_doAppletLoadApplet(JNIEnv* e, jobject o, jstring name, jbyteArray data)
{
    (void)e;
    (void)o;
    (void)name;
    ALOGD ("%s: enter", __FUNCTION__);
    NFCSTATUS wStatus, status;
    IChannel_t Dwp;
    bool stat = false;
    const char *choice = NULL;
    if(Spichannel_init(&Dwp, LDR_SRVCE))
    {
        wStatus = ALA_Init(&Dwp);
        if(wStatus != STATUS_SUCCESS)
        {
            ALOGE("%s: ALA initialization failed", __FUNCTION__);
        }
        else
        {
            ALOGE("%s: start Applet load applet", __FUNCTION__);
            choice = e->GetStringUTFChars(name, 0);
            ALOGE("choice= %s", choice);
            ScopedByteArrayRO bytes(e, data);
            uint8_t* buf = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&bytes[0]));
            size_t bufLen = bytes.size();
            wStatus = ALA_Start(choice, buf, bufLen);
        }
        stat = ALA_DeInit();
        if(choice != NULL)
            e->ReleaseStringUTFChars(name, choice);
    }
    else
    {
        ALOGE("%s: Spi channel Already in use..", __FUNCTION__);
    }
    ALOGD ("%s: exit; status =0x%X", __FUNCTION__,wStatus);
    return wStatus;

}
#else
/*******************************************************************************
**
** Function:        eSEManager_lsExecuteScript
**
** Description:     start jcos download.
**                  e: JVM environment.
**                  o: Java object.
**                  name: path of the ALA script file located
**                  data: SHA encrypted package name
**
** Returns:         True if ok.
**
*******************************************************************************/
jbyteArray eSEManager_lsExecuteScript(JNIEnv* e, jobject o, jstring name, jstring dest, jbyteArray data)
{
    (void)e;
    (void)o;
    (void)name;
    (void)dest;
    const char *destpath = NULL;
    const UINT8 lsExecuteResponseSize = 4;
    uint8_t resSW [4]={0x4E, 0x02, 0x69, 0x87};
    jbyteArray result = e->NewByteArray(0);
    ALOGD ("%s: enter", __FUNCTION__);
    ESESTATUS wStatus, status;
    IChannel_t Dwp;
    bool stat = false;
    const char *choice = NULL;

    gJcopDwnldinProgress = true;
    if(Spichannel_init(&Dwp, LDR_SRVCE)!= true)
    {
        ALOGD ("%s: exit; Client already in-use status =0x%X", __FUNCTION__,wStatus);
        return result;
    }
    wStatus = ALA_Init(&Dwp);
    if(wStatus != STATUS_SUCCESS)
    {
        ALOGE("%s: ALA initialization failed", __FUNCTION__);
    }
    else
    {
        destpath = e->GetStringUTFChars(dest, 0);
        ALOGE("destpath= %s", destpath);
        ALOGE("%s: start Applet load applet", __FUNCTION__);
        choice = e->GetStringUTFChars(name, 0);
        ALOGE("choice= %s", choice);
        ScopedByteArrayRO bytes(e, data);
        uint8_t* buf = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&bytes[0]));
        size_t bufLen = bytes.size();
        wStatus = ALA_Start(choice,destpath, buf, bufLen,resSW);

       /*copy results back to java*/
       result = e->NewByteArray(lsExecuteResponseSize);
       if (result != NULL)
       {
           e->SetByteArrayRegion(result, 0, lsExecuteResponseSize, (jbyte *) resSW);
       }
    }

    stat = ALA_DeInit();
    gJcopDwnldinProgress = false;
    if(choice != NULL)
        e->ReleaseStringUTFChars(name, choice);


    ALOGD ("%s: exit; status =0x%X", __FUNCTION__,wStatus);
    return result;
}
#endif
#ifndef NXP_LDR_SVC_VER_2
/*******************************************************************************
**
** Function:        eSEManager_GetCertificateKey
**
** Description:     It is ued to get the reference certificate key
**                  e: JVM environment.
**                  o: Java object.
**
** Returns:         key value.
**
*******************************************************************************/

jbyteArray eSEManager_GetCertificateKey(JNIEnv* e, jobject)
{
    ALOGD ("%s: enter", __FUNCTION__);
    NFCSTATUS wStatus = STATUS_FAILED;
    IChannel_t Dwp;
    bool stat = false;
    const INT32 recvBufferMaxSize = 256;
    UINT8 recvBuffer [recvBufferMaxSize];
    INT32 recvBufferActualSize = 0;
    jbyteArray result = e->NewByteArray(0);

    if(Spichannel_init(&Dwp, LDR_SRVCE) != true)
    {
        ALOGD("%s: exit: recv len=%ld", __FUNCTION__, recvBufferActualSize);
        return result;
    }
    wStatus = ALA_Init(&Dwp);
    if(wStatus != STATUS_SUCCESS)
    {
        ALOGE("%s: ALA initialization failed", __FUNCTION__);
    }
    else
    {
        ALOGE("%s: start Get reference Certificate Key", __FUNCTION__);
        wStatus = ALA_GetCertificateKey(recvBuffer, &recvBufferActualSize);
    }

    /*copy results back to java*/
    result = e->NewByteArray(recvBufferActualSize);
    if (result != NULL)
    {
        e->SetByteArrayRegion(result, 0, recvBufferActualSize, (jbyte *) recvBuffer);
    }

    stat = ALA_DeInit();
    /*startRfDiscovery (true);*/

    ALOGD("%s: exit: recv len=%ld", __FUNCTION__, recvBufferActualSize);
    return result;
}
#else

/*******************************************************************************
**
** Function:        eSEManager_lsGetVersion
**
** Description:     It is ued to get version of Loader service client & Applet
**                  e: JVM environment.
**                  o: Java object.
**
** Returns:         version of Loder service.
**
*******************************************************************************/
jbyteArray eSEManager_lsGetVersion(JNIEnv* e, jobject)
{

    ALOGD ("%s: enter", __FUNCTION__);
    ESESTATUS wStatus = STATUS_FAILED;
    IChannel_t Dwp;
    bool stat = false;
    const INT32 recvBufferMaxSize = 4;
    UINT8 recvBuffer [recvBufferMaxSize];
    jbyteArray result = e->NewByteArray(0);

    if(Spichannel_init(&Dwp, LDR_SRVCE) != true)
    {
        ALOGD("%s: exit: recv len=%ld", __FUNCTION__, recvBufferMaxSize);
        return result;
    }
    wStatus = ALA_Init(&Dwp);
    gJcopDwnldinProgress = true;

    if(wStatus != STATUS_SUCCESS)
    {
        ALOGE("%s: ALA initialization failed", __FUNCTION__);
    }
    else
    {
        ALOGE("%s: start Get reference Certificate Key", __FUNCTION__);
        wStatus = ALA_lsGetVersion(recvBuffer);
    }
    gJcopDwnldinProgress = false;

    /*copy results back to java*/
    result = e->NewByteArray(recvBufferMaxSize);
    if (result != NULL)
    {
        e->SetByteArrayRegion(result, 0, recvBufferMaxSize, (jbyte *) recvBuffer);
    }

    stat = ALA_DeInit();

    ALOGD("%s: exit: recv len=%ld", __FUNCTION__, recvBufferMaxSize);
    return result;

}

/*******************************************************************************
**
** Function:        nfcManager_lsGetAppletStatus
**
** Description:     It is ued to get LS Applet status SUCCESS/FAIL
**                  e: JVM environment.
**                  o: Java object.
**
** Returns:         LS Previous execution Applet status .
**
*******************************************************************************/
jbyteArray eSEManager_lsGetAppletStatus(JNIEnv* e, jobject)
{

    ALOGD ("%s: enter", __FUNCTION__);
    ESESTATUS wStatus = STATUS_FAILED;
    bool stat = false;
    const INT32 recvBufferMaxSize = 2;
    UINT8 recvBuffer [recvBufferMaxSize]={0x63,0x40};
    IChannel_t Dwp;
    jbyteArray result = e->NewByteArray(0);

    if(Spichannel_init(&Dwp, LDR_SRVCE) != true)
    {
        ALOGD("%s: exit: recv len=%ld", __FUNCTION__, recvBufferMaxSize);
        return result;
    }
    wStatus = ALA_Init(&Dwp);
    if(wStatus != STATUS_SUCCESS)
    {
        ALOGE("%s: ALA initialization failed", __FUNCTION__);
    }
    else
    {
        gJcopDwnldinProgress = true;
        ALOGE("%s: start Get reference Certificate Key", __FUNCTION__);
        wStatus = ALA_lsGetAppletStatus(recvBuffer);
        gJcopDwnldinProgress = false;
    }

    ALOGD ("%s: lsGetAppletStatus values %x %x", __FUNCTION__, recvBuffer[0], recvBuffer[1]);
    //copy results back to java
    result = e->NewByteArray(recvBufferMaxSize);
    if (result != NULL)
    {
        e->SetByteArrayRegion(result, 0, recvBufferMaxSize, (jbyte *) recvBuffer);
    }
    stat = ALA_DeInit();

    ALOGD("%s: exit: recv len=%ld", __FUNCTION__, recvBufferMaxSize);

    return result;
}

/*******************************************************************************
**
** Function:        nfcManager_lsGetStatus
**
** Description:     It is ued to get LS Client status SUCCESS/FAIL
**                  e: JVM environment.
**                  o: Java object.
**
** Returns:         version of Loder service.
**
*******************************************************************************/
jbyteArray eSEManager_lsGetStatus(JNIEnv* e, jobject)
{

    ALOGD ("%s: enter", __FUNCTION__);
    ESESTATUS wStatus = STATUS_FAILED;
    const INT32 recvBufferMaxSize = 2;
    UINT8 recvBuffer [recvBufferMaxSize] = {0x63,0x40};

    wStatus = ALA_lsGetStatus(recvBuffer);

    ALOGD ("%s: lsGetStatus values %x %x", __FUNCTION__, recvBuffer[0], recvBuffer[1]);

    jbyteArray result = e->NewByteArray(recvBufferMaxSize);
    if (result != NULL)
    {
        e->SetByteArrayRegion(result, 0, recvBufferMaxSize, (jbyte *) recvBuffer);
    }
    ALOGD("%s: exit: recv len=%ld", __FUNCTION__, recvBufferMaxSize);
    return result;
}

#endif

/*******************************************************************************
**
** Function:        nfcManager_getLoaderServiceConfVersion
**
** Description:     Get current Loader service version from config file.
**                  e: JVM environment.
**                  o: Java object.
**
** Returns:         Void.
**
*******************************************************************************/
jint eSEManager_getLSConfigVer(JNIEnv* e, jobject o)
{
    unsigned long num = 0;
    jint ls_version = LS_DEFAULT_VERSION;
    ALOGD ("%s: enter", __FUNCTION__);
    if(GetNxpNumValue (NAME_NXP_LOADER_SERICE_VERSION, (void*)&num, sizeof(num))==false)
    {
        ALOGD ("LOADER_SERVICE_VERSION not found");
        num = 0;
    }
    /*If LS version exists in config file*/
    if(num != 0)
    {
        ls_version = (jint)num;
    }
    ALOGD ("%s: exit", __FUNCTION__);
    return ls_version;
}

/*****************************************************************************
 **
 ** Description:     JNI functions
 **
 *****************************************************************************/
static JNINativeMethod gMethods[] =
{
#ifdef NXP_LDR_SVC_VER_2
    {"doLsExecuteScript","(Ljava/lang/String;Ljava/lang/String;[B)[B",
                (void *)eSEManager_lsExecuteScript},
    {"doLsGetVersion","()[B",
                (void *)eSEManager_lsGetVersion},
    {"doLsGetStatus","()[B",
                 (void *)eSEManager_lsGetStatus},
    {"doLsGetAppletStatus","()[B",
                 (void *)eSEManager_lsGetAppletStatus},
    {"doGetLSConfigVersion", "()I",
                 (void*)eSEManager_getLSConfigVer}
#else
    {"GetAppletsList", "([Ljava/lang/String;)I",
                (void *)eSEManager_GetAppletsList},

    {"doAppletLoadApplet", "(Ljava/lang/String;[B)I",
                (void *)eSEManager_doAppletLoadApplet},

    {"GetCertificateKey", "()[B",
                (void *)eSEManager_GetCertificateKey},
#endif
};

/*******************************************************************************
 **
 ** Function:        register_com_android_nfc_NativeNfcAla
 **
 ** Description:     Regisgter JNI functions with Java Virtual Machine.
 **                  e: Environment of JVM.
 **
 ** Returns:         Status of registration.
 **
 *******************************************************************************/
int register_com_android_ese_NativeEseAla(JNIEnv *e)
{
    return jniRegisterNativeMethods(e, gNativeNfcAlaClassName,
            gMethods, NELEM(gMethods));
}

} /*namespace android*/
