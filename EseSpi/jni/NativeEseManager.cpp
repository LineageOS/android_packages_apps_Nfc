/*
 * Copyright (C) 2014 NXP Semiconductors
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

/**
 * \addtogroup spi_package
 *
 * @{ */

#define LOG_TAG "NativeEseManager"
#include "SyncEvent.h"
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <SpiJniUtil.h>
#include <ScopedLocalRef.h>
#include <ScopedPrimitiveArray.h>
#include <pthread.h>
#include <IChannel.h>
#include <JcDnld.h>
#include "SpiChannel.h"

#ifdef ESE_NFC_SYNCHRONIZATION
#include <linux/ese-nfc-sync.h>
#endif

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>


#ifdef ESE_NFC_SYNCHRONIZATION

/* timing calculation structure*/
typedef struct time_cal
{
    struct timeval  tv1;
    struct timeval tv2;
}TimeCal;
static int fd_ese_nfc_sync; /*file descriptor to hold sync driver handle*/
#endif

extern "C"
{
#include "phNxpConfig.h"
#if(NXP_ESE_CHIP_TYPE == P61)
#include "phNxpEseHal_Api.h"
#include "phNxpEseHal_Apdu.h"
#elif(NXP_ESE_CHIP_TYPE == P73)
#include "phNxpEse_Api.h"
#include "phNxpEse_Apdu_Api.h"
#else
#error "Define chip type macro"
#endif
}


// Global Varibales
BOOLEAN isInit=false;
IChannel_t swp;
extern unsigned char JCDNLD_Init(IChannel *channel);
extern unsigned char JCDNLD_StartDownload();
extern bool          JCDNLD_DeInit();
extern bool spiChannelForceClose;
#define IFSC_JCOPDWNLD    (240)
#define IFSC_NONJCOPDWNLD (254)

namespace android
{
JavaVM * g_vm;
jobject g_obj;
jmethodID g_mid;
ese_jni_native_data* mNativeData = NULL;
SyncEvent     sTransceiveEvent;  //fevent for Set_Config....
uint8_t*      sTransceiveData = NULL;
uint32_t      sTransceiveDataLen = 0;
jmethodID     gCachedEseManagerListeners;
const char    *gNativeEseManagerClassName = "com/nxp/ese/dhimpl/NativeEseManager";
bool          gJcopDwnldinProgress = false;
#if(NXP_ESE_CHIP_TYPE == P61)
static void          eseStackCallback (ESESTATUS status, phNxpEseP61_data* eventData);
#endif

ESESTATUS EseNfcSyncInit(void);
ESESTATUS EseNfcSyncDeInit(void);
ESESTATUS SpiReqResourceIoctl(double time_limit);
ESESTATUS SpiReleaseResourceIoctl(double time_limit);
void sig_handler(int signo);
#define NAME_NXP_P61_LS_DEFAULT_INTERFACE "NXP_P61_LS_DEFAULT_INTERFACE"
#define NAME_NXP_P61_JCOP_DEFAULT_INTERFACE "NXP_P61_JCOP_DEFAULT_INTERFACE"
#define NAME_NXP_P61_LTSM_DEFAULT_INTERFACE "NXP_P61_LTSM_DEFAULT_INTERFACE"
extern bool Spichannel_init(IChannel_t *swp, seClient_t mHandle);
void Spichannel_Deinit(seClient_t clientType);
BOOLEAN isIntialized()
{
    return isInit;
}
#if(NXP_ESE_CHIP_TYPE == P61)
void eseStackCB(ESESTATUS status, phNxpEseP61_data* eventData)
{
    eseStackCallback (status, eventData);
}
#endif
/**
 * \ingroup spi_package
 * \brief Open ESE
 *
 * \param[in]       JNIEnv*
 * \param[in]       jobject
 *
 * \retval True if ok.
 *
 */

static jboolean nativeEseManager_doInitialize(JNIEnv *e, jobject obj, jint timeout)
{
    (void)e;
    (void)obj;
    ALOGD ("%s: enter...timeout=%d\n", __FUNCTION__, timeout);
    ESESTATUS status = ESESTATUS_SUCCESS;
    BOOLEAN returnStatus = true;
#if(NXP_ESE_CHIP_TYPE == P61)
    phNxpEseP61_initParams initParams;
    memset(&initParams,0x00,sizeof(phNxpEseP61_initParams));
    initParams.initMode = ESE_MODE_NORMAL;
#endif
#if(NXP_ESE_CHIP_TYPE == P73)
    phNxpEse_initParams initParams;
    memset(&initParams,0x00,sizeof(phNxpEse_initParams));
#endif

#ifdef ISO7816_4_APDU_PARSER_ENABLE
    ALOGD(" ISO7816_4_APDU_PARSER_ENABLE ");
#if(NXP_ESE_CHIP_TYPE == P61)
    status = phNxpEseP61_open(NULL, initParams);
#elif(NXP_ESE_CHIP_TYPE == P73)
    status = phNxpEse_open(initParams);
#endif
#else
    if(timeout == 9999)
    {
#if(NXP_ESE_CHIP_TYPE == P61)
        status = phNxpEseP61_open(eseStackCallback, initParams);
#elif(NXP_ESE_CHIP_TYPE == P73)
        status = phNxpEse_open(initParams);
#endif
    }
    else if(timeout >= 0)
    {
#if(NXP_ESE_CHIP_TYPE == P61)
    status = phNxpEseP61_openPrioSession(eseStackCallback, timeout, initParams);
#elif(NXP_ESE_CHIP_TYPE == P73)
    status = phNxpEse_openPrioSession(initParams);
#endif
    }
#endif
    ALOGD("phNxpEse_open, status = %x", status);
    if(status == ESESTATUS_SUCCESS)
    {
        isInit=true;
        if(Spichannel_init(&swp, SPI_SRVCE) != TRUE)
        {
            ALOGE("%s: phNxpEse_Transceive Already in use", __FUNCTION__);
            returnStatus = false;
        }
        /* Intialization of protocol stack parameters and the libstatus */
#if(NXP_ESE_CHIP_TYPE == P73)
        initParams.initMode = ESE_MODE_NORMAL;
        status = phNxpEse_init(initParams);
#endif
    }
    if(status != ESESTATUS_SUCCESS)
    {
        isInit=false;
        returnStatus = false;
    }

    ALOGD ("%s: exit", __FUNCTION__);
    return returnStatus;
}

/**
 * \ingroup spi_package
 * \brief Send raw data; receive response.
 *
 * \param[in]       JNIEnv*
 * \param[in]       jobject
 *
 * \retval Response data.
 *
 */
#ifdef ISO7816_4_APDU_PARSER_ENABLE
/* this is the test code, which basically parse the 7816-4 Headers from
 * data received from application layer and passed the data in 7816-4 format
 * to phNxpEse_7816_Transceive api.
 */
static jbyteArray nativeEseManager_doTransceive(JNIEnv *e, jobject obj, jbyteArray data)
{
    ALOGD ("%s: enter", __FUNCTION__);
    uint8_t* buf = NULL;
    uint8_t *temp_buff = NULL;
    uint32_t data_index = 0;
    uint32_t le_size = 0;
    ESESTATUS status = ESESTATUS_SUCCESS;
    // get input buffer and length from java call
    ScopedByteArrayRO bytes(e, data);
    buf = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&bytes[0]));
    size_t bufLen = bytes.size();
    ScopedLocalRef<jbyteArray> result(e, NULL);

#if(NXP_ESE_CHIP_TYPE == P61)
    phNxpEseP61_7816_cpdu_t pCmd;
    phNxpEseP61_7816_rpdu_t pRsp;
    memset(&pCmd,0x00,sizeof(phNxpEseP61_7816_cpdu_t));
    memset(&pRsp,0x00,sizeof(phNxpEseP61_7816_rpdu_t));
#elif(NXP_ESE_CHIP_TYPE == P73)
    phNxpEse_7816_cpdu_t pCmd;
    phNxpEse_7816_rpdu_t pRsp;
    memset(&pCmd,0x00,sizeof(phNxpEse_7816_cpdu_t));
    memset(&pRsp,0x00,sizeof(phNxpEse_7816_rpdu_t));
#endif
    ALOGD("Data lenght = %d\n", bufLen);

    pCmd.cla = buf[0]; /* Class of instruction */
    pCmd.ins = buf[1]; /* Instruction code */
    pCmd.p1 = buf[2];/* Instruction parameter 1 */
    pCmd.p2 = buf[3]; /* Instruction parameter 2 */

    if(bufLen > 7)
    ALOGD("LC lenght = 0x%x 0x%x 0x%x", buf[4], buf[5], buf[6]);
    if(bufLen == 7 && buf[4] == 0)
    {
        /* no data with extended le */
        ALOGD("no data with extended le");
        pCmd.lc = buf[4];
        pCmd.cpdu_type = 0;
        pCmd.le_type = 3;
        pCmd.le = ((buf[5] << 8) | buf[6]);
    }
    else if(bufLen == 5 )
    {
        /* no data with short le */
        ALOGD("no data with short le");
        pCmd.lc = 0x00;
        pCmd.cpdu_type = 0;
        pCmd.le_type = 1;
        if(buf[4] == 0)
        pCmd.le = 256;
        else
        pCmd.le = buf[4];
    }
    else if (bufLen == 4)
    {
        /* no data with short le */
        ALOGD("no data no le");
        pCmd.lc = 0x00;
        pCmd.cpdu_type = 0;
        pCmd.le_type = 0;
    }
    else if((0 < buf[4] && buf[4] <= 255)  && bufLen >= 6)
    {
        /* short data */
        ALOGD("short data");
        pCmd.lc = buf[4];
        le_size = (bufLen - pCmd.lc) - 5;
        pCmd.cpdu_type = 0;
        ALOGD("le_size = %d", le_size);
        if(le_size > 0)
        {
            ALOGD("Le is present");
        }
        else
        {
            le_size = 0;
        }
        if(le_size == 1)
        {
            ALOGD("Short Le is present");
            pCmd.le = buf[bufLen - 1];
        }
        else if (le_size == 2)
        {
            ALOGD("Long Le is present");
            pCmd.le = ((buf[bufLen - 2] << 8)|(buf[bufLen - 1]));
        }
        pCmd.le_type = le_size;
        data_index = 5;
    }
    else if((0 == buf[4]) && (bufLen > 255))
    {
        /* Long data */
        ALOGD("long data");
        pCmd.lc = 0;
        pCmd.lc = (uint16_t)( (buf[5]) << 8| (buf[6]));
        pCmd.cpdu_type = 1;
        ALOGD("pCmd.lc %x", pCmd.lc);
        le_size = (bufLen - pCmd.lc) - 7;
        ALOGD("le_size %x = bufLen%x - pCmd.lc%x",le_size, bufLen,pCmd.lc);
        if(le_size > 0)
        {
            ALOGD("Le is present");
        }
        else
        {
            ALOGD("Le is not present");
            pCmd.le_type = 0;
        }
        if(le_size == 1)
        {
            ALOGD("Short Le is present");
            pCmd.le = buf[bufLen - 1];
            ALOGD("pCmd.le %d", pCmd.le);
            pCmd.le_type = 1;
        }

        else if(le_size == 2)
        {
            ALOGD("Long Le is present");
            pCmd.le = ((buf[bufLen - 2] << 8)|(buf[bufLen - 1]));
            ALOGD("pCmd.le %d", pCmd.le);
            pCmd.le_type = 2;
        }
        data_index = 7;
    }
    else
    {
        ALOGD("Undefined data len and le");
    }

    if (pCmd.lc > 0)
    {
        pCmd.pdata = (uint8_t *)malloc(pCmd.lc * sizeof(uint8_t));
        if (pCmd.pdata == NULL)
        {
            ALOGD("Memory allocation failed \n");
            return NULL;
        }
        memcpy(&pCmd.pdata[0], &buf[data_index], pCmd.lc);
    }
    if(pCmd.le_type == 0 || pCmd.le_type == 1)
    {
        ALOGD("Allocating 256 res buff");
        pRsp.pdata = (uint8_t *)malloc(sizeof(char) * 256);
        if(pRsp.pdata == NULL)
        {
             ALOGD("Memory allocation failed \n");
             return NULL;
        }
    }
    else
    {
        ALOGD("Allocating %d res buff", pCmd.le);
        pRsp.pdata = (uint8_t *)malloc(sizeof(char) * pCmd.le);
        if(pRsp.pdata == NULL)
        {
            ALOGD("Memory allocation failed \n");
            return NULL;
        }
    }
    pRsp.len = 0;
    ALOGD("cla = 0x%x , ins = 0x%x , p1 = 0x%x, p2 = 0x%x , lc =0x%x, cpdu_type= 0x%x, le_type= 0x%x, le = 0x%x"
            ,pCmd.cla, pCmd.ins, pCmd.p1, pCmd.p2, pCmd.lc, pCmd.cpdu_type, pCmd.le_type, pCmd.le);
#if(NXP_ESE_CHIP_TYPE == P61)
    status = phNxpEseP61_7816_Transceive(&pCmd, &pRsp);
#elif(NXP_ESE_CHIP_TYPE == P73)
    status = phNxpEse_7816_Transceive(&pCmd, &pRsp);
#endif
    if (status == ESESTATUS_SUCCESS)
    {
        ALOGD ("%s: phNxpEse_7816_Transceive Success pRsp.len %d", __FUNCTION__, pRsp.len);
        temp_buff = (uint8_t *)malloc((pRsp.len + 2) * sizeof(uint8_t));
        if (temp_buff == NULL)
        {
            ALOGE ("%s: Failed to allocate java byte array", __FUNCTION__);
            return NULL;
        }
        if(pRsp.len > 0)
        {
            memcpy(&temp_buff[0], &pRsp.pdata[0], pRsp.len);
        }
        ALOGD("pRsp.sw1 = 0x%x, pRsp.sw2 = 0x%x, pRsp.len %d", pRsp.sw1, pRsp.sw2, pRsp.len);
        temp_buff[pRsp.len] = pRsp.sw1;
        temp_buff[pRsp.len + 1] = pRsp.sw2;
        result.reset(e->NewByteArray(pRsp.len + 2));
        if (result.get() != NULL)
        {
            e->SetByteArrayRegion(result.get(), 0, (pRsp.len + 2), (jbyte *) &temp_buff[0]);
        }
        else
            ALOGE ("%s: Failed to allocate java byte array", __FUNCTION__);
    }
    else
    {
        ALOGE ("%s: phNxpEse_7816_Transceive Failed", __FUNCTION__);
        return NULL;
    }

    ALOGD ("%s: status: %d , sTransceiveDataLen :%d", __FUNCTION__,status , sTransceiveDataLen);

    if (temp_buff != NULL)
        free (temp_buff);

    temp_buff = NULL;
    ALOGD ("%s: Exit", __FUNCTION__);
    return result.release();
}
#else
static jbyteArray nativeEseManager_doTransceive(JNIEnv *e, jobject obj, jbyteArray data)
{
    (void)obj;
    ALOGD ("%s: enter", __FUNCTION__);
    uint8_t* buf = NULL;
    ESESTATUS status = ESESTATUS_SUCCESS;
#if(NXP_ESE_CHIP_TYPE == P73)
    phNxpEse_data pCmd;
    phNxpEse_data pRsp;
    memset(&pCmd,0x00,sizeof(phNxpEse_data));
    memset(&pRsp,0x00,sizeof(phNxpEse_data));
#endif
    // get input buffer and length from java call
    ScopedByteArrayRO bytes(e, data);
#if(NXP_ESE_CHIP_TYPE == P61)
    buf = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&bytes[0]));
    size_t bufLen = bytes.size();
#elif(NXP_ESE_CHIP_TYPE == P73)
    pCmd.p_data = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&bytes[0]));
    size_t bufLen = bytes.size();
    pCmd.len = bufLen;
#endif
    ScopedLocalRef<jbyteArray> result(e, NULL);

#if(NXP_ESE_CHIP_TYPE == P61)
    SyncEventGuard guard (sTransceiveEvent);
    status = phNxpEseP61_Transceive(bufLen, buf);
    if (status == ESESTATUS_SUCCESS)
        sTransceiveEvent.wait ();
    else
        ALOGE ("%s: phNxpEseP61_Transceive Failed", __FUNCTION__);

    ALOGD ("%s: status: %d , sTransceiveDataLen :%d", __FUNCTION__,status , sTransceiveDataLen);

    if(sTransceiveDataLen != 0)
    {
        result.reset(e->NewByteArray(sTransceiveDataLen));
    }
    else
    {
        ALOGD ("%s: TransceiveDataLen: %d", __FUNCTION__,sTransceiveDataLen);
        return NULL;
    }
    if (result.get() != NULL)
    {
        e->SetByteArrayRegion(result.get(), 0, sTransceiveDataLen, (jbyte *) sTransceiveData);
    }
    else
        ALOGE ("%s: Failed to allocate java byte array", __FUNCTION__);

    if (sTransceiveData != NULL)
        free (sTransceiveData);

    sTransceiveData = NULL;
    sTransceiveDataLen = 0;
#elif(NXP_ESE_CHIP_TYPE == P73)
    status = phNxpEse_Transceive(&pCmd, &pRsp);
    if (status == ESESTATUS_SUCCESS)
    {
        ALOGD ("%s: phNxpEse_Transceive Success", __FUNCTION__);
        if(pRsp.len != 0)
        {
            result.reset(e->NewByteArray(pRsp.len));
        }
        else /* if transceive is success but length is zero */
        {
            ALOGE ("%s: Data reached JNI: but data length is zero", __FUNCTION__);
            return NULL;
        }
    }
    else
    {
        ALOGE ("%s: phNxpEse_Transceive Failed", __FUNCTION__);
        return NULL;
    }

    if (result.get() != NULL)
    {
        e->SetByteArrayRegion(result.get(), 0, pRsp.len, (jbyte *) pRsp.p_data);
    }
    else
        ALOGE ("%s: Failed to allocate java byte array", __FUNCTION__);

    if (pRsp.p_data != NULL)
        free (pRsp.p_data);

    pRsp.p_data = NULL;
    pRsp.len = 0;
#endif
    //e->ReleaseByteArrayElements (data, (jbyte *) buf, JNI_ABORT);
    ALOGD ("%s: Exit", __FUNCTION__);
    return result.release();
}
#endif
/**
 * \ingroup spi_package
 * \brief Start Download
 *
 * \param[in]       JNIEnv*
 * \param[in]       jobject
 *
 * \retval True if ok.
 *
 */

static int nativeEseManager_doStartDownload(JNIEnv *e, jobject obj)
{
    (void)e;
    (void)obj;
    ALOGD ("%s: enter", __FUNCTION__);
    ESESTATUS status = STATUS_FAILED;
    bool stat = false;
    BOOLEAN returnStatus = true;

    gJcopDwnldinProgress = true;

    if(Spichannel_init(&swp, JCP_SRVCE))
    {

#if(NXP_ESE_CHIP_TYPE == P61)
        phNxpEseP61_setIfsc(IFSC_JCOPDWNLD);
#elif(NXP_ESE_CHIP_TYPE == P73)
        phNxpEse_setIfsc(IFSC_JCOPDWNLD);
#endif
        status = JCDNLD_Init(&swp);
        if(status != STATUS_SUCCESS)
        {
            ALOGE("%s: JCDND initialization failed", __FUNCTION__);
        }else
        {
            status = JCDNLD_StartDownload();
            if(status != ESESTATUS_SUCCESS)
            {
                ALOGE("%s: JCDNLD_StartDownload failed", __FUNCTION__);
            }
        }
        stat = JCDNLD_DeInit();
#if(NXP_ESE_CHIP_TYPE == P61)
        phNxpEseP61_setIfsc(IFSC_NONJCOPDWNLD);
#elif(NXP_ESE_CHIP_TYPE == P73)
        phNxpEse_setIfsc(IFSC_NONJCOPDWNLD);
        Spichannel_Deinit(JCP_SRVCE);
#endif
    }
    gJcopDwnldinProgress = false;
    ALOGD ("%s: Exit; status =0x%X", __FUNCTION__,status);
    return status;
}

/**
 * \ingroup spi_package
 * \brief Initialize the SPI Channel
 *
 * \param[in]       IChannel_t *
 *
 * \retval True if ok.
 *
 */
bool Spichannel_init(IChannel_t *swp, seClient_t clientType)
{
    bool stat = false;

    /*Check Handle is free & available*/
    if(mHandle == DEFAULT)
    {
        mHandle = clientType;
        ALOGD("Spichannel_init -Enter : \n");
        swp->open = open;
        swp->close = close;
        swp->transceive = transceive;
        swp->doeSE_Reset = doeSE_Reset;
#if(NXP_ESE_CHIP_TYPE == P73)
        swp->doeSE_JcopDownLoadReset = doeSE_JcopDownLoadReset;
#elif(NXP_ESE_CHIP_TYPE == P61)
        swp->doeSE_JcopDownLoadReset = doeSE_Reset;
#endif

        stat = true;
    }
    /*Otherwise handle is not available*/
    else
    {
        ALOGD("Spichannel_init -Already InUse : \n");
    }
return stat;
}

/**
 * \ingroup spi_package
 * \brief De-Initialize the SPI Channel
 *
 * \param[in]       seClient_t
 *
 * \retval none.
 *
 */
void Spichannel_Deinit(seClient_t clientType)
{
    if(clientType == mHandle)
        mHandle = DEFAULT;
}

/**
 * \ingroup spi_package
 * \brief DeInitialize variables.
 *
 * \param[in]       JNIEnv*
 * \param[in]       jobject
 *
 * \retval True if ok.
 *
 */

static jboolean nativeEseManager_doDeinitialize(JNIEnv *e, jobject obj)
{
    (void)e;
    (void)obj;
    ESESTATUS status = ESESTATUS_SUCCESS;
    BOOLEAN returnStatus = true;
    ALOGD ("%s: enter", __FUNCTION__);
    if(mHandle == SPI_SRVCE)
    {
        /*Release the handle so that other clients can use*/
        mHandle = DEFAULT;
    }
#if(NXP_ESE_CHIP_TYPE == P73)
    if(status != phNxpEse_deInit())
    {
        returnStatus = false;
    }
    else
    {
#endif
    #if(NXP_ESE_CHIP_TYPE == P61)
        if(status  != phNxpEseP61_close())
    #elif(NXP_ESE_CHIP_TYPE == P73)
        if(status  != phNxpEse_close())
    #endif
        {
            returnStatus = false;
        }
#if(NXP_ESE_CHIP_TYPE == P73)
    }
#endif
    isInit=false;
    ALOGD ("%s: Exit", __FUNCTION__);
    return returnStatus;
}

/**
 * \ingroup spi_package
 * \brief Reset the chip.
 *
 * \param[in]       JNIEnv*
 * \param[in]       jobject
 *
 * \retval True if ok.
 *
 */
static jboolean nativeEseManager_doReset(JNIEnv *e, jobject obj)
{
    (void)e;
    (void)obj;
    ESESTATUS status = ESESTATUS_SUCCESS;
    BOOLEAN returnStatus = true;
    ALOGD ("%s: enter", __FUNCTION__);
#if(NXP_ESE_CHIP_TYPE == P61)
    if(status != phNxpEseP61_reset())
#elif(NXP_ESE_CHIP_TYPE == P73)
    if(status != phNxpEse_reset())
#endif
    {
        returnStatus = false;
    }
    isInit=true;
    ALOGD ("%s: Exit, status: %d", __FUNCTION__,status);
    return returnStatus;
}

/**
 * \ingroup spi_package
 * \brief Reset the chip.
 *
 * \param[in]       JNIEnv*
 * \param[in]       jobject
 *
 * \retval True if ok.
 *
 */
static jboolean nativeEseManager_doChipReset(JNIEnv *e, jobject obj)
{
    (void)e;
    (void)obj;
#if(NXP_ESE_CHIP_TYPE == P73)
    ESESTATUS status = ESESTATUS_SUCCESS;
    BOOLEAN returnStatus = true;
    ALOGD ("%s: enter", __FUNCTION__);
    if(status != phNxpEse_chipReset())
    {
        returnStatus = false;
    }
    isInit=true;
    ALOGD ("%s: Exit, status: %d", __FUNCTION__,status);
    return returnStatus;
#elif(NXP_ESE_CHIP_TYPE == P61)
    ALOGD ("%s: API not supported", __FUNCTION__);
    return false;
#endif
}
/**
 * \ingroup spi_package
 * \brief  Abort.
 *
 * \param[in]       JNIEnv *
 * \param[in]       jobject
 *
 * \retval  True if ok.
 *
 */

static void nativeEseManager_doAbort(JNIEnv *e, jobject obj)
{
    (void)e;
    (void)obj;

    ALOGD ("%s: enter; Status:ESESTATUS_ABORTED", __FUNCTION__);
    SyncEventGuard guard (sTransceiveEvent);
    sTransceiveEvent.notifyOne();
    ALOGD ("%s: exit", __FUNCTION__);
}

static int nativeEseManager_doGetSeInterface(JNIEnv *e, jobject obj, jint type)
{
    unsigned long num = 2;
#if 0
    switch(type)
    {
    case LDR_SRVCE:
        if(GetNxpNumValue (NAME_NXP_P61_LS_DEFAULT_INTERFACE, (void*)&num, sizeof(num))==false)
        {
            ALOGD ("NAME_NXP_P61_LS_DEFAULT_INTERFACE not found");
            num = 2;
        }
        break;
    case JCP_SRVCE:
        if(GetNxpNumValue (NAME_NXP_P61_JCOP_DEFAULT_INTERFACE, (void*)&num, sizeof(num))==false)
        {
            ALOGD ("NAME_NXP_P61_JCOP_DEFAULT_INTERFACE not found");
            num = 2;
        }
        break;
    case LTSM_SRVCE:
        if(GetNxpNumValue (NAME_NXP_P61_LTSM_DEFAULT_INTERFACE, (void*)&num, sizeof(num))==false)
        {
            ALOGD ("NAME_NXP_P61_LTSM_DEFAULT_INTERFACE not found");
            num = 2;
        }
        break;
    default:
        break;
    }
#endif
    ALOGD ("%d: nfcManager_doGetSeInterface", num);
    return num;
}
/**
 * \ingroup spi_package
 * \brief Initialize Global variables.
 *
 * \param[in]       JNIEnv*
 * \param[in]       jobject
 *
 * \retval True if ok.
 *
 */
static jboolean nativeEseManager_doCheckJcopDlAtBoot(JNIEnv *e, jobject obj)
{
    unsigned int num = 0;
    ALOGD ("%s: enter", __FUNCTION__);
    if(GetNxpNumValue (NAME_NXP_JCOPDL_AT_BOOT_ENABLE, (void*)&num, sizeof(num)))
    {
        if(num == 0x01) {
            return JNI_TRUE;
        }
        else {
            return JNI_FALSE;
        }
    }
    else {
        return JNI_FALSE;
    }
}

static jboolean nativeEseManager_initNativeStruct(JNIEnv* e, jobject o)
{
    ALOGD ("%s: enter", __FUNCTION__);
    mNativeData = (ese_jni_native_data*)malloc(sizeof(struct ese_jni_native_data));
    if (mNativeData == NULL)
    {
        ALOGE ("%s: fail allocate native data", __FUNCTION__);
        return JNI_FALSE;
    }
    memset (mNativeData, 0, sizeof(*mNativeData));
    e->GetJavaVM(&(mNativeData->vm));  // VM copied to Global variable
    mNativeData->manager = e->NewGlobalRef(o);
    ALOGE ("%d: e->GetVersion()",   e->GetVersion());

    ScopedLocalRef<jclass> cls(e, e->GetObjectClass(o));

    gCachedEseManagerListeners = e->GetMethodID(cls.get(), "notifyEseManagerServiceListeners", "(I)V");

    ALOGD ("%s: exit", __FUNCTION__);
    return JNI_TRUE;
}


static JNINativeMethod methods[] = {

        {"doInitialize", "(I)Z", (void*)nativeEseManager_doInitialize },
        {"doDeinitialize", "()Z", (void*)nativeEseManager_doDeinitialize },
        {"doTransceive", "([B)[B", (void*)nativeEseManager_doTransceive },
        {"doReset", "()Z", (void*)nativeEseManager_doReset },
        {"doChipReset", "()Z", (void*)nativeEseManager_doChipReset },
        {"initializeNativeStructure", "()Z", (void*)nativeEseManager_initNativeStruct},
        {"doStartJcopDownload", "()I", (void*)nativeEseManager_doStartDownload},
        {"doAbort", "()V", (void*)nativeEseManager_doAbort},
        {"doGetSeInterface", "(I)I", (void*)nativeEseManager_doGetSeInterface},
        {"doCheckJcopDlAtBoot", "()Z", (void*)nativeEseManager_doCheckJcopDlAtBoot}

};

/**
 * \ingroup spi_package
 * \brief Receive connection-related events from stack.
 *                  connEvent: Event code.
 *                  eventData: Event data.
 *
 * \param[in]       ESESTATUS
 * \param[in]       phNxpEse_data*
 *
 * \retval void
 *
 */

#if(NXP_ESE_CHIP_TYPE == P61)
static void eseStackCallback (ESESTATUS status, phNxpEseP61_data* eventData)
#elif(NXP_ESE_CHIP_TYPE == P73)
static void eseStackCallback (ESESTATUS status, phNxpEse_data* eventData)
#endif
{
    ALOGD("%s: event= %u", __FUNCTION__, status);
    JNIEnv* e = NULL;
    ScopedAttach attach(mNativeData->vm, &e);
    sTransceiveDataLen = 0;
    if (e == NULL)
    {
        ALOGE ("%s: jni env is null", __FUNCTION__);
        return;
    }
    switch (status)
    {
    case ESESTATUS_SUCCESS:
    {
        if(eventData != NULL){
            ALOGD ("%s: Status:ESESTATUS_SUCCESS", __FUNCTION__);
            if (eventData->len)
            {
                if (NULL == (sTransceiveData = (uint8_t *) malloc (eventData->len)))
                {
                    ALOGD ("%s: memory allocation error", __FUNCTION__);
                }
                else
                {
                    memcpy (sTransceiveData, eventData->p_data, sTransceiveDataLen = eventData->len);
                }
            }
            if (gJcopDwnldinProgress == false)
                e->CallVoidMethod (mNativeData->manager, android::gCachedEseManagerListeners, 0);
        }
#if(NXP_ESE_CHIP_TYPE == P61)
        SyncEventGuard guard (sTransceiveEvent);
        sTransceiveEvent.notifyOne();
#endif
        break;
    }

    case ESESTATUS_FAILED:
    {
        ALOGD ("%s: Status:ESESTATUS_FAILED", __FUNCTION__);
        e->CallVoidMethod (mNativeData->manager, android::gCachedEseManagerListeners, 1);
        SyncEventGuard guard (sTransceiveEvent);
        sTransceiveEvent.notifyOne();
        break;
    }

    case ESESTATUS_WTX_REQ:
    {
        ALOGD ("%s: Status:ESESTATUS_WTX_REQ", __FUNCTION__);
        if (gJcopDwnldinProgress == false)
        {
            e->CallVoidMethod (mNativeData->manager, android::gCachedEseManagerListeners, 2);
        }
        break;
    }
    }

    ALOGD ("%s: exit", __FUNCTION__);
}

/**
 * \ingroup spi_package
 * \brief Register native methods for all classes we know about.
 *
 * \param[in]       JNIEnv*
 *
 * \retval JNI_TRUE on success.
 *
 */

int register_com_android_ese_NativeEseManager(JNIEnv* env)
{
    return jniRegisterNativeMethods(env, gNativeEseManagerClassName,
            methods, sizeof(methods) / sizeof(methods[0]));
}

}

/** @} */
