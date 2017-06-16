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

#include "SpiChannel.h"
#include <cutils/log.h>
#include "SyncEvent.h"

extern "C"
{
#if(NXP_ESE_CHIP_TYPE == P61)
    #include "phNxpEseHal_Api.h"
#elif(NXP_ESE_CHIP_TYPE == P73)
    #include "phNxpEse_Api.h"
#else
#error "Define chip type macro"
#endif

}



namespace android
{
   extern SyncEvent     sTransceiveEvent;  // event for Set_Config....
   extern uint8_t*      sTransceiveData;
   extern uint32_t      sTransceiveDataLen;
   extern BOOLEAN       isIntialized();
#if(NXP_ESE_CHIP_TYPE == P61)
   extern void          eseStackCB(ESESTATUS status, phNxpEseP61_data *eventData);
#elif(NXP_ESE_CHIP_TYPE == P73)
   extern void          eseStackCB(ESESTATUS status, phNxpEse_data *eventData);
#endif
}
bool spiChannelForceClose = false;
INT16 mHandle = DEFAULT;

/*******************************************************************************
**
** Function:        open
**
** Description:     Opens the DWP channel to eSE
**
** Returns:         True if ok.
**
*******************************************************************************/
INT16 open()
{
    bool stat = true;
    INT16 status = EE_ERROR_OPEN_FAIL;
#if(NXP_ESE_CHIP_TYPE == P73)
    phNxpEse_initParams initParams;
    memset(&initParams,0x00,sizeof(phNxpEse_initParams));
#elif(NXP_ESE_CHIP_TYPE == P61)
    phNxpEseP61_initParams initParams;
    memset(&initParams,0x00,sizeof(phNxpEseP61_initParams));
#endif
    ALOGE("SpiChannel: Sec Element open Enter");
    //stat = android::isIntialized();
	spiChannelForceClose = false;
    if(JCP_SRVCE == mHandle) /* Check the client handle to identify the client */
        initParams.initMode = ESE_MODE_OSU;
    else
        initParams.initMode = ESE_MODE_NORMAL;
#if(NXP_ESE_CHIP_TYPE == P61)
    if(phNxpEseP61_open(android::eseStackCB, initParams))
#elif(NXP_ESE_CHIP_TYPE == P73)
    if(phNxpEse_open(initParams))
#endif
    {
        stat = false;
    }
#if(NXP_ESE_CHIP_TYPE == P73)
    else
    {
        /* Intialization of protocol stack parameters and the libstatus */
        if(phNxpEse_init(initParams))
        {
            stat = false;
        }
    }
#endif
    /*If channel is open and client handle is free*/
    if((stat == true)&&(mHandle != DEFAULT))
    {
        ALOGE("SpiChannel: Channel open success");
        status = mHandle;
    }
    else
    {
        ALOGE("SpiChannel: Open Failed");
    }
    return status;
}

/*******************************************************************************
**
** Function:        close
**
** Description:     closes the DWP connection with eSE
**
** Returns:         True if ok.
**
*******************************************************************************/
bool close(INT16 clientType)
{
    bool stat = false;
    static const char fn [] = "SpiChannel::close";

    ALOGD("%s: enter", fn);
    if(clientType == mHandle)
    {
#if(NXP_ESE_CHIP_TYPE == P73)
        if(!(phNxpEse_deInit()))
#endif
        {
    #if(NXP_ESE_CHIP_TYPE == P61)
            phNxpEseP61_close();
    #elif(NXP_ESE_CHIP_TYPE == P73)
            phNxpEse_close();
    #endif
            mHandle = DEFAULT;
            stat = true;
        }
    }
    else
    {
        //Do Nothing
    }
    return stat;
}

/*******************************************************************************
**
** Function:        transceive
**
** Description:     transceive the DWP connection with eSE
**
** Returns:         True if ok.
**
*******************************************************************************/
bool transceive (UINT8* xmitBuffer, INT32 xmitBufferSize, UINT8* recvBuffer,
                 INT32 recvBufferMaxSize, INT32& recvBufferActualSize, INT32 timeoutMillisec)
{
    (void)timeoutMillisec;
    static const char fn [] = "SpiChannel::transceive";
    ALOGD("%s: enter", fn);
    ESESTATUS status = ESESTATUS_SUCCESS;
    bool stat = false;
    UINT32 recvBuffLen=recvBufferMaxSize;
    if(spiChannelForceClose == true)
        return stat;
#if(NXP_ESE_CHIP_TYPE == P73)
    phNxpEse_data pCmd, pRsp;
    memset(&pCmd,0x00,sizeof(phNxpEse_data));
    memset(&pRsp,0x00,sizeof(phNxpEse_data));

    pCmd.p_data = xmitBuffer;
    pCmd.len = xmitBufferSize;
#endif

    SyncEventGuard guard (android::sTransceiveEvent);
#if(NXP_ESE_CHIP_TYPE == P61)
    status = phNxpEseP61_Transceive(xmitBufferSize, xmitBuffer);
    if (status == ESESTATUS_SUCCESS)
        android::sTransceiveEvent.wait ();
     else
         ALOGE ("%s: phNxpEseP61_Transceive Failed", __FUNCTION__);

    recvBufferActualSize = android::sTransceiveDataLen;

    if(recvBufferActualSize > 0)
    {
        ALOGD("%s: recvBuffLen=0x0%x", fn, android::sTransceiveDataLen);
        memcpy (recvBuffer, android::sTransceiveData, recvBufferActualSize);
        stat = true;
    }
#elif(NXP_ESE_CHIP_TYPE == P73)
    status = phNxpEse_Transceive(&pCmd, &pRsp);
    if (status == ESESTATUS_SUCCESS)
        ALOGD("%s: phNxpEse_Transceive success");
     else
         ALOGE ("%s: phNxpEse_Transceive Failed", __FUNCTION__);

    recvBufferActualSize = pRsp.len;

    if(recvBufferActualSize > 0)
    {
        ALOGD("%s: recvBuffLen=0x0%x", fn, recvBufferActualSize);
        memcpy (recvBuffer, pRsp.p_data, recvBufferActualSize);
        stat = true;
    }
    /* Freeing the response buffer filled from the protocol stack layer */
    if(NULL != pRsp.p_data)
    {
        free(pRsp.p_data);
        pRsp.p_data = NULL;
    }
#endif

    ALOGD("%s: exit; status=0x0%x", fn, stat);
    return stat;
}

/*******************************************************************************
**
** Function:        doeSE_Reset
**
** Description:     Reset the DWP connection with eSE
**
** Returns:         True if ok.
**
*******************************************************************************/
void doeSE_Reset(void)
{
    static const char fn [] = "SpiChannel::doeSE_Reset";
    ESESTATUS status = ESESTATUS_SUCCESS;
    ALOGD("%s: enter:", fn);
#if(NXP_ESE_CHIP_TYPE == P61)
    if(status != phNxpEseP61_reset())
#elif(NXP_ESE_CHIP_TYPE == P73)
    if(status != phNxpEse_reset())
#endif
    {
        ALOGD ("phNxpEse_reset: Failed");
    }
    ALOGD("%s: exit:", fn);

}
#if(NXP_ESE_CHIP_TYPE == P73)
/*******************************************************************************
**
** Function:        doeSE_JcopDownLoadReset
**
** Description:     Reset the DWP connection with eSE
**
** Returns:         True if ok.
**
*******************************************************************************/
void doeSE_JcopDownLoadReset(void)
{
    static const char fn [] = "SpiChannel::doeSE_JcopDownLoadReset";
    ESESTATUS status = ESESTATUS_SUCCESS;
    ALOGD("%s: enter:", fn);
    if(status != phNxpEse_resetJcopUpdate())
    {
        ALOGD ("doeSE_JcopDownLoadReset: Failed");
    }
    ALOGD("%s: exit:", fn);

}
#endif
