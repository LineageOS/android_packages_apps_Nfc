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

#ifndef SPICHANNEL_H_
#define SPICHANNEL_H_

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
/*Compiler in Panda setup was giving error for negative enum values*/
#define EE_ERROR_OPEN_FAIL -1
typedef enum se_client
{
    DEFAULT = 0x00,
    LDR_SRVCE,
    JCP_SRVCE,
    LTSM_SRVCE,
    SPI_SRVCE
}seClient_t;

INT16 open();
bool close(INT16 mHandle);

bool transceive (UINT8* xmitBuffer, INT32 xmitBufferSize, UINT8* recvBuffer,
                 INT32 recvBufferMaxSize, INT32& recvBufferActualSize, INT32 timeoutMillisec);

void doeSE_Reset();
#if(NXP_ESE_CHIP_TYPE == P73)
void doeSE_JcopDownLoadReset();
#endif
extern INT16 mHandle;
#endif /* SPICHANNEL_H_ */
