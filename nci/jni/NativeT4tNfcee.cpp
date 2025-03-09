/******************************************************************************
 *
 *  Copyright (C) 2024 The Android Open Source Project.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
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

#include "NativeT4tNfcee.h"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <nativehelper/ScopedPrimitiveArray.h>

#include "NfcJniUtil.h"
#include "nfa_nfcee_api.h"
#include "nfa_nfcee_int.h"
#include "nfc_config.h"

using android::base::StringPrintf;

/*Considering NCI response timeout which is 2s, Timeout set 100ms more*/
#define T4TNFCEE_TIMEOUT 2100
#define T4TOP_TIMEOUT 200
#define FILE_ID_LEN 0x02

extern bool gActivated;
namespace android {
extern bool isDiscoveryStarted();
extern void startRfDiscovery(bool isStart);
extern bool nfcManager_isNfcActive();
}  // namespace android

NativeT4tNfcee NativeT4tNfcee::sNativeT4tNfceeInstance;
bool NativeT4tNfcee::sIsNfcOffTriggered = false;

NativeT4tNfcee::NativeT4tNfcee() {
  mBusy = false;
  memset(&mReadData, 0x00, sizeof(tNFA_RX_DATA));
  mT4tOpStatus = NFA_STATUS_FAILED;
}

/*****************************************************************************
**
** Function:        getInstance
**
** Description:     Get the NativeT4tNfcee singleton object.
**
** Returns:         NativeT4tNfcee object.
**
*******************************************************************************/
NativeT4tNfcee& NativeT4tNfcee::getInstance() {
  return sNativeT4tNfceeInstance;
}

/*******************************************************************************
**
** Function:        initialize
**
** Description:     Initialize all member variables.
**
** Returns:         None.
**
*******************************************************************************/
void NativeT4tNfcee::initialize(void) {
  sIsNfcOffTriggered = false;
  mBusy = false;
}

/*****************************************************************************
**
** Function:        onNfccShutdown
**
** Description:     This api shall be called in NFC OFF case.
**
** Returns:         none.
**
*******************************************************************************/
void NativeT4tNfcee::onNfccShutdown() {
  sIsNfcOffTriggered = true;
  if (mBusy) {
    /* Unblock JNI APIs */
    {
      SyncEventGuard g(mT4tNfcOffEvent);
      if (mT4tNfcOffEvent.wait(T4TOP_TIMEOUT) == false) {
        SyncEventGuard ga(mT4tNfcEeRWCEvent);
        mT4tNfcEeRWCEvent.notifyOne();
      }
    }
    /* Try to close the connection with t4t nfcee, discard the status */
    (void)closeConnection();
    resetBusy();
  }
}
/*******************************************************************************
**
** Function:        t4tClearData
**
** Description:     This API will set all the T4T NFCEE NDEF data to zero.
**                  This API can be called regardless of NDEF file lock state.
**
** Returns:         boolean : Return the Success or fail of the operation.
**                  Return "True" when operation is successful. else "False"
**
*******************************************************************************/
jboolean NativeT4tNfcee::t4tClearData(JNIEnv* e, jobject o) {
  LOG(DEBUG) << StringPrintf("%s:Enter: ", __func__);

  /*Local variable Initialization*/
  uint8_t pFileId[] = {0xE1, 0x04};
  jbyteArray fileIdArray = e->NewByteArray(sizeof(pFileId));
  e->SetByteArrayRegion(fileIdArray, 0, sizeof(pFileId), (jbyte*)pFileId);
  bool clear_status = false;

  /*Validate Precondition*/
  T4TNFCEE_STATUS_t t4tNfceeStatus =
      validatePreCondition(OP_CLEAR, fileIdArray);

  switch (t4tNfceeStatus) {
    case STATUS_SUCCESS:
      /*NFC is ON*/
      clear_status = performT4tClearData(pFileId);
      break;
    default:
      LOG(ERROR) << StringPrintf("%s:Exit: Returnig status : %d", __func__,
                                 clear_status);
      break;
  }
  LOG(DEBUG) << StringPrintf("%s:Exit: ", __func__);
  return clear_status;
}
/*******************************************************************************
**
** Function:        performT4tClearData
**
** Description:     This api clear the T4T Nfcee data
**
** Returns:         boolean : Return the Success or fail of the operation.
**                  Return "True" when operation is successful. else "False"
**
*******************************************************************************/
jboolean NativeT4tNfcee::performT4tClearData(uint8_t* fileId) {
  bool t4tClearReturn = false;
  tNFA_STATUS status = NFA_STATUS_FAILED;

  /*Open connection and stop discovery*/
  if (setup() != NFA_STATUS_OK) return t4tClearReturn;

  /*Clear Ndef data*/
  SyncEventGuard g(mT4tNfcEeRWCEvent);
  status = NFA_T4tNfcEeClear(fileId);
  if (status == NFA_STATUS_OK) {
    if (mT4tNfcEeRWCEvent.wait(T4TNFCEE_TIMEOUT) == false)
      t4tClearReturn = false;
    else {
      if (mT4tOpStatus == NFA_STATUS_OK) {
        t4tClearReturn = true;
      }
    }
  }

  /*Close connection and start discovery*/
  cleanup();
  return t4tClearReturn;
}
/*******************************************************************************
**
** Function:        getT4tStatus
**
** Description:     This API will get T4T NDEF NFCEE status.
**
** Returns:         boolean : Indicates whether T4T NDEF NFCEE Read or write
**                            operation is under process
**                  Return "True" when operation is in progress. else "False"
**
*******************************************************************************/
jboolean NativeT4tNfcee::getT4tStatus(JNIEnv* e, jobject o) {
  LOG(DEBUG) << StringPrintf("%s:Enter: ", __func__);

  bool t4tStatus = false;
  t4tStatus = NFA_T4tNfcEeIsProcessing();

  LOG(DEBUG) << StringPrintf("%s:Exit: Returnig status : %d", __func__,
                             t4tStatus);
  return t4tStatus;
}
/*******************************************************************************
**
** Function:        isT4tNdefNfceeEmulationSupported
**
** Description:     This API will tell whether T4T NDEF NFCEE emulation is
**                  supported or not.
**
** Returns:         boolean : Indicates whether T4T NDEF NFCEE emulation is
**                            supported or not
**                  Return "True" emulation is supported. else "False"
**
*******************************************************************************/
jboolean NativeT4tNfcee::isT4tNdefNfceeEmulationSupported(JNIEnv* e,
                                                          jobject o) {
  LOG(DEBUG) << StringPrintf("%s:Enter: ", __func__);

  bool t4tStatus = false;
  t4tStatus = NFA_T4tNfcEeIsEmulationSupported();

  LOG(DEBUG) << StringPrintf("%s:Exit: ", __func__);
  return t4tStatus;
}

/*******************************************************************************
**
** Function:        t4tWriteData
**
** Description:     Write the data into the T4T file of the specific file ID
**
** Returns:         Return the size of data written
**                  Return negative number of error code
**
*******************************************************************************/
jint NativeT4tNfcee::t4tWriteData(JNIEnv* e, jobject object, jbyteArray fileId,
                                  jbyteArray data) {
  tNFA_STATUS status = NFA_STATUS_FAILED;

  T4TNFCEE_STATUS_t t4tNfceeStatus =
      validatePreCondition(OP_WRITE, fileId, data);
  if (t4tNfceeStatus != STATUS_SUCCESS) return t4tNfceeStatus;

  ScopedByteArrayRO bytes(e, fileId);
  if (bytes.size() < FILE_ID_LEN) {
    LOG(ERROR) << StringPrintf("%s:Wrong File Id", __func__);
    return ERROR_INVALID_FILE_ID;
  }

  ScopedByteArrayRO bytesData(e, data);
  if (bytesData.size() == 0x00) {
    LOG(ERROR) << StringPrintf("%s:Empty Data", __func__);
    return ERROR_EMPTY_PAYLOAD;
  }

  if (setup() != NFA_STATUS_OK) return ERROR_CONNECTION_FAILED;

  uint8_t* pFileId = NULL;
  pFileId = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&bytes[0]));

  uint8_t* pData = NULL;
  pData = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&bytesData[0]));

  jint t4tWriteReturn = STATUS_FAILED;
  {
    SyncEventGuard g(mT4tNfcEeRWCEvent);
    status = NFA_T4tNfcEeWrite(pFileId, pData, bytesData.size());
    if (status == NFA_STATUS_OK) {
      if (mT4tNfcEeRWCEvent.wait(T4TNFCEE_TIMEOUT) == false)
        t4tWriteReturn = STATUS_FAILED;
      else {
        if (mT4tOpStatus == NFA_STATUS_OK) {
          /*if status is success then return length of data written*/
          t4tWriteReturn = mReadData.len;
        } else if (mT4tOpStatus == NFA_STATUS_REJECTED) {
          t4tWriteReturn = ERROR_NDEF_VALIDATION_FAILED;
        } else if (mT4tOpStatus == NFA_T4T_STATUS_INVALID_FILE_ID) {
          t4tWriteReturn = ERROR_INVALID_FILE_ID;
        } else if (mT4tOpStatus == NFA_STATUS_READ_ONLY) {
          t4tWriteReturn = ERROR_WRITE_PERMISSION;
        } else {
          t4tWriteReturn = STATUS_FAILED;
        }
      }
    }
  }

  /*Close connection and start discovery*/
  cleanup();
  LOG(ERROR) << StringPrintf("%s:Exit: Returnig status : %d", __func__,
                             t4tWriteReturn);
  return t4tWriteReturn;
}

/*******************************************************************************
**
** Function:        t4tReadData
**
** Description:     Read the data from the T4T file of the specific file ID.
**
** Returns:         byte[] : all the data previously written to the specific
**                  file ID.
**                  Return one byte '0xFF' if the data was never written to the
**                  specific file ID,
**                  Return null if reading fails.
**
*******************************************************************************/
jbyteArray NativeT4tNfcee::t4tReadData(JNIEnv* e, jobject object,
                                       jbyteArray fileId) {
  tNFA_STATUS status = NFA_STATUS_FAILED;

  T4TNFCEE_STATUS_t t4tNfceeStatus = validatePreCondition(OP_READ, fileId);
  if (t4tNfceeStatus != STATUS_SUCCESS) return NULL;

  ScopedByteArrayRO bytes(e, fileId);
  ScopedLocalRef<jbyteArray> result(e, NULL);
  if (bytes.size() < FILE_ID_LEN) {
    LOG(ERROR) << StringPrintf("%s:Wrong File Id", __func__);
    return NULL;
  }

  if (setup() != NFA_STATUS_OK) return NULL;

  uint8_t* pFileId = NULL;
  pFileId = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&bytes[0]));

  { /*syncEvent code section*/
    SyncEventGuard g(mT4tNfcEeRWCEvent);
    sRxDataBuffer.clear();
    status = NFA_T4tNfcEeRead(pFileId);
    if ((status != NFA_STATUS_OK) ||
        (mT4tNfcEeRWCEvent.wait(T4TNFCEE_TIMEOUT) == false)) {
      LOG(ERROR) << StringPrintf("%s:Read Failed, status = 0x%X", __func__,
                                 status);
      cleanup();
      return NULL;
    }
  }

  if (sRxDataBuffer.size() > 0) {
    result.reset(e->NewByteArray(sRxDataBuffer.size()));
    if (result.get() != NULL) {
      e->SetByteArrayRegion(result.get(), 0, sRxDataBuffer.size(),
                            (const jbyte*)sRxDataBuffer.data());
    } else {
      result.reset(e->NewByteArray(0x00));
      e->SetByteArrayRegion(result.get(), 0, 0x00, (jbyte*){});
      LOG(ERROR) << StringPrintf("%s: Failed to allocate java byte array",
                                 __func__);
    }
    sRxDataBuffer.clear();
  } else if (mT4tOpStatus == NFA_T4T_STATUS_INVALID_FILE_ID) {
    result.reset(e->NewByteArray(0x00));
    e->SetByteArrayRegion(result.get(), 0, 0x00, (jbyte*){});
  }
  /*Close connection and start discovery*/
  cleanup();
  return result.release();
}

/*******************************************************************************
**
** Function:        openConnection
**
** Description:     Open T4T Nfcee Connection
**
** Returns:         Status
**
*******************************************************************************/
tNFA_STATUS NativeT4tNfcee::openConnection() {
  tNFA_STATUS status = NFA_STATUS_FAILED;
  LOG(DEBUG) << StringPrintf("%s: Enter", __func__);
  SyncEventGuard g(mT4tNfcEeEvent);
  status = NFA_T4tNfcEeOpenConnection();
  if (status == NFA_STATUS_OK) {
    if (mT4tNfcEeEvent.wait(T4TNFCEE_TIMEOUT) == false)
      status = NFA_STATUS_FAILED;
    else
      status = mT4tNfcEeEventStat;
  }
  LOG(DEBUG) << StringPrintf("%s: Exit status = 0x%02x", __func__, status);
  return status;
}

/*******************************************************************************
**
** Function:        closeConnection
**
** Description:     Close T4T Nfcee Connection
**
** Returns:         Status
**
*******************************************************************************/
tNFA_STATUS NativeT4tNfcee::closeConnection() {
  tNFA_STATUS status = NFA_STATUS_FAILED;
  LOG(DEBUG) << StringPrintf("%s: Enter", __func__);
  {
    SyncEventGuard g(mT4tNfcEeEvent);
    status = NFA_T4tNfcEeCloseConnection();
    if (status == NFA_STATUS_OK) {
      if (mT4tNfcEeEvent.wait(T4TNFCEE_TIMEOUT) == false)
        status = NFA_STATUS_FAILED;
      else
        status = mT4tNfcEeEventStat;
    }
  }

  LOG(DEBUG) << StringPrintf("%s: Exit status = 0x%02x", __func__, status);
  return status;
}

/*******************************************************************************
**
** Function:        setup
**
** Description:     stops Discovery and opens T4TNFCEE connection
**
** Returns:         Status
**
*******************************************************************************/
tNFA_STATUS NativeT4tNfcee::setup(void) {
  tNFA_STATUS status = NFA_STATUS_FAILED;
  setBusy();
  if (android::isDiscoveryStarted()) {
    android::startRfDiscovery(false);
  }

  status = openConnection();
  if (status != NFA_STATUS_OK) {
    LOG(ERROR) << StringPrintf("%s: openConnection Failed, status = 0x%X",
                               __func__, status);
    if (!android::isDiscoveryStarted()) android::startRfDiscovery(true);
    resetBusy();
  }
  return status;
}
/*******************************************************************************
**
** Function:        cleanup
**
** Description:     closes connection and starts discovery
**
** Returns:         Status
**
*******************************************************************************/
void NativeT4tNfcee::cleanup(void) {
  if (sIsNfcOffTriggered) {
    SyncEventGuard g(mT4tNfcOffEvent);
    mT4tNfcOffEvent.notifyOne();
    LOG(ERROR) << StringPrintf("%s: Nfc Off triggered", __func__);
    return;
  }
  if (closeConnection() != NFA_STATUS_OK) {
    LOG(ERROR) << StringPrintf("%s: closeConnection Failed", __func__);
  }
  if (!android::isDiscoveryStarted()) {
    android::startRfDiscovery(true);
  }
  resetBusy();
}

/*******************************************************************************
**
** Function:        validatePreCondition
**
** Description:     Runs precondition checks for requested operation
**
** Returns:         Status
**
*******************************************************************************/
T4TNFCEE_STATUS_t NativeT4tNfcee::validatePreCondition(T4TNFCEE_OPERATIONS_t op,
                                                       jbyteArray fileId,
                                                       jbyteArray data) {
  T4TNFCEE_STATUS_t t4tNfceeStatus = STATUS_SUCCESS;
  if (!android::nfcManager_isNfcActive()) {
    t4tNfceeStatus = ERROR_NFC_NOT_ON;
  } else if (sIsNfcOffTriggered) {
    t4tNfceeStatus = ERROR_NFC_OFF_TRIGGERED;
  } else if (gActivated) {
    t4tNfceeStatus = ERROR_RF_ACTIVATED;
  } else if (fileId == NULL) {
    LOG(ERROR) << StringPrintf("%s:Invalid File Id", __func__);
    t4tNfceeStatus = ERROR_INVALID_FILE_ID;
  }

  switch (op) {
    case OP_READ:
      break;
    case OP_WRITE:
      if (data == NULL) {
        LOG(ERROR) << StringPrintf("%s:Empty data", __func__);
        t4tNfceeStatus = ERROR_EMPTY_PAYLOAD;
      }
      break;
    case OP_CLEAR:
      [[fallthrough]];
    default:
      break;
  }
  return t4tNfceeStatus;
}

/*******************************************************************************
**
** Function:        t4tReadComplete
**
** Description:     Updates read data to the waiting READ API
**
** Returns:         none
**
*******************************************************************************/
void NativeT4tNfcee::t4tReadComplete(tNFA_STATUS status, tNFA_RX_DATA data) {
  mT4tOpStatus = status;
  if (status == NFA_STATUS_OK) {
    if (data.len > 0) {
      sRxDataBuffer.insert(sRxDataBuffer.end(), data.p_data,
                           data.p_data + data.len);
      LOG(DEBUG) << StringPrintf("%s: Read Data len new: %d ", __func__,
                                 data.len);
    }
  }
  SyncEventGuard g(mT4tNfcEeRWCEvent);
  mT4tNfcEeRWCEvent.notifyOne();
}

/*******************************************************************************
 **
 ** Function:        t4tWriteComplete
 **
 ** Description:     Returns write complete information
 **
 ** Returns:         none
 **
 *******************************************************************************/
void NativeT4tNfcee::t4tWriteComplete(tNFA_STATUS status, tNFA_RX_DATA data) {
  mReadData.len = 0x00;
  LOG(DEBUG) << StringPrintf("%s: Enter", __func__);
  if (status == NFA_STATUS_OK) mReadData.len = data.len;
  mT4tOpStatus = status;
  SyncEventGuard g(mT4tNfcEeRWCEvent);
  mT4tNfcEeRWCEvent.notifyOne();
}
/*******************************************************************************
 **
 ** Function:        t4tClearComplete
 **
 ** Description:     Update T4T clear data status, waiting T4tClearData API.
 **
 ** Returns:         none
 **
 *******************************************************************************/
void NativeT4tNfcee::t4tClearComplete(tNFA_STATUS status) {
  LOG(DEBUG) << StringPrintf("%s: Enter", __func__);
  mT4tOpStatus = status;
  SyncEventGuard g(mT4tNfcEeRWCEvent);
  mT4tNfcEeRWCEvent.notifyOne();
}
/*******************************************************************************
**
** Function:        t4tNfceeEventHandler
**
** Description:     Handles callback events received from lower layer
**
** Returns:         none
**
*******************************************************************************/
void NativeT4tNfcee::eventHandler(uint8_t event,
                                  tNFA_CONN_EVT_DATA* eventData) {
  switch (event) {
    case NFA_T4TNFCEE_EVT:
      LOG(DEBUG) << StringPrintf("%s: NFA_T4TNFCEE_EVT", __func__);
      {
        SyncEventGuard guard(mT4tNfcEeEvent);
        mT4tNfcEeEventStat = eventData->status;
        mT4tNfcEeEvent.notifyOne();
      }
      break;

    case NFA_T4TNFCEE_READ_CPLT_EVT:
      LOG(DEBUG) << StringPrintf("%s: NFA_T4TNFCEE_READ_CPLT_EVT", __func__);
      t4tReadComplete(eventData->status, eventData->data);
      break;

    case NFA_T4TNFCEE_WRITE_CPLT_EVT:
      LOG(DEBUG) << StringPrintf("%s: NFA_T4TNFCEE_WRITE_CPLT_EVT", __func__);
      t4tWriteComplete(eventData->status, eventData->data);
      break;

    case NFA_T4TNFCEE_CLEAR_CPLT_EVT:
      LOG(DEBUG) << StringPrintf("%s: NFA_T4TNFCEE_CLEAR_CPLT_EVT", __func__);
      t4tClearComplete(eventData->status);
      break;

    case NFA_T4TNFCEE_READ_CC_DATA_CPLT_EVT:
      LOG(DEBUG) << StringPrintf("%s: NFA_T4TNFCEE_READ_CC_DATA_CPLT_EVT",
                                 __func__);
      t4tReadComplete(eventData->status, eventData->data);
      break;

    default:
      LOG(DEBUG) << StringPrintf("%s: unknown Event", __func__);
      break;
  }
}

/*******************************************************************************
 **
 ** Function:        isT4tNfceeBusy
 **
 ** Description:     Returns True if T4tNfcee operation is ongoing else false
 **
 ** Returns:         true/false
 **
 *******************************************************************************/
bool NativeT4tNfcee::isT4tNfceeBusy(void) { return mBusy; }

/*******************************************************************************
 **
 ** Function:        setBusy
 **
 ** Description:     Sets busy flag indicating T4T operation is ongoing
 **
 ** Returns:         none
 **
 *******************************************************************************/
void NativeT4tNfcee::setBusy() { mBusy = true; }

/*******************************************************************************
 **
 ** Function:        resetBusy
 **
 ** Description:     Resets busy flag indicating T4T operation is completed
 **
 ** Returns:         none
 **
 *******************************************************************************/
void NativeT4tNfcee::resetBusy() { mBusy = false; }
/*******************************************************************************
**
** Function:        getT4TNfceeAid
**
** Description:     Get the T4T Nfcee AID.
**
** Returns:         T4T AID: vector<uint8_t>
**
*******************************************************************************/
vector<uint8_t> NativeT4tNfcee::getT4TNfceeAid() {
  LOG(DEBUG) << StringPrintf("%s:enter", __func__);

  std::vector<uint8_t> t4tNfceeAidBuf;

  if (NfcConfig::hasKey(NAME_T4T_NDEF_NFCEE_AID)) {
    t4tNfceeAidBuf = NfcConfig::getBytes(NAME_T4T_NDEF_NFCEE_AID);
  }

  LOG(DEBUG) << StringPrintf("%s:Exit", __func__);

  return t4tNfceeAidBuf;
}

/*******************************************************************************
**
** Function:        checkAndUpdateT4TAid
**
** Description:     Check and update T4T Ndef Nfcee AID.
**
** Returns:         void
**
*******************************************************************************/
void NativeT4tNfcee::checkAndUpdateT4TAid(uint8_t* t4tNdefAid,
                                          uint8_t* t4tNdefAidLen) {
  vector<uint8_t> t4tNfceeAidBuf = getT4TNfceeAid();
  if (t4tNfceeAidBuf.size() != 0) {
    uint8_t* t4tAidBuf = t4tNfceeAidBuf.data();
    *t4tNdefAidLen = t4tNfceeAidBuf.size();
    memcpy(t4tNdefAid, t4tAidBuf, *t4tNdefAidLen);
  }
}
