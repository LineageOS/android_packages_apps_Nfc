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

#include <nativehelper/ScopedLocalRef.h>

#include <vector>

#include "NfcJniUtil.h"
#include "SyncEvent.h"
#include "nfa_api.h"

typedef enum { OP_READ = 0, OP_WRITE, OP_CLEAR } T4TNFCEE_OPERATIONS_t;

typedef enum {
  STATUS_SUCCESS = 0,
  STATUS_FAILED = -1,
  ERROR_RF_ACTIVATED = -2,
  ERROR_NFC_NOT_ON = -3,
  ERROR_INVALID_FILE_ID = -4,
  ERROR_INVALID_LENGTH = -5,
  ERROR_CONNECTION_FAILED = -6,
  ERROR_EMPTY_PAYLOAD = -7,
  ERROR_NDEF_VALIDATION_FAILED = -8,
  ERROR_WRITE_PERMISSION = -9,
  ERROR_NFC_OFF_TRIGGERED = -10,
} T4TNFCEE_STATUS_t;

class NativeT4tNfcee {
 public:
  /*****************************************************************************
  **
  ** Function:        getInstance
  **
  ** Description:     Get the NativeT4tNfcee singleton object.
  **
  ** Returns:         NativeT4tNfcee object.
  **
  *******************************************************************************/
  static NativeT4tNfcee& getInstance();

  /*******************************************************************************
  **
  ** Function:        initialize
  **
  ** Description:     Initialize all member variables.
  **
  ** Returns:         None.
  **
  *******************************************************************************/
  void initialize(void);
  /*****************************************************************************
  **
  ** Function:        onNfccShutdown
  **
  ** Description:     This api shall be called in NFC OFF case.
  **
  ** Returns:         none.
  **
  *******************************************************************************/
  void onNfccShutdown();

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
  int t4tWriteData(JNIEnv* e, jobject o, jbyteArray fileId, jbyteArray data);
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
  jboolean t4tClearData(JNIEnv* e, jobject o);
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
  jboolean performT4tClearData(uint8_t* fileId);
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
   **
   *******************************************************************************/
  jboolean getT4tStatus(JNIEnv* e, jobject o);
  /*******************************************************************************
   **
   ** Function:        t4tNfceeManager_isT4tNdefNfceeEmulationSupported
   **
   ** Description:     This API will tell whether T4T NDEF NFCEE emulation is
   **                  supported or not.
   **
   ** Returns:         boolean : Indicates whether T4T NDEF NFCEE emulation is
   **                            supported or not
   **                  Return "True" when feature supported. else "False"
   **
   *******************************************************************************/
  jboolean isT4tNdefNfceeEmulationSupported(JNIEnv* e, jobject o);
  /*******************************************************************************
  **
  ** Function:        t4tReadData
  **
  ** Description:     Read the data from the T4T file of the specific file ID.
  **
  ** Returns:         byte[] : all the data previously written to the specific
  **                  file ID.
  **                  Return one byte '0xFF' if the data was never written to
  *the
  **                  specific file ID,
  **                  Return null if reading fails.
  **
  *******************************************************************************/
  jbyteArray t4tReadData(JNIEnv* e, jobject o, jbyteArray fileId);

  /*******************************************************************************
  **
  ** Function:        t4tReadComplete
  **
  ** Description:     Updates read data to the waiting READ API
  **
  ** Returns:         none
  **
  *******************************************************************************/
  void t4tReadComplete(tNFA_STATUS status, tNFA_RX_DATA data);

  /*******************************************************************************
   **
   ** Function:        t4tWriteComplete
   **
   ** Description:     Returns write complete information
   **
   ** Returns:         none
   **
   *******************************************************************************/
  void t4tWriteComplete(tNFA_STATUS status, tNFA_RX_DATA data);
  /*******************************************************************************
   **
   ** Function:        t4tClearComplete
   **
   ** Description:     Update T4T clear data status, waiting T4tClearData API.
   **
   ** Returns:         none
   **
   *******************************************************************************/
  void t4tClearComplete(tNFA_STATUS status);

  /*******************************************************************************
   **
   ** Function:        isT4tNfceeBusy
   **
   ** Description:     Returns True if T4tNfcee operation is ongoing else false
   **
   ** Returns:         true/false
   **
   *******************************************************************************/
  bool isT4tNfceeBusy(void);

  /*******************************************************************************
  **
  ** Function:        t4tNfceeEventHandler
  **
  ** Description:     Handles callback events received from lower layer
  **
  ** Returns:         none
  **
  *******************************************************************************/
  void eventHandler(uint8_t event, tNFA_CONN_EVT_DATA* eventData);
  /*******************************************************************************
  **
  ** Function:        checkAndUpdateT4TAid
  **
  ** Description:     Check and update T4T Ndef Nfcee AID.
  **
  ** Returns:         void
  **
  *******************************************************************************/
  void checkAndUpdateT4TAid(uint8_t* t4tAid, uint8_t* t4tNdefAidLen);

 private:
  bool mBusy;
  static NativeT4tNfcee sNativeT4tNfceeInstance;
  static bool sIsNfcOffTriggered;
  SyncEvent mT4tNfcOffEvent;
  SyncEvent mT4tNfcEeRWCEvent;  // Read, Write, & Clear event
  SyncEvent mT4tNfcEeEvent;
  tNFA_RX_DATA mReadData;
  tNFA_STATUS mT4tOpStatus = NFA_STATUS_FAILED;
  tNFA_STATUS mT4tNfcEeEventStat = NFA_STATUS_FAILED;
  std::vector<uint8_t> sRxDataBuffer;
  NativeT4tNfcee();

  /*******************************************************************************
  **
  ** Function:        openConnection
  **
  ** Description:     Open T4T Nfcee Connection
  **
  ** Returns:         Status
  **
  *******************************************************************************/
  tNFA_STATUS openConnection();

  /*******************************************************************************
  **
  ** Function:        closeConnection
  **
  ** Description:     Close T4T Nfcee Connection
  **
  ** Returns:         Status
  **
  *******************************************************************************/
  tNFA_STATUS closeConnection();

  /*******************************************************************************
  **
  ** Function:        setup
  **
  ** Description:     stops Discovery and opens T4TNFCEE connection
  **
  ** Returns:         Status
  **
  *******************************************************************************/
  tNFA_STATUS setup(void);

  /*******************************************************************************
  **
  ** Function:        cleanup
  **
  ** Description:     closes connection and starts discovery
  **
  ** Returns:         Status
  **
  *******************************************************************************/
  void cleanup(void);

  /*******************************************************************************
  **
  ** Function:        validatePreCondition
  **
  ** Description:     Runs precondition checks for requested operation
  **
  ** Returns:         Status
  **
  *******************************************************************************/
  T4TNFCEE_STATUS_t validatePreCondition(T4TNFCEE_OPERATIONS_t op,
                                         jbyteArray fileId,
                                         jbyteArray data = nullptr);

  /*******************************************************************************
   **
   ** Function:        setBusy
   **
   ** Description:     Sets busy flag indicating T4T operation is ongoing
   **
   ** Returns:         none
   **
   *******************************************************************************/
  void setBusy();

  /*******************************************************************************
   **
   ** Function:        resetBusy
   **
   ** Description:     Resets busy flag indicating T4T operation is completed
   **
   ** Returns:         none
   **
   *******************************************************************************/
  void resetBusy();
  /*******************************************************************************
  **
  ** Function:        getT4TNfceeAid
  **
  ** Description:     Get the T4T Nfcee AID.
  **
  ** Returns:         T4T AID: vector<uint8_t>
  **
  *******************************************************************************/
  std::vector<uint8_t> getT4TNfceeAid();
};
