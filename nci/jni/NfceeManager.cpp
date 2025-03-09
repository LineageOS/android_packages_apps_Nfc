/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include "NfceeManager.h"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <errno.h>
#include <nativehelper/ScopedLocalRef.h>

#include "nfc_config.h"

using android::base::StringPrintf;

NfceeManager NfceeManager::sNfceeManager;

/*******************************************************************************
**
** Function:        NfceeManager
**
** Description:     Initialize member variables.
**
** Returns:         None
**
*******************************************************************************/
NfceeManager::NfceeManager() : mNumEePresent(0) {
  mActualNumEe = MAX_NUM_NFCEE;
  eseName = "eSE";
  uiccName = "SIM";
  memset(&mNfceeData_t, 0, sizeof(mNfceeData));
}

/*******************************************************************************
**
** Function:        ~NfceeManager
**
** Description:     Release all resources.
**
** Returns:         None
**
*******************************************************************************/
NfceeManager::~NfceeManager() {}

/*******************************************************************************
**
** Function:        getInstance
**
** Description:     Get the singleton of this object.
**
** Returns:         Reference to this object.
**
*******************************************************************************/
NfceeManager& NfceeManager::getInstance() { return sNfceeManager; }

/*******************************************************************************
**
** Function:        getActiveNfceeList
**
** Description:     Get the list of Activated NFCEE.
**                  e: Java Virtual Machine.
**
** Returns:         List of Activated NFCEE.
**
*******************************************************************************/
jobject NfceeManager::getActiveNfceeList(JNIEnv* e) {
  ScopedLocalRef<jclass> hashMapClass(e, e->FindClass(mHashMapClassName));
  jmethodID hashMapConstructor =
      e->GetMethodID(hashMapClass.get(), "<init>", "()V");
  jmethodID hashMapPut = e->GetMethodID(
      hashMapClass.get(), "put",
      "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
  jobject nfceeHashMaptObj =
      e->NewObject(hashMapClass.get(), hashMapConstructor);
  ScopedLocalRef<jclass> integerClass(e, e->FindClass("java/lang/Integer"));
  jmethodID integerConstructor =
      e->GetMethodID(integerClass.get(), "<init>", "(I)V");
  if (!getNFCEeInfo()) return (nfceeHashMaptObj);

  vector<uint8_t> eSERoute;
  vector<uint8_t> uiccRoute;
  map<uint8_t, std::string> nfceeMap;

  if (NfcConfig::hasKey(NAME_OFFHOST_ROUTE_ESE)) {
    eSERoute = NfcConfig::getBytes(NAME_OFFHOST_ROUTE_ESE);
  }

  if (NfcConfig::hasKey(NAME_OFFHOST_ROUTE_UICC)) {
    uiccRoute = NfcConfig::getBytes(NAME_OFFHOST_ROUTE_UICC);
  }

  for (uint8_t i = 0; i < eSERoute.size(); ++i) {
    nfceeMap[eSERoute[i]] = eseName + std::to_string(i + 1);
  }

  for (uint8_t i = 0; i < uiccRoute.size(); ++i) {
    nfceeMap[uiccRoute[i]] = uiccName + std::to_string(i + 1);
  }

  for (int i = 0; i < mNfceeData_t.mNfceePresent; i++) {
    uint8_t id = (mNfceeData_t.mNfceeID[i] & ~NFA_HANDLE_GROUP_EE);
    uint8_t status = mNfceeData_t.mNfceeStatus[i];
    if ((nfceeMap.find(id) != nfceeMap.end()) &&
        (status == NFC_NFCEE_STATUS_ACTIVE)) {
      jstring element = e->NewStringUTF(nfceeMap[id].c_str());
      jobject jtechmask = e->NewObject(integerClass.get(), integerConstructor,
                                       mNfceeData_t.mNfceeTechMask[i]);
      e->CallObjectMethod(nfceeHashMaptObj, hashMapPut, element, jtechmask);
      e->DeleteLocalRef(element);
    }
  }
  return nfceeHashMaptObj;
}

/*******************************************************************************
**
** Function:        getNFCEeInfo
**
** Description:     Get latest information about execution
**                  environments from stack.
** Returns:         True if at least 1 EE is available.
**
*******************************************************************************/
bool NfceeManager::getNFCEeInfo() {
  static const char fn[] = "getNFCEeInfo";
  LOG(INFO) << StringPrintf("%s: enter", fn);
  tNFA_STATUS nfaStat = NFA_STATUS_FAILED;
  mNumEePresent = 0x00;
  memset(&mNfceeData_t, 0, sizeof(mNfceeData_t));

  /* Reading latest NFCEE info  in case it is updated */
  if ((nfaStat = NFA_EeGetInfo(&mActualNumEe, mEeInfo)) != NFA_STATUS_OK) {
    LOG(ERROR) << StringPrintf("%s: fail get info; error=0x%X", fn, nfaStat);
    mActualNumEe = 0;
  } else {
    LOG(INFO) << StringPrintf("%s: num NFCEE discovered: %u", fn, mActualNumEe);
    if (mActualNumEe != 0) {
      for (uint8_t xx = 0; xx < mActualNumEe; xx++) {
        tNFA_TECHNOLOGY_MASK eeTechnology = 0x00;
        if (mEeInfo[xx].ee_interface[0] != NCI_NFCEE_INTERFACE_HCI_ACCESS)
          mNumEePresent++;

        mNfceeData_t.mNfceeID[xx] = mEeInfo[xx].ee_handle;
        mNfceeData_t.mNfceeStatus[xx] = mEeInfo[xx].ee_status;
        if (mEeInfo[xx].la_protocol) eeTechnology |= NFA_TECHNOLOGY_MASK_A;
        if (mEeInfo[xx].lb_protocol) eeTechnology |= NFA_TECHNOLOGY_MASK_B;
        if (mEeInfo[xx].lf_protocol) eeTechnology |= NFA_TECHNOLOGY_MASK_F;
        mNfceeData_t.mNfceeTechMask[xx] = eeTechnology;
      }
    }
  }
  LOG(INFO) << StringPrintf("%s: exit; mActualNumEe=%d, mNumEePresent=%d", fn,
                            mActualNumEe, mNumEePresent);
  mNfceeData_t.mNfceePresent = mNumEePresent;
  return (mActualNumEe != 0);
}
