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
#pragma once
#include "NfcJniUtil.h"

namespace android {
extern jmethodID gCachedNfcManagerNotifyNdefMessageListeners;
extern jmethodID gCachedNfcManagerNotifyTransactionListeners;

/*
 * host-based card emulation
 */
extern jmethodID gCachedNfcManagerNotifyHostEmuActivated;
extern jmethodID gCachedNfcManagerNotifyHostEmuData;
extern jmethodID gCachedNfcManagerNotifyHostEmuDeactivated;

extern jmethodID gCachedNfcManagerNotifyEeListenActivated;

extern jmethodID gCachedNfcManagerNotifyEeUpdated;
extern jmethodID gCachedNfcManagerNotifyTagDiscovered;
extern jmethodID gCachedNfcManagerNotifyWlcStopped;

extern jmethodID gCachedNfcManagerNotifyEeAidSelected;
extern jmethodID gCachedNfcManagerNotifyEeProtocolSelected;
extern jmethodID gCachedNfcManagerNotifyEeTechSelected;

extern const char* gNativeNfcTagClassName;
extern const char* gNativeNfcManagerClassName;
extern const char* gNativeT4tNfceeClassName;
}  // namespace android
