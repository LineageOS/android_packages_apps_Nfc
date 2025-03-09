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

package com.android.nfc.emulatorapp

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel

class EmulatorViewModel : ViewModel() {
  private val _uiState: MutableLiveData<EmulatorUiState> = MutableLiveData(EmulatorUiState())
  val uiState: LiveData<EmulatorUiState> = _uiState

  fun addLog(newLog: String) {
    val existingLog = _uiState.value?.transactionLog
    _uiState.value = uiState.value?.copy(transactionLog = "$existingLog\n\n$newLog")
  }

  fun setSnoopFile(file: String) {
    _uiState.value = uiState.value?.copy(snoopFile = file)
  }
}

data class EmulatorUiState(val snoopFile: String = "", val transactionLog: String = "")

data class ApduPair(val command: String, val response: String)