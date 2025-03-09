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

import android.nfc.cardemulation.HostApduService
import android.nfc.cardemulation.PollingFrame
import android.os.Bundle
import androidx.lifecycle.MutableLiveData
import java.math.BigInteger

/**
 * Implementation of HostApduService that receives APDU commands from the reader and sends back
 * responses.
 */
class EmulatorHostApduService : HostApduService() {

  override fun processPollingFrames(frames: List<PollingFrame>) {
    for (frame in frames) {
      viewModel.addLog("Received polling frame ${frame.toString()}")
    }
  }

  /**
   * Processes the APDU command received from the reader and sends back a response. If the command
   * was not found in the original snoop log, a failure response is sent instead.
   */
  override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
    val command = commandApdu?.toHexString()
    val responseList = apdus.value?.get(command)
    if (responseList != null && responseList.isNotEmpty()) {
      val response = responseList.removeAt(0)
      viewModel.addLog(createApduLog(command, response))
      return if (response.isEmpty()) ByteArray(0) else BigInteger(response, 16).toByteArray()
    } else {
      viewModel.addLog(createApduLog(command, FAILURE_RESPONSE.toHexString()))
      return FAILURE_RESPONSE
    }
  }

  override fun onDeactivated(reason: Int) {
    if (reason == DEACTIVATION_LINK_LOSS) {
      viewModel.addLog("Service has been deactivated due to NFC link loss")
    } else { // DEACTIVATION_DESELECTED
      viewModel.addLog("Service has been deactivated due to a different AID being selected")
    }
  }

  private fun ByteArray.toHexString(): String {
    return this.joinToString("") { java.lang.String.format("%02x", it) }
  }

  private fun createApduLog(command: String?, response: String): String {
    if (command == null) {
      return "Received null command"
    }
    if (responseDecoder.containsKey(response.lowercase())) {
      return "Received command: $command\n\n     Sent response: ${responseDecoder[response]}"
    } else {
      return "Received command: $command\n\n     Sent response: $response"
    }
  }

  companion object {
    private const val TAG = "EmulatorHostApduServiceLog"
    private val FAILURE_RESPONSE = BigInteger("6f00", 16).toByteArray()
    val apdus = MutableLiveData<Map<String, MutableList<String>>>()
    val responseDecoder = mapOf("6f00" to "Failure", "6a82" to "AID not found")
    lateinit var viewModel: EmulatorViewModel
  }
}