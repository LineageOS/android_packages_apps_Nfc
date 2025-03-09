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

import android.content.ComponentName
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity;
import androidx.activity.viewModels
import androidx.lifecycle.Observer
import com.google.android.material.button.MaterialButton
import com.google.android.material.textview.MaterialTextView
import java.io.BufferedReader
import java.io.InputStreamReader

class MainActivity : AppCompatActivity() {

  private val viewModel: EmulatorViewModel by viewModels()

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)

    val observer =
      Observer<EmulatorUiState> { state ->
        val replayedFileText = "${getString(R.string.replayed_file_text)} ${state.snoopFile}"
        findViewById<MaterialTextView>(R.id.snoop_file_name).text = replayedFileText
        val logText = "${getString(R.string.log_text)}\n${state.transactionLog}"
        findViewById<MaterialTextView>(R.id.transaction_log).text = logText
      }
    viewModel.uiState.observe(this, observer)
    EmulatorHostApduService.viewModel = viewModel

    findViewById<MaterialButton>(R.id.service_button).setOnClickListener {
      startHostApduService()
      findViewById<MaterialButton>(R.id.service_button).isEnabled = false
    }

    val snoopFile = intent.getStringExtra(SNOOP_FILE_FLAG)
    if (snoopFile != null) {
      val apdus = openAndParseFile(PARSED_FILES_DIR + snoopFile)
      updateService(apdus)
      viewModel.setSnoopFile(snoopFile)
    }
  }

  private fun startHostApduService() {
    packageManager.setComponentEnabledSetting(
      ComponentName(this, EmulatorHostApduService::class.java),
      PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
      PackageManager.DONT_KILL_APP,
    )
  }

  /** Opens the snoop file and extracts all APDU commands and responses. */
  private fun openAndParseFile(file: String): List<ApduPair> {
    val apduPairs = mutableListOf<ApduPair>()
    val text = BufferedReader(InputStreamReader(getAssets().open(file))).use { it.readText() }
    val lines = text.split("\n").toTypedArray()
    for (line in lines) {
      val arr = line.split(";").toTypedArray()
      if (arr.size != 2) { // Should contain commands, followed by responses
        continue
      }
      val commands = arr[0].split(",").toTypedArray()
      val responses = arr[1].split(",").toTypedArray()
      if (commands.size != responses.size) {
        continue
      }
      for (i in commands.indices) {
        val command = standardize(commands[i])
        val response = standardize(responses[i])
        apduPairs.add(ApduPair(command, response))
      }
    }
    return apduPairs
  }

  private fun standardize(s: String): String {
    return s.replace("[", "").replace("]", "").replace("\'", "").replace(" ", "")
  }

  /** Updates EmulatorHostApduService with the given APDU commands and responses. */
  private fun updateService(apdus: List<ApduPair>) {
    val hashmap: HashMap<String, MutableList<String>> = HashMap()
    for (apduPair in apdus) {
      val existingList = hashmap[apduPair.command]
      if (existingList == null) {
        hashmap[apduPair.command] = mutableListOf(apduPair.response)
      } else {
        existingList.add(apduPair.response)
        hashmap[apduPair.command] = existingList
      }
    }
    EmulatorHostApduService.apdus.postValue(hashmap)
  }

  companion object {
    private const val TAG = "EmulatorHostApduServiceLog"
    private const val SNOOP_FILE_FLAG = "snoop_file"
    private const val PARSED_FILES_DIR = "src/com/android/nfc/emulatorapp/parsed_files/"
  }
}