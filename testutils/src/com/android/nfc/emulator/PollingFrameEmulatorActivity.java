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
package com.android.nfc.emulator;

import android.content.Intent;
import android.nfc.cardemulation.PollingFrame;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

/**
 * This activity is used to test the polling frame feature.
 *
 * <p>This activity will register a broadcast receiver to receive the polling frame information from
 * the polling loop service.
 */
public class PollingFrameEmulatorActivity extends PollingLoopEmulatorActivity {
    private static final String TAG = "PollingFrameEmulatorActivity";
    public static final String POLLING_FRAME_OFF_DETECTED =
            PACKAGE_NAME + ".POLLING_FRAME_OFF_DETECTED";

    private List<PollingFrame> pollingFrames = new ArrayList<PollingFrame>();

    public PollingFrame[] getPollingFrames() {
        PollingFrame[] result = pollingFrames.stream().toArray(PollingFrame[]::new);
        this.pollingFrames = new ArrayList<PollingFrame>();
        return result;
    }

    @Override
    void processPollingFrames(List<PollingFrame> frames) {
        Log.d(TAG, "processPollingFrames of size " + frames.size());
        pollingFrames.addAll(frames);

        if (frames.stream()
                .anyMatch(frame -> frame.getType() == PollingFrame.POLLING_LOOP_TYPE_OFF)) {
            Intent intent = new Intent(POLLING_FRAME_OFF_DETECTED);
            sendBroadcast(intent);
        }
    }
}
