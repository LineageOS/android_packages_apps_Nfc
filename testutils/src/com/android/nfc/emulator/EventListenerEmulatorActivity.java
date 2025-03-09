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

import android.content.ComponentName;
import android.nfc.cardemulation.CardEmulation;
import android.os.Bundle;

import android.util.Log;
import androidx.annotation.NonNull;
import com.android.nfc.utils.HceUtils;
import com.android.nfc.service.TransportService1;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class EventListenerEmulatorActivity extends BaseEmulatorActivity {

    private ArrayList<Boolean> mFieldChanged = new ArrayList<>();
    private ArrayList<String> mAidNotRouted = new ArrayList<>();

    private CardEmulation.NfcEventListener mEventListener = new CardEmulation.NfcEventListener() {
        @Override
        public void onRemoteFieldChanged(boolean isDetected) {
            mFieldChanged.add(isDetected);
        }

        public void onAidNotRouted(@NonNull String aid) {
            mAidNotRouted.add(aid);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setupServices(TransportService1.COMPONENT);
    }

    public void onResume() {
        super.onResume();
        ComponentName serviceName =
                new ComponentName(this.getApplicationContext(), TransportService1.class);
        mCardEmulation.setPreferredService(this, serviceName);
        waitForPreferredService();

        mFieldChanged.clear();
        mAidNotRouted.clear();
        registerEventListener(mEventListener);
    }

    @Override
    public void onPause() {
        super.onPause();

        mCardEmulation.unsetPreferredService(this);
    }

    @Override
    public void onApduSequenceComplete(ComponentName component, long duration) {
        boolean success = mAidNotRouted.equals(Arrays.asList(HceUtils.ACCESS_AID));
        success = success && TransportService1.COMPONENT.equals(component);
        success = success && mFieldChanged.equals(Arrays.asList(true, false, true));

        if (success) {
            setTestPassed();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mCardEmulation.unregisterNfcEventListener(mEventListener);
    }

    @Override
    public ComponentName getPreferredServiceComponent(){
        return TransportService1.COMPONENT;
    }
}
