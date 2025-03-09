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

package com.android.nfc.handover;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.assertNotNull;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.content.Intent;

import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class ConfirmConnectActivityTest {
    private Context context;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    }

    @Test
    public void testOnCreate_createAlertDialog() {
        Intent intent = new Intent(context,
                ConfirmConnectActivity.class);
        BluetoothDevice mockDevice = BluetoothAdapter.getDefaultAdapter()
                .getRemoteDevice("00:11:22:33:44:55");
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mockDevice);
        intent.putExtra(BluetoothDevice.EXTRA_NAME, "Mock Device");

        try (ActivityScenario<ConfirmConnectActivity> scenario = ActivityScenario.launch(intent)) {
            scenario.onActivity(activity -> {
                assertNotNull(activity.mAlert);
            });
            assertThat(scenario.getState()).isAtLeast(Lifecycle.State.CREATED);
        }
    }

    @Test
    public void testOnCreate_NullBtDeviceFinishActivity() {
        Intent intent = new Intent(context,
                ConfirmConnectActivity.class);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, (android.os.Parcelable) null);
        intent.putExtra(BluetoothDevice.EXTRA_NAME, "Mock Device");

        try (ActivityScenario<ConfirmConnectActivity> scenario = ActivityScenario.launch(intent)) {
            assertThat(scenario.getState()).isAtLeast(Lifecycle.State.DESTROYED);
        }
    }

    @Test
    public void testOnDestroy() {
        Intent intent = new Intent(context,
                ConfirmConnectActivity.class);
        BluetoothDevice mockDevice = BluetoothAdapter.getDefaultAdapter()
                .getRemoteDevice("00:11:22:33:44:55");
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mockDevice);
        intent.putExtra(BluetoothDevice.EXTRA_NAME, "Mock Device");

        try (ActivityScenario<ConfirmConnectActivity> scenario = ActivityScenario.launch(intent)) {
            scenario.onActivity(Activity::finish);
            assertThat(scenario.getState()).isAtLeast(Lifecycle.State.DESTROYED);
        }
    }
}
