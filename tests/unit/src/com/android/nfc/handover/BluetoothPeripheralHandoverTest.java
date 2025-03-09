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

import static com.android.nfc.handover.BluetoothPeripheralHandover.ACTION_ALLOW_CONNECT;
import static com.android.nfc.handover.BluetoothPeripheralHandover.ACTION_CONNECT;
import static com.android.nfc.handover.BluetoothPeripheralHandover.ACTION_DENY_CONNECT;
import static com.android.nfc.handover.BluetoothPeripheralHandover.ACTION_DISCONNECT;
import static com.android.nfc.handover.BluetoothPeripheralHandover.ACTION_INIT;
import static com.android.nfc.handover.BluetoothPeripheralHandover.RESULT_CONNECTED;
import static com.android.nfc.handover.BluetoothPeripheralHandover.RESULT_DISCONNECTED;
import static com.android.nfc.handover.BluetoothPeripheralHandover.RESULT_PENDING;
import static com.android.nfc.handover.BluetoothPeripheralHandover.STATE_BONDING;
import static com.android.nfc.handover.BluetoothPeripheralHandover.STATE_COMPLETE;
import static com.android.nfc.handover.BluetoothPeripheralHandover.STATE_CONNECTING;
import static com.android.nfc.handover.BluetoothPeripheralHandover.STATE_DISCONNECTING;
import static com.android.nfc.handover.BluetoothPeripheralHandover.STATE_INIT;
import static com.android.nfc.handover.BluetoothPeripheralHandover.STATE_INIT_COMPLETE;
import static com.android.nfc.handover.BluetoothPeripheralHandover.STATE_WAITING_FOR_BOND_CONFIRMATION;
import static com.android.nfc.handover.BluetoothPeripheralHandover.STATE_WAITING_FOR_PROXIES;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothHidHost;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.OobData;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.media.AudioManager;
import android.os.ParcelUuid;
import android.provider.Settings;
import android.widget.Toast;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.android.dx.mockito.inline.extended.ExtendedMockito;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.MockitoSession;
import org.mockito.quality.Strictness;

import java.util.Collections;

@RunWith(AndroidJUnit4.class)
public class BluetoothPeripheralHandoverTest {

    @Mock
    BluetoothPeripheralHandover mBluetoothPeripheralHandover;
    @Mock
    private Context mockContext;
    @Mock
    private BluetoothDevice mockDevice;
    @Mock
    private BluetoothAdapter mockBluetoothAdapter;
    @Mock
    private AudioManager mockAudioManager;
    @Mock
    private ContentResolver mockContentResolver;
    @Mock
    private BluetoothClass mockBtClass;
    @Mock
    private BluetoothPeripheralHandover.Callback mockCallback;
    @Mock
    private BluetoothHidHost mockInput;
    @Mock
    private Toast mockToast;
    @Mock
    OobData mockOobData;
    @Mock
    private Resources mockResources;
    @Mock
    BluetoothHeadset mockHeadset;
    @Mock
    Intent mockIntent;
    @Mock
    BluetoothA2dp mockA2dp;
    private MockitoSession mStaticMockSession;
    BluetoothPeripheralHandover bluetoothPeripheralHandover;

    @Before
    public void setUp() {
        mStaticMockSession = ExtendedMockito.mockitoSession().mockStatic(
                Settings.Global.class).mockStatic(Toast.class).strictness(
                Strictness.LENIENT).startMocking();
        MockitoAnnotations.initMocks(this);
        when(mockContext.getSystemService(AudioManager.class)).thenReturn(mockAudioManager);
        when(mockContext.getContentResolver()).thenReturn(mockContentResolver);
        when(mockContext.getResources()).thenReturn(mockResources);
        when(Toast.makeText(any(), anyString(), anyInt())).thenReturn(mockToast);
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_LE);
    }

    private BluetoothPeripheralHandover createBluetoothPerHandOvrInstance(int transport) {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {

            ParcelUuid[] testUuids = new ParcelUuid[]{};
            boolean testHasHeadsetCapability = true;
            boolean testHasA2dpCapability = true;

            when(mBluetoothPeripheralHandover.hasHeadsetCapability(testUuids,
                    mockBtClass)).thenReturn(testHasHeadsetCapability);
            when(mBluetoothPeripheralHandover.hasA2dpCapability(testUuids, mockBtClass)).thenReturn(
                    testHasA2dpCapability);
            when(Settings.Global.getInt(mockContentResolver, Settings.Global.DEVICE_PROVISIONED,
                    0)).thenReturn(0);

            bluetoothPeripheralHandover = new BluetoothPeripheralHandover(mockContext, mockDevice,
                    "Test Device", transport, mockOobData, new ParcelUuid[]{}, mockBtClass,
                    mockCallback, mockBluetoothAdapter);
        });
        return bluetoothPeripheralHandover;
    }

    @After
    public void tearDown() {
        mStaticMockSession.finishMocking();
    }

    @Test
    public void testComplete() {
        bluetoothPeripheralHandover.complete(true);
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
        verify(mockCallback).onBluetoothPeripheralHandoverComplete(true);
    }

    @Test
    public void testComplete_mA2dp() {
        bluetoothPeripheralHandover.mA2dp = mockA2dp;
        bluetoothPeripheralHandover.complete(true);

        assertNull(bluetoothPeripheralHandover.mA2dp);
        verify(mockCallback).onBluetoothPeripheralHandoverComplete(true);
    }

    @Test
    public void testComplete_mInput() {
        bluetoothPeripheralHandover.mInput = mockInput;
        bluetoothPeripheralHandover.complete(true);

        assertNull(bluetoothPeripheralHandover.mInput);
        verify(mockCallback).onBluetoothPeripheralHandoverComplete(true);
    }

    @Test
    public void testComplete_mHeadset() {
        bluetoothPeripheralHandover.mHeadset = mockHeadset;
        bluetoothPeripheralHandover.complete(true);

        assertNull(bluetoothPeripheralHandover.mHeadset);
    }

    @Test
    public void testNextStepConnect_STATE_INIT_COMPLETE() {
        bluetoothPeripheralHandover.mState = STATE_INIT_COMPLETE;
        when(mockDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDING);

        bluetoothPeripheralHandover.nextStepConnect();
        assertEquals(STATE_WAITING_FOR_BOND_CONFIRMATION, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStepConnect_STATE_INIT_COMPLETE_TRANSPORT_LE() {
        bluetoothPeripheralHandover.mState = STATE_INIT_COMPLETE;
        when(mockDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDED);

        bluetoothPeripheralHandover.nextStepConnect();
        assertEquals(STATE_WAITING_FOR_BOND_CONFIRMATION, bluetoothPeripheralHandover.mState);
        verify(mockDevice).removeBond();
    }

    @Test
    public void testNextStepConnect_STATE_WAITING_FOR_BOND_CONFIRMATION() {
        bluetoothPeripheralHandover.mState = STATE_WAITING_FOR_BOND_CONFIRMATION;
        bluetoothPeripheralHandover.mRetryCount = 1;
        bluetoothPeripheralHandover.mOobData = null;
        when(mockDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDING);
        when(mockDevice.createBond(anyInt())).thenReturn(true);

        bluetoothPeripheralHandover.nextStepConnect();
        assertEquals(STATE_BONDING, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStepConnect_STATE_BONDING_RETRY_CONNECT_WAIT_TIME_MS() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        bluetoothPeripheralHandover.mHeadset = mockHeadset;
        bluetoothPeripheralHandover.mA2dp = mockA2dp;
        bluetoothPeripheralHandover.mState = STATE_BONDING;
        bluetoothPeripheralHandover.mIsHeadsetAvailable = true;
        bluetoothPeripheralHandover.mIsA2dpAvailable = true;
        bluetoothPeripheralHandover.mRetryCount = 1;
        when(mockHeadset.getConnectionState(mockDevice)).thenReturn(
                BluetoothProfile.STATE_CONNECTING);
        when(mockA2dp.getConnectionState(mockDevice)).thenReturn(BluetoothProfile.STATE_CONNECTING);

        bluetoothPeripheralHandover.nextStepConnect();
        assertEquals(RESULT_PENDING, bluetoothPeripheralHandover.mHfpResult);
        assertEquals(RESULT_PENDING, bluetoothPeripheralHandover.mA2dpResult);
        assertEquals(STATE_CONNECTING, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStepConnect_STATE_BONDING_mRetryCount_Zero() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        bluetoothPeripheralHandover.mHeadset = mockHeadset;
        bluetoothPeripheralHandover.mA2dp = mockA2dp;
        bluetoothPeripheralHandover.mState = STATE_BONDING;
        bluetoothPeripheralHandover.mIsHeadsetAvailable = true;
        bluetoothPeripheralHandover.mIsA2dpAvailable = true;
        bluetoothPeripheralHandover.mRetryCount = 0;
        when(mockHeadset.getConnectionState(mockDevice)).thenReturn(
                BluetoothProfile.STATE_CONNECTING);
        when(mockA2dp.getConnectionState(mockDevice)).thenReturn(BluetoothProfile.STATE_CONNECTING);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepConnect();
        assertEquals(RESULT_PENDING, bluetoothPeripheralHandover.mHfpResult);
        assertEquals(RESULT_PENDING, bluetoothPeripheralHandover.mA2dpResult);
        assertEquals(STATE_CONNECTING, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStepConnect_STATE_BONDING_TRANSPORT_LE_STATE_CONNECTING() {
        bluetoothPeripheralHandover.mState = STATE_BONDING;
        bluetoothPeripheralHandover.mInput = mockInput;
        when(mockInput.getConnectionState(mockDevice)).thenReturn(
                BluetoothProfile.STATE_CONNECTING);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepConnect();
        assertEquals(RESULT_PENDING, bluetoothPeripheralHandover.mHidResult);
        assertEquals(STATE_CONNECTING, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStepConnect_STATE_BONDING_TRANSPORT_LE_STATE_CONNECTED() {
        bluetoothPeripheralHandover.mState = STATE_BONDING;
        bluetoothPeripheralHandover.mInput = mockInput;
        when(mockInput.getConnectionState(mockDevice)).thenReturn(BluetoothProfile.STATE_CONNECTED);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepConnect();
        assertEquals(RESULT_CONNECTED, bluetoothPeripheralHandover.mHidResult);
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
        verify(mockCallback).onBluetoothPeripheralHandoverComplete(anyBoolean());
    }

    @Test
    public void testNextStepConnect_STATE_BONDING_notTRANSPORT_LE_HeadsetNotAvailable() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        bluetoothPeripheralHandover.mHeadset = mockHeadset;
        bluetoothPeripheralHandover.mA2dp = mockA2dp;
        bluetoothPeripheralHandover.mState = STATE_BONDING;
        bluetoothPeripheralHandover.mIsHeadsetAvailable = false;
        bluetoothPeripheralHandover.mIsA2dpAvailable = false;
        when(mockHeadset.getConnectionState(mockDevice)).thenReturn(
                BluetoothProfile.STATE_CONNECTING);
        when(mockA2dp.getConnectionState(mockDevice)).thenReturn(BluetoothProfile.STATE_CONNECTING);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepConnect();
        assertEquals(RESULT_DISCONNECTED, bluetoothPeripheralHandover.mHfpResult);
        assertEquals(RESULT_DISCONNECTED, bluetoothPeripheralHandover.mA2dpResult);
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStepConnect_STATE_BONDING_notTRANSPORT_LE_STATE_CONNECTED() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        bluetoothPeripheralHandover.mHeadset = mockHeadset;
        bluetoothPeripheralHandover.mA2dp = mockA2dp;
        when(mockHeadset.getConnectionState(mockDevice)).thenReturn(
                BluetoothProfile.STATE_CONNECTED);
        bluetoothPeripheralHandover.mState = STATE_BONDING;
        when(mockA2dp.getConnectionState(mockDevice)).thenReturn(BluetoothProfile.STATE_CONNECTED);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepConnect();
        assertEquals(RESULT_CONNECTED, bluetoothPeripheralHandover.mHfpResult);
        assertEquals(RESULT_CONNECTED, bluetoothPeripheralHandover.mA2dpResult);
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStepConnect_STATE_CONNECTING_TRANSPORT_LE_RESULT_DISCONNECTED() {
        bluetoothPeripheralHandover.mState = STATE_CONNECTING;
        bluetoothPeripheralHandover.mHidResult = RESULT_DISCONNECTED;
        when(mockInput.getConnectionState(mockDevice)).thenReturn(BluetoothProfile.STATE_CONNECTED);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepConnect();
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
        verify(mockCallback).onBluetoothPeripheralHandoverComplete(anyBoolean());
    }

    @Test
    public void testHasA2dpCapability_withUuidsContainingA2dpSink() {
        ParcelUuid[] uuids = new ParcelUuid[]{BluetoothUuid.A2DP_SINK};
        boolean result = bluetoothPeripheralHandover.hasA2dpCapability(uuids, null);
        assertTrue(result);
    }

    @Test
    public void testHasA2dpCapability_withUuidsContainingAdvAudioDist() {
        ParcelUuid[] uuids = new ParcelUuid[]{BluetoothUuid.ADV_AUDIO_DIST};

        boolean result = bluetoothPeripheralHandover.hasA2dpCapability(uuids, null);
        assertTrue(result);
    }

    @Test
    public void testHasA2dpCapability_withBluetoothClassMatchingA2dp() {
        BluetoothClass mockBtClass = mock(BluetoothClass.class);
        when(mockBtClass.doesClassMatch(BluetoothClass.PROFILE_A2DP)).thenReturn(true);

        boolean result = bluetoothPeripheralHandover.hasA2dpCapability(null, mockBtClass);
        assertTrue(result);
    }

    @Test
    public void testHasA2dpCapability_withNoUuidsAndNonMatchingBluetoothClass() {
        BluetoothClass mockBtClass = mock(BluetoothClass.class);
        when(mockBtClass.doesClassMatch(BluetoothClass.PROFILE_A2DP)).thenReturn(false);

        boolean result = bluetoothPeripheralHandover.hasA2dpCapability(null, mockBtClass);
        assertFalse(result);
    }

    @Test
    public void testHasHeadsetCapability_withUuidsContainingHfp() {
        ParcelUuid[] uuids = new ParcelUuid[]{BluetoothUuid.HFP};

        boolean result = bluetoothPeripheralHandover.hasHeadsetCapability(uuids, null);
        assertTrue(result);
    }

    @Test
    public void testHasHeadsetCapability_withUuidsContainingHsp() {
        ParcelUuid[] uuids = new ParcelUuid[]{BluetoothUuid.HSP};

        boolean result = bluetoothPeripheralHandover.hasHeadsetCapability(uuids, null);
        assertTrue(result);
    }

    @Test
    public void testHasHeadsetCapability_withNoMatchingUuids() {
        ParcelUuid[] uuids = new ParcelUuid[]{ParcelUuid.fromString(
                "0000110D-0000-1000-8000-00805F9B34FB")}; // Some other UUID

        boolean result = bluetoothPeripheralHandover.hasHeadsetCapability(uuids, null);
        assertFalse(result);
    }

    @Test
    public void testHasHeadsetCapability_withBluetoothClassMatchingHeadset() {
        BluetoothClass mockBtClass = mock(BluetoothClass.class);
        when(mockBtClass.doesClassMatch(BluetoothClass.PROFILE_HEADSET)).thenReturn(true);

        boolean result = bluetoothPeripheralHandover.hasHeadsetCapability(null, mockBtClass);
        assertTrue(result);
    }

    @Test
    public void testHasHeadsetCapability_withNoUuidsAndNonMatchingBluetoothClass() {
        BluetoothClass mockBtClass = mock(BluetoothClass.class);
        when(mockBtClass.doesClassMatch(BluetoothClass.PROFILE_HEADSET)).thenReturn(false);

        boolean result = bluetoothPeripheralHandover.hasHeadsetCapability(null, mockBtClass);
        assertFalse(result);
    }

    @Test
    public void testGetProfileProxys_withTransportLE_success() {
        when(mockBluetoothAdapter.getProfileProxy(eq(mockContext), eq(bluetoothPeripheralHandover),
                eq(BluetoothProfile.HID_HOST))).thenReturn(true);

        boolean result = bluetoothPeripheralHandover.getProfileProxys();
        assertTrue(result);
        verify(mockBluetoothAdapter).getProfileProxy(mockContext, bluetoothPeripheralHandover,
                BluetoothProfile.HID_HOST);
    }

    @Test
    public void testGetProfileProxys_withTransportLE_failure() {
        when(mockBluetoothAdapter.getProfileProxy(eq(mockContext), eq(bluetoothPeripheralHandover),
                eq(BluetoothProfile.HID_HOST))).thenReturn(false);

        boolean result = bluetoothPeripheralHandover.getProfileProxys();
        assertFalse(result);
        verify(mockBluetoothAdapter).getProfileProxy(mockContext, bluetoothPeripheralHandover,
                BluetoothProfile.HID_HOST);
    }

    @Test
    public void testGetProfileProxys_withClassicTransport_success() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        when(mockBluetoothAdapter.getProfileProxy(eq(mockContext), eq(bluetoothPeripheralHandover),
                eq(BluetoothProfile.HEADSET))).thenReturn(true);

        when(mockBluetoothAdapter.getProfileProxy(eq(mockContext), eq(bluetoothPeripheralHandover),
                eq(BluetoothProfile.A2DP))).thenReturn(true);

        boolean result = bluetoothPeripheralHandover.getProfileProxys();
        assertTrue(result);
        verify(mockBluetoothAdapter).getProfileProxy(mockContext, bluetoothPeripheralHandover,
                BluetoothProfile.HEADSET);
        verify(mockBluetoothAdapter).getProfileProxy(mockContext, bluetoothPeripheralHandover,
                BluetoothProfile.A2DP);
    }

    @Test
    public void testGetProfileProxys_withClassicTransport_failureInHeadset() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        when(mockBluetoothAdapter.getProfileProxy(eq(mockContext), eq(bluetoothPeripheralHandover),
                eq(BluetoothProfile.HEADSET))).thenReturn(false);

        boolean result = bluetoothPeripheralHandover.getProfileProxys();
        assertFalse(result);
        verify(mockBluetoothAdapter).getProfileProxy(mockContext, bluetoothPeripheralHandover,
                BluetoothProfile.HEADSET);
        verify(mockBluetoothAdapter, never()).getProfileProxy(mockContext,
                bluetoothPeripheralHandover, BluetoothProfile.A2DP);
    }

    @Test
    public void testGetProfileProxys_withClassicTransport_failureInA2dp() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        when(mockBluetoothAdapter.getProfileProxy(eq(mockContext), eq(bluetoothPeripheralHandover),
                eq(BluetoothProfile.HEADSET))).thenReturn(true);
        when(mockBluetoothAdapter.getProfileProxy(eq(mockContext), eq(bluetoothPeripheralHandover),
                eq(BluetoothProfile.A2DP))).thenReturn(false);
        boolean result = bluetoothPeripheralHandover.getProfileProxys();

        assertFalse(result);
        verify(mockBluetoothAdapter).getProfileProxy(mockContext, bluetoothPeripheralHandover,
                BluetoothProfile.HEADSET);
        verify(mockBluetoothAdapter).getProfileProxy(mockContext, bluetoothPeripheralHandover,
                BluetoothProfile.A2DP);
    }

    @Test
    public void testNextStep_NextStepInit() {
        bluetoothPeripheralHandover.mAction = ACTION_INIT;
        bluetoothPeripheralHandover.mA2dp = null;
        bluetoothPeripheralHandover.mState = STATE_INIT;

        bluetoothPeripheralHandover.nextStep();
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStep_ACTION_CONNECT() {
        bluetoothPeripheralHandover.mAction = ACTION_CONNECT;
        bluetoothPeripheralHandover.mState = STATE_INIT_COMPLETE;
        when(mockDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDING);

        bluetoothPeripheralHandover.nextStep();
        assertEquals(STATE_WAITING_FOR_BOND_CONFIRMATION, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStep_NextStepDisconnect() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        bluetoothPeripheralHandover.mAction = ACTION_DISCONNECT;
        bluetoothPeripheralHandover.mState = STATE_DISCONNECTING;
        bluetoothPeripheralHandover.mInput = mockInput;
        bluetoothPeripheralHandover.mHidResult = RESULT_CONNECTED;
        when(mockInput.getConnectionState(mockDevice)).thenReturn(
                BluetoothProfile.STATE_DISCONNECTED);

        bluetoothPeripheralHandover.nextStep();
        assertEquals(STATE_DISCONNECTING, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testHandleIntent_ACTION_PAIRING_REQUEST() {
        when(mockIntent.getAction()).thenReturn(BluetoothDevice.ACTION_PAIRING_REQUEST);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        verify(mockDevice).setPairingConfirmation(true);
        assertTrue(bluetoothPeripheralHandover.mShouldAbortBroadcast);
    }

    @Test
    public void testHandleIntent_ACTION_ALLOW_CONNECT() {
        bluetoothPeripheralHandover.mState = STATE_INIT_COMPLETE;
        when(mockDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDING);
        when(mockIntent.getAction()).thenReturn(ACTION_ALLOW_CONNECT);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        assertEquals(STATE_WAITING_FOR_BOND_CONFIRMATION, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testHandleIntent_ACTION_DENY_CONNECT() {
        when(mockIntent.getAction()).thenReturn(ACTION_DENY_CONNECT);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
        verify(mockCallback).onBluetoothPeripheralHandoverComplete(false);
    }

    @Test
    public void testHandleIntentHidHostStateChangedToBluetoothConnected() {
        bluetoothPeripheralHandover.mState = STATE_CONNECTING;
        when(mockIntent.getAction()).thenReturn(BluetoothHidHost.ACTION_CONNECTION_STATE_CHANGED);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);
        when(mockIntent.getIntExtra(BluetoothProfile.EXTRA_STATE,
                BluetoothDevice.ERROR)).thenReturn(BluetoothProfile.STATE_CONNECTED);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        assertEquals(RESULT_CONNECTED, bluetoothPeripheralHandover.mHidResult);
    }

    @Test
    public void testHandleIntentHidHostStateChangedToBluetoothDisconnected() {
        bluetoothPeripheralHandover.mState = STATE_CONNECTING;
        when(mockIntent.getAction()).thenReturn(BluetoothHidHost.ACTION_CONNECTION_STATE_CHANGED);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);
        when(mockIntent.getIntExtra(BluetoothProfile.EXTRA_STATE,
                BluetoothDevice.ERROR)).thenReturn(BluetoothProfile.STATE_DISCONNECTED);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        assertEquals(RESULT_DISCONNECTED, bluetoothPeripheralHandover.mHidResult);
    }

    @Test
    public void testHandleIntent_A2dpACTION_CONNECTION_STATE_CHANGED_BLUETOOTH_STATE_CONNECTED() {
        bluetoothPeripheralHandover.mState = STATE_CONNECTING;
        when(mockIntent.getAction()).thenReturn(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);
        when(mockIntent.getIntExtra(BluetoothProfile.EXTRA_STATE,
                BluetoothDevice.ERROR)).thenReturn(BluetoothProfile.STATE_CONNECTED);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        assertEquals(RESULT_CONNECTED, bluetoothPeripheralHandover.mA2dpResult);
    }

    //STATE_DISCONNECTED
    @Test
    public void testHandleIntentA2dpStateChangedToBluetoothDisconnected() {
        bluetoothPeripheralHandover.mState = STATE_CONNECTING;
        when(mockIntent.getAction()).thenReturn(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);
        when(mockIntent.getIntExtra(BluetoothProfile.EXTRA_STATE,
                BluetoothDevice.ERROR)).thenReturn(BluetoothProfile.STATE_DISCONNECTED);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        assertEquals(RESULT_DISCONNECTED, bluetoothPeripheralHandover.mA2dpResult);
    }

    @Test
    public void testHandleIntentHeadsetStateChangedToBluetoothConnected() {
        bluetoothPeripheralHandover.mState = STATE_CONNECTING;
        when(mockIntent.getAction()).thenReturn(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);
        when(mockIntent.getIntExtra(BluetoothProfile.EXTRA_STATE,
                BluetoothDevice.ERROR)).thenReturn(BluetoothProfile.STATE_CONNECTED);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        assertEquals(RESULT_CONNECTED, bluetoothPeripheralHandover.mHfpResult);
    }

    @Test
    public void testHandleIntentHeadsetStateChangedToBluetoothDisconnected() {
        bluetoothPeripheralHandover.mState = STATE_CONNECTING;
        when(mockIntent.getAction()).thenReturn(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);
        when(mockIntent.getIntExtra(BluetoothProfile.EXTRA_STATE,
                BluetoothDevice.ERROR)).thenReturn(BluetoothProfile.STATE_DISCONNECTED);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        assertEquals(RESULT_DISCONNECTED, bluetoothPeripheralHandover.mHfpResult);
    }

    @Test
    public void testHandleIntent_BluetoothDevice_ACTION_BOND_STATE_CHANGED_STATE_BONDING() {
        bluetoothPeripheralHandover.mState = STATE_BONDING;
        when(mockIntent.getAction()).thenReturn(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.BOND_BONDED);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        assertEquals(0, bluetoothPeripheralHandover.mRetryCount);
    }

    @Test
    public void testHandleBondStateChangedToBondingAndBondNone() {
        bluetoothPeripheralHandover.mState = STATE_BONDING;
        when(mockIntent.getAction()).thenReturn(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED);
        when(mockIntent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).thenReturn(mockDevice);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.PAIRING_VARIANT_CONSENT);
        when(mockIntent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE,
                BluetoothDevice.ERROR)).thenReturn(BluetoothDevice.BOND_NONE);

        bluetoothPeripheralHandover.handleIntent(mockIntent);
        assertEquals(0, bluetoothPeripheralHandover.mRetryCount);
    }

    @Test
    public void testNextStepInit_STATE_WAITING_FOR_PROXIES_ACTION_DISCONNECT() {
        bluetoothPeripheralHandover.mState = STATE_WAITING_FOR_PROXIES;
        bluetoothPeripheralHandover.mInput = mockInput;
        when(mockDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDING);

        bluetoothPeripheralHandover.nextStepInit();
        assertEquals(ACTION_CONNECT, bluetoothPeripheralHandover.mAction);
    }

    @Test
    public void testNextStepInit_STATE_WAITING_FOR_PROXIES_BlDeviceNonTRANSPORT_LE_COMPLETE() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        bluetoothPeripheralHandover.mState = STATE_WAITING_FOR_PROXIES;
        bluetoothPeripheralHandover.mHeadset = mockHeadset;
        bluetoothPeripheralHandover.mA2dp = mockA2dp;
        bluetoothPeripheralHandover.mInput = mockInput;

        when(mockHeadset.getConnectionPolicy(mockDevice)).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_FORBIDDEN);
        when(mockA2dp.getConnectionPolicy(mockDevice)).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_FORBIDDEN);

        bluetoothPeripheralHandover.nextStepInit();
        assertNull(bluetoothPeripheralHandover.mA2dp);
        assertNull(bluetoothPeripheralHandover.mHeadset);
        assertNull(bluetoothPeripheralHandover.mInput);
        verify(mockCallback).onBluetoothPeripheralHandoverComplete(false);
    }

    @Test
    public void testNextStepInit_STATE_WAITING_FOR_PROXIES_BlDeviceNonTRANSPORT_LE_ACTION_CONNECT() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        bluetoothPeripheralHandover.mState = STATE_WAITING_FOR_PROXIES;
        bluetoothPeripheralHandover.mHeadset = mockHeadset;
        bluetoothPeripheralHandover.mA2dp = mockA2dp;
        bluetoothPeripheralHandover.mInput = mockInput;
        when(mockHeadset.getConnectionPolicy(mockDevice)).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_FORBIDDEN);
        when(mockA2dp.getConnectionPolicy(mockDevice)).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);

        bluetoothPeripheralHandover.nextStepInit();
        assertEquals(ACTION_CONNECT, bluetoothPeripheralHandover.mAction);
    }

    @Test
    public void testNextStepInitWaitingForProxiesTransportLeDisconnect() {
        bluetoothPeripheralHandover.mState = STATE_WAITING_FOR_PROXIES;
        bluetoothPeripheralHandover.mHeadset = mockHeadset;
        bluetoothPeripheralHandover.mA2dp = mockA2dp;
        bluetoothPeripheralHandover.mInput = mockInput;
        when(mockInput.getConnectedDevices()).thenReturn(Collections.singletonList(mockDevice));
        when(mockInput.getConnectionState(mockDevice)).thenReturn(BluetoothProfile.STATE_CONNECTED);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepInit();
        assertEquals(ACTION_DISCONNECT, bluetoothPeripheralHandover.mAction);
        assertEquals(RESULT_PENDING, bluetoothPeripheralHandover.mHidResult);
        verify(mockDevice).disconnect();
    }

    @Test
    public void testNextStepInit_STATE_WAITING_FOR_PROXIES_BlDeviceTRANSPORT_LE_ACTION_CONNECT() {
        bluetoothPeripheralHandover.mState = STATE_WAITING_FOR_PROXIES;
        bluetoothPeripheralHandover.mInput = mockInput;
        when(mockDevice.getBondState()).thenReturn(BluetoothDevice.BOND_BONDING);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepInit();
        assertEquals(ACTION_CONNECT, bluetoothPeripheralHandover.mAction);
        assertEquals(STATE_WAITING_FOR_BOND_CONFIRMATION, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testHasStarted() {
        bluetoothPeripheralHandover.mState = STATE_INIT;

        assertFalse(bluetoothPeripheralHandover.hasStarted());
    }

    @Test
    public void testStartBonding_STATE_BONDING() {
        bluetoothPeripheralHandover.mOobData = mockOobData;
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);
        when(mockDevice.createBondOutOfBand(bluetoothPeripheralHandover.mTransport, null,
                mockOobData)).thenReturn(false);

        bluetoothPeripheralHandover.startBonding();
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testStartBonding_STATE_BONDING_oobDataNull() {
        bluetoothPeripheralHandover.mOobData = null;
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);
        when(mockDevice.createBond(bluetoothPeripheralHandover.mTransport)).thenReturn(false);

        bluetoothPeripheralHandover.startBonding();
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStepDisconnect_STATE_INIT_COMPLETE_TRANSPORT_LE_STATE_CONNECTED() {
        bluetoothPeripheralHandover.mState = STATE_INIT_COMPLETE;
        bluetoothPeripheralHandover.mInput = mockInput;
        when(mockInput.getConnectionState(mockDevice)).thenReturn(BluetoothProfile.STATE_CONNECTED);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepDisconnect();
        assertEquals(RESULT_PENDING, bluetoothPeripheralHandover.mHidResult);
    }

    @Test
    public void testNextStepDisconnect_STATE_INIT_COMPLETE_TRANSPORT_LE_STATE_DISCONNECTED() {
        bluetoothPeripheralHandover.mState = STATE_INIT_COMPLETE;
        bluetoothPeripheralHandover.mInput = mockInput;
        when(mockInput.getConnectionState(mockDevice)).thenReturn(
                BluetoothProfile.STATE_DISCONNECTED);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepDisconnect();
        assertEquals(RESULT_DISCONNECTED, bluetoothPeripheralHandover.mHidResult);
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStepDisconnect_STATE_INIT_COMPLETE_Not_TRANSPORT_LE_STATE_CONNECTED() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        bluetoothPeripheralHandover.mState = STATE_INIT_COMPLETE;
        bluetoothPeripheralHandover.mHeadset = mockHeadset;
        bluetoothPeripheralHandover.mA2dp = mockA2dp;
        when(mockHeadset.getConnectionState(mockDevice)).thenReturn(
                BluetoothProfile.STATE_CONNECTED);
        when(mockA2dp.getConnectionState(mockDevice)).thenReturn(BluetoothProfile.STATE_CONNECTED);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepDisconnect();
        assertEquals(RESULT_PENDING, bluetoothPeripheralHandover.mA2dpResult);
        assertEquals(RESULT_PENDING, bluetoothPeripheralHandover.mHfpResult);
        assertEquals(STATE_DISCONNECTING, bluetoothPeripheralHandover.mState);
    }

    @Test
    public void testNextStepDisconnect_STATE_INIT_COMPLETE_Not_TRANSPORT_LE_STATE_DISCONNECTED() {
        bluetoothPeripheralHandover = createBluetoothPerHandOvrInstance(
                BluetoothDevice.TRANSPORT_AUTO);
        bluetoothPeripheralHandover.mState = STATE_INIT_COMPLETE;
        bluetoothPeripheralHandover.mHeadset = mockHeadset;
        bluetoothPeripheralHandover.mA2dp = mockA2dp;
        when(mockHeadset.getConnectionState(mockDevice)).thenReturn(
                BluetoothProfile.STATE_DISCONNECTED);
        when(mockA2dp.getConnectionState(mockDevice)).thenReturn(
                BluetoothProfile.STATE_DISCONNECTED);
        when(Toast.makeText(mockContext, eq(any()), anyInt())).thenReturn(mockToast);

        bluetoothPeripheralHandover.nextStepDisconnect();
        assertEquals(RESULT_DISCONNECTED, bluetoothPeripheralHandover.mA2dpResult);
        assertEquals(RESULT_DISCONNECTED, bluetoothPeripheralHandover.mHfpResult);
        assertEquals(STATE_COMPLETE, bluetoothPeripheralHandover.mState);
    }
}
