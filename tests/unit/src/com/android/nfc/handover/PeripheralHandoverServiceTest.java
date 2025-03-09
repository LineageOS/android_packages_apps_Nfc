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

import static android.app.Service.START_NOT_STICKY;
import static android.app.Service.START_STICKY;

import static com.android.nfc.handover.PeripheralHandoverService.EXTRA_PERIPHERAL_DEVICE;
import static com.android.nfc.handover.PeripheralHandoverService.EXTRA_PERIPHERAL_NAME;
import static com.android.nfc.handover.PeripheralHandoverService.MSG_PAUSE_POLLING;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.provider.Settings;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.dx.mockito.inline.extended.ExtendedMockito;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.MockitoSession;
import org.mockito.quality.Strictness;

import java.util.HashSet;
import java.util.Set;

public class PeripheralHandoverServiceTest {
    @Mock
    private BluetoothAdapter mMockBluetoothAdapter;
    @Mock
    private NfcAdapter mMockNfcAdapter;
    @Mock
    private Context mMockContext;
    @Mock
    private BluetoothDevice mMockDevice1;
    @Mock
    private BluetoothDevice mMockDevice2;
    @Mock
    private Messenger mMockClient;
    @Mock
    private PeripheralHandoverService.MessageHandler mMockHandler;
    @Mock
    private BluetoothPeripheralHandover mMockBluetoothPeripheralHandover;
    @Mock
    private ContentResolver mMockContentResolver;
    @Mock
    private BluetoothDevice mMockDevice;
    @Mock
    private Resources mMockResources;
    private MockitoSession mStaticMockSession;
    private PeripheralHandoverService mService;

    @Before
    public void setUp() {
        mStaticMockSession = ExtendedMockito.mockitoSession()
                .mockStatic(NfcAdapter.class)
                .strictness(Strictness.LENIENT).startMocking();
        MockitoAnnotations.initMocks(this);
        mService = createServiceInstance(mMockBluetoothAdapter, mMockNfcAdapter,
                mMockBluetoothPeripheralHandover, mMockHandler, mMockClient, mMockDevice1, false);
        when(mMockContext.getApplicationContext()).thenReturn(mMockContext);
        when(mMockContext.getContentResolver()).thenReturn(mMockContentResolver);
        when(mMockContext.getResources()).thenReturn(mMockResources);
        when(NfcAdapter.getDefaultAdapter(mMockContext)).thenReturn(mMockNfcAdapter);
    }

    private PeripheralHandoverService createServiceInstance(BluetoothAdapter bluetoothAdapter,
            NfcAdapter nfcAdapter,
            BluetoothPeripheralHandover bluetoothPeripheralHandover,
            PeripheralHandoverService.MessageHandler handler,
            Messenger messenger, BluetoothDevice device, boolean bluetoothEnabledByNfc) {
        mService = new PeripheralHandoverService(bluetoothAdapter, nfcAdapter,
                bluetoothPeripheralHandover, handler, messenger, device, bluetoothEnabledByNfc);
        return mService;
    }

    @After
    public void tearDown() {
        mStaticMockSession.finishMocking();
    }

    @Test
    public void testEnableBluetoothAdapterDisabled() {
        when(mMockBluetoothAdapter.isEnabled()).thenReturn(false);
        when(mMockBluetoothAdapter.enableNoAutoConnect()).thenReturn(true);

        boolean result = mService.enableBluetooth();
        verify(mMockBluetoothAdapter).enableNoAutoConnect();
        assertTrue(mService.mBluetoothEnabledByNfc);
        assertTrue(result);
    }

    @Test
    public void testEnableBluetoothAdapterEnabled() {
        when(mMockBluetoothAdapter.isEnabled()).thenReturn(true);

        boolean result = mService.enableBluetooth();
        assertTrue(result);
    }

    @Test
    public void testHasConnectedBluetoothDevices_DeviceConnected() {
        Set<BluetoothDevice> bondedDevices = new HashSet<>();
        bondedDevices.add(mMockDevice1);
        bondedDevices.add(mMockDevice2);
        when(mMockBluetoothAdapter.getBondedDevices()).thenReturn(bondedDevices);
        when(mMockDevice2.isConnected()).thenReturn(true);

        boolean result = mService.hasConnectedBluetoothDevices();
        assertTrue(result);
    }

    @Test
    public void testHasConnectedBluetoothDevices_DeviceNotConnected() {
        Set<BluetoothDevice> bondedDevices = new HashSet<>();
        bondedDevices.add(mMockDevice1);
        bondedDevices.add(mMockDevice2);
        when(mMockBluetoothAdapter.getBondedDevices()).thenReturn(bondedDevices);
        when(mMockDevice2.isConnected()).thenReturn(false);

        boolean result = mService.hasConnectedBluetoothDevices();
        assertFalse(result);
    }

    @Test
    public void testDisableBluetoothIfNeededWhenBluetoothDisabledByNfc() {
        mService.disableBluetoothIfNeeded();
        verify(mMockBluetoothAdapter, never()).disable();
    }

    @Test
    public void testDisableBluetoothIfNeededWhenConnectedBluetoothDevices() {
        mService = createServiceInstance(mMockBluetoothAdapter, mMockNfcAdapter,
                mMockBluetoothPeripheralHandover, mMockHandler, mMockClient, mMockDevice1, true);
        Set<BluetoothDevice> bondedDevices = new HashSet<>();
        bondedDevices.add(mMockDevice1);
        bondedDevices.add(mMockDevice2);
        when(mMockBluetoothAdapter.getBondedDevices()).thenReturn(bondedDevices);
        when(mMockDevice2.isConnected()).thenReturn(true);

        mService.disableBluetoothIfNeeded();
        verify(mMockBluetoothAdapter, never()).disable();
        verify(mMockBluetoothAdapter).getBondedDevices();
    }

    @Test
    public void testDisableBluetoothIfNeededWhenBluetoothHeadsetNotConnected() {
        mService = createServiceInstance(mMockBluetoothAdapter, mMockNfcAdapter,
                mMockBluetoothPeripheralHandover, mMockHandler, mMockClient, mMockDevice1, true);
        Set<BluetoothDevice> bondedDevices = new HashSet<>();
        bondedDevices.add(mMockDevice1);
        bondedDevices.add(mMockDevice2);
        when(mMockBluetoothAdapter.getBondedDevices()).thenReturn(bondedDevices);
        when(mMockDevice2.isConnected()).thenReturn(false);

        mService.disableBluetoothIfNeeded();
        verify(mMockBluetoothAdapter).disable();
        assertFalse(mService.mBluetoothEnabledByNfc);
    }

    @Test
    public void testReplyToClient_ClientIsNull() throws RemoteException {
        mService = createServiceInstance(mMockBluetoothAdapter, mMockNfcAdapter,
                mMockBluetoothPeripheralHandover, mMockHandler, null, mMockDevice1, false);

        mService.replyToClient(true);
        verify(mMockClient, never()).send(any(Message.class));
    }

    @Test
    public void testReplyToClient_ClientReceivesConnectedMessage() throws RemoteException {
        mService = createServiceInstance(mMockBluetoothAdapter, mMockNfcAdapter,
                mMockBluetoothPeripheralHandover, mMockHandler, mMockClient, mMockDevice1, true);

        mService.replyToClient(true);
        verify(mMockClient).send(any(Message.class));
    }

    @Test
    public void testReplyToClient_ClientReceivesNotConnectedMessage() throws RemoteException {
        mService.replyToClient(false);
        verify(mMockClient).send(any(Message.class));
    }

    @Test
    public void testOnBluetoothPeripheralHandoverComplete_Connected() {
        mService = createServiceInstance(mMockBluetoothAdapter, mMockNfcAdapter,
                mMockBluetoothPeripheralHandover, mMockHandler, null, mMockDevice1, false);
        when(mMockBluetoothPeripheralHandover.getTransport()).thenReturn(
                BluetoothDevice.TRANSPORT_LE);

        mService.onBluetoothPeripheralHandoverComplete(true);
        assertEquals(0, mService.mStartId);
        verify(mMockNfcAdapter, never()).resumePolling();
        verify(mMockHandler, never()).removeMessages(MSG_PAUSE_POLLING);
    }

    @Test
    public void testOnBluetoothPeripheralHandoverComplete_NotConnected() {
        mService = createServiceInstance(mMockBluetoothAdapter, mMockNfcAdapter,
                mMockBluetoothPeripheralHandover, mMockHandler, null, mMockDevice1, false);
        when(mMockHandler.hasMessages(MSG_PAUSE_POLLING)).thenReturn(true);
        when(mMockBluetoothPeripheralHandover.getTransport()).thenReturn(
                BluetoothDevice.TRANSPORT_LE);

        mService.onBluetoothPeripheralHandoverComplete(false);
        verify(mMockNfcAdapter).resumePolling();
        verify(mMockHandler).removeMessages(MSG_PAUSE_POLLING);
    }

    @Test
    public void testBluetoothStatusReceiver_onReceive() {
        mService = createServiceInstance(mMockBluetoothAdapter, mMockNfcAdapter,
                mMockBluetoothPeripheralHandover, mMockHandler, null, mMockDevice1, false);
        Intent mockIntent = mock(Intent.class);
        when(mockIntent.getAction()).thenReturn(BluetoothAdapter.ACTION_STATE_CHANGED);
        when(mockIntent.getIntExtra(BluetoothAdapter.EXTRA_STATE,
                BluetoothAdapter.ERROR)).thenReturn(BluetoothAdapter.STATE_ON);
        when(mMockBluetoothPeripheralHandover.hasStarted()).thenReturn(true);
        when(mMockBluetoothPeripheralHandover.start()).thenReturn(true);

        mService.mBluetoothStatusReceiver.onReceive(mMockContext, mockIntent);
        assertEquals(0, mService.mStartId);
        verify(mockIntent).getIntExtra(BluetoothAdapter.EXTRA_STATE,
                BluetoothAdapter.ERROR);
    }

    @Test
    public void testOnBind() {
        assertNull(mService.onBind(null));
    }

    @Test
    public void testUnBind() {
        assertFalse(mService.onUnbind(null));
    }

    @Test
    public void testOnStartCommand_START_NOT_STICKY() {
        assertEquals(START_NOT_STICKY, mService.onStartCommand(null, 0, 0));
    }

    @Test
    public void testOnStartCommand_START_STICKY() {
        mService = createServiceInstance(mMockBluetoothAdapter, mMockNfcAdapter,
                mMockBluetoothPeripheralHandover, mMockHandler, mMockClient, mMockDevice, false);
        Bundle mockBundle = mock(Bundle.class);
        Intent mockIntent = mock(Intent.class);
        int mStartId = 0;
        when(mockIntent.getExtras()).thenReturn(mockBundle);

        assertEquals(START_STICKY, mService.onStartCommand(mockIntent, 0, mStartId));
        assertEquals(mStartId, mService.mStartId);
    }

    @Test
    public void testOnStartCommand_CancelOnGoingHandover() {
        mService = createServiceInstance(mMockBluetoothAdapter, mMockNfcAdapter,
                mMockBluetoothPeripheralHandover, mMockHandler, mMockClient, mMockDevice, false);
        Bundle mockBundle = mock(Bundle.class);
        Intent mockIntent = mock(Intent.class);
        int mStartId = 1;
        when(mockIntent.getExtras()).thenReturn(mockBundle);
        when(mockBundle.getParcelable(EXTRA_PERIPHERAL_DEVICE)).thenReturn(mMockDevice);
        when(mockBundle.getString(EXTRA_PERIPHERAL_NAME)).thenReturn("Test name");

        assertEquals(START_STICKY, mService.onStartCommand(mockIntent, 0, mStartId));
        assertEquals(mStartId, mService.mStartId);
    }

    @Test
    public void testOnStartCommandNonPeripheralHandover_START_NOT_STICKY() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
            PeripheralHandoverService peripheralServ = new PeripheralHandoverService(
                    mMockBluetoothAdapter, mMockNfcAdapter,
                    mMockBluetoothPeripheralHandover, mMockHandler, null, mMockDevice, false) {
                @Override
                boolean doPeripheralHandover(Bundle extras) {
                    return false; // Override to return false
                }
            };
            Bundle mockBundle = mock(Bundle.class);
            Intent mockIntent = mock(Intent.class);
            when(mockIntent.getExtras()).thenReturn(mockBundle).thenReturn(null);
            when(mockBundle.getParcelable(EXTRA_PERIPHERAL_DEVICE)).thenReturn(mMockDevice);
            when(mockBundle.getString(EXTRA_PERIPHERAL_NAME)).thenReturn("Test name");
            when(mMockBluetoothPeripheralHandover.getTransport()).thenReturn(
                    BluetoothDevice.TRANSPORT_LE);

            int result = peripheralServ.onStartCommand(mockIntent, 0, 0);
            assertEquals(START_NOT_STICKY, result);
            assertEquals(0, peripheralServ.mStartId);
        });
    }
}