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

package com.android.nfc.wlc;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.content.ContextWrapper;
import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.android.dx.mockito.inline.extended.ExtendedMockito;
import com.android.nfc.DeviceHost;
import com.android.nfc.NfcService;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.MockitoSession;
import org.mockito.quality.Strictness;

@RunWith(AndroidJUnit4.class)
public class NfcChargingTest {
    private static String TAG = NfcChargingTest.class.getSimpleName();
    private MockitoSession mStaticMockSession;
    private NfcCharging mNfcCharging;
    private Context mContext;
    @Mock
    private DeviceHost mDeviceHost;

    @Mock
    private DeviceHost.TagEndpoint mTagEndpoint;

    @Before
    public void setUp() throws Exception {
        mStaticMockSession = ExtendedMockito.mockitoSession()
                .mockStatic(NfcService.class)
                .strictness(Strictness.LENIENT)
                .startMocking();
        MockitoAnnotations.initMocks(this);

        mContext = new ContextWrapper(
                InstrumentationRegistry.getInstrumentation().getTargetContext()) {
        };


        InstrumentationRegistry.getInstrumentation().runOnMainSync(
                () -> mNfcCharging = new NfcCharging(mContext, mDeviceHost));
        mNfcCharging.TagHandler = mTagEndpoint;
        Assert.assertNotNull(mNfcCharging);
    }

    @After
    public void tearDown() {
        mStaticMockSession.finishMocking();
    }

    @Test
    public void bytesToHex_convertsByteArrayToHexString() {
        byte[] bytes = new byte[] {0x01, 0x0A, (byte) 0xFF};
        String hexString = NfcCharging.bytesToHex(bytes);
        assertThat(hexString).isEqualTo("010AFF");
    }

    @Test
    public void testResetInternalValues() {
        // Set some values to non-default
        mNfcCharging.mCnt = 10;
        mNfcCharging.WlcCtl_BatteryLevel = 50;
        mNfcCharging.WlcDeviceInfo.put(NfcCharging.BatteryLevel, 80);

        mNfcCharging.resetInternalValues();

        assertEquals(-1, mNfcCharging.mCnt);
        assertEquals(-1, mNfcCharging.WlcCtl_BatteryLevel);
        assertEquals(-1, mNfcCharging.WlcDeviceInfo.get(NfcCharging.BatteryLevel).intValue());
    }

    @Test
    public void testCheckWlcCapMsg_InvalidMessageType() {
        // Construct an NDEF message with an invalid type
        byte[] type = NfcCharging.WLCCTL; // Incorrect type
        byte[] payload = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04,0x05 };
        NdefRecord record = new NdefRecord(NdefRecord.TNF_WELL_KNOWN, type, new byte[] {}, payload);
        NdefMessage ndefMessage = new NdefMessage(record);

        assertFalse(mNfcCharging.checkWlcCapMsg(ndefMessage));
    }

    @Test
    public void testCheckWlcCtlMsg_ValidMessage() {
        // Construct a valid WLCCTL NDEF message
        byte[] type = NfcCharging.WLCCTL;
        byte[] payload = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        NdefRecord record = new NdefRecord(NdefRecord.TNF_WELL_KNOWN, type, new byte[] {}, payload);
        NdefMessage ndefMessage = new NdefMessage(record);

        assertTrue(mNfcCharging.checkWlcCtlMsg(ndefMessage));
        assertEquals(0, mNfcCharging.WlcCtl_ErrorFlag);
        assertEquals(0, mNfcCharging.WlcCtl_BatteryStatus);
    }

    @Test
    public void testCheckWlcCtlMsg_InvalidMessageType() {
        // Construct an NDEF message with an invalid type
        byte[] type = NfcCharging.WLCCAP; // Incorrect type
        byte[] payload = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        NdefRecord record = new NdefRecord(NdefRecord.TNF_WELL_KNOWN, type, new byte[] {}, payload);
        NdefMessage ndefMessage = new NdefMessage(record);

        assertFalse(mNfcCharging.checkWlcCtlMsg(ndefMessage));
    }

    @Test
    public void testWLCL_Presence() {
        NdefMessage ndefMessage = mock(NdefMessage.class);
        when(mTagEndpoint.getNdef()).thenReturn(ndefMessage);
        mNfcCharging.mFirstOccurrence = false;
        NfcService nfcService = mock(NfcService.class);
        when(NfcService.getInstance()).thenReturn(nfcService);
        mNfcCharging.HandleWLCState();
        verify(mNfcCharging.mNdefMessage).getRecords();
        Assert.assertFalse(mNfcCharging.WLCL_Presence);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State6() {
        NdefMessage ndefMessage = mock(NdefMessage.class);
        NdefRecord ndefRecord = mock(NdefRecord.class);
        when(ndefRecord.getType()).thenReturn(NfcCharging.WLCCAP);
        byte[] payload = {0x01, 0x02, 0x01, 0x10, 0x02, 0x01};
        when(ndefRecord.getPayload()).thenReturn(payload);
        NdefRecord[] records = {ndefRecord};
        when(ndefMessage.getRecords()).thenReturn(records);
        when(mTagEndpoint.getNdef()).thenReturn(ndefMessage);
        mNfcCharging.mFirstOccurrence = false;
        NfcService nfcService = mock(NfcService.class);
        when(NfcService.getInstance()).thenReturn(nfcService);
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(1, mNfcCharging.WLCState);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State8() {
        mNfcCharging.WLCState = 2;
        mNfcCharging.WlcCap_NegoWait = 1;
        mNfcCharging.mNretry = 1;
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(0, mNfcCharging.WLCState);
        Assert.assertFalse(mNfcCharging.WLCL_Presence);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State8_Retry() {
        mNfcCharging.WLCState = 2;
        mNfcCharging.WlcCap_NegoWait = 1;
        mNfcCharging.mNretry = 0;
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(0, mNfcCharging.WLCState);
        mNfcCharging.WLCState = 2;
        mNfcCharging.WlcCap_NegoWait = 2;
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(3, mNfcCharging.WLCState);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State11() throws FormatException {
        mNfcCharging.WLCState = 3;
        mNfcCharging.HandleWLCState();
        ArgumentCaptor<byte[]> argumentCaptor = ArgumentCaptor.forClass(byte[].class);
        verify(mTagEndpoint).writeNdef(argumentCaptor.capture());
        byte[] messageArray = argumentCaptor.getValue();
        Assert.assertNotNull(messageArray);
        NdefMessage ndefMessage = new NdefMessage(messageArray);
        Assert.assertNotNull(ndefMessage);
        Assert.assertEquals(4, mNfcCharging.WLCState);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State12() {
        mNfcCharging.WLCState = 4;
        NdefMessage ndefMessage = mock(NdefMessage.class);
        NdefRecord ndefRecord = mock(NdefRecord.class);
        when(ndefRecord.getType()).thenReturn(NfcCharging.WLCCTL);
        byte[] payload = {0x57, 0x4c, 0x43, 0x43, 0x54, 0x4C};
        when(ndefRecord.getPayload()).thenReturn(payload);

        NdefRecord ndefRecordWLCSTAI = mock(NdefRecord.class);
        when(ndefRecordWLCSTAI.getType()).thenReturn(NfcCharging.WLCSTAI);
        byte[] payloadWLCSTAI = {0x57, 0x4c, 0x43, 0x43, 0x54, 0x4C};
        when(ndefRecordWLCSTAI.getPayload()).thenReturn(payloadWLCSTAI);

        NdefRecord[] records = {ndefRecord, ndefRecordWLCSTAI};
        when(ndefMessage.getRecords()).thenReturn(records);
        when(mTagEndpoint.getNdef()).thenReturn(ndefMessage);
        NfcService nfcService = mock(NfcService.class);
        when(NfcService.getInstance()).thenReturn(nfcService);
        mNfcCharging.HandleWLCState();
        verify(nfcService).onWlcData(any());
        Assert.assertEquals(6, mNfcCharging.WLCState);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State12_WlcCtlMsgFalse() {
        mNfcCharging.WLCState = 4;
        NdefMessage ndefMessage = mock(NdefMessage.class);
        NdefRecord ndefRecord = mock(NdefRecord.class);
        when(ndefRecord.getType()).thenReturn(NfcCharging.WLCPI);

        NdefRecord[] records = {ndefRecord};
        when(ndefMessage.getRecords()).thenReturn(records);
        when(mTagEndpoint.getNdef()).thenReturn(ndefMessage);
        mNfcCharging.mNwcc_retry = 3;
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(0, mNfcCharging.mNwcc_retry);
        Assert.assertFalse(mNfcCharging.WLCL_Presence);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State12_WlcCtlMsgFalse_Retry() {
        mNfcCharging.WLCState = 4;
        NdefMessage ndefMessage = mock(NdefMessage.class);
        NdefRecord ndefRecord = mock(NdefRecord.class);
        when(ndefRecord.getType()).thenReturn(NfcCharging.WLCPI);

        NdefRecord[] records = {ndefRecord};
        when(ndefMessage.getRecords()).thenReturn(records);
        when(mTagEndpoint.getNdef()).thenReturn(ndefMessage);
        mNfcCharging.mNwcc_retry = 0;
        mNfcCharging.HandleWLCState();
        Assert.assertTrue(mNfcCharging.mNwcc_retry > 0);
        Assert.assertFalse(mNfcCharging.WLCL_Presence);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State16() {
        mNfcCharging.WLCState = 5;
        mNfcCharging.HandleWLCState();
        ArgumentCaptor<byte[]> captor = ArgumentCaptor.forClass(byte[].class);
        verify(mNfcCharging.TagHandler).writeNdef(captor.capture());
        Assert.assertNotNull(captor.getValue());
        Assert.assertEquals(6, mNfcCharging.WLCState);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State17() {
        mNfcCharging.WLCState = 6;
        mNfcCharging.WlcCtl_WptReq = 0x0;
        mNfcCharging.TWptDuration = 5000;
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(9, mNfcCharging.WLCState);
        ArgumentCaptor<DeviceHost.TagDisconnectedCallback> captor = ArgumentCaptor
                .forClass(DeviceHost.TagDisconnectedCallback.class);
        verify(mNfcCharging.TagHandler).startPresenceChecking(anyInt(), captor.capture());
        Assert.assertNotNull(captor.getValue());
    }

    @Test
    public void testTagDisconnectedCallback() {
        mNfcCharging.WLCState = 6;
        mNfcCharging.WlcCtl_WptReq = 0x0;
        mNfcCharging.TWptDuration = 5000;
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(9, mNfcCharging.WLCState);
        ArgumentCaptor<DeviceHost.TagDisconnectedCallback> captor = ArgumentCaptor
                .forClass(DeviceHost.TagDisconnectedCallback.class);
        verify(mNfcCharging.TagHandler).startPresenceChecking(anyInt(), captor.capture());
        DeviceHost.TagDisconnectedCallback callback = captor.getValue();
        Assert.assertNotNull(callback);
        NfcService nfcService = mock(NfcService.class);
        when(NfcService.getInstance()).thenReturn(nfcService);
        callback.onTagDisconnected();
        verify(nfcService).sendScreenMessageAfterNfcCharging();
        Assert.assertFalse(mNfcCharging.NfcChargingOnGoing);
        Assert.assertEquals(0, mNfcCharging.WLCState);
        verify(mNfcCharging.TagHandler).disconnect();
        Assert.assertTrue(mNfcCharging.mFirstOccurrence);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State22() {
        mNfcCharging.WLCState = 8;
        mNfcCharging.WlcCtl_WptInfoReq = 1;
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(3, mNfcCharging.WLCState);
        mNfcCharging.WLCState = 8;
        mNfcCharging.WlcCtl_WptInfoReq = 0;
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(4, mNfcCharging.WLCState);
    }

    @Test
    public void testHandleWlcCap_ModeReq_State24() {
        mNfcCharging.WLCState = 9;
        mNfcCharging.HandleWLCState();
        verify(mNfcCharging.TagHandler).stopPresenceChecking();
        Assert.assertEquals(0, mNfcCharging.WLCState);
    }

    @Test
    public void testHandleWlcCap_ModeReq_TimeCompleted() {
        mNfcCharging.WLCState = 10;
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(8, mNfcCharging.WLCState);
    }

    @Test
    public void testHandleWlcCap_ModeReq_TimeCompleted_Exit() {
        mNfcCharging.WLCState = 11;
        mNfcCharging.HandleWLCState();
        Assert.assertEquals(0, mNfcCharging.WLCState);
        Assert.assertFalse(mNfcCharging.NfcChargingOnGoing);
    }
}

