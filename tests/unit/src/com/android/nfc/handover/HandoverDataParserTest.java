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


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;

import com.android.nfc.handover.HandoverDataParser.BluetoothHandoverData;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class HandoverDataParserTest {
    @Mock
    private BluetoothAdapter mBluetoothAdapter;
    @Mock
    private NdefMessage mNdefMessage;
    @Mock
    private NdefRecord mNdefRecord;
    @Mock
    private BluetoothDevice mBluetoothDevice;
    @Mock
    private HandoverDataParser mockHandoverDataParser;
    private HandoverDataParser mHandoverDataParser;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        when(mNdefMessage.getRecords()).thenReturn(new NdefRecord[]{mNdefRecord});
        byte[] macAddress =
                new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,
                        (byte) 0xAB};
        when(mBluetoothAdapter.getRemoteDevice(macAddress)).thenReturn(mBluetoothDevice);
        mHandoverDataParser = new HandoverDataParser(mBluetoothAdapter) {
            @Override
            boolean isCarrierActivating(NdefRecord handoverRec, byte[] carrierId) {
                return true;
            }
        };
    }

    @Test
    public void testCreateCollisionRecord() {
        NdefRecord result = HandoverDataParser.createCollisionRecord();
        assertNotNull(result);
        assertEquals(NdefRecord.TNF_WELL_KNOWN, result.getTnf());
    }

    @Test
    public void testIsHandoverSupportedAdapterAvailable() {
        assertTrue(mHandoverDataParser.isHandoverSupported());
    }

    @Test
    public void testCreateBluetoothAlternateCarrierRecord() {
        NdefRecord ndefRecord = mHandoverDataParser.createBluetoothAlternateCarrierRecord(true);
        byte[] payload = ndefRecord.getPayload();
        assertNotNull(ndefRecord);
        assertEquals(1, payload[1]);
    }

    @Test
    public void testCreateHandoverRequestRecord() {
        NdefRecord ndefRecord = mHandoverDataParser.createHandoverRequestRecord();
        byte[] payload = ndefRecord.getPayload();
        assertNotNull(ndefRecord);
        assertArrayEquals(NdefRecord.RTD_HANDOVER_REQUEST, ndefRecord.getType());
        assertEquals((byte) 0x12, payload[0]);
    }

    @Test
    public void testIsHandoverNotSupported() {
        mHandoverDataParser = new HandoverDataParser(null);
        assertFalse(mHandoverDataParser.isHandoverSupported());
    }

    @Test
    public void testCreateHandoverSelectRecord() {
        NdefRecord alternateCarrier = mHandoverDataParser.createBluetoothAlternateCarrierRecord
                (true);
        NdefRecord result = mHandoverDataParser.createHandoverSelectRecord(alternateCarrier);
        byte[] payload = result.getPayload();
        assertNotNull(result);
        assertEquals((byte) 0x12, payload[0]);
    }

    @Test
    public void testParseNokiaValidPayload() {
        byte[] macAddress =
                new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,
                        (byte) 0xAB};
        String deviceName = "NokiaDevice";
        ByteBuffer payload = ByteBuffer.allocate(30);
        payload.put((byte) 0);
        payload.position(1);
        payload.put(macAddress);
        payload.position(14);
        payload.put((byte) deviceName.length());
        payload.put(deviceName.getBytes(StandardCharsets.UTF_8));
        payload.flip();
        BluetoothHandoverData result = mHandoverDataParser.parseNokia(payload);
        assertTrue(result.valid);
        assertEquals(deviceName, result.name);
    }

    @Test
    public void testParseNokiaWithInvalidBluetoothAddress() {
        byte[] invalidMacAddress = new byte[]{(byte) 0xFF};
        ByteBuffer payload = ByteBuffer.allocate(24);
        payload.put((byte) 0x00);
        payload.put(invalidMacAddress);
        payload.flip();
        BluetoothHandoverData result = mHandoverDataParser.parseNokia(payload);
        assertFalse(result.valid);
        assertNull(result.device);
        assertNull(result.name);
    }

    @Test
    public void testParseNokiaWithShortPayload() {
        ByteBuffer payload = ByteBuffer.allocate(10);
        payload.put((byte) 0x00);
        payload.flip();
        BluetoothHandoverData result = mHandoverDataParser.parseNokia(payload);
        assertFalse(result.valid);
        assertNull(result.device);
        assertNull(result.name);
    }

    @Test
    public void testParseBtOobValidShortName() {
        byte[] macAddress =
                new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,
                        (byte) 0xAB};
        String deviceName = "TestDevice";
        ByteBuffer payload = ByteBuffer.allocate(20);
        payload.put((byte) 0x00);
        payload.put((byte) 0x00);
        payload.put(macAddress);
        payload.put((byte) (deviceName.length() + 1));
        payload.put((byte) 0x08);
        payload.put(deviceName.getBytes(StandardCharsets.UTF_8));
        payload.flip();
        when(mBluetoothAdapter.getRemoteDevice(macAddress)).thenReturn(mBluetoothDevice);
        BluetoothHandoverData result = mHandoverDataParser.parseBtOob(payload);
        assertTrue(result.valid);
        assertEquals(deviceName, result.name);
    }

    @Test
    public void testParseBtOobWithEmptyPayload() {
        ByteBuffer emptyPayload = ByteBuffer.allocate(2);
        BluetoothHandoverData result = mHandoverDataParser.parseBtOob(
                emptyPayload);
        assertFalse(result.valid);
        assertNull(result.device);
        assertNull(result.name);
    }

    @Test
    public void testParseBtOobWithInvalidPayload() {
        ByteBuffer invalidPayload = ByteBuffer.allocate(10);
        invalidPayload.put((byte) 0x00);
        invalidPayload.put((byte) 0x00);
        invalidPayload.flip();
        BluetoothHandoverData result = mHandoverDataParser.parseBtOob(
                invalidPayload);
        assertFalse(result.valid);
        assertNull(result.device);
        assertNull(result.name);
    }

    @Test
    public void testParseBtOobWithLongLocalName() {
        byte[] macAddress =
                new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,
                        (byte) 0xAB};
        String deviceName = "TestLongDeviceName";
        ByteBuffer payload = ByteBuffer.allocate(30);
        payload.put((byte) 0x00);
        payload.put((byte) 0x00);
        payload.put(macAddress);
        payload.put((byte) (deviceName.length() + 1));
        payload.put((byte) 0x09);
        payload.put(deviceName.getBytes(StandardCharsets.UTF_8));
        payload.flip();
        when(mBluetoothAdapter.getRemoteDevice(macAddress)).thenReturn(mBluetoothDevice);
        BluetoothHandoverData result = mHandoverDataParser.parseBtOob(payload);
        assertTrue(result.valid);
        assertEquals(deviceName, result.name);
    }

    @Test
    public void testParseBtOobWith16BitUuidsPartial() {
        byte[] macAddress =
                new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,
                        (byte) 0xAB};
        ByteBuffer payload = ByteBuffer.allocate(20);
        payload.put((byte) 0x00);
        payload.put((byte) 0x00);
        payload.put(macAddress);
        payload.put((byte) 3);
        payload.put((byte) 0x02);
        payload.put((byte) 0x12);
        payload.put((byte) 0x34);
        payload.flip();
        when(mBluetoothAdapter.getRemoteDevice(macAddress)).thenReturn(mBluetoothDevice);
        BluetoothHandoverData result = mHandoverDataParser.parseBtOob(payload);
        assertTrue(result.valid);
        assertNotNull(result.uuids);
        assertEquals(1, result.uuids.length);
    }

    @Test
    public void testParseBtOobWithClassOfDevice() {
        byte[] macAddress =
                new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,
                        (byte) 0xAB};
        ByteBuffer payload = ByteBuffer.allocate(20);
        payload.put((byte) 0x00);
        payload.put((byte) 0x00);
        payload.put(macAddress);
        payload.put((byte) 4);
        payload.put((byte) 0x0D);
        payload.put((byte) 0x00);
        payload.put((byte) 0x1F);
        payload.put((byte) 0x00);
        payload.flip();
        when(mBluetoothAdapter.getRemoteDevice(macAddress)).thenReturn(mBluetoothDevice);
        BluetoothHandoverData result = mHandoverDataParser.parseBtOob(payload);
        assertTrue(result.valid);
        assertNotNull(result.btClass);
    }

    @Test
    public void testParseBtOobWithUnknownType() {
        byte[] macAddress =
                new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,
                        (byte) 0xAB};
        ByteBuffer payload = ByteBuffer.allocate(20);
        payload.put((byte) 0x00);
        payload.put((byte) 0x00);
        payload.put(macAddress);
        payload.put((byte) 3);
        payload.put((byte) 0xFF);
        payload.put((byte) 0x00);
        payload.put((byte) 0x00);
        payload.flip();
        when(mBluetoothAdapter.getRemoteDevice(macAddress)).thenReturn(mBluetoothDevice);
        BluetoothHandoverData result = mHandoverDataParser.parseBtOob(payload);
        assertTrue(result.valid);
        assertEquals("", result.name);
        assertNull(result.uuids);
        assertNull(result.btClass);
    }

    @Test
    public void testParseBleOobWithMacAddress() {
        when(mBluetoothAdapter.getRemoteDevice(any(byte[].class))).thenReturn(mBluetoothDevice);
        BluetoothHandoverData result = mHandoverDataParser.parseBleOob(blePayload());
        assertNotNull(result);
        assertTrue(result.valid);
        assertNotNull(result.device);
        assertEquals(mBluetoothDevice, result.device);
        verify(mBluetoothAdapter).getRemoteDevice(any(byte[].class));
    }

    @Test
    public void testParseBleOobWithCentralRoleOnly() {
        ByteBuffer payload = ByteBuffer.allocate(10);
        payload.put((byte) 2);
        payload.put((byte) 0x1C);
        payload.put((byte) 0x01);
        payload.flip();
        BluetoothHandoverData result = mHandoverDataParser.parseBleOob(payload);
        assertFalse(result.valid);
    }

    @Test
    public void testParseBluetoothWithBtOobRecord() {
        when(mNdefRecord.getTnf()).thenReturn(NdefRecord.TNF_MIME_MEDIA);
        when(mNdefRecord.getType()).thenReturn("application/vnd.bluetooth.ep.oob"
                .getBytes(StandardCharsets.US_ASCII));
        when(mNdefRecord.getPayload()).thenReturn(btPayload().array());
        when(mNdefRecord.getId()).thenReturn(new byte[]{0x10});
        BluetoothHandoverData result = mHandoverDataParser.parseBluetooth(mNdefMessage);
        assertNotNull(result);
    }

    @Test
    public void testParseBluetoothWithBleOobRecord() {
        when(mBluetoothAdapter.getRemoteDevice(any(byte[].class))).thenReturn(mBluetoothDevice);
        when(mNdefRecord.getTnf()).thenReturn(NdefRecord.TNF_MIME_MEDIA);
        when(mNdefRecord.getType()).thenReturn("application/vnd.bluetooth.le.oob"
                .getBytes(StandardCharsets.US_ASCII));
        when(mNdefRecord.getPayload()).thenReturn(blePayload().array());
        BluetoothHandoverData result = mHandoverDataParser.parseBluetooth(mNdefMessage);
        assertNotNull(result);
    }

    @Test
    public void testParseBluetoothWithNokiaRecord() {
        byte[] macAddress =
                new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,
                        (byte) 0xAB};
        String deviceName = "NokiaDevice";
        ByteBuffer payload = ByteBuffer.allocate(30);
        payload.put((byte) 0);
        payload.position(1);
        payload.put(macAddress);
        payload.position(14);
        payload.put((byte) deviceName.length());
        payload.put(deviceName.getBytes(StandardCharsets.UTF_8));
        payload.flip();

        when(mNdefRecord.getTnf()).thenReturn(NdefRecord.TNF_EXTERNAL_TYPE);
        when(mNdefRecord.getType()).thenReturn(
                "nokia.com:bt".getBytes(StandardCharsets.US_ASCII));
        when(mNdefRecord.getPayload()).thenReturn(payload.array());
        BluetoothHandoverData result = mHandoverDataParser.parseBluetooth(mNdefMessage);
        assertNotNull(result);
        assertTrue(result.valid);
        assertEquals(deviceName, result.name);
    }

    @Test
    public void testParseBluetoothWithUnknownType() {
        when(mNdefRecord.getTnf()).thenReturn(NdefRecord.TNF_MIME_MEDIA);
        when(mNdefRecord.getType()).thenReturn(new byte[]{0x03, 0x04});
        BluetoothHandoverData result = mockHandoverDataParser.parseBluetooth(mNdefMessage);
        verify(mockHandoverDataParser, never()).parseBtOob(any(ByteBuffer.class));
        verify(mockHandoverDataParser, never()).parseBleOob(any(ByteBuffer.class));
        verify(mockHandoverDataParser, never()).parseBluetoothHandoverSelect(
                any(NdefMessage.class));
        verify(mockHandoverDataParser, never()).parseNokia(any(ByteBuffer.class));
        assertNull(result);
    }

    @Test
    public void testParseBluetoothHandoverSelectWithBtOobRecordAndCarrierActivating() {
        when(mNdefRecord.getTnf()).thenReturn(NdefRecord.TNF_MIME_MEDIA);
        when(mNdefRecord.getType()).thenReturn("application/vnd.bluetooth.ep.oob"
                .getBytes(StandardCharsets.US_ASCII));
        when(mNdefRecord.getPayload()).thenReturn(btPayload().array());
        when(mNdefRecord.getId()).thenReturn(new byte[]{0x10});
        BluetoothHandoverData result = mHandoverDataParser.parseBluetoothHandoverSelect(
                mNdefMessage);
        assertNotNull(result);
        assertTrue(result.carrierActivating);
    }

    @Test
    public void testParseBluetoothHandoverSelectWithBleOobRecord() {
        when(mBluetoothAdapter.getRemoteDevice(any(byte[].class))).thenReturn(mBluetoothDevice);
        when(mNdefRecord.getTnf()).thenReturn(NdefRecord.TNF_MIME_MEDIA);
        when(mNdefRecord.getType()).thenReturn("application/vnd.bluetooth.le.oob"
                .getBytes(StandardCharsets.US_ASCII));
        when(mNdefRecord.getPayload()).thenReturn(blePayload().array());
        BluetoothHandoverData result = mHandoverDataParser.parseBluetoothHandoverSelect(
                mNdefMessage);
        assertNotNull(result);
        assertTrue(result.valid);
    }

    @Test
    public void testParseBluetoothHandoverSelectWithNoMatchingRecord() {
        when(mNdefRecord.getTnf()).thenReturn(NdefRecord.TNF_MIME_MEDIA);
        when(mNdefRecord.getType()).thenReturn(new byte[]{0x03, 0x04});
        BluetoothHandoverData result = mockHandoverDataParser.parseBluetoothHandoverSelect(
                mNdefMessage);
        verify(mockHandoverDataParser, never()).parseBtOob(any(ByteBuffer.class));
        verify(mockHandoverDataParser, never()).parseBleOob(any(ByteBuffer.class));
        verify(mockHandoverDataParser, never()).isCarrierActivating(any(NdefRecord.class),
                any(byte[].class));
        assertNull(result);
    }

    @Test
    public void testGetOutgoingHandoverData() {
        when(mBluetoothAdapter.getRemoteDevice(any(byte[].class))).thenReturn(mBluetoothDevice);
        when(mNdefRecord.getTnf()).thenReturn(NdefRecord.TNF_MIME_MEDIA);
        when(mNdefRecord.getType()).thenReturn("application/vnd.bluetooth.le.oob"
                .getBytes(StandardCharsets.US_ASCII));
        when(mNdefRecord.getPayload()).thenReturn(blePayload().array());
        BluetoothHandoverData result = mHandoverDataParser.getOutgoingHandoverData(
                mNdefMessage);
        assertNotNull(result);
        assertTrue(result.valid);
    }

    @Test
    public void testAddressToReverseBytesWithValidAddress() {
        String address = "01:23:45:67:89:AB";
        byte[] result = HandoverDataParser.addressToReverseBytes(address);
        assertNotNull(result);
        assertEquals(6, result.length);
        assertArrayEquals(
                new byte[]{(byte) 0xAB, (byte) 0x89, (byte) 0x67, (byte) 0x45, (byte) 0x23,
                        (byte) 0x01}, result);
    }

    @Test
    public void testAddressToReverseBytesWithNullAddress() {
        byte[] result = HandoverDataParser.addressToReverseBytes(null);
        assertNull(result);
    }

    @Test
    public void testAddressToReverseBytesWithInvalidAddress() {
        String address = "01:23:45:67:89";
        byte[] result = HandoverDataParser.addressToReverseBytes(address);
        assertNull(result);
    }

    @Test
    public void testAddressToReverseBytesWithInvalidHexValues() {
        String address = "01:23:45:67:89:GZ";
        try {
            HandoverDataParser.addressToReverseBytes(address);
            fail("Expected NumberFormatException to be thrown");
        } catch (NumberFormatException e) {
            assertTrue(e.getMessage().contains("For input string: \"GZ\""));
        }
    }

    private ByteBuffer blePayload() {
        ByteBuffer payload = ByteBuffer.allocate(20);
        payload.put((byte) 0x07); // Length
        payload.put((byte) 0x1B); // Type
        payload.put((byte) 0x01); // MAC Address Byte 1
        payload.put((byte) 0x02); // MAC Address Byte 2
        payload.put((byte) 0x03); // MAC Address Byte 3
        payload.put((byte) 0x04); // MAC Address Byte 4
        payload.put((byte) 0x05); // MAC Address Byte 5
        payload.put((byte) 0x06); // MAC Address Byte 6
        payload.put((byte) 8);
        payload.put((byte) 0x04);
        byte[] leScC = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        payload.put(leScC);
        payload.flip(); // Reset position to read from the beginning
        return payload;
    }

    private ByteBuffer btPayload() {
        byte[] macAddress =
                new byte[]{(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,
                        (byte) 0xAB};
        String deviceName = "TestLongDeviceName";
        ByteBuffer payload = ByteBuffer.allocate(30);
        payload.put((byte) 0x00);
        payload.put((byte) 0x00);
        payload.put(macAddress);
        payload.put((byte) (deviceName.length() + 1));
        payload.put((byte) 0x09);
        payload.put(deviceName.getBytes(StandardCharsets.UTF_8));
        payload.flip();
        return payload;
    }
}