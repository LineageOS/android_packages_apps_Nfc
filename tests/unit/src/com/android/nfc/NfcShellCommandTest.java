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

package com.android.nfc;


import static com.google.common.truth.Truth.assertThat;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.RemoteException;

import com.android.dx.mockito.inline.extended.ExtendedMockito;
import com.android.nfc.cardemulation.CardEmulationManager;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.MockitoSession;
import org.mockito.quality.Strictness;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import static org.mockito.ArgumentMatchers.isNull;
import android.nfc.INfcDta;
import android.nfc.INfcCardEmulation;


import java.io.FileDescriptor;
import java.io.PrintWriter;

@RunWith(AndroidJUnit4.class)
public class NfcShellCommandTest {
    @Mock
    Context mContext;
    @Mock
    NfcService mNfcService;
    @Mock
    PrintWriter mPrintWriter;
    @Mock
    Binder mBinder;
    @Mock
    FileDescriptor mFileDescriptorIn;
    @Mock
    FileDescriptor mFileDescriptorOut;
    @Mock
    FileDescriptor mFileDescriptorErr;

    private NfcShellCommand mNfcShellCommand;

    private MockitoSession mStaticMockSession;

    @Before
    public void setUp() throws PackageManager.NameNotFoundException {
        mStaticMockSession = ExtendedMockito.mockitoSession()
                .mockStatic(ArrayUtils.class)
                .strictness(Strictness.LENIENT)
                .startMocking();
        MockitoAnnotations.initMocks(this);

        mNfcShellCommand = new NfcShellCommand(mNfcService, mContext, mPrintWriter);
        mNfcShellCommand
                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                        mFileDescriptorErr,
                        new String[]{"test", "enable-polling", "disable-polling"}, 0);
    }

    @After
    public void tearDown() {
        mStaticMockSession.finishMocking();
    }

    @Test
    public void testOnCommandStatus() {
        when(mNfcService.isNfcEnabled()).thenReturn(true);
        int status = mNfcShellCommand.onCommand("status");
        assertThat(status).isEqualTo(0);
        verify(mPrintWriter).println("Nfc is enabled");
    }

    @Test
    public void testOnCommandDisableNfc() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        int status = mNfcShellCommand.onCommand("disable-nfc");
        verify(nfcAdapterService).disable(anyBoolean(), any());
        assertThat(status).isEqualTo(0);
    }

    @Test
    public void testOnCommandEnableNfc() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        when(mContext.getPackageName()).thenReturn("com.android.test");
        int status = mNfcShellCommand.onCommand("enable-nfc");
        verify(nfcAdapterService).enable("com.android.test");
        assertThat(status).isEqualTo(0);
    }

    @Test
    public void testOnCommandSetReaderMode() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        when(ArrayUtils.indexOf(any(), anyString())).thenReturn(0);
        mNfcShellCommand
                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                        mFileDescriptorErr, new String[]{"enable-polling"}, 0);
        int status = mNfcShellCommand.onCommand("set-reader-mode");
        verify(nfcAdapterService).setReaderMode(any(), isNull(), anyInt(), isNull(), isNull());
        assertThat(status).isEqualTo(0);
    }

    @Test
    public void testOnCommandSetObserveMode() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        when(ArrayUtils.indexOf(any(), anyString())).thenReturn(0);
        mNfcShellCommand
                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                        mFileDescriptorErr, new String[]{"enable"}, 0);
        int status = mNfcShellCommand.onCommand("set-observe-mode");
        verify(nfcAdapterService).setObserveMode(anyBoolean(), isNull());
        assertThat(status).isEqualTo(0);
    }


    @Test
    public void testOnCommandSetControllerAlwaysOn() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        mNfcShellCommand
                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                        mFileDescriptorErr, new String[]{"1"}, 0);
        int status = mNfcShellCommand.onCommand("set-controller-always-on");
        verify(nfcAdapterService).setControllerAlwaysOn(anyInt());
        assertThat(status).isEqualTo(0);
    }

    @Test
    public void testOnCommandSetDiscoveryTech() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        mNfcShellCommand
                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                        mFileDescriptorErr, new String[]{"1", "2"}, 0);
        when(mContext.getPackageName()).thenReturn("com.android.test");
        int status = mNfcShellCommand.onCommand("set-discovery-tech");
        verify(nfcAdapterService).updateDiscoveryTechnology(any(), anyInt(), anyInt(), anyString());
        assertThat(status).isEqualTo(0);
    }

    @Test
    public void testOnCommandConfigureDta() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        mNfcShellCommand
                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                        mFileDescriptorErr, new String[]{"enable"}, 0);
        when(mContext.getPackageName()).thenReturn("com.android.test");
        INfcDta dtaService = mock(INfcDta.class);
        when(nfcAdapterService.getNfcDtaInterface("com.android.test")).thenReturn(dtaService);
        int status = mNfcShellCommand.onCommand("configure-dta");
        verify(mPrintWriter).println("  configure-dta");
        verify(mPrintWriter).println("  enableDta()");
        verify(dtaService).enableDta();
        assertThat(status).isEqualTo(0);
    }

    @Test
    public void testOnCommandSetOffHostSe() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        mNfcShellCommand
                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                        mFileDescriptorErr, new String[]{"1", "com.android.test",
                                "NfcTest", "test"}, 0);
        CardEmulationManager cardEmulationManager = mock(CardEmulationManager.class);
        INfcCardEmulation iNfcCardEmulation = mock(INfcCardEmulation.class);
        when(cardEmulationManager.getNfcCardEmulationInterface()).thenReturn(iNfcCardEmulation);
        mNfcService.mCardEmulationManager = cardEmulationManager;
        int status = mNfcShellCommand.onCommand("set-offhost-se");
        verify(cardEmulationManager).getNfcCardEmulationInterface();
        verify(iNfcCardEmulation).setOffHostForService(anyInt(), any(), anyString());
        assertThat(status).isEqualTo(0);
    }

    @Test
    public void testOnCommandResetOffHostSe() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        mNfcShellCommand
                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                        mFileDescriptorErr, new String[]{"1", "com.android.test",
                                "NfcTest"}, 0);
        CardEmulationManager cardEmulationManager = mock(CardEmulationManager.class);
        INfcCardEmulation iNfcCardEmulation = mock(INfcCardEmulation.class);
        when(cardEmulationManager.getNfcCardEmulationInterface()).thenReturn(iNfcCardEmulation);
        mNfcService.mCardEmulationManager = cardEmulationManager;
        int status = mNfcShellCommand.onCommand("reset-offhost-se");
        verify(cardEmulationManager).getNfcCardEmulationInterface();
        verify(iNfcCardEmulation).unsetOffHostForService(anyInt(), any());
        assertThat(status).isEqualTo(0);
    }

    @Test
    public void testOnCommandRegisterAidGroup() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        mNfcShellCommand
                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                        mFileDescriptorErr, new String[]{"1", "com.android.test",
                                "NfcTest", "325041592E5359532E4444463031", "payment"}, 0);
        CardEmulationManager cardEmulationManager = mock(CardEmulationManager.class);
        INfcCardEmulation iNfcCardEmulation = mock(INfcCardEmulation.class);
        when(cardEmulationManager.getNfcCardEmulationInterface()).thenReturn(iNfcCardEmulation);
        mNfcService.mCardEmulationManager = cardEmulationManager;
        int status = mNfcShellCommand.onCommand("register-aid-group");
        verify(cardEmulationManager).getNfcCardEmulationInterface();
        verify(iNfcCardEmulation).registerAidGroupForService(anyInt(), any(), any());
        assertThat(status).isEqualTo(0);
    }


    @Test
    public void testOnCommandRemoveAidGroup() throws RemoteException {
        NfcService.NfcAdapterService nfcAdapterService = mock(NfcService.NfcAdapterService.class);
        mNfcService.mNfcAdapter = nfcAdapterService;
        mNfcShellCommand
                .init(mBinder, mFileDescriptorIn, mFileDescriptorOut,
                        mFileDescriptorErr, new String[]{"1", "com.android.test",
                                "NfcTest", "payment"}, 0);
        CardEmulationManager cardEmulationManager = mock(CardEmulationManager.class);
        INfcCardEmulation iNfcCardEmulation = mock(INfcCardEmulation.class);
        when(cardEmulationManager.getNfcCardEmulationInterface()).thenReturn(iNfcCardEmulation);
        mNfcService.mCardEmulationManager = cardEmulationManager;
        int status = mNfcShellCommand.onCommand("remove-aid-group");
        verify(cardEmulationManager).getNfcCardEmulationInterface();
        verify(iNfcCardEmulation).removeAidGroupForService(anyInt(), any(), any());
        assertThat(status).isEqualTo(0);
    }
}
