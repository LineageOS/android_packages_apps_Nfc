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

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.content.pm.PackageManager;
import android.nfc.INfcUnlockHandler;
import android.nfc.Tag;
import android.os.IBinder;
import android.os.RemoteException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.mockito.MockitoSession;
import org.mockito.quality.Strictness;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.android.dx.mockito.inline.extended.ExtendedMockito;

@RunWith(AndroidJUnit4.class)
public class NfcUnlockManagerTest {
    private MockitoSession mStaticMockSession;
    private NfcUnlockManager mNfcUnlockManager;


    @Before
    public void setUp() throws PackageManager.NameNotFoundException {
        mStaticMockSession = ExtendedMockito.mockitoSession()
                .strictness(Strictness.LENIENT)
                .startMocking();

        MockitoAnnotations.initMocks(this);
        mNfcUnlockManager = NfcUnlockManager.getInstance();
    }

    @After
    public void tearDown() {
        mStaticMockSession.finishMocking();
    }

    @Test
    public void testAddUnlockHandler() {
        INfcUnlockHandler unlockHandler = mock(INfcUnlockHandler.class);
        IBinder iBinder = mock(IBinder.class);
        when(unlockHandler.asBinder()).thenReturn(iBinder);
        int result = mNfcUnlockManager.addUnlockHandler(unlockHandler, 1);
        assertThat(result).isEqualTo(1);
    }

    @Test
    public void testRemoveUnlockHandler() {
        INfcUnlockHandler unlockHandler = mock(INfcUnlockHandler.class);
        IBinder iBinder = mock(IBinder.class);
        when(unlockHandler.asBinder()).thenReturn(iBinder);
        int result = mNfcUnlockManager.addUnlockHandler(unlockHandler, 1);
        assertThat(result).isEqualTo(1);

        int pollMask = mNfcUnlockManager.getLockscreenPollMask();
        assertThat(pollMask).isEqualTo(result);
        result = mNfcUnlockManager.removeUnlockHandler(iBinder);
        assertThat(pollMask).isEqualTo(1);
    }

    @Test
    public void testTryUnlock() throws RemoteException {
        INfcUnlockHandler unlockHandler = mock(INfcUnlockHandler.class);
        IBinder iBinder = mock(IBinder.class);
        when(unlockHandler.asBinder()).thenReturn(iBinder);
        int result = mNfcUnlockManager.addUnlockHandler(unlockHandler, 1);
        assertThat(result).isEqualTo(1);

        Tag tag = mock(Tag.class);
        when(unlockHandler.onUnlockAttempted(tag)).thenReturn(true);
        boolean status = mNfcUnlockManager.tryUnlock(tag);
        assertThat(status).isTrue();
    }

    @Test
    public void testIsLockScreenPollingEnabled() {
        INfcUnlockHandler unlockHandler = mock(INfcUnlockHandler.class);
        IBinder iBinder = mock(IBinder.class);
        when(unlockHandler.asBinder()).thenReturn(iBinder);
        int result = mNfcUnlockManager.addUnlockHandler(unlockHandler, 1);
        assertThat(result).isEqualTo(1);

        boolean lockScreenPollMask = mNfcUnlockManager.isLockscreenPollingEnabled();
        assertThat(lockScreenPollMask).isTrue();
    }

    @Test
    public void testGetLockScreenPollMask() {
        INfcUnlockHandler unlockHandler = mock(INfcUnlockHandler.class);
        IBinder iBinder = mock(IBinder.class);
        when(unlockHandler.asBinder()).thenReturn(iBinder);
        int result = mNfcUnlockManager.addUnlockHandler(unlockHandler, 1);
        assertThat(result).isEqualTo(1);

        int status = mNfcUnlockManager.getLockscreenPollMask();
        assertThat(status).isEqualTo(result);
    }
}
