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
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.nfc.NfcAdapter;
import android.os.BugreportManager;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.android.dx.mockito.inline.extended.ExtendedMockito;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.MockitoSession;
import org.mockito.quality.Strictness;

import java.util.ArrayList;
import java.util.List;

@RunWith(AndroidJUnit4.class)
public class NfcDiagnosticsTest {

    private MockitoSession mStaticMockSession;
    private NfcDiagnostics mNfcDiagnostics;
    @Mock
    Context mContext;
    @Mock
    PackageManager mPackageManager;
    @Mock
    BugreportManager mBugreportManager;
    @Captor
    ArgumentCaptor<Intent> mIntentArgumentCaptor;

    @Before
    public void setUp() throws PackageManager.NameNotFoundException {
        mStaticMockSession = ExtendedMockito.mockitoSession()
                .strictness(Strictness.LENIENT)
                .startMocking();

        MockitoAnnotations.initMocks(this);

        when(mContext.getSystemService(BugreportManager.class)).thenReturn(mBugreportManager);
        List<ResolveInfo> list = new ArrayList<>();
        list.add(mock(ResolveInfo.class));
        when(mPackageManager.queryIntentActivities(any(), anyInt())).thenReturn(list);
        when(mContext.getPackageManager()).thenReturn(mPackageManager);

        mNfcDiagnostics = new NfcDiagnostics(mContext);
    }

    @After
    public void tearDown() {
        mStaticMockSession.finishMocking();
    }

    @Test
    public void testTakeBugReport() {
        mNfcDiagnostics.takeBugReport("test1", "test description");
        verify(mPackageManager).queryIntentActivities(mIntentArgumentCaptor.capture(), anyInt());
        Intent intent = mIntentArgumentCaptor.getValue();
        assertThat(intent).isNotNull();
        assertThat(intent.getStringExtra("EXTRA_ISSUE_TITLE")).isEqualTo("test1");
        assertThat(intent.getAction())
                .isEqualTo("com.google.android.apps.betterbug.intent.FILE_BUG_DEEPLINK");
        verify(mContext).startActivity(any());
    }

    @Test
    public void testTakeBugreportThroughBugreportManager() {
        when(mPackageManager.queryIntentActivities(any(), anyInt())).thenReturn(new ArrayList<>());
        mNfcDiagnostics.takeBugReport("test1", "test description");
        verify(mPackageManager).queryIntentActivities(mIntentArgumentCaptor.capture(), anyInt());
        Intent intent = mIntentArgumentCaptor.getValue();
        assertThat(intent).isNotNull();
        assertThat(intent.getStringExtra("EXTRA_ISSUE_TITLE")).isEqualTo("test1");
        assertThat(intent.getAction())
                .isEqualTo("com.google.android.apps.betterbug.intent.FILE_BUG_DEEPLINK");
        verify(mBugreportManager).requestBugreport(any(), anyString(), anyString());
    }
}
