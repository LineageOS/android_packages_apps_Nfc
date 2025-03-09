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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.content.res.Resources;
import android.os.Handler;
import android.os.IBinder;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.android.dx.mockito.inline.extended.ExtendedMockito;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.MockitoSession;
import org.mockito.quality.Strictness;

import java.util.ArrayList;
import java.util.List;


@RunWith(AndroidJUnit4.class)
public class DtaServiceConnectorTest {
    @Mock
    Context mContext;
    @Mock
    private PackageManager mPackageManager;
    private MockitoSession mStaticMockSession;
    private DtaServiceConnector mDtaServiceConnector;


    @Before
    public void setUp() throws Exception {
        mStaticMockSession = ExtendedMockito.mockitoSession()
                .strictness(Strictness.LENIENT)
                .startMocking();
        MockitoAnnotations.initMocks(this);

        when(mContext.getPackageManager()).thenReturn(mPackageManager);
        mDtaServiceConnector = new DtaServiceConnector(mContext);
    }

    @After
    public void tearDown() throws Exception {
        mStaticMockSession.finishMocking();
    }

    @Test
    public void testCreateExplicitFromImplicitIntent() {
        Intent implicitIntent = mock(Intent.class);
        ResolveInfo resolveInfo = mock(ResolveInfo.class);
        resolveInfo.serviceInfo = mock(ServiceInfo.class);
        resolveInfo.serviceInfo.packageName = "com.android.nfc";
        resolveInfo.serviceInfo.name = "Nfc";
        List<ResolveInfo> resolveInfos = new ArrayList<>();
        resolveInfos.add(resolveInfo);
        when(mPackageManager.queryIntentServices(implicitIntent, 0)).thenReturn(resolveInfos);
        Intent intent = DtaServiceConnector.createExplicitFromImplicitIntent(mContext,
                implicitIntent);
        Assert.assertNotNull(intent);
        ComponentName componentName = intent.getComponent();
        Assert.assertNotNull(componentName);
        Assert.assertEquals("com.android.nfc", componentName.getPackageName());
    }

    @Test
    public void testBindService() {
        mDtaServiceConnector.bindService();
        ArgumentCaptor<Intent> intentArgumentCaptor = ArgumentCaptor.forClass(Intent.class);
        ArgumentCaptor<ServiceConnection> serviceConnectionArgumentCaptor = ArgumentCaptor.forClass(
                ServiceConnection.class);
        verify(mContext).bindService(intentArgumentCaptor.capture(),
                serviceConnectionArgumentCaptor.capture(), anyInt());
        ServiceConnection serviceConnection = serviceConnectionArgumentCaptor.getValue();
        Assert.assertNotNull(serviceConnection);
        ComponentName componentName = mock(ComponentName.class);
        serviceConnection.onServiceConnected(componentName, mock(IBinder.class));
        assertThat(mDtaServiceConnector.dtaMessenger).isNotNull();
        assertThat(mDtaServiceConnector.isBound).isTrue();

        serviceConnection.onServiceDisconnected(componentName);
        assertThat(mDtaServiceConnector.dtaMessenger).isNull();
        assertThat(mDtaServiceConnector.isBound).isFalse();
    }

    @Test
    public void testSendMessage() throws RemoteException {
        mDtaServiceConnector.dtaMessenger = mock(Messenger.class);
        mDtaServiceConnector.isBound = true;
        mDtaServiceConnector.sendMessage("message");
        verify(mDtaServiceConnector.dtaMessenger).send(any());
    }

    @Test
    public void testSetMessageService() {
        mDtaServiceConnector.isBound = false;
        DtaServiceConnector.setMessageService("test");
        ResolveInfo resolveInfo = mock(ResolveInfo.class);
        resolveInfo.serviceInfo = mock(ServiceInfo.class);
        resolveInfo.serviceInfo.packageName = "com.android.nfc";
        resolveInfo.serviceInfo.name = "Nfc";
        List<ResolveInfo> resolveInfos = new ArrayList<>();
        resolveInfos.add(resolveInfo);
        when(mPackageManager.queryIntentServices(any(), anyInt())).thenReturn(resolveInfos);
        mDtaServiceConnector.bindService();
        ArgumentCaptor<Intent> intentArgumentCaptor = ArgumentCaptor.forClass(Intent.class);
        verify(mContext).bindService(intentArgumentCaptor.capture(), any(), anyInt());
        Intent intent = intentArgumentCaptor.getValue();
        Assert.assertNotNull(intent);
        assertThat(intent.getAction()).isEqualTo("test");
    }
}
