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
package com.android.nfc.cardemulation.util;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.content.pm.PackageManager;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.android.dx.mockito.inline.extended.ExtendedMockito;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.mockito.MockitoSession;
import org.mockito.quality.Strictness;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@RunWith(AndroidJUnit4.class)
public class NfcFileUtilsTest {

    private MockitoSession mStaticMockSession;

    @Before
    public void setUp() throws PackageManager.NameNotFoundException {
        mStaticMockSession = ExtendedMockito.mockitoSession()
                .mockStatic(Files.class)
                .strictness(Strictness.LENIENT)
                .startMocking();

        MockitoAnnotations.initMocks(this);
    }

    @After
    public void tearDown() {
        mStaticMockSession.finishMocking();
    }


    @Test
    public void testIsEmptyDir() {
        File fileDir = mock(File.class);
        File file = mock(File.class);
        when(fileDir.listFiles()).thenReturn(new File[]{file});
        boolean isEmptyDir = NfcFileUtils.isEmptyDir(fileDir);
        assertThat(isEmptyDir).isFalse();
    }

    @Test
    public void testMoveFiles() throws IOException {
        File sourceDir = mock(File.class);
        File file = mock(File.class);
        when(file.getName()).thenReturn("test");
        when(sourceDir.listFiles()).thenReturn(new File[]{file});
        File targetDir = new File("test");
        when(sourceDir.toPath()).thenReturn(mock(Path.class));
        when(Files.move(any(), any(), any())).thenReturn(mock(Path.class));
        int result = NfcFileUtils.moveFiles(sourceDir, targetDir);
        assertThat(result).isEqualTo(1);

    }
}
