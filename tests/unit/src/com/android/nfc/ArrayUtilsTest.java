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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.List;

public class ArrayUtilsTest {
    @Test
    public void testIsEmptyEmptyArray() {
        assertTrue(ArrayUtils.isEmpty((int[]) null));
        assertTrue(ArrayUtils.isEmpty(new int[0]));
    }

    @Test
    public void testIsEmptyNonEmptyArray() {
        assertFalse(ArrayUtils.isEmpty(new int[] {1, 2, 3}));
    }

    @Test
    public void testIsEmptyByteArrayNonEmptyArray() {
        assertFalse(ArrayUtils.isEmpty(new byte[] {1, 2, 3}));
    }

    @Test
    public void testIsEmptyByteArrayNullArray() {
        assertTrue(ArrayUtils.isEmpty((byte[]) null));
    }

    @Test
    public void testToPrimitiveSingleElementList() {
        List<byte[]> list = List.of(new byte[] {1, 2, 3});
        byte[] result = ArrayUtils.toPrimitive(list);
        assertArrayEquals(new byte[] {1, 2, 3}, result);
    }

    @Test
    public void testToPrimitiveEmptyList() {
        List<byte[]> list = List.of();
        byte[] result = ArrayUtils.toPrimitive(list);
        assertArrayEquals(new byte[0], result);
    }

    @Test
    public void testToIndexOfNotNullArray() {
        assertEquals(2, ArrayUtils.indexOf(new Integer[] {2, 0, -1, 5, 1}, -1));
    }

    @Test
    public void testToIndexOfNullArray() {
        assertEquals(-1, ArrayUtils.indexOf(null, 8));
    }

    @Test
    public void testToIndexOfValueNotFound() {
        assertEquals(-1, ArrayUtils.indexOf(new Character[] {'a', 'e', 'i', 'o', 'u'}, 'k'));
    }
}