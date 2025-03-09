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

import android.os.Bundle;
import android.os.ResultReceiver;

import java.util.concurrent.CountDownLatch;

public class NfcCallbackResultReceiver extends ResultReceiver {
    CountDownLatch mCountDownLatch;
    OnReceiveResultListener mListener;
    public NfcCallbackResultReceiver(CountDownLatch latch, OnReceiveResultListener listener) {
        super(null);
        mListener = listener;
        mCountDownLatch = latch;
    }

    @Override
    protected void onReceiveResult(int resultCode, Bundle resultData) {
        mListener.onReceiveResult(resultCode, resultData);
        mCountDownLatch.countDown();
    }

    public static class OnReceiveResultListener {
        int resultCode;
        Bundle resultData;
        void onReceiveResult(int resultCode, Bundle resultData) {
            this.resultCode = resultCode;
            this.resultData = resultData;
        }

        public int getResultCode() {
            return resultCode;
        }

        public Bundle getResultData() {
            return resultData;
        }
    }
}
