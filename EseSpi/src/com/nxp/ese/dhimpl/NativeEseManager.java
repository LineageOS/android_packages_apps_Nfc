/*
 * Copyright (C) 2014 NXP Semiconductors
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

package com.nxp.ese.dhimpl;

import java.lang.reflect.Method;
import com.nxp.ese.EseSpiService;

import android.content.SharedPreferences;
import android.content.Context;
import android.util.Log;

import com.nxp.ese.DeviceHost;



public class NativeEseManager{

    static {
        System.loadLibrary("ese_spi_jni");
    }


    private final Context mContext;

    static final boolean DBG = true;
    private final String TAG = "NativeEseManager";
    static final String PREF = "NativeSpiPrefs";
    private final EseSpiService mListener;


    public NativeEseManager(Context context, EseSpiService listener) {
        mContext = context;
        initializeNativeStructure();
        mListener = listener;
    }

    /**
     * Notifies transaction to SPI Service
     */
    public void notifyEseManagerServiceListeners(int status) {
        if(status == -1)
            return;
        Log.d(TAG, "notifyEseServiceListeners in SPI Service " + "Status: " + status);
        mListener.notifyEseServiceListeners(status);
    }

    public native boolean initializeNativeStructure();

    public native void doAbort();


    public native boolean doInitialize(int timeout);

    public native boolean doDeinitialize();

    public native boolean doReset();

    public native int doStartJcopDownload();

    public native boolean doIntfReset();

    public native byte[] doTransceive(byte[] data);

    public boolean deinitialize() {
        SharedPreferences prefs = mContext.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        return doDeinitialize();
    }

    public byte[] manageTransceive(byte[] data)
    {
        return doTransceive(data);
    }
    public native int doGetSeInterface(int type);
    public native boolean doCheckJcopDlAtBoot();

}
