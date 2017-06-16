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

package com.nxp.ese;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningAppProcessInfo;
import android.app.Application;
import android.os.Process;
import java.util.Iterator;
import java.util.List;

public class EseSpiApplication extends Application {

    static final String TAG = "SpiApplication";
    static final String SPI_PROCESS = "com.nxp.spi";

    EseSpiService mSpiService;

    public EseSpiApplication() {

    }

    @Override
    public void onCreate() {
        super.onCreate();

        boolean isMainProcess = false;
        //Check whether we're the main SPI service
        ActivityManager am = (ActivityManager)this.getSystemService(ACTIVITY_SERVICE);
        List processes = am.getRunningAppProcesses();
        Iterator i = processes.iterator();
        while (i.hasNext()) {
            RunningAppProcessInfo appInfo = (RunningAppProcessInfo)(i.next());
            if (appInfo.pid == Process.myPid()) {
                isMainProcess =  (SPI_PROCESS.equals(appInfo.processName));
                break;
            }
        }
        if (isMainProcess) {
            mSpiService = new EseSpiService(this);
        }
    }
}
