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

import android.content.Context;

import com.nxp.ese.dhimpl.NativeEseManager;
import com.nxp.ese.dhimpl.NativeEseAla;

import android.app.Application;
import android.content.SharedPreferences;
import com.nxp.ese.spi.EseSpiAdapter;
import android.os.PowerManager;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Process;
import android.util.Log;
import com.nxp.ese.spi.IEseSpiAdapter;
import com.nxp.intf.ILoaderService;
import com.nxp.intf.IJcopService;
import com.nxp.intf.INxpExtrasService;
import com.nxp.intf.IeSEClientServicesAdapter;
import android.os.RemoteException;
import java.io.IOException;

import android.os.Bundle;
import android.os.IBinder;
import android.os.ServiceManager;
import android.os.Handler;
import android.os.Message;
import android.content.BroadcastReceiver;
import android.os.UserHandle;
import android.os.Binder;
import android.app.ActivityManager;
import android.app.Application;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.List;
import java.io.PrintWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileNotFoundException;

import android.content.ComponentName;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
//import src.com.android.nfc.NfcService.WatchDogThread;
import android.os.AsyncTask;

import java.security.MessageDigest;

class WatchDog implements Runnable {
        static String TAG = "SPI_WDT:";
        static boolean sIsThreadPoolInitialized = false;
        static int MAX_NUM_WATCHDOGS=10;
        static ExecutorService sExecutor = Executors.newFixedThreadPool(MAX_NUM_WATCHDOGS);
        static LinkedBlockingDeque<WatchDog> sWatchDogTaskQ = new LinkedBlockingDeque<WatchDog>(MAX_NUM_WATCHDOGS);
        final  Object mCancelWaiter = new Object();
        int mTimeout = 0;
        NativeEseManager mSpiMgr = null;
        String mTaskName;
        String mWatchDogNum;
        boolean mWatchDogCancelled = false;
        private WatchDog(String taskName,int timeout,String watchDogNum) {
            mTaskName    = taskName;
            mTimeout     = timeout;
            mWatchDogNum = watchDogNum;
            Log.i(TAG,"WatchDog constructed with Num:"+mWatchDogNum);
        }
        /*As watchdog's are used by invocation of each API, Reuse of threads used by watchdog is essential.
         * So Pool of watchdog threads(Executors)& and corresponding set of WorkQueues (TaskQueues) are registered.
         * When a watchdog is requested, a task from TaskQueue is retreived and assigned to a worker thread in executor's thread pool*/
        public static WatchDog getWatchdogTimer(String taskName, int timeout, NativeEseManager spiMgr){
            WatchDog wdg = null;
            Log.i(TAG,"WatchDog getWatchdogTimer from Pool with name:"+taskName);
            try{
                if(!sIsThreadPoolInitialized){
                    Log.i(TAG,"WatchDog Initialize Watchdog Runnables");
                    for(int i=0;i<MAX_NUM_WATCHDOGS;i++){
                        sWatchDogTaskQ.put(new WatchDog("Default",100,"WATCHDOG_"+i));
                    }
                    sIsThreadPoolInitialized = true;
                }
                wdg = sWatchDogTaskQ.take();
                if(wdg != null){
                    wdg.mTaskName   = taskName;
                    wdg.mTimeout    = timeout;
                    wdg.mSpiMgr     =  spiMgr;
                    wdg.mWatchDogCancelled = false;
                    Log.i(TAG,"WatchDog Allocated.for task:"+taskName+":timeout:"+wdg.mTimeout+":Num:"+wdg.mWatchDogNum);
                }
            }catch (InterruptedException e) {
                Log.i(TAG,"getWatchdogTimer thread interrupted.");
                e.printStackTrace();
            }
            return wdg;
        }
        public void setTimeOut(int newTimeout){
            mTimeout = newTimeout;
        }
        @Override
        public void run() {
            synchronized (mCancelWaiter) {
                try{
                    Log.i(TAG,"WatchDog thread Running:"+mTaskName);
                    mCancelWaiter.wait(mTimeout);
                    if(!mWatchDogCancelled){
                        Log.i(TAG, "Watchdog expired:name="+mTaskName +":timeout="+ mTimeout+":Num:"+mWatchDogNum);
                        if(mSpiMgr != null){
                           mSpiMgr.doAbort();
                        }
                    }
                    Log.i(TAG,"Watchdog Adding task back to queue"+":Num:"+mWatchDogNum);
                    sWatchDogTaskQ.put(this);
                    mWatchDogCancelled = false;
                } catch (InterruptedException e) {
                    Log.i(TAG,"Watchdog thread interrupted.");
                    e.printStackTrace();
                }
            }
        }
        public synchronized void cancel() {
            synchronized (mCancelWaiter) {
                Log.i(TAG,"Watchdog thread Cancelled."+":timeout="+ mTimeout+":Num:"+mWatchDogNum);
                mWatchDogCancelled = true;
                mCancelWaiter.notify();
            }
        }
        public synchronized void start() {
            Log.i(TAG,"Watchdog thread starting:"+mTaskName+":timeout="+ mTimeout+":Num:"+mWatchDogNum);
            /*Execute the task(this/runnable) in a executor worker thread*/
            sExecutor.execute(this);
        }
}
public class EseSpiService implements DeviceHost{

    /**SPI ADMIN permission - only for system apps */
    private static final String ADMIN_PERM = android.Manifest.permission.WRITE_SECURE_SETTINGS;
    private static final String ADMIN_PERM_ERROR = "WRITE_SECURE_SETTINGS permission required";
    static final String NFC_PERMISSION = android.Manifest.permission.NFC;
    private static final String NFC_PERM_ERROR = "NFC permission required";
    public static final String ACTION_ESE_SUCCESS = "com.nxp.ese.spi.action.ESE_SUCCESS";
    public static final String ACTION_ESE_FAILED =  "com.nxp.ese.spi.action.ESE_FAILED";
    public static final String ACTION_ESE_ABORTED = "com.nxp.ese.spi.action.ESE_ABORTED";
    private static final String ACTION_ESE_ENABLE_DONE = "com.nxp.ese.spi.action.ENABLE_DONE";
    private static final String[] path = {"/data/nfc/JcopOs_Update1.apdu",
                                          "/data/nfc/JcopOs_Update2.apdu",
                                          "data/nfc/JcopOs_Update3.apdu"};
    private static final String[] PREF_JCOP_MODTIME = {"jcop file1 modtime",
                                                       "jcop file2 modtime",
                                                       "jcop file3 modtime"};
    private static final long[] JCOP_MODTIME_DEFAULT = {-1,-1,-1};
    private static final long[] JCOP_MODTIME_TEMP = {-1,-1,-1};
    public static final int STATUS_SUCCESS = 0x00;
    public static final int STATUS_UPTO_DATE = 0x01;
    public static final int STATUS_FAILED = 0x03;
    public static final int STATUS_INUSE = 0x04;
    public static final int STATUS_FILE_NOT_FOUND = 0x05;

    public static final String SERVICE_NAME = "spi";
    Context mContext;
    static final String TAG = "EseSpiService";
    public static final String PREF = "SpiServicePrefs";
    static final String PREF_SPI_ON = "spi_on";
    static final boolean DBG = true;
    private PowerManager.WakeLock mRoutingWakeLock;

    private PowerManager mPowerManager;
    private SharedPreferences mPrefs;
    private SharedPreferences.Editor mPrefsEditor;
    boolean mIsAirplaneSensitive;
    int mState;
    private int mTransiveStatus = -1;;
    EseSpiAdapterService mSpiAdapter;
    NativeEseManager mSpiManager;
    EseSpiLoaderService mAlaService;
    SpiJcopService mJcpService;
    NxpExtrasService mNxpExtrasService;
    EseClientServicesAdapter mEseClientServicesAdapter;
    private NativeEseAla mNfcAla;
    private DeviceHost mDeviceHost;
    private WatchDogThread watchDog = null;
    private static final String LS_BACKUP_PATH = "/data/nfc/ls_backup.txt";
    private static final String LS_UPDATE_BACKUP_PATH = "/data/nfc/loaderservice_updater.txt";
    private static final String LS_UPDATE_BACKUP_OUT_PATH = "/data/nfc/loaderservice_updater_out.txt";
    private static final byte LOADER_SERVICE_VERSION_21 = 0x21;
    static final int INIT_WATCHDOG_MS = 90000;
    static final int INIT_WATCHDOG_LS_MS = 180000;
    static final int TRANSCEIVE_WATCHDOG_MS = 120000; /** 20 Seconds */

    static final int TASK_ENABLE = 1;
    static final int TASK_DISABLE = 2;
    static final int MSG_SUCCESS = 0;
    static final int MSG_FAILED = 1;
    static final int MSG_WTX_RES = 2;
    public static final int LS_RETRY_CNT = 3;
    NfceeAccessControl mNfceeAccessControl;
    static final int EE_ERROR_IO = -1;
    private int mPid;
    private WatchDog mWatchDog = null;
    private OpenSPI mOpenSPI;

    //private EseServiceHandler mHandler = new EseServiceHandler();

    @Override
    public void notifyEseServiceListeners(int what) {
        Log.d(TAG,"Status: "+ what);
        switch (what) {
            case MSG_SUCCESS: {
                Log.i(TAG, "EseSpiService: MSG_SUCCESS");
                mTransiveStatus = MSG_SUCCESS;
                break;
            }
            case MSG_FAILED:{
                Log.i(TAG, "EseSpiService: MSG_FAILED");
                mTransiveStatus = MSG_FAILED;
                break;
            }
            case MSG_WTX_RES:{
                Log.i(TAG, "  MSG_WTX_RES");
                mTransiveStatus = MSG_WTX_RES;

                if(mWatchDog != null){
                    mWatchDog.cancel();
                    mWatchDog = null;
                }
                mWatchDog = WatchDog.getWatchdogTimer("transceive", TRANSCEIVE_WATCHDOG_MS, mSpiManager);
                if(mWatchDog != null)
                    mWatchDog.start();
                else
                    Log.e(TAG, "EseSpiService:  Watchdog resource not available");
                break;
            }
        }
        return;
    }

    public EseSpiService(Application spiApplication) {

        mSpiAdapter = new EseSpiAdapterService();
        ServiceManager.addService(SERVICE_NAME, mSpiAdapter);

        mContext = spiApplication;
        mSpiManager = new NativeEseManager(mContext, this);
        mSpiManager.notifyEseManagerServiceListeners(-1);

        mNfcAla = new NativeEseAla();
        mNfceeAccessControl = new NfceeAccessControl(mContext);
        mPrefs = mContext.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        mPrefsEditor = mPrefs.edit();

        mState = EseSpiAdapter.STATE_OFF;
        mPowerManager = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
        mRoutingWakeLock = mPowerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK, "SpiService:mRoutingWakeLock");


    }


    public static void enforceAdminPerm(Context context) {
        context.enforceCallingOrSelfPermission(ADMIN_PERM, ADMIN_PERM_ERROR);
    }
    public static void enforceUserPermissions(Context context) {
        context.enforceCallingOrSelfPermission(NFC_PERMISSION, NFC_PERM_ERROR);
    }
    public void enforceNfceeAdminPerm(String pkg) {
        if (pkg == null) {
            throw new SecurityException("caller must pass a package name");
        }
        EseSpiService.enforceUserPermissions(mContext);
        if (!mNfceeAccessControl.check(Binder.getCallingUid(), pkg)) {
            throw new SecurityException(NfceeAccessControl.NFCEE_ACCESS_PATH +
                    " denies NFCEE access to " + pkg);
        }
        if (UserHandle.getCallingUserId() != UserHandle.USER_OWNER) {
            throw new SecurityException("only the owner is allowed to call SE APIs");
        }
    }

    void saveSpiOnSetting(boolean on) {
        synchronized (EseSpiService.this) {
            mPrefsEditor.putBoolean(PREF_SPI_ON, on);
            mPrefsEditor.apply();
        }
    }

    /*class EnableDisableTask extends AsyncTask<Integer, Void, Void> {
        @Override
        protected Void doInBackground(Integer... params) {
            switch (mState) {
            case EseSpiAdapter.STATE_TURNING_OFF:
            case EseSpiAdapter.STATE_TURNING_ON:
                Log.e(TAG, "Processing EnableDisable task " + params[0] + " from bad state " +
                        mState);
                return null;
            }


            Process.setThreadPriority(Process.THREAD_PRIORITY_DEFAULT);

            switch (params[0].intValue()) {
            case TASK_ENABLE:
                enableInternal();
                break;
            case TASK_DISABLE:
                disableInternal();
                break;

            }

            // Restore default AsyncTask priority
            Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
            return null;
        }}*/

        /**
         * Enable SPI adapter functions.
         * Does not toggle preferences.
         */
        boolean getJcopOsFileInfo() {
            File jcopOsFile;
            Log.i(TAG, "getJcopOsFileInfo");
            for (int num = 0; num < 3; num++) {
                try{
                    jcopOsFile = new File(path[num]);
                }catch(NullPointerException npe) {
                    Log.e(TAG,"path to jcop os file was null");
                    return false;
                }
                long modtime = jcopOsFile.lastModified();
                SharedPreferences prefs = mContext.getSharedPreferences(PREF,Context.MODE_PRIVATE);
                long prev_modtime = prefs.getLong(PREF_JCOP_MODTIME[num], JCOP_MODTIME_DEFAULT[num]);
                Log.d(TAG,"prev_modtime:" + prev_modtime);
                Log.d(TAG,"new_modtime:" + modtime);
                if(prev_modtime == modtime){
                    return false;
                }
                JCOP_MODTIME_TEMP[num] = modtime;
            }
            return true;
        }
        void jcopOsDownload() {
            int status = STATUS_FAILED;
            boolean jcopStatus;
            Log.i(TAG, "Jcop Download starts");
            SharedPreferences prefs = mContext.getSharedPreferences(PREF,Context.MODE_PRIVATE);
            jcopStatus = getJcopOsFileInfo();
            if( jcopStatus == true) {
                status = mSpiManager.doStartJcopDownload();
                if(status != STATUS_SUCCESS) {
                    Log.i(TAG, "Jcop Download failed");
                }
                else {
                    Log.i(TAG, "Jcop Download success");
                    prefs.edit().putLong(PREF_JCOP_MODTIME[1],JCOP_MODTIME_TEMP[1]).apply();
                    prefs.edit().putLong(PREF_JCOP_MODTIME[2],JCOP_MODTIME_TEMP[2]).apply();
                    prefs.edit().putLong(PREF_JCOP_MODTIME[3],JCOP_MODTIME_TEMP[3]).apply();
                }
            }
        }
        boolean enableInternal(int timeout, IBinder b) {
            if (mState == EseSpiAdapter.STATE_ON) {
                Log.i(TAG, "Inside 2nd try returning, Calling application PID :"+Binder.getCallingPid()+" Saved PID :"+mPid);
                if(mPid != Binder.getCallingPid()){
                    return false;
                }else
                {
                    return true;
                }
            }
            mOpenSPI = new OpenSPI(Binder.getCallingPid(), b);
            try {
                b.linkToDeath(mOpenSPI, 0);
            } catch (RemoteException e) {
                mOpenSPI.binderDied();
            }
            try {
                Log.i(TAG, "Inside 1st try after thread creation");
                mRoutingWakeLock.acquire();
                try {
                    if (!mSpiManager.doInitialize(timeout)) {
                        Log.w(TAG, "Error enabling SPI");
                        /* One App at a time, second app comes here after doInitialize fail
                         * but shouldn't update the state to STATE_OFF, otherwise
                         * disableInternal won't happen once the first app finishes */
                        if (mState != EseSpiAdapter.STATE_ON)
                            updateState(EseSpiAdapter.STATE_OFF);
                        return false;
                    }else
                    {
                        Log.i(TAG, "Initialization success ");
                        updateState(EseSpiAdapter.STATE_ON);
                        mPid = Binder.getCallingPid();
                        Log.i(TAG, "Calling application PID :"+mPid);
                        Intent intent = new Intent(ACTION_ESE_ENABLE_DONE);
                        mContext.sendBroadcast(intent);
                        Log.i(TAG, "Calling application PID2 :"+mPid);
/*                        long startTime = System.nanoTime();
                        mSpiManager.doStartJcopDownload();
                        long estimatedTime = System.nanoTime() - startTime;
                        double elaspedTime = (double)estimatedTime / 1000000000.0;
                        System.out.println("Time taken for JCOP update is " + elaspedTime + " secs");
                        Log.i(TAG,"Time taken for JCOP update is : " + elaspedTime + " secs");*/

                    }
                } finally {
                    mRoutingWakeLock.release();
                }
            } catch(Exception e) {
                Log.i(TAG, "Something Wrong in EnableInternal");
                e.printStackTrace();
            }
            synchronized (EseSpiService.this) {
                if(mSpiManager.doCheckJcopDlAtBoot()) {
                    /* start jcop download */
                    Log.i(TAG, "Calling Jcop Download");
                    jcopOsDownload();
                }
            }
            return true;
        }

        boolean disableInternal() {
            Log.i(TAG, "Inside disableInternal() Calling application PID :"+Binder.getCallingPid()+" Saved PID :"+mPid);
            if(mPid != Binder.getCallingPid()){
                return false;
            }
            if (mState == EseSpiAdapter.STATE_OFF) {
                return true;
            }
            try {
                Log.i(TAG, "deinitialize start ...");
                mRoutingWakeLock.acquire();
                if (!mSpiManager.deinitialize()) {
                    Log.w(TAG, "Error disabling SPI");
                    updateState(EseSpiAdapter.STATE_ON);
                    return false;
                } else{
                    Log.i(TAG, "Deitialization success ");
                    updateState(EseSpiAdapter.STATE_OFF);
                    /* Resetting Application PID */
                    mPid = 0;
                    return true;
                }
            } finally {
                mRoutingWakeLock.release();
            }
        }

        void updateState(int newState) {
            Log.i(TAG, "Update State:mState:"+mState+"newState:"+newState);
            synchronized (EseSpiService.this) {
                if (newState == mState) {
                    return;
                }
            if(newState == EseSpiAdapter.STATE_ON){
                Log.i(TAG, "Update State:STATE_ON");
                EseSpiLoaderService nas = new EseSpiLoaderService();
                nas.LSReexecute();
                IntentFilter lsFilter = new IntentFilter(EseSpiAdapter.ACTION_ADAPTER_STATE_CHANGED);
                mContext.registerReceiverAsUser(mAlaReceiver, UserHandle.ALL, lsFilter, null, null);
               }
                Log.i(TAG, "Update State:Changing State");
                mState = newState;
                Intent intent = new Intent(EseSpiAdapter.ACTION_ADAPTER_STATE_CHANGED);
                intent.setFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
                intent.putExtra(EseSpiAdapter.EXTRA_ADAPTER_STATE, mState);
                mContext.sendBroadcast(intent);
                Log.i(TAG, "BroadCast Sent");
            }
        }

    class WatchDogThread extends Thread {
        boolean mWatchDogCanceled = false;
        final int mTimeout;
        final Object mCancelWaiter = new Object();

        public WatchDogThread(String threadName, int timeout) {
            super(threadName);
            mTimeout = timeout;
        }

        @Override
        public void run() {

            try {
                synchronized (mCancelWaiter) {
                    Log.e(TAG,"Watch dog thread Started.");
                    mCancelWaiter.wait(mTimeout);
                    if(mWatchDogCanceled) {
                        Log.e(TAG,"Watch dog thread Returned.");
                        return;
                    }
                }
            } catch (InterruptedException e) {
                Log.e(TAG,"Watch dog thread interrupted.");
                interrupt();
            }

            // Trigger watch-dog
            Log.e(TAG, "Watchdog fired: name=" + getName() + " threadId=" +
                    getId() + " timeout=" + mTimeout);
            mSpiManager.doAbort();
        }

        public synchronized void cancel() {
            synchronized (mCancelWaiter) {
                mWatchDogCanceled = true;
                Log.e(TAG,"Watch dog thread Cancled.");
                mCancelWaiter.notify();
            }
        }
    }

    private class OpenSPI implements IBinder.DeathRecipient {
        public int pid;
        public IBinder binder;

        public OpenSPI(int pid, IBinder binder) {
            this.pid = pid;
            this.binder = binder;
        }
        @Override
        public void binderDied() {
            Log.i(TAG, "Tracked app " + pid + " died");
            mPid = Binder.getCallingPid();
            saveSpiOnSetting(false);
            disableInternal();
        }
    }

    final class EseSpiAdapterService extends IEseSpiAdapter.Stub {
        @Override
        public boolean enable(int timeout,IBinder b) throws RemoteException {
            boolean status = false;
            EseSpiService.enforceAdminPerm(mContext);
            saveSpiOnSetting(true);
            Log.i(TAG,"before enable call mStateValue : " + mState);
            //new EnableDisableTask().execute(TASK_ENABLE);
            status = enableInternal(timeout, b);
            Log.i(TAG,"mStateValue : " + mState);
            return status;
        }

        @Override
        public boolean disable(boolean saveState) throws RemoteException {
            boolean status = false;
            EseSpiService.enforceAdminPerm(mContext);
            if (saveState) {
                saveSpiOnSetting(false);
            }
            Log.i(TAG,"before disable call mStateValue : " + mState);
            //new EnableDisableTask().execute(TASK_DISABLE);
            status = disableInternal();
            Log.i(TAG,"mStateValue : " + mState);
            return status;
        }

        @Override
        public boolean reset() throws RemoteException {
            EseSpiService.enforceAdminPerm(mContext);
            if (!isSpiEnabled()) {
                Log.i(TAG," reset: SPI is not Enabled ");
                return false;
            }
            Log.i(TAG,"before reset ");
            if(mPid != Binder.getCallingPid())
            {
                throw new SecurityException("Wrong PID");
            }
            boolean status = mSpiManager.doReset();
            Log.i(TAG," dorest status: "+ status);
            return status;
        }

        @Override
        public boolean eseChipReset() throws RemoteException {
            EseSpiService.enforceAdminPerm(mContext);
            if (!isSpiEnabled()) {
                Log.i(TAG," reset: SPI is not Enabled ");
                return false;
            }
            Log.i(TAG,"Perfrom ese chip reset ");
            if(mPid != Binder.getCallingPid())
            {
                throw new SecurityException("Wrong PID");
            }
            boolean status = mSpiManager.doChipReset();
            Log.i(TAG," rest interface status: "+ status);
            return status;
        }
        @Override
        public int getState() throws RemoteException {
            synchronized (EseSpiService.this) {
                return mState;
            }
        }


        @Override
        public byte[] transceive(String pkg, byte[] in) throws RemoteException {
            EseSpiService.this.enforceNfceeAdminPerm(pkg);
            byte[] result = null;
            int retryCount =1;
            do {
                try {
                    Log.i(TAG, "Inside transceive() Calling application PID :"+Binder.getCallingPid()+" Saved PID :"+mPid);
                    if(mPid != Binder.getCallingPid())
                    {
                        throw new SecurityException("Wrong PID");
                    }
                    mWatchDog = WatchDog.getWatchdogTimer("transceive", TRANSCEIVE_WATCHDOG_MS, mSpiManager);
                    if(mWatchDog != null)
                        mWatchDog.start();
                    try {
                        Log.i(TAG, " _transceive start ...");
                        mRoutingWakeLock.acquire();
                        result =_transceive(in);
                    }finally {
                        mRoutingWakeLock.release();
                    }
                    if(mWatchDog != null)
                        mWatchDog.cancel();
                    } catch (IOException e) {
                       result = e.getMessage().getBytes();
                       Log.i(TAG,"\tRESULT ERROR  " +e.getMessage());
                    }

                   retryCount++;
                   if(result == null && retryCount < 2){
                       mSpiManager.doReset();

                   }

            }while(result == null && retryCount < 2);

            if(result == null){
                byte ret[] = {(byte)0x64,(byte)0xFF};
                result = ret;
            }

            return result;
        }

        public byte[] _transceive(byte[] data) throws IOException {

            if (!isSpiEnabled()) {
                throw new IOException("SPI is not enabled");
            }
            Log.i(TAG,"inside transceive ");
            return mSpiManager.manageTransceive(data);
        }
        @Override
        public IeSEClientServicesAdapter getSpieSEClientServicesAdapterInterface(){
            if(mEseClientServicesAdapter == null){
                mEseClientServicesAdapter = new EseClientServicesAdapter();
            }
            return mEseClientServicesAdapter;
        }
        public int getSeInterface(int type) {
            return mSpiManager.doGetSeInterface(type);
        }
    }
    final class NxpExtrasService extends INxpExtrasService.Stub{

        private Bundle writeNoException() {
            Bundle p = new Bundle();
            p.putInt("e", 0);
            return p;
        }

        private Bundle writeEeException(int exceptionType, String message) {
            Bundle p = new Bundle();
            p.putInt("e", exceptionType);
            p.putString("m", message);
            return p;
        }

        @Override
        public boolean isEnabled()
        {
            try {
                return (mState == EseSpiAdapter.STATE_ON);
            } catch (Exception e) {
                Log.d(TAG, "Exception " + e.getMessage());
                return false;
            }
        }

        @Override
        public byte[] getSecureElementUid(String pkg)
        {
            return null;
        }


        @Override
        public Bundle getCallingAppPkg(String pkg, IBinder b) throws RemoteException {
            Bundle result;
            String packageName;
            EseSpiService.enforceAdminPerm(mContext);
            try{
                packageName = EseSpiService.this.getCallingAppPkg(mContext);
                result = writeNoException();
                result.putString("packageName", packageName);
            } catch(Exception e){
                result = writeEeException(EE_ERROR_IO, e.getMessage());
            }
            return result;

        }

        @Override
        public Bundle open(String pkg, IBinder b) throws RemoteException {
            Bundle result;
            EseSpiService.enforceAdminPerm(mContext);
            saveSpiOnSetting(true);
            try{
                Log.i(TAG,"before enable call mStateValue : " + mState);
                enableInternal(9999,b);
                Log.i(TAG,"mStateValue : " + mState);
                result = writeNoException();
            }catch(Exception e){
                result = writeEeException(EE_ERROR_IO, e.getMessage());
                Log.i(TAG,"\tRESULT ERROR  " +e.getMessage());
            }
            return result;
        }

        @Override

        public Bundle transceive(String pkg, byte[] in) throws RemoteException{
            byte[] result = null;
            Bundle out;
            int retryCount =1;
            do {
                try {

                    mWatchDog = WatchDog.getWatchdogTimer("transceive", TRANSCEIVE_WATCHDOG_MS, mSpiManager);
                    if (mWatchDog != null) {
                        mWatchDog.start();
                    }

                    try {
                        Log.i(TAG, " _transceive start ...");
                        mRoutingWakeLock.acquire();
                        result =_transceive(in);
                        out = writeNoException();
                        out.putByteArray("out", result);
                    }finally {
                        mRoutingWakeLock.release();
                    }

                    if (mWatchDog != null) {
                        mWatchDog.cancel();
                    }

                    } catch (Exception e) {
                       result = e.getMessage().getBytes();
                       Log.i(TAG,"\tRESULT ERROR  " +e.getMessage());
                       out = writeEeException(EE_ERROR_IO, e.getMessage());
                    }

                   retryCount++;
                   if(result == null && retryCount < 2){
                       mSpiManager.doReset();
                   }

            }while(result == null && retryCount < 2);

            if(result == null){
                byte ret[] = {(byte)0x64,(byte)0xFF};
                result = ret;
            }

            return out;
        }

        public byte[] _transceive(byte[] data) throws IOException {

            if (!isSpiEnabled()) {
                throw new IOException("SPI is not enabled");
            }
            Log.i(TAG,"inside transceive ");
            return mSpiManager.manageTransceive(data);
        }
        @Override
        public Bundle close(String pkg, IBinder binder) throws RemoteException {
            EseSpiService.enforceAdminPerm(mContext);
            Bundle result;
            //if (saveState) {
                saveSpiOnSetting(false);
            //}
            try {
                Log.i(TAG,"before disable call mStateValue : " + mState);
                disableInternal();
                Log.i(TAG,"mStateValue : " + mState);
                result = writeNoException();
            }catch(Exception e) {
                result = writeEeException(EE_ERROR_IO, e.getMessage());
            }
            return result;
        }
    }
    final class EseClientServicesAdapter extends IeSEClientServicesAdapter.Stub{
        @Override
        public IJcopService getJcopService() {
            mContext.enforceCallingOrSelfPermission(ADMIN_PERM, ADMIN_PERM_ERROR);
            if(mJcpService == null){
                mJcpService = new SpiJcopService();
            }
            return mJcpService;
        }
        @Override

        public ILoaderService getLoaderService() {
            mContext.enforceCallingOrSelfPermission(ADMIN_PERM, ADMIN_PERM_ERROR);
            //begin
            if(mAlaService == null){
                mAlaService = new EseSpiLoaderService();
            }
            //end
            return mAlaService;
        }
        public INxpExtrasService getNxpExtrasService() {
            mContext.enforceCallingOrSelfPermission(ADMIN_PERM, ADMIN_PERM_ERROR);
            if(mNxpExtrasService == null){
                mNxpExtrasService = new NxpExtrasService();
            }
            return mNxpExtrasService;
        }
    };
    final class SpiJcopService extends IJcopService.Stub{

        @Override
        public int jcopOsDownload(String pkg) throws RemoteException {
            boolean mode;
            int status;

            mode = mSpiManager.doCheckJcopDlAtBoot();
            if( mode == false) {
                long startTime = System.nanoTime();
                status = mSpiManager.doStartJcopDownload();
                long estimatedTime = System.nanoTime() - startTime;
                double elaspedTime = (double)estimatedTime / 1000000000.0;
                System.out.println("Time taken for JCOP update is " + elaspedTime + " secs");
                Log.i(TAG,"Time taken for JCOP update is : " + elaspedTime + " secs");
                return status;
            }
            else {
                Log.i(TAG," Download not Supported via APK ");
                return -1;
            }
        }
    }

    final class EseSpiLoaderService extends ILoaderService.Stub{
        private boolean isRecovery = false;
        private String appName = null;
        private String srcIn = null;
        private String respOut = null;
        private String status = "false";
        private String TAG = "SpiLoaderService";
        private byte [] data_buffer = new byte[1024];
        void EseSpiLoaderService()
        {
            appName = null;
            srcIn = null;
            respOut = null;
            status = "false";
            isRecovery = false;
        }

        public int appletLoadApplet(String pkg, String choice) throws RemoteException {
            /*Disabled as ALA_VERSION_1 code*/
            /*String pkg_name = getCallingAppPkg(mContext);
            byte[] sha_data = CreateSHA(pkg_name);
            Log.i(TAG, "sha_data len : " + sha_data.length);
            if(sha_data != null)
            {
                return mNfcAla.doAppletLoadApplet(choice, sha_data);
            }
            else*/
                return 0xFF;
        }
        public int getListofApplets(String pkg, String[] name) throws RemoteException {
            /*Disabled as ALA_VERSION_1 code*/
            /*int cnt = mNfcAla.GetAppletsList(name);
            Log.i(TAG, "GetListofApplets count : " + cnt);
            for(int i=0;i<cnt;i++) {
                Log.i(TAG, "GetListofApplets " + name[i]);
            }

            return cnt;*/
            return 0xFF;
        }

        public byte[] getKeyCertificate() throws RemoteException {
            /*Disabled as ALA_VERSION_1 code*/
            /*return mNfcAla.GetCertificateKey();*/
            return (new byte[0]);
        }/*
        public byte[] lsExecuteScript( String srcIn, String respOut) throws RemoteException {
            String pkg_name = getCallingAppPkg(mContext);
            byte[] sha_data = CreateSHA(pkg_name);
            byte[] respSW = {0x4e,0x02,0x69,(byte)0x87};
            Log.i(TAG, "sha_data len : " + sha_data.length);
            if(sha_data != null)
            {
                return mNfcAla.doLsExecuteScript(srcIn, respOut, sha_data);
            }
            else
                return respSW;
        }*/

        public  synchronized void LSReexecute()
        {
             byte[] ret = {0x4E,0x02,(byte)0x69,(byte)0x87};
             byte retry = LS_RETRY_CNT;
             PrintWriter out= null;
             BufferedReader br = null;
             Log.i(TAG, "Enter: NfcAlaService constructor");
             try{
             File f = new File(LS_BACKUP_PATH);

             Log.i(TAG, "Enter: NfcAlaService constructor file open");
             /*If the file does not exists*/
             if(!(f.isFile()))
             {
                 Log.i(TAG, "FileNotFound ls backup");
                 out = new PrintWriter(LS_BACKUP_PATH);
                 out.println("null");
                 out.println("null");
                 out.println("null");
                 out.println("true");
                 out.close();
                 this.status = "true";
             }
             /*If the file exists*/
             else
             {
                 Log.i(TAG, "File Found ls backup");
                 br = new BufferedReader(new FileReader(LS_BACKUP_PATH));
                 this.appName = br.readLine();
                 this.srcIn = br.readLine();
                 this.respOut = br.readLine();
                 this.status = br.readLine();
             }
             }catch(FileNotFoundException f)
             {
                 Log.i(TAG, "FileNotFoundException Raised during LS Initialization");
                 return;
             }
             catch(IOException ie)
             {
                 Log.i(TAG, "IOException Raised during LS Initialization ");
                 return;
             }
             finally{
                 try{
                 if(out != null)
                 out.close();
                 if(br != null)
                     br.close();
                 }catch(IOException e)
                 {
                     Log.i(TAG, "IOException Raised during LS Initialization ");
                     return;
                 }
             }
             if(this.status.equals("true"))
             {
                 Log.i(TAG, "LS Script execution completed");
             }
             else
             {
                 Log.i(TAG, "LS Script execution aborted or tear down happened");
                 Log.i(TAG, "Input script path"+ this.srcIn);
                 Log.i(TAG, "Output response path"+ this.respOut);
                 Log.i(TAG, "Application name which invoked LS"+ this.appName);
                 try{
                 File fSrc = new File(this.srcIn);
                 File fRsp = new File(this.respOut);
                 if((fSrc.isFile() && fRsp.isFile()))
                 {
                     byte[] lsAppletStatus = {0x6F,0x00};
                         Log.i(TAG, "Started LS recovery since previous session failed");
                         this.isRecovery = true;
                         mWatchDog = WatchDog.getWatchdogTimer("Loader service ", INIT_WATCHDOG_LS_MS, mSpiManager);
                         if(mWatchDog != null)
                             mWatchDog.start();

                         try {
                             mRoutingWakeLock.acquire();
                              try {
                                  /*Reset retry counter*/
                                  while((retry-- > 0))
                                  {
                                      Thread.sleep(1000);
                                      lsAppletStatus = mNfcAla.doLsGetAppletStatus();
                                      /*Check if the LS applet status returns SUCCESS 9000 or FAIL 6340*/
                                      if((lsAppletStatus[0]==0x63) && (lsAppletStatus[1]==0x40))
                                      {
                                      ret = this.lsExecuteScript(this.srcIn, this.respOut);
                                      }
                                      else
                                      {
                                          break;
                                      }
                                  }
                                  } finally {
                                      this.isRecovery = false;

                                      if(mWatchDog != null)
                                          mWatchDog.cancel();

                                      mRoutingWakeLock.release();
                                }
                            }
                         catch(RemoteException ie)
                         {
                             Log.i(TAG, "LS recovery Exception: ");
                         }
                lsAppletStatus = mNfcAla.doLsGetAppletStatus();
                if((lsAppletStatus[0]==(byte)0x90)&&(lsAppletStatus[1]==(byte)0x00))
                {
                    out = new PrintWriter(LS_BACKUP_PATH);
                    out.println("null");
                    out.println("null");
                    out.println("null");
                    out.println("true");
                    out.close();
                    Log.i(TAG, "Commiting Default Values of Loader Service AS RETRY ENDS: ");
                }
             }
             else
             {
                 Log.i(TAG, "LS recovery not required");
             }
            }catch(InterruptedException re)
            {
                /*Retry failed todo*/
                Log.i(TAG, "RemoteException while LS recovery");
            }catch(FileNotFoundException re)
            {
                /*Retry failed todo*/
                Log.i(TAG, "InterruptException while LS recovery");
            }
           }
         }

         private void updateLoaderService() {
             byte[] ret = {0x4E,0x02,(byte)0x69,(byte)0x87};
            Log.i(TAG, "Enter: NfcAlaService constructor file open");
             File f = new File(LS_UPDATE_BACKUP_PATH);
            /*If the file does not exists*/
            if((f.isFile()))
            {
                Log.i(TAG, "File Found LS update required");

                mWatchDog = WatchDog.getWatchdogTimer("LoaderService:Update", (2*INIT_WATCHDOG_LS_MS), mSpiManager);
               if(mWatchDog != null){
                   mWatchDog.start();
                }

               try {
                       try {
                               /*Reset retry counter*/
                               {
                                       Log.i(TAG, "Started LS update");
                                       ret = this.lsExecuteScript(LS_UPDATE_BACKUP_PATH, LS_UPDATE_BACKUP_OUT_PATH);
                                       if(ret[2] == (byte)(0x90) && ret[3] == (byte)(0x00))
                                       {
                                               Log.i(TAG, " LS update successfully completed");
                                               f.delete();
                                       } else {
                                               Log.i(TAG, " LS update failed");
                                       }
                               }
                       } finally {
                                if(mWatchDog != null)
                                    mWatchDog.cancel();
                       }
               }
               catch(RemoteException ie)
               {
                       Log.i(TAG, "LS update recovery Exception: ");
               }
            }
            /*If the file exists*/
            else
            {
                Log.i(TAG, "No LS update");
            }
       }

        public byte[] lsExecuteScript( String srcIn, String respOut) throws RemoteException {
            String pkg_name = getCallingAppPkg(mContext);
            byte[] sha_data = CreateSHA(pkg_name);
            byte[] respSW = {0x4e,0x02,0x69,(byte)0x87};
            InputStream is = null;
            OutputStream os = null;
            PrintWriter out = null;
            FileReader fr = null;
            byte[] buffer = data_buffer;
            int length = 0;
            String srcBackup = srcIn+"mw";
            String rspBackup = null;
            File rspFile = null;
            if(respOut != null)
            rspBackup = respOut+"mw";
            File srcFile = new File(srcBackup);
            if(respOut != null)
            rspFile = new File(rspBackup);

            if(this.isRecovery != false)
            {
                /*If Previously Tear down happened before completion of LS execution*/
                try{
                fr =  new FileReader(LS_BACKUP_PATH);
                if(fr != null)
                {
                    BufferedReader br = new BufferedReader(fr);
                    if(br != null)
                    {
                        String appName = br.readLine();
                        if(appName != null)
                        {
                            sha_data = CreateSHA(appName);
                            pkg_name = appName;
                        }
                    }
                   }
                }catch(IOException ioe)
                {
                    Log.i(TAG, "IOException thrown for opening ");
                }
                finally{
                    try{
                    if(fr != null)
                        fr.close();
                    }
                    catch(IOException e)
                    {
                        Log.i(TAG, "IOException thrown for opening ");
                    }
                }
            }
            /*Store it in File*/
            try{
            out = new PrintWriter(LS_BACKUP_PATH);
            out.println(pkg_name);
            out.println(srcIn);
            out.println(respOut);
            out.println(false);
            }catch(IOException fe)
            {
                Log.i(TAG, "IOException thrown during clearing ");
            }
            finally{
                if(out != null)
                out.close();
            }
            try{
                /*To avoid rewriting of backup file*/
                if(this.isRecovery != true){
                is = new FileInputStream(srcIn);
                os = new FileOutputStream(srcBackup);

                while((length = is.read(buffer))>0)
                {
                    os.write(buffer,0,length);
                }
                if(is != null)is.close();
                if(os != null)os.close();}
                Log.i(TAG, "sha_data len : " + sha_data.length);
                if(sha_data != null)
                {
                    respSW = mNfcAla.doLsExecuteScript(srcBackup, rspBackup, sha_data);
                }
                /*resp file is not null*/
                if(respOut != null){
                    is = new FileInputStream(rspBackup);
                    os = new FileOutputStream(respOut);
                    length = 0;
                    while((length = is.read(buffer))>0)
                    {
                       os.write(buffer,0,length);
                    }
                }
                if(is != null)is.close();
                if(os != null)os.close();
            }catch(IOException ioe)
            {
                Log.i(TAG, "LS File not found");
            }catch(SecurityException se)
            {
                Log.i(TAG, "LS File access permission deneied");
            }
            finally{
            byte[] status = mNfcAla.doLsGetStatus();
            Log.i(TAG, "LS getStatus return SW1 : "+status[0]);
            Log.i(TAG, "LS getStatus return  SW2: "+status[1]);
            if((status[0]== (byte)0x90) && (status[1] == 0x00))
            {
                try{
                out = new PrintWriter(LS_BACKUP_PATH);
                out.println("null");
                out.println("null");
                out.println("null");
                out.println("true");
                }catch(IOException fe)
                {
                    Log.i(TAG, "FileNotFoundException thrown during clearing ");
                }
                finally
                {
                    if(out != null)
                    out.close();
                }
                Log.i(TAG, "COMMITTING THE DEFAULT VALUES OF LS : ");
                srcFile.delete();
                rspFile.delete();
            }
            else
            {
                Log.i(TAG, "NOT COMMITTING THE DEFAULT VALUES OF LS : ");
            }
          }
            return respSW;
        }

        public byte[] lsGetVersion()
        {
            return mNfcAla.doLsGetVersion();
        }
    };


    boolean isSpiEnabled() {
        synchronized (this) {
            if (mState == EseSpiAdapter.STATE_ON) {
                Log.i(TAG,"Spi On ");
                return true;
            }
            else{
                Log.i(TAG,"Spi Off ");
                return false;
            }
        }
    }
        public static byte[] CreateSHA(String pkg){
        String TAG = "Utils:CreateSHA";
        StringBuffer sb = new StringBuffer();
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(pkg.getBytes());
            byte byteData[] = md.digest();
            Log.i(TAG, "byteData len : " + byteData.length);
            return byteData;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static String getCallingAppPkg(Context context) {
        String TAG = "getCallingAppPkg";
        ActivityManager am = (ActivityManager) context.getSystemService(context.ACTIVITY_SERVICE);
        List< ActivityManager.RunningTaskInfo > taskInfo = am.getRunningTasks(1);
        Log.d("topActivity", "CURRENT Activity ::"
                + taskInfo.get(0).topActivity.getClassName());
        String s = taskInfo.get(0).topActivity.getClassName();
        ComponentName componentInfo = taskInfo.get(0).topActivity;
        componentInfo.getPackageName();
        Log.i(TAG,"componentInfo.getPackageName()" + componentInfo.getPackageName());
        return componentInfo.getPackageName();
    }
    final BroadcastReceiver mAlaReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (EseSpiAdapter.ACTION_ADAPTER_STATE_CHANGED.equals(intent.getAction())) {
                int state = intent.getIntExtra(EseSpiAdapter.EXTRA_ADAPTER_STATE,
                        EseSpiAdapter.STATE_OFF);
                if (state == EseSpiAdapter.STATE_ON) {
                    Log.e(TAG, "Loader service update start from NFC_ON Broadcast");
                    EseSpiLoaderService nas = new EseSpiLoaderService();
                        mNfcAla.doGetLSConfigVersion();
                        nas.updateLoaderService();
            }
        }
      }
    };
}
