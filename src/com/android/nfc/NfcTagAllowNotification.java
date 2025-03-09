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

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.nfc.NfcAdapter;

/**
 * This class handles the Notification Manager for the tag app allowlist info
 */

public class NfcTagAllowNotification {
    private static final String NFC_NOTIFICATION_CHANNEL = "nfc_tag_notification_channel";
    private NotificationChannel mNotificationChannel;
    public static final int NOTIFICATION_ID_NFC = -1000003;
    Context mContext;
    String mAppName;

    /**
     * Constructor
     *
     * @param ctx The context to use to obtain access to the resources
     * @param appName The tag application name
     */
    public NfcTagAllowNotification(Context ctx, String appName) {
        mContext = ctx;
        mAppName = appName;
    }

    /**
     * Start the notification.
     */
    public void startNotification() {
        Intent infoIntent = new Intent().setAction(NfcAdapter.ACTION_CHANGE_TAG_INTENT_PREFERENCE);
        Notification.Builder builder = new Notification.Builder(mContext, NFC_NOTIFICATION_CHANNEL);
        String formatString = mContext.getString(R.string.nfc_tag_alert_title);
        builder.setContentTitle(String.format(formatString, mAppName))
                .setContentText(mContext.getString(R.string.nfc_tag_alert_message))
                .setSmallIcon(R.drawable.nfc_icon)
                .setPriority(NotificationManager.IMPORTANCE_DEFAULT)
                .setAutoCancel(true)
                .setContentIntent(PendingIntent.getActivity(mContext, 0, infoIntent,
                      PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE));
        mNotificationChannel = new NotificationChannel(NFC_NOTIFICATION_CHANNEL,
                mContext.getString(R.string.nfcUserLabel), NotificationManager.IMPORTANCE_DEFAULT);
        NotificationManager notificationManager =
                mContext.getSystemService(NotificationManager.class);
        notificationManager.createNotificationChannel(mNotificationChannel);
        notificationManager.notify(NOTIFICATION_ID_NFC, builder.build());
    }
}

