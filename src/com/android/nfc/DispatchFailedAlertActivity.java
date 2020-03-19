/*
 * Copyright (C) 2020 The Android Open Source Project
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

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Resources;
import android.os.Bundle;
import android.text.TextUtils;
import android.net.Uri;
import com.android.nfc.R;

public class DispatchFailedAlertActivity extends Activity {
    AlertDialog mAlert = null;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        AlertDialog.Builder builder = new AlertDialog.Builder(this,
            AlertDialog.THEME_DEVICE_DEFAULT_LIGHT);
        Intent launchIntent = getIntent();
        Resources res = getResources();
        builder.setTitle(R.string.nfc_blocking_alert_title)
               .setMessage(R.string.nfc_blocking_alert_message)
               .setCancelable(false);
        if (TextUtils.isEmpty(getString(R.string.nfc_blocking_alert_link))) {
            builder.setPositiveButton(android.R.string.ok, null);
        } else {
            builder.setPositiveButton(android.R.string.ok,
                new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Intent infoIntent = new Intent(Intent.ACTION_VIEW);
                        infoIntent.setData(Uri.parse(getString(R.string.nfc_blocking_alert_link)));
                        startActivity(infoIntent);
                    }
                });
        }
        mAlert = builder.create();
        mAlert.show();
    }
}
