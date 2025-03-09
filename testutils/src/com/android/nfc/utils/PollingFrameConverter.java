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
package com.android.nfc.utils;

import android.nfc.cardemulation.PollingFrame;

import com.google.android.mobly.snippet.SnippetObjectConverter;

import org.json.JSONException;
import org.json.JSONObject;

import java.lang.reflect.Type;

public class PollingFrameConverter implements SnippetObjectConverter {
    @Override
    public JSONObject serialize(Object object) throws JSONException {
        JSONObject result = new JSONObject();
        if (object instanceof PollingFrame) {
            PollingFrame frame = (PollingFrame) object;
            result.put("type", Character.toString(frame.getType()));
            result.put("vendorSpecificGain", frame.getVendorSpecificGain());
            result.put("timestamp", frame.getTimestamp());
            result.put("data", HceUtils.getHexBytes(null, frame.getData()).replaceAll("\\s+", ""));
            result.put("triggeredAutoTransact", frame.getTriggeredAutoTransact());
            return result;
        }
        return null;
    }

    @Override
    public Object deserialize(JSONObject jsonObject, Type type) throws JSONException {
        // Not implemented
        return null;
    }
}
