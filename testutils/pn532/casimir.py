#  Copyright (C) 2024 The Android Open Source Project
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# Lint as: python3

import logging
from . import tag
from binascii import hexlify
from mobly import logger as mobly_logger
import http
from urllib.parse import urlparse
from http.client import HTTPSConnection
from .nfcutils.reader import Reader, ReaderTag, CONFIGURATION_A_LONG
import ssl
import json


def responses_match(expected: bytes, actual: bytes) -> bool:
    if expected == actual:
        return True
    if expected is None or actual is None:
        return False
    if len(expected) == 0 or len(actual) == 0:
        return False
    if expected[0] != 0x00 and actual[0] == 0x00:
        if expected == actual[1:]:
            return True
    return False


class CasimirTag(ReaderTag):
    def __init__(self, casimir, sender_id):
        """Empty init"""
        self.casimir = casimir
        self.sender_id = sender_id
        self.sel_res = 0x60
        self.ats = [0x70, 0x80, 0x08, 0x00]
        self.log = casimir.log

    def transact(self, command_apdus, expected_response_apdus):
        response_apdus = self.casimir.transceive_multiple(self.sender_id, command_apdus)
        if response_apdus is None:
            self.log.info("received None for response APDUs")
            return False
        if len(response_apdus) < len(expected_response_apdus):
            self.log.info(f"received {len(response_apdus)} responses, expected {len(expected_response_apdus)}")
            return False

        for i in range(len(expected_response_apdus)):
            if expected_response_apdus[i] != "*" and len(response_apdus) > i and not responses_match(expected_response_apdus[i], response_apdus[i]):
                received_apdu = hexlify(response_apdus[i]).decode() if type(response_apdus[i]) is bytes else "None"
                self.log.error(
                    "Unexpected APDU: received %s, expected %s",
                    received_apdu,
                    hexlify(expected_response_apdus[i]).decode(),
                )
                return False
        return True


class Casimir(Reader):
    def __init__(self, id):
        """ Init """
        self.id = id
        self.host = 'localhost'
        self.conn = None
        self.rf_on = False
        self.log = mobly_logger.PrefixLoggerAdapter(
            logging.getLogger(),
            {
                mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                    f"[Casimir|{id}]"
                )
            },
        )

    def __del__(self):
        self.mute()

    def poll_a(self):
        """Attempts to detect target for NFC type A."""
        response = self._send_command("PollA", {})
        if response is None:
            return None
        if response == {}:
            sender_id = 0
        else:
            sender_id = response["sender_id"]
        self.log.debug("got sender_id: " + str(sender_id))
        return CasimirTag(self, sender_id)

    def poll_b(self):
        """Attempts to detect target for NFC type B."""
        raise RuntimeError("not implemented")

    def send_broadcast(
        self,
        data,
        *,
        configuration=CONFIGURATION_A_LONG,
    ):
        """Emits broadcast frame"""
        if configuration.power != 100:
            self._send_command(
                "SetPowerLevel", {"power_level": configuration.power / 10}
            )
        return self.transceive(data)

    def transceive(self, apdu):
        ret = self.transceive_multiple(None, [apdu])
        if isinstance(ret, list) and len(ret) > 0:
            return ret[0]
        return None

    def transceive_multiple(self, sender_id, command_apdus):
        self.unmute()
        data = {"apdu_hex_strings": [c.hex() for c in command_apdus]}
        if isinstance(sender_id, int):
            data["sender_id"] = sender_id
        response = self._send_command('SendApdu', data)
        if response in (None, {}):
            return []
        return [
            bytes.fromhex(apdu) for apdu in response["responseHexStrings"]
        ]

    def unmute(self):
        """Turns on device's RF antenna."""
        if self.rf_on:
            return
        self._send_command('SetRadioState', {"radio_on": True})
        self.rf_on = True

    def mute(self):
        """Turns off device's RF antenna."""
        if self.conn is None:
            self.rf_on = False
            return
        if self.rf_on:
            self.rf_on = False
            self._send_command('SetRadioState', {"radio_on": False})
        self._send_command("Close", {})
        self.conn.close()
        self.conn = None

    def reset(self):
        """Nothing to reset"""

    def _ensure_connected(self):
        if self.conn is not None:
            return
        self.conn = HTTPSConnection(
            self.host, 1443,
            context=ssl._create_unverified_context()
        )
        self._send_command("Init", {})
        self.rf_on = False

    def _send_command(self, command, data):
        self._ensure_connected()
        self.conn.request(
            method="POST",
            url=f"/devices/{self.id}/services/CasimirControlService/{command}",
            body= json.dumps(data),
            headers={'Content-type': 'application/json'}
        )
        response = self.conn.getresponse()
        response_data = response.read()
        self.log.debug(f"response_data: {response_data}")
        if str(response_data).startswith("b'rpc error"):
            return None
        response_string = json.loads(response_data)
        return json.loads(response_string)
