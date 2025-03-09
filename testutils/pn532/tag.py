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

from binascii import hexlify
from .nfcutils.reader import ReaderTag


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


class Tag(ReaderTag):
    def __init__(self, pn532, target_id: int):
        self.pn532 = pn532
        self.target_id = target_id
        self.log = pn532.log

    def transceive(self, data):
        """Uses PN532.in_data_exchange to transceive data via ISO-DEP"""
        return self.pn532.in_data_exchange(
            self.target_id, data, raise_on_error_status=False, timeout=5
        )

    def transact(self, command_apdus, response_apdus):
        """Sends command_apdus
        and verifies successful reception of matching response_apdus"""
        self.log.debug(f"Starting transaction with {len(command_apdus)} pairs")
        for command, response in zip(command_apdus, response_apdus):
            rsp = self.transceive(command)
            if response != "*" and not responses_match(response, rsp):
                received_apdu = rsp.hex() if isinstance(rsp, bytes) else "None"
                self.log.error(
                    "Unexpected APDU: received %s, expected %s",
                    received_apdu,
                    hexlify(response).decode(),
                )
                return False
        return True


class TypeATag(Tag):

    def __init__(
        self,
        pn532: "PN532",
        target_id: int,
        sense_res: bytearray,
        sel_res: int,
        nfcid: bytearray,
        ats: bytearray,
    ):
        super().__init__(pn532, target_id)
        self.sense_res = sense_res
        self.sel_res = sel_res
        self.nfcid = nfcid
        self.ats = ats


    @classmethod
    def from_target_data(cls, pn532, data):
        """Constructs TypeATag from TargetData[] returned by PN532"""
        target_id = data[0]
        sense_res = data[1:3]
        sel_res = data[3]
        nfcid_length = data[4]
        nfcid = data[5:5 + nfcid_length]
        offset = (1 + 2 + 1 + 1) + nfcid_length
        ats = bytearray()
        # If Type4A, and extra data available
        if sel_res & 0x20 and len(data) > offset:
            ats_length = data[offset]
            ats = data[offset + 1 : offset + 1 + ats_length]
            offset += 1 + ats_length
        return cls(pn532, target_id, sense_res, sel_res, nfcid, ats), offset


class TypeBTag(Tag):

    def __init__(
        self,
        pn532: "PN532",
        target_id: int,
        sensb_res: bytearray,
        attrib_res: bytearray,
    ):
        super().__init__(pn532, target_id)
        self.sensb_res = sensb_res
        self.attrib_res = attrib_res
        # NFCID0
        self.nfcid = sensb_res[1:5]

    @classmethod
    def from_target_data(cls, pn532, data):
        """Constructs TypeBTag from TargetData[] returned by PN532"""
        target_id = data[0]
        sensb_res = data[1:13]
        assert sensb_res[0] == 0x50
        attrib_res_length = data[13]
        attrib_res = data[14:14 + attrib_res_length]
        offset = (1 + 12 + 1) + attrib_res_length
        return cls(pn532, target_id, sensb_res, attrib_res), offset
