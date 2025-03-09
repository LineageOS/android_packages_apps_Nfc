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
import struct
from typing import Optional, Dict
from enum import IntEnum
from binascii import hexlify

import serial

from serial.tools.list_ports import comports
from mobly import logger as mobly_logger

from .tag import TypeATag, TypeBTag
from .nfcutils import ByteStruct, snake_to_camel, s_to_us
from .nfcutils.reader import Reader, CONFIGURATION_A_LONG


_LONG_PREAMBLE = bytes(20)
_ACK_FRAME = bytes.fromhex("0000ff00ff00")
_SOF = bytes.fromhex("0000ff")


_BITRATE = {106: 0b000, 212: 0b001, 424: 0b010, 848: 0b011}
# Framing values defined in PN532_C1, 8.6.23
_FRAMING = {"A": 0b00, "DEP": 0b01, "F": 0b10, "B": 0b11}
# Timeout values defined in UM0701-02, Table 17,
# from 100 µs (n=1) up to 3.28 sec (n=16)
_TIMEOUT = {n: 100 * 2 ** (n - 1) for n in range(0x01, 0x10)}


# Picked manually, might not be the best combinations
_POWER_LEVELS_TO_P_N_DRIVER_CONFIGS = {
    # No frames should be detected
    0: (0b000000, 0b0000),
    # A, F detected with gain 1-3
    20: (0b000001, 0b0001),
    # A, F detected with gain 4-5
    40: (0b000010, 0b0010),
    # A, F detected with gain 5-6
    60: (0b000011, 0b0100),
    # A, F, detected with gain 7-8
    80: (0b001000, 0b1000),
    # A, B, F detected with gain 9
    100: (0b111111, 0b1111)
}


class Command(IntEnum):
    """https://www.nxp.com/docs/en/user-guide/141520.pdf
    UM0701-02
    """

    DIAGNOSE = 0x00
    GET_FIRMWARE_VERSION = 0x02
    GET_GENERAL_STATUS = 0x04

    READ_REGISTER = 0x06
    WRITE_REGISTER = 0x08

    SAM_CONFIGURATION = 0x14
    POWER_DOWN = 0x16

    RF_CONFIGURATION = 0x32

    IN_JUMP_FOR_DEP = 0x56
    IN_JUMP_FOR_PSL = 0x46
    IN_LIST_PASSIVE_TARGET = 0x4A

    IN_DATA_EXCHANGE = 0x40
    IN_COMMUNICATE_THRU = 0x42

    IN_DESELECT = 0x44
    IN_RELEASE = 0x52
    IN_SELECT = 0x54

    IN_AUTO_POLL = 0x60

    TG_INIT_AS_TARGET = 0x8C
    TG_SET_GENERAL_BYTES = 0x92
    TG_GET_DATA = 0x86
    TG_SET_DATA = 0x8E
    TG_SET_METADATA = 0x94
    TG_GET_INITIATOR_COMMAND = 0x88
    TG_RESPONSE_TO_INITIATOR = 0x90
    TG_GET_TARGET_STATUS = 0x8A


_BS = ByteStruct.of


class Register(IntEnum):
    """https://www.nxp.com/docs/en/nxp/data-sheets/PN532_C1.pdf
    PN532/C1
    8.6.22 CIU memory map
    8.7.1  Standard registers
    """

    structure: ByteStruct

    def __new__(cls, address: int, structure: Optional[ByteStruct] = None):
        obj = int.__new__(cls, address)
        obj._value_ = address
        obj.structure = None
        return obj

    def __init__(self, _, structure: Optional[ByteStruct] = None):
        # When initializing, we already know the name, so we're able to
        # generate a nice name for matching ByteStruct
        name = snake_to_camel(self.name.lower(), lower=False)
        self.structure = ByteStruct.of(
            name, **(structure.fields if structure else {"value": (7, 0)})
        )

    COMMAND = 0x6331
    COMM_I_EN = 0x6332
    DIV_I_EN = 0x6333
    COMM_I_RQ = 0x6334
    DIV_I_RQ = 0x6335
    ERROR = 0x6336
    WATER_LEVEL = 0x633B
    # (8.6.23.14) Control
    CONTROL = 0x633C, _BS(
        t_stop_now=7,
        t_start_now=6,
        wr_nfcip1_id_to_fifo=5,
        initiator=4,
        rfu=3,
        rx_last_bits=(2, 0),
    )
    # (8.6.23.15) BitFraming
    BIT_FRAMING = 0x633D, _BS(
        start_send=7, rx_align=(6, 4), rfu=3, tx_last_bits=(2, 0)
    )
    # (8.6.23.16) Coll
    COLL = 0x633E, _BS(
        values_after_coll=7,
        rfu=6,
        coll_pos_not_valid=5,
        coll_pos=(4, 0),
    )
    # (8.6.23.17) Mode
    MODE = 0x6301, _BS(
        msb_first=7,
        detect_sync=6,
        tx_wait_rf=5,
        rx_wait_rf=4,
        pol_sigin=3,
        mode_det_off=2,
        crc_preset=(1, 0),
    )
    # (8.6.23.18) TxMode
    TX_MODE = 0x6302, _BS(
        crc_en=7, speed=(6, 4), inv_mod=3, mix=2, framing=(1, 0)
    )
    # (8.6.23.19) RxMode
    RX_MODE = 0x6303, _BS(
        crc_en=7, speed=(6, 4), no_err=3, multiple=2, framing=(1, 0)
    )
    # (8.6.23.20) TxControl
    TX_CONTROL = 0x6304, _BS(
        inv_tx2_rf_on=7,
        inv_tx1_rf_on=6,
        inv_tx2_rf_off=5,
        inv_tx1_rf_off=4,
        tx2_cw=3,
        check_rf=2,
        tx2_rf_en=1,
        tx1_rf_en=0,
    )
    # (8.6.23.21) TxAuto
    TX_AUTO = 0x6305, _BS(
        auto_rf_off=7,
        force_100_ask=6,
        auto_wake_up=5,
        rfu=4,
        ca_on=3,
        initial_rf_on=2,
        tx2_rf_auto_en=1,
        tx1_rf_auto_en=0,
    )
    TX_SEL = 0x6306
    RX_SEL = 0x6307
    # (8.6.23.24) RxThreshold
    RX_THRESHOLD = 0x6308, _BS(min_level=(7, 4), rfu=3, col_level=(2, 0))
    # (8.6.23.25) Demod
    DEMOD = 0x6309, _BS(
        add_iq=(7, 6), fix_iq=5, tau_rcv=(3, 2), tau_sync=(1, 0)
    )
    MANUAL_RCV = 0x630D
    TYPE_B = 0x630E
    # (8.6.23.33) GsNOff
    GS_N_OFF = 0x6313, _BS(cw_gs_n_off=(7, 4), mod_gs_n_off=(3, 0))
    # (8.6.23.34) ModWidth
    MOD_WIDTH = 0x6314, _BS(mod_width=(7, 0))
    # (8.6.23.35) TxBitPhase
    TX_BIT_PHASE = 0x6315, _BS(rcv_clk_change=7, tx_bit_phase=(6, 0))
    # (8.6.23.36) RfCfg
    RF_CFG = 0x6316, _BS(rf_level_amp=7, rx_gain=(6, 4), rf_level=(3, 0))
    # (8.6.23.37) GsNOn
    GS_N_ON = 0x6317, _BS(cw_gs_n_on=(7, 4), mod_gs_n_on=(3, 0))
    # (8.6.23.38) CWGsP
    CW_GS_P = 0x6318, _BS(rfu=(7, 6), cw_gs_p=(5, 0))
    # (8.6.23.39) ModGsP
    MOD_GS_P = 0x6319, _BS(rfu=(7, 6), mod_gs_p=(5, 0))


REG = Register


REGISTER_VALUES_FOR_TRANSCEIVE = {
    # The following registers are configured for transmit
    # based on register states after using IN_LIST_PASSIVE_TARGET
    REG.CONTROL: REG.CONTROL.structure(initiator=True),
    REG.TX_CONTROL: REG.TX_CONTROL.structure(
        inv_tx2_rf_on=True,
        tx2_rf_en=True,
        tx1_rf_en=True,
    ),
    REG.RX_THRESHOLD: REG.RX_THRESHOLD.structure(
        min_level=0b1000, col_level=0b101
    ),
    REG.GS_N_OFF: REG.GS_N_OFF.structure(
        cw_gs_n_off=0b0110, mod_gs_n_off=0b1111
    ),
}


class RFConfigItem(IntEnum):
    """https://www.nxp.com/docs/en/user-guide/141520.pdf
    UM0701-02
    7.3.1 RFConfiguration
    """

    RF_FIELD = 0x01  # ConfigurationData
    VARIOUS_TIMINGS = 0x02  # RFU, fATR_RES_Timeout, fRetryTimeout
    # 0x03 RFU
    MAX_RTY_COM = 0x04  # MaxRtyCOM
    MAX_RETRIES = 0x05  # MxRtyATR, MxRtyPSL, MxRtyPassiveActivation


class BrTy(IntEnum):
    """https://www.nxp.com/docs/en/user-guide/141520.pdf
    UM0701-02
    7.3.5 InListPassiveTarget
    """

    # InitiatorData is optional and may contain a UID to initialize
    TYPE_A_106 = 0x00
    # InitiatorData contains "Polling" command payload
    TYPE_F_212 = 0x01
    TYPE_F_424 = 0x02
    # InitiatorData contains AFI and optional polling method byte
    TYPE_B_106 = 0x03
    # InitiatorData field unused
    TYPE_A_JEWEL = 0x04


class Status(IntEnum):
    """https://www.nxp.com/docs/en/user-guide/141520.pdf
    UM0701-02
    7.1 Error Handling
    """

    OK = 0x00
    TIME_OUT = 0x01
    CRC_ERROR = 0x02
    PARITY_ERROR = 0x03
    ERRONEOUS_BIT_COUNT = 0x04
    MIFARE_FRAMING_ERROR = 0x05
    BIT_COLLISION = 0x06
    COMMUNICATION_BUFFER_SIZE_INSUFFICIENT = 0x07
    RF_BUFFER_OVERFLOW = 0x09
    RF_PROTOCOL_ERROR = 0x0B
    TEMPERATURE_ERROR = 0x0D
    INTERNAL_BUFFER_OVERFLOW = 0x0E
    INVALID_PARAMETER = 0x10


class PN532(Reader):
    """Implements an NFC reader with a PN532 chip"""

    def __init__(self, path):
        """Initializes device on path,
        or first available serial port if none is provided."""
        if len(comports()) == 0:
            raise IndexError(
                "Could not find device on serial port"
                + ", make sure reader is plugged in."
            )
        if len(path) == 0:
            path = comports()[0].device

        self.register_cache = {}
        self.rf_configuration_cache = {}
        self.write_long_preamble = True

        self.log = mobly_logger.PrefixLoggerAdapter(
            logging.getLogger(),
            {
                mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX: (
                    f"[PN532|{path}]"
                )
            },
        )
        self.log.debug("Serial port: %s", path)
        self.device = serial.Serial(path, 115200, timeout=0.5)

        self.device.flush()
        self._send_ack_frame()
        self.device.flushInput()
        if not self.verify_firmware_version():
            raise RuntimeError(
                "Could not verify PN532 firmware on serial path " + path
            )
        self.sam_configuration(mode=0x01, timeout_value=0x00)

        self.write_long_preamble = False

        # Disable retries
        self.device.flushInput()
        self.rf_configuration(
            RFConfigItem.MAX_RETRIES,
            [
                0x00,  # MxRtyATR
                0x00,  # MxRtyPSL
                0x00,  # MxRtyPassiveActivation
            ],
        )

    # Custom functions

    def poll_a(self):
        """Attempts to detect target for NFC type A."""
        self.log.debug("Polling A")
        tag = self.in_list_passive_target(br_ty=BrTy.TYPE_A_106)
        if tag:
            self.log.debug(f"Got Type A tag, SEL_RES={tag.sel_res}")
        return tag

    def poll_b(self):
        """Attempts to detect target for NFC type B."""
        self.log.debug("Polling B")
        afi = 0x00
        tag = self.in_list_passive_target(
            br_ty=BrTy.TYPE_B_106, initiator_data=(afi,)
        )
        if tag:
            self.log.debug(f"Got Type B tag {tag.sensb_res}")
        return tag

    def send_broadcast(
        self,
        data: bytes,
        *,
        configuration=CONFIGURATION_A_LONG
    ):
        """Emits a broadcast frame into the polling loop"""
        self.log.debug("Sending broadcast %s", hexlify(data).decode())
        return self.transceive_raw(
            data=data,
            type_=configuration.type,
            crc=configuration.crc,
            bits=configuration.bits,
            bitrate=configuration.bitrate,
            timeout=configuration.timeout or 0.25,
            power_level=configuration.power,
        )

    def mute(self):
        """Turns off device's RF antenna."""
        self.log.debug("Muting")
        self.rf_configuration(RFConfigItem.RF_FIELD, [0b10])

    def unmute(self, auto_rf_ca=False):
        """Turns on device's RF antenna."""
        self.log.debug("Unmuting")
        self.rf_configuration(RFConfigItem.RF_FIELD, [(auto_rf_ca << 1) + 0b01])

    def reset(self):
        """Clears out input and output buffers to expunge leftover data"""
        self.device.reset_input_buffer()
        self.device.reset_output_buffer()

    # Special commands

    def transceive_raw(
        self,
        data,
        type_="A",
        crc=True,
        bits=8,
        bitrate=106,
        *,
        timeout=1,
        power_level=100,
        cache_configuration=True,
    ):
        """Configures the CIU with specified configuration and sends raw data
        :param timeout: Timeout in seconds
        :param cache_configuration: if true, prevents redundant writes & reads
        """
        # Choose the least index of timeout duration
        # where result >= given value. Timeout is in μs.
        # If timeout value is too big, or <= 0,
        # fall back to maximum timeout duration
        timeout_index = next(
            (idx for idx, t in _TIMEOUT.items() if t >= s_to_us(timeout)), 0x10
        )
        self.rf_configuration(
            RFConfigItem.VARIOUS_TIMINGS,
            [
                0x00,  # RFU
                0x0B,  # ATR_RES TimeOut, default value is 0x0B
                timeout_index,
            ],
            cache=cache_configuration,
        )


        p_n_config = next(
            (
                config
                for power, config in _POWER_LEVELS_TO_P_N_DRIVER_CONFIGS.items()
                if power >= power_level
            ),
            _POWER_LEVELS_TO_P_N_DRIVER_CONFIGS[0]
        )
        p_driver_conductance_level, n_driver_conductance_level = p_n_config


        (
            tx_mode, rx_mode, tx_auto, bit_frm,
            gs_n_on, cw_gs_p, md_gs_p,
            rf_cfg, tx_bit_phase, demod,
        ) = self.read_registers(
            REG.TX_MODE, REG.RX_MODE, REG.TX_AUTO, REG.BIT_FRAMING,
            REG.GS_N_ON, REG.CW_GS_P, REG.MOD_GS_P,
            REG.RF_CFG, REG.TX_BIT_PHASE, REG.DEMOD,
            cache=cache_configuration,
        )

        # The following register modifications are based on register state
        # modifications when performing IN_LIST_PASSIVE_TARGET and communication
        registers_to_write = {
            REG.TX_MODE: tx_mode.replace(
                crc_en=crc, speed=_BITRATE[bitrate], framing=_FRAMING[type_]
            ),
            REG.RX_MODE: rx_mode.replace(
                crc_en=crc, speed=_BITRATE[bitrate], framing=_FRAMING[type_]
            ),
            REG.TX_AUTO: tx_auto.replace(force_100_ask=type_ == "A"),
            REG.BIT_FRAMING: bit_frm.replace(tx_last_bits=bits & 0b111),
            REG.GS_N_ON: gs_n_on.replace(
                mod_gs_n_on=0b0100 if type_ == "A" else 0b1111,
                cw_gs_n_on=n_driver_conductance_level & 0b1111,
            ),
            REG.CW_GS_P: cw_gs_p.replace(
                cw_gs_p=p_driver_conductance_level & 0b111111
            ),
            REG.MOD_GS_P: md_gs_p.replace(
                mod_gs_p=0b010111 if type_ == "B" else 0b010001
            ),
            REG.RF_CFG: rf_cfg.replace(
                rx_gain=0b110 if type_ == "F" else 0b101,
                rf_level=0b1001,
            ),
            REG.TX_BIT_PHASE: tx_bit_phase.replace(
                rcv_clk_change=1,
                tx_bit_phase=0b1111 if type_ == "F" else 0b0111,
            ),
            REG.DEMOD: demod.replace(
                add_iq=0b01,
                tau_rcv=0b00 if type_ == "F" else 0b11,
                tau_sync=0b01,
            ),
            **REGISTER_VALUES_FOR_TRANSCEIVE,
        }

        self.write_registers(registers_to_write, cache=cache_configuration)

        # Handle a special case for FeliCa, where length byte has to be present
        if type_ == "F":
            data = [len(data) + 1, *data]

        # No data is OK for this use case
        return self.in_communicate_thru(data, raise_on_error_status=False)

    def verify_firmware_version(self):
        """Verifies we are talking to a PN532."""
        self.log.debug("Checking firmware version")
        rsp = self.get_firmware_version()
        return rsp[0] == 0x32

    # PN532 defined commands

    def initialize_target_mode(self):
        """Configures the PN532 as target."""
        self.log.debug("Initializing target mode")
        self._execute_command(
            Command.TG_INIT_AS_TARGET,
            [
                0x05,  # Mode
                0x04,  # SENS_RES (2 bytes)
                0x00,
                0x12,  # nfcid1T (3 BYTES)
                0x34,
                0x56,
                0x20,  # SEL_RES
                0x00,  # FeliCAParams[] (18 bytes)
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,  # NFCID3T[] (10 bytes)
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,  # LEN Gt
                0x00,  # LEN Tk
            ],
        )

    def sam_configuration(self, mode=0x01, timeout_value=0x00):
        """(7.2.10) SAMConfiguration"""
        return self._execute_command(
            Command.SAM_CONFIGURATION,
            [mode, timeout_value],
            timeout=1,
            min_response=0,
        )

    def get_firmware_version(self):
        """(7.2.2) GetFirmwareVersion"""
        return self._execute_command(
            Command.GET_FIRMWARE_VERSION, min_response=4
        )

    def in_data_exchange(
        self, tg, data, *, timeout=3, raise_on_error_status=True
    ):
        """(7.3.8) InDataExchange"""
        rsp = self._execute_command(
            Command.IN_DATA_EXCHANGE,
            [tg, *data],
            timeout=timeout,
        )
        if rsp is None or rsp[0] != Status.OK:
            if raise_on_error_status:
                raise RuntimeError(f"No response to {data}; {rsp}")
            self.log.error("Got error exchanging data")
            return None
        return rsp[1:]

    def in_communicate_thru(
        self, data, *, timeout=1, raise_on_error_status=True
    ):
        """(7.3.9) InCommunicateThru"""
        rsp = self._execute_command(
            Command.IN_COMMUNICATE_THRU, data, min_response=1, timeout=timeout
        )
        if rsp[0] != Status.OK:
            if raise_on_error_status:
                raise RuntimeError(f"No response to {data}; {rsp}")
            return None
        return rsp[1:]

    def in_list_passive_target(
        self, br_ty: BrTy, initiator_data: bytes = b"", max_tg=1
    ):
        """(7.3.5) InListPassiveTarget
        If max_tg=1, returns a tag or None if none was found,
        Otherwise, returns a list
        """
        # Reset cache values as IN_LIST_PASSIVE_TARGET modifies them
        self.register_cache = {}
        self.rf_configuration_cache = {}

        rsp = self._execute_command(
            Command.IN_LIST_PASSIVE_TARGET,
            [max_tg, br_ty, *initiator_data],
            min_response=1,
        )

        if rsp[0] == 0:
            return [] if max_tg > 1 else None

        data = rsp[1:]

        tags = []
        offset = 0

        tag_for_brty = {
            BrTy.TYPE_A_106: TypeATag,
            BrTy.TYPE_B_106: TypeBTag
        }

        if br_ty not in tag_for_brty:
            raise RuntimeError(f"BrTy {br_ty} not supported yet")

        while offset <= len(data) - 1:
            tag, offset = tag_for_brty[br_ty].from_target_data(
                self, data[offset:]
            )
            tags.append(tag)

        if max_tg == 1:
            return tags[0]
        return tags

    def read_registers(self, *registers: Register, cache=False):
        """(7.2.4) ReadRegister:
        Reads CIU registers
         :param registers: an iterable containing addresses of registers to read
         :param cache: prevents redundant register reads
        """
        if cache and all(
            Register(register) in self.register_cache for register in registers
        ):
            return [self.register_cache[register] for register in registers]
        data = b"".join(struct.pack(">H", register) for register in registers)
        rsp = self._execute_command(Command.READ_REGISTER, data)
        if not rsp:
            raise RuntimeError(f"No response for read registers {registers}.")
        return list(
            register.structure(byte) for byte, register in zip(rsp, registers)
        )

    def write_registers(
        self, registers: Dict[Register, int], cache=False
    ) -> None:
        """(7.2.5) WriteRegister:
        Writes CIU registers
         :param registers: dictionary containing key-value pairs
         of register addresses and values to be written
         :param cache: prevents redundant register writes
        """
        # If not caching, assume all are different
        difference = {
            reg: val
            for reg, val in registers.items()
            if not cache or self.register_cache.get(reg) != val
        }
        if not difference:
            return
        data = b"".join(
            struct.pack(">HB", reg, val) for reg, val in difference.items()
        )
        self._execute_command(Command.WRITE_REGISTER, data)
        self.register_cache = {**self.register_cache, **registers}

    def rf_configuration(
        self, cfg_item: RFConfigItem, value: int, *, cache=False
    ):
        """(7.3.1) RFConfiguration
        Applies settings to one of the available configuration items
        :param cache: prevents redundant config writes
        """
        if cache and self.rf_configuration_cache.get(cfg_item) == value:
            return
        self._execute_command(
            Command.RF_CONFIGURATION, [cfg_item, *value], min_response=0
        )
        self.rf_configuration_cache[cfg_item] = value

    # Internal communication commands

    def _execute_command(
        self, command: Command, data=b"", *, timeout=0.5, min_response=None
    ):
        """Executes the provided command
        Verifies that response code matches the command code if response arrived
        If min_response is set, checks if enough data was returned
        """
        rsp = self._send_frame(
            self._construct_frame([command, *data]), timeout=timeout
        )

        if not rsp:
            if min_response is not None:
                raise RuntimeError(f"No response for {command.name}; {rsp}")
            return None
        if rsp[0] != command + 1:
            raise RuntimeError(
                f"Response code {rsp[0]} does not match the command {command}"
            )
        del rsp[0]

        if isinstance(min_response, int) and len(rsp) < min_response:
            raise RuntimeError(
                f"Got unexpected response for {command.name}"
                + f"; Length mismatch {len(rsp)} < {min_response}"
                + f"; {bytes(rsp).hex()}"
            )

        return rsp

    # Protocol communication methods

    def _construct_frame(self, data):
        """Construct a data fram to be sent to the PN532."""
        # Preamble, start code, length, length checksum, TFI
        frame = [
            0x00,
            0x00,
            0xFF,
            (len(data) + 1) & 0xFF,
            ((~(len(data) + 1) & 0xFF) + 0x01) & 0xFF,
            0xD4,
        ]
        data_sum = 0xD4

        # Add data to frame
        for b in data:
            data_sum += b
            frame.append(b)
        frame.append(((~data_sum & 0xFF) + 0x01) & 0xFF)  # Data checksum

        frame.append(0x00)  # Postamble
        self.log.debug(
            "Constructed frame " + hexlify(bytearray(frame)).decode()
        )
        return bytearray(frame)

    def _write(self, frame):
        """Performs serial writes
        while handling config for sending long preambles"""
        if self.write_long_preamble:
            frame = _LONG_PREAMBLE + frame
        self.device.write(frame)

    def _send_frame(self, frame, timeout=0.5):
        """Writes a frame to the device and returns the response."""
        self._write(frame)
        return self._get_device_response(timeout)

    def _send_ack_frame(self, timeout=0.5):
        """Send ACK frame, there is no response."""
        self.device.timeout = timeout
        self._write(_ACK_FRAME)

    def _get_device_response(self, timeout=0.5):
        """onfirms we get an ACK frame from device.
        Reads response frame, and writes ACK.
        """
        self.device.timeout = timeout
        frame = bytearray(self.device.read(6))

        if (len(frame)) == 0:
            self.log.error("Did not get response from PN532")
            return None

        if bytes(frame) != _ACK_FRAME:
            self.log.error(
                "Did not get ACK frame, got %s", hexlify(frame).decode()
            )

        frame = bytearray(self.device.read(6))

        if (len(frame)) == 0:
            return None

        if bytes(frame[0:3]) != _SOF:
            self.log.error(
                "Unexpected start to frame, got %s",
                hexlify(frame[0:3]).decode(),
            )

        data_len = frame[3]
        length_checksum = frame[4]
        if (length_checksum + data_len) & 0xFF != 0:
            self.log.error("Frame failed length checksum")
            return None

        tfi = frame[5]
        if tfi != 0xD5:
            self.log.error(
                "Unexpected TFI byte when performing read, got %02x", frame[5]
            )
            return None

        data_packet = bytearray(
            self.device.read(data_len - 1)
        )  # subtract one since length includes TFI byte.
        data_checksum = bytearray(self.device.read(1))[0]
        if (tfi + sum(data_packet) + data_checksum) & 0xFF != 0:
            self.log.error("Frame failed data checksum")

        postamble = bytearray(self.device.read(1))[0]
        if postamble != 0x00:
            if tfi != 0xD5:
                self.log.error(
                    "Unexpected postamble byte when performing read, got %02x",
                    frame[4],
                )

        self._send_ack_frame()

        self.log.debug(
            "Received frame %s%s",
            hexlify(frame).decode(),
            hexlify(data_packet).decode(),
        )

        return data_packet
