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

"""Parses the snoop log to extract polling loop data and APDU exchanges."""

import base64
import dataclasses
import datetime
import enum
import os
import zlib

PREAMBLE_LENGTH = 9
HEADER_LENGTH = 7
SNOOP_LOG_START = "BEGIN:NFCSNOOP_"
SNOOP_LOG_END = "END:NFCSNOOP_"

# Bytes identifying the starts of polling loop and APDU transactions
POLLING_LOOP_START_BYTES = bytes.fromhex("6f0c")
APDU_START_BYTES = bytes.fromhex("6f02")

# Index corresponding to the total length of the APDU data packet
APDU_LEN_INDEX = 2

# Size of the main APDU header, which precedes either a list of APDU exchanges
# or a single APDU exchange
APDU_MAIN_HEADER_SIZE = 5

# Start of the APDU data, which follows the main header
APDU_DATA_START_INDEX = 6

# Minimum lengths of a valid APDU command and response
APDU_COMMAND_MIN_LENGTH = 13
APDU_RESPONSE_MIN_LENGTH = 10

# Sequence of bytes that identifies an APDU transaction
APDU_IDENTIFIER = bytes([0x20, 0x00])

# Byte that identifies an APDU command
APDU_COMMAND_IDENTIFIER = 0x19

# Byte that identifies an APDU response
APDU_RESPONSE_IDENTIFIER = 0x08

# Sequence of bytes that identifies whether the APDU command or response was
# the first command or response in a longer list of APDU commands or responses
APDU_ORDER_FIRST = 0x02
APDU_ORDER_FIRST_ALT = bytes([0x0A, 0x00])
APDU_ORDER_SECOND = 0x03
APDU_ORDER_SECOND_ALT = bytes([0x0B, 0x00])

# Sequence of bytes that identifies the start of a "SELECT AID" APDU command
AID_START_BYTES = bytes.fromhex("00A40400")

# AID groups that are used by the emulator app
SELECT_AID_FIRST = bytes.fromhex("00A4040008A000000151000000")
SELECT_AID_SECOND = bytes.fromhex("00A4040008A000000003000000")


class NfcType(enum.Enum):
  NFC_A = 0
  NFC_B = 1
  NFC_F = 2
  NFC_V = 3
  REMOTE_FIELD = 4
  UNKNOWN = 5


@dataclasses.dataclass
class PollingLoopEntry:
  ts: int = 0
  type: NfcType = NfcType.UNKNOWN
  data: bytes = b""
  error: str | None = None


@dataclasses.dataclass
class PartialApduEntry:
  ts: int = 0
  is_command: bool = False
  data: bytes = b""  # data sent by the APDU command or response
  is_first: bool = (
      True
      # whether this is the first entry in the list of APDU commands or responses sent together
  )


@dataclasses.dataclass
class FullApduEntry:
  ts: int = 0
  command: list[bytes] = dataclasses.field(default_factory=lambda: [])
  response: list[bytes] = dataclasses.field(default_factory=lambda: [])
  error: str | None = None


def replace_aids(
    log: list[PollingLoopEntry | FullApduEntry],
) -> list[PollingLoopEntry | FullApduEntry]:
  """Replaces the AIDs in the log with the AIDs that are used by the emulator app."""
  new_log: list[PollingLoopEntry | FullApduEntry] = []
  for cur in log:
    is_first_aid = True
    if isinstance(cur, FullApduEntry):
      new_apdu_entry = FullApduEntry(
          ts=cur.ts, command=[], response=cur.response
      )
      for cmd in cur.command:
        if cmd.startswith(AID_START_BYTES):
          if is_first_aid:
            new_apdu_entry.command.append(SELECT_AID_FIRST)
            is_first_aid = False
          else:
            new_apdu_entry.command.append(SELECT_AID_SECOND)
        else:
          new_apdu_entry.command.append(cmd)
      new_log.append(new_apdu_entry)
    else:
      new_log.append(cur)
  return new_log


def parse_timeframe(log, start, end):
  """Returns a subset of the log that falls within the given timeframe."""
  if start is None and end is None:
    return log
  parsed_log = log
  if start is not None:
    start_dt = datetime.datetime.strptime(start, "%Y-%m-%d %H:%M:%S.%f")
    start_ts = int(float(datetime.datetime.timestamp(start_dt)) * 1000000)
    parsed_log = list(filter(lambda x: x.ts >= start_ts, log))
  if end is not None:
    end_dt = datetime.datetime.strptime(end, "%Y-%m-%d %H:%M:%S.%f")
    end_ts = int(float(datetime.datetime.timestamp(end_dt)) * 1000000)
    parsed_log = list(filter(lambda x: x.ts <= end_ts, parsed_log))
  return parsed_log


def standardize_log(
    log: list[PollingLoopEntry | PartialApduEntry],
) -> list[PollingLoopEntry | FullApduEntry]:
  """Standardizes the log to ensure that it can be replayed by the PN 532 module.

  This includes removing redundant calls to polling loop A and combining APDU
  commands and responses into a single entry.

  Args:
    log: The log to be standardized.

  Returns:
    The standardized log.
  """
  cmds = []
  rsps = []
  last_ts = 0
  standardized: list[PollingLoopEntry | FullApduEntry] = []
  for cur in log:
    if isinstance(cur, PollingLoopEntry):
      if cur.type == NfcType.NFC_A or cur.type == NfcType.NFC_B:
        standardized.append(cur)
      elif cur.type == NfcType.UNKNOWN:
        if not standardized:
          standardized.append(cur)
        else:
          standardized[-1] = cur
    elif isinstance(cur, PartialApduEntry):
      if cur.is_command:
        if len(cmds) == len(rsps) + 1:  # extra command without response
          rsps.append(b"")
        if len(cmds) == len(rsps) != 0 and cur.data.startswith(AID_START_BYTES):
          standardized.append(FullApduEntry(last_ts, cmds, rsps))
          cmds = []
          rsps = []
        cmds.append(cur.data)
      else:
        if len(cmds) == len(rsps):  # extra response without command
          continue
        rsps.append(cur.data)
      last_ts = cur.ts
  # handle last command and response
  if len(cmds) == len(rsps) + 1:
    rsps.append(b"")
  if len(cmds) == len(rsps) != 0:
    standardized.append(FullApduEntry(last_ts, cmds, rsps))
  return standardized


def parse_file(data: bytes) -> list[PollingLoopEntry | PartialApduEntry]:
  """Parses the file to extract polling loop data and APDU exchanges."""
  if not data:
    raise RuntimeError("No data found in file")
  version = data[0]
  if version != 1:
    raise RuntimeError("Unsupported version: {}".format(version))

  offset = PREAMBLE_LENGTH
  header_length = HEADER_LENGTH
  pts_offset = 2
  polling_list = []
  ts = calculate_timestamp(data)
  while len(data) - offset > header_length:

    # length of the current transaction in bytes
    length = data[offset] + (data[offset + 1] << 8)

    # duration between the last transaction and the current one
    pts = bytearray(data[offset + pts_offset : offset + pts_offset + 4])
    pts_real = pts[0] + (pts[1] << 8) + (pts[2] << 16) + (pts[3] << 24)
    ts += pts_real

    transaction_type = (data[offset + header_length] & 0xE0) >> 5
    if transaction_type == 3:  # ST_NTF or NCI_NTF transactions
      cur_data = data[offset + header_length : offset + header_length + length]
      if cur_data.startswith(POLLING_LOOP_START_BYTES):
        polling_list.extend(add_polling_data(cur_data, ts))
      elif cur_data.startswith(APDU_START_BYTES):
        apdu_transactions = find_apdu_transactions(cur_data, ts)
        polling_list.extend(apdu_transactions)
    offset += header_length + length
  return polling_list


def open_and_parse_file(
    file_path: str,
) -> list[PollingLoopEntry | FullApduEntry]:
  """Opens the file that contains the unparsed snoop log and parses it.

  Args:
    file_path: The path of the file containing the unparsed snoop log.

  Returns:
    A list of polling loop entries and APDU exchanges parsed from the file.

  Raises:
    RuntimeError: If the file cannot be found.
  """
  snoop_file = open_read_file(file_path)
  str_data = ""
  found_log = False
  while line := snoop_file.readline():
    if not found_log and SNOOP_LOG_START in line:
      found_log = True
    elif found_log:
      if SNOOP_LOG_END in line:
        break
      str_data += line
  snoop_bytes = inflate(base64.b64decode(str_data))
  parsed = parse_file(snoop_bytes)
  return standardize_log(parsed)


def find_apdu_transactions(data: bytes, ts: int) -> list[PartialApduEntry]:
  """Finds all APDU transactions in the given data."""
  total_size = data[APDU_LEN_INDEX]
  if total_size < APDU_MAIN_HEADER_SIZE or data[4:6] != APDU_IDENTIFIER:
    return []

  apdus: list[PartialApduEntry] = []
  index = APDU_DATA_START_INDEX
  while index < len(data):
    cur_size = data[index + 1]
    cur_data = data[index : index + cur_size + 2]
    cmd, is_first = parse_apdu_command(cur_data) or (None, None)
    if cmd is not None:
      apdus.append(
          PartialApduEntry(ts=ts, is_command=True, data=cmd, is_first=is_first)
      )
    else:
      rsp, is_first = parse_apdu_response(cur_data) or (None, None)
      if rsp is not None:
        apdus.append(
            PartialApduEntry(
                ts=ts, is_command=False, data=rsp, is_first=is_first
            )
        )
    index += cur_size + 2
  return apdus


def parse_apdu_command(data: bytes):
  """Isolate the bytes sent from the reader to the emulator.

  Args:
    data: The raw APDU command in bytes.

  Returns:
    the data sent by the APDU command, or none if it is not a valid APDU
    command.
  """
  if len(data) < APDU_COMMAND_MIN_LENGTH:
    return None
  if data[0] != APDU_COMMAND_IDENTIFIER:
    return None
  if data[1] != len(data) - 2:
    return None
  if data[5:7] != bytes.fromhex("0000"):
    return None
  if data[8] in [APDU_ORDER_FIRST, APDU_ORDER_SECOND]:
    is_first = True if data[8] == APDU_ORDER_FIRST else False
    return data[9:-4], is_first
  elif data[8:10] in [APDU_ORDER_FIRST_ALT, APDU_ORDER_SECOND_ALT]:
    is_first = True if data[8:10] == APDU_ORDER_FIRST_ALT else False
    return data[10:-4], is_first
  return None


def parse_apdu_response(data: bytes):
  """Isolates the data sent from the emulator to the reader.

  Args:
    data: The raw APDU response in bytes.

  Returns:
    the data sent by the APDU response, or none if it is not a valid APDU
    response.
  """
  if len(data) < APDU_RESPONSE_MIN_LENGTH:
    return None
  if data[0] != APDU_RESPONSE_IDENTIFIER:
    return None
  if data[1] != len(data) - 2:
    return None
  if data[5] in [APDU_ORDER_FIRST, APDU_ORDER_SECOND]:
    is_first = True if data[5] == APDU_ORDER_FIRST else False
    return data[6:-4], is_first
  elif data[5:7] in [APDU_ORDER_FIRST_ALT, APDU_ORDER_SECOND_ALT]:
    is_first = True if data[5:7] == APDU_ORDER_FIRST_ALT else False
    return data[7:-4], is_first
  elif data[7] in [APDU_ORDER_FIRST, APDU_ORDER_SECOND]:
    is_first = True if data[7] == APDU_ORDER_FIRST else False
    return data[8:-4], is_first
  return None


def add_polling_data(data: bytes, ts: int) -> list[PollingLoopEntry]:
  """Adds polling data to the list of transactions.

  Each entry may contain multiple polling data transactions.

  Args:
    data: The raw polling data in bytes.
    ts: The timestamp of the polling transaction.

  Returns:
    A list of polling data transactions.
  """
  transaction_list = []
  count = 4
  while count < len(data):
    flag = data[count]
    match flag:
      case 0:
        entry_type = NfcType.REMOTE_FIELD
      case 1:
        entry_type = NfcType.NFC_A
      case 2:
        entry_type = NfcType.NFC_B
      case _:
        entry_type = NfcType.UNKNOWN
    length = data[count + 2] - 5
    polling_data = data[count + 8 : count + 8 + length]
    transaction_list.append(
        PollingLoopEntry(
            ts=ts,
            type=entry_type,
            data=polling_data,
        )
    )
    count += 8 + length
  return transaction_list


def calculate_timestamp(data: bytes) -> int:
  """Calculates the timestamp of the first frame in the log."""
  ts = data[1:9]
  ts_real = (
      ts[0]
      + (ts[1] << 8)
      + (ts[2] << 16)
      + (ts[3] << 24)
      + (ts[4] << 32)
      + (ts[5] << 40)
      + (ts[6] << 48)
      + (ts[7] << 56)
  )
  offset = PREAMBLE_LENGTH
  while (len(data) - offset) > HEADER_LENGTH:
    length = data[offset] + (data[offset + 1] << 8)
    pts = bytearray(data[offset + 2 : offset + 6])
    pts_real = pts[0] + (pts[1] << 8) + (pts[2] << 16) + (pts[3] << 24)
    ts_real -= pts_real
    offset += HEADER_LENGTH + length
  return ts_real


def inflate(data: bytes) -> bytes:
  """Inflates decompressed data."""
  decompressed = zlib.decompressobj().decompress(data[PREAMBLE_LENGTH:])
  return data[0:PREAMBLE_LENGTH] + decompressed


def open_read_file(file_path: str):
  """Opens the file at the given path.

  Args:
    file_path: The path of the file to be opened. This can be either a local
      path or an absolute path.

  Returns:
    An object representing the opened file.

  Raises:
    RuntimeError: If the file cannot be opened.
  """
  full_path = os.path.dirname(os.path.realpath(__file__)) + "/" + file_path
  if os.path.exists(file_path):
    file_to_open = file_path
  elif os.path.exists(full_path):
    file_to_open = full_path
  else:
    raise RuntimeError("File not found: {}".format(file_path))

  try:
    return open(file_to_open, "rt")
  except Exception as e:
    raise RuntimeError(
        "Error occurred while opening file: {}".format(file_path)
    ) from e
