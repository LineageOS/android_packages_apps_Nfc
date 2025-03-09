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

import argparse
import datetime
import os
import subprocess
import time
from generate_test import generate_test
from parse_log import FullApduEntry, NfcType, PollingLoopEntry, open_and_parse_file, parse_timeframe, replace_aids
from pn532 import PN532

# Minimum amount of time between successive NFC transactions, to prevent the
# reader from being overloaded.
_MIN_SLEEP_TIME_SECONDS = 0.5

# Maximum amount of time allowed between successive NFC transactions, to allow
# for ease of use.
_MAX_SLEEP_TIME_SECONDS = 5

_EXPECTED_ERROR_INDEX = 0
_ACTUAL_ERROR_INDEX = 1

# Number of times to try to obtain a tag before declaring failure.
_NUM_RETRIES = 50

# String templates for the output of a test case or snoop log.
_APDU_OUTPUT_STR = "{}: APDU exchange: sent {}, received {}"
_APDU_OUTPUT_TEST_STR = "{}: APDU exchange: sent {} APDUs, received {} APDUs"
_POLLING_OUTPUT_STR = "{}: sent NFC data of type {}"
_ERROR_STR = "     ERROR: {}"

# Width of the column for outputting the results of a test case.
_COLUMN_WIDTH = 80

# Directory for generated test cases and files for the emulator app.
_EMULATOR_APP_PARSED_DIR = "src/com/android/nfc/emulatorapp/parsed_files/"


def send_nfc_a_data(reader: PN532) -> str | None:
  """Calls poll_a() on the reader.

  Args:
    reader: The PN532 reader.

  Returns:
    the error, if one occurs
  """
  try:
    reader.poll_a()
  except Exception as e:
    return e.__str__()


def send_nfc_b_data(reader: PN532) -> str | None:
  """Calls poll_b() on the reader.

  Args:
    reader: The PN532 reader.

  Returns:
    the error, if one occurs
  """
  try:
    reader.poll_b()
  except Exception as e:
    return e.__str__()


def send_unknown_data(reader: PN532, data: bytes) -> str | None:
  """Sends a custom polling frame to the reader.

  Args:
    reader: The PN532 reader.
    data: The custom polling frame to be sent to the reader.

  Returns:
    the error, if one occurs
  """
  try:
    reader.poll_a()
    reader.send_broadcast(data)
    reader.mute()
  except Exception as e:
    return e.__str__()


def conduct_apdu_exchange(reader: PN532, current: FullApduEntry) -> str | None:
  """Conducts an APDU exchange between the emulator and the PN 532 module.

  Once the device is detected by the reader, the reader will send the APDU
  commands to the device and receive the responses. If an error occurs -- for
  instance, if the response from the emulator differs from the expected response
  -- the error is logged in the output.

  Args:
    reader: The PN532 reader.
    current: A data object containing the APDU commands to be sent to the
      emulator and the expected responses.

  Returns:
    the error, if one occurs
  """
  try:
    for i in range(_NUM_RETRIES):
      tag = reader.poll_a()
      if tag is not None:
        transacted = tag.transact(current.command, current.response)

        if not transacted:
          return "Received incorrect response. Expected: ".format(
              current.response
          )
        return None
      reader.mute()
    return "No tag received"
  except Exception as e:
    return e.__str__()


def replay_transaction(log, module_path: str):
  """Replays the given transaction log on the PN 532 module.

  Args:
    log: The transaction log to be replayed.
    module_path: The serial path to the PN 532 module.
  """
  try:
    reader = PN532(module_path)
  except Exception as e:
    print("Could not connect to PN532 module")
    return

  if not log:
    return

  prev_time = log[0].ts

  for current in log:
    num_seconds = (current.ts - prev_time) / 1000000
    if num_seconds < _MIN_SLEEP_TIME_SECONDS:
      time.sleep(_MIN_SLEEP_TIME_SECONDS)
    elif num_seconds > _MAX_SLEEP_TIME_SECONDS:
      time.sleep(_MAX_SLEEP_TIME_SECONDS)
    else:
      time.sleep(num_seconds)

    error = None

    if isinstance(current, PollingLoopEntry):
      if current.type == NfcType.NFC_A:
        error = send_nfc_a_data(reader)
      elif current.type == NfcType.NFC_B:
        error = send_nfc_b_data(reader)
      elif current.type == NfcType.UNKNOWN:
        error = send_unknown_data(reader, current.data)
    elif isinstance(current, FullApduEntry):
      error = conduct_apdu_exchange(reader, current)

    output_line_for_snoop_log(current, error)

    # adjust timestamp
    prev_time = current.ts

  reader.mute()


def parse_snoop_log(args: argparse.Namespace):
  """Parses the given snoop log file.

  If the file will be used for replaying a transaction with the emulator app,
  the AIDs will be replaced with the ones used by the app. Additionally, if the
  user specifies a start and end time, the log will be filtered to only include
  transactions that fall within that timeframe.

  Args:
    snoop_file: The local path to the snoop log file.

  Returns:
    The parsed snoop log.
  """
  parsed = open_and_parse_file(args.file)

  # replace the AIDs with the ones used by the emulator app
  if args.replay_with_app or args.parse_only:
    parsed = replace_aids(parsed)

  return parse_timeframe(parsed, args.start, args.end)


def output_line_for_snoop_log(
    entry: PollingLoopEntry | FullApduEntry,
    error: str | None,
):
  """Outputs a summary of an interaction from a snoop log.

  Args:
    entry: The current interaction to be replayed from the snoop log.
    error: Whether or not an error occurred during the replayed (actual)
      transaction.
  """
  cur_time = int(float(datetime.datetime.now().timestamp() * 1000000))
  cur_time_str = datetime.datetime.fromtimestamp(cur_time / 1000000).strftime(
      "%Y-%m-%d %H:%M:%S.%f"
  )
  if isinstance(entry, FullApduEntry):
    print(
        _APDU_OUTPUT_STR.format(
            cur_time_str,
            [command.hex() for command in entry.command],
            [response.hex() for response in entry.response],
        )
    )
  else:  # isinstance(entry, PollingLoopEntry)
    print(_POLLING_OUTPUT_STR.format(cur_time_str, entry.type.name))

  if error is not None:
    print(_ERROR_STR.format(error))


def print_opening_sequence(
    file_name: str,
    start: str | None = None,
    end: str | None = None,
):
  """Prints the opening sequence for a test case or snoop log.

  The name of the file to be replayed is displayed, along with the timeframe
  that will be replayed, if specified by the user.

  Args:
    file_name: The name of the file to be replayed.
    start: The start of the timeframe to be replayed.
    end: The end of the timeframe to be replayed.
  """
  print()
  print("Replaying transaction from snoop log: {}".format(file_name))
  if start is not None and end is not None:
    print("Timeframe: {} - {}".format(start, end))
  elif start is not None:
    print("Timeframe: {} - end".format(start))
  elif end is not None:
    print("Timeframe: start - {}".format(end))
  else:
    print()


def create_file_for_emulator_app(
    output: list[PollingLoopEntry | FullApduEntry], filename: str
):
  """Creates a file containing the parsed APDU exchanges from a snoop log.

  This will be to replay the transaction with an Android app installed on the
  emulator.

  Args:
    output: A list of polling loop entries and APDU exchanges parsed from the
      snoop log.
    filename: The name of the file to be created. This is near-identical to the
      name of the snoop log file.
  """
  local_path = _EMULATOR_APP_PARSED_DIR + filename.replace("/", "_")
  full_path = os.path.dirname(os.path.realpath(__file__)) + "/" + local_path
  try:
    file = open(full_path, "wt")
  except Exception as e:
    raise RuntimeError(
        "Error occurred while opening file: {}".format(full_path)
    ) from e
  for entry in output:
    if isinstance(entry, FullApduEntry):
      file.write(
          "{};{}".format(
              [command.hex() for command in entry.command],
              [response.hex() for response in entry.response],
          )
      )
      file.write("\n")
  print()
  print("File for third party app generated at: {}".format(local_path))


def get_name_for_test_case(filename: str) -> str:
  return "Generated" + filename.replace("/", "").replace(".txt", "")


def main():
  parser = argparse.ArgumentParser(prog="pn532")
  parser.add_argument(
      "-p",
      "--path",
      action="store",
      help="Path to the PN532 serial device, e.g. /dev/ttyUSB0",
  )
  parser.add_argument(
      "-f",
      "--file",
      action="store",
      required=True,
      help="Path to the file of the snoop log",
  )
  parser.add_argument(
      "--start",
      action="store",
      help="Start of the timeframe to be replayed",
  )
  parser.add_argument(
      "--end",
      action="store",
      help="End of the timeframe to be replayed",
  )
  parser.add_argument(
      "--parse_only",
      action="store_true",
      help="Parse the log without replaying the transaction",
  )
  parser.add_argument(
      "--replay_with_app",
      action="store_true",
      help="Replay the transaction with the emulator app",
  )
  parser.add_argument(
      "--generate_and_replay_test",
      action="store_true",
      help="Generate a test case from the log and then immediately run it",
  )
  args = parser.parse_args()

  parsed_snoop_log = parse_snoop_log(args)
  if args.parse_only:  # scenario 1: parse snoop log for the emulator app
    create_file_for_emulator_app(parsed_snoop_log, args.file)
  else:  # scenario 2: replay transaction from a snoop log
    print_opening_sequence(
        file_name=args.file,
        start=args.start,
        end=args.end,
    )
    if args.generate_and_replay_test:  # Replay the test that was just generated
      test_case_name = get_name_for_test_case(args.file)
      apdu_local_file = generate_test(parsed_snoop_log, test_case_name)
      test_command = [
          "atest",
          "-v",
          test_case_name,
          "--",
          "--testparam",
          "pn532_serial_path=" + args.path,
          "--testparam",
          "file_path=" + apdu_local_file,
      ]
      if args.replay_with_app:
        test_command += ["--testparam", "with_emulator_app=True"]
      subprocess.run(test_command)
    else:  # Default: replay the transaction
      replay_transaction(parsed_snoop_log, args.path)


if __name__ == "__main__":
  main()
