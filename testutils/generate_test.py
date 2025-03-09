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

"""Generates a Python test case from a snoop log."""

import json
import math
import os

from parse_log import FullApduEntry, NfcType, PollingLoopEntry

INDENT_SIZE = 4


def generate_test(
    log: list[FullApduEntry | PollingLoopEntry], name: str
) -> str:
  """Generates a Python test case from a snoop log parsed by the replay tool.

  The generated test will be placed in the current directory.

  Args:
    log: The parsed snoop log.
    name: The name of the file containing the snoop log.

  Returns:
    The name of the JSON file containing APDUs needed to run the test.
  """
  # The name of the test file is based on the name of the snoop log
  python_local_file = name + "_test.py"
  file_path = (
      os.path.dirname(os.path.realpath(__file__)) + "/" + python_local_file
  )

  try:
    file = open(file_path, "wt")
  except Exception as e:
    raise RuntimeError(
        "Error occurred while opening file: {}".format(file_path)
    ) from e
  file.write(create_imports())
  file.write(create_replace_aids_method())
  file.write(create_polling_loop_methods())
  file.write(create_apdu_exchange_method())
  file.write(create_setup())
  file.write(create_test_opening(name))

  last_timestamp = log[0].ts
  json_list = []
  for entry in log:
    if isinstance(entry, PollingLoopEntry):
      file.write(create_polling_loop_test(entry, last_timestamp))
    else:  # isinstance(entry, FullApduEntry):
      file.write(create_apdu_test(entry, last_timestamp))
      json_list.append(create_apdu_dict(entry))
    last_timestamp = entry.ts

  json_dump = json.dumps(json_list)
  apdu_local_file = name + "_apdus.json"
  apdu_file_path = (
      os.path.dirname(os.path.realpath(__file__)) + "/" + apdu_local_file
  )
  apdu_file = open(apdu_file_path, "wt")
  apdu_file.write(json_dump)

  file.write(create_teardown_test())
  file.write(create_main_function())

  print()
  print(
      "Test generated at {}. To run the test, copy the test file to"
      " packages/apps/Nfc/tests/testcases/multidevices/.".format(file_path)
  )
  update_android_bp(python_local_file, name)

  return apdu_local_file


def update_android_bp(local_file_path, test_name):
  """Creates a new python_test_host entry in Android.bp for the generated test."""
  try:
    android_bp = open("Android.bp", "a")
  except Exception as e:
    raise RuntimeError("Error occurred while opening Android.bp") from e

  s = create_line()
  s += create_line()
  s += create_line("python_test_host {")
  s += create_line('name: "{}",'.format(test_name), indent=1)
  s += create_line('main: "{}",'.format(local_file_path), indent=1)
  s += create_line('srcs: ["{}"],'.format(local_file_path), indent=1)
  s += create_line('test_config: "AndroidTest.xml",', indent=1)
  s += create_line("test_options: {", indent=1)
  s += create_line("unit_test: false,", indent=2)
  s += create_line('tags: ["mobly"],', indent=2)
  s += create_line("},", indent=1)
  s += create_line('defaults: ["GeneratedTestsPythonDefaults"],', indent=1)
  s += create_line("}")
  android_bp.write(s)


def create_apdu_dict(entry: FullApduEntry):
  """Creates a dictionary representation of an APDU entry."""
  command_arr = []
  for cmd in entry.command:
    command_arr.append(cmd.hex())
  response_arr = []
  for rsp in entry.response:
    if isinstance(rsp, str):
      response_arr.append(rsp)
    else:
      response_arr.append(rsp.hex())
  apdu_dict = {
      "commands": command_arr,
      "responses": response_arr,
  }
  return apdu_dict


def create_test_opening(name: str):
  """Creates the opening of the test file."""
  s = create_line("def test_{}(self):".format(name), indent=1)
  s += create_line("# Read in APDU commands and responses from file", indent=2)
  s += create_line(
      'file_path_name = self.user_params.get("file_path", "")', indent=2
  )
  s += create_line("apdu_cmds = []", indent=2)
  s += create_line("apdu_rsps = []", indent=2)
  s += create_line("if file_path_name:", indent=2)
  s += create_line('with open(file_path_name, "r") as json_data:', indent=3)
  s += create_line("d = json.load(json_data)", indent=4)
  s += create_line("for entry in d:", indent=4)
  s += create_line("apdu_cmds.append(", indent=5)
  s += create_line(
      '[bytearray.fromhex(cmd) for cmd in entry["commands"]]', indent=6
  )
  s += create_line(")", indent=5)
  s += create_line("apdu_rsps.append(", indent=5)
  s += create_line(
      '[bytearray.fromhex(rsp) for rsp in entry["responses"]]', indent=6
  )
  s += create_line(")", indent=5)
  s += create_line()
  return s


def create_polling_loop_test(entry: PollingLoopEntry, last_timestamp: int):
  """Adds code to send a polling loop from the reader to the emulator.

  The test will check to ensure that the polling loop is successfully received.
  """
  s = create_line(
      "# Sending {} polling loop".format(entry.type),
      indent=2,
  )

  sleep_time = calculate_time_to_sleep(entry.ts, last_timestamp)
  s += create_line("time.sleep({})".format(sleep_time), indent=2)

  match entry.type:
    case NfcType.NFC_A:
      s += create_line("saw_loop = send_polling_loop_a(self.reader)", indent=2)
    case NfcType.NFC_B:
      s += create_line("saw_loop = send_polling_loop_b(self.reader)", indent=2)
    case _:  # NfcType.UNKNOWN
      s += create_line('custom_data = "{}"'.format(entry.data.hex()), indent=2)
      s += create_line(
          "saw_loop = send_custom_polling_loop(self.reader, custom_data)",
          indent=2,
      )
  s += create_line(
      'asserts.assert_true(saw_loop, "Did not see polling loop")', indent=2
  )
  s += create_line()
  return s


def create_apdu_test(entry: FullApduEntry, last_timestamp: int):
  """Adds code to conduct an APDU exchange between the reader and emulator.

  The test will check to ensure that the expected response is received from the
  emulator.
  """
  s = create_line("# Conducting APDU exchange", indent=2)

  sleep_time = calculate_time_to_sleep(entry.ts, last_timestamp)
  s += create_line("time.sleep({})".format(sleep_time), indent=2)

  s += create_line("commands = apdu_cmds[0]", indent=2)
  s += create_line("if self.with_emulator_app:", indent=2)
  s += create_line("commands = replace_aids(commands)", indent=3)
  s += create_line("responses = apdu_rsps[0]", indent=2)
  s += create_line(
      "tag_found, transacted = conduct_apdu_exchange(self.reader, commands,"
      " responses)",
      indent=2,
  )
  s += create_line()
  s += create_line("asserts.assert_true(", indent=2)
  s += create_line(
      'tag_found, "Reader did not detect tag, transaction not attempted."',
      indent=3,
  )
  s += create_line(")", indent=2)
  s += create_line("asserts.assert_true(", indent=2)
  s += create_line("transacted,", indent=3)
  s += create_line(
      '"Transaction failed, check device logs for more information."', indent=3
  )
  s += create_line(")", indent=2)
  s += create_line()
  s += create_line("apdu_cmds.pop(0)", indent=2)
  s += create_line("apdu_rsps.pop(0)", indent=2)
  s += create_line()
  return s


def create_imports():
  s = create_line('"""Test generated from the NFC Replay Tool."""')
  s += create_line()
  s += create_line("import json")
  s += create_line("import time")
  s += create_line("from mobly import asserts")
  s += create_line("from mobly import base_test")
  s += create_line("from mobly import test_runner")
  s += create_line("from mobly.controllers import android_device")
  s += create_line("import pn532")
  s += create_line()
  s += create_line("# Number of polling loops to perform.")
  s += create_line("_NUM_POLLING_LOOPS = 50")
  s += create_line()
  return s


def create_replace_aids_method():
  """Create a method that replaces the AIDs sent by the test with the ones

  that are used by the emulator app.
  """
  s = create_line("_EMULATOR_AIDS = [")
  s += create_line('bytearray.fromhex("00a4040008a000000151000000"),', indent=1)
  s += create_line('bytearray.fromhex("00a4040008a000000003000000"),', indent=1)
  s += create_line("]")
  s += create_line()
  s += create_line()
  s += create_line("def replace_aids(commands: list[bytearray]):")
  s += create_line(
      '"""Replaces SELECT AID commands with AIDs from the emulator app."""',
      indent=1,
  )
  s += create_line("new_commands = []", indent=1)
  s += create_line("is_first_aid = True", indent=1)
  s += create_line("for command in commands:", indent=1)
  s += create_line(
      'if command.startswith(bytearray.fromhex("00a40400")):', indent=2
  )
  s += create_line("if is_first_aid:", indent=3)
  s += create_line(
      "new_commands.append(_EMULATOR_AIDS[0])",
      indent=4,
  )
  s += create_line("is_first_aid = False", indent=4)
  s += create_line("else:", indent=3)
  s += create_line("new_commands.append(_EMULATOR_AIDS[1])", indent=4)
  s += create_line("else:", indent=2)
  s += create_line("new_commands.append(command)", indent=3)
  s += create_line("return new_commands", indent=1)
  return s


def create_polling_loop_methods():
  """Create methods that send polling loops to the reader.

  Specifically, three methods are created: send_polling_loop_a(),
  send_polling_loop_b(), and send_custom_polling_loop().
  """
  s = create_line()
  s += create_line()
  s += create_line("def send_polling_loop_a(reader: pn532.PN532) -> bool:")
  s += create_line("saw_loop = False", indent=1)
  s += create_line("for i in range(_NUM_POLLING_LOOPS):", indent=1)
  s += create_line("tag = reader.poll_a()", indent=2)
  s += create_line("if tag is not None:", indent=2)
  s += create_line("saw_loop = True", indent=3)
  s += create_line("break", indent=3)
  s += create_line("reader.mute()", indent=2)
  s += create_line("return saw_loop", indent=1)
  s += create_line()
  s += create_line()
  s += create_line("def send_polling_loop_b(reader: pn532.PN532) -> bool:")
  s += create_line("saw_loop = False", indent=1)
  s += create_line("for i in range(_NUM_POLLING_LOOPS):", indent=1)
  s += create_line("tag = reader.poll_b()", indent=2)
  s += create_line("if tag is not None:", indent=2)
  s += create_line("saw_loop = True", indent=3)
  s += create_line("break", indent=3)
  s += create_line("reader.mute()", indent=2)
  s += create_line("return saw_loop", indent=1)
  s += create_line()
  s += create_line()
  s += create_line(
      "def send_custom_polling_loop(reader: pn532.PN532, custom_data_hex: str)"
      " -> bool:"
  )
  s += create_line("saw_loop = False", indent=1)
  s += create_line("for i in range(_NUM_POLLING_LOOPS):", indent=1)
  s += create_line("tag = reader.poll_a()", indent=2)
  s += create_line("if tag is not None:", indent=2)
  s += create_line(
      "reader.send_broadcast(bytearray.fromhex(custom_data_hex))", indent=3
  )
  s += create_line("saw_loop = True", indent=3)
  s += create_line("break", indent=3)
  s += create_line("reader.poll_b()", indent=2)
  s += create_line("reader.mute()", indent=2)
  s += create_line("return saw_loop", indent=1)
  return s


def create_apdu_exchange_method():
  """Creates method to conduct an APDU exchange between the emulator and reader."""
  s = create_line()
  s += create_line()
  s += create_line("def conduct_apdu_exchange(")
  s += create_line(
      "reader: pn532.PN532, commands: list[bytearray], responses:"
      " list[bytearray]",
      indent=2,
  )
  s += create_line(") -> tuple[bool, bool]:")
  s += create_line(
      '"""Conducts an APDU exchange with the PN532 reader."""', indent=1
  )
  s += create_line("transacted = False", indent=1)
  s += create_line("tag = None", indent=1)
  s += create_line("for _ in range(_NUM_POLLING_LOOPS):", indent=1)
  s += create_line("tag = reader.poll_a()", indent=2)
  s += create_line("if tag is not None:", indent=2)
  s += create_line("transacted = tag.transact(commands, responses)", indent=3)
  s += create_line("reader.mute()", indent=3)
  s += create_line("break", indent=3)
  s += create_line("reader.mute()", indent=2)
  s += create_line("return tag, transacted", indent=1)
  return s


def create_setup():
  """Creates methods to prepare the PN532 reader and emulator before the test.

  This involves checking to ensure that the raeder and emulator are both
  present, and enabling NFC on the emulator.

  Args:
    name: The name of the original snoop log file.
  """
  s = create_line()
  s += create_line()
  s += create_line(
      "class GeneratedMultiDeviceTestCases(base_test.BaseTestClass):"
  )
  s += create_line()
  s += create_line("def setup_class(self):", indent=1)
  s += create_line(
      "self.emulator = self.register_controller(android_device)[0]", indent=2
  )
  s += create_line('self.emulator.debug_tag = "emulator"', indent=2)
  s += create_line(
      'pn532_serial_path = self.user_params.get("pn532_serial_path", "")',
      indent=2,
  )
  s += create_line(
      'self.with_emulator_app = self.user_params.get("with_emulator_app",'
      " False)",
      indent=2,
  )
  s += create_line(
      'self.emulator.adb.shell(["svc", "nfc", "disable"])', indent=2
  )
  s += create_line(
      'self.emulator.adb.shell(["svc", "nfc", "enable"])', indent=2
  )
  s += create_line("self.reader = pn532.PN532(pn532_serial_path)", indent=2)
  s += create_line("self.reader.mute()", indent=2)
  s += create_line()
  return s


def create_teardown_test():
  s = create_line("def teardown_test(self):", indent=1)
  s += create_line("self.reader.mute()", indent=2)
  return s


def create_main_function():
  s = create_line()
  s += create_line('if __name__ == "__main__":')
  s += create_line("test_runner.main()", indent=1)
  s += create_line()
  return s


def create_line(s: str = "", indent: int = 0):
  return "{}{}\n".format(create_indent(indent), s)


def create_indent(multiplier: int):
  return " " * multiplier * INDENT_SIZE


def calculate_time_to_sleep(current_ts: int, last_ts: int) -> int:
  num_seconds = math.ceil((current_ts - last_ts) / 1000000)
  if num_seconds < 1:
    return 1
  return num_seconds
