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

import time
import functools


class classproperty(property):
    """Inherits from property descriptor as shown in documentation
    https://docs.python.org/3/howto/descriptor.html
    """

    def __get__(self, owner_self, owner_cls):
        return self.fget(owner_cls)


class TimedWrapper:
    """Proxies attribute access operation target
    If accessed attribute is callable, wraps the original callable
    into a function which tracks execution time
    """

    def __init__(self, target):
        self._target = target
        self.timings = []

    def __getattr__(self, name):
        attr = getattr(self._target, name)

        if not callable(attr):
            return attr

        @functools.wraps(attr)
        def wrapped_method(*args, **kwargs):
            start_time = time.monotonic_ns()
            result = attr(*args, **kwargs)
            end_time = time.monotonic_ns()

            # Store the timing
            self.timings.append((start_time, end_time))

            return result

        return wrapped_method
