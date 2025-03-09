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

# String transformations

from .other import classproperty


def snake_to_camel(string, lower=True) -> str:
    """Converts snake_case string to camelcase"""
    pref, *other = string.split("_")
    return (pref if lower else pref.capitalize()) + "".join(
        x.capitalize() or "_" for x in other
    )


# Time conversion
def ns_to_ms(t):
    """Converts nanoseconds (10^−9) to milliseconds (10^−3)"""
    return round(t / 1000000)


def ns_to_us(t):
    """Converts nanoseconds (10^−9) to microseconds (10^−6)"""
    return round(t / 1000)


def us_to_ms(t):
    """Converts microseconds (10^−6) to milliseconds (10^−3)"""
    return round(t / 1000)


def s_to_us(t):
    """Converts seconds (10^0) to microseconds (10^−6)"""
    return round(t * 1000000)


class ByteStruct(int):
    """This class enables an ability to assign attribute names to specific bit
    offsets in a byte, making access more approachable
    """

    def __new__(cls, *args, **kwargs):
        fields: dict = {**cls.fields}

        for kwarg, _ in kwargs.items():
            if kwarg not in fields:
                raise ValueError(f"{cls.__name__} does not have field {kwarg}")

        value = 0
        if len(args) == 1 and isinstance(args[0], int):
            # Initialize from bitmask
            value = args[0]
        else:
            for key, bit_position in fields.items():
                start, end = bit_position
                bit_value = int(kwargs.get(key, 0))
                bit_size = start - end + 1
                if bit_value > 2**bit_size - 1:
                    raise ValueError(f"{key} size in bits exceeds {bit_size}")
                value |= (bit_value & ((1 << bit_size) - 1)) << end

        values = {}
        for name in fields.keys():
            start, end = fields[name]
            values[name] = (value >> end) & ((1 << (start - end + 1)) - 1)

        instance = super().__new__(cls, value)
        instance._values = values

        return instance

    def replace(self, **kwargs):
        """Return a new instance with specific values replaced by name."""
        return self.__class__(**{**self.values, **kwargs})

    def __getattribute__(self, item):
        values = super().__getattribute__("_values")
        if item == "values":
            return {**values}
        if item not in values:
            return super().__getattribute__(item)
        return values[item]

    @classmethod
    def of(cls, name=None, **kwargs):
        """Create a subclass with the specified name and parameters"""
        if name is None:
            name = "ByteStructOf" + ''.join(k.upper() for k in kwargs)
        subclass = type(name, (cls,), kwargs)
        return subclass

    @classproperty
    def fields(cls) -> dict:  # pylint: disable=no-self-argument
        return {
            k: sorted((v, v) if isinstance(v, int) else v)[::-1]
            for k, v in cls.__dict__.items()
            if not k.startswith("_")
        }

    def __repr__(self):
        fields = self.fields
        result = []
        for name, value in self.values.items():
            start, end = fields[name]
            length = start - end + 1
            result.append(f"{name}={bin(value)[2:].zfill(length)}")
        return f"{self.__class__.__name__}({', '.join(result)})"


# CRC Calculation
def crc16a(data):
    w_crc = 0x6363
    for byte in data:
        byte = byte ^ (w_crc & 0x00FF)
        byte = (byte ^ (byte << 4)) & 0xFF
        w_crc = (
            (w_crc >> 8) ^ (byte << 8) ^ (byte << 3) ^ (byte >> 4)
        ) & 0xFFFF
    return bytes([w_crc & 0xFF, (w_crc >> 8) & 0xFF])


def with_crc16a(data):
    return bytes(data) + crc16a(data)
