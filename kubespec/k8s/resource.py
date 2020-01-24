# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import re
from copy import copy
from typing import Dict, Union, Tuple

from kubespec.k8s import base
from kubespec import types
from typeguard import typechecked


# Format lists the three possible formattings of a quantity.
Format = base.Enum(
    "Format",
    {
        # e.g., 12Mi (12 * 2^20)
        "BinarySI": "BinarySI",
        # e.g., 12e6
        "DecimalExponent": "DecimalExponent",
        # e.g., 12M  (12 * 10^6)
        "DecimalSI": "DecimalSI",
    },
)


_suffixes: Dict[str, Tuple[int, int, Format]] = {  # str -> (base, exp, fmt)
    # Decimal
    "": (10, 0, Format.DecimalSI),
    "n": (10, -9, Format.DecimalSI),
    "u": (10, -6, Format.DecimalSI),
    "m": (10, -3, Format.DecimalSI),
    "k": (10, 3, Format.DecimalSI),
    "M": (10, 6, Format.DecimalSI),
    "G": (10, 9, Format.DecimalSI),
    "T": (10, 12, Format.DecimalSI),
    "P": (10, 15, Format.DecimalSI),
    "E": (10, 18, Format.DecimalSI),
    # Binary
    "Ki": (2, 10, Format.BinarySI),
    "Mi": (2, 20, Format.BinarySI),
    "Gi": (2, 30, Format.BinarySI),
    "Ti": (2, 40, Format.BinarySI),
    "Pi": (2, 50, Format.BinarySI),
    "Ei": (2, 60, Format.BinarySI),
}

_bin_suffixes: Dict[int, str] = {v[1]: k for k, v in _suffixes.items() if v[0] == 2}

_dec_suffixes: Dict[int, str] = {v[1]: k for k, v in _suffixes.items() if v[0] == 10}


# Quantity is a fixed-point representation of a number.
# It provides convenient marshaling/unmarshaling in JSON and YAML,
# in addition to String() and AsInt64() accessors.
#
# The serialization format is:
#
# <quantity>        ::= <signedNumber><suffix>
#   (Note that <suffix> may be empty, from the "" case in <decimalSI>.)
# <digit>           ::= 0 | 1 | ... | 9
# <digits>          ::= <digit> | <digit><digits>
# <number>          ::= <digits> | <digits>.<digits> | <digits>. | .<digits>
# <sign>            ::= "+" | "-"
# <signedNumber>    ::= <number> | <sign><number>
# <suffix>          ::= <binarySI> | <decimalExponent> | <decimalSI>
# <binarySI>        ::= Ki | Mi | Gi | Ti | Pi | Ei
#   (International System of units; See: http://physics.nist.gov/cuu/Units/binary.html)
# <decimalSI>       ::= m | "" | k | M | G | T | P | E
#   (Note that 1024 = 1Ki but 1000 = 1k; I didn't choose the capitalization.)
# <decimalExponent> ::= "e" <signedNumber> | "E" <signedNumber>
#
# No matter which of the three exponent forms is used, no quantity may represent
# a number greater than 2^63-1 in magnitude, nor may it have more than 3 decimal
# places. Numbers larger or more precise will be capped or rounded up.
# (E.g.: 0.1m will rounded up to 1m.)
# This may be extended in the future if we require larger or smaller quantities.
#
# When a Quantity is parsed from a string, it will remember the type of suffix
# it had, and will use the same type again when it is serialized.
#
# Before serializing, Quantity will be put in "canonical form".
# This means that Exponent/suffix will be adjusted up or down (with a
# corresponding increase or decrease in Mantissa) such that:
#   a. No precision is lost
#   b. No fractional digits will be emitted
#   c. The exponent (or suffix) is as large as possible.
# The sign will be omitted unless the number is negative.
#
# Examples:
#   1.5 will be serialized as "1500m"
#   1.5Gi will be serialized as "1536Mi"
#
# Note that the quantity will NEVER be internally represented by a
# floating point number. That is the whole point of this exercise.
#
# Non-canonical values will still parse as long as they are well formed,
# but will be re-emitted in their canonical form. (So always use canonical
# form, or don't diff.)
#
# This format is intended to make it difficult to use these numbers without
# writing some sort of special handling code in the hopes that that will
# cause implementors to also use a fixed point implementation.
class Quantity(types.Renderable):
    @typechecked
    def __init__(
        self, value: Union[int, float, str] = 0, fmt: Format = Format.DecimalSI
    ):
        self.value = 0
        self.scale = 0
        self.format = fmt
        if isinstance(value, int):
            self._from_int(value, 0, fmt)
        elif isinstance(value, float):
            self._from_int(int(1000 * value), -3, fmt)
        else:
            self._from_str(value)

    def _from_int(self, value: int, scale: int, fmt: Format):
        while value != 0 and value % 10 == 0:
            value //= 10
            scale += 1
        self.value = value
        self.scale = scale
        self.format = fmt

    def _from_str(self, value: str):
        negative = value.startswith("-")
        _, whole, frac, suffix = _parse_value(value)
        base_, exp, fmt = _parse_suffix(suffix)
        value = int(whole + frac)
        scale = -len(frac)
        if base_ == 10:
            scale += exp
        elif base_ == 2:
            value *= 1 << exp
        if negative:
            value = -value
        self._from_int(value, scale, fmt)

    def render(self) -> str:
        return str(self)

    def __str__(self) -> str:
        if self.value == 0:
            return "0"

        # If BinarySI formatting is requested but would
        # cause rounding, switch to another format.
        fmt = self.format
        if fmt == Format.BinarySI:
            rounded = self._with_scale(0)
            if rounded == self and abs(rounded.value) >= 1024:
                value, exp = _remove_factors(rounded.value, 1024)
                if exp == 0:
                    return str(value)
                return str(value) + _bin_suffixes[10 * exp]
            fmt = Format.DecimalSI

        value, exp = _remove_factors(self.value, 10)
        exp += self.scale
        while exp % 3 != 0:
            value *= 10
            exp -= 1
        if exp == 0:
            return str(value)
        if fmt == Format.DecimalSI and exp in _dec_suffixes:
            return str(value) + _dec_suffixes[exp]
        return str(value) + "e" + str(exp)

    def _with_scale(self, scale: int) -> "Quantity":
        obj = copy(self)
        fact = 10 ** (obj.scale - scale)
        if fact > 1:
            obj.value = obj.value * int(fact)
        elif fact < 1:
            obj.value = int(round(obj.value * fact))
        obj.scale = scale
        return obj

    def _same_scale(self, other: "Quantity") -> Tuple["Quantity", "Quantity"]:
        scale = min(self.scale, other.scale)
        return self._with_scale(scale), other._with_scale(scale)

    def __lt__(self, other):
        if isinstance(other, (int, float, str)):
            other = Quantity(other)
        this, that = self._same_scale(other)
        return this.value < that.value

    def __gt__(self, other):
        if isinstance(other, (int, float, str)):
            other = Quantity(other)
        this, that = self._same_scale(other)
        return this.value > that.value

    def __le__(self, other):
        if isinstance(other, (int, float, str)):
            other = Quantity(other)
        this, that = self._same_scale(other)
        return this.value <= that.value

    def __ge__(self, other):
        if isinstance(other, (int, float, str)):
            other = Quantity(other)
        this, that = self._same_scale(other)
        return this.value >= that.value

    def __eq__(self, other):
        if isinstance(other, (int, float, str)):
            other = Quantity(other)
        this, that = self._same_scale(other)
        return this.value == that.value

    def __ne__(self, other):
        if isinstance(other, (int, float, str)):
            other = Quantity(other)
        this, that = self._same_scale(other)
        return this.value != that.value

    def __add__(self, other):
        if isinstance(other, (int, float, str)):
            other = Quantity(other)
        this, that = self._same_scale(other)
        this.value += that.value
        return this

    def __sub__(self, other):
        if isinstance(other, (int, float, str)):
            other = Quantity(other)
        this, that = self._same_scale(other)
        this.value -= that.value
        return this

    def __mul__(self, other):
        if isinstance(other, (int, float, str)):
            other = Quantity(other)
        this = copy(self)
        this.value *= other.value
        this.scale += other.scale
        return this


def _parse_value(s: str) -> Tuple[str, str, str, str]:
    match = re.search("^([-+]?([0-9]+)(\\.([0-9]+)?)?)(.*)$", s)
    if not match:
        # TODO: raise exception
        return "0", "0", "", s
    return (
        match[1].lstrip("0") or "0",  # value
        match[2].lstrip("0") or "0",  # whole component
        match[4] or "",  # fractional component
        match[5],  # suffix
    )


def _parse_suffix(s: str) -> Tuple[int, int, Format]:  # str -> (base, exp, fmt)
    if s in _suffixes:
        return _suffixes[s]
    if s[0] in ("E", "e"):
        return 10, int(s[1:]), Format.DecimalExponent
    # TODO: raise exception
    return 10, 0, Format.DecimalSI


def _remove_factors(value: int, factor: int) -> Tuple[int, int]:
    count = 0
    result = value
    negative = result < 0
    if negative:
        result = -result
    while result >= factor and result % factor == 0:
        result = result // factor
        count += 1
    if negative:
        result = -result
    return result, count

