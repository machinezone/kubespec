# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import base64
from typing import Any, Dict, Union

import addict
from korps import context
from typeguard import typechecked


class Renderable:

    def render(self) -> Any:
        return self


class Object(Renderable):

    @context.scoped
    def __init__(self, **kwargs):
        self._kwargs = addict.Dict(kwargs)

    def render(self) -> Dict:
        return addict.Dict()


class Kadet:

    @typechecked
    def __init__(self, obj: Union[Dict, Object]):
        self.obj = obj

    def to_dict(self) -> dict:

        def _recurse(value):
            if isinstance(value, Renderable):
                value = value.render()
            if isinstance(value, dict):
                base = {}
                for k, v in value.items():
                    base[k] = _recurse(v)
                return base
            # Base64 encode bytes
            if isinstance(value, bytes):
                return base64.b64encode(value).decode('UTF-8')
            # Don't convert strings into lists
            if isinstance(value, str):
                return value
            try:
                it = iter(value)
            except TypeError:
                return value
            return [_recurse(v) for v in it]

        return _recurse(self.obj)
