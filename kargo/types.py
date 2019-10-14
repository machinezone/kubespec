# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import base64
from typing import Any, Dict, Union

from typeguard import typechecked


class Renderable:
    def render(self) -> Any:
        return self


class Object(Renderable):
    def render(self) -> Dict[str, Any]:
        return {}


@typechecked
def render(obj: Union[Dict[str, Object], Object]) -> dict:
    def _render(value):
        if isinstance(value, Renderable):
            value = value.render()
        if isinstance(value, dict):
            base = {}
            for k, v in value.items():
                base[k] = _render(v)
            return base
        # Base64 encode bytes
        if isinstance(value, bytes):
            return base64.b64encode(value).decode("UTF-8")
        # Don't convert strings into lists
        if isinstance(value, str):
            return value
        try:
            it = iter(value)
        except TypeError:
            return value
        return [_render(v) for v in it]

    return _render(obj)
