# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import base64
from typing import Any, Dict


class Renderable:
    def render(self) -> Any:
        return self


class Object(Renderable):
    def _root(self) -> Dict[str, Any]:
        return {}

    def render(self) -> Dict[str, Any]:
        def _render(value):
            if isinstance(value, Renderable):
                value = value.render()
            if isinstance(value, dict):
                return {k: _render(v) for k, v in value.items()}
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

        return {k: _render(v) for k, v in self._root().items()}

