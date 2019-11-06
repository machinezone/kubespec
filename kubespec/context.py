# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import contextvars
import functools
import inspect

import typeguard


_current_scope = contextvars.ContextVar("kubespec.context")


def scoped(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        scope = _current_scope.get(None)
        if scope:
            sig = inspect.signature(func, follow_wrapped=True)
            for i, val in enumerate(sig.parameters.values()):
                if (
                    val.name in scope
                    and val.name not in kwargs
                    and (
                        (
                            val.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD
                            and len(args) <= i
                        )
                        or val.kind == inspect.Parameter.KEYWORD_ONLY
                    )
                ):
                    if val.annotation != inspect.Parameter.empty:
                        try:
                            typeguard.check_type("", scope[val.name], val.annotation)
                        except TypeError:
                            continue
                    kwargs[val.name] = scope[val.name]
        return func(*args, **kwargs)

    return wrapper


class Scope:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.prev = None

    def __enter__(self):
        self.prev = _current_scope.get({})
        ctx = self.prev.copy()
        ctx.update(self.kwargs)
        _current_scope.set(ctx)
        return ctx

    def __exit__(self, typ, value, traceback):
        _current_scope.set(self.prev)
