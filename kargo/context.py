# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import contextvars
import functools


_current_scope = contextvars.ContextVar('kargo.context')


def scoped(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        scope = _current_scope.get({}).copy()
        scope.update(**kwargs)
        func(*args, **scope)
    return wrapper


class Scope:

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __enter__(self):
        self.prev = _current_scope.get({})
        ctx = self.prev.copy()
        ctx.update(self.kwargs)
        _current_scope.set(ctx)
        return ctx

    def __exit__(self, typ, value, traceback):
        _current_scope.set(self.prev)
