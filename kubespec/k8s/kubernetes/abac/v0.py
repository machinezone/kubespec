# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


class Policy(base.TypedObject):
    """
    Policy contains a single ABAC policy rule
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        user: str = None,
        group: str = None,
        readonly: bool = None,
        resource: str = None,
        namespace: str = None,
    ):
        super().__init__(
            apiVersion="abac.authorization.kubernetes.io/v0", kind="Policy"
        )
        self.__user = user
        self.__group = group
        self.__readonly = readonly
        self.__resource = resource
        self.__namespace = namespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        user = self.user()
        check_type("user", user, Optional[str])
        if user:  # omit empty
            v["user"] = user
        group = self.group()
        check_type("group", group, Optional[str])
        if group:  # omit empty
            v["group"] = group
        readonly = self.readonly()
        check_type("readonly", readonly, Optional[bool])
        if readonly:  # omit empty
            v["readonly"] = readonly
        resource = self.resource()
        check_type("resource", resource, Optional[str])
        if resource:  # omit empty
            v["resource"] = resource
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        return v

    def user(self) -> Optional[str]:
        """
        User is the username this rule applies to.
        Either user or group is required to match the request.
        "*" matches all users.
        """
        return self.__user

    def group(self) -> Optional[str]:
        """
        Group is the group this rule applies to.
        Either user or group is required to match the request.
        "*" matches all groups.
        """
        return self.__group

    def readonly(self) -> Optional[bool]:
        """
        Readonly matches readonly requests when true, and all requests when false
        """
        return self.__readonly

    def resource(self) -> Optional[str]:
        """
        Resource is the name of a resource
        "*" matches all resources
        """
        return self.__resource

    def namespace(self) -> Optional[str]:
        """
        Namespace is the name of a namespace
        "*" matches all namespaces (including unnamespaced requests)
        """
        return self.__namespace
