# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# PolicySpec contains the attributes for a policy rule
class PolicySpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        user: str = None,
        group: str = None,
        readonly: bool = None,
        apiGroup: str = None,
        resource: str = None,
        namespace: str = None,
        nonResourcePath: str = None,
    ):
        super().__init__()
        self.__user = user
        self.__group = group
        self.__readonly = readonly
        self.__apiGroup = apiGroup
        self.__resource = resource
        self.__namespace = namespace
        self.__nonResourcePath = nonResourcePath

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
        apiGroup = self.apiGroup()
        check_type("apiGroup", apiGroup, Optional[str])
        if apiGroup:  # omit empty
            v["apiGroup"] = apiGroup
        resource = self.resource()
        check_type("resource", resource, Optional[str])
        if resource:  # omit empty
            v["resource"] = resource
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        nonResourcePath = self.nonResourcePath()
        check_type("nonResourcePath", nonResourcePath, Optional[str])
        if nonResourcePath:  # omit empty
            v["nonResourcePath"] = nonResourcePath
        return v

    # User is the username this rule applies to.
    # Either user or group is required to match the request.
    # "*" matches all users.
    def user(self) -> Optional[str]:
        return self.__user

    # Group is the group this rule applies to.
    # Either user or group is required to match the request.
    # "*" matches all groups.
    def group(self) -> Optional[str]:
        return self.__group

    # Readonly matches readonly requests when true, and all requests when false
    def readonly(self) -> Optional[bool]:
        return self.__readonly

    # APIGroup is the name of an API group. APIGroup, Resource, and Namespace are required to match resource requests.
    # "*" matches all API groups
    def apiGroup(self) -> Optional[str]:
        return self.__apiGroup

    # Resource is the name of a resource. APIGroup, Resource, and Namespace are required to match resource requests.
    # "*" matches all resources
    def resource(self) -> Optional[str]:
        return self.__resource

    # Namespace is the name of a namespace. APIGroup, Resource, and Namespace are required to match resource requests.
    # "*" matches all namespaces (including unnamespaced requests)
    def namespace(self) -> Optional[str]:
        return self.__namespace

    # NonResourcePath matches non-resource request paths.
    # "*" matches all paths
    # "/foo/*" matches all subpaths of foo
    def nonResourcePath(self) -> Optional[str]:
        return self.__nonResourcePath


# Policy contains a single ABAC policy rule
class Policy(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(self, spec: PolicySpec = None):
        super().__init__(
            apiVersion="abac.authorization.kubernetes.io/v1beta1", kind="Policy"
        )
        self.__spec = spec if spec is not None else PolicySpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, PolicySpec)
        v["spec"] = spec
        return v

    # Spec describes the policy rule
    def spec(self) -> PolicySpec:
        return self.__spec