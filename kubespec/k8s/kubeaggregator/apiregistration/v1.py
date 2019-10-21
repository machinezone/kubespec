# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import typechecked


# ServiceReference holds a reference to Service.legacy.k8s.io
class ServiceReference(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, namespace: str = None, name: str = None, port: int = None):
        super().__init__(**{})
        self.__namespace = namespace
        self.__name = name
        self.__port = port if port is not None else 443

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        if namespace:  # omit empty
            v["namespace"] = namespace
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        port = self.port()
        if port is not None:  # omit empty
            v["port"] = port
        return v

    # Namespace is the namespace of the service
    @typechecked
    def namespace(self) -> Optional[str]:
        return self.__namespace

    # Name is the name of the service
    @typechecked
    def name(self) -> Optional[str]:
        return self.__name

    # If specified, the port on the service that hosting webhook.
    # Default to 443 for backward compatibility.
    # `port` should be a valid port number (1-65535, inclusive).
    @typechecked
    def port(self) -> Optional[int]:
        return self.__port


# APIServiceSpec contains information for locating and communicating with a server.
# Only https is supported, though you are able to disable certificate verification.
class APIServiceSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        service: ServiceReference = None,
        group: str = None,
        version: str = None,
        insecureSkipTLSVerify: bool = None,
        caBundle: bytes = None,
        groupPriorityMinimum: int = 0,
        versionPriority: int = 0,
    ):
        super().__init__(**{})
        self.__service = service
        self.__group = group
        self.__version = version
        self.__insecureSkipTLSVerify = insecureSkipTLSVerify
        self.__caBundle = caBundle if caBundle is not None else b""
        self.__groupPriorityMinimum = groupPriorityMinimum
        self.__versionPriority = versionPriority

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["service"] = self.service()
        group = self.group()
        if group:  # omit empty
            v["group"] = group
        version = self.version()
        if version:  # omit empty
            v["version"] = version
        insecureSkipTLSVerify = self.insecureSkipTLSVerify()
        if insecureSkipTLSVerify:  # omit empty
            v["insecureSkipTLSVerify"] = insecureSkipTLSVerify
        caBundle = self.caBundle()
        if caBundle:  # omit empty
            v["caBundle"] = caBundle
        v["groupPriorityMinimum"] = self.groupPriorityMinimum()
        v["versionPriority"] = self.versionPriority()
        return v

    # Service is a reference to the service for this API server.  It must communicate
    # on port 443
    # If the Service is nil, that means the handling for the API groupversion is handled locally on this server.
    # The call will simply delegate to the normal handler chain to be fulfilled.
    @typechecked
    def service(self) -> Optional[ServiceReference]:
        return self.__service

    # Group is the API group name this server hosts
    @typechecked
    def group(self) -> Optional[str]:
        return self.__group

    # Version is the API version this server hosts.  For example, "v1"
    @typechecked
    def version(self) -> Optional[str]:
        return self.__version

    # InsecureSkipTLSVerify disables TLS certificate verification when communicating with this server.
    # This is strongly discouraged.  You should use the CABundle instead.
    @typechecked
    def insecureSkipTLSVerify(self) -> Optional[bool]:
        return self.__insecureSkipTLSVerify

    # CABundle is a PEM encoded CA bundle which will be used to validate an API server's serving certificate.
    # If unspecified, system trust roots on the apiserver are used.
    @typechecked
    def caBundle(self) -> Optional[bytes]:
        return self.__caBundle

    # GroupPriorityMininum is the priority this group should have at least. Higher priority means that the group is preferred by clients over lower priority ones.
    # Note that other versions of this group might specify even higher GroupPriorityMininum values such that the whole group gets a higher priority.
    # The primary sort is based on GroupPriorityMinimum, ordered highest number to lowest (20 before 10).
    # The secondary sort is based on the alphabetical comparison of the name of the object.  (v1.bar before v1.foo)
    # We'd recommend something like: *.k8s.io (except extensions) at 18000 and
    # PaaSes (OpenShift, Deis) are recommended to be in the 2000s
    @typechecked
    def groupPriorityMinimum(self) -> int:
        return self.__groupPriorityMinimum

    # VersionPriority controls the ordering of this API version inside of its group.  Must be greater than zero.
    # The primary sort is based on VersionPriority, ordered highest to lowest (20 before 10).
    # Since it's inside of a group, the number can be small, probably in the 10s.
    # In case of equal version priorities, the version string will be used to compute the order inside a group.
    # If the version string is "kube-like", it will sort above non "kube-like" version strings, which are ordered
    # lexicographically. "Kube-like" versions start with a "v", then are followed by a number (the major version),
    # then optionally the string "alpha" or "beta" and another number (the minor version). These are sorted first
    # by GA > beta > alpha (where GA is a version with no suffix such as beta or alpha), and then by comparing major
    # version, then minor version. An example sorted list of versions:
    # v10, v2, v1, v11beta2, v10beta3, v3beta1, v12alpha1, v11alpha2, foo1, foo10.
    @typechecked
    def versionPriority(self) -> int:
        return self.__versionPriority


# APIService represents a server for a particular GroupVersion.
# Name must be "version.group".
class APIService(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: APIServiceSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "apiregistration.k8s.io/v1",
                "kind": "APIService",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else APIServiceSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Spec contains information for locating and communicating with a server
    @typechecked
    def spec(self) -> Optional[APIServiceSpec]:
        return self.__spec
