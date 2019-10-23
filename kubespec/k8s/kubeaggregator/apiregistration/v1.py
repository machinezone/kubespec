# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


class ServiceReference(types.Object):
    """
    ServiceReference holds a reference to Service.legacy.k8s.io
    """

    @context.scoped
    @typechecked
    def __init__(self, namespace: str = None, name: str = None, port: int = None):
        super().__init__()
        self.__namespace = namespace
        self.__name = name
        self.__port = port if port is not None else 443

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        port = self.port()
        check_type("port", port, Optional[int])
        if port is not None:  # omit empty
            v["port"] = port
        return v

    def namespace(self) -> Optional[str]:
        """
        Namespace is the namespace of the service
        """
        return self.__namespace

    def name(self) -> Optional[str]:
        """
        Name is the name of the service
        """
        return self.__name

    def port(self) -> Optional[int]:
        """
        If specified, the port on the service that hosting webhook.
        Default to 443 for backward compatibility.
        `port` should be a valid port number (1-65535, inclusive).
        """
        return self.__port


class APIServiceSpec(types.Object):
    """
    APIServiceSpec contains information for locating and communicating with a server.
    Only https is supported, though you are able to disable certificate verification.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        service: "ServiceReference" = None,
        group: str = None,
        version: str = None,
        insecureSkipTLSVerify: bool = None,
        caBundle: bytes = None,
        groupPriorityMinimum: int = 0,
        versionPriority: int = 0,
    ):
        super().__init__()
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
        service = self.service()
        check_type("service", service, Optional["ServiceReference"])
        v["service"] = service
        group = self.group()
        check_type("group", group, Optional[str])
        if group:  # omit empty
            v["group"] = group
        version = self.version()
        check_type("version", version, Optional[str])
        if version:  # omit empty
            v["version"] = version
        insecureSkipTLSVerify = self.insecureSkipTLSVerify()
        check_type("insecureSkipTLSVerify", insecureSkipTLSVerify, Optional[bool])
        if insecureSkipTLSVerify:  # omit empty
            v["insecureSkipTLSVerify"] = insecureSkipTLSVerify
        caBundle = self.caBundle()
        check_type("caBundle", caBundle, Optional[bytes])
        if caBundle:  # omit empty
            v["caBundle"] = caBundle
        groupPriorityMinimum = self.groupPriorityMinimum()
        check_type("groupPriorityMinimum", groupPriorityMinimum, int)
        v["groupPriorityMinimum"] = groupPriorityMinimum
        versionPriority = self.versionPriority()
        check_type("versionPriority", versionPriority, int)
        v["versionPriority"] = versionPriority
        return v

    def service(self) -> Optional["ServiceReference"]:
        """
        Service is a reference to the service for this API server.  It must communicate
        on port 443
        If the Service is nil, that means the handling for the API groupversion is handled locally on this server.
        The call will simply delegate to the normal handler chain to be fulfilled.
        """
        return self.__service

    def group(self) -> Optional[str]:
        """
        Group is the API group name this server hosts
        """
        return self.__group

    def version(self) -> Optional[str]:
        """
        Version is the API version this server hosts.  For example, "v1"
        """
        return self.__version

    def insecureSkipTLSVerify(self) -> Optional[bool]:
        """
        InsecureSkipTLSVerify disables TLS certificate verification when communicating with this server.
        This is strongly discouraged.  You should use the CABundle instead.
        """
        return self.__insecureSkipTLSVerify

    def caBundle(self) -> Optional[bytes]:
        """
        CABundle is a PEM encoded CA bundle which will be used to validate an API server's serving certificate.
        If unspecified, system trust roots on the apiserver are used.
        """
        return self.__caBundle

    def groupPriorityMinimum(self) -> int:
        """
        GroupPriorityMininum is the priority this group should have at least. Higher priority means that the group is preferred by clients over lower priority ones.
        Note that other versions of this group might specify even higher GroupPriorityMininum values such that the whole group gets a higher priority.
        The primary sort is based on GroupPriorityMinimum, ordered highest number to lowest (20 before 10).
        The secondary sort is based on the alphabetical comparison of the name of the object.  (v1.bar before v1.foo)
        We'd recommend something like: *.k8s.io (except extensions) at 18000 and
        PaaSes (OpenShift, Deis) are recommended to be in the 2000s
        """
        return self.__groupPriorityMinimum

    def versionPriority(self) -> int:
        """
        VersionPriority controls the ordering of this API version inside of its group.  Must be greater than zero.
        The primary sort is based on VersionPriority, ordered highest to lowest (20 before 10).
        Since it's inside of a group, the number can be small, probably in the 10s.
        In case of equal version priorities, the version string will be used to compute the order inside a group.
        If the version string is "kube-like", it will sort above non "kube-like" version strings, which are ordered
        lexicographically. "Kube-like" versions start with a "v", then are followed by a number (the major version),
        then optionally the string "alpha" or "beta" and another number (the minor version). These are sorted first
        by GA > beta > alpha (where GA is a version with no suffix such as beta or alpha), and then by comparing major
        version, then minor version. An example sorted list of versions:
        v10, v2, v1, v11beta2, v10beta3, v3beta1, v12alpha1, v11alpha2, foo1, foo10.
        """
        return self.__versionPriority


class APIService(base.TypedObject, base.MetadataObject):
    """
    APIService represents a server for a particular GroupVersion.
    Name must be "version.group".
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "APIServiceSpec" = None,
    ):
        super().__init__(
            apiVersion="apiregistration.k8s.io/v1",
            kind="APIService",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else APIServiceSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["APIServiceSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["APIServiceSpec"]:
        """
        Spec contains information for locating and communicating with a server
        """
        return self.__spec
