# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import resource
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, List


class ContainerMetrics(types.Object):
    """
    ContainerMetrics sets resource usage metrics of a container.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        usage: Dict[k8sv1.ResourceName, "resource.Quantity"] = None,
    ):
        super().__init__()
        self.__name = name
        self.__usage = usage if usage is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        usage = self.usage()
        check_type("usage", usage, Dict[k8sv1.ResourceName, "resource.Quantity"])
        v["usage"] = usage
        return v

    def name(self) -> str:
        """
        Container name corresponding to the one from pod.spec.containers.
        """
        return self.__name

    def usage(self) -> Dict[k8sv1.ResourceName, "resource.Quantity"]:
        """
        The memory usage is the memory working set.
        """
        return self.__usage


class NodeMetrics(base.TypedObject, base.MetadataObject):
    """
    NodeMetrics sets resource usage metrics of a node.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        timestamp: "base.Time" = None,
        window: "base.Duration" = None,
        usage: Dict[k8sv1.ResourceName, "resource.Quantity"] = None,
    ):
        super().__init__(
            api_version="metrics.k8s.io/v1beta1",
            kind="NodeMetrics",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__timestamp = timestamp
        self.__window = window if window is not None else metav1.Duration()
        self.__usage = usage if usage is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        timestamp = self.timestamp()
        check_type("timestamp", timestamp, "base.Time")
        v["timestamp"] = timestamp
        window = self.window()
        check_type("window", window, "base.Duration")
        v["window"] = window
        usage = self.usage()
        check_type("usage", usage, Dict[k8sv1.ResourceName, "resource.Quantity"])
        v["usage"] = usage
        return v

    def timestamp(self) -> "base.Time":
        """
        The following fields define time interval from which metrics were
        collected from the interval [Timestamp-Window, Timestamp].
        """
        return self.__timestamp

    def window(self) -> "base.Duration":
        return self.__window

    def usage(self) -> Dict[k8sv1.ResourceName, "resource.Quantity"]:
        """
        The memory usage is the memory working set.
        """
        return self.__usage


class PodMetrics(base.TypedObject, base.NamespacedMetadataObject):
    """
    PodMetrics sets resource usage metrics of a pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        timestamp: "base.Time" = None,
        window: "base.Duration" = None,
        containers: List["ContainerMetrics"] = None,
    ):
        super().__init__(
            api_version="metrics.k8s.io/v1beta1",
            kind="PodMetrics",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__timestamp = timestamp
        self.__window = window if window is not None else metav1.Duration()
        self.__containers = containers if containers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        timestamp = self.timestamp()
        check_type("timestamp", timestamp, "base.Time")
        v["timestamp"] = timestamp
        window = self.window()
        check_type("window", window, "base.Duration")
        v["window"] = window
        containers = self.containers()
        check_type("containers", containers, List["ContainerMetrics"])
        v["containers"] = containers
        return v

    def timestamp(self) -> "base.Time":
        """
        The following fields define time interval from which metrics were
        collected from the interval [Timestamp-Window, Timestamp].
        """
        return self.__timestamp

    def window(self) -> "base.Duration":
        return self.__window

    def containers(self) -> List["ContainerMetrics"]:
        """
        Metrics for all containers are collected within the same time window.
        """
        return self.__containers
