# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec.k8s.apimachinery import resource
from kubespec.k8s.apimachinery.meta import v1 as metav1
from kubespec import context
from kubespec import types
from typeguard import typechecked


# ContainerMetrics sets resource usage metrics of a container.
class ContainerMetrics(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        usage: Dict[corev1.ResourceName, "resource.Quantity"] = None,
    ):
        super().__init__(**{})
        self.__name = name
        self.__usage = usage if usage is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        v["usage"] = self.usage()
        return v

    # Container name corresponding to the one from pod.spec.containers.
    @typechecked
    def name(self) -> str:
        return self.__name

    # The memory usage is the memory working set.
    @typechecked
    def usage(self) -> Dict[corev1.ResourceName, "resource.Quantity"]:
        return self.__usage


# NodeMetrics sets resource usage metrics of a node.
class NodeMetrics(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        timestamp: "base.Time" = None,
        window: "base.Duration" = None,
        usage: Dict[corev1.ResourceName, "resource.Quantity"] = None,
    ):
        super().__init__(
            **{
                "apiVersion": "metrics.k8s.io/v1beta1",
                "kind": "NodeMetrics",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__timestamp = timestamp
        self.__window = window if window is not None else metav1.Duration()
        self.__usage = usage if usage is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["timestamp"] = self.timestamp()
        v["window"] = self.window()
        v["usage"] = self.usage()
        return v

    # The following fields define time interval from which metrics were
    # collected from the interval [Timestamp-Window, Timestamp].
    @typechecked
    def timestamp(self) -> "base.Time":
        return self.__timestamp

    @typechecked
    def window(self) -> "base.Duration":
        return self.__window

    # The memory usage is the memory working set.
    @typechecked
    def usage(self) -> Dict[corev1.ResourceName, "resource.Quantity"]:
        return self.__usage


# PodMetrics sets resource usage metrics of a pod.
class PodMetrics(base.TypedObject, base.NamespacedMetadataObject):
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
        containers: Dict[str, ContainerMetrics] = None,
    ):
        super().__init__(
            **{
                "apiVersion": "metrics.k8s.io/v1beta1",
                "kind": "PodMetrics",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__timestamp = timestamp
        self.__window = window if window is not None else metav1.Duration()
        self.__containers = containers if containers is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["timestamp"] = self.timestamp()
        v["window"] = self.window()
        v["containers"] = self.containers().values()  # named list
        return v

    # The following fields define time interval from which metrics were
    # collected from the interval [Timestamp-Window, Timestamp].
    @typechecked
    def timestamp(self) -> "base.Time":
        return self.__timestamp

    @typechecked
    def window(self) -> "base.Duration":
        return self.__window

    # Metrics for all containers are collected within the same time window.
    @typechecked
    def containers(self) -> Dict[str, ContainerMetrics]:
        return self.__containers
