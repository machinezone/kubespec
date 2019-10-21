# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec.k8s.apimachinery import resource
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# Overhead structure represents the resource overhead associated with running a pod.
class Overhead(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, podFixed: Dict[corev1.ResourceName, "resource.Quantity"] = None):
        super().__init__(**{})
        self.__podFixed = podFixed if podFixed is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        podFixed = self.podFixed()
        check_type(
            "podFixed",
            podFixed,
            Optional[Dict[corev1.ResourceName, "resource.Quantity"]],
        )
        if podFixed:  # omit empty
            v["podFixed"] = podFixed
        return v

    # PodFixed represents the fixed resource overhead associated with running a pod.
    def podFixed(self) -> Optional[Dict[corev1.ResourceName, "resource.Quantity"]]:
        return self.__podFixed


# Scheduling specifies the scheduling constraints for nodes supporting a
# RuntimeClass.
class Scheduling(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        nodeSelector: Dict[str, str] = None,
        tolerations: List["corev1.Toleration"] = None,
    ):
        super().__init__(**{})
        self.__nodeSelector = nodeSelector if nodeSelector is not None else {}
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        nodeSelector = self.nodeSelector()
        check_type("nodeSelector", nodeSelector, Optional[Dict[str, str]])
        if nodeSelector:  # omit empty
            v["nodeSelector"] = nodeSelector
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["corev1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    # nodeSelector lists labels that must be present on nodes that support this
    # RuntimeClass. Pods using this RuntimeClass can only be scheduled to a
    # node matched by this selector. The RuntimeClass nodeSelector is merged
    # with a pod's existing nodeSelector. Any conflicts will cause the pod to
    # be rejected in admission.
    def nodeSelector(self) -> Optional[Dict[str, str]]:
        return self.__nodeSelector

    # tolerations are appended (excluding duplicates) to pods running with this
    # RuntimeClass during admission, effectively unioning the set of nodes
    # tolerated by the pod and the RuntimeClass.
    # +listType=atomic
    def tolerations(self) -> Optional[List["corev1.Toleration"]]:
        return self.__tolerations


# RuntimeClassSpec is a specification of a RuntimeClass. It contains parameters
# that are required to describe the RuntimeClass to the Container Runtime
# Interface (CRI) implementation, as well as any other components that need to
# understand how the pod will be run. The RuntimeClassSpec is immutable.
class RuntimeClassSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        runtimeHandler: str = "",
        overhead: Overhead = None,
        scheduling: Scheduling = None,
    ):
        super().__init__(**{})
        self.__runtimeHandler = runtimeHandler
        self.__overhead = overhead
        self.__scheduling = scheduling

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        runtimeHandler = self.runtimeHandler()
        check_type("runtimeHandler", runtimeHandler, str)
        v["runtimeHandler"] = runtimeHandler
        overhead = self.overhead()
        check_type("overhead", overhead, Optional[Overhead])
        if overhead is not None:  # omit empty
            v["overhead"] = overhead
        scheduling = self.scheduling()
        check_type("scheduling", scheduling, Optional[Scheduling])
        if scheduling is not None:  # omit empty
            v["scheduling"] = scheduling
        return v

    # RuntimeHandler specifies the underlying runtime and configuration that the
    # CRI implementation will use to handle pods of this class. The possible
    # values are specific to the node & CRI configuration.  It is assumed that
    # all handlers are available on every node, and handlers of the same name are
    # equivalent on every node.
    # For example, a handler called "runc" might specify that the runc OCI
    # runtime (using native Linux containers) will be used to run the containers
    # in a pod.
    # The RuntimeHandler must conform to the DNS Label (RFC 1123) requirements
    # and is immutable.
    def runtimeHandler(self) -> str:
        return self.__runtimeHandler

    # Overhead represents the resource overhead associated with running a pod for a
    # given RuntimeClass. For more details, see
    # https://git.k8s.io/enhancements/keps/sig-node/20190226-pod-overhead.md
    # This field is alpha-level as of Kubernetes v1.15, and is only honored by servers that enable the PodOverhead feature.
    def overhead(self) -> Optional[Overhead]:
        return self.__overhead

    # Scheduling holds the scheduling constraints to ensure that pods running
    # with this RuntimeClass are scheduled to nodes that support it.
    # If scheduling is nil, this RuntimeClass is assumed to be supported by all
    # nodes.
    def scheduling(self) -> Optional[Scheduling]:
        return self.__scheduling


# RuntimeClass defines a class of container runtime supported in the cluster.
# The RuntimeClass is used to determine which container runtime is used to run
# all containers in a pod. RuntimeClasses are (currently) manually defined by a
# user or cluster provisioner, and referenced in the PodSpec. The Kubelet is
# responsible for resolving the RuntimeClassName reference before running the
# pod.  For more details, see
# https://git.k8s.io/enhancements/keps/sig-node/runtime-class.md
class RuntimeClass(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: RuntimeClassSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "node.k8s.io/v1alpha1",
                "kind": "RuntimeClass",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else RuntimeClassSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, RuntimeClassSpec)
        v["spec"] = spec
        return v

    # Specification of the RuntimeClass
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    def spec(self) -> RuntimeClassSpec:
        return self.__spec
