# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import resource
from kubespec.k8s import v1 as k8sv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


class Overhead(types.Object):
    """
    Overhead structure represents the resource overhead associated with running a pod.
    """

    @context.scoped
    @typechecked
    def __init__(self, pod_fixed: Dict[k8sv1.ResourceName, "resource.Quantity"] = None):
        super().__init__()
        self.__pod_fixed = pod_fixed if pod_fixed is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pod_fixed = self.pod_fixed()
        check_type(
            "pod_fixed",
            pod_fixed,
            Optional[Dict[k8sv1.ResourceName, "resource.Quantity"]],
        )
        if pod_fixed:  # omit empty
            v["podFixed"] = pod_fixed
        return v

    def pod_fixed(self) -> Optional[Dict[k8sv1.ResourceName, "resource.Quantity"]]:
        """
        PodFixed represents the fixed resource overhead associated with running a pod.
        """
        return self.__pod_fixed


class Scheduling(types.Object):
    """
    Scheduling specifies the scheduling constraints for nodes supporting a
    RuntimeClass.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        node_selector: Dict[str, str] = None,
        tolerations: List["k8sv1.Toleration"] = None,
    ):
        super().__init__()
        self.__node_selector = node_selector if node_selector is not None else {}
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional[Dict[str, str]])
        if node_selector:  # omit empty
            v["nodeSelector"] = node_selector
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    def node_selector(self) -> Optional[Dict[str, str]]:
        """
        nodeSelector lists labels that must be present on nodes that support this
        RuntimeClass. Pods using this RuntimeClass can only be scheduled to a
        node matched by this selector. The RuntimeClass nodeSelector is merged
        with a pod's existing nodeSelector. Any conflicts will cause the pod to
        be rejected in admission.
        """
        return self.__node_selector

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        tolerations are appended (excluding duplicates) to pods running with this
        RuntimeClass during admission, effectively unioning the set of nodes
        tolerated by the pod and the RuntimeClass.
        +listType=atomic
        """
        return self.__tolerations


class RuntimeClass(base.TypedObject, base.MetadataObject):
    """
    RuntimeClass defines a class of container runtime supported in the cluster.
    The RuntimeClass is used to determine which container runtime is used to run
    all containers in a pod. RuntimeClasses are (currently) manually defined by a
    user or cluster provisioner, and referenced in the PodSpec. The Kubelet is
    responsible for resolving the RuntimeClassName reference before running the
    pod.  For more details, see
    https://git.k8s.io/enhancements/keps/sig-node/runtime-class.md
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        handler: str = "",
        overhead: "Overhead" = None,
        scheduling: "Scheduling" = None,
    ):
        super().__init__(
            api_version="node.k8s.io/v1beta1",
            kind="RuntimeClass",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__handler = handler
        self.__overhead = overhead
        self.__scheduling = scheduling

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        handler = self.handler()
        check_type("handler", handler, str)
        v["handler"] = handler
        overhead = self.overhead()
        check_type("overhead", overhead, Optional["Overhead"])
        if overhead is not None:  # omit empty
            v["overhead"] = overhead
        scheduling = self.scheduling()
        check_type("scheduling", scheduling, Optional["Scheduling"])
        if scheduling is not None:  # omit empty
            v["scheduling"] = scheduling
        return v

    def handler(self) -> str:
        """
        Handler specifies the underlying runtime and configuration that the CRI
        implementation will use to handle pods of this class. The possible values
        are specific to the node & CRI configuration.  It is assumed that all
        handlers are available on every node, and handlers of the same name are
        equivalent on every node.
        For example, a handler called "runc" might specify that the runc OCI
        runtime (using native Linux containers) will be used to run the containers
        in a pod.
        The Handler must conform to the DNS Label (RFC 1123) requirements, and is
        immutable.
        """
        return self.__handler

    def overhead(self) -> Optional["Overhead"]:
        """
        Overhead represents the resource overhead associated with running a pod for a
        given RuntimeClass. For more details, see
        https://git.k8s.io/enhancements/keps/sig-node/20190226-pod-overhead.md
        This field is alpha-level as of Kubernetes v1.15, and is only honored by servers that enable the PodOverhead feature.
        """
        return self.__overhead

    def scheduling(self) -> Optional["Scheduling"]:
        """
        Scheduling holds the scheduling constraints to ensure that pods running
        with this RuntimeClass are scheduled to nodes that support it.
        If scheduling is nil, this RuntimeClass is assumed to be supported by all
        nodes.
        """
        return self.__scheduling
