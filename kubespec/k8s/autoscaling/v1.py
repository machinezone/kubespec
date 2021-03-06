# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


class CrossVersionObjectReference(types.Object):
    """
    CrossVersionObjectReference contains enough information to let you identify the referred resource.
    """

    @context.scoped
    @typechecked
    def __init__(self, kind: str = "", name: str = "", api_version: str = None):
        super().__init__()
        self.__kind = kind
        self.__name = name
        self.__api_version = api_version

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        api_version = self.api_version()
        check_type("api_version", api_version, Optional[str])
        if api_version:  # omit empty
            v["apiVersion"] = api_version
        return v

    def kind(self) -> str:
        """
        Kind of the referent; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"
        """
        return self.__kind

    def name(self) -> str:
        """
        Name of the referent; More info: http://kubernetes.io/docs/user-guide/identifiers#names
        """
        return self.__name

    def api_version(self) -> Optional[str]:
        """
        API version of the referent
        """
        return self.__api_version


class HorizontalPodAutoscalerSpec(types.Object):
    """
    specification of a horizontal pod autoscaler.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        scale_target_ref: "CrossVersionObjectReference" = None,
        min_replicas: int = None,
        max_replicas: int = 0,
        target_cpu_utilization_percentage: int = None,
    ):
        super().__init__()
        self.__scale_target_ref = (
            scale_target_ref
            if scale_target_ref is not None
            else CrossVersionObjectReference()
        )
        self.__min_replicas = min_replicas if min_replicas is not None else 1
        self.__max_replicas = max_replicas
        self.__target_cpu_utilization_percentage = target_cpu_utilization_percentage

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        scale_target_ref = self.scale_target_ref()
        check_type("scale_target_ref", scale_target_ref, "CrossVersionObjectReference")
        v["scaleTargetRef"] = scale_target_ref
        min_replicas = self.min_replicas()
        check_type("min_replicas", min_replicas, Optional[int])
        if min_replicas is not None:  # omit empty
            v["minReplicas"] = min_replicas
        max_replicas = self.max_replicas()
        check_type("max_replicas", max_replicas, int)
        v["maxReplicas"] = max_replicas
        target_cpu_utilization_percentage = self.target_cpu_utilization_percentage()
        check_type(
            "target_cpu_utilization_percentage",
            target_cpu_utilization_percentage,
            Optional[int],
        )
        if target_cpu_utilization_percentage is not None:  # omit empty
            v["targetCPUUtilizationPercentage"] = target_cpu_utilization_percentage
        return v

    def scale_target_ref(self) -> "CrossVersionObjectReference":
        """
        reference to scaled resource; horizontal pod autoscaler will learn the current resource consumption
        and will set the desired number of pods by using its Scale subresource.
        """
        return self.__scale_target_ref

    def min_replicas(self) -> Optional[int]:
        """
        minReplicas is the lower limit for the number of replicas to which the autoscaler
        can scale down.  It defaults to 1 pod.  minReplicas is allowed to be 0 if the
        alpha feature gate HPAScaleToZero is enabled and at least one Object or External
        metric is configured.  Scaling is active as long as at least one metric value is
        available.
        """
        return self.__min_replicas

    def max_replicas(self) -> int:
        """
        upper limit for the number of pods that can be set by the autoscaler; cannot be smaller than MinReplicas.
        """
        return self.__max_replicas

    def target_cpu_utilization_percentage(self) -> Optional[int]:
        """
        target average CPU utilization (represented as a percentage of requested CPU) over all the pods;
        if not specified the default autoscaling policy will be used.
        """
        return self.__target_cpu_utilization_percentage


class HorizontalPodAutoscaler(base.TypedObject, base.NamespacedMetadataObject):
    """
    configuration of a horizontal pod autoscaler.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "HorizontalPodAutoscalerSpec" = None,
    ):
        super().__init__(
            api_version="autoscaling/v1",
            kind="HorizontalPodAutoscaler",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else HorizontalPodAutoscalerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["HorizontalPodAutoscalerSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["HorizontalPodAutoscalerSpec"]:
        """
        behaviour of autoscaler. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        """
        return self.__spec


class ScaleSpec(types.Object):
    """
    ScaleSpec describes the attributes of a scale subresource.
    """

    @context.scoped
    @typechecked
    def __init__(self, replicas: int = None):
        super().__init__()
        self.__replicas = replicas

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas:  # omit empty
            v["replicas"] = replicas
        return v

    def replicas(self) -> Optional[int]:
        """
        desired number of instances for the scaled object.
        """
        return self.__replicas


class Scale(base.TypedObject, base.NamespacedMetadataObject):
    """
    Scale represents a scaling request for a resource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ScaleSpec" = None,
    ):
        super().__init__(
            api_version="autoscaling/v1",
            kind="Scale",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ScaleSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["ScaleSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["ScaleSpec"]:
        """
        defines the behavior of the scale. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        """
        return self.__spec
