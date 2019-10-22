# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# CrossVersionObjectReference contains enough information to let you identify the referred resource.
class CrossVersionObjectReference(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, kind: str = "", name: str = "", apiVersion: str = None):
        super().__init__()
        self.__kind = kind
        self.__name = name
        self.__apiVersion = apiVersion

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        apiVersion = self.apiVersion()
        check_type("apiVersion", apiVersion, Optional[str])
        if apiVersion:  # omit empty
            v["apiVersion"] = apiVersion
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

    def apiVersion(self) -> Optional[str]:
        """
        API version of the referent
        """
        return self.__apiVersion


# specification of a horizontal pod autoscaler.
class HorizontalPodAutoscalerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        scaleTargetRef: CrossVersionObjectReference = None,
        minReplicas: int = None,
        maxReplicas: int = 0,
        targetCPUUtilizationPercentage: int = None,
    ):
        super().__init__()
        self.__scaleTargetRef = (
            scaleTargetRef
            if scaleTargetRef is not None
            else CrossVersionObjectReference()
        )
        self.__minReplicas = minReplicas if minReplicas is not None else 1
        self.__maxReplicas = maxReplicas
        self.__targetCPUUtilizationPercentage = targetCPUUtilizationPercentage

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        scaleTargetRef = self.scaleTargetRef()
        check_type("scaleTargetRef", scaleTargetRef, CrossVersionObjectReference)
        v["scaleTargetRef"] = scaleTargetRef
        minReplicas = self.minReplicas()
        check_type("minReplicas", minReplicas, Optional[int])
        if minReplicas is not None:  # omit empty
            v["minReplicas"] = minReplicas
        maxReplicas = self.maxReplicas()
        check_type("maxReplicas", maxReplicas, int)
        v["maxReplicas"] = maxReplicas
        targetCPUUtilizationPercentage = self.targetCPUUtilizationPercentage()
        check_type(
            "targetCPUUtilizationPercentage",
            targetCPUUtilizationPercentage,
            Optional[int],
        )
        if targetCPUUtilizationPercentage is not None:  # omit empty
            v["targetCPUUtilizationPercentage"] = targetCPUUtilizationPercentage
        return v

    def scaleTargetRef(self) -> CrossVersionObjectReference:
        """
        reference to scaled resource; horizontal pod autoscaler will learn the current resource consumption
        and will set the desired number of pods by using its Scale subresource.
        """
        return self.__scaleTargetRef

    def minReplicas(self) -> Optional[int]:
        """
        minReplicas is the lower limit for the number of replicas to which the autoscaler
        can scale down.  It defaults to 1 pod.  minReplicas is allowed to be 0 if the
        alpha feature gate HPAScaleToZero is enabled and at least one Object or External
        metric is configured.  Scaling is active as long as at least one metric value is
        available.
        """
        return self.__minReplicas

    def maxReplicas(self) -> int:
        """
        upper limit for the number of pods that can be set by the autoscaler; cannot be smaller than MinReplicas.
        """
        return self.__maxReplicas

    def targetCPUUtilizationPercentage(self) -> Optional[int]:
        """
        target average CPU utilization (represented as a percentage of requested CPU) over all the pods;
        if not specified the default autoscaling policy will be used.
        """
        return self.__targetCPUUtilizationPercentage


# configuration of a horizontal pod autoscaler.
class HorizontalPodAutoscaler(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: HorizontalPodAutoscalerSpec = None,
    ):
        super().__init__(
            apiVersion="autoscaling/v1",
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
        check_type("spec", spec, Optional[HorizontalPodAutoscalerSpec])
        v["spec"] = spec
        return v

    def spec(self) -> Optional[HorizontalPodAutoscalerSpec]:
        """
        behaviour of autoscaler. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        """
        return self.__spec


# ScaleSpec describes the attributes of a scale subresource.
class ScaleSpec(types.Object):
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


# Scale represents a scaling request for a resource.
class Scale(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: ScaleSpec = None,
    ):
        super().__init__(
            apiVersion="autoscaling/v1",
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
        check_type("spec", spec, Optional[ScaleSpec])
        v["spec"] = spec
        return v

    def spec(self) -> Optional[ScaleSpec]:
        """
        defines the behavior of the scale. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        """
        return self.__spec
