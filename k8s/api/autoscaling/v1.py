# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# CrossVersionObjectReference contains enough information to let you identify the referred resource.
class CrossVersionObjectReference(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["kind"] = self.kind()
        v["name"] = self.name()
        apiVersion = self.apiVersion()
        if apiVersion:  # omit empty
            v["apiVersion"] = apiVersion
        return v

    # Kind of the referent; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"
    @typechecked
    def kind(self) -> str:
        if "kind" in self._kwargs:
            return self._kwargs["kind"]
        if "kind" in self._context and check_return_type(self._context["kind"]):
            return self._context["kind"]
        return ""

    # Name of the referent; More info: http://kubernetes.io/docs/user-guide/identifiers#names
    @typechecked
    def name(self) -> str:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return ""

    # API version of the referent
    @typechecked
    def apiVersion(self) -> Optional[str]:
        if "apiVersion" in self._kwargs:
            return self._kwargs["apiVersion"]
        if "apiVersion" in self._context and check_return_type(
            self._context["apiVersion"]
        ):
            return self._context["apiVersion"]
        return None


# specification of a horizontal pod autoscaler.
class HorizontalPodAutoscalerSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["scaleTargetRef"] = self.scaleTargetRef()
        minReplicas = self.minReplicas()
        if minReplicas is not None:  # omit empty
            v["minReplicas"] = minReplicas
        v["maxReplicas"] = self.maxReplicas()
        targetCPUUtilizationPercentage = self.targetCPUUtilizationPercentage()
        if targetCPUUtilizationPercentage is not None:  # omit empty
            v["targetCPUUtilizationPercentage"] = targetCPUUtilizationPercentage
        return v

    # reference to scaled resource; horizontal pod autoscaler will learn the current resource consumption
    # and will set the desired number of pods by using its Scale subresource.
    @typechecked
    def scaleTargetRef(self) -> CrossVersionObjectReference:
        if "scaleTargetRef" in self._kwargs:
            return self._kwargs["scaleTargetRef"]
        if "scaleTargetRef" in self._context and check_return_type(
            self._context["scaleTargetRef"]
        ):
            return self._context["scaleTargetRef"]
        with context.Scope(**self._context):
            return CrossVersionObjectReference()

    # minReplicas is the lower limit for the number of replicas to which the autoscaler
    # can scale down.  It defaults to 1 pod.  minReplicas is allowed to be 0 if the
    # alpha feature gate HPAScaleToZero is enabled and at least one Object or External
    # metric is configured.  Scaling is active as long as at least one metric value is
    # available.
    @typechecked
    def minReplicas(self) -> Optional[int]:
        if "minReplicas" in self._kwargs:
            return self._kwargs["minReplicas"]
        if "minReplicas" in self._context and check_return_type(
            self._context["minReplicas"]
        ):
            return self._context["minReplicas"]
        return 1

    # upper limit for the number of pods that can be set by the autoscaler; cannot be smaller than MinReplicas.
    @typechecked
    def maxReplicas(self) -> int:
        if "maxReplicas" in self._kwargs:
            return self._kwargs["maxReplicas"]
        if "maxReplicas" in self._context and check_return_type(
            self._context["maxReplicas"]
        ):
            return self._context["maxReplicas"]
        return 0

    # target average CPU utilization (represented as a percentage of requested CPU) over all the pods;
    # if not specified the default autoscaling policy will be used.
    @typechecked
    def targetCPUUtilizationPercentage(self) -> Optional[int]:
        if "targetCPUUtilizationPercentage" in self._kwargs:
            return self._kwargs["targetCPUUtilizationPercentage"]
        if "targetCPUUtilizationPercentage" in self._context and check_return_type(
            self._context["targetCPUUtilizationPercentage"]
        ):
            return self._context["targetCPUUtilizationPercentage"]
        return None


# configuration of a horizontal pod autoscaler.
class HorizontalPodAutoscaler(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "autoscaling/v1"

    @typechecked
    def kind(self) -> str:
        return "HorizontalPodAutoscaler"

    # behaviour of autoscaler. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
    @typechecked
    def spec(self) -> HorizontalPodAutoscalerSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return HorizontalPodAutoscalerSpec()


# ScaleSpec describes the attributes of a scale subresource.
class ScaleSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        replicas = self.replicas()
        if replicas:  # omit empty
            v["replicas"] = replicas
        return v

    # desired number of instances for the scaled object.
    @typechecked
    def replicas(self) -> Optional[int]:
        if "replicas" in self._kwargs:
            return self._kwargs["replicas"]
        if "replicas" in self._context and check_return_type(self._context["replicas"]):
            return self._context["replicas"]
        return None


# Scale represents a scaling request for a resource.
class Scale(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "autoscaling/v1"

    @typechecked
    def kind(self) -> str:
        return "Scale"

    # defines the behavior of the scale. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
    @typechecked
    def spec(self) -> ScaleSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return ScaleSpec()
