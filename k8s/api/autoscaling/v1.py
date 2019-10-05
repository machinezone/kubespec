# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Optional

import addict
from k8s import base
from korps import types
from typeguard import typechecked


# CrossVersionObjectReference contains enough information to let you identify the referred resource.
class CrossVersionObjectReference(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['kind'] = self.kind()
        v['name'] = self.name()
        apiVersion = self.apiVersion()
        if apiVersion:  # omit empty
            v['apiVersion'] = apiVersion
        return v
    
    # Kind of the referent; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"
    @typechecked
    def kind(self) -> str:
        return self._kwargs.get('kind', '')
    
    # Name of the referent; More info: http://kubernetes.io/docs/user-guide/identifiers#names
    @typechecked
    def name(self) -> str:
        return self._kwargs.get('name', '')
    
    # API version of the referent
    @typechecked
    def apiVersion(self) -> Optional[str]:
        return self._kwargs.get('apiVersion')


# specification of a horizontal pod autoscaler.
class HorizontalPodAutoscalerSpec(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['scaleTargetRef'] = self.scaleTargetRef()
        minReplicas = self.minReplicas()
        if minReplicas is not None:  # omit empty
            v['minReplicas'] = minReplicas
        v['maxReplicas'] = self.maxReplicas()
        targetCPUUtilizationPercentage = self.targetCPUUtilizationPercentage()
        if targetCPUUtilizationPercentage is not None:  # omit empty
            v['targetCPUUtilizationPercentage'] = targetCPUUtilizationPercentage
        return v
    
    # reference to scaled resource; horizontal pod autoscaler will learn the current resource consumption
    # and will set the desired number of pods by using its Scale subresource.
    @typechecked
    def scaleTargetRef(self) -> CrossVersionObjectReference:
        return self._kwargs.get('scaleTargetRef', CrossVersionObjectReference())
    
    # minReplicas is the lower limit for the number of replicas to which the autoscaler
    # can scale down.  It defaults to 1 pod.  minReplicas is allowed to be 0 if the
    # alpha feature gate HPAScaleToZero is enabled and at least one Object or External
    # metric is configured.  Scaling is active as long as at least one metric value is
    # available.
    @typechecked
    def minReplicas(self) -> Optional[int]:
        return self._kwargs.get('minReplicas', 1)
    
    # upper limit for the number of pods that can be set by the autoscaler; cannot be smaller than MinReplicas.
    @typechecked
    def maxReplicas(self) -> int:
        return self._kwargs.get('maxReplicas', 0)
    
    # target average CPU utilization (represented as a percentage of requested CPU) over all the pods;
    # if not specified the default autoscaling policy will be used.
    @typechecked
    def targetCPUUtilizationPercentage(self) -> Optional[int]:
        return self._kwargs.get('targetCPUUtilizationPercentage')


# configuration of a horizontal pod autoscaler.
class HorizontalPodAutoscaler(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        spec = self.spec()
        if spec:  # omit empty
            v['spec'] = spec
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'autoscaling/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'HorizontalPodAutoscaler'
    
    # behaviour of autoscaler. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
    @typechecked
    def spec(self) -> Optional[HorizontalPodAutoscalerSpec]:
        return self._kwargs.get('spec', HorizontalPodAutoscalerSpec())


# ScaleSpec describes the attributes of a scale subresource.
class ScaleSpec(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        replicas = self.replicas()
        if replicas:  # omit empty
            v['replicas'] = replicas
        return v
    
    # desired number of instances for the scaled object.
    @typechecked
    def replicas(self) -> Optional[int]:
        return self._kwargs.get('replicas')


# Scale represents a scaling request for a resource.
class Scale(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        spec = self.spec()
        if spec:  # omit empty
            v['spec'] = spec
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'autoscaling/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'Scale'
    
    # defines the behavior of the scale. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
    @typechecked
    def spec(self) -> Optional[ScaleSpec]:
        return self._kwargs.get('spec')
