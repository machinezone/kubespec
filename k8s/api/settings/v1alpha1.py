# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List

from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery.meta import v1 as metav1
from kargo import types
from typeguard import typechecked


# PodPresetSpec is a description of a pod preset.
class PodPresetSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['selector'] = self.selector()
        env = self.env()
        if env:  # omit empty
            v['env'] = env.values()  # named list
        envFrom = self.envFrom()
        if envFrom:  # omit empty
            v['envFrom'] = envFrom
        volumes = self.volumes()
        if volumes:  # omit empty
            v['volumes'] = volumes.values()  # named list
        volumeMounts = self.volumeMounts()
        if volumeMounts:  # omit empty
            v['volumeMounts'] = volumeMounts.values()  # named list
        return v
    
    # Selector is a label query over a set of resources, in this case pods.
    # Required.
    @typechecked
    def selector(self) -> 'metav1.LabelSelector':
        return self._kwargs.get('selector', metav1.LabelSelector())
    
    # Env defines the collection of EnvVar to inject into containers.
    @typechecked
    def env(self) -> Dict[str, 'corev1.EnvVar']:
        return self._kwargs.get('env', {})
    
    # EnvFrom defines the collection of EnvFromSource to inject into containers.
    @typechecked
    def envFrom(self) -> List['corev1.EnvFromSource']:
        return self._kwargs.get('envFrom', [])
    
    # Volumes defines the collection of Volume to inject into the pod.
    @typechecked
    def volumes(self) -> Dict[str, 'corev1.Volume']:
        return self._kwargs.get('volumes', {})
    
    # VolumeMounts defines the collection of VolumeMount to inject into containers.
    @typechecked
    def volumeMounts(self) -> Dict[str, 'corev1.VolumeMount']:
        return self._kwargs.get('volumeMounts', {})


# PodPreset is a policy resource that defines additional runtime
# requirements for a Pod.
class PodPreset(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'settings.k8s.io/v1alpha1'
    
    @typechecked
    def kind(self) -> str:
        return 'PodPreset'
    
    @typechecked
    def spec(self) -> PodPresetSpec:
        return self._kwargs.get('spec', PodPresetSpec())
