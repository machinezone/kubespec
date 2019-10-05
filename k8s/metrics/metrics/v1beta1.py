# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Dict

import addict
from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery import resource
from k8s.apimachinery.meta import v1 as metav1
from korps import types
from typeguard import typechecked


# ContainerMetrics sets resource usage metrics of a container.
class ContainerMetrics(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['name'] = self.name()
        v['usage'] = self.usage()
        return v
    
    # Container name corresponding to the one from pod.spec.containers.
    @typechecked
    def name(self) -> str:
        return self._kwargs.get('name', '')
    
    # The memory usage is the memory working set.
    @typechecked
    def usage(self) -> Dict[corev1.ResourceName, 'resource.Quantity']:
        return self._kwargs.get('usage', addict.Dict())


# NodeMetrics sets resource usage metrics of a node.
class NodeMetrics(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['timestamp'] = self.timestamp()
        v['window'] = self.window()
        v['usage'] = self.usage()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'metrics.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'NodeMetrics'
    
    # The following fields define time interval from which metrics were
    # collected from the interval [Timestamp-Window, Timestamp].
    @typechecked
    def timestamp(self) -> 'base.Time':
        return self._kwargs.get('timestamp')
    
    @typechecked
    def window(self) -> 'metav1.Duration':
        return self._kwargs.get('window', metav1.Duration())
    
    # The memory usage is the memory working set.
    @typechecked
    def usage(self) -> Dict[corev1.ResourceName, 'resource.Quantity']:
        return self._kwargs.get('usage', addict.Dict())


# PodMetrics sets resource usage metrics of a pod.
class PodMetrics(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['timestamp'] = self.timestamp()
        v['window'] = self.window()
        v['containers'] = self.containers().values()  # named list
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'metrics.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'PodMetrics'
    
    # The following fields define time interval from which metrics were
    # collected from the interval [Timestamp-Window, Timestamp].
    @typechecked
    def timestamp(self) -> 'base.Time':
        return self._kwargs.get('timestamp')
    
    @typechecked
    def window(self) -> 'metav1.Duration':
        return self._kwargs.get('window', metav1.Duration())
    
    # Metrics for all containers are collected within the same time window.
    @typechecked
    def containers(self) -> Dict[str, ContainerMetrics]:
        return self._kwargs.get('containers', addict.Dict())
