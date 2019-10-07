# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery import resource
from k8s.apimachinery.meta import v1 as metav1
from kargo import types
from typeguard import typechecked


# MetricListOptions is used to select metrics by their label selectors
class MetricListOptions(base.TypedObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        labelSelector = self.labelSelector()
        if labelSelector:  # omit empty
            v['labelSelector'] = labelSelector
        metricLabelSelector = self.metricLabelSelector()
        if metricLabelSelector:  # omit empty
            v['metricLabelSelector'] = metricLabelSelector
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'custom.metrics.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'MetricListOptions'
    
    # A selector to restrict the list of returned objects by their labels.
    # Defaults to everything.
    @typechecked
    def labelSelector(self) -> Optional[str]:
        return self._kwargs.get('labelSelector')
    
    # A selector to restrict the list of returned metrics by their labels
    @typechecked
    def metricLabelSelector(self) -> Optional[str]:
        return self._kwargs.get('metricLabelSelector')


# MetricValue is a metric value for some object
class MetricValue(base.TypedObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['describedObject'] = self.describedObject()
        v['metricName'] = self.metricName()
        v['timestamp'] = self.timestamp()
        window = self.window()
        if window is not None:  # omit empty
            v['window'] = window
        v['value'] = self.value()
        v['selector'] = self.selector()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'custom.metrics.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'MetricValue'
    
    # a reference to the described object
    @typechecked
    def describedObject(self) -> 'corev1.ObjectReference':
        return self._kwargs.get('describedObject', corev1.ObjectReference())
    
    # the name of the metric
    @typechecked
    def metricName(self) -> str:
        return self._kwargs.get('metricName', '')
    
    # indicates the time at which the metrics were produced
    @typechecked
    def timestamp(self) -> 'base.Time':
        return self._kwargs.get('timestamp')
    
    # indicates the window ([Timestamp-Window, Timestamp]) from
    # which these metrics were calculated, when returning rate
    # metrics calculated from cumulative metrics (or zero for
    # non-calculated instantaneous metrics).
    @typechecked
    def window(self) -> Optional[int]:
        return self._kwargs.get('window')
    
    # the value of the metric for this
    @typechecked
    def value(self) -> 'resource.Quantity':
        return self._kwargs.get('value', resource.Quantity())
    
    # selector represents the label selector that could be used to select
    # this metric, and will generally just be the selector passed in to
    # the query used to fetch this metric.
    # When left blank, only the metric's Name will be used to gather metrics.
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        return self._kwargs.get('selector')
