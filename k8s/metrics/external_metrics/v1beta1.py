# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.apimachinery import resource
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# ExternalMetricValue is a metric value for external metric
# A single metric value is identified by metric name and a set of string labels.
# For one metric there can be multiple values with different sets of labels.
class ExternalMetricValue(base.TypedObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['metricName'] = self.metricName()
        v['metricLabels'] = self.metricLabels()
        v['timestamp'] = self.timestamp()
        window = self.window()
        if window is not None:  # omit empty
            v['window'] = window
        v['value'] = self.value()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'external.metrics.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'ExternalMetricValue'
    
    # the name of the metric
    @typechecked
    def metricName(self) -> str:
        if 'metricName' in self._kwargs:
            return self._kwargs['metricName']
        if 'metricName' in self._context and check_return_type(self._context['metricName']):
            return self._context['metricName']
        return ''
    
    # a set of labels that identify a single time series for the metric
    @typechecked
    def metricLabels(self) -> Dict[str, str]:
        if 'metricLabels' in self._kwargs:
            return self._kwargs['metricLabels']
        if 'metricLabels' in self._context and check_return_type(self._context['metricLabels']):
            return self._context['metricLabels']
        return {}
    
    # indicates the time at which the metrics were produced
    @typechecked
    def timestamp(self) -> 'base.Time':
        if 'timestamp' in self._kwargs:
            return self._kwargs['timestamp']
        if 'timestamp' in self._context and check_return_type(self._context['timestamp']):
            return self._context['timestamp']
        return None
    
    # indicates the window ([Timestamp-Window, Timestamp]) from
    # which these metrics were calculated, when returning rate
    # metrics calculated from cumulative metrics (or zero for
    # non-calculated instantaneous metrics).
    @typechecked
    def window(self) -> Optional[int]:
        if 'window' in self._kwargs:
            return self._kwargs['window']
        if 'window' in self._context and check_return_type(self._context['window']):
            return self._context['window']
        return None
    
    # the value of the metric
    @typechecked
    def value(self) -> 'resource.Quantity':
        if 'value' in self._kwargs:
            return self._kwargs['value']
        if 'value' in self._context and check_return_type(self._context['value']):
            return self._context['value']
        with context.Scope(**self._context):
            return resource.Quantity()
