# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Dict, Optional

import addict
from k8s import base
from k8s.apimachinery import resource
from korps import types
from typeguard import typechecked


# ExternalMetricValue is a metric value for external metric
# A single metric value is identified by metric name and a set of string labels.
# For one metric there can be multiple values with different sets of labels.
class ExternalMetricValue(base.TypedObject):

    @typechecked
    def render(self) -> addict.Dict:
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
        return self._kwargs.get('metricName', '')
    
    # a set of labels that identify a single time series for the metric
    @typechecked
    def metricLabels(self) -> Dict[str, str]:
        return self._kwargs.get('metricLabels', addict.Dict())
    
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
    
    # the value of the metric
    @typechecked
    def value(self) -> 'resource.Quantity':
        return self._kwargs.get('value', resource.Quantity())
