# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery import resource
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# MetricListOptions is used to select metrics by their label selectors
class MetricListOptions(base.TypedObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        labelSelector = self.labelSelector()
        if labelSelector:  # omit empty
            v["labelSelector"] = labelSelector
        metricLabelSelector = self.metricLabelSelector()
        if metricLabelSelector:  # omit empty
            v["metricLabelSelector"] = metricLabelSelector
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "custom.metrics.k8s.io/v1beta1"

    @typechecked
    def kind(self) -> str:
        return "MetricListOptions"

    # A selector to restrict the list of returned objects by their labels.
    # Defaults to everything.
    @typechecked
    def labelSelector(self) -> Optional[str]:
        if "labelSelector" in self._kwargs:
            return self._kwargs["labelSelector"]
        if "labelSelector" in self._context and check_return_type(
            self._context["labelSelector"]
        ):
            return self._context["labelSelector"]
        return None

    # A selector to restrict the list of returned metrics by their labels
    @typechecked
    def metricLabelSelector(self) -> Optional[str]:
        if "metricLabelSelector" in self._kwargs:
            return self._kwargs["metricLabelSelector"]
        if "metricLabelSelector" in self._context and check_return_type(
            self._context["metricLabelSelector"]
        ):
            return self._context["metricLabelSelector"]
        return None


# MetricValue is a metric value for some object
class MetricValue(base.TypedObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["describedObject"] = self.describedObject()
        v["metricName"] = self.metricName()
        v["timestamp"] = self.timestamp()
        window = self.window()
        if window is not None:  # omit empty
            v["window"] = window
        v["value"] = self.value()
        v["selector"] = self.selector()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "custom.metrics.k8s.io/v1beta1"

    @typechecked
    def kind(self) -> str:
        return "MetricValue"

    # a reference to the described object
    @typechecked
    def describedObject(self) -> "corev1.ObjectReference":
        if "describedObject" in self._kwargs:
            return self._kwargs["describedObject"]
        if "describedObject" in self._context and check_return_type(
            self._context["describedObject"]
        ):
            return self._context["describedObject"]
        with context.Scope(**self._context):
            return corev1.ObjectReference()

    # the name of the metric
    @typechecked
    def metricName(self) -> str:
        if "metricName" in self._kwargs:
            return self._kwargs["metricName"]
        if "metricName" in self._context and check_return_type(
            self._context["metricName"]
        ):
            return self._context["metricName"]
        return ""

    # indicates the time at which the metrics were produced
    @typechecked
    def timestamp(self) -> "base.Time":
        if "timestamp" in self._kwargs:
            return self._kwargs["timestamp"]
        if "timestamp" in self._context and check_return_type(
            self._context["timestamp"]
        ):
            return self._context["timestamp"]
        return None

    # indicates the window ([Timestamp-Window, Timestamp]) from
    # which these metrics were calculated, when returning rate
    # metrics calculated from cumulative metrics (or zero for
    # non-calculated instantaneous metrics).
    @typechecked
    def window(self) -> Optional[int]:
        if "window" in self._kwargs:
            return self._kwargs["window"]
        if "window" in self._context and check_return_type(self._context["window"]):
            return self._context["window"]
        return None

    # the value of the metric for this
    @typechecked
    def value(self) -> "resource.Quantity":
        if "value" in self._kwargs:
            return self._kwargs["value"]
        if "value" in self._context and check_return_type(self._context["value"]):
            return self._context["value"]
        with context.Scope(**self._context):
            return resource.Quantity()

    # selector represents the label selector that could be used to select
    # this metric, and will generally just be the selector passed in to
    # the query used to fetch this metric.
    # When left blank, only the metric's Name will be used to gather metrics.
    @typechecked
    def selector(self) -> Optional["metav1.LabelSelector"]:
        if "selector" in self._kwargs:
            return self._kwargs["selector"]
        if "selector" in self._context and check_return_type(self._context["selector"]):
            return self._context["selector"]
        return None
