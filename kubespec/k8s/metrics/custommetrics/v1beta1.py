# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec.k8s.apimachinery import resource
from kubespec.k8s.apimachinery.meta import v1 as metav1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# MetricListOptions is used to select metrics by their label selectors
class MetricListOptions(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(self, labelSelector: str = None, metricLabelSelector: str = None):
        super().__init__(
            apiVersion="custom.metrics.k8s.io/v1beta1", kind="MetricListOptions"
        )
        self.__labelSelector = labelSelector
        self.__metricLabelSelector = metricLabelSelector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        labelSelector = self.labelSelector()
        check_type("labelSelector", labelSelector, Optional[str])
        if labelSelector:  # omit empty
            v["labelSelector"] = labelSelector
        metricLabelSelector = self.metricLabelSelector()
        check_type("metricLabelSelector", metricLabelSelector, Optional[str])
        if metricLabelSelector:  # omit empty
            v["metricLabelSelector"] = metricLabelSelector
        return v

    # A selector to restrict the list of returned objects by their labels.
    # Defaults to everything.
    def labelSelector(self) -> Optional[str]:
        return self.__labelSelector

    # A selector to restrict the list of returned metrics by their labels
    def metricLabelSelector(self) -> Optional[str]:
        return self.__metricLabelSelector


# MetricValue is a metric value for some object
class MetricValue(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        describedObject: "corev1.ObjectReference" = None,
        metricName: str = "",
        timestamp: "base.Time" = None,
        window: int = None,
        value: "resource.Quantity" = None,
        selector: "metav1.LabelSelector" = None,
    ):
        super().__init__(apiVersion="custom.metrics.k8s.io/v1beta1", kind="MetricValue")
        self.__describedObject = (
            describedObject if describedObject is not None else corev1.ObjectReference()
        )
        self.__metricName = metricName
        self.__timestamp = timestamp
        self.__window = window
        self.__value = value if value is not None else resource.Quantity()
        self.__selector = selector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        describedObject = self.describedObject()
        check_type("describedObject", describedObject, "corev1.ObjectReference")
        v["describedObject"] = describedObject
        metricName = self.metricName()
        check_type("metricName", metricName, str)
        v["metricName"] = metricName
        timestamp = self.timestamp()
        check_type("timestamp", timestamp, "base.Time")
        v["timestamp"] = timestamp
        window = self.window()
        check_type("window", window, Optional[int])
        if window is not None:  # omit empty
            v["window"] = window
        value = self.value()
        check_type("value", value, "resource.Quantity")
        v["value"] = value
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        v["selector"] = selector
        return v

    # a reference to the described object
    def describedObject(self) -> "corev1.ObjectReference":
        return self.__describedObject

    # the name of the metric
    def metricName(self) -> str:
        return self.__metricName

    # indicates the time at which the metrics were produced
    def timestamp(self) -> "base.Time":
        return self.__timestamp

    # indicates the window ([Timestamp-Window, Timestamp]) from
    # which these metrics were calculated, when returning rate
    # metrics calculated from cumulative metrics (or zero for
    # non-calculated instantaneous metrics).
    def window(self) -> Optional[int]:
        return self.__window

    # the value of the metric for this
    def value(self) -> "resource.Quantity":
        return self.__value

    # selector represents the label selector that could be used to select
    # this metric, and will generally just be the selector passed in to
    # the query used to fetch this metric.
    # When left blank, only the metric's Name will be used to gather metrics.
    def selector(self) -> Optional["metav1.LabelSelector"]:
        return self.__selector
