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
from typeguard import typechecked


# MetricIdentifier identifies a metric by name and, optionally, selector
class MetricIdentifier(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = "", selector: "metav1.LabelSelector" = None):
        super().__init__(**{})
        self.__name = name
        self.__selector = selector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        v["selector"] = self.selector()
        return v

    # name is the name of the given metric
    @typechecked
    def name(self) -> str:
        return self.__name

    # selector represents the label selector that could be used to select
    # this metric, and will generally just be the selector passed in to
    # the query used to fetch this metric.
    # When left blank, only the metric's Name will be used to gather metrics.
    @typechecked
    def selector(self) -> Optional["metav1.LabelSelector"]:
        return self.__selector


# MetricListOptions is used to select metrics by their label selectors
class MetricListOptions(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(self, labelSelector: str = None, metricLabelSelector: str = None):
        super().__init__(
            **{
                "apiVersion": "custom.metrics.k8s.io/v1beta2",
                "kind": "MetricListOptions",
            }
        )
        self.__labelSelector = labelSelector
        self.__metricLabelSelector = metricLabelSelector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        labelSelector = self.labelSelector()
        if labelSelector:  # omit empty
            v["labelSelector"] = labelSelector
        metricLabelSelector = self.metricLabelSelector()
        if metricLabelSelector:  # omit empty
            v["metricLabelSelector"] = metricLabelSelector
        return v

    # A selector to restrict the list of returned objects by their labels.
    # Defaults to everything.
    @typechecked
    def labelSelector(self) -> Optional[str]:
        return self.__labelSelector

    # A selector to restrict the list of returned metrics by their labels
    @typechecked
    def metricLabelSelector(self) -> Optional[str]:
        return self.__metricLabelSelector


# MetricValue is the metric value for some object
class MetricValue(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        describedObject: "corev1.ObjectReference" = None,
        metric: MetricIdentifier = None,
        timestamp: "base.Time" = None,
        windowSeconds: int = None,
        value: "resource.Quantity" = None,
    ):
        super().__init__(
            **{"apiVersion": "custom.metrics.k8s.io/v1beta2", "kind": "MetricValue"}
        )
        self.__describedObject = (
            describedObject if describedObject is not None else corev1.ObjectReference()
        )
        self.__metric = metric if metric is not None else MetricIdentifier()
        self.__timestamp = timestamp
        self.__windowSeconds = windowSeconds
        self.__value = value if value is not None else resource.Quantity()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["describedObject"] = self.describedObject()
        v["metric"] = self.metric()
        v["timestamp"] = self.timestamp()
        windowSeconds = self.windowSeconds()
        if windowSeconds is not None:  # omit empty
            v["windowSeconds"] = windowSeconds
        v["value"] = self.value()
        return v

    # a reference to the described object
    @typechecked
    def describedObject(self) -> "corev1.ObjectReference":
        return self.__describedObject

    @typechecked
    def metric(self) -> MetricIdentifier:
        return self.__metric

    # indicates the time at which the metrics were produced
    @typechecked
    def timestamp(self) -> "base.Time":
        return self.__timestamp

    # indicates the window ([Timestamp-Window, Timestamp]) from
    # which these metrics were calculated, when returning rate
    # metrics calculated from cumulative metrics (or zero for
    # non-calculated instantaneous metrics).
    @typechecked
    def windowSeconds(self) -> Optional[int]:
        return self.__windowSeconds

    # the value of the metric for this
    @typechecked
    def value(self) -> "resource.Quantity":
        return self.__value
