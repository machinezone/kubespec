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


class MetricIdentifier(types.Object):
    """
    MetricIdentifier identifies a metric by name and, optionally, selector
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", selector: "metav1.LabelSelector" = None):
        super().__init__()
        self.__name = name
        self.__selector = selector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        v["selector"] = selector
        return v

    def name(self) -> str:
        """
        name is the name of the given metric
        """
        return self.__name

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        selector represents the label selector that could be used to select
        this metric, and will generally just be the selector passed in to
        the query used to fetch this metric.
        When left blank, only the metric's Name will be used to gather metrics.
        """
        return self.__selector


class MetricListOptions(base.TypedObject):
    """
    MetricListOptions is used to select metrics by their label selectors
    """

    @context.scoped
    @typechecked
    def __init__(self, labelSelector: str = None, metricLabelSelector: str = None):
        super().__init__(
            apiVersion="custom.metrics.k8s.io/v1beta2", kind="MetricListOptions"
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

    def labelSelector(self) -> Optional[str]:
        """
        A selector to restrict the list of returned objects by their labels.
        Defaults to everything.
        """
        return self.__labelSelector

    def metricLabelSelector(self) -> Optional[str]:
        """
        A selector to restrict the list of returned metrics by their labels
        """
        return self.__metricLabelSelector


class MetricValue(base.TypedObject):
    """
    MetricValue is the metric value for some object
    """

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
        super().__init__(apiVersion="custom.metrics.k8s.io/v1beta2", kind="MetricValue")
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
        describedObject = self.describedObject()
        check_type("describedObject", describedObject, "corev1.ObjectReference")
        v["describedObject"] = describedObject
        metric = self.metric()
        check_type("metric", metric, MetricIdentifier)
        v["metric"] = metric
        timestamp = self.timestamp()
        check_type("timestamp", timestamp, "base.Time")
        v["timestamp"] = timestamp
        windowSeconds = self.windowSeconds()
        check_type("windowSeconds", windowSeconds, Optional[int])
        if windowSeconds is not None:  # omit empty
            v["windowSeconds"] = windowSeconds
        value = self.value()
        check_type("value", value, "resource.Quantity")
        v["value"] = value
        return v

    def describedObject(self) -> "corev1.ObjectReference":
        """
        a reference to the described object
        """
        return self.__describedObject

    def metric(self) -> MetricIdentifier:
        return self.__metric

    def timestamp(self) -> "base.Time":
        """
        indicates the time at which the metrics were produced
        """
        return self.__timestamp

    def windowSeconds(self) -> Optional[int]:
        """
        indicates the window ([Timestamp-Window, Timestamp]) from
        which these metrics were calculated, when returning rate
        metrics calculated from cumulative metrics (or zero for
        non-calculated instantaneous metrics).
        """
        return self.__windowSeconds

    def value(self) -> "resource.Quantity":
        """
        the value of the metric for this
        """
        return self.__value
