# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import resource
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


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
    def __init__(self, label_selector: str = None, metric_label_selector: str = None):
        super().__init__(
            api_version="custom.metrics.k8s.io/v1beta2", kind="MetricListOptions"
        )
        self.__label_selector = label_selector
        self.__metric_label_selector = metric_label_selector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        label_selector = self.label_selector()
        check_type("label_selector", label_selector, Optional[str])
        if label_selector:  # omit empty
            v["labelSelector"] = label_selector
        metric_label_selector = self.metric_label_selector()
        check_type("metric_label_selector", metric_label_selector, Optional[str])
        if metric_label_selector:  # omit empty
            v["metricLabelSelector"] = metric_label_selector
        return v

    def label_selector(self) -> Optional[str]:
        """
        A selector to restrict the list of returned objects by their labels.
        Defaults to everything.
        """
        return self.__label_selector

    def metric_label_selector(self) -> Optional[str]:
        """
        A selector to restrict the list of returned metrics by their labels
        """
        return self.__metric_label_selector


class MetricValue(base.TypedObject):
    """
    MetricValue is the metric value for some object
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        described_object: "k8sv1.ObjectReference" = None,
        metric: "MetricIdentifier" = None,
        timestamp: "base.Time" = None,
        window_seconds: int = None,
        value: "resource.Quantity" = None,
    ):
        super().__init__(
            api_version="custom.metrics.k8s.io/v1beta2", kind="MetricValue"
        )
        self.__described_object = (
            described_object
            if described_object is not None
            else k8sv1.ObjectReference()
        )
        self.__metric = metric if metric is not None else MetricIdentifier()
        self.__timestamp = timestamp
        self.__window_seconds = window_seconds
        self.__value = value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        described_object = self.described_object()
        check_type("described_object", described_object, "k8sv1.ObjectReference")
        v["describedObject"] = described_object
        metric = self.metric()
        check_type("metric", metric, "MetricIdentifier")
        v["metric"] = metric
        timestamp = self.timestamp()
        check_type("timestamp", timestamp, "base.Time")
        v["timestamp"] = timestamp
        window_seconds = self.window_seconds()
        check_type("window_seconds", window_seconds, Optional[int])
        if window_seconds is not None:  # omit empty
            v["windowSeconds"] = window_seconds
        value = self.value()
        check_type("value", value, "resource.Quantity")
        v["value"] = value
        return v

    def described_object(self) -> "k8sv1.ObjectReference":
        """
        a reference to the described object
        """
        return self.__described_object

    def metric(self) -> "MetricIdentifier":
        return self.__metric

    def timestamp(self) -> "base.Time":
        """
        indicates the time at which the metrics were produced
        """
        return self.__timestamp

    def window_seconds(self) -> Optional[int]:
        """
        indicates the window ([Timestamp-Window, Timestamp]) from
        which these metrics were calculated, when returning rate
        metrics calculated from cumulative metrics (or zero for
        non-calculated instantaneous metrics).
        """
        return self.__window_seconds

    def value(self) -> "resource.Quantity":
        """
        the value of the metric for this
        """
        return self.__value
