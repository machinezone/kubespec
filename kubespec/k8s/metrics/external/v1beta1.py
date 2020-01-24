# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec.k8s import base
from kubespec.k8s import resource
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


class ExternalMetricValue(base.TypedObject):
    """
    ExternalMetricValue is a metric value for external metric
    A single metric value is identified by metric name and a set of string labels.
    For one metric there can be multiple values with different sets of labels.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        metric_name: str = "",
        metric_labels: Dict[str, str] = None,
        timestamp: "base.Time" = None,
        window: int = None,
        value: "resource.Quantity" = None,
    ):
        super().__init__(
            api_version="external.metrics.k8s.io/v1beta1", kind="ExternalMetricValue"
        )
        self.__metric_name = metric_name
        self.__metric_labels = metric_labels if metric_labels is not None else {}
        self.__timestamp = timestamp
        self.__window = window
        self.__value = value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        metric_name = self.metric_name()
        check_type("metric_name", metric_name, str)
        v["metricName"] = metric_name
        metric_labels = self.metric_labels()
        check_type("metric_labels", metric_labels, Dict[str, str])
        v["metricLabels"] = metric_labels
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
        return v

    def metric_name(self) -> str:
        """
        the name of the metric
        """
        return self.__metric_name

    def metric_labels(self) -> Dict[str, str]:
        """
        a set of labels that identify a single time series for the metric
        """
        return self.__metric_labels

    def timestamp(self) -> "base.Time":
        """
        indicates the time at which the metrics were produced
        """
        return self.__timestamp

    def window(self) -> Optional[int]:
        """
        indicates the window ([Timestamp-Window, Timestamp]) from
        which these metrics were calculated, when returning rate
        metrics calculated from cumulative metrics (or zero for
        non-calculated instantaneous metrics).
        """
        return self.__window

    def value(self) -> "resource.Quantity":
        """
        the value of the metric
        """
        return self.__value
