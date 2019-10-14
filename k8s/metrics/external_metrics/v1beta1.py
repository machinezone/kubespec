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
    @context.scoped
    @typechecked
    def __init__(
        self,
        metricName: str = "",
        metricLabels: Dict[str, str] = None,
        timestamp: "base.Time" = None,
        window: int = None,
        value: "resource.Quantity" = None,
    ):
        super().__init__(
            **{
                "apiVersion": "external.metrics.k8s.io/v1beta1",
                "kind": "ExternalMetricValue",
            }
        )
        self.__metricName = metricName
        self.__metricLabels = metricLabels if metricLabels is not None else {}
        self.__timestamp = timestamp
        self.__window = window
        self.__value = value if value is not None else resource.Quantity()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["metricName"] = self.metricName()
        v["metricLabels"] = self.metricLabels()
        v["timestamp"] = self.timestamp()
        window = self.window()
        if window is not None:  # omit empty
            v["window"] = window
        v["value"] = self.value()
        return v

    # the name of the metric
    @typechecked
    def metricName(self) -> str:
        return self.__metricName

    # a set of labels that identify a single time series for the metric
    @typechecked
    def metricLabels(self) -> Dict[str, str]:
        return self.__metricLabels

    # indicates the time at which the metrics were produced
    @typechecked
    def timestamp(self) -> "base.Time":
        return self.__timestamp

    # indicates the window ([Timestamp-Window, Timestamp]) from
    # which these metrics were calculated, when returning rate
    # metrics calculated from cumulative metrics (or zero for
    # non-calculated instantaneous metrics).
    @typechecked
    def window(self) -> Optional[int]:
        return self.__window

    # the value of the metric
    @typechecked
    def value(self) -> "resource.Quantity":
        return self.__value
