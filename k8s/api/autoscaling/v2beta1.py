# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery import resource
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# MetricSourceType indicates the type of metric.
MetricSourceType = base.Enum(
    "MetricSourceType",
    {
        # External is a global metric that is not associated
        # with any Kubernetes object. It allows autoscaling based on information
        # coming from components running outside of cluster
        # (for example length of queue in cloud messaging service, or
        # QPS from loadbalancer running outside of cluster).
        "External": "External",
        # Object is a metric describing a kubernetes object
        # (for example, hits-per-second on an Ingress object).
        "Object": "Object",
        # Pods is a metric describing each pod in the current scale
        # target (for example, transactions-processed-per-second).  The values
        # will be averaged together before being compared to the target value.
        "Pods": "Pods",
        # Resource is a resource metric known to Kubernetes, as
        # specified in requests and limits, describing each pod in the current
        # scale target (e.g. CPU or memory).  Such metrics are built in to
        # Kubernetes, and have special scaling options on top of those available
        # to normal per-pod metrics (the "pods" source).
        "Resource": "Resource",
    },
)


# CrossVersionObjectReference contains enough information to let you identify the referred resource.
class CrossVersionObjectReference(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["kind"] = self.kind()
        v["name"] = self.name()
        apiVersion = self.apiVersion()
        if apiVersion:  # omit empty
            v["apiVersion"] = apiVersion
        return v

    # Kind of the referent; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"
    @typechecked
    def kind(self) -> str:
        if "kind" in self._kwargs:
            return self._kwargs["kind"]
        if "kind" in self._context and check_return_type(self._context["kind"]):
            return self._context["kind"]
        return ""

    # Name of the referent; More info: http://kubernetes.io/docs/user-guide/identifiers#names
    @typechecked
    def name(self) -> str:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return ""

    # API version of the referent
    @typechecked
    def apiVersion(self) -> Optional[str]:
        if "apiVersion" in self._kwargs:
            return self._kwargs["apiVersion"]
        if "apiVersion" in self._context and check_return_type(
            self._context["apiVersion"]
        ):
            return self._context["apiVersion"]
        return None


# ExternalMetricSource indicates how to scale on a metric not associated with
# any Kubernetes object (for example length of queue in cloud
# messaging service, or QPS from loadbalancer running outside of cluster).
# Exactly one "target" type should be set.
class ExternalMetricSource(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["metricName"] = self.metricName()
        metricSelector = self.metricSelector()
        if metricSelector is not None:  # omit empty
            v["metricSelector"] = metricSelector
        targetValue = self.targetValue()
        if targetValue is not None:  # omit empty
            v["targetValue"] = targetValue
        targetAverageValue = self.targetAverageValue()
        if targetAverageValue is not None:  # omit empty
            v["targetAverageValue"] = targetAverageValue
        return v

    # metricName is the name of the metric in question.
    @typechecked
    def metricName(self) -> str:
        if "metricName" in self._kwargs:
            return self._kwargs["metricName"]
        if "metricName" in self._context and check_return_type(
            self._context["metricName"]
        ):
            return self._context["metricName"]
        return ""

    # metricSelector is used to identify a specific time series
    # within a given metric.
    @typechecked
    def metricSelector(self) -> Optional["metav1.LabelSelector"]:
        if "metricSelector" in self._kwargs:
            return self._kwargs["metricSelector"]
        if "metricSelector" in self._context and check_return_type(
            self._context["metricSelector"]
        ):
            return self._context["metricSelector"]
        return None

    # targetValue is the target value of the metric (as a quantity).
    # Mutually exclusive with TargetAverageValue.
    @typechecked
    def targetValue(self) -> Optional["resource.Quantity"]:
        if "targetValue" in self._kwargs:
            return self._kwargs["targetValue"]
        if "targetValue" in self._context and check_return_type(
            self._context["targetValue"]
        ):
            return self._context["targetValue"]
        return None

    # targetAverageValue is the target per-pod value of global metric (as a quantity).
    # Mutually exclusive with TargetValue.
    @typechecked
    def targetAverageValue(self) -> Optional["resource.Quantity"]:
        if "targetAverageValue" in self._kwargs:
            return self._kwargs["targetAverageValue"]
        if "targetAverageValue" in self._context and check_return_type(
            self._context["targetAverageValue"]
        ):
            return self._context["targetAverageValue"]
        return None


# ObjectMetricSource indicates how to scale on a metric describing a
# kubernetes object (for example, hits-per-second on an Ingress object).
class ObjectMetricSource(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["target"] = self.target()
        v["metricName"] = self.metricName()
        v["targetValue"] = self.targetValue()
        selector = self.selector()
        if selector is not None:  # omit empty
            v["selector"] = selector
        averageValue = self.averageValue()
        if averageValue is not None:  # omit empty
            v["averageValue"] = averageValue
        return v

    # target is the described Kubernetes object.
    @typechecked
    def target(self) -> CrossVersionObjectReference:
        if "target" in self._kwargs:
            return self._kwargs["target"]
        if "target" in self._context and check_return_type(self._context["target"]):
            return self._context["target"]
        with context.Scope(**self._context):
            return CrossVersionObjectReference()

    # metricName is the name of the metric in question.
    @typechecked
    def metricName(self) -> str:
        if "metricName" in self._kwargs:
            return self._kwargs["metricName"]
        if "metricName" in self._context and check_return_type(
            self._context["metricName"]
        ):
            return self._context["metricName"]
        return ""

    # targetValue is the target value of the metric (as a quantity).
    @typechecked
    def targetValue(self) -> "resource.Quantity":
        if "targetValue" in self._kwargs:
            return self._kwargs["targetValue"]
        if "targetValue" in self._context and check_return_type(
            self._context["targetValue"]
        ):
            return self._context["targetValue"]
        with context.Scope(**self._context):
            return resource.Quantity()

    # selector is the string-encoded form of a standard kubernetes label selector for the given metric
    # When set, it is passed as an additional parameter to the metrics server for more specific metrics scoping
    # When unset, just the metricName will be used to gather metrics.
    @typechecked
    def selector(self) -> Optional["metav1.LabelSelector"]:
        if "selector" in self._kwargs:
            return self._kwargs["selector"]
        if "selector" in self._context and check_return_type(self._context["selector"]):
            return self._context["selector"]
        return None

    # averageValue is the target value of the average of the
    # metric across all relevant pods (as a quantity)
    @typechecked
    def averageValue(self) -> Optional["resource.Quantity"]:
        if "averageValue" in self._kwargs:
            return self._kwargs["averageValue"]
        if "averageValue" in self._context and check_return_type(
            self._context["averageValue"]
        ):
            return self._context["averageValue"]
        return None


# PodsMetricSource indicates how to scale on a metric describing each pod in
# the current scale target (for example, transactions-processed-per-second).
# The values will be averaged together before being compared to the target
# value.
class PodsMetricSource(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["metricName"] = self.metricName()
        v["targetAverageValue"] = self.targetAverageValue()
        selector = self.selector()
        if selector is not None:  # omit empty
            v["selector"] = selector
        return v

    # metricName is the name of the metric in question
    @typechecked
    def metricName(self) -> str:
        if "metricName" in self._kwargs:
            return self._kwargs["metricName"]
        if "metricName" in self._context and check_return_type(
            self._context["metricName"]
        ):
            return self._context["metricName"]
        return ""

    # targetAverageValue is the target value of the average of the
    # metric across all relevant pods (as a quantity)
    @typechecked
    def targetAverageValue(self) -> "resource.Quantity":
        if "targetAverageValue" in self._kwargs:
            return self._kwargs["targetAverageValue"]
        if "targetAverageValue" in self._context and check_return_type(
            self._context["targetAverageValue"]
        ):
            return self._context["targetAverageValue"]
        with context.Scope(**self._context):
            return resource.Quantity()

    # selector is the string-encoded form of a standard kubernetes label selector for the given metric
    # When set, it is passed as an additional parameter to the metrics server for more specific metrics scoping
    # When unset, just the metricName will be used to gather metrics.
    @typechecked
    def selector(self) -> Optional["metav1.LabelSelector"]:
        if "selector" in self._kwargs:
            return self._kwargs["selector"]
        if "selector" in self._context and check_return_type(self._context["selector"]):
            return self._context["selector"]
        return None


# ResourceMetricSource indicates how to scale on a resource metric known to
# Kubernetes, as specified in requests and limits, describing each pod in the
# current scale target (e.g. CPU or memory).  The values will be averaged
# together before being compared to the target.  Such metrics are built in to
# Kubernetes, and have special scaling options on top of those available to
# normal per-pod metrics using the "pods" source.  Only one "target" type
# should be set.
class ResourceMetricSource(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["name"] = self.name()
        targetAverageUtilization = self.targetAverageUtilization()
        if targetAverageUtilization is not None:  # omit empty
            v["targetAverageUtilization"] = targetAverageUtilization
        targetAverageValue = self.targetAverageValue()
        if targetAverageValue is not None:  # omit empty
            v["targetAverageValue"] = targetAverageValue
        return v

    # name is the name of the resource in question.
    @typechecked
    def name(self) -> corev1.ResourceName:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return None

    # targetAverageUtilization is the target value of the average of the
    # resource metric across all relevant pods, represented as a percentage of
    # the requested value of the resource for the pods.
    @typechecked
    def targetAverageUtilization(self) -> Optional[int]:
        if "targetAverageUtilization" in self._kwargs:
            return self._kwargs["targetAverageUtilization"]
        if "targetAverageUtilization" in self._context and check_return_type(
            self._context["targetAverageUtilization"]
        ):
            return self._context["targetAverageUtilization"]
        return None

    # targetAverageValue is the target value of the average of the
    # resource metric across all relevant pods, as a raw value (instead of as
    # a percentage of the request), similar to the "pods" metric source type.
    @typechecked
    def targetAverageValue(self) -> Optional["resource.Quantity"]:
        if "targetAverageValue" in self._kwargs:
            return self._kwargs["targetAverageValue"]
        if "targetAverageValue" in self._context and check_return_type(
            self._context["targetAverageValue"]
        ):
            return self._context["targetAverageValue"]
        return None


# MetricSpec specifies how to scale based on a single metric
# (only `type` and one other matching field should be set at once).
class MetricSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["type"] = self.type()
        object = self.object()
        if object is not None:  # omit empty
            v["object"] = object
        pods = self.pods()
        if pods is not None:  # omit empty
            v["pods"] = pods
        resource = self.resource()
        if resource is not None:  # omit empty
            v["resource"] = resource
        external = self.external()
        if external is not None:  # omit empty
            v["external"] = external
        return v

    # type is the type of metric source.  It should be one of "Object",
    # "Pods" or "Resource", each mapping to a matching field in the object.
    @typechecked
    def type(self) -> MetricSourceType:
        if "type" in self._kwargs:
            return self._kwargs["type"]
        if "type" in self._context and check_return_type(self._context["type"]):
            return self._context["type"]
        return None

    # object refers to a metric describing a single kubernetes object
    # (for example, hits-per-second on an Ingress object).
    @typechecked
    def object(self) -> Optional[ObjectMetricSource]:
        if "object" in self._kwargs:
            return self._kwargs["object"]
        if "object" in self._context and check_return_type(self._context["object"]):
            return self._context["object"]
        return None

    # pods refers to a metric describing each pod in the current scale target
    # (for example, transactions-processed-per-second).  The values will be
    # averaged together before being compared to the target value.
    @typechecked
    def pods(self) -> Optional[PodsMetricSource]:
        if "pods" in self._kwargs:
            return self._kwargs["pods"]
        if "pods" in self._context and check_return_type(self._context["pods"]):
            return self._context["pods"]
        return None

    # resource refers to a resource metric (such as those specified in
    # requests and limits) known to Kubernetes describing each pod in the
    # current scale target (e.g. CPU or memory). Such metrics are built in to
    # Kubernetes, and have special scaling options on top of those available
    # to normal per-pod metrics using the "pods" source.
    @typechecked
    def resource(self) -> Optional[ResourceMetricSource]:
        if "resource" in self._kwargs:
            return self._kwargs["resource"]
        if "resource" in self._context and check_return_type(self._context["resource"]):
            return self._context["resource"]
        return None

    # external refers to a global metric that is not associated
    # with any Kubernetes object. It allows autoscaling based on information
    # coming from components running outside of cluster
    # (for example length of queue in cloud messaging service, or
    # QPS from loadbalancer running outside of cluster).
    @typechecked
    def external(self) -> Optional[ExternalMetricSource]:
        if "external" in self._kwargs:
            return self._kwargs["external"]
        if "external" in self._context and check_return_type(self._context["external"]):
            return self._context["external"]
        return None


# HorizontalPodAutoscalerSpec describes the desired functionality of the HorizontalPodAutoscaler.
class HorizontalPodAutoscalerSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["scaleTargetRef"] = self.scaleTargetRef()
        minReplicas = self.minReplicas()
        if minReplicas is not None:  # omit empty
            v["minReplicas"] = minReplicas
        v["maxReplicas"] = self.maxReplicas()
        metrics = self.metrics()
        if metrics:  # omit empty
            v["metrics"] = metrics
        return v

    # scaleTargetRef points to the target resource to scale, and is used to the pods for which metrics
    # should be collected, as well as to actually change the replica count.
    @typechecked
    def scaleTargetRef(self) -> CrossVersionObjectReference:
        if "scaleTargetRef" in self._kwargs:
            return self._kwargs["scaleTargetRef"]
        if "scaleTargetRef" in self._context and check_return_type(
            self._context["scaleTargetRef"]
        ):
            return self._context["scaleTargetRef"]
        with context.Scope(**self._context):
            return CrossVersionObjectReference()

    # minReplicas is the lower limit for the number of replicas to which the autoscaler
    # can scale down.  It defaults to 1 pod.  minReplicas is allowed to be 0 if the
    # alpha feature gate HPAScaleToZero is enabled and at least one Object or External
    # metric is configured.  Scaling is active as long as at least one metric value is
    # available.
    @typechecked
    def minReplicas(self) -> Optional[int]:
        if "minReplicas" in self._kwargs:
            return self._kwargs["minReplicas"]
        if "minReplicas" in self._context and check_return_type(
            self._context["minReplicas"]
        ):
            return self._context["minReplicas"]
        return 1

    # maxReplicas is the upper limit for the number of replicas to which the autoscaler can scale up.
    # It cannot be less that minReplicas.
    @typechecked
    def maxReplicas(self) -> int:
        if "maxReplicas" in self._kwargs:
            return self._kwargs["maxReplicas"]
        if "maxReplicas" in self._context and check_return_type(
            self._context["maxReplicas"]
        ):
            return self._context["maxReplicas"]
        return 0

    # metrics contains the specifications for which to use to calculate the
    # desired replica count (the maximum replica count across all metrics will
    # be used).  The desired replica count is calculated multiplying the
    # ratio between the target value and the current value by the current
    # number of pods.  Ergo, metrics used must decrease as the pod count is
    # increased, and vice-versa.  See the individual metric source types for
    # more information about how each type of metric must respond.
    @typechecked
    def metrics(self) -> List[MetricSpec]:
        if "metrics" in self._kwargs:
            return self._kwargs["metrics"]
        if "metrics" in self._context and check_return_type(self._context["metrics"]):
            return self._context["metrics"]
        return []


# HorizontalPodAutoscaler is the configuration for a horizontal pod
# autoscaler, which automatically manages the replica count of any resource
# implementing the scale subresource based on the metrics specified.
class HorizontalPodAutoscaler(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "autoscaling/v2beta1"

    @typechecked
    def kind(self) -> str:
        return "HorizontalPodAutoscaler"

    # spec is the specification for the behaviour of the autoscaler.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
    @typechecked
    def spec(self) -> HorizontalPodAutoscalerSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return HorizontalPodAutoscalerSpec()
