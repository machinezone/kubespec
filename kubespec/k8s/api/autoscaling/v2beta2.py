# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec.k8s.apimachinery import resource
from kubespec.k8s.apimachinery.meta import v1 as metav1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


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


# MetricTargetType specifies the type of metric being targeted, and should be either
# "Value", "AverageValue", or "Utilization"
MetricTargetType = base.Enum(
    "MetricTargetType",
    {
        # AverageValue declares a MetricTarget is an
        "AverageValue": "AverageValue",
        # Utilization declares a MetricTarget is an AverageUtilization value
        "Utilization": "Utilization",
        # Value declares a MetricTarget is a raw value
        "Value": "Value",
    },
)


# CrossVersionObjectReference contains enough information to let you identify the referred resource.
class CrossVersionObjectReference(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, kind: str = "", name: str = "", apiVersion: str = None):
        super().__init__()
        self.__kind = kind
        self.__name = name
        self.__apiVersion = apiVersion

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        apiVersion = self.apiVersion()
        check_type("apiVersion", apiVersion, Optional[str])
        if apiVersion:  # omit empty
            v["apiVersion"] = apiVersion
        return v

    # Kind of the referent; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"
    def kind(self) -> str:
        return self.__kind

    # Name of the referent; More info: http://kubernetes.io/docs/user-guide/identifiers#names
    def name(self) -> str:
        return self.__name

    # API version of the referent
    def apiVersion(self) -> Optional[str]:
        return self.__apiVersion


# MetricIdentifier defines the name and optionally selector for a metric
class MetricIdentifier(types.Object):
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
        if selector is not None:  # omit empty
            v["selector"] = selector
        return v

    # name is the name of the given metric
    def name(self) -> str:
        return self.__name

    # selector is the string-encoded form of a standard kubernetes label selector for the given metric
    # When set, it is passed as an additional parameter to the metrics server for more specific metrics scoping.
    # When unset, just the metricName will be used to gather metrics.
    def selector(self) -> Optional["metav1.LabelSelector"]:
        return self.__selector


# MetricTarget defines the target value, average value, or average utilization of a specific metric
class MetricTarget(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        type: MetricTargetType = None,
        value: "resource.Quantity" = None,
        averageValue: "resource.Quantity" = None,
        averageUtilization: int = None,
    ):
        super().__init__()
        self.__type = type
        self.__value = value
        self.__averageValue = averageValue
        self.__averageUtilization = averageUtilization

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, MetricTargetType)
        v["type"] = type
        value = self.value()
        check_type("value", value, Optional["resource.Quantity"])
        if value is not None:  # omit empty
            v["value"] = value
        averageValue = self.averageValue()
        check_type("averageValue", averageValue, Optional["resource.Quantity"])
        if averageValue is not None:  # omit empty
            v["averageValue"] = averageValue
        averageUtilization = self.averageUtilization()
        check_type("averageUtilization", averageUtilization, Optional[int])
        if averageUtilization is not None:  # omit empty
            v["averageUtilization"] = averageUtilization
        return v

    # type represents whether the metric type is Utilization, Value, or AverageValue
    def type(self) -> MetricTargetType:
        return self.__type

    # value is the target value of the metric (as a quantity).
    def value(self) -> Optional["resource.Quantity"]:
        return self.__value

    # averageValue is the target value of the average of the
    # metric across all relevant pods (as a quantity)
    def averageValue(self) -> Optional["resource.Quantity"]:
        return self.__averageValue

    # averageUtilization is the target value of the average of the
    # resource metric across all relevant pods, represented as a percentage of
    # the requested value of the resource for the pods.
    # Currently only valid for Resource metric source type
    def averageUtilization(self) -> Optional[int]:
        return self.__averageUtilization


# ExternalMetricSource indicates how to scale on a metric not associated with
# any Kubernetes object (for example length of queue in cloud
# messaging service, or QPS from loadbalancer running outside of cluster).
class ExternalMetricSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, metric: MetricIdentifier = None, target: MetricTarget = None):
        super().__init__()
        self.__metric = metric if metric is not None else MetricIdentifier()
        self.__target = target if target is not None else MetricTarget()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        metric = self.metric()
        check_type("metric", metric, MetricIdentifier)
        v["metric"] = metric
        target = self.target()
        check_type("target", target, MetricTarget)
        v["target"] = target
        return v

    # metric identifies the target metric by name and selector
    def metric(self) -> MetricIdentifier:
        return self.__metric

    # target specifies the target value for the given metric
    def target(self) -> MetricTarget:
        return self.__target


# ObjectMetricSource indicates how to scale on a metric describing a
# kubernetes object (for example, hits-per-second on an Ingress object).
class ObjectMetricSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        describedObject: CrossVersionObjectReference = None,
        target: MetricTarget = None,
        metric: MetricIdentifier = None,
    ):
        super().__init__()
        self.__describedObject = (
            describedObject
            if describedObject is not None
            else CrossVersionObjectReference()
        )
        self.__target = target if target is not None else MetricTarget()
        self.__metric = metric if metric is not None else MetricIdentifier()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        describedObject = self.describedObject()
        check_type("describedObject", describedObject, CrossVersionObjectReference)
        v["describedObject"] = describedObject
        target = self.target()
        check_type("target", target, MetricTarget)
        v["target"] = target
        metric = self.metric()
        check_type("metric", metric, MetricIdentifier)
        v["metric"] = metric
        return v

    def describedObject(self) -> CrossVersionObjectReference:
        return self.__describedObject

    # target specifies the target value for the given metric
    def target(self) -> MetricTarget:
        return self.__target

    # metric identifies the target metric by name and selector
    def metric(self) -> MetricIdentifier:
        return self.__metric


# PodsMetricSource indicates how to scale on a metric describing each pod in
# the current scale target (for example, transactions-processed-per-second).
# The values will be averaged together before being compared to the target
# value.
class PodsMetricSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, metric: MetricIdentifier = None, target: MetricTarget = None):
        super().__init__()
        self.__metric = metric if metric is not None else MetricIdentifier()
        self.__target = target if target is not None else MetricTarget()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        metric = self.metric()
        check_type("metric", metric, MetricIdentifier)
        v["metric"] = metric
        target = self.target()
        check_type("target", target, MetricTarget)
        v["target"] = target
        return v

    # metric identifies the target metric by name and selector
    def metric(self) -> MetricIdentifier:
        return self.__metric

    # target specifies the target value for the given metric
    def target(self) -> MetricTarget:
        return self.__target


# ResourceMetricSource indicates how to scale on a resource metric known to
# Kubernetes, as specified in requests and limits, describing each pod in the
# current scale target (e.g. CPU or memory).  The values will be averaged
# together before being compared to the target.  Such metrics are built in to
# Kubernetes, and have special scaling options on top of those available to
# normal per-pod metrics using the "pods" source.  Only one "target" type
# should be set.
class ResourceMetricSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: corev1.ResourceName = None, target: MetricTarget = None):
        super().__init__()
        self.__name = name
        self.__target = target if target is not None else MetricTarget()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, corev1.ResourceName)
        v["name"] = name
        target = self.target()
        check_type("target", target, MetricTarget)
        v["target"] = target
        return v

    # name is the name of the resource in question.
    def name(self) -> corev1.ResourceName:
        return self.__name

    # target specifies the target value for the given metric
    def target(self) -> MetricTarget:
        return self.__target


# MetricSpec specifies how to scale based on a single metric
# (only `type` and one other matching field should be set at once).
class MetricSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        type: MetricSourceType = None,
        object: ObjectMetricSource = None,
        pods: PodsMetricSource = None,
        resource: ResourceMetricSource = None,
        external: ExternalMetricSource = None,
    ):
        super().__init__()
        self.__type = type
        self.__object = object
        self.__pods = pods
        self.__resource = resource
        self.__external = external

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, MetricSourceType)
        v["type"] = type
        object = self.object()
        check_type("object", object, Optional[ObjectMetricSource])
        if object is not None:  # omit empty
            v["object"] = object
        pods = self.pods()
        check_type("pods", pods, Optional[PodsMetricSource])
        if pods is not None:  # omit empty
            v["pods"] = pods
        resource = self.resource()
        check_type("resource", resource, Optional[ResourceMetricSource])
        if resource is not None:  # omit empty
            v["resource"] = resource
        external = self.external()
        check_type("external", external, Optional[ExternalMetricSource])
        if external is not None:  # omit empty
            v["external"] = external
        return v

    # type is the type of metric source.  It should be one of "Object",
    # "Pods" or "Resource", each mapping to a matching field in the object.
    def type(self) -> MetricSourceType:
        return self.__type

    # object refers to a metric describing a single kubernetes object
    # (for example, hits-per-second on an Ingress object).
    def object(self) -> Optional[ObjectMetricSource]:
        return self.__object

    # pods refers to a metric describing each pod in the current scale target
    # (for example, transactions-processed-per-second).  The values will be
    # averaged together before being compared to the target value.
    def pods(self) -> Optional[PodsMetricSource]:
        return self.__pods

    # resource refers to a resource metric (such as those specified in
    # requests and limits) known to Kubernetes describing each pod in the
    # current scale target (e.g. CPU or memory). Such metrics are built in to
    # Kubernetes, and have special scaling options on top of those available
    # to normal per-pod metrics using the "pods" source.
    def resource(self) -> Optional[ResourceMetricSource]:
        return self.__resource

    # external refers to a global metric that is not associated
    # with any Kubernetes object. It allows autoscaling based on information
    # coming from components running outside of cluster
    # (for example length of queue in cloud messaging service, or
    # QPS from loadbalancer running outside of cluster).
    def external(self) -> Optional[ExternalMetricSource]:
        return self.__external


# HorizontalPodAutoscalerSpec describes the desired functionality of the HorizontalPodAutoscaler.
class HorizontalPodAutoscalerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        scaleTargetRef: CrossVersionObjectReference = None,
        minReplicas: int = None,
        maxReplicas: int = 0,
        metrics: List[MetricSpec] = None,
    ):
        super().__init__()
        self.__scaleTargetRef = (
            scaleTargetRef
            if scaleTargetRef is not None
            else CrossVersionObjectReference()
        )
        self.__minReplicas = minReplicas
        self.__maxReplicas = maxReplicas
        self.__metrics = metrics if metrics is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        scaleTargetRef = self.scaleTargetRef()
        check_type("scaleTargetRef", scaleTargetRef, CrossVersionObjectReference)
        v["scaleTargetRef"] = scaleTargetRef
        minReplicas = self.minReplicas()
        check_type("minReplicas", minReplicas, Optional[int])
        if minReplicas is not None:  # omit empty
            v["minReplicas"] = minReplicas
        maxReplicas = self.maxReplicas()
        check_type("maxReplicas", maxReplicas, int)
        v["maxReplicas"] = maxReplicas
        metrics = self.metrics()
        check_type("metrics", metrics, Optional[List[MetricSpec]])
        if metrics:  # omit empty
            v["metrics"] = metrics
        return v

    # scaleTargetRef points to the target resource to scale, and is used to the pods for which metrics
    # should be collected, as well as to actually change the replica count.
    def scaleTargetRef(self) -> CrossVersionObjectReference:
        return self.__scaleTargetRef

    # minReplicas is the lower limit for the number of replicas to which the autoscaler
    # can scale down.  It defaults to 1 pod.  minReplicas is allowed to be 0 if the
    # alpha feature gate HPAScaleToZero is enabled and at least one Object or External
    # metric is configured.  Scaling is active as long as at least one metric value is
    # available.
    def minReplicas(self) -> Optional[int]:
        return self.__minReplicas

    # maxReplicas is the upper limit for the number of replicas to which the autoscaler can scale up.
    # It cannot be less that minReplicas.
    def maxReplicas(self) -> int:
        return self.__maxReplicas

    # metrics contains the specifications for which to use to calculate the
    # desired replica count (the maximum replica count across all metrics will
    # be used).  The desired replica count is calculated multiplying the
    # ratio between the target value and the current value by the current
    # number of pods.  Ergo, metrics used must decrease as the pod count is
    # increased, and vice-versa.  See the individual metric source types for
    # more information about how each type of metric must respond.
    # If not set, the default metric will be set to 80% average CPU utilization.
    def metrics(self) -> Optional[List[MetricSpec]]:
        return self.__metrics


# HorizontalPodAutoscaler is the configuration for a horizontal pod
# autoscaler, which automatically manages the replica count of any resource
# implementing the scale subresource based on the metrics specified.
class HorizontalPodAutoscaler(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: HorizontalPodAutoscalerSpec = None,
    ):
        super().__init__(
            apiVersion="autoscaling/v2beta2",
            kind="HorizontalPodAutoscaler",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else HorizontalPodAutoscalerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional[HorizontalPodAutoscalerSpec])
        v["spec"] = spec
        return v

    # spec is the specification for the behaviour of the autoscaler.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
    def spec(self) -> Optional[HorizontalPodAutoscalerSpec]:
        return self.__spec
