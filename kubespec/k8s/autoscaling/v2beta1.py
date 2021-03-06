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
from typing import Any, Dict, List, Optional


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


class CrossVersionObjectReference(types.Object):
    """
    CrossVersionObjectReference contains enough information to let you identify the referred resource.
    """

    @context.scoped
    @typechecked
    def __init__(self, kind: str = "", name: str = "", api_version: str = None):
        super().__init__()
        self.__kind = kind
        self.__name = name
        self.__api_version = api_version

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        api_version = self.api_version()
        check_type("api_version", api_version, Optional[str])
        if api_version:  # omit empty
            v["apiVersion"] = api_version
        return v

    def kind(self) -> str:
        """
        Kind of the referent; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"
        """
        return self.__kind

    def name(self) -> str:
        """
        Name of the referent; More info: http://kubernetes.io/docs/user-guide/identifiers#names
        """
        return self.__name

    def api_version(self) -> Optional[str]:
        """
        API version of the referent
        """
        return self.__api_version


class ExternalMetricSource(types.Object):
    """
    ExternalMetricSource indicates how to scale on a metric not associated with
    any Kubernetes object (for example length of queue in cloud
    messaging service, or QPS from loadbalancer running outside of cluster).
    Exactly one "target" type should be set.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        metric_name: str = "",
        metric_selector: "metav1.LabelSelector" = None,
        target_value: "resource.Quantity" = None,
        target_average_value: "resource.Quantity" = None,
    ):
        super().__init__()
        self.__metric_name = metric_name
        self.__metric_selector = metric_selector
        self.__target_value = target_value
        self.__target_average_value = target_average_value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        metric_name = self.metric_name()
        check_type("metric_name", metric_name, str)
        v["metricName"] = metric_name
        metric_selector = self.metric_selector()
        check_type("metric_selector", metric_selector, Optional["metav1.LabelSelector"])
        if metric_selector is not None:  # omit empty
            v["metricSelector"] = metric_selector
        target_value = self.target_value()
        check_type("target_value", target_value, Optional["resource.Quantity"])
        if target_value is not None:  # omit empty
            v["targetValue"] = target_value
        target_average_value = self.target_average_value()
        check_type(
            "target_average_value", target_average_value, Optional["resource.Quantity"]
        )
        if target_average_value is not None:  # omit empty
            v["targetAverageValue"] = target_average_value
        return v

    def metric_name(self) -> str:
        """
        metricName is the name of the metric in question.
        """
        return self.__metric_name

    def metric_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        metricSelector is used to identify a specific time series
        within a given metric.
        """
        return self.__metric_selector

    def target_value(self) -> Optional["resource.Quantity"]:
        """
        targetValue is the target value of the metric (as a quantity).
        Mutually exclusive with TargetAverageValue.
        """
        return self.__target_value

    def target_average_value(self) -> Optional["resource.Quantity"]:
        """
        targetAverageValue is the target per-pod value of global metric (as a quantity).
        Mutually exclusive with TargetValue.
        """
        return self.__target_average_value


class ObjectMetricSource(types.Object):
    """
    ObjectMetricSource indicates how to scale on a metric describing a
    kubernetes object (for example, hits-per-second on an Ingress object).
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        target: "CrossVersionObjectReference" = None,
        metric_name: str = "",
        target_value: "resource.Quantity" = None,
        selector: "metav1.LabelSelector" = None,
        average_value: "resource.Quantity" = None,
    ):
        super().__init__()
        self.__target = target if target is not None else CrossVersionObjectReference()
        self.__metric_name = metric_name
        self.__target_value = target_value
        self.__selector = selector
        self.__average_value = average_value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        target = self.target()
        check_type("target", target, "CrossVersionObjectReference")
        v["target"] = target
        metric_name = self.metric_name()
        check_type("metric_name", metric_name, str)
        v["metricName"] = metric_name
        target_value = self.target_value()
        check_type("target_value", target_value, "resource.Quantity")
        v["targetValue"] = target_value
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        average_value = self.average_value()
        check_type("average_value", average_value, Optional["resource.Quantity"])
        if average_value is not None:  # omit empty
            v["averageValue"] = average_value
        return v

    def target(self) -> "CrossVersionObjectReference":
        """
        target is the described Kubernetes object.
        """
        return self.__target

    def metric_name(self) -> str:
        """
        metricName is the name of the metric in question.
        """
        return self.__metric_name

    def target_value(self) -> "resource.Quantity":
        """
        targetValue is the target value of the metric (as a quantity).
        """
        return self.__target_value

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        selector is the string-encoded form of a standard kubernetes label selector for the given metric
        When set, it is passed as an additional parameter to the metrics server for more specific metrics scoping
        When unset, just the metricName will be used to gather metrics.
        """
        return self.__selector

    def average_value(self) -> Optional["resource.Quantity"]:
        """
        averageValue is the target value of the average of the
        metric across all relevant pods (as a quantity)
        """
        return self.__average_value


class PodsMetricSource(types.Object):
    """
    PodsMetricSource indicates how to scale on a metric describing each pod in
    the current scale target (for example, transactions-processed-per-second).
    The values will be averaged together before being compared to the target
    value.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        metric_name: str = "",
        target_average_value: "resource.Quantity" = None,
        selector: "metav1.LabelSelector" = None,
    ):
        super().__init__()
        self.__metric_name = metric_name
        self.__target_average_value = target_average_value
        self.__selector = selector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        metric_name = self.metric_name()
        check_type("metric_name", metric_name, str)
        v["metricName"] = metric_name
        target_average_value = self.target_average_value()
        check_type("target_average_value", target_average_value, "resource.Quantity")
        v["targetAverageValue"] = target_average_value
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        return v

    def metric_name(self) -> str:
        """
        metricName is the name of the metric in question
        """
        return self.__metric_name

    def target_average_value(self) -> "resource.Quantity":
        """
        targetAverageValue is the target value of the average of the
        metric across all relevant pods (as a quantity)
        """
        return self.__target_average_value

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        selector is the string-encoded form of a standard kubernetes label selector for the given metric
        When set, it is passed as an additional parameter to the metrics server for more specific metrics scoping
        When unset, just the metricName will be used to gather metrics.
        """
        return self.__selector


class ResourceMetricSource(types.Object):
    """
    ResourceMetricSource indicates how to scale on a resource metric known to
    Kubernetes, as specified in requests and limits, describing each pod in the
    current scale target (e.g. CPU or memory).  The values will be averaged
    together before being compared to the target.  Such metrics are built in to
    Kubernetes, and have special scaling options on top of those available to
    normal per-pod metrics using the "pods" source.  Only one "target" type
    should be set.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: k8sv1.ResourceName = None,
        target_average_utilization: int = None,
        target_average_value: "resource.Quantity" = None,
    ):
        super().__init__()
        self.__name = name
        self.__target_average_utilization = target_average_utilization
        self.__target_average_value = target_average_value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, k8sv1.ResourceName)
        v["name"] = name
        target_average_utilization = self.target_average_utilization()
        check_type(
            "target_average_utilization", target_average_utilization, Optional[int]
        )
        if target_average_utilization is not None:  # omit empty
            v["targetAverageUtilization"] = target_average_utilization
        target_average_value = self.target_average_value()
        check_type(
            "target_average_value", target_average_value, Optional["resource.Quantity"]
        )
        if target_average_value is not None:  # omit empty
            v["targetAverageValue"] = target_average_value
        return v

    def name(self) -> k8sv1.ResourceName:
        """
        name is the name of the resource in question.
        """
        return self.__name

    def target_average_utilization(self) -> Optional[int]:
        """
        targetAverageUtilization is the target value of the average of the
        resource metric across all relevant pods, represented as a percentage of
        the requested value of the resource for the pods.
        """
        return self.__target_average_utilization

    def target_average_value(self) -> Optional["resource.Quantity"]:
        """
        targetAverageValue is the target value of the average of the
        resource metric across all relevant pods, as a raw value (instead of as
        a percentage of the request), similar to the "pods" metric source type.
        """
        return self.__target_average_value


class MetricSpec(types.Object):
    """
    MetricSpec specifies how to scale based on a single metric
    (only `type` and one other matching field should be set at once).
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: MetricSourceType = None,
        object: "ObjectMetricSource" = None,
        pods: "PodsMetricSource" = None,
        resource: "ResourceMetricSource" = None,
        external: "ExternalMetricSource" = None,
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
        check_type("object", object, Optional["ObjectMetricSource"])
        if object is not None:  # omit empty
            v["object"] = object
        pods = self.pods()
        check_type("pods", pods, Optional["PodsMetricSource"])
        if pods is not None:  # omit empty
            v["pods"] = pods
        resource = self.resource()
        check_type("resource", resource, Optional["ResourceMetricSource"])
        if resource is not None:  # omit empty
            v["resource"] = resource
        external = self.external()
        check_type("external", external, Optional["ExternalMetricSource"])
        if external is not None:  # omit empty
            v["external"] = external
        return v

    def type(self) -> MetricSourceType:
        """
        type is the type of metric source.  It should be one of "Object",
        "Pods" or "Resource", each mapping to a matching field in the object.
        """
        return self.__type

    def object(self) -> Optional["ObjectMetricSource"]:
        """
        object refers to a metric describing a single kubernetes object
        (for example, hits-per-second on an Ingress object).
        """
        return self.__object

    def pods(self) -> Optional["PodsMetricSource"]:
        """
        pods refers to a metric describing each pod in the current scale target
        (for example, transactions-processed-per-second).  The values will be
        averaged together before being compared to the target value.
        """
        return self.__pods

    def resource(self) -> Optional["ResourceMetricSource"]:
        """
        resource refers to a resource metric (such as those specified in
        requests and limits) known to Kubernetes describing each pod in the
        current scale target (e.g. CPU or memory). Such metrics are built in to
        Kubernetes, and have special scaling options on top of those available
        to normal per-pod metrics using the "pods" source.
        """
        return self.__resource

    def external(self) -> Optional["ExternalMetricSource"]:
        """
        external refers to a global metric that is not associated
        with any Kubernetes object. It allows autoscaling based on information
        coming from components running outside of cluster
        (for example length of queue in cloud messaging service, or
        QPS from loadbalancer running outside of cluster).
        """
        return self.__external


class HorizontalPodAutoscalerSpec(types.Object):
    """
    HorizontalPodAutoscalerSpec describes the desired functionality of the HorizontalPodAutoscaler.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        scale_target_ref: "CrossVersionObjectReference" = None,
        min_replicas: int = None,
        max_replicas: int = 0,
        metrics: List["MetricSpec"] = None,
    ):
        super().__init__()
        self.__scale_target_ref = (
            scale_target_ref
            if scale_target_ref is not None
            else CrossVersionObjectReference()
        )
        self.__min_replicas = min_replicas if min_replicas is not None else 1
        self.__max_replicas = max_replicas
        self.__metrics = metrics if metrics is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        scale_target_ref = self.scale_target_ref()
        check_type("scale_target_ref", scale_target_ref, "CrossVersionObjectReference")
        v["scaleTargetRef"] = scale_target_ref
        min_replicas = self.min_replicas()
        check_type("min_replicas", min_replicas, Optional[int])
        if min_replicas is not None:  # omit empty
            v["minReplicas"] = min_replicas
        max_replicas = self.max_replicas()
        check_type("max_replicas", max_replicas, int)
        v["maxReplicas"] = max_replicas
        metrics = self.metrics()
        check_type("metrics", metrics, Optional[List["MetricSpec"]])
        if metrics:  # omit empty
            v["metrics"] = metrics
        return v

    def scale_target_ref(self) -> "CrossVersionObjectReference":
        """
        scaleTargetRef points to the target resource to scale, and is used to the pods for which metrics
        should be collected, as well as to actually change the replica count.
        """
        return self.__scale_target_ref

    def min_replicas(self) -> Optional[int]:
        """
        minReplicas is the lower limit for the number of replicas to which the autoscaler
        can scale down.  It defaults to 1 pod.  minReplicas is allowed to be 0 if the
        alpha feature gate HPAScaleToZero is enabled and at least one Object or External
        metric is configured.  Scaling is active as long as at least one metric value is
        available.
        """
        return self.__min_replicas

    def max_replicas(self) -> int:
        """
        maxReplicas is the upper limit for the number of replicas to which the autoscaler can scale up.
        It cannot be less that minReplicas.
        """
        return self.__max_replicas

    def metrics(self) -> Optional[List["MetricSpec"]]:
        """
        metrics contains the specifications for which to use to calculate the
        desired replica count (the maximum replica count across all metrics will
        be used).  The desired replica count is calculated multiplying the
        ratio between the target value and the current value by the current
        number of pods.  Ergo, metrics used must decrease as the pod count is
        increased, and vice-versa.  See the individual metric source types for
        more information about how each type of metric must respond.
        """
        return self.__metrics


class HorizontalPodAutoscaler(base.TypedObject, base.NamespacedMetadataObject):
    """
    HorizontalPodAutoscaler is the configuration for a horizontal pod
    autoscaler, which automatically manages the replica count of any resource
    implementing the scale subresource based on the metrics specified.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "HorizontalPodAutoscalerSpec" = None,
    ):
        super().__init__(
            api_version="autoscaling/v2beta1",
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
        check_type("spec", spec, Optional["HorizontalPodAutoscalerSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["HorizontalPodAutoscalerSpec"]:
        """
        spec is the specification for the behaviour of the autoscaler.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        """
        return self.__spec
