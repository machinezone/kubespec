# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import List, Optional

import addict
from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery import resource
from k8s.apimachinery.meta import v1 as metav1
from kargo import types
from typeguard import typechecked


# MetricSourceType indicates the type of metric.
MetricSourceType = base.Enum('MetricSourceType', {
    # External is a global metric that is not associated
    # with any Kubernetes object. It allows autoscaling based on information
    # coming from components running outside of cluster
    # (for example length of queue in cloud messaging service, or
    # QPS from loadbalancer running outside of cluster).
    'External': 'External',
    # Object is a metric describing a kubernetes object
    # (for example, hits-per-second on an Ingress object).
    'Object': 'Object',
    # Pods is a metric describing each pod in the current scale
    # target (for example, transactions-processed-per-second).  The values
    # will be averaged together before being compared to the target value.
    'Pods': 'Pods',
    # Resource is a resource metric known to Kubernetes, as
    # specified in requests and limits, describing each pod in the current
    # scale target (e.g. CPU or memory).  Such metrics are built in to
    # Kubernetes, and have special scaling options on top of those available
    # to normal per-pod metrics (the "pods" source).
    'Resource': 'Resource',
})


# CrossVersionObjectReference contains enough information to let you identify the referred resource.
class CrossVersionObjectReference(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['kind'] = self.kind()
        v['name'] = self.name()
        apiVersion = self.apiVersion()
        if apiVersion:  # omit empty
            v['apiVersion'] = apiVersion
        return v
    
    # Kind of the referent; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"
    @typechecked
    def kind(self) -> str:
        return self._kwargs.get('kind', '')
    
    # Name of the referent; More info: http://kubernetes.io/docs/user-guide/identifiers#names
    @typechecked
    def name(self) -> str:
        return self._kwargs.get('name', '')
    
    # API version of the referent
    @typechecked
    def apiVersion(self) -> Optional[str]:
        return self._kwargs.get('apiVersion')


# ExternalMetricSource indicates how to scale on a metric not associated with
# any Kubernetes object (for example length of queue in cloud
# messaging service, or QPS from loadbalancer running outside of cluster).
# Exactly one "target" type should be set.
class ExternalMetricSource(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['metricName'] = self.metricName()
        metricSelector = self.metricSelector()
        if metricSelector is not None:  # omit empty
            v['metricSelector'] = metricSelector
        targetValue = self.targetValue()
        if targetValue is not None:  # omit empty
            v['targetValue'] = targetValue
        targetAverageValue = self.targetAverageValue()
        if targetAverageValue is not None:  # omit empty
            v['targetAverageValue'] = targetAverageValue
        return v
    
    # metricName is the name of the metric in question.
    @typechecked
    def metricName(self) -> str:
        return self._kwargs.get('metricName', '')
    
    # metricSelector is used to identify a specific time series
    # within a given metric.
    @typechecked
    def metricSelector(self) -> Optional['metav1.LabelSelector']:
        return self._kwargs.get('metricSelector')
    
    # targetValue is the target value of the metric (as a quantity).
    # Mutually exclusive with TargetAverageValue.
    @typechecked
    def targetValue(self) -> Optional['resource.Quantity']:
        return self._kwargs.get('targetValue')
    
    # targetAverageValue is the target per-pod value of global metric (as a quantity).
    # Mutually exclusive with TargetValue.
    @typechecked
    def targetAverageValue(self) -> Optional['resource.Quantity']:
        return self._kwargs.get('targetAverageValue')


# ObjectMetricSource indicates how to scale on a metric describing a
# kubernetes object (for example, hits-per-second on an Ingress object).
class ObjectMetricSource(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['target'] = self.target()
        v['metricName'] = self.metricName()
        v['targetValue'] = self.targetValue()
        selector = self.selector()
        if selector is not None:  # omit empty
            v['selector'] = selector
        averageValue = self.averageValue()
        if averageValue is not None:  # omit empty
            v['averageValue'] = averageValue
        return v
    
    # target is the described Kubernetes object.
    @typechecked
    def target(self) -> CrossVersionObjectReference:
        return self._kwargs.get('target', CrossVersionObjectReference())
    
    # metricName is the name of the metric in question.
    @typechecked
    def metricName(self) -> str:
        return self._kwargs.get('metricName', '')
    
    # targetValue is the target value of the metric (as a quantity).
    @typechecked
    def targetValue(self) -> 'resource.Quantity':
        return self._kwargs.get('targetValue', resource.Quantity())
    
    # selector is the string-encoded form of a standard kubernetes label selector for the given metric
    # When set, it is passed as an additional parameter to the metrics server for more specific metrics scoping
    # When unset, just the metricName will be used to gather metrics.
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        return self._kwargs.get('selector')
    
    # averageValue is the target value of the average of the
    # metric across all relevant pods (as a quantity)
    @typechecked
    def averageValue(self) -> Optional['resource.Quantity']:
        return self._kwargs.get('averageValue')


# PodsMetricSource indicates how to scale on a metric describing each pod in
# the current scale target (for example, transactions-processed-per-second).
# The values will be averaged together before being compared to the target
# value.
class PodsMetricSource(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['metricName'] = self.metricName()
        v['targetAverageValue'] = self.targetAverageValue()
        selector = self.selector()
        if selector is not None:  # omit empty
            v['selector'] = selector
        return v
    
    # metricName is the name of the metric in question
    @typechecked
    def metricName(self) -> str:
        return self._kwargs.get('metricName', '')
    
    # targetAverageValue is the target value of the average of the
    # metric across all relevant pods (as a quantity)
    @typechecked
    def targetAverageValue(self) -> 'resource.Quantity':
        return self._kwargs.get('targetAverageValue', resource.Quantity())
    
    # selector is the string-encoded form of a standard kubernetes label selector for the given metric
    # When set, it is passed as an additional parameter to the metrics server for more specific metrics scoping
    # When unset, just the metricName will be used to gather metrics.
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        return self._kwargs.get('selector')


# ResourceMetricSource indicates how to scale on a resource metric known to
# Kubernetes, as specified in requests and limits, describing each pod in the
# current scale target (e.g. CPU or memory).  The values will be averaged
# together before being compared to the target.  Such metrics are built in to
# Kubernetes, and have special scaling options on top of those available to
# normal per-pod metrics using the "pods" source.  Only one "target" type
# should be set.
class ResourceMetricSource(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['name'] = self.name()
        targetAverageUtilization = self.targetAverageUtilization()
        if targetAverageUtilization is not None:  # omit empty
            v['targetAverageUtilization'] = targetAverageUtilization
        targetAverageValue = self.targetAverageValue()
        if targetAverageValue is not None:  # omit empty
            v['targetAverageValue'] = targetAverageValue
        return v
    
    # name is the name of the resource in question.
    @typechecked
    def name(self) -> corev1.ResourceName:
        return self._kwargs.get('name')
    
    # targetAverageUtilization is the target value of the average of the
    # resource metric across all relevant pods, represented as a percentage of
    # the requested value of the resource for the pods.
    @typechecked
    def targetAverageUtilization(self) -> Optional[int]:
        return self._kwargs.get('targetAverageUtilization')
    
    # targetAverageValue is the target value of the average of the
    # resource metric across all relevant pods, as a raw value (instead of as
    # a percentage of the request), similar to the "pods" metric source type.
    @typechecked
    def targetAverageValue(self) -> Optional['resource.Quantity']:
        return self._kwargs.get('targetAverageValue')


# MetricSpec specifies how to scale based on a single metric
# (only `type` and one other matching field should be set at once).
class MetricSpec(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['type'] = self.type()
        object = self.object()
        if object is not None:  # omit empty
            v['object'] = object
        pods = self.pods()
        if pods is not None:  # omit empty
            v['pods'] = pods
        resource = self.resource()
        if resource is not None:  # omit empty
            v['resource'] = resource
        external = self.external()
        if external is not None:  # omit empty
            v['external'] = external
        return v
    
    # type is the type of metric source.  It should be one of "Object",
    # "Pods" or "Resource", each mapping to a matching field in the object.
    @typechecked
    def type(self) -> MetricSourceType:
        return self._kwargs.get('type')
    
    # object refers to a metric describing a single kubernetes object
    # (for example, hits-per-second on an Ingress object).
    @typechecked
    def object(self) -> Optional[ObjectMetricSource]:
        return self._kwargs.get('object')
    
    # pods refers to a metric describing each pod in the current scale target
    # (for example, transactions-processed-per-second).  The values will be
    # averaged together before being compared to the target value.
    @typechecked
    def pods(self) -> Optional[PodsMetricSource]:
        return self._kwargs.get('pods')
    
    # resource refers to a resource metric (such as those specified in
    # requests and limits) known to Kubernetes describing each pod in the
    # current scale target (e.g. CPU or memory). Such metrics are built in to
    # Kubernetes, and have special scaling options on top of those available
    # to normal per-pod metrics using the "pods" source.
    @typechecked
    def resource(self) -> Optional[ResourceMetricSource]:
        return self._kwargs.get('resource')
    
    # external refers to a global metric that is not associated
    # with any Kubernetes object. It allows autoscaling based on information
    # coming from components running outside of cluster
    # (for example length of queue in cloud messaging service, or
    # QPS from loadbalancer running outside of cluster).
    @typechecked
    def external(self) -> Optional[ExternalMetricSource]:
        return self._kwargs.get('external')


# HorizontalPodAutoscalerSpec describes the desired functionality of the HorizontalPodAutoscaler.
class HorizontalPodAutoscalerSpec(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['scaleTargetRef'] = self.scaleTargetRef()
        minReplicas = self.minReplicas()
        if minReplicas is not None:  # omit empty
            v['minReplicas'] = minReplicas
        v['maxReplicas'] = self.maxReplicas()
        metrics = self.metrics()
        if metrics:  # omit empty
            v['metrics'] = metrics
        return v
    
    # scaleTargetRef points to the target resource to scale, and is used to the pods for which metrics
    # should be collected, as well as to actually change the replica count.
    @typechecked
    def scaleTargetRef(self) -> CrossVersionObjectReference:
        return self._kwargs.get('scaleTargetRef', CrossVersionObjectReference())
    
    # minReplicas is the lower limit for the number of replicas to which the autoscaler
    # can scale down.  It defaults to 1 pod.  minReplicas is allowed to be 0 if the
    # alpha feature gate HPAScaleToZero is enabled and at least one Object or External
    # metric is configured.  Scaling is active as long as at least one metric value is
    # available.
    @typechecked
    def minReplicas(self) -> Optional[int]:
        return self._kwargs.get('minReplicas', 1)
    
    # maxReplicas is the upper limit for the number of replicas to which the autoscaler can scale up.
    # It cannot be less that minReplicas.
    @typechecked
    def maxReplicas(self) -> int:
        return self._kwargs.get('maxReplicas', 0)
    
    # metrics contains the specifications for which to use to calculate the
    # desired replica count (the maximum replica count across all metrics will
    # be used).  The desired replica count is calculated multiplying the
    # ratio between the target value and the current value by the current
    # number of pods.  Ergo, metrics used must decrease as the pod count is
    # increased, and vice-versa.  See the individual metric source types for
    # more information about how each type of metric must respond.
    @typechecked
    def metrics(self) -> List[MetricSpec]:
        return self._kwargs.get('metrics', [])


# HorizontalPodAutoscaler is the configuration for a horizontal pod
# autoscaler, which automatically manages the replica count of any resource
# implementing the scale subresource based on the metrics specified.
class HorizontalPodAutoscaler(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        spec = self.spec()
        if spec:  # omit empty
            v['spec'] = spec
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'autoscaling/v2beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'HorizontalPodAutoscaler'
    
    # spec is the specification for the behaviour of the autoscaler.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
    @typechecked
    def spec(self) -> Optional[HorizontalPodAutoscalerSpec]:
        return self._kwargs.get('spec', HorizontalPodAutoscalerSpec())
