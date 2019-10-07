# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional, Union

from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery import runtime
from k8s.apimachinery.meta import v1 as metav1
from kargo import types
from typeguard import typechecked


DaemonSetUpdateStrategyType = base.Enum('DaemonSetUpdateStrategyType', {
    # Replace the old daemons only when it's killed
    'OnDelete': 'OnDelete',
    # Replace the old daemons by new ones using rolling update i.e replace them on each node one after the other.
    'RollingUpdate': 'RollingUpdate',
})


DeploymentStrategyType = base.Enum('DeploymentStrategyType', {
    # Kill all existing pods before creating new ones.
    'Recreate': 'Recreate',
    # Replace the old ReplicaSets by new one using rolling update i.e gradually scale down the old ReplicaSets and scale up the new one.
    'RollingUpdate': 'RollingUpdate',
})


# PodManagementPolicyType defines the policy for creating pods under a stateful set.
PodManagementPolicyType = base.Enum('PodManagementPolicyType', {
    # OrderedReady will create pods in strictly increasing order on
    # scale up and strictly decreasing order on scale down, progressing only when
    # the previous pod is ready or terminated. At most one pod will be changed
    # at any time.
    'OrderedReady': 'OrderedReady',
    # Parallel will create and delete pods as soon as the stateful set
    # replica count is changed, and will not wait for pods to be ready or complete
    # termination.
    'Parallel': 'Parallel',
})


# StatefulSetUpdateStrategyType is a string enumeration type that enumerates
# all possible update strategies for the StatefulSet controller.
StatefulSetUpdateStrategyType = base.Enum('StatefulSetUpdateStrategyType', {
    # OnDelete triggers the legacy behavior. Version
    # tracking and ordered rolling restarts are disabled. Pods are recreated
    # from the StatefulSetSpec when they are manually deleted. When a scale
    # operation is performed with this strategy,specification version indicated
    # by the StatefulSet's currentRevision.
    'OnDelete': 'OnDelete',
    # RollingUpdate indicates that update will be
    # applied to all Pods in the StatefulSet with respect to the StatefulSet
    # ordering constraints. When a scale operation is performed with this
    # strategy, new Pods will be created from the specification version indicated
    # by the StatefulSet's updateRevision.
    'RollingUpdate': 'RollingUpdate',
})


# DEPRECATED - This group version of ControllerRevision is deprecated by apps/v1/ControllerRevision. See the
# release notes for more information.
# ControllerRevision implements an immutable snapshot of state data. Clients
# are responsible for serializing and deserializing the objects that contain
# their internal state.
# Once a ControllerRevision has been successfully created, it can not be updated.
# The API Server will fail validation of all requests that attempt to mutate
# the Data field. ControllerRevisions may, however, be deleted. Note that, due to its use by both
# the DaemonSet and StatefulSet controllers for update and rollback, this object is beta. However,
# it may be subject to name and representation changes in future releases, and clients should not
# depend on its stability. It is primarily for internal use by controllers.
class ControllerRevision(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['data'] = self.data()
        v['revision'] = self.revision()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'apps/v1beta2'
    
    @typechecked
    def kind(self) -> str:
        return 'ControllerRevision'
    
    # Data is the serialized representation of the state.
    @typechecked
    def data(self) -> 'runtime.RawExtension':
        return self._get('data', runtime.RawExtension())
    
    # Revision indicates the revision of the state represented by Data.
    @typechecked
    def revision(self) -> int:
        return self._get('revision', 0)


# Spec to control the desired behavior of daemon set rolling update.
class RollingUpdateDaemonSet(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        maxUnavailable = self.maxUnavailable()
        if maxUnavailable is not None:  # omit empty
            v['maxUnavailable'] = maxUnavailable
        return v
    
    # The maximum number of DaemonSet pods that can be unavailable during the
    # update. Value can be an absolute number (ex: 5) or a percentage of total
    # number of DaemonSet pods at the start of the update (ex: 10%). Absolute
    # number is calculated from percentage by rounding up.
    # This cannot be 0.
    # Default value is 1.
    # Example: when this is set to 30%, at most 30% of the total number of nodes
    # that should be running the daemon pod (i.e. status.desiredNumberScheduled)
    # can have their pods stopped for an update at any given
    # time. The update starts by stopping at most 30% of those DaemonSet pods
    # and then brings up new DaemonSet pods in their place. Once the new pods
    # are available, it then proceeds onto other DaemonSet pods, thus ensuring
    # that at least 70% of original number of DaemonSet pods are available at
    # all times during the update.
    @typechecked
    def maxUnavailable(self) -> Optional[Union[int, str]]:
        return self._get('maxUnavailable', 1)


# DaemonSetUpdateStrategy is a struct used to control the update strategy for a DaemonSet.
class DaemonSetUpdateStrategy(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        type = self.type()
        if type:  # omit empty
            v['type'] = type
        rollingUpdate = self.rollingUpdate()
        if rollingUpdate is not None:  # omit empty
            v['rollingUpdate'] = rollingUpdate
        return v
    
    # Type of daemon set update. Can be "RollingUpdate" or "OnDelete". Default is RollingUpdate.
    @typechecked
    def type(self) -> Optional[DaemonSetUpdateStrategyType]:
        return self._get('type', DaemonSetUpdateStrategyType['RollingUpdate'])
    
    # Rolling update config params. Present only if type = "RollingUpdate".
    # ---
    # TODO: Update this to follow our convention for oneOf, whatever we decide it
    # to be. Same as Deployment `strategy.rollingUpdate`.
    # See https://github.com/kubernetes/kubernetes/issues/35345
    @typechecked
    def rollingUpdate(self) -> Optional[RollingUpdateDaemonSet]:
        return self._get('rollingUpdate', RollingUpdateDaemonSet())


# DaemonSetSpec is the specification of a daemon set.
class DaemonSetSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['selector'] = self.selector()
        v['template'] = self.template()
        v['updateStrategy'] = self.updateStrategy()
        minReadySeconds = self.minReadySeconds()
        if minReadySeconds:  # omit empty
            v['minReadySeconds'] = minReadySeconds
        revisionHistoryLimit = self.revisionHistoryLimit()
        if revisionHistoryLimit is not None:  # omit empty
            v['revisionHistoryLimit'] = revisionHistoryLimit
        return v
    
    # A label query over pods that are managed by the daemon set.
    # Must match in order to be controlled.
    # It must match the pod template's labels.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        return self._get('selector')
    
    # An object that describes the pod that will be created.
    # The DaemonSet will create exactly one copy of this pod on every node
    # that matches the template's node selector (or on every node if no node
    # selector is specified).
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#pod-template
    @typechecked
    def template(self) -> 'corev1.PodTemplateSpec':
        return self._get('template', corev1.PodTemplateSpec())
    
    # An update strategy to replace existing DaemonSet pods with new pods.
    @typechecked
    def updateStrategy(self) -> DaemonSetUpdateStrategy:
        return self._get('updateStrategy', DaemonSetUpdateStrategy())
    
    # The minimum number of seconds for which a newly created DaemonSet pod should
    # be ready without any of its container crashing, for it to be considered
    # available. Defaults to 0 (pod will be considered available as soon as it
    # is ready).
    @typechecked
    def minReadySeconds(self) -> Optional[int]:
        return self._get('minReadySeconds')
    
    # The number of old history to retain to allow rollback.
    # This is a pointer to distinguish between explicit zero and not specified.
    # Defaults to 10.
    @typechecked
    def revisionHistoryLimit(self) -> Optional[int]:
        return self._get('revisionHistoryLimit', 10)


# DEPRECATED - This group version of DaemonSet is deprecated by apps/v1/DaemonSet. See the release notes for
# more information.
# DaemonSet represents the configuration of a daemon set.
class DaemonSet(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'apps/v1beta2'
    
    @typechecked
    def kind(self) -> str:
        return 'DaemonSet'
    
    # The desired behavior of this daemon set.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> DaemonSetSpec:
        return self._get('spec', DaemonSetSpec())


# Spec to control the desired behavior of rolling update.
class RollingUpdateDeployment(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        maxUnavailable = self.maxUnavailable()
        if maxUnavailable is not None:  # omit empty
            v['maxUnavailable'] = maxUnavailable
        maxSurge = self.maxSurge()
        if maxSurge is not None:  # omit empty
            v['maxSurge'] = maxSurge
        return v
    
    # The maximum number of pods that can be unavailable during the update.
    # Value can be an absolute number (ex: 5) or a percentage of desired pods (ex: 10%).
    # Absolute number is calculated from percentage by rounding down.
    # This can not be 0 if MaxSurge is 0.
    # Defaults to 25%.
    # Example: when this is set to 30%, the old ReplicaSet can be scaled down to 70% of desired pods
    # immediately when the rolling update starts. Once new pods are ready, old ReplicaSet
    # can be scaled down further, followed by scaling up the new ReplicaSet, ensuring
    # that the total number of pods available at all times during the update is at
    # least 70% of desired pods.
    @typechecked
    def maxUnavailable(self) -> Optional[Union[int, str]]:
        return self._get('maxUnavailable', '25%')
    
    # The maximum number of pods that can be scheduled above the desired number of
    # pods.
    # Value can be an absolute number (ex: 5) or a percentage of desired pods (ex: 10%).
    # This can not be 0 if MaxUnavailable is 0.
    # Absolute number is calculated from percentage by rounding up.
    # Defaults to 25%.
    # Example: when this is set to 30%, the new ReplicaSet can be scaled up immediately when
    # the rolling update starts, such that the total number of old and new pods do not exceed
    # 130% of desired pods. Once old pods have been killed,
    # new ReplicaSet can be scaled up further, ensuring that total number of pods running
    # at any time during the update is at most 130% of desired pods.
    @typechecked
    def maxSurge(self) -> Optional[Union[int, str]]:
        return self._get('maxSurge', '25%')


# DeploymentStrategy describes how to replace existing pods with new ones.
class DeploymentStrategy(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        type = self.type()
        if type:  # omit empty
            v['type'] = type
        rollingUpdate = self.rollingUpdate()
        if rollingUpdate is not None:  # omit empty
            v['rollingUpdate'] = rollingUpdate
        return v
    
    # Type of deployment. Can be "Recreate" or "RollingUpdate". Default is RollingUpdate.
    @typechecked
    def type(self) -> Optional[DeploymentStrategyType]:
        return self._get('type', DeploymentStrategyType['RollingUpdate'])
    
    # Rolling update config params. Present only if DeploymentStrategyType =
    # RollingUpdate.
    # ---
    # TODO: Update this to follow our convention for oneOf, whatever we decide it
    # to be.
    @typechecked
    def rollingUpdate(self) -> Optional[RollingUpdateDeployment]:
        return self._get('rollingUpdate', RollingUpdateDeployment())


# DeploymentSpec is the specification of the desired behavior of the Deployment.
class DeploymentSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        replicas = self.replicas()
        if replicas is not None:  # omit empty
            v['replicas'] = replicas
        v['selector'] = self.selector()
        v['template'] = self.template()
        v['strategy'] = self.strategy()
        minReadySeconds = self.minReadySeconds()
        if minReadySeconds:  # omit empty
            v['minReadySeconds'] = minReadySeconds
        revisionHistoryLimit = self.revisionHistoryLimit()
        if revisionHistoryLimit is not None:  # omit empty
            v['revisionHistoryLimit'] = revisionHistoryLimit
        paused = self.paused()
        if paused:  # omit empty
            v['paused'] = paused
        progressDeadlineSeconds = self.progressDeadlineSeconds()
        if progressDeadlineSeconds is not None:  # omit empty
            v['progressDeadlineSeconds'] = progressDeadlineSeconds
        return v
    
    # Number of desired pods. This is a pointer to distinguish between explicit
    # zero and not specified. Defaults to 1.
    @typechecked
    def replicas(self) -> Optional[int]:
        return self._get('replicas', 1)
    
    # Label selector for pods. Existing ReplicaSets whose pods are
    # selected by this will be the ones affected by this deployment.
    # It must match the pod template's labels.
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        return self._get('selector')
    
    # Template describes the pods that will be created.
    @typechecked
    def template(self) -> 'corev1.PodTemplateSpec':
        return self._get('template', corev1.PodTemplateSpec())
    
    # The deployment strategy to use to replace existing pods with new ones.
    @typechecked
    def strategy(self) -> DeploymentStrategy:
        return self._get('strategy', DeploymentStrategy())
    
    # Minimum number of seconds for which a newly created pod should be ready
    # without any of its container crashing, for it to be considered available.
    # Defaults to 0 (pod will be considered available as soon as it is ready)
    @typechecked
    def minReadySeconds(self) -> Optional[int]:
        return self._get('minReadySeconds')
    
    # The number of old ReplicaSets to retain to allow rollback.
    # This is a pointer to distinguish between explicit zero and not specified.
    # Defaults to 10.
    @typechecked
    def revisionHistoryLimit(self) -> Optional[int]:
        return self._get('revisionHistoryLimit', 10)
    
    # Indicates that the deployment is paused.
    @typechecked
    def paused(self) -> Optional[bool]:
        return self._get('paused')
    
    # The maximum time in seconds for a deployment to make progress before it
    # is considered to be failed. The deployment controller will continue to
    # process failed deployments and a condition with a ProgressDeadlineExceeded
    # reason will be surfaced in the deployment status. Note that progress will
    # not be estimated during the time a deployment is paused. Defaults to 600s.
    @typechecked
    def progressDeadlineSeconds(self) -> Optional[int]:
        return self._get('progressDeadlineSeconds', 600)


# DEPRECATED - This group version of Deployment is deprecated by apps/v1/Deployment. See the release notes for
# more information.
# Deployment enables declarative updates for Pods and ReplicaSets.
class Deployment(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'apps/v1beta2'
    
    @typechecked
    def kind(self) -> str:
        return 'Deployment'
    
    # Specification of the desired behavior of the Deployment.
    @typechecked
    def spec(self) -> DeploymentSpec:
        return self._get('spec', DeploymentSpec())


# ReplicaSetSpec is the specification of a ReplicaSet.
class ReplicaSetSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        replicas = self.replicas()
        if replicas is not None:  # omit empty
            v['replicas'] = replicas
        minReadySeconds = self.minReadySeconds()
        if minReadySeconds:  # omit empty
            v['minReadySeconds'] = minReadySeconds
        v['selector'] = self.selector()
        v['template'] = self.template()
        return v
    
    # Replicas is the number of desired replicas.
    # This is a pointer to distinguish between explicit zero and unspecified.
    # Defaults to 1.
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller/#what-is-a-replicationcontroller
    @typechecked
    def replicas(self) -> Optional[int]:
        return self._get('replicas', 1)
    
    # Minimum number of seconds for which a newly created pod should be ready
    # without any of its container crashing, for it to be considered available.
    # Defaults to 0 (pod will be considered available as soon as it is ready)
    @typechecked
    def minReadySeconds(self) -> Optional[int]:
        return self._get('minReadySeconds')
    
    # Selector is a label query over pods that should match the replica count.
    # Label keys and values that must match in order to be controlled by this replica set.
    # It must match the pod template's labels.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        return self._get('selector')
    
    # Template is the object that describes the pod that will be created if
    # insufficient replicas are detected.
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#pod-template
    @typechecked
    def template(self) -> 'corev1.PodTemplateSpec':
        return self._get('template', corev1.PodTemplateSpec())


# DEPRECATED - This group version of ReplicaSet is deprecated by apps/v1/ReplicaSet. See the release notes for
# more information.
# ReplicaSet ensures that a specified number of pod replicas are running at any given time.
class ReplicaSet(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'apps/v1beta2'
    
    @typechecked
    def kind(self) -> str:
        return 'ReplicaSet'
    
    # Spec defines the specification of the desired behavior of the ReplicaSet.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> ReplicaSetSpec:
        return self._get('spec', ReplicaSetSpec())


# RollingUpdateStatefulSetStrategy is used to communicate parameter for RollingUpdateStatefulSetStrategyType.
class RollingUpdateStatefulSetStrategy(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        partition = self.partition()
        if partition is not None:  # omit empty
            v['partition'] = partition
        return v
    
    # Partition indicates the ordinal at which the StatefulSet should be
    # partitioned.
    # Default value is 0.
    @typechecked
    def partition(self) -> Optional[int]:
        return self._get('partition')


# ScaleSpec describes the attributes of a scale subresource
class ScaleSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        replicas = self.replicas()
        if replicas:  # omit empty
            v['replicas'] = replicas
        return v
    
    # desired number of instances for the scaled object.
    @typechecked
    def replicas(self) -> Optional[int]:
        return self._get('replicas')


# Scale represents a scaling request for a resource.
class Scale(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'apps/v1beta2'
    
    @typechecked
    def kind(self) -> str:
        return 'Scale'
    
    # defines the behavior of the scale. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
    @typechecked
    def spec(self) -> ScaleSpec:
        return self._get('spec', ScaleSpec())


# StatefulSetUpdateStrategy indicates the strategy that the StatefulSet
# controller will use to perform updates. It includes any additional parameters
# necessary to perform the update for the indicated strategy.
class StatefulSetUpdateStrategy(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        type = self.type()
        if type:  # omit empty
            v['type'] = type
        rollingUpdate = self.rollingUpdate()
        if rollingUpdate is not None:  # omit empty
            v['rollingUpdate'] = rollingUpdate
        return v
    
    # Type indicates the type of the StatefulSetUpdateStrategy.
    # Default is RollingUpdate.
    @typechecked
    def type(self) -> Optional[StatefulSetUpdateStrategyType]:
        return self._get('type', StatefulSetUpdateStrategyType['RollingUpdate'])
    
    # RollingUpdate is used to communicate parameters when Type is RollingUpdateStatefulSetStrategyType.
    @typechecked
    def rollingUpdate(self) -> Optional[RollingUpdateStatefulSetStrategy]:
        return self._get('rollingUpdate', RollingUpdateStatefulSetStrategy())


# A StatefulSetSpec is the specification of a StatefulSet.
class StatefulSetSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        replicas = self.replicas()
        if replicas is not None:  # omit empty
            v['replicas'] = replicas
        v['selector'] = self.selector()
        v['template'] = self.template()
        volumeClaimTemplates = self.volumeClaimTemplates()
        if volumeClaimTemplates:  # omit empty
            v['volumeClaimTemplates'] = volumeClaimTemplates
        v['serviceName'] = self.serviceName()
        podManagementPolicy = self.podManagementPolicy()
        if podManagementPolicy:  # omit empty
            v['podManagementPolicy'] = podManagementPolicy
        v['updateStrategy'] = self.updateStrategy()
        revisionHistoryLimit = self.revisionHistoryLimit()
        if revisionHistoryLimit is not None:  # omit empty
            v['revisionHistoryLimit'] = revisionHistoryLimit
        return v
    
    # replicas is the desired number of replicas of the given Template.
    # These are replicas in the sense that they are instantiations of the
    # same Template, but individual replicas also have a consistent identity.
    # If unspecified, defaults to 1.
    # TODO: Consider a rename of this field.
    @typechecked
    def replicas(self) -> Optional[int]:
        return self._get('replicas', 1)
    
    # selector is a label query over pods that should match the replica count.
    # It must match the pod template's labels.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        return self._get('selector')
    
    # template is the object that describes the pod that will be created if
    # insufficient replicas are detected. Each pod stamped out by the StatefulSet
    # will fulfill this Template, but have a unique identity from the rest
    # of the StatefulSet.
    @typechecked
    def template(self) -> 'corev1.PodTemplateSpec':
        return self._get('template', corev1.PodTemplateSpec())
    
    # volumeClaimTemplates is a list of claims that pods are allowed to reference.
    # The StatefulSet controller is responsible for mapping network identities to
    # claims in a way that maintains the identity of a pod. Every claim in
    # this list must have at least one matching (by name) volumeMount in one
    # container in the template. A claim in this list takes precedence over
    # any volumes in the template, with the same name.
    # TODO: Define the behavior if a claim already exists with the same name.
    @typechecked
    def volumeClaimTemplates(self) -> List['corev1.PersistentVolumeClaim']:
        return self._get('volumeClaimTemplates', [])
    
    # serviceName is the name of the service that governs this StatefulSet.
    # This service must exist before the StatefulSet, and is responsible for
    # the network identity of the set. Pods get DNS/hostnames that follow the
    # pattern: pod-specific-string.serviceName.default.svc.cluster.local
    # where "pod-specific-string" is managed by the StatefulSet controller.
    @typechecked
    def serviceName(self) -> str:
        return self._get('serviceName', '')
    
    # podManagementPolicy controls how pods are created during initial scale up,
    # when replacing pods on nodes, or when scaling down. The default policy is
    # `OrderedReady`, where pods are created in increasing order (pod-0, then
    # pod-1, etc) and the controller will wait until each pod is ready before
    # continuing. When scaling down, the pods are removed in the opposite order.
    # The alternative policy is `Parallel` which will create pods in parallel
    # to match the desired scale without waiting, and on scale down will delete
    # all pods at once.
    @typechecked
    def podManagementPolicy(self) -> Optional[PodManagementPolicyType]:
        return self._get('podManagementPolicy', PodManagementPolicyType['OrderedReady'])
    
    # updateStrategy indicates the StatefulSetUpdateStrategy that will be
    # employed to update Pods in the StatefulSet when a revision is made to
    # Template.
    @typechecked
    def updateStrategy(self) -> StatefulSetUpdateStrategy:
        return self._get('updateStrategy', StatefulSetUpdateStrategy())
    
    # revisionHistoryLimit is the maximum number of revisions that will
    # be maintained in the StatefulSet's revision history. The revision history
    # consists of all revisions not represented by a currently applied
    # StatefulSetSpec version. The default value is 10.
    @typechecked
    def revisionHistoryLimit(self) -> Optional[int]:
        return self._get('revisionHistoryLimit', 10)


# DEPRECATED - This group version of StatefulSet is deprecated by apps/v1/StatefulSet. See the release notes for
# more information.
# StatefulSet represents a set of pods with consistent identities.
# Identities are defined as:
#  - Network: A single stable DNS and hostname.
#  - Storage: As many VolumeClaims as requested.
# The StatefulSet guarantees that a given network identity will always
# map to the same storage identity.
class StatefulSet(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'apps/v1beta2'
    
    @typechecked
    def kind(self) -> str:
        return 'StatefulSet'
    
    # Spec defines the desired identities of pods in this set.
    @typechecked
    def spec(self) -> StatefulSetSpec:
        return self._get('spec', StatefulSetSpec())
