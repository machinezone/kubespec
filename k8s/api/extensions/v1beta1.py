# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional, Union

from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


DaemonSetUpdateStrategyType = base.Enum('DaemonSetUpdateStrategyType', {
    # Replace the old daemons only when it's killed
    'OnDelete': 'OnDelete',
    # Replace the old daemons by new ones using rolling update i.e replace them on each node one after the other.
    'RollingUpdate': 'RollingUpdate',
})


DeploymentStrategyType = base.Enum('DeploymentStrategyType', {
    # Kill all existing pods before creating new ones.
    'Recreate': 'Recreate',
    # Replace the old RCs by new one using rolling update i.e gradually scale down the old RCs and scale up the new one.
    'RollingUpdate': 'RollingUpdate',
})


# FSGroupStrategyType denotes strategy types for generating FSGroup values for a
# SecurityContext
# Deprecated: use FSGroupStrategyType from policy API Group instead.
FSGroupStrategyType = base.Enum('FSGroupStrategyType', {
    # MustRunAs meant that container must have FSGroup of X applied.
    # Deprecated: use MustRunAs from policy API Group instead.
    'MustRunAs': 'MustRunAs',
    # RunAsAny means that container may make requests for any FSGroup labels.
    # Deprecated: use RunAsAny from policy API Group instead.
    'RunAsAny': 'RunAsAny',
})


# FSType gives strong typing to different file systems that are used by volumes.
# Deprecated: use FSType from policy API Group instead.
FSType = base.Enum('FSType', {
    'AWSElasticBlockStore': 'awsElasticBlockStore',
    'All': '*',
    'AzureDisk': 'azureDisk',
    'AzureFile': 'azureFile',
    'CSI': 'csi',
    'CephFS': 'cephFS',
    'Cinder': 'cinder',
    'ConfigMap': 'configMap',
    'DownwardAPI': 'downwardAPI',
    'EmptyDir': 'emptyDir',
    'FC': 'fc',
    'FlexVolume': 'flexVolume',
    'Flocker': 'flocker',
    'GCEPersistentDisk': 'gcePersistentDisk',
    'GitRepo': 'gitRepo',
    'Glusterfs': 'glusterfs',
    'HostPath': 'hostPath',
    'ISCSI': 'iscsi',
    'NFS': 'nfs',
    'PersistentVolumeClaim': 'persistentVolumeClaim',
    'Quobyte': 'quobyte',
    'RBD': 'rbd',
    'Secret': 'secret',
})


# DEPRECATED 1.9 - This group version of PolicyType is deprecated by networking/v1/PolicyType.
# Policy Type string describes the NetworkPolicy type
# This type is beta-level in 1.8
PolicyType = base.Enum('PolicyType', {
    # Egress is a NetworkPolicy that affects egress traffic on selected pods
    'Egress': 'Egress',
    # Ingress is a NetworkPolicy that affects ingress traffic on selected pods
    'Ingress': 'Ingress',
})


# RunAsGroupStrategy denotes strategy types for generating RunAsGroup values for a
# Security Context.
# Deprecated: use RunAsGroupStrategy from policy API Group instead.
RunAsGroupStrategy = base.Enum('RunAsGroupStrategy', {
    # MayRunAs means that container does not need to run with a particular gid.
    # However, when RunAsGroup are specified, they have to fall in the defined range.
    'MayRunAs': 'MayRunAs',
    # MustRunAs means that container must run as a particular gid.
    # Deprecated: use MustRunAs from policy API Group instead.
    'MustRunAs': 'MustRunAs',
    # RunAsAny means that container may make requests for any gid.
    # Deprecated: use RunAsAny from policy API Group instead.
    'RunAsAny': 'RunAsAny',
})


# RunAsUserStrategy denotes strategy types for generating RunAsUser values for a
# Security Context.
# Deprecated: use RunAsUserStrategy from policy API Group instead.
RunAsUserStrategy = base.Enum('RunAsUserStrategy', {
    # MustRunAs means that container must run as a particular uid.
    # Deprecated: use MustRunAs from policy API Group instead.
    'MustRunAs': 'MustRunAs',
    # MustRunAsNonRoot means that container must run as a non-root uid.
    # Deprecated: use MustRunAsNonRoot from policy API Group instead.
    'MustRunAsNonRoot': 'MustRunAsNonRoot',
    # RunAsAny means that container may make requests for any uid.
    # Deprecated: use RunAsAny from policy API Group instead.
    'RunAsAny': 'RunAsAny',
})


# SELinuxStrategy denotes strategy types for generating SELinux options for a
# Security Context.
# Deprecated: use SELinuxStrategy from policy API Group instead.
SELinuxStrategy = base.Enum('SELinuxStrategy', {
    # MustRunAs means that container must have SELinux labels of X applied.
    # Deprecated: use MustRunAs from policy API Group instead.
    'MustRunAs': 'MustRunAs',
    # RunAsAny means that container may make requests for any SELinux context labels.
    # Deprecated: use RunAsAny from policy API Group instead.
    'RunAsAny': 'RunAsAny',
})


# SupplementalGroupsStrategyType denotes strategy types for determining valid supplemental
# groups for a SecurityContext.
# Deprecated: use SupplementalGroupsStrategyType from policy API Group instead.
SupplementalGroupsStrategyType = base.Enum('SupplementalGroupsStrategyType', {
    # MustRunAs means that container must run as a particular gid.
    # Deprecated: use MustRunAs from policy API Group instead.
    'MustRunAs': 'MustRunAs',
    # RunAsAny means that container may make requests for any gid.
    # Deprecated: use RunAsAny from policy API Group instead.
    'RunAsAny': 'RunAsAny',
})


# AllowedCSIDriver represents a single inline CSI Driver that is allowed to be used.
class AllowedCSIDriver(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['name'] = self.name()
        return v
    
    # Name is the registered name of the CSI driver
    @typechecked
    def name(self) -> str:
        if 'name' in self._kwargs:
            return self._kwargs['name']
        if 'name' in self._context and check_return_type(self._context['name']):
            return self._context['name']
        return ''


# AllowedFlexVolume represents a single Flexvolume that is allowed to be used.
# Deprecated: use AllowedFlexVolume from policy API Group instead.
class AllowedFlexVolume(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['driver'] = self.driver()
        return v
    
    # driver is the name of the Flexvolume driver.
    @typechecked
    def driver(self) -> str:
        if 'driver' in self._kwargs:
            return self._kwargs['driver']
        if 'driver' in self._context and check_return_type(self._context['driver']):
            return self._context['driver']
        return ''


# AllowedHostPath defines the host volume conditions that will be enabled by a policy
# for pods to use. It requires the path prefix to be defined.
# Deprecated: use AllowedHostPath from policy API Group instead.
class AllowedHostPath(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        pathPrefix = self.pathPrefix()
        if pathPrefix:  # omit empty
            v['pathPrefix'] = pathPrefix
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v['readOnly'] = readOnly
        return v
    
    # pathPrefix is the path prefix that the host volume must match.
    # It does not support `*`.
    # Trailing slashes are trimmed when validating the path prefix with a host path.
    # 
    # Examples:
    # `/foo` would allow `/foo`, `/foo/` and `/foo/bar`
    # `/foo` would not allow `/food` or `/etc/foo`
    @typechecked
    def pathPrefix(self) -> Optional[str]:
        if 'pathPrefix' in self._kwargs:
            return self._kwargs['pathPrefix']
        if 'pathPrefix' in self._context and check_return_type(self._context['pathPrefix']):
            return self._context['pathPrefix']
        return None
    
    # when set to true, will allow host volumes matching the pathPrefix only if all volume mounts are readOnly.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        if 'readOnly' in self._kwargs:
            return self._kwargs['readOnly']
        if 'readOnly' in self._context and check_return_type(self._context['readOnly']):
            return self._context['readOnly']
        return None


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
        if 'maxUnavailable' in self._kwargs:
            return self._kwargs['maxUnavailable']
        if 'maxUnavailable' in self._context and check_return_type(self._context['maxUnavailable']):
            return self._context['maxUnavailable']
        return None


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
    
    # Type of daemon set update. Can be "RollingUpdate" or "OnDelete".
    # Default is OnDelete.
    @typechecked
    def type(self) -> Optional[DaemonSetUpdateStrategyType]:
        if 'type' in self._kwargs:
            return self._kwargs['type']
        if 'type' in self._context and check_return_type(self._context['type']):
            return self._context['type']
        return DaemonSetUpdateStrategyType['OnDelete']
    
    # Rolling update config params. Present only if type = "RollingUpdate".
    # ---
    # TODO: Update this to follow our convention for oneOf, whatever we decide it
    # to be. Same as Deployment `strategy.rollingUpdate`.
    # See https://github.com/kubernetes/kubernetes/issues/35345
    @typechecked
    def rollingUpdate(self) -> Optional[RollingUpdateDaemonSet]:
        if 'rollingUpdate' in self._kwargs:
            return self._kwargs['rollingUpdate']
        if 'rollingUpdate' in self._context and check_return_type(self._context['rollingUpdate']):
            return self._context['rollingUpdate']
        return None


# DaemonSetSpec is the specification of a daemon set.
class DaemonSetSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        selector = self.selector()
        if selector is not None:  # omit empty
            v['selector'] = selector
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
    # If empty, defaulted to labels on Pod template.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        if 'selector' in self._kwargs:
            return self._kwargs['selector']
        if 'selector' in self._context and check_return_type(self._context['selector']):
            return self._context['selector']
        return None
    
    # An object that describes the pod that will be created.
    # The DaemonSet will create exactly one copy of this pod on every node
    # that matches the template's node selector (or on every node if no node
    # selector is specified).
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#pod-template
    @typechecked
    def template(self) -> 'corev1.PodTemplateSpec':
        if 'template' in self._kwargs:
            return self._kwargs['template']
        if 'template' in self._context and check_return_type(self._context['template']):
            return self._context['template']
        with context.Scope(**self._context):
            return corev1.PodTemplateSpec()
    
    # An update strategy to replace existing DaemonSet pods with new pods.
    @typechecked
    def updateStrategy(self) -> DaemonSetUpdateStrategy:
        if 'updateStrategy' in self._kwargs:
            return self._kwargs['updateStrategy']
        if 'updateStrategy' in self._context and check_return_type(self._context['updateStrategy']):
            return self._context['updateStrategy']
        with context.Scope(**self._context):
            return DaemonSetUpdateStrategy()
    
    # The minimum number of seconds for which a newly created DaemonSet pod should
    # be ready without any of its container crashing, for it to be considered
    # available. Defaults to 0 (pod will be considered available as soon as it
    # is ready).
    @typechecked
    def minReadySeconds(self) -> Optional[int]:
        if 'minReadySeconds' in self._kwargs:
            return self._kwargs['minReadySeconds']
        if 'minReadySeconds' in self._context and check_return_type(self._context['minReadySeconds']):
            return self._context['minReadySeconds']
        return None
    
    # The number of old history to retain to allow rollback.
    # This is a pointer to distinguish between explicit zero and not specified.
    # Defaults to 10.
    @typechecked
    def revisionHistoryLimit(self) -> Optional[int]:
        if 'revisionHistoryLimit' in self._kwargs:
            return self._kwargs['revisionHistoryLimit']
        if 'revisionHistoryLimit' in self._context and check_return_type(self._context['revisionHistoryLimit']):
            return self._context['revisionHistoryLimit']
        return 10


# DEPRECATED - This group version of DaemonSet is deprecated by apps/v1beta2/DaemonSet. See the release notes for
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
        return 'extensions/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'DaemonSet'
    
    # The desired behavior of this daemon set.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> DaemonSetSpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return DaemonSetSpec()


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
    # By default, a fixed value of 1 is used.
    # Example: when this is set to 30%, the old RC can be scaled down to 70% of desired pods
    # immediately when the rolling update starts. Once new pods are ready, old RC
    # can be scaled down further, followed by scaling up the new RC, ensuring
    # that the total number of pods available at all times during the update is at
    # least 70% of desired pods.
    @typechecked
    def maxUnavailable(self) -> Optional[Union[int, str]]:
        if 'maxUnavailable' in self._kwargs:
            return self._kwargs['maxUnavailable']
        if 'maxUnavailable' in self._context and check_return_type(self._context['maxUnavailable']):
            return self._context['maxUnavailable']
        return 1
    
    # The maximum number of pods that can be scheduled above the desired number of
    # pods.
    # Value can be an absolute number (ex: 5) or a percentage of desired pods (ex: 10%).
    # This can not be 0 if MaxUnavailable is 0.
    # Absolute number is calculated from percentage by rounding up.
    # By default, a value of 1 is used.
    # Example: when this is set to 30%, the new RC can be scaled up immediately when
    # the rolling update starts, such that the total number of old and new pods do not exceed
    # 130% of desired pods. Once old pods have been killed,
    # new RC can be scaled up further, ensuring that total number of pods running
    # at any time during the update is at most 130% of desired pods.
    @typechecked
    def maxSurge(self) -> Optional[Union[int, str]]:
        if 'maxSurge' in self._kwargs:
            return self._kwargs['maxSurge']
        if 'maxSurge' in self._context and check_return_type(self._context['maxSurge']):
            return self._context['maxSurge']
        return 1


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
        if 'type' in self._kwargs:
            return self._kwargs['type']
        if 'type' in self._context and check_return_type(self._context['type']):
            return self._context['type']
        return DeploymentStrategyType['RollingUpdate']
    
    # Rolling update config params. Present only if DeploymentStrategyType =
    # RollingUpdate.
    # ---
    # TODO: Update this to follow our convention for oneOf, whatever we decide it
    # to be.
    @typechecked
    def rollingUpdate(self) -> Optional[RollingUpdateDeployment]:
        if 'rollingUpdate' in self._kwargs:
            return self._kwargs['rollingUpdate']
        if 'rollingUpdate' in self._context and check_return_type(self._context['rollingUpdate']):
            return self._context['rollingUpdate']
        with context.Scope(**self._context):
            return RollingUpdateDeployment()


# DeploymentSpec is the specification of the desired behavior of the Deployment.
class DeploymentSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        replicas = self.replicas()
        if replicas is not None:  # omit empty
            v['replicas'] = replicas
        selector = self.selector()
        if selector is not None:  # omit empty
            v['selector'] = selector
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
        if 'replicas' in self._kwargs:
            return self._kwargs['replicas']
        if 'replicas' in self._context and check_return_type(self._context['replicas']):
            return self._context['replicas']
        return 1
    
    # Label selector for pods. Existing ReplicaSets whose pods are
    # selected by this will be the ones affected by this deployment.
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        if 'selector' in self._kwargs:
            return self._kwargs['selector']
        if 'selector' in self._context and check_return_type(self._context['selector']):
            return self._context['selector']
        return None
    
    # Template describes the pods that will be created.
    @typechecked
    def template(self) -> 'corev1.PodTemplateSpec':
        if 'template' in self._kwargs:
            return self._kwargs['template']
        if 'template' in self._context and check_return_type(self._context['template']):
            return self._context['template']
        with context.Scope(**self._context):
            return corev1.PodTemplateSpec()
    
    # The deployment strategy to use to replace existing pods with new ones.
    @typechecked
    def strategy(self) -> DeploymentStrategy:
        if 'strategy' in self._kwargs:
            return self._kwargs['strategy']
        if 'strategy' in self._context and check_return_type(self._context['strategy']):
            return self._context['strategy']
        with context.Scope(**self._context):
            return DeploymentStrategy()
    
    # Minimum number of seconds for which a newly created pod should be ready
    # without any of its container crashing, for it to be considered available.
    # Defaults to 0 (pod will be considered available as soon as it is ready)
    @typechecked
    def minReadySeconds(self) -> Optional[int]:
        if 'minReadySeconds' in self._kwargs:
            return self._kwargs['minReadySeconds']
        if 'minReadySeconds' in self._context and check_return_type(self._context['minReadySeconds']):
            return self._context['minReadySeconds']
        return None
    
    # The number of old ReplicaSets to retain to allow rollback.
    # This is a pointer to distinguish between explicit zero and not specified.
    # This is set to the max value of int32 (i.e. 2147483647) by default, which
    # means "retaining all old RelicaSets".
    @typechecked
    def revisionHistoryLimit(self) -> Optional[int]:
        if 'revisionHistoryLimit' in self._kwargs:
            return self._kwargs['revisionHistoryLimit']
        if 'revisionHistoryLimit' in self._context and check_return_type(self._context['revisionHistoryLimit']):
            return self._context['revisionHistoryLimit']
        return 2147483647
    
    # Indicates that the deployment is paused and will not be processed by the
    # deployment controller.
    @typechecked
    def paused(self) -> Optional[bool]:
        if 'paused' in self._kwargs:
            return self._kwargs['paused']
        if 'paused' in self._context and check_return_type(self._context['paused']):
            return self._context['paused']
        return None
    
    # The maximum time in seconds for a deployment to make progress before it
    # is considered to be failed. The deployment controller will continue to
    # process failed deployments and a condition with a ProgressDeadlineExceeded
    # reason will be surfaced in the deployment status. Note that progress will
    # not be estimated during the time a deployment is paused. This is set to
    # the max value of int32 (i.e. 2147483647) by default, which means "no deadline".
    @typechecked
    def progressDeadlineSeconds(self) -> Optional[int]:
        if 'progressDeadlineSeconds' in self._kwargs:
            return self._kwargs['progressDeadlineSeconds']
        if 'progressDeadlineSeconds' in self._context and check_return_type(self._context['progressDeadlineSeconds']):
            return self._context['progressDeadlineSeconds']
        return 2147483647


# DEPRECATED - This group version of Deployment is deprecated by apps/v1beta2/Deployment. See the release notes for
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
        return 'extensions/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'Deployment'
    
    # Specification of the desired behavior of the Deployment.
    @typechecked
    def spec(self) -> DeploymentSpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return DeploymentSpec()


# DEPRECATED.
class RollbackConfig(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        revision = self.revision()
        if revision:  # omit empty
            v['revision'] = revision
        return v
    
    # The revision to rollback to. If set to 0, rollback to the last revision.
    @typechecked
    def revision(self) -> Optional[int]:
        if 'revision' in self._kwargs:
            return self._kwargs['revision']
        if 'revision' in self._context and check_return_type(self._context['revision']):
            return self._context['revision']
        return None


# DEPRECATED.
# DeploymentRollback stores the information required to rollback a deployment.
class DeploymentRollback(base.TypedObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['name'] = self.name()
        updatedAnnotations = self.updatedAnnotations()
        if updatedAnnotations:  # omit empty
            v['updatedAnnotations'] = updatedAnnotations
        v['rollbackTo'] = self.rollbackTo()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'extensions/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'DeploymentRollback'
    
    # Required: This must match the Name of a deployment.
    @typechecked
    def name(self) -> str:
        if 'name' in self._kwargs:
            return self._kwargs['name']
        if 'name' in self._context and check_return_type(self._context['name']):
            return self._context['name']
        return ''
    
    # The annotations to be updated to a deployment
    @typechecked
    def updatedAnnotations(self) -> Dict[str, str]:
        if 'updatedAnnotations' in self._kwargs:
            return self._kwargs['updatedAnnotations']
        if 'updatedAnnotations' in self._context and check_return_type(self._context['updatedAnnotations']):
            return self._context['updatedAnnotations']
        return {}
    
    # The config of this deployment rollback.
    @typechecked
    def rollbackTo(self) -> RollbackConfig:
        if 'rollbackTo' in self._kwargs:
            return self._kwargs['rollbackTo']
        if 'rollbackTo' in self._context and check_return_type(self._context['rollbackTo']):
            return self._context['rollbackTo']
        with context.Scope(**self._context):
            return RollbackConfig()


# IDRange provides a min/max of an allowed range of IDs.
# Deprecated: use IDRange from policy API Group instead.
class IDRange(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['min'] = self.min()
        v['max'] = self.max()
        return v
    
    # min is the start of the range, inclusive.
    @typechecked
    def min(self) -> int:
        if 'min' in self._kwargs:
            return self._kwargs['min']
        if 'min' in self._context and check_return_type(self._context['min']):
            return self._context['min']
        return 0
    
    # max is the end of the range, inclusive.
    @typechecked
    def max(self) -> int:
        if 'max' in self._kwargs:
            return self._kwargs['max']
        if 'max' in self._context and check_return_type(self._context['max']):
            return self._context['max']
        return 0


# FSGroupStrategyOptions defines the strategy type and options used to create the strategy.
# Deprecated: use FSGroupStrategyOptions from policy API Group instead.
class FSGroupStrategyOptions(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        rule = self.rule()
        if rule:  # omit empty
            v['rule'] = rule
        ranges = self.ranges()
        if ranges:  # omit empty
            v['ranges'] = ranges
        return v
    
    # rule is the strategy that will dictate what FSGroup is used in the SecurityContext.
    @typechecked
    def rule(self) -> Optional[FSGroupStrategyType]:
        if 'rule' in self._kwargs:
            return self._kwargs['rule']
        if 'rule' in self._context and check_return_type(self._context['rule']):
            return self._context['rule']
        return None
    
    # ranges are the allowed ranges of fs groups.  If you would like to force a single
    # fs group then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> List[IDRange]:
        if 'ranges' in self._kwargs:
            return self._kwargs['ranges']
        if 'ranges' in self._context and check_return_type(self._context['ranges']):
            return self._context['ranges']
        return []


# IngressBackend describes all endpoints for a given service and port.
class IngressBackend(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['serviceName'] = self.serviceName()
        v['servicePort'] = self.servicePort()
        return v
    
    # Specifies the name of the referenced service.
    @typechecked
    def serviceName(self) -> str:
        if 'serviceName' in self._kwargs:
            return self._kwargs['serviceName']
        if 'serviceName' in self._context and check_return_type(self._context['serviceName']):
            return self._context['serviceName']
        return ''
    
    # Specifies the port of the referenced service.
    @typechecked
    def servicePort(self) -> Union[int, str]:
        if 'servicePort' in self._kwargs:
            return self._kwargs['servicePort']
        if 'servicePort' in self._context and check_return_type(self._context['servicePort']):
            return self._context['servicePort']
        return 0


# HTTPIngressPath associates a path regex with a backend. Incoming urls matching
# the path are forwarded to the backend.
class HTTPIngressPath(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        path = self.path()
        if path:  # omit empty
            v['path'] = path
        v['backend'] = self.backend()
        return v
    
    # Path is an extended POSIX regex as defined by IEEE Std 1003.1,
    # (i.e this follows the egrep/unix syntax, not the perl syntax)
    # matched against the path of an incoming request. Currently it can
    # contain characters disallowed from the conventional "path"
    # part of a URL as defined by RFC 3986. Paths must begin with
    # a '/'. If unspecified, the path defaults to a catch all sending
    # traffic to the backend.
    @typechecked
    def path(self) -> Optional[str]:
        if 'path' in self._kwargs:
            return self._kwargs['path']
        if 'path' in self._context and check_return_type(self._context['path']):
            return self._context['path']
        return None
    
    # Backend defines the referenced service endpoint to which the traffic
    # will be forwarded to.
    @typechecked
    def backend(self) -> IngressBackend:
        if 'backend' in self._kwargs:
            return self._kwargs['backend']
        if 'backend' in self._context and check_return_type(self._context['backend']):
            return self._context['backend']
        with context.Scope(**self._context):
            return IngressBackend()


# HTTPIngressRuleValue is a list of http selectors pointing to backends.
# In the example: http://<host>/<path>?<searchpart> -> backend where
# where parts of the url correspond to RFC 3986, this resource will be used
# to match against everything after the last '/' and before the first '?'
# or '#'.
class HTTPIngressRuleValue(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['paths'] = self.paths()
        return v
    
    # A collection of paths that map requests to backends.
    @typechecked
    def paths(self) -> List[HTTPIngressPath]:
        if 'paths' in self._kwargs:
            return self._kwargs['paths']
        if 'paths' in self._context and check_return_type(self._context['paths']):
            return self._context['paths']
        return []


# HostPortRange defines a range of host ports that will be enabled by a policy
# for pods to use.  It requires both the start and end to be defined.
# Deprecated: use HostPortRange from policy API Group instead.
class HostPortRange(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['min'] = self.min()
        v['max'] = self.max()
        return v
    
    # min is the start of the range, inclusive.
    @typechecked
    def min(self) -> int:
        if 'min' in self._kwargs:
            return self._kwargs['min']
        if 'min' in self._context and check_return_type(self._context['min']):
            return self._context['min']
        return 0
    
    # max is the end of the range, inclusive.
    @typechecked
    def max(self) -> int:
        if 'max' in self._kwargs:
            return self._kwargs['max']
        if 'max' in self._context and check_return_type(self._context['max']):
            return self._context['max']
        return 0


# DEPRECATED 1.9 - This group version of IPBlock is deprecated by networking/v1/IPBlock.
# IPBlock describes a particular CIDR (Ex. "192.168.1.1/24") that is allowed to the pods
# matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs that should
# not be included within this rule.
class IPBlock(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['cidr'] = self.cidr()
        except_ = self.except_()
        if except_:  # omit empty
            v['except'] = except_
        return v
    
    # CIDR is a string representing the IP Block
    # Valid examples are "192.168.1.1/24"
    @typechecked
    def cidr(self) -> str:
        if 'cidr' in self._kwargs:
            return self._kwargs['cidr']
        if 'cidr' in self._context and check_return_type(self._context['cidr']):
            return self._context['cidr']
        return ''
    
    # Except is a slice of CIDRs that should not be included within an IP Block
    # Valid examples are "192.168.1.1/24"
    # Except values will be rejected if they are outside the CIDR range
    @typechecked
    def except_(self) -> List[str]:
        if 'except' in self._kwargs:
            return self._kwargs['except']
        if 'except' in self._context and check_return_type(self._context['except']):
            return self._context['except']
        return []


# IngressRuleValue represents a rule to apply against incoming requests. If the
# rule is satisfied, the request is routed to the specified backend. Currently
# mixing different types of rules in a single Ingress is disallowed, so exactly
# one of the following must be set.
class IngressRuleValue(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        http = self.http()
        if http is not None:  # omit empty
            v['http'] = http
        return v
    
    @typechecked
    def http(self) -> Optional[HTTPIngressRuleValue]:
        if 'http' in self._kwargs:
            return self._kwargs['http']
        if 'http' in self._context and check_return_type(self._context['http']):
            return self._context['http']
        return None


# IngressRule represents the rules mapping the paths under a specified host to
# the related backend services. Incoming requests are first evaluated for a host
# match, then routed to the backend associated with the matching IngressRuleValue.
class IngressRule(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        host = self.host()
        if host:  # omit empty
            v['host'] = host
        v.update(self.ingressRuleValue().render())  # inline
        return v
    
    # Host is the fully qualified domain name of a network host, as defined
    # by RFC 3986. Note the following deviations from the "host" part of the
    # URI as defined in the RFC:
    # 1. IPs are not allowed. Currently an IngressRuleValue can only apply to the
    # 	  IP in the Spec of the parent Ingress.
    # 2. The `:` delimiter is not respected because ports are not allowed.
    # 	  Currently the port of an Ingress is implicitly :80 for http and
    # 	  :443 for https.
    # Both these may change in the future.
    # Incoming requests are matched against the host before the IngressRuleValue.
    # If the host is unspecified, the Ingress routes all traffic based on the
    # specified IngressRuleValue.
    @typechecked
    def host(self) -> Optional[str]:
        if 'host' in self._kwargs:
            return self._kwargs['host']
        if 'host' in self._context and check_return_type(self._context['host']):
            return self._context['host']
        return None
    
    # IngressRuleValue represents a rule to route requests for this IngressRule.
    # If unspecified, the rule defaults to a http catch-all. Whether that sends
    # just traffic matching the host to the default backend or all traffic to the
    # default backend, is left to the controller fulfilling the Ingress. Http is
    # currently the only supported IngressRuleValue.
    @typechecked
    def ingressRuleValue(self) -> IngressRuleValue:
        if 'ingressRuleValue' in self._kwargs:
            return self._kwargs['ingressRuleValue']
        if 'ingressRuleValue' in self._context and check_return_type(self._context['ingressRuleValue']):
            return self._context['ingressRuleValue']
        with context.Scope(**self._context):
            return IngressRuleValue()


# IngressTLS describes the transport layer security associated with an Ingress.
class IngressTLS(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        hosts = self.hosts()
        if hosts:  # omit empty
            v['hosts'] = hosts
        secretName = self.secretName()
        if secretName:  # omit empty
            v['secretName'] = secretName
        return v
    
    # Hosts are a list of hosts included in the TLS certificate. The values in
    # this list must match the name/s used in the tlsSecret. Defaults to the
    # wildcard host setting for the loadbalancer controller fulfilling this
    # Ingress, if left unspecified.
    @typechecked
    def hosts(self) -> List[str]:
        if 'hosts' in self._kwargs:
            return self._kwargs['hosts']
        if 'hosts' in self._context and check_return_type(self._context['hosts']):
            return self._context['hosts']
        return []
    
    # SecretName is the name of the secret used to terminate SSL traffic on 443.
    # Field is left optional to allow SSL routing based on SNI hostname alone.
    # If the SNI host in a listener conflicts with the "Host" header field used
    # by an IngressRule, the SNI host is used for termination and value of the
    # Host header is used for routing.
    @typechecked
    def secretName(self) -> Optional[str]:
        if 'secretName' in self._kwargs:
            return self._kwargs['secretName']
        if 'secretName' in self._context and check_return_type(self._context['secretName']):
            return self._context['secretName']
        return None


# IngressSpec describes the Ingress the user wishes to exist.
class IngressSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        backend = self.backend()
        if backend is not None:  # omit empty
            v['backend'] = backend
        tls = self.tls()
        if tls:  # omit empty
            v['tls'] = tls
        rules = self.rules()
        if rules:  # omit empty
            v['rules'] = rules
        return v
    
    # A default backend capable of servicing requests that don't match any
    # rule. At least one of 'backend' or 'rules' must be specified. This field
    # is optional to allow the loadbalancer controller or defaulting logic to
    # specify a global default.
    @typechecked
    def backend(self) -> Optional[IngressBackend]:
        if 'backend' in self._kwargs:
            return self._kwargs['backend']
        if 'backend' in self._context and check_return_type(self._context['backend']):
            return self._context['backend']
        return None
    
    # TLS configuration. Currently the Ingress only supports a single TLS
    # port, 443. If multiple members of this list specify different hosts, they
    # will be multiplexed on the same port according to the hostname specified
    # through the SNI TLS extension, if the ingress controller fulfilling the
    # ingress supports SNI.
    @typechecked
    def tls(self) -> List[IngressTLS]:
        if 'tls' in self._kwargs:
            return self._kwargs['tls']
        if 'tls' in self._context and check_return_type(self._context['tls']):
            return self._context['tls']
        return []
    
    # A list of host rules used to configure the Ingress. If unspecified, or
    # no rule matches, all traffic is sent to the default backend.
    @typechecked
    def rules(self) -> List[IngressRule]:
        if 'rules' in self._kwargs:
            return self._kwargs['rules']
        if 'rules' in self._context and check_return_type(self._context['rules']):
            return self._context['rules']
        return []


# Ingress is a collection of rules that allow inbound connections to reach the
# endpoints defined by a backend. An Ingress can be configured to give services
# externally-reachable urls, load balance traffic, terminate SSL, offer name
# based virtual hosting etc.
# DEPRECATED - This group version of Ingress is deprecated by networking.k8s.io/v1beta1 Ingress. See the release notes for more information.
class Ingress(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'extensions/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'Ingress'
    
    # Spec is the desired state of the Ingress.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> IngressSpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return IngressSpec()


# DEPRECATED 1.9 - This group version of NetworkPolicyPeer is deprecated by networking/v1/NetworkPolicyPeer.
class NetworkPolicyPeer(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        podSelector = self.podSelector()
        if podSelector is not None:  # omit empty
            v['podSelector'] = podSelector
        namespaceSelector = self.namespaceSelector()
        if namespaceSelector is not None:  # omit empty
            v['namespaceSelector'] = namespaceSelector
        ipBlock = self.ipBlock()
        if ipBlock is not None:  # omit empty
            v['ipBlock'] = ipBlock
        return v
    
    # This is a label selector which selects Pods. This field follows standard label
    # selector semantics; if present but empty, it selects all pods.
    # 
    # If NamespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
    # the Pods matching PodSelector in the Namespaces selected by NamespaceSelector.
    # Otherwise it selects the Pods matching PodSelector in the policy's own Namespace.
    @typechecked
    def podSelector(self) -> Optional['metav1.LabelSelector']:
        if 'podSelector' in self._kwargs:
            return self._kwargs['podSelector']
        if 'podSelector' in self._context and check_return_type(self._context['podSelector']):
            return self._context['podSelector']
        return None
    
    # Selects Namespaces using cluster-scoped labels. This field follows standard label
    # selector semantics; if present but empty, it selects all namespaces.
    # 
    # If PodSelector is also set, then the NetworkPolicyPeer as a whole selects
    # the Pods matching PodSelector in the Namespaces selected by NamespaceSelector.
    # Otherwise it selects all Pods in the Namespaces selected by NamespaceSelector.
    @typechecked
    def namespaceSelector(self) -> Optional['metav1.LabelSelector']:
        if 'namespaceSelector' in self._kwargs:
            return self._kwargs['namespaceSelector']
        if 'namespaceSelector' in self._context and check_return_type(self._context['namespaceSelector']):
            return self._context['namespaceSelector']
        return None
    
    # IPBlock defines policy on a particular IPBlock. If this field is set then
    # neither of the other fields can be.
    @typechecked
    def ipBlock(self) -> Optional[IPBlock]:
        if 'ipBlock' in self._kwargs:
            return self._kwargs['ipBlock']
        if 'ipBlock' in self._context and check_return_type(self._context['ipBlock']):
            return self._context['ipBlock']
        return None


# DEPRECATED 1.9 - This group version of NetworkPolicyPort is deprecated by networking/v1/NetworkPolicyPort.
class NetworkPolicyPort(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        protocol = self.protocol()
        if protocol is not None:  # omit empty
            v['protocol'] = protocol
        port = self.port()
        if port is not None:  # omit empty
            v['port'] = port
        return v
    
    # Optional.  The protocol (TCP, UDP, or SCTP) which traffic must match.
    # If not specified, this field defaults to TCP.
    @typechecked
    def protocol(self) -> Optional[corev1.Protocol]:
        if 'protocol' in self._kwargs:
            return self._kwargs['protocol']
        if 'protocol' in self._context and check_return_type(self._context['protocol']):
            return self._context['protocol']
        return None
    
    # If specified, the port on the given protocol.  This can
    # either be a numerical or named port on a pod.  If this field is not provided,
    # this matches all port names and numbers.
    # If present, only traffic on the specified protocol AND port
    # will be matched.
    @typechecked
    def port(self) -> Optional[Union[int, str]]:
        if 'port' in self._kwargs:
            return self._kwargs['port']
        if 'port' in self._context and check_return_type(self._context['port']):
            return self._context['port']
        return None


# DEPRECATED 1.9 - This group version of NetworkPolicyEgressRule is deprecated by networking/v1/NetworkPolicyEgressRule.
# NetworkPolicyEgressRule describes a particular set of traffic that is allowed out of pods
# matched by a NetworkPolicySpec's podSelector. The traffic must match both ports and to.
# This type is beta-level in 1.8
class NetworkPolicyEgressRule(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        ports = self.ports()
        if ports:  # omit empty
            v['ports'] = ports
        to = self.to()
        if to:  # omit empty
            v['to'] = to
        return v
    
    # List of destination ports for outgoing traffic.
    # Each item in this list is combined using a logical OR. If this field is
    # empty or missing, this rule matches all ports (traffic not restricted by port).
    # If this field is present and contains at least one item, then this rule allows
    # traffic only if the traffic matches at least one port in the list.
    @typechecked
    def ports(self) -> List[NetworkPolicyPort]:
        if 'ports' in self._kwargs:
            return self._kwargs['ports']
        if 'ports' in self._context and check_return_type(self._context['ports']):
            return self._context['ports']
        return []
    
    # List of destinations for outgoing traffic of pods selected for this rule.
    # Items in this list are combined using a logical OR operation. If this field is
    # empty or missing, this rule matches all destinations (traffic not restricted by
    # destination). If this field is present and contains at least one item, this rule
    # allows traffic only if the traffic matches at least one item in the to list.
    @typechecked
    def to(self) -> List[NetworkPolicyPeer]:
        if 'to' in self._kwargs:
            return self._kwargs['to']
        if 'to' in self._context and check_return_type(self._context['to']):
            return self._context['to']
        return []


# DEPRECATED 1.9 - This group version of NetworkPolicyIngressRule is deprecated by networking/v1/NetworkPolicyIngressRule.
# This NetworkPolicyIngressRule matches traffic if and only if the traffic matches both ports AND from.
class NetworkPolicyIngressRule(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        ports = self.ports()
        if ports:  # omit empty
            v['ports'] = ports
        from_ = self.from_()
        if from_:  # omit empty
            v['from'] = from_
        return v
    
    # List of ports which should be made accessible on the pods selected for this rule.
    # Each item in this list is combined using a logical OR.
    # If this field is empty or missing, this rule matches all ports (traffic not restricted by port).
    # If this field is present and contains at least one item, then this rule allows traffic
    # only if the traffic matches at least one port in the list.
    @typechecked
    def ports(self) -> List[NetworkPolicyPort]:
        if 'ports' in self._kwargs:
            return self._kwargs['ports']
        if 'ports' in self._context and check_return_type(self._context['ports']):
            return self._context['ports']
        return []
    
    # List of sources which should be able to access the pods selected for this rule.
    # Items in this list are combined using a logical OR operation.
    # If this field is empty or missing, this rule matches all sources (traffic not restricted by source).
    # If this field is present and contains at least one item, this rule allows traffic only if the
    # traffic matches at least one item in the from list.
    @typechecked
    def from_(self) -> List[NetworkPolicyPeer]:
        if 'from' in self._kwargs:
            return self._kwargs['from']
        if 'from' in self._context and check_return_type(self._context['from']):
            return self._context['from']
        return []


# DEPRECATED 1.9 - This group version of NetworkPolicySpec is deprecated by networking/v1/NetworkPolicySpec.
class NetworkPolicySpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['podSelector'] = self.podSelector()
        ingress = self.ingress()
        if ingress:  # omit empty
            v['ingress'] = ingress
        egress = self.egress()
        if egress:  # omit empty
            v['egress'] = egress
        policyTypes = self.policyTypes()
        if policyTypes:  # omit empty
            v['policyTypes'] = policyTypes
        return v
    
    # Selects the pods to which this NetworkPolicy object applies.  The array of ingress rules
    # is applied to any pods selected by this field. Multiple network policies can select the
    # same set of pods.  In this case, the ingress rules for each are combined additively.
    # This field is NOT optional and follows standard label selector semantics.
    # An empty podSelector matches all pods in this namespace.
    @typechecked
    def podSelector(self) -> 'metav1.LabelSelector':
        if 'podSelector' in self._kwargs:
            return self._kwargs['podSelector']
        if 'podSelector' in self._context and check_return_type(self._context['podSelector']):
            return self._context['podSelector']
        with context.Scope(**self._context):
            return metav1.LabelSelector()
    
    # List of ingress rules to be applied to the selected pods.
    # Traffic is allowed to a pod if there are no NetworkPolicies selecting the pod
    # OR if the traffic source is the pod's local node,
    # OR if the traffic matches at least one ingress rule across all of the NetworkPolicy
    # objects whose podSelector matches the pod.
    # If this field is empty then this NetworkPolicy does not allow any traffic
    # (and serves solely to ensure that the pods it selects are isolated by default).
    @typechecked
    def ingress(self) -> List[NetworkPolicyIngressRule]:
        if 'ingress' in self._kwargs:
            return self._kwargs['ingress']
        if 'ingress' in self._context and check_return_type(self._context['ingress']):
            return self._context['ingress']
        return []
    
    # List of egress rules to be applied to the selected pods. Outgoing traffic is
    # allowed if there are no NetworkPolicies selecting the pod (and cluster policy
    # otherwise allows the traffic), OR if the traffic matches at least one egress rule
    # across all of the NetworkPolicy objects whose podSelector matches the pod. If
    # this field is empty then this NetworkPolicy limits all outgoing traffic (and serves
    # solely to ensure that the pods it selects are isolated by default).
    # This field is beta-level in 1.8
    @typechecked
    def egress(self) -> List[NetworkPolicyEgressRule]:
        if 'egress' in self._kwargs:
            return self._kwargs['egress']
        if 'egress' in self._context and check_return_type(self._context['egress']):
            return self._context['egress']
        return []
    
    # List of rule types that the NetworkPolicy relates to.
    # Valid options are "Ingress", "Egress", or "Ingress,Egress".
    # If this field is not specified, it will default based on the existence of Ingress or Egress rules;
    # policies that contain an Egress section are assumed to affect Egress, and all policies
    # (whether or not they contain an Ingress section) are assumed to affect Ingress.
    # If you want to write an egress-only policy, you must explicitly specify policyTypes [ "Egress" ].
    # Likewise, if you want to write a policy that specifies that no egress is allowed,
    # you must specify a policyTypes value that include "Egress" (since such a policy would not include
    # an Egress section and would otherwise default to just [ "Ingress" ]).
    # This field is beta-level in 1.8
    @typechecked
    def policyTypes(self) -> List[PolicyType]:
        if 'policyTypes' in self._kwargs:
            return self._kwargs['policyTypes']
        if 'policyTypes' in self._context and check_return_type(self._context['policyTypes']):
            return self._context['policyTypes']
        return []


# DEPRECATED 1.9 - This group version of NetworkPolicy is deprecated by networking/v1/NetworkPolicy.
# NetworkPolicy describes what network traffic is allowed for a set of Pods
class NetworkPolicy(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'extensions/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'NetworkPolicy'
    
    # Specification of the desired behavior for this NetworkPolicy.
    @typechecked
    def spec(self) -> NetworkPolicySpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return NetworkPolicySpec()


# RunAsGroupStrategyOptions defines the strategy type and any options used to create the strategy.
# Deprecated: use RunAsGroupStrategyOptions from policy API Group instead.
class RunAsGroupStrategyOptions(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['rule'] = self.rule()
        ranges = self.ranges()
        if ranges:  # omit empty
            v['ranges'] = ranges
        return v
    
    # rule is the strategy that will dictate the allowable RunAsGroup values that may be set.
    @typechecked
    def rule(self) -> RunAsGroupStrategy:
        if 'rule' in self._kwargs:
            return self._kwargs['rule']
        if 'rule' in self._context and check_return_type(self._context['rule']):
            return self._context['rule']
        return None
    
    # ranges are the allowed ranges of gids that may be used. If you would like to force a single gid
    # then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> List[IDRange]:
        if 'ranges' in self._kwargs:
            return self._kwargs['ranges']
        if 'ranges' in self._context and check_return_type(self._context['ranges']):
            return self._context['ranges']
        return []


# RunAsUserStrategyOptions defines the strategy type and any options used to create the strategy.
# Deprecated: use RunAsUserStrategyOptions from policy API Group instead.
class RunAsUserStrategyOptions(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['rule'] = self.rule()
        ranges = self.ranges()
        if ranges:  # omit empty
            v['ranges'] = ranges
        return v
    
    # rule is the strategy that will dictate the allowable RunAsUser values that may be set.
    @typechecked
    def rule(self) -> RunAsUserStrategy:
        if 'rule' in self._kwargs:
            return self._kwargs['rule']
        if 'rule' in self._context and check_return_type(self._context['rule']):
            return self._context['rule']
        return None
    
    # ranges are the allowed ranges of uids that may be used. If you would like to force a single uid
    # then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> List[IDRange]:
        if 'ranges' in self._kwargs:
            return self._kwargs['ranges']
        if 'ranges' in self._context and check_return_type(self._context['ranges']):
            return self._context['ranges']
        return []


# RuntimeClassStrategyOptions define the strategy that will dictate the allowable RuntimeClasses
# for a pod.
class RuntimeClassStrategyOptions(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['allowedRuntimeClassNames'] = self.allowedRuntimeClassNames()
        defaultRuntimeClassName = self.defaultRuntimeClassName()
        if defaultRuntimeClassName is not None:  # omit empty
            v['defaultRuntimeClassName'] = defaultRuntimeClassName
        return v
    
    # allowedRuntimeClassNames is a whitelist of RuntimeClass names that may be specified on a pod.
    # A value of "*" means that any RuntimeClass name is allowed, and must be the only item in the
    # list. An empty list requires the RuntimeClassName field to be unset.
    @typechecked
    def allowedRuntimeClassNames(self) -> List[str]:
        if 'allowedRuntimeClassNames' in self._kwargs:
            return self._kwargs['allowedRuntimeClassNames']
        if 'allowedRuntimeClassNames' in self._context and check_return_type(self._context['allowedRuntimeClassNames']):
            return self._context['allowedRuntimeClassNames']
        return []
    
    # defaultRuntimeClassName is the default RuntimeClassName to set on the pod.
    # The default MUST be allowed by the allowedRuntimeClassNames list.
    # A value of nil does not mutate the Pod.
    @typechecked
    def defaultRuntimeClassName(self) -> Optional[str]:
        if 'defaultRuntimeClassName' in self._kwargs:
            return self._kwargs['defaultRuntimeClassName']
        if 'defaultRuntimeClassName' in self._context and check_return_type(self._context['defaultRuntimeClassName']):
            return self._context['defaultRuntimeClassName']
        return None


# SELinuxStrategyOptions defines the strategy type and any options used to create the strategy.
# Deprecated: use SELinuxStrategyOptions from policy API Group instead.
class SELinuxStrategyOptions(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['rule'] = self.rule()
        seLinuxOptions = self.seLinuxOptions()
        if seLinuxOptions is not None:  # omit empty
            v['seLinuxOptions'] = seLinuxOptions
        return v
    
    # rule is the strategy that will dictate the allowable labels that may be set.
    @typechecked
    def rule(self) -> SELinuxStrategy:
        if 'rule' in self._kwargs:
            return self._kwargs['rule']
        if 'rule' in self._context and check_return_type(self._context['rule']):
            return self._context['rule']
        return None
    
    # seLinuxOptions required to run as; required for MustRunAs
    # More info: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
    @typechecked
    def seLinuxOptions(self) -> Optional['corev1.SELinuxOptions']:
        if 'seLinuxOptions' in self._kwargs:
            return self._kwargs['seLinuxOptions']
        if 'seLinuxOptions' in self._context and check_return_type(self._context['seLinuxOptions']):
            return self._context['seLinuxOptions']
        return None


# SupplementalGroupsStrategyOptions defines the strategy type and options used to create the strategy.
# Deprecated: use SupplementalGroupsStrategyOptions from policy API Group instead.
class SupplementalGroupsStrategyOptions(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        rule = self.rule()
        if rule:  # omit empty
            v['rule'] = rule
        ranges = self.ranges()
        if ranges:  # omit empty
            v['ranges'] = ranges
        return v
    
    # rule is the strategy that will dictate what supplemental groups is used in the SecurityContext.
    @typechecked
    def rule(self) -> Optional[SupplementalGroupsStrategyType]:
        if 'rule' in self._kwargs:
            return self._kwargs['rule']
        if 'rule' in self._context and check_return_type(self._context['rule']):
            return self._context['rule']
        return None
    
    # ranges are the allowed ranges of supplemental groups.  If you would like to force a single
    # supplemental group then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> List[IDRange]:
        if 'ranges' in self._kwargs:
            return self._kwargs['ranges']
        if 'ranges' in self._context and check_return_type(self._context['ranges']):
            return self._context['ranges']
        return []


# PodSecurityPolicySpec defines the policy enforced.
# Deprecated: use PodSecurityPolicySpec from policy API Group instead.
class PodSecurityPolicySpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        privileged = self.privileged()
        if privileged:  # omit empty
            v['privileged'] = privileged
        defaultAddCapabilities = self.defaultAddCapabilities()
        if defaultAddCapabilities:  # omit empty
            v['defaultAddCapabilities'] = defaultAddCapabilities
        requiredDropCapabilities = self.requiredDropCapabilities()
        if requiredDropCapabilities:  # omit empty
            v['requiredDropCapabilities'] = requiredDropCapabilities
        allowedCapabilities = self.allowedCapabilities()
        if allowedCapabilities:  # omit empty
            v['allowedCapabilities'] = allowedCapabilities
        volumes = self.volumes()
        if volumes:  # omit empty
            v['volumes'] = volumes
        hostNetwork = self.hostNetwork()
        if hostNetwork:  # omit empty
            v['hostNetwork'] = hostNetwork
        hostPorts = self.hostPorts()
        if hostPorts:  # omit empty
            v['hostPorts'] = hostPorts
        hostPID = self.hostPID()
        if hostPID:  # omit empty
            v['hostPID'] = hostPID
        hostIPC = self.hostIPC()
        if hostIPC:  # omit empty
            v['hostIPC'] = hostIPC
        v['seLinux'] = self.seLinux()
        v['runAsUser'] = self.runAsUser()
        runAsGroup = self.runAsGroup()
        if runAsGroup is not None:  # omit empty
            v['runAsGroup'] = runAsGroup
        v['supplementalGroups'] = self.supplementalGroups()
        v['fsGroup'] = self.fsGroup()
        readOnlyRootFilesystem = self.readOnlyRootFilesystem()
        if readOnlyRootFilesystem:  # omit empty
            v['readOnlyRootFilesystem'] = readOnlyRootFilesystem
        defaultAllowPrivilegeEscalation = self.defaultAllowPrivilegeEscalation()
        if defaultAllowPrivilegeEscalation is not None:  # omit empty
            v['defaultAllowPrivilegeEscalation'] = defaultAllowPrivilegeEscalation
        allowPrivilegeEscalation = self.allowPrivilegeEscalation()
        if allowPrivilegeEscalation is not None:  # omit empty
            v['allowPrivilegeEscalation'] = allowPrivilegeEscalation
        allowedHostPaths = self.allowedHostPaths()
        if allowedHostPaths:  # omit empty
            v['allowedHostPaths'] = allowedHostPaths
        allowedFlexVolumes = self.allowedFlexVolumes()
        if allowedFlexVolumes:  # omit empty
            v['allowedFlexVolumes'] = allowedFlexVolumes
        allowedCSIDrivers = self.allowedCSIDrivers()
        if allowedCSIDrivers:  # omit empty
            v['allowedCSIDrivers'] = allowedCSIDrivers.values()  # named list
        allowedUnsafeSysctls = self.allowedUnsafeSysctls()
        if allowedUnsafeSysctls:  # omit empty
            v['allowedUnsafeSysctls'] = allowedUnsafeSysctls
        forbiddenSysctls = self.forbiddenSysctls()
        if forbiddenSysctls:  # omit empty
            v['forbiddenSysctls'] = forbiddenSysctls
        allowedProcMountTypes = self.allowedProcMountTypes()
        if allowedProcMountTypes:  # omit empty
            v['allowedProcMountTypes'] = allowedProcMountTypes
        runtimeClass = self.runtimeClass()
        if runtimeClass is not None:  # omit empty
            v['runtimeClass'] = runtimeClass
        return v
    
    # privileged determines if a pod can request to be run as privileged.
    @typechecked
    def privileged(self) -> Optional[bool]:
        if 'privileged' in self._kwargs:
            return self._kwargs['privileged']
        if 'privileged' in self._context and check_return_type(self._context['privileged']):
            return self._context['privileged']
        return None
    
    # defaultAddCapabilities is the default set of capabilities that will be added to the container
    # unless the pod spec specifically drops the capability.  You may not list a capability in both
    # defaultAddCapabilities and requiredDropCapabilities. Capabilities added here are implicitly
    # allowed, and need not be included in the allowedCapabilities list.
    @typechecked
    def defaultAddCapabilities(self) -> List[corev1.Capability]:
        if 'defaultAddCapabilities' in self._kwargs:
            return self._kwargs['defaultAddCapabilities']
        if 'defaultAddCapabilities' in self._context and check_return_type(self._context['defaultAddCapabilities']):
            return self._context['defaultAddCapabilities']
        return []
    
    # requiredDropCapabilities are the capabilities that will be dropped from the container.  These
    # are required to be dropped and cannot be added.
    @typechecked
    def requiredDropCapabilities(self) -> List[corev1.Capability]:
        if 'requiredDropCapabilities' in self._kwargs:
            return self._kwargs['requiredDropCapabilities']
        if 'requiredDropCapabilities' in self._context and check_return_type(self._context['requiredDropCapabilities']):
            return self._context['requiredDropCapabilities']
        return []
    
    # allowedCapabilities is a list of capabilities that can be requested to add to the container.
    # Capabilities in this field may be added at the pod author's discretion.
    # You must not list a capability in both allowedCapabilities and requiredDropCapabilities.
    @typechecked
    def allowedCapabilities(self) -> List[corev1.Capability]:
        if 'allowedCapabilities' in self._kwargs:
            return self._kwargs['allowedCapabilities']
        if 'allowedCapabilities' in self._context and check_return_type(self._context['allowedCapabilities']):
            return self._context['allowedCapabilities']
        return []
    
    # volumes is a white list of allowed volume plugins. Empty indicates that
    # no volumes may be used. To allow all volumes you may use '*'.
    @typechecked
    def volumes(self) -> List[FSType]:
        if 'volumes' in self._kwargs:
            return self._kwargs['volumes']
        if 'volumes' in self._context and check_return_type(self._context['volumes']):
            return self._context['volumes']
        return []
    
    # hostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
    @typechecked
    def hostNetwork(self) -> Optional[bool]:
        if 'hostNetwork' in self._kwargs:
            return self._kwargs['hostNetwork']
        if 'hostNetwork' in self._context and check_return_type(self._context['hostNetwork']):
            return self._context['hostNetwork']
        return None
    
    # hostPorts determines which host port ranges are allowed to be exposed.
    @typechecked
    def hostPorts(self) -> List[HostPortRange]:
        if 'hostPorts' in self._kwargs:
            return self._kwargs['hostPorts']
        if 'hostPorts' in self._context and check_return_type(self._context['hostPorts']):
            return self._context['hostPorts']
        return []
    
    # hostPID determines if the policy allows the use of HostPID in the pod spec.
    @typechecked
    def hostPID(self) -> Optional[bool]:
        if 'hostPID' in self._kwargs:
            return self._kwargs['hostPID']
        if 'hostPID' in self._context and check_return_type(self._context['hostPID']):
            return self._context['hostPID']
        return None
    
    # hostIPC determines if the policy allows the use of HostIPC in the pod spec.
    @typechecked
    def hostIPC(self) -> Optional[bool]:
        if 'hostIPC' in self._kwargs:
            return self._kwargs['hostIPC']
        if 'hostIPC' in self._context and check_return_type(self._context['hostIPC']):
            return self._context['hostIPC']
        return None
    
    # seLinux is the strategy that will dictate the allowable labels that may be set.
    @typechecked
    def seLinux(self) -> SELinuxStrategyOptions:
        if 'seLinux' in self._kwargs:
            return self._kwargs['seLinux']
        if 'seLinux' in self._context and check_return_type(self._context['seLinux']):
            return self._context['seLinux']
        with context.Scope(**self._context):
            return SELinuxStrategyOptions()
    
    # runAsUser is the strategy that will dictate the allowable RunAsUser values that may be set.
    @typechecked
    def runAsUser(self) -> RunAsUserStrategyOptions:
        if 'runAsUser' in self._kwargs:
            return self._kwargs['runAsUser']
        if 'runAsUser' in self._context and check_return_type(self._context['runAsUser']):
            return self._context['runAsUser']
        with context.Scope(**self._context):
            return RunAsUserStrategyOptions()
    
    # RunAsGroup is the strategy that will dictate the allowable RunAsGroup values that may be set.
    # If this field is omitted, the pod's RunAsGroup can take any value. This field requires the
    # RunAsGroup feature gate to be enabled.
    @typechecked
    def runAsGroup(self) -> Optional[RunAsGroupStrategyOptions]:
        if 'runAsGroup' in self._kwargs:
            return self._kwargs['runAsGroup']
        if 'runAsGroup' in self._context and check_return_type(self._context['runAsGroup']):
            return self._context['runAsGroup']
        return None
    
    # supplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
    @typechecked
    def supplementalGroups(self) -> SupplementalGroupsStrategyOptions:
        if 'supplementalGroups' in self._kwargs:
            return self._kwargs['supplementalGroups']
        if 'supplementalGroups' in self._context and check_return_type(self._context['supplementalGroups']):
            return self._context['supplementalGroups']
        with context.Scope(**self._context):
            return SupplementalGroupsStrategyOptions()
    
    # fsGroup is the strategy that will dictate what fs group is used by the SecurityContext.
    @typechecked
    def fsGroup(self) -> FSGroupStrategyOptions:
        if 'fsGroup' in self._kwargs:
            return self._kwargs['fsGroup']
        if 'fsGroup' in self._context and check_return_type(self._context['fsGroup']):
            return self._context['fsGroup']
        with context.Scope(**self._context):
            return FSGroupStrategyOptions()
    
    # readOnlyRootFilesystem when set to true will force containers to run with a read only root file
    # system.  If the container specifically requests to run with a non-read only root file system
    # the PSP should deny the pod.
    # If set to false the container may run with a read only root file system if it wishes but it
    # will not be forced to.
    @typechecked
    def readOnlyRootFilesystem(self) -> Optional[bool]:
        if 'readOnlyRootFilesystem' in self._kwargs:
            return self._kwargs['readOnlyRootFilesystem']
        if 'readOnlyRootFilesystem' in self._context and check_return_type(self._context['readOnlyRootFilesystem']):
            return self._context['readOnlyRootFilesystem']
        return None
    
    # defaultAllowPrivilegeEscalation controls the default setting for whether a
    # process can gain more privileges than its parent process.
    @typechecked
    def defaultAllowPrivilegeEscalation(self) -> Optional[bool]:
        if 'defaultAllowPrivilegeEscalation' in self._kwargs:
            return self._kwargs['defaultAllowPrivilegeEscalation']
        if 'defaultAllowPrivilegeEscalation' in self._context and check_return_type(self._context['defaultAllowPrivilegeEscalation']):
            return self._context['defaultAllowPrivilegeEscalation']
        return None
    
    # allowPrivilegeEscalation determines if a pod can request to allow
    # privilege escalation. If unspecified, defaults to true.
    @typechecked
    def allowPrivilegeEscalation(self) -> Optional[bool]:
        if 'allowPrivilegeEscalation' in self._kwargs:
            return self._kwargs['allowPrivilegeEscalation']
        if 'allowPrivilegeEscalation' in self._context and check_return_type(self._context['allowPrivilegeEscalation']):
            return self._context['allowPrivilegeEscalation']
        return True
    
    # allowedHostPaths is a white list of allowed host paths. Empty indicates
    # that all host paths may be used.
    @typechecked
    def allowedHostPaths(self) -> List[AllowedHostPath]:
        if 'allowedHostPaths' in self._kwargs:
            return self._kwargs['allowedHostPaths']
        if 'allowedHostPaths' in self._context and check_return_type(self._context['allowedHostPaths']):
            return self._context['allowedHostPaths']
        return []
    
    # allowedFlexVolumes is a whitelist of allowed Flexvolumes.  Empty or nil indicates that all
    # Flexvolumes may be used.  This parameter is effective only when the usage of the Flexvolumes
    # is allowed in the "volumes" field.
    @typechecked
    def allowedFlexVolumes(self) -> List[AllowedFlexVolume]:
        if 'allowedFlexVolumes' in self._kwargs:
            return self._kwargs['allowedFlexVolumes']
        if 'allowedFlexVolumes' in self._context and check_return_type(self._context['allowedFlexVolumes']):
            return self._context['allowedFlexVolumes']
        return []
    
    # AllowedCSIDrivers is a whitelist of inline CSI drivers that must be explicitly set to be embedded within a pod spec.
    # An empty value indicates that any CSI driver can be used for inline ephemeral volumes.
    @typechecked
    def allowedCSIDrivers(self) -> Dict[str, AllowedCSIDriver]:
        if 'allowedCSIDrivers' in self._kwargs:
            return self._kwargs['allowedCSIDrivers']
        if 'allowedCSIDrivers' in self._context and check_return_type(self._context['allowedCSIDrivers']):
            return self._context['allowedCSIDrivers']
        return {}
    
    # allowedUnsafeSysctls is a list of explicitly allowed unsafe sysctls, defaults to none.
    # Each entry is either a plain sysctl name or ends in "*" in which case it is considered
    # as a prefix of allowed sysctls. Single * means all unsafe sysctls are allowed.
    # Kubelet has to whitelist all allowed unsafe sysctls explicitly to avoid rejection.
    # 
    # Examples:
    # e.g. "foo/*" allows "foo/bar", "foo/baz", etc.
    # e.g. "foo.*" allows "foo.bar", "foo.baz", etc.
    @typechecked
    def allowedUnsafeSysctls(self) -> List[str]:
        if 'allowedUnsafeSysctls' in self._kwargs:
            return self._kwargs['allowedUnsafeSysctls']
        if 'allowedUnsafeSysctls' in self._context and check_return_type(self._context['allowedUnsafeSysctls']):
            return self._context['allowedUnsafeSysctls']
        return []
    
    # forbiddenSysctls is a list of explicitly forbidden sysctls, defaults to none.
    # Each entry is either a plain sysctl name or ends in "*" in which case it is considered
    # as a prefix of forbidden sysctls. Single * means all sysctls are forbidden.
    # 
    # Examples:
    # e.g. "foo/*" forbids "foo/bar", "foo/baz", etc.
    # e.g. "foo.*" forbids "foo.bar", "foo.baz", etc.
    @typechecked
    def forbiddenSysctls(self) -> List[str]:
        if 'forbiddenSysctls' in self._kwargs:
            return self._kwargs['forbiddenSysctls']
        if 'forbiddenSysctls' in self._context and check_return_type(self._context['forbiddenSysctls']):
            return self._context['forbiddenSysctls']
        return []
    
    # AllowedProcMountTypes is a whitelist of allowed ProcMountTypes.
    # Empty or nil indicates that only the DefaultProcMountType may be used.
    # This requires the ProcMountType feature flag to be enabled.
    @typechecked
    def allowedProcMountTypes(self) -> List[corev1.ProcMountType]:
        if 'allowedProcMountTypes' in self._kwargs:
            return self._kwargs['allowedProcMountTypes']
        if 'allowedProcMountTypes' in self._context and check_return_type(self._context['allowedProcMountTypes']):
            return self._context['allowedProcMountTypes']
        return []
    
    # runtimeClass is the strategy that will dictate the allowable RuntimeClasses for a pod.
    # If this field is omitted, the pod's runtimeClassName field is unrestricted.
    # Enforcement of this field depends on the RuntimeClass feature gate being enabled.
    @typechecked
    def runtimeClass(self) -> Optional[RuntimeClassStrategyOptions]:
        if 'runtimeClass' in self._kwargs:
            return self._kwargs['runtimeClass']
        if 'runtimeClass' in self._context and check_return_type(self._context['runtimeClass']):
            return self._context['runtimeClass']
        return None


# PodSecurityPolicy governs the ability to make requests that affect the Security Context
# that will be applied to a pod and container.
# Deprecated: use PodSecurityPolicy from policy API Group instead.
class PodSecurityPolicy(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'extensions/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'PodSecurityPolicy'
    
    # spec defines the policy enforced.
    @typechecked
    def spec(self) -> PodSecurityPolicySpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return PodSecurityPolicySpec()


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
        selector = self.selector()
        if selector is not None:  # omit empty
            v['selector'] = selector
        v['template'] = self.template()
        return v
    
    # Replicas is the number of desired replicas.
    # This is a pointer to distinguish between explicit zero and unspecified.
    # Defaults to 1.
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller/#what-is-a-replicationcontroller
    @typechecked
    def replicas(self) -> Optional[int]:
        if 'replicas' in self._kwargs:
            return self._kwargs['replicas']
        if 'replicas' in self._context and check_return_type(self._context['replicas']):
            return self._context['replicas']
        return 1
    
    # Minimum number of seconds for which a newly created pod should be ready
    # without any of its container crashing, for it to be considered available.
    # Defaults to 0 (pod will be considered available as soon as it is ready)
    @typechecked
    def minReadySeconds(self) -> Optional[int]:
        if 'minReadySeconds' in self._kwargs:
            return self._kwargs['minReadySeconds']
        if 'minReadySeconds' in self._context and check_return_type(self._context['minReadySeconds']):
            return self._context['minReadySeconds']
        return None
    
    # Selector is a label query over pods that should match the replica count.
    # If the selector is empty, it is defaulted to the labels present on the pod template.
    # Label keys and values that must match in order to be controlled by this replica set.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        if 'selector' in self._kwargs:
            return self._kwargs['selector']
        if 'selector' in self._context and check_return_type(self._context['selector']):
            return self._context['selector']
        return None
    
    # Template is the object that describes the pod that will be created if
    # insufficient replicas are detected.
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#pod-template
    @typechecked
    def template(self) -> 'corev1.PodTemplateSpec':
        if 'template' in self._kwargs:
            return self._kwargs['template']
        if 'template' in self._context and check_return_type(self._context['template']):
            return self._context['template']
        with context.Scope(**self._context):
            return corev1.PodTemplateSpec()


# DEPRECATED - This group version of ReplicaSet is deprecated by apps/v1beta2/ReplicaSet. See the release notes for
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
        return 'extensions/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'ReplicaSet'
    
    # Spec defines the specification of the desired behavior of the ReplicaSet.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> ReplicaSetSpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return ReplicaSetSpec()


# Dummy definition
class ReplicationControllerDummy(base.TypedObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'extensions/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'ReplicationControllerDummy'


# describes the attributes of a scale subresource
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
        if 'replicas' in self._kwargs:
            return self._kwargs['replicas']
        if 'replicas' in self._context and check_return_type(self._context['replicas']):
            return self._context['replicas']
        return None


# represents a scaling request for a resource.
class Scale(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'extensions/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'Scale'
    
    # defines the behavior of the scale. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
    @typechecked
    def spec(self) -> ScaleSpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return ScaleSpec()
