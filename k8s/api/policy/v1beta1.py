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


# FSGroupStrategyType denotes strategy types for generating FSGroup values for a
# SecurityContext
FSGroupStrategyType = base.Enum('FSGroupStrategyType', {
    # MayRunAs means that container does not need to have FSGroup of X applied.
    # However, when FSGroups are specified, they have to fall in the defined range.
    'MayRunAs': 'MayRunAs',
    # MustRunAs meant that container must have FSGroup of X applied.
    'MustRunAs': 'MustRunAs',
    # RunAsAny means that container may make requests for any FSGroup labels.
    'RunAsAny': 'RunAsAny',
})


# FSType gives strong typing to different file systems that are used by volumes.
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
    'PhotonPersistentDisk': 'photonPersistentDisk',
    'PortworxVolume': 'portworxVolume',
    'Projected': 'projected',
    'Quobyte': 'quobyte',
    'RBD': 'rbd',
    'ScaleIO': 'scaleIO',
    'Secret': 'secret',
    'StorageOS': 'storageos',
    'VsphereVolume': 'vsphereVolume',
})


# RunAsGroupStrategy denotes strategy types for generating RunAsGroup values for a
# Security Context.
RunAsGroupStrategy = base.Enum('RunAsGroupStrategy', {
    # MayRunAs means that container does not need to run with a particular gid.
    # However, when RunAsGroup are specified, they have to fall in the defined range.
    'MayRunAs': 'MayRunAs',
    # MustRunAs means that container must run as a particular gid.
    'MustRunAs': 'MustRunAs',
    # RunAsUserStrategyRunAsAny means that container may make requests for any gid.
    'RunAsAny': 'RunAsAny',
})


# RunAsUserStrategy denotes strategy types for generating RunAsUser values for a
# Security Context.
RunAsUserStrategy = base.Enum('RunAsUserStrategy', {
    # MustRunAs means that container must run as a particular uid.
    'MustRunAs': 'MustRunAs',
    # MustRunAsNonRoot means that container must run as a non-root uid.
    'MustRunAsNonRoot': 'MustRunAsNonRoot',
    # RunAsAny means that container may make requests for any uid.
    'RunAsAny': 'RunAsAny',
})


# SELinuxStrategy denotes strategy types for generating SELinux options for a
# Security Context.
SELinuxStrategy = base.Enum('SELinuxStrategy', {
    # MustRunAs means that container must have SELinux labels of X applied.
    'MustRunAs': 'MustRunAs',
    # RunAsAny means that container may make requests for any SELinux context labels.
    'RunAsAny': 'RunAsAny',
})


# SupplementalGroupsStrategyType denotes strategy types for determining valid supplemental
# groups for a SecurityContext.
SupplementalGroupsStrategyType = base.Enum('SupplementalGroupsStrategyType', {
    # MayRunAs means that container does not need to run with a particular gid.
    # However, when gids are specified, they have to fall in the defined range.
    'MayRunAs': 'MayRunAs',
    # MustRunAs means that container must run as a particular gid.
    'MustRunAs': 'MustRunAs',
    # RunAsAny means that container may make requests for any gid.
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


# Eviction evicts a pod from its node subject to certain policies and safety constraints.
# This is a subresource of Pod.  A request to cause such an eviction is
# created by POSTing to .../pods/<pod name>/evictions.
class Eviction(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        deleteOptions = self.deleteOptions()
        if deleteOptions is not None:  # omit empty
            v['deleteOptions'] = deleteOptions
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'policy/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'Eviction'
    
    # DeleteOptions may be provided
    @typechecked
    def deleteOptions(self) -> Optional['metav1.DeleteOptions']:
        if 'deleteOptions' in self._kwargs:
            return self._kwargs['deleteOptions']
        if 'deleteOptions' in self._context and check_return_type(self._context['deleteOptions']):
            return self._context['deleteOptions']
        return None


# IDRange provides a min/max of an allowed range of IDs.
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


# HostPortRange defines a range of host ports that will be enabled by a policy
# for pods to use.  It requires both the start and end to be defined.
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


# PodDisruptionBudgetSpec is a description of a PodDisruptionBudget.
class PodDisruptionBudgetSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        minAvailable = self.minAvailable()
        if minAvailable is not None:  # omit empty
            v['minAvailable'] = minAvailable
        selector = self.selector()
        if selector is not None:  # omit empty
            v['selector'] = selector
        maxUnavailable = self.maxUnavailable()
        if maxUnavailable is not None:  # omit empty
            v['maxUnavailable'] = maxUnavailable
        return v
    
    # An eviction is allowed if at least "minAvailable" pods selected by
    # "selector" will still be available after the eviction, i.e. even in the
    # absence of the evicted pod.  So for example you can prevent all voluntary
    # evictions by specifying "100%".
    @typechecked
    def minAvailable(self) -> Optional[Union[int, str]]:
        if 'minAvailable' in self._kwargs:
            return self._kwargs['minAvailable']
        if 'minAvailable' in self._context and check_return_type(self._context['minAvailable']):
            return self._context['minAvailable']
        return None
    
    # Label query over pods whose evictions are managed by the disruption
    # budget.
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        if 'selector' in self._kwargs:
            return self._kwargs['selector']
        if 'selector' in self._context and check_return_type(self._context['selector']):
            return self._context['selector']
        return None
    
    # An eviction is allowed if at most "maxUnavailable" pods selected by
    # "selector" are unavailable after the eviction, i.e. even in absence of
    # the evicted pod. For example, one can prevent all voluntary evictions
    # by specifying 0. This is a mutually exclusive setting with "minAvailable".
    @typechecked
    def maxUnavailable(self) -> Optional[Union[int, str]]:
        if 'maxUnavailable' in self._kwargs:
            return self._kwargs['maxUnavailable']
        if 'maxUnavailable' in self._context and check_return_type(self._context['maxUnavailable']):
            return self._context['maxUnavailable']
        return None


# PodDisruptionBudget is an object to define the max disruption that can be caused to a collection of pods
class PodDisruptionBudget(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'policy/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'PodDisruptionBudget'
    
    # Specification of the desired behavior of the PodDisruptionBudget.
    @typechecked
    def spec(self) -> PodDisruptionBudgetSpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return PodDisruptionBudgetSpec()


# RunAsGroupStrategyOptions defines the strategy type and any options used to create the strategy.
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
    # This is an alpha field, and is only honored if the API server enables the CSIInlineVolume feature gate.
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
class PodSecurityPolicy(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'policy/v1beta1'
    
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
