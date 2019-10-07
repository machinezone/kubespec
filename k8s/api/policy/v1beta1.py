# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional, Union

from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery.meta import v1 as metav1
from kargo import types
from typeguard import typechecked


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
        return self._get('name', '')


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
        return self._get('driver', '')


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
        return self._get('pathPrefix')
    
    # when set to true, will allow host volumes matching the pathPrefix only if all volume mounts are readOnly.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self._get('readOnly')


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
        return self._get('deleteOptions')


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
        return self._get('min', 0)
    
    # max is the end of the range, inclusive.
    @typechecked
    def max(self) -> int:
        return self._get('max', 0)


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
        return self._get('rule')
    
    # ranges are the allowed ranges of fs groups.  If you would like to force a single
    # fs group then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> List[IDRange]:
        return self._get('ranges', [])


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
        return self._get('min', 0)
    
    # max is the end of the range, inclusive.
    @typechecked
    def max(self) -> int:
        return self._get('max', 0)


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
        return self._get('minAvailable')
    
    # Label query over pods whose evictions are managed by the disruption
    # budget.
    @typechecked
    def selector(self) -> Optional['metav1.LabelSelector']:
        return self._get('selector')
    
    # An eviction is allowed if at most "maxUnavailable" pods selected by
    # "selector" are unavailable after the eviction, i.e. even in absence of
    # the evicted pod. For example, one can prevent all voluntary evictions
    # by specifying 0. This is a mutually exclusive setting with "minAvailable".
    @typechecked
    def maxUnavailable(self) -> Optional[Union[int, str]]:
        return self._get('maxUnavailable')


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
        return self._get('spec', PodDisruptionBudgetSpec())


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
        return self._get('rule')
    
    # ranges are the allowed ranges of gids that may be used. If you would like to force a single gid
    # then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> List[IDRange]:
        return self._get('ranges', [])


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
        return self._get('rule')
    
    # ranges are the allowed ranges of uids that may be used. If you would like to force a single uid
    # then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> List[IDRange]:
        return self._get('ranges', [])


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
        return self._get('allowedRuntimeClassNames', [])
    
    # defaultRuntimeClassName is the default RuntimeClassName to set on the pod.
    # The default MUST be allowed by the allowedRuntimeClassNames list.
    # A value of nil does not mutate the Pod.
    @typechecked
    def defaultRuntimeClassName(self) -> Optional[str]:
        return self._get('defaultRuntimeClassName')


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
        return self._get('rule')
    
    # seLinuxOptions required to run as; required for MustRunAs
    # More info: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
    @typechecked
    def seLinuxOptions(self) -> Optional['corev1.SELinuxOptions']:
        return self._get('seLinuxOptions')


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
        return self._get('rule')
    
    # ranges are the allowed ranges of supplemental groups.  If you would like to force a single
    # supplemental group then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> List[IDRange]:
        return self._get('ranges', [])


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
        return self._get('privileged')
    
    # defaultAddCapabilities is the default set of capabilities that will be added to the container
    # unless the pod spec specifically drops the capability.  You may not list a capability in both
    # defaultAddCapabilities and requiredDropCapabilities. Capabilities added here are implicitly
    # allowed, and need not be included in the allowedCapabilities list.
    @typechecked
    def defaultAddCapabilities(self) -> List[corev1.Capability]:
        return self._get('defaultAddCapabilities', [])
    
    # requiredDropCapabilities are the capabilities that will be dropped from the container.  These
    # are required to be dropped and cannot be added.
    @typechecked
    def requiredDropCapabilities(self) -> List[corev1.Capability]:
        return self._get('requiredDropCapabilities', [])
    
    # allowedCapabilities is a list of capabilities that can be requested to add to the container.
    # Capabilities in this field may be added at the pod author's discretion.
    # You must not list a capability in both allowedCapabilities and requiredDropCapabilities.
    @typechecked
    def allowedCapabilities(self) -> List[corev1.Capability]:
        return self._get('allowedCapabilities', [])
    
    # volumes is a white list of allowed volume plugins. Empty indicates that
    # no volumes may be used. To allow all volumes you may use '*'.
    @typechecked
    def volumes(self) -> List[FSType]:
        return self._get('volumes', [])
    
    # hostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
    @typechecked
    def hostNetwork(self) -> Optional[bool]:
        return self._get('hostNetwork')
    
    # hostPorts determines which host port ranges are allowed to be exposed.
    @typechecked
    def hostPorts(self) -> List[HostPortRange]:
        return self._get('hostPorts', [])
    
    # hostPID determines if the policy allows the use of HostPID in the pod spec.
    @typechecked
    def hostPID(self) -> Optional[bool]:
        return self._get('hostPID')
    
    # hostIPC determines if the policy allows the use of HostIPC in the pod spec.
    @typechecked
    def hostIPC(self) -> Optional[bool]:
        return self._get('hostIPC')
    
    # seLinux is the strategy that will dictate the allowable labels that may be set.
    @typechecked
    def seLinux(self) -> SELinuxStrategyOptions:
        return self._get('seLinux', SELinuxStrategyOptions())
    
    # runAsUser is the strategy that will dictate the allowable RunAsUser values that may be set.
    @typechecked
    def runAsUser(self) -> RunAsUserStrategyOptions:
        return self._get('runAsUser', RunAsUserStrategyOptions())
    
    # RunAsGroup is the strategy that will dictate the allowable RunAsGroup values that may be set.
    # If this field is omitted, the pod's RunAsGroup can take any value. This field requires the
    # RunAsGroup feature gate to be enabled.
    @typechecked
    def runAsGroup(self) -> Optional[RunAsGroupStrategyOptions]:
        return self._get('runAsGroup')
    
    # supplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
    @typechecked
    def supplementalGroups(self) -> SupplementalGroupsStrategyOptions:
        return self._get('supplementalGroups', SupplementalGroupsStrategyOptions())
    
    # fsGroup is the strategy that will dictate what fs group is used by the SecurityContext.
    @typechecked
    def fsGroup(self) -> FSGroupStrategyOptions:
        return self._get('fsGroup', FSGroupStrategyOptions())
    
    # readOnlyRootFilesystem when set to true will force containers to run with a read only root file
    # system.  If the container specifically requests to run with a non-read only root file system
    # the PSP should deny the pod.
    # If set to false the container may run with a read only root file system if it wishes but it
    # will not be forced to.
    @typechecked
    def readOnlyRootFilesystem(self) -> Optional[bool]:
        return self._get('readOnlyRootFilesystem')
    
    # defaultAllowPrivilegeEscalation controls the default setting for whether a
    # process can gain more privileges than its parent process.
    @typechecked
    def defaultAllowPrivilegeEscalation(self) -> Optional[bool]:
        return self._get('defaultAllowPrivilegeEscalation')
    
    # allowPrivilegeEscalation determines if a pod can request to allow
    # privilege escalation. If unspecified, defaults to true.
    @typechecked
    def allowPrivilegeEscalation(self) -> Optional[bool]:
        return self._get('allowPrivilegeEscalation', True)
    
    # allowedHostPaths is a white list of allowed host paths. Empty indicates
    # that all host paths may be used.
    @typechecked
    def allowedHostPaths(self) -> List[AllowedHostPath]:
        return self._get('allowedHostPaths', [])
    
    # allowedFlexVolumes is a whitelist of allowed Flexvolumes.  Empty or nil indicates that all
    # Flexvolumes may be used.  This parameter is effective only when the usage of the Flexvolumes
    # is allowed in the "volumes" field.
    @typechecked
    def allowedFlexVolumes(self) -> List[AllowedFlexVolume]:
        return self._get('allowedFlexVolumes', [])
    
    # AllowedCSIDrivers is a whitelist of inline CSI drivers that must be explicitly set to be embedded within a pod spec.
    # An empty value indicates that any CSI driver can be used for inline ephemeral volumes.
    # This is an alpha field, and is only honored if the API server enables the CSIInlineVolume feature gate.
    @typechecked
    def allowedCSIDrivers(self) -> Dict[str, AllowedCSIDriver]:
        return self._get('allowedCSIDrivers', {})
    
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
        return self._get('allowedUnsafeSysctls', [])
    
    # forbiddenSysctls is a list of explicitly forbidden sysctls, defaults to none.
    # Each entry is either a plain sysctl name or ends in "*" in which case it is considered
    # as a prefix of forbidden sysctls. Single * means all sysctls are forbidden.
    # 
    # Examples:
    # e.g. "foo/*" forbids "foo/bar", "foo/baz", etc.
    # e.g. "foo.*" forbids "foo.bar", "foo.baz", etc.
    @typechecked
    def forbiddenSysctls(self) -> List[str]:
        return self._get('forbiddenSysctls', [])
    
    # AllowedProcMountTypes is a whitelist of allowed ProcMountTypes.
    # Empty or nil indicates that only the DefaultProcMountType may be used.
    # This requires the ProcMountType feature flag to be enabled.
    @typechecked
    def allowedProcMountTypes(self) -> List[corev1.ProcMountType]:
        return self._get('allowedProcMountTypes', [])
    
    # runtimeClass is the strategy that will dictate the allowable RuntimeClasses for a pod.
    # If this field is omitted, the pod's runtimeClassName field is unrestricted.
    # Enforcement of this field depends on the RuntimeClass feature gate being enabled.
    @typechecked
    def runtimeClass(self) -> Optional[RuntimeClassStrategyOptions]:
        return self._get('runtimeClass')


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
        return self._get('spec', PodSecurityPolicySpec())
