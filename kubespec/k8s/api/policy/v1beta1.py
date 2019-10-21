# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional, Union

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec.k8s.apimachinery.meta import v1 as metav1
from kubespec import context
from kubespec import types
from typeguard import typechecked


# FSGroupStrategyType denotes strategy types for generating FSGroup values for a
# SecurityContext
FSGroupStrategyType = base.Enum(
    "FSGroupStrategyType",
    {
        # MayRunAs means that container does not need to have FSGroup of X applied.
        # However, when FSGroups are specified, they have to fall in the defined range.
        "MayRunAs": "MayRunAs",
        # MustRunAs meant that container must have FSGroup of X applied.
        "MustRunAs": "MustRunAs",
        # RunAsAny means that container may make requests for any FSGroup labels.
        "RunAsAny": "RunAsAny",
    },
)


# FSType gives strong typing to different file systems that are used by volumes.
FSType = base.Enum(
    "FSType",
    {
        "AWSElasticBlockStore": "awsElasticBlockStore",
        "All": "*",
        "AzureDisk": "azureDisk",
        "AzureFile": "azureFile",
        "CSI": "csi",
        "CephFS": "cephFS",
        "Cinder": "cinder",
        "ConfigMap": "configMap",
        "DownwardAPI": "downwardAPI",
        "EmptyDir": "emptyDir",
        "FC": "fc",
        "FlexVolume": "flexVolume",
        "Flocker": "flocker",
        "GCEPersistentDisk": "gcePersistentDisk",
        "GitRepo": "gitRepo",
        "Glusterfs": "glusterfs",
        "HostPath": "hostPath",
        "ISCSI": "iscsi",
        "NFS": "nfs",
        "PersistentVolumeClaim": "persistentVolumeClaim",
        "PhotonPersistentDisk": "photonPersistentDisk",
        "PortworxVolume": "portworxVolume",
        "Projected": "projected",
        "Quobyte": "quobyte",
        "RBD": "rbd",
        "ScaleIO": "scaleIO",
        "Secret": "secret",
        "StorageOS": "storageos",
        "VsphereVolume": "vsphereVolume",
    },
)


# RunAsGroupStrategy denotes strategy types for generating RunAsGroup values for a
# Security Context.
RunAsGroupStrategy = base.Enum(
    "RunAsGroupStrategy",
    {
        # MayRunAs means that container does not need to run with a particular gid.
        # However, when RunAsGroup are specified, they have to fall in the defined range.
        "MayRunAs": "MayRunAs",
        # MustRunAs means that container must run as a particular gid.
        "MustRunAs": "MustRunAs",
        # RunAsUserStrategyRunAsAny means that container may make requests for any gid.
        "RunAsAny": "RunAsAny",
    },
)


# RunAsUserStrategy denotes strategy types for generating RunAsUser values for a
# Security Context.
RunAsUserStrategy = base.Enum(
    "RunAsUserStrategy",
    {
        # MustRunAs means that container must run as a particular uid.
        "MustRunAs": "MustRunAs",
        # MustRunAsNonRoot means that container must run as a non-root uid.
        "MustRunAsNonRoot": "MustRunAsNonRoot",
        # RunAsAny means that container may make requests for any uid.
        "RunAsAny": "RunAsAny",
    },
)


# SELinuxStrategy denotes strategy types for generating SELinux options for a
# Security Context.
SELinuxStrategy = base.Enum(
    "SELinuxStrategy",
    {
        # MustRunAs means that container must have SELinux labels of X applied.
        "MustRunAs": "MustRunAs",
        # RunAsAny means that container may make requests for any SELinux context labels.
        "RunAsAny": "RunAsAny",
    },
)


# SupplementalGroupsStrategyType denotes strategy types for determining valid supplemental
# groups for a SecurityContext.
SupplementalGroupsStrategyType = base.Enum(
    "SupplementalGroupsStrategyType",
    {
        # MayRunAs means that container does not need to run with a particular gid.
        # However, when gids are specified, they have to fall in the defined range.
        "MayRunAs": "MayRunAs",
        # MustRunAs means that container must run as a particular gid.
        "MustRunAs": "MustRunAs",
        # RunAsAny means that container may make requests for any gid.
        "RunAsAny": "RunAsAny",
    },
)


# AllowedCSIDriver represents a single inline CSI Driver that is allowed to be used.
class AllowedCSIDriver(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = ""):
        super().__init__(**{})
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        return v

    # Name is the registered name of the CSI driver
    @typechecked
    def name(self) -> str:
        return self.__name


# AllowedFlexVolume represents a single Flexvolume that is allowed to be used.
class AllowedFlexVolume(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, driver: str = ""):
        super().__init__(**{})
        self.__driver = driver

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["driver"] = self.driver()
        return v

    # driver is the name of the Flexvolume driver.
    @typechecked
    def driver(self) -> str:
        return self.__driver


# AllowedHostPath defines the host volume conditions that will be enabled by a policy
# for pods to use. It requires the path prefix to be defined.
class AllowedHostPath(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, pathPrefix: str = None, readOnly: bool = None):
        super().__init__(**{})
        self.__pathPrefix = pathPrefix
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pathPrefix = self.pathPrefix()
        if pathPrefix:  # omit empty
            v["pathPrefix"] = pathPrefix
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
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
        return self.__pathPrefix

    # when set to true, will allow host volumes matching the pathPrefix only if all volume mounts are readOnly.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# Eviction evicts a pod from its node subject to certain policies and safety constraints.
# This is a subresource of Pod.  A request to cause such an eviction is
# created by POSTing to .../pods/<pod name>/evictions.
class Eviction(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        deleteOptions: "metav1.DeleteOptions" = None,
    ):
        super().__init__(
            **{
                "apiVersion": "policy/v1beta1",
                "kind": "Eviction",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__deleteOptions = deleteOptions

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        deleteOptions = self.deleteOptions()
        if deleteOptions is not None:  # omit empty
            v["deleteOptions"] = deleteOptions
        return v

    # DeleteOptions may be provided
    @typechecked
    def deleteOptions(self) -> Optional["metav1.DeleteOptions"]:
        return self.__deleteOptions


# IDRange provides a min/max of an allowed range of IDs.
class IDRange(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, min: int = 0, max: int = 0):
        super().__init__(**{})
        self.__min = min
        self.__max = max

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["min"] = self.min()
        v["max"] = self.max()
        return v

    # min is the start of the range, inclusive.
    @typechecked
    def min(self) -> int:
        return self.__min

    # max is the end of the range, inclusive.
    @typechecked
    def max(self) -> int:
        return self.__max


# FSGroupStrategyOptions defines the strategy type and options used to create the strategy.
class FSGroupStrategyOptions(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, rule: FSGroupStrategyType = None, ranges: List[IDRange] = None):
        super().__init__(**{})
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        if rule:  # omit empty
            v["rule"] = rule
        ranges = self.ranges()
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    # rule is the strategy that will dictate what FSGroup is used in the SecurityContext.
    @typechecked
    def rule(self) -> Optional[FSGroupStrategyType]:
        return self.__rule

    # ranges are the allowed ranges of fs groups.  If you would like to force a single
    # fs group then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> Optional[List[IDRange]]:
        return self.__ranges


# HostPortRange defines a range of host ports that will be enabled by a policy
# for pods to use.  It requires both the start and end to be defined.
class HostPortRange(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, min: int = 0, max: int = 0):
        super().__init__(**{})
        self.__min = min
        self.__max = max

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["min"] = self.min()
        v["max"] = self.max()
        return v

    # min is the start of the range, inclusive.
    @typechecked
    def min(self) -> int:
        return self.__min

    # max is the end of the range, inclusive.
    @typechecked
    def max(self) -> int:
        return self.__max


# PodDisruptionBudgetSpec is a description of a PodDisruptionBudget.
class PodDisruptionBudgetSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        minAvailable: Union[int, str] = None,
        selector: "metav1.LabelSelector" = None,
        maxUnavailable: Union[int, str] = None,
    ):
        super().__init__(**{})
        self.__minAvailable = minAvailable
        self.__selector = selector
        self.__maxUnavailable = maxUnavailable

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        minAvailable = self.minAvailable()
        if minAvailable is not None:  # omit empty
            v["minAvailable"] = minAvailable
        selector = self.selector()
        if selector is not None:  # omit empty
            v["selector"] = selector
        maxUnavailable = self.maxUnavailable()
        if maxUnavailable is not None:  # omit empty
            v["maxUnavailable"] = maxUnavailable
        return v

    # An eviction is allowed if at least "minAvailable" pods selected by
    # "selector" will still be available after the eviction, i.e. even in the
    # absence of the evicted pod.  So for example you can prevent all voluntary
    # evictions by specifying "100%".
    @typechecked
    def minAvailable(self) -> Optional[Union[int, str]]:
        return self.__minAvailable

    # Label query over pods whose evictions are managed by the disruption
    # budget.
    @typechecked
    def selector(self) -> Optional["metav1.LabelSelector"]:
        return self.__selector

    # An eviction is allowed if at most "maxUnavailable" pods selected by
    # "selector" are unavailable after the eviction, i.e. even in absence of
    # the evicted pod. For example, one can prevent all voluntary evictions
    # by specifying 0. This is a mutually exclusive setting with "minAvailable".
    @typechecked
    def maxUnavailable(self) -> Optional[Union[int, str]]:
        return self.__maxUnavailable


# PodDisruptionBudget is an object to define the max disruption that can be caused to a collection of pods
class PodDisruptionBudget(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: PodDisruptionBudgetSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "policy/v1beta1",
                "kind": "PodDisruptionBudget",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else PodDisruptionBudgetSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Specification of the desired behavior of the PodDisruptionBudget.
    @typechecked
    def spec(self) -> Optional[PodDisruptionBudgetSpec]:
        return self.__spec


# RunAsGroupStrategyOptions defines the strategy type and any options used to create the strategy.
class RunAsGroupStrategyOptions(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, rule: RunAsGroupStrategy = None, ranges: List[IDRange] = None):
        super().__init__(**{})
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["rule"] = self.rule()
        ranges = self.ranges()
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    # rule is the strategy that will dictate the allowable RunAsGroup values that may be set.
    @typechecked
    def rule(self) -> RunAsGroupStrategy:
        return self.__rule

    # ranges are the allowed ranges of gids that may be used. If you would like to force a single gid
    # then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> Optional[List[IDRange]]:
        return self.__ranges


# RunAsUserStrategyOptions defines the strategy type and any options used to create the strategy.
class RunAsUserStrategyOptions(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, rule: RunAsUserStrategy = None, ranges: List[IDRange] = None):
        super().__init__(**{})
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["rule"] = self.rule()
        ranges = self.ranges()
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    # rule is the strategy that will dictate the allowable RunAsUser values that may be set.
    @typechecked
    def rule(self) -> RunAsUserStrategy:
        return self.__rule

    # ranges are the allowed ranges of uids that may be used. If you would like to force a single uid
    # then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> Optional[List[IDRange]]:
        return self.__ranges


# RuntimeClassStrategyOptions define the strategy that will dictate the allowable RuntimeClasses
# for a pod.
class RuntimeClassStrategyOptions(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        allowedRuntimeClassNames: List[str] = None,
        defaultRuntimeClassName: str = None,
    ):
        super().__init__(**{})
        self.__allowedRuntimeClassNames = (
            allowedRuntimeClassNames if allowedRuntimeClassNames is not None else []
        )
        self.__defaultRuntimeClassName = defaultRuntimeClassName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["allowedRuntimeClassNames"] = self.allowedRuntimeClassNames()
        defaultRuntimeClassName = self.defaultRuntimeClassName()
        if defaultRuntimeClassName is not None:  # omit empty
            v["defaultRuntimeClassName"] = defaultRuntimeClassName
        return v

    # allowedRuntimeClassNames is a whitelist of RuntimeClass names that may be specified on a pod.
    # A value of "*" means that any RuntimeClass name is allowed, and must be the only item in the
    # list. An empty list requires the RuntimeClassName field to be unset.
    @typechecked
    def allowedRuntimeClassNames(self) -> List[str]:
        return self.__allowedRuntimeClassNames

    # defaultRuntimeClassName is the default RuntimeClassName to set on the pod.
    # The default MUST be allowed by the allowedRuntimeClassNames list.
    # A value of nil does not mutate the Pod.
    @typechecked
    def defaultRuntimeClassName(self) -> Optional[str]:
        return self.__defaultRuntimeClassName


# SELinuxStrategyOptions defines the strategy type and any options used to create the strategy.
class SELinuxStrategyOptions(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        rule: SELinuxStrategy = None,
        seLinuxOptions: "corev1.SELinuxOptions" = None,
    ):
        super().__init__(**{})
        self.__rule = rule
        self.__seLinuxOptions = seLinuxOptions

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["rule"] = self.rule()
        seLinuxOptions = self.seLinuxOptions()
        if seLinuxOptions is not None:  # omit empty
            v["seLinuxOptions"] = seLinuxOptions
        return v

    # rule is the strategy that will dictate the allowable labels that may be set.
    @typechecked
    def rule(self) -> SELinuxStrategy:
        return self.__rule

    # seLinuxOptions required to run as; required for MustRunAs
    # More info: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
    @typechecked
    def seLinuxOptions(self) -> Optional["corev1.SELinuxOptions"]:
        return self.__seLinuxOptions


# SupplementalGroupsStrategyOptions defines the strategy type and options used to create the strategy.
class SupplementalGroupsStrategyOptions(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, rule: SupplementalGroupsStrategyType = None, ranges: List[IDRange] = None
    ):
        super().__init__(**{})
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        if rule:  # omit empty
            v["rule"] = rule
        ranges = self.ranges()
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    # rule is the strategy that will dictate what supplemental groups is used in the SecurityContext.
    @typechecked
    def rule(self) -> Optional[SupplementalGroupsStrategyType]:
        return self.__rule

    # ranges are the allowed ranges of supplemental groups.  If you would like to force a single
    # supplemental group then supply a single range with the same start and end. Required for MustRunAs.
    @typechecked
    def ranges(self) -> Optional[List[IDRange]]:
        return self.__ranges


# PodSecurityPolicySpec defines the policy enforced.
class PodSecurityPolicySpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        privileged: bool = None,
        defaultAddCapabilities: List[corev1.Capability] = None,
        requiredDropCapabilities: List[corev1.Capability] = None,
        allowedCapabilities: List[corev1.Capability] = None,
        volumes: List[FSType] = None,
        hostNetwork: bool = None,
        hostPorts: List[HostPortRange] = None,
        hostPID: bool = None,
        hostIPC: bool = None,
        seLinux: SELinuxStrategyOptions = None,
        runAsUser: RunAsUserStrategyOptions = None,
        runAsGroup: RunAsGroupStrategyOptions = None,
        supplementalGroups: SupplementalGroupsStrategyOptions = None,
        fsGroup: FSGroupStrategyOptions = None,
        readOnlyRootFilesystem: bool = None,
        defaultAllowPrivilegeEscalation: bool = None,
        allowPrivilegeEscalation: bool = None,
        allowedHostPaths: List[AllowedHostPath] = None,
        allowedFlexVolumes: List[AllowedFlexVolume] = None,
        allowedCSIDrivers: Dict[str, AllowedCSIDriver] = None,
        allowedUnsafeSysctls: List[str] = None,
        forbiddenSysctls: List[str] = None,
        allowedProcMountTypes: List[corev1.ProcMountType] = None,
        runtimeClass: RuntimeClassStrategyOptions = None,
    ):
        super().__init__(**{})
        self.__privileged = privileged
        self.__defaultAddCapabilities = (
            defaultAddCapabilities if defaultAddCapabilities is not None else []
        )
        self.__requiredDropCapabilities = (
            requiredDropCapabilities if requiredDropCapabilities is not None else []
        )
        self.__allowedCapabilities = (
            allowedCapabilities if allowedCapabilities is not None else []
        )
        self.__volumes = volumes if volumes is not None else []
        self.__hostNetwork = hostNetwork
        self.__hostPorts = hostPorts if hostPorts is not None else []
        self.__hostPID = hostPID
        self.__hostIPC = hostIPC
        self.__seLinux = seLinux if seLinux is not None else SELinuxStrategyOptions()
        self.__runAsUser = (
            runAsUser if runAsUser is not None else RunAsUserStrategyOptions()
        )
        self.__runAsGroup = runAsGroup
        self.__supplementalGroups = (
            supplementalGroups
            if supplementalGroups is not None
            else SupplementalGroupsStrategyOptions()
        )
        self.__fsGroup = fsGroup if fsGroup is not None else FSGroupStrategyOptions()
        self.__readOnlyRootFilesystem = readOnlyRootFilesystem
        self.__defaultAllowPrivilegeEscalation = defaultAllowPrivilegeEscalation
        self.__allowPrivilegeEscalation = (
            allowPrivilegeEscalation if allowPrivilegeEscalation is not None else True
        )
        self.__allowedHostPaths = (
            allowedHostPaths if allowedHostPaths is not None else []
        )
        self.__allowedFlexVolumes = (
            allowedFlexVolumes if allowedFlexVolumes is not None else []
        )
        self.__allowedCSIDrivers = (
            allowedCSIDrivers if allowedCSIDrivers is not None else {}
        )
        self.__allowedUnsafeSysctls = (
            allowedUnsafeSysctls if allowedUnsafeSysctls is not None else []
        )
        self.__forbiddenSysctls = (
            forbiddenSysctls if forbiddenSysctls is not None else []
        )
        self.__allowedProcMountTypes = (
            allowedProcMountTypes if allowedProcMountTypes is not None else []
        )
        self.__runtimeClass = runtimeClass

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        privileged = self.privileged()
        if privileged:  # omit empty
            v["privileged"] = privileged
        defaultAddCapabilities = self.defaultAddCapabilities()
        if defaultAddCapabilities:  # omit empty
            v["defaultAddCapabilities"] = defaultAddCapabilities
        requiredDropCapabilities = self.requiredDropCapabilities()
        if requiredDropCapabilities:  # omit empty
            v["requiredDropCapabilities"] = requiredDropCapabilities
        allowedCapabilities = self.allowedCapabilities()
        if allowedCapabilities:  # omit empty
            v["allowedCapabilities"] = allowedCapabilities
        volumes = self.volumes()
        if volumes:  # omit empty
            v["volumes"] = volumes
        hostNetwork = self.hostNetwork()
        if hostNetwork:  # omit empty
            v["hostNetwork"] = hostNetwork
        hostPorts = self.hostPorts()
        if hostPorts:  # omit empty
            v["hostPorts"] = hostPorts
        hostPID = self.hostPID()
        if hostPID:  # omit empty
            v["hostPID"] = hostPID
        hostIPC = self.hostIPC()
        if hostIPC:  # omit empty
            v["hostIPC"] = hostIPC
        v["seLinux"] = self.seLinux()
        v["runAsUser"] = self.runAsUser()
        runAsGroup = self.runAsGroup()
        if runAsGroup is not None:  # omit empty
            v["runAsGroup"] = runAsGroup
        v["supplementalGroups"] = self.supplementalGroups()
        v["fsGroup"] = self.fsGroup()
        readOnlyRootFilesystem = self.readOnlyRootFilesystem()
        if readOnlyRootFilesystem:  # omit empty
            v["readOnlyRootFilesystem"] = readOnlyRootFilesystem
        defaultAllowPrivilegeEscalation = self.defaultAllowPrivilegeEscalation()
        if defaultAllowPrivilegeEscalation is not None:  # omit empty
            v["defaultAllowPrivilegeEscalation"] = defaultAllowPrivilegeEscalation
        allowPrivilegeEscalation = self.allowPrivilegeEscalation()
        if allowPrivilegeEscalation is not None:  # omit empty
            v["allowPrivilegeEscalation"] = allowPrivilegeEscalation
        allowedHostPaths = self.allowedHostPaths()
        if allowedHostPaths:  # omit empty
            v["allowedHostPaths"] = allowedHostPaths
        allowedFlexVolumes = self.allowedFlexVolumes()
        if allowedFlexVolumes:  # omit empty
            v["allowedFlexVolumes"] = allowedFlexVolumes
        allowedCSIDrivers = self.allowedCSIDrivers()
        if allowedCSIDrivers:  # omit empty
            v["allowedCSIDrivers"] = allowedCSIDrivers.values()  # named list
        allowedUnsafeSysctls = self.allowedUnsafeSysctls()
        if allowedUnsafeSysctls:  # omit empty
            v["allowedUnsafeSysctls"] = allowedUnsafeSysctls
        forbiddenSysctls = self.forbiddenSysctls()
        if forbiddenSysctls:  # omit empty
            v["forbiddenSysctls"] = forbiddenSysctls
        allowedProcMountTypes = self.allowedProcMountTypes()
        if allowedProcMountTypes:  # omit empty
            v["allowedProcMountTypes"] = allowedProcMountTypes
        runtimeClass = self.runtimeClass()
        if runtimeClass is not None:  # omit empty
            v["runtimeClass"] = runtimeClass
        return v

    # privileged determines if a pod can request to be run as privileged.
    @typechecked
    def privileged(self) -> Optional[bool]:
        return self.__privileged

    # defaultAddCapabilities is the default set of capabilities that will be added to the container
    # unless the pod spec specifically drops the capability.  You may not list a capability in both
    # defaultAddCapabilities and requiredDropCapabilities. Capabilities added here are implicitly
    # allowed, and need not be included in the allowedCapabilities list.
    @typechecked
    def defaultAddCapabilities(self) -> Optional[List[corev1.Capability]]:
        return self.__defaultAddCapabilities

    # requiredDropCapabilities are the capabilities that will be dropped from the container.  These
    # are required to be dropped and cannot be added.
    @typechecked
    def requiredDropCapabilities(self) -> Optional[List[corev1.Capability]]:
        return self.__requiredDropCapabilities

    # allowedCapabilities is a list of capabilities that can be requested to add to the container.
    # Capabilities in this field may be added at the pod author's discretion.
    # You must not list a capability in both allowedCapabilities and requiredDropCapabilities.
    @typechecked
    def allowedCapabilities(self) -> Optional[List[corev1.Capability]]:
        return self.__allowedCapabilities

    # volumes is a white list of allowed volume plugins. Empty indicates that
    # no volumes may be used. To allow all volumes you may use '*'.
    @typechecked
    def volumes(self) -> Optional[List[FSType]]:
        return self.__volumes

    # hostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
    @typechecked
    def hostNetwork(self) -> Optional[bool]:
        return self.__hostNetwork

    # hostPorts determines which host port ranges are allowed to be exposed.
    @typechecked
    def hostPorts(self) -> Optional[List[HostPortRange]]:
        return self.__hostPorts

    # hostPID determines if the policy allows the use of HostPID in the pod spec.
    @typechecked
    def hostPID(self) -> Optional[bool]:
        return self.__hostPID

    # hostIPC determines if the policy allows the use of HostIPC in the pod spec.
    @typechecked
    def hostIPC(self) -> Optional[bool]:
        return self.__hostIPC

    # seLinux is the strategy that will dictate the allowable labels that may be set.
    @typechecked
    def seLinux(self) -> SELinuxStrategyOptions:
        return self.__seLinux

    # runAsUser is the strategy that will dictate the allowable RunAsUser values that may be set.
    @typechecked
    def runAsUser(self) -> RunAsUserStrategyOptions:
        return self.__runAsUser

    # RunAsGroup is the strategy that will dictate the allowable RunAsGroup values that may be set.
    # If this field is omitted, the pod's RunAsGroup can take any value. This field requires the
    # RunAsGroup feature gate to be enabled.
    @typechecked
    def runAsGroup(self) -> Optional[RunAsGroupStrategyOptions]:
        return self.__runAsGroup

    # supplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
    @typechecked
    def supplementalGroups(self) -> SupplementalGroupsStrategyOptions:
        return self.__supplementalGroups

    # fsGroup is the strategy that will dictate what fs group is used by the SecurityContext.
    @typechecked
    def fsGroup(self) -> FSGroupStrategyOptions:
        return self.__fsGroup

    # readOnlyRootFilesystem when set to true will force containers to run with a read only root file
    # system.  If the container specifically requests to run with a non-read only root file system
    # the PSP should deny the pod.
    # If set to false the container may run with a read only root file system if it wishes but it
    # will not be forced to.
    @typechecked
    def readOnlyRootFilesystem(self) -> Optional[bool]:
        return self.__readOnlyRootFilesystem

    # defaultAllowPrivilegeEscalation controls the default setting for whether a
    # process can gain more privileges than its parent process.
    @typechecked
    def defaultAllowPrivilegeEscalation(self) -> Optional[bool]:
        return self.__defaultAllowPrivilegeEscalation

    # allowPrivilegeEscalation determines if a pod can request to allow
    # privilege escalation. If unspecified, defaults to true.
    @typechecked
    def allowPrivilegeEscalation(self) -> Optional[bool]:
        return self.__allowPrivilegeEscalation

    # allowedHostPaths is a white list of allowed host paths. Empty indicates
    # that all host paths may be used.
    @typechecked
    def allowedHostPaths(self) -> Optional[List[AllowedHostPath]]:
        return self.__allowedHostPaths

    # allowedFlexVolumes is a whitelist of allowed Flexvolumes.  Empty or nil indicates that all
    # Flexvolumes may be used.  This parameter is effective only when the usage of the Flexvolumes
    # is allowed in the "volumes" field.
    @typechecked
    def allowedFlexVolumes(self) -> Optional[List[AllowedFlexVolume]]:
        return self.__allowedFlexVolumes

    # AllowedCSIDrivers is a whitelist of inline CSI drivers that must be explicitly set to be embedded within a pod spec.
    # An empty value indicates that any CSI driver can be used for inline ephemeral volumes.
    # This is an alpha field, and is only honored if the API server enables the CSIInlineVolume feature gate.
    @typechecked
    def allowedCSIDrivers(self) -> Optional[Dict[str, AllowedCSIDriver]]:
        return self.__allowedCSIDrivers

    # allowedUnsafeSysctls is a list of explicitly allowed unsafe sysctls, defaults to none.
    # Each entry is either a plain sysctl name or ends in "*" in which case it is considered
    # as a prefix of allowed sysctls. Single * means all unsafe sysctls are allowed.
    # Kubelet has to whitelist all allowed unsafe sysctls explicitly to avoid rejection.
    #
    # Examples:
    # e.g. "foo/*" allows "foo/bar", "foo/baz", etc.
    # e.g. "foo.*" allows "foo.bar", "foo.baz", etc.
    @typechecked
    def allowedUnsafeSysctls(self) -> Optional[List[str]]:
        return self.__allowedUnsafeSysctls

    # forbiddenSysctls is a list of explicitly forbidden sysctls, defaults to none.
    # Each entry is either a plain sysctl name or ends in "*" in which case it is considered
    # as a prefix of forbidden sysctls. Single * means all sysctls are forbidden.
    #
    # Examples:
    # e.g. "foo/*" forbids "foo/bar", "foo/baz", etc.
    # e.g. "foo.*" forbids "foo.bar", "foo.baz", etc.
    @typechecked
    def forbiddenSysctls(self) -> Optional[List[str]]:
        return self.__forbiddenSysctls

    # AllowedProcMountTypes is a whitelist of allowed ProcMountTypes.
    # Empty or nil indicates that only the DefaultProcMountType may be used.
    # This requires the ProcMountType feature flag to be enabled.
    @typechecked
    def allowedProcMountTypes(self) -> Optional[List[corev1.ProcMountType]]:
        return self.__allowedProcMountTypes

    # runtimeClass is the strategy that will dictate the allowable RuntimeClasses for a pod.
    # If this field is omitted, the pod's runtimeClassName field is unrestricted.
    # Enforcement of this field depends on the RuntimeClass feature gate being enabled.
    @typechecked
    def runtimeClass(self) -> Optional[RuntimeClassStrategyOptions]:
        return self.__runtimeClass


# PodSecurityPolicy governs the ability to make requests that affect the Security Context
# that will be applied to a pod and container.
class PodSecurityPolicy(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: PodSecurityPolicySpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "policy/v1beta1",
                "kind": "PodSecurityPolicy",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else PodSecurityPolicySpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # spec defines the policy enforced.
    @typechecked
    def spec(self) -> Optional[PodSecurityPolicySpec]:
        return self.__spec
