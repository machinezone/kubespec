# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s.core import v1 as corev1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional, Union


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


class AllowedCSIDriver(types.Object):
    """
    AllowedCSIDriver represents a single inline CSI Driver that is allowed to be used.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = ""):
        super().__init__()
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def name(self) -> str:
        """
        Name is the registered name of the CSI driver
        """
        return self.__name


class AllowedFlexVolume(types.Object):
    """
    AllowedFlexVolume represents a single Flexvolume that is allowed to be used.
    """

    @context.scoped
    @typechecked
    def __init__(self, driver: str = ""):
        super().__init__()
        self.__driver = driver

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        driver = self.driver()
        check_type("driver", driver, str)
        v["driver"] = driver
        return v

    def driver(self) -> str:
        """
        driver is the name of the Flexvolume driver.
        """
        return self.__driver


class AllowedHostPath(types.Object):
    """
    AllowedHostPath defines the host volume conditions that will be enabled by a policy
    for pods to use. It requires the path prefix to be defined.
    """

    @context.scoped
    @typechecked
    def __init__(self, pathPrefix: str = None, readOnly: bool = None):
        super().__init__()
        self.__pathPrefix = pathPrefix
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pathPrefix = self.pathPrefix()
        check_type("pathPrefix", pathPrefix, Optional[str])
        if pathPrefix:  # omit empty
            v["pathPrefix"] = pathPrefix
        readOnly = self.readOnly()
        check_type("readOnly", readOnly, Optional[bool])
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    def pathPrefix(self) -> Optional[str]:
        """
        pathPrefix is the path prefix that the host volume must match.
        It does not support `*`.
        Trailing slashes are trimmed when validating the path prefix with a host path.
        
        Examples:
        `/foo` would allow `/foo`, `/foo/` and `/foo/bar`
        `/foo` would not allow `/food` or `/etc/foo`
        """
        return self.__pathPrefix

    def readOnly(self) -> Optional[bool]:
        """
        when set to true, will allow host volumes matching the pathPrefix only if all volume mounts are readOnly.
        """
        return self.__readOnly


class Eviction(base.TypedObject, base.NamespacedMetadataObject):
    """
    Eviction evicts a pod from its node subject to certain policies and safety constraints.
    This is a subresource of Pod.  A request to cause such an eviction is
    created by POSTing to .../pods/<pod name>/evictions.
    """

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
            apiVersion="policy/v1beta1",
            kind="Eviction",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__deleteOptions = deleteOptions

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        deleteOptions = self.deleteOptions()
        check_type("deleteOptions", deleteOptions, Optional["metav1.DeleteOptions"])
        if deleteOptions is not None:  # omit empty
            v["deleteOptions"] = deleteOptions
        return v

    def deleteOptions(self) -> Optional["metav1.DeleteOptions"]:
        """
        DeleteOptions may be provided
        """
        return self.__deleteOptions


class IDRange(types.Object):
    """
    IDRange provides a min/max of an allowed range of IDs.
    """

    @context.scoped
    @typechecked
    def __init__(self, min: int = 0, max: int = 0):
        super().__init__()
        self.__min = min
        self.__max = max

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        min = self.min()
        check_type("min", min, int)
        v["min"] = min
        max = self.max()
        check_type("max", max, int)
        v["max"] = max
        return v

    def min(self) -> int:
        """
        min is the start of the range, inclusive.
        """
        return self.__min

    def max(self) -> int:
        """
        max is the end of the range, inclusive.
        """
        return self.__max


class FSGroupStrategyOptions(types.Object):
    """
    FSGroupStrategyOptions defines the strategy type and options used to create the strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, rule: FSGroupStrategyType = None, ranges: List["IDRange"] = None
    ):
        super().__init__()
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, Optional[FSGroupStrategyType])
        if rule:  # omit empty
            v["rule"] = rule
        ranges = self.ranges()
        check_type("ranges", ranges, Optional[List["IDRange"]])
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    def rule(self) -> Optional[FSGroupStrategyType]:
        """
        rule is the strategy that will dictate what FSGroup is used in the SecurityContext.
        """
        return self.__rule

    def ranges(self) -> Optional[List["IDRange"]]:
        """
        ranges are the allowed ranges of fs groups.  If you would like to force a single
        fs group then supply a single range with the same start and end. Required for MustRunAs.
        """
        return self.__ranges


class HostPortRange(types.Object):
    """
    HostPortRange defines a range of host ports that will be enabled by a policy
    for pods to use.  It requires both the start and end to be defined.
    """

    @context.scoped
    @typechecked
    def __init__(self, min: int = 0, max: int = 0):
        super().__init__()
        self.__min = min
        self.__max = max

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        min = self.min()
        check_type("min", min, int)
        v["min"] = min
        max = self.max()
        check_type("max", max, int)
        v["max"] = max
        return v

    def min(self) -> int:
        """
        min is the start of the range, inclusive.
        """
        return self.__min

    def max(self) -> int:
        """
        max is the end of the range, inclusive.
        """
        return self.__max


class PodDisruptionBudgetSpec(types.Object):
    """
    PodDisruptionBudgetSpec is a description of a PodDisruptionBudget.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        minAvailable: Union[int, str] = None,
        selector: "metav1.LabelSelector" = None,
        maxUnavailable: Union[int, str] = None,
    ):
        super().__init__()
        self.__minAvailable = minAvailable
        self.__selector = selector
        self.__maxUnavailable = maxUnavailable

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        minAvailable = self.minAvailable()
        check_type("minAvailable", minAvailable, Optional[Union[int, str]])
        if minAvailable is not None:  # omit empty
            v["minAvailable"] = minAvailable
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        maxUnavailable = self.maxUnavailable()
        check_type("maxUnavailable", maxUnavailable, Optional[Union[int, str]])
        if maxUnavailable is not None:  # omit empty
            v["maxUnavailable"] = maxUnavailable
        return v

    def minAvailable(self) -> Optional[Union[int, str]]:
        """
        An eviction is allowed if at least "minAvailable" pods selected by
        "selector" will still be available after the eviction, i.e. even in the
        absence of the evicted pod.  So for example you can prevent all voluntary
        evictions by specifying "100%".
        """
        return self.__minAvailable

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        Label query over pods whose evictions are managed by the disruption
        budget.
        """
        return self.__selector

    def maxUnavailable(self) -> Optional[Union[int, str]]:
        """
        An eviction is allowed if at most "maxUnavailable" pods selected by
        "selector" are unavailable after the eviction, i.e. even in absence of
        the evicted pod. For example, one can prevent all voluntary evictions
        by specifying 0. This is a mutually exclusive setting with "minAvailable".
        """
        return self.__maxUnavailable


class PodDisruptionBudget(base.TypedObject, base.NamespacedMetadataObject):
    """
    PodDisruptionBudget is an object to define the max disruption that can be caused to a collection of pods
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PodDisruptionBudgetSpec" = None,
    ):
        super().__init__(
            apiVersion="policy/v1beta1",
            kind="PodDisruptionBudget",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PodDisruptionBudgetSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["PodDisruptionBudgetSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["PodDisruptionBudgetSpec"]:
        """
        Specification of the desired behavior of the PodDisruptionBudget.
        """
        return self.__spec


class RunAsGroupStrategyOptions(types.Object):
    """
    RunAsGroupStrategyOptions defines the strategy type and any options used to create the strategy.
    """

    @context.scoped
    @typechecked
    def __init__(self, rule: RunAsGroupStrategy = None, ranges: List["IDRange"] = None):
        super().__init__()
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, RunAsGroupStrategy)
        v["rule"] = rule
        ranges = self.ranges()
        check_type("ranges", ranges, Optional[List["IDRange"]])
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    def rule(self) -> RunAsGroupStrategy:
        """
        rule is the strategy that will dictate the allowable RunAsGroup values that may be set.
        """
        return self.__rule

    def ranges(self) -> Optional[List["IDRange"]]:
        """
        ranges are the allowed ranges of gids that may be used. If you would like to force a single gid
        then supply a single range with the same start and end. Required for MustRunAs.
        """
        return self.__ranges


class RunAsUserStrategyOptions(types.Object):
    """
    RunAsUserStrategyOptions defines the strategy type and any options used to create the strategy.
    """

    @context.scoped
    @typechecked
    def __init__(self, rule: RunAsUserStrategy = None, ranges: List["IDRange"] = None):
        super().__init__()
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, RunAsUserStrategy)
        v["rule"] = rule
        ranges = self.ranges()
        check_type("ranges", ranges, Optional[List["IDRange"]])
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    def rule(self) -> RunAsUserStrategy:
        """
        rule is the strategy that will dictate the allowable RunAsUser values that may be set.
        """
        return self.__rule

    def ranges(self) -> Optional[List["IDRange"]]:
        """
        ranges are the allowed ranges of uids that may be used. If you would like to force a single uid
        then supply a single range with the same start and end. Required for MustRunAs.
        """
        return self.__ranges


class RuntimeClassStrategyOptions(types.Object):
    """
    RuntimeClassStrategyOptions define the strategy that will dictate the allowable RuntimeClasses
    for a pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        allowedRuntimeClassNames: List[str] = None,
        defaultRuntimeClassName: str = None,
    ):
        super().__init__()
        self.__allowedRuntimeClassNames = (
            allowedRuntimeClassNames if allowedRuntimeClassNames is not None else []
        )
        self.__defaultRuntimeClassName = defaultRuntimeClassName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        allowedRuntimeClassNames = self.allowedRuntimeClassNames()
        check_type("allowedRuntimeClassNames", allowedRuntimeClassNames, List[str])
        v["allowedRuntimeClassNames"] = allowedRuntimeClassNames
        defaultRuntimeClassName = self.defaultRuntimeClassName()
        check_type("defaultRuntimeClassName", defaultRuntimeClassName, Optional[str])
        if defaultRuntimeClassName is not None:  # omit empty
            v["defaultRuntimeClassName"] = defaultRuntimeClassName
        return v

    def allowedRuntimeClassNames(self) -> List[str]:
        """
        allowedRuntimeClassNames is a whitelist of RuntimeClass names that may be specified on a pod.
        A value of "*" means that any RuntimeClass name is allowed, and must be the only item in the
        list. An empty list requires the RuntimeClassName field to be unset.
        """
        return self.__allowedRuntimeClassNames

    def defaultRuntimeClassName(self) -> Optional[str]:
        """
        defaultRuntimeClassName is the default RuntimeClassName to set on the pod.
        The default MUST be allowed by the allowedRuntimeClassNames list.
        A value of nil does not mutate the Pod.
        """
        return self.__defaultRuntimeClassName


class SELinuxStrategyOptions(types.Object):
    """
    SELinuxStrategyOptions defines the strategy type and any options used to create the strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        rule: SELinuxStrategy = None,
        seLinuxOptions: "corev1.SELinuxOptions" = None,
    ):
        super().__init__()
        self.__rule = rule
        self.__seLinuxOptions = seLinuxOptions

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, SELinuxStrategy)
        v["rule"] = rule
        seLinuxOptions = self.seLinuxOptions()
        check_type("seLinuxOptions", seLinuxOptions, Optional["corev1.SELinuxOptions"])
        if seLinuxOptions is not None:  # omit empty
            v["seLinuxOptions"] = seLinuxOptions
        return v

    def rule(self) -> SELinuxStrategy:
        """
        rule is the strategy that will dictate the allowable labels that may be set.
        """
        return self.__rule

    def seLinuxOptions(self) -> Optional["corev1.SELinuxOptions"]:
        """
        seLinuxOptions required to run as; required for MustRunAs
        More info: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
        """
        return self.__seLinuxOptions


class SupplementalGroupsStrategyOptions(types.Object):
    """
    SupplementalGroupsStrategyOptions defines the strategy type and options used to create the strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        rule: SupplementalGroupsStrategyType = None,
        ranges: List["IDRange"] = None,
    ):
        super().__init__()
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, Optional[SupplementalGroupsStrategyType])
        if rule:  # omit empty
            v["rule"] = rule
        ranges = self.ranges()
        check_type("ranges", ranges, Optional[List["IDRange"]])
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    def rule(self) -> Optional[SupplementalGroupsStrategyType]:
        """
        rule is the strategy that will dictate what supplemental groups is used in the SecurityContext.
        """
        return self.__rule

    def ranges(self) -> Optional[List["IDRange"]]:
        """
        ranges are the allowed ranges of supplemental groups.  If you would like to force a single
        supplemental group then supply a single range with the same start and end. Required for MustRunAs.
        """
        return self.__ranges


class PodSecurityPolicySpec(types.Object):
    """
    PodSecurityPolicySpec defines the policy enforced.
    """

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
        hostPorts: List["HostPortRange"] = None,
        hostPID: bool = None,
        hostIPC: bool = None,
        seLinux: "SELinuxStrategyOptions" = None,
        runAsUser: "RunAsUserStrategyOptions" = None,
        runAsGroup: "RunAsGroupStrategyOptions" = None,
        supplementalGroups: "SupplementalGroupsStrategyOptions" = None,
        fsGroup: "FSGroupStrategyOptions" = None,
        readOnlyRootFilesystem: bool = None,
        defaultAllowPrivilegeEscalation: bool = None,
        allowPrivilegeEscalation: bool = None,
        allowedHostPaths: List["AllowedHostPath"] = None,
        allowedFlexVolumes: List["AllowedFlexVolume"] = None,
        allowedCSIDrivers: List["AllowedCSIDriver"] = None,
        allowedUnsafeSysctls: List[str] = None,
        forbiddenSysctls: List[str] = None,
        allowedProcMountTypes: List[corev1.ProcMountType] = None,
        runtimeClass: "RuntimeClassStrategyOptions" = None,
    ):
        super().__init__()
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
            allowedCSIDrivers if allowedCSIDrivers is not None else []
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
        check_type("privileged", privileged, Optional[bool])
        if privileged:  # omit empty
            v["privileged"] = privileged
        defaultAddCapabilities = self.defaultAddCapabilities()
        check_type(
            "defaultAddCapabilities",
            defaultAddCapabilities,
            Optional[List[corev1.Capability]],
        )
        if defaultAddCapabilities:  # omit empty
            v["defaultAddCapabilities"] = defaultAddCapabilities
        requiredDropCapabilities = self.requiredDropCapabilities()
        check_type(
            "requiredDropCapabilities",
            requiredDropCapabilities,
            Optional[List[corev1.Capability]],
        )
        if requiredDropCapabilities:  # omit empty
            v["requiredDropCapabilities"] = requiredDropCapabilities
        allowedCapabilities = self.allowedCapabilities()
        check_type(
            "allowedCapabilities",
            allowedCapabilities,
            Optional[List[corev1.Capability]],
        )
        if allowedCapabilities:  # omit empty
            v["allowedCapabilities"] = allowedCapabilities
        volumes = self.volumes()
        check_type("volumes", volumes, Optional[List[FSType]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        hostNetwork = self.hostNetwork()
        check_type("hostNetwork", hostNetwork, Optional[bool])
        if hostNetwork:  # omit empty
            v["hostNetwork"] = hostNetwork
        hostPorts = self.hostPorts()
        check_type("hostPorts", hostPorts, Optional[List["HostPortRange"]])
        if hostPorts:  # omit empty
            v["hostPorts"] = hostPorts
        hostPID = self.hostPID()
        check_type("hostPID", hostPID, Optional[bool])
        if hostPID:  # omit empty
            v["hostPID"] = hostPID
        hostIPC = self.hostIPC()
        check_type("hostIPC", hostIPC, Optional[bool])
        if hostIPC:  # omit empty
            v["hostIPC"] = hostIPC
        seLinux = self.seLinux()
        check_type("seLinux", seLinux, "SELinuxStrategyOptions")
        v["seLinux"] = seLinux
        runAsUser = self.runAsUser()
        check_type("runAsUser", runAsUser, "RunAsUserStrategyOptions")
        v["runAsUser"] = runAsUser
        runAsGroup = self.runAsGroup()
        check_type("runAsGroup", runAsGroup, Optional["RunAsGroupStrategyOptions"])
        if runAsGroup is not None:  # omit empty
            v["runAsGroup"] = runAsGroup
        supplementalGroups = self.supplementalGroups()
        check_type(
            "supplementalGroups",
            supplementalGroups,
            "SupplementalGroupsStrategyOptions",
        )
        v["supplementalGroups"] = supplementalGroups
        fsGroup = self.fsGroup()
        check_type("fsGroup", fsGroup, "FSGroupStrategyOptions")
        v["fsGroup"] = fsGroup
        readOnlyRootFilesystem = self.readOnlyRootFilesystem()
        check_type("readOnlyRootFilesystem", readOnlyRootFilesystem, Optional[bool])
        if readOnlyRootFilesystem:  # omit empty
            v["readOnlyRootFilesystem"] = readOnlyRootFilesystem
        defaultAllowPrivilegeEscalation = self.defaultAllowPrivilegeEscalation()
        check_type(
            "defaultAllowPrivilegeEscalation",
            defaultAllowPrivilegeEscalation,
            Optional[bool],
        )
        if defaultAllowPrivilegeEscalation is not None:  # omit empty
            v["defaultAllowPrivilegeEscalation"] = defaultAllowPrivilegeEscalation
        allowPrivilegeEscalation = self.allowPrivilegeEscalation()
        check_type("allowPrivilegeEscalation", allowPrivilegeEscalation, Optional[bool])
        if allowPrivilegeEscalation is not None:  # omit empty
            v["allowPrivilegeEscalation"] = allowPrivilegeEscalation
        allowedHostPaths = self.allowedHostPaths()
        check_type(
            "allowedHostPaths", allowedHostPaths, Optional[List["AllowedHostPath"]]
        )
        if allowedHostPaths:  # omit empty
            v["allowedHostPaths"] = allowedHostPaths
        allowedFlexVolumes = self.allowedFlexVolumes()
        check_type(
            "allowedFlexVolumes",
            allowedFlexVolumes,
            Optional[List["AllowedFlexVolume"]],
        )
        if allowedFlexVolumes:  # omit empty
            v["allowedFlexVolumes"] = allowedFlexVolumes
        allowedCSIDrivers = self.allowedCSIDrivers()
        check_type(
            "allowedCSIDrivers", allowedCSIDrivers, Optional[List["AllowedCSIDriver"]]
        )
        if allowedCSIDrivers:  # omit empty
            v["allowedCSIDrivers"] = allowedCSIDrivers
        allowedUnsafeSysctls = self.allowedUnsafeSysctls()
        check_type("allowedUnsafeSysctls", allowedUnsafeSysctls, Optional[List[str]])
        if allowedUnsafeSysctls:  # omit empty
            v["allowedUnsafeSysctls"] = allowedUnsafeSysctls
        forbiddenSysctls = self.forbiddenSysctls()
        check_type("forbiddenSysctls", forbiddenSysctls, Optional[List[str]])
        if forbiddenSysctls:  # omit empty
            v["forbiddenSysctls"] = forbiddenSysctls
        allowedProcMountTypes = self.allowedProcMountTypes()
        check_type(
            "allowedProcMountTypes",
            allowedProcMountTypes,
            Optional[List[corev1.ProcMountType]],
        )
        if allowedProcMountTypes:  # omit empty
            v["allowedProcMountTypes"] = allowedProcMountTypes
        runtimeClass = self.runtimeClass()
        check_type(
            "runtimeClass", runtimeClass, Optional["RuntimeClassStrategyOptions"]
        )
        if runtimeClass is not None:  # omit empty
            v["runtimeClass"] = runtimeClass
        return v

    def privileged(self) -> Optional[bool]:
        """
        privileged determines if a pod can request to be run as privileged.
        """
        return self.__privileged

    def defaultAddCapabilities(self) -> Optional[List[corev1.Capability]]:
        """
        defaultAddCapabilities is the default set of capabilities that will be added to the container
        unless the pod spec specifically drops the capability.  You may not list a capability in both
        defaultAddCapabilities and requiredDropCapabilities. Capabilities added here are implicitly
        allowed, and need not be included in the allowedCapabilities list.
        """
        return self.__defaultAddCapabilities

    def requiredDropCapabilities(self) -> Optional[List[corev1.Capability]]:
        """
        requiredDropCapabilities are the capabilities that will be dropped from the container.  These
        are required to be dropped and cannot be added.
        """
        return self.__requiredDropCapabilities

    def allowedCapabilities(self) -> Optional[List[corev1.Capability]]:
        """
        allowedCapabilities is a list of capabilities that can be requested to add to the container.
        Capabilities in this field may be added at the pod author's discretion.
        You must not list a capability in both allowedCapabilities and requiredDropCapabilities.
        """
        return self.__allowedCapabilities

    def volumes(self) -> Optional[List[FSType]]:
        """
        volumes is a white list of allowed volume plugins. Empty indicates that
        no volumes may be used. To allow all volumes you may use '*'.
        """
        return self.__volumes

    def hostNetwork(self) -> Optional[bool]:
        """
        hostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
        """
        return self.__hostNetwork

    def hostPorts(self) -> Optional[List["HostPortRange"]]:
        """
        hostPorts determines which host port ranges are allowed to be exposed.
        """
        return self.__hostPorts

    def hostPID(self) -> Optional[bool]:
        """
        hostPID determines if the policy allows the use of HostPID in the pod spec.
        """
        return self.__hostPID

    def hostIPC(self) -> Optional[bool]:
        """
        hostIPC determines if the policy allows the use of HostIPC in the pod spec.
        """
        return self.__hostIPC

    def seLinux(self) -> "SELinuxStrategyOptions":
        """
        seLinux is the strategy that will dictate the allowable labels that may be set.
        """
        return self.__seLinux

    def runAsUser(self) -> "RunAsUserStrategyOptions":
        """
        runAsUser is the strategy that will dictate the allowable RunAsUser values that may be set.
        """
        return self.__runAsUser

    def runAsGroup(self) -> Optional["RunAsGroupStrategyOptions"]:
        """
        RunAsGroup is the strategy that will dictate the allowable RunAsGroup values that may be set.
        If this field is omitted, the pod's RunAsGroup can take any value. This field requires the
        RunAsGroup feature gate to be enabled.
        """
        return self.__runAsGroup

    def supplementalGroups(self) -> "SupplementalGroupsStrategyOptions":
        """
        supplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
        """
        return self.__supplementalGroups

    def fsGroup(self) -> "FSGroupStrategyOptions":
        """
        fsGroup is the strategy that will dictate what fs group is used by the SecurityContext.
        """
        return self.__fsGroup

    def readOnlyRootFilesystem(self) -> Optional[bool]:
        """
        readOnlyRootFilesystem when set to true will force containers to run with a read only root file
        system.  If the container specifically requests to run with a non-read only root file system
        the PSP should deny the pod.
        If set to false the container may run with a read only root file system if it wishes but it
        will not be forced to.
        """
        return self.__readOnlyRootFilesystem

    def defaultAllowPrivilegeEscalation(self) -> Optional[bool]:
        """
        defaultAllowPrivilegeEscalation controls the default setting for whether a
        process can gain more privileges than its parent process.
        """
        return self.__defaultAllowPrivilegeEscalation

    def allowPrivilegeEscalation(self) -> Optional[bool]:
        """
        allowPrivilegeEscalation determines if a pod can request to allow
        privilege escalation. If unspecified, defaults to true.
        """
        return self.__allowPrivilegeEscalation

    def allowedHostPaths(self) -> Optional[List["AllowedHostPath"]]:
        """
        allowedHostPaths is a white list of allowed host paths. Empty indicates
        that all host paths may be used.
        """
        return self.__allowedHostPaths

    def allowedFlexVolumes(self) -> Optional[List["AllowedFlexVolume"]]:
        """
        allowedFlexVolumes is a whitelist of allowed Flexvolumes.  Empty or nil indicates that all
        Flexvolumes may be used.  This parameter is effective only when the usage of the Flexvolumes
        is allowed in the "volumes" field.
        """
        return self.__allowedFlexVolumes

    def allowedCSIDrivers(self) -> Optional[List["AllowedCSIDriver"]]:
        """
        AllowedCSIDrivers is a whitelist of inline CSI drivers that must be explicitly set to be embedded within a pod spec.
        An empty value indicates that any CSI driver can be used for inline ephemeral volumes.
        This is an alpha field, and is only honored if the API server enables the CSIInlineVolume feature gate.
        """
        return self.__allowedCSIDrivers

    def allowedUnsafeSysctls(self) -> Optional[List[str]]:
        """
        allowedUnsafeSysctls is a list of explicitly allowed unsafe sysctls, defaults to none.
        Each entry is either a plain sysctl name or ends in "*" in which case it is considered
        as a prefix of allowed sysctls. Single * means all unsafe sysctls are allowed.
        Kubelet has to whitelist all allowed unsafe sysctls explicitly to avoid rejection.
        
        Examples:
        e.g. "foo/*" allows "foo/bar", "foo/baz", etc.
        e.g. "foo.*" allows "foo.bar", "foo.baz", etc.
        """
        return self.__allowedUnsafeSysctls

    def forbiddenSysctls(self) -> Optional[List[str]]:
        """
        forbiddenSysctls is a list of explicitly forbidden sysctls, defaults to none.
        Each entry is either a plain sysctl name or ends in "*" in which case it is considered
        as a prefix of forbidden sysctls. Single * means all sysctls are forbidden.
        
        Examples:
        e.g. "foo/*" forbids "foo/bar", "foo/baz", etc.
        e.g. "foo.*" forbids "foo.bar", "foo.baz", etc.
        """
        return self.__forbiddenSysctls

    def allowedProcMountTypes(self) -> Optional[List[corev1.ProcMountType]]:
        """
        AllowedProcMountTypes is a whitelist of allowed ProcMountTypes.
        Empty or nil indicates that only the DefaultProcMountType may be used.
        This requires the ProcMountType feature flag to be enabled.
        """
        return self.__allowedProcMountTypes

    def runtimeClass(self) -> Optional["RuntimeClassStrategyOptions"]:
        """
        runtimeClass is the strategy that will dictate the allowable RuntimeClasses for a pod.
        If this field is omitted, the pod's runtimeClassName field is unrestricted.
        Enforcement of this field depends on the RuntimeClass feature gate being enabled.
        """
        return self.__runtimeClass


class PodSecurityPolicy(base.TypedObject, base.MetadataObject):
    """
    PodSecurityPolicy governs the ability to make requests that affect the Security Context
    that will be applied to a pod and container.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PodSecurityPolicySpec" = None,
    ):
        super().__init__(
            apiVersion="policy/v1beta1",
            kind="PodSecurityPolicy",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PodSecurityPolicySpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["PodSecurityPolicySpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["PodSecurityPolicySpec"]:
        """
        spec defines the policy enforced.
        """
        return self.__spec
