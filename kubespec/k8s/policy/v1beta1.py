# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
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
    def __init__(self, path_prefix: str = None, read_only: bool = None):
        super().__init__()
        self.__path_prefix = path_prefix
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path_prefix = self.path_prefix()
        check_type("path_prefix", path_prefix, Optional[str])
        if path_prefix:  # omit empty
            v["pathPrefix"] = path_prefix
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def path_prefix(self) -> Optional[str]:
        """
        pathPrefix is the path prefix that the host volume must match.
        It does not support `*`.
        Trailing slashes are trimmed when validating the path prefix with a host path.
        
        Examples:
        `/foo` would allow `/foo`, `/foo/` and `/foo/bar`
        `/foo` would not allow `/food` or `/etc/foo`
        """
        return self.__path_prefix

    def read_only(self) -> Optional[bool]:
        """
        when set to true, will allow host volumes matching the pathPrefix only if all volume mounts are readOnly.
        """
        return self.__read_only


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
        delete_options: "metav1.DeleteOptions" = None,
    ):
        super().__init__(
            api_version="policy/v1beta1",
            kind="Eviction",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__delete_options = delete_options

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        delete_options = self.delete_options()
        check_type("delete_options", delete_options, Optional["metav1.DeleteOptions"])
        if delete_options is not None:  # omit empty
            v["deleteOptions"] = delete_options
        return v

    def delete_options(self) -> Optional["metav1.DeleteOptions"]:
        """
        DeleteOptions may be provided
        """
        return self.__delete_options


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
        min_available: Union[int, str] = None,
        selector: "metav1.LabelSelector" = None,
        max_unavailable: Union[int, str] = None,
    ):
        super().__init__()
        self.__min_available = min_available
        self.__selector = selector
        self.__max_unavailable = max_unavailable

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        min_available = self.min_available()
        check_type("min_available", min_available, Optional[Union[int, str]])
        if min_available is not None:  # omit empty
            v["minAvailable"] = min_available
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        max_unavailable = self.max_unavailable()
        check_type("max_unavailable", max_unavailable, Optional[Union[int, str]])
        if max_unavailable is not None:  # omit empty
            v["maxUnavailable"] = max_unavailable
        return v

    def min_available(self) -> Optional[Union[int, str]]:
        """
        An eviction is allowed if at least "minAvailable" pods selected by
        "selector" will still be available after the eviction, i.e. even in the
        absence of the evicted pod.  So for example you can prevent all voluntary
        evictions by specifying "100%".
        """
        return self.__min_available

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        Label query over pods whose evictions are managed by the disruption
        budget.
        """
        return self.__selector

    def max_unavailable(self) -> Optional[Union[int, str]]:
        """
        An eviction is allowed if at most "maxUnavailable" pods selected by
        "selector" are unavailable after the eviction, i.e. even in absence of
        the evicted pod. For example, one can prevent all voluntary evictions
        by specifying 0. This is a mutually exclusive setting with "minAvailable".
        """
        return self.__max_unavailable


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
            api_version="policy/v1beta1",
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
        allowed_runtime_class_names: List[str] = None,
        default_runtime_class_name: str = None,
    ):
        super().__init__()
        self.__allowed_runtime_class_names = (
            allowed_runtime_class_names
            if allowed_runtime_class_names is not None
            else []
        )
        self.__default_runtime_class_name = default_runtime_class_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        allowed_runtime_class_names = self.allowed_runtime_class_names()
        check_type(
            "allowed_runtime_class_names", allowed_runtime_class_names, List[str]
        )
        v["allowedRuntimeClassNames"] = allowed_runtime_class_names
        default_runtime_class_name = self.default_runtime_class_name()
        check_type(
            "default_runtime_class_name", default_runtime_class_name, Optional[str]
        )
        if default_runtime_class_name is not None:  # omit empty
            v["defaultRuntimeClassName"] = default_runtime_class_name
        return v

    def allowed_runtime_class_names(self) -> List[str]:
        """
        allowedRuntimeClassNames is a whitelist of RuntimeClass names that may be specified on a pod.
        A value of "*" means that any RuntimeClass name is allowed, and must be the only item in the
        list. An empty list requires the RuntimeClassName field to be unset.
        """
        return self.__allowed_runtime_class_names

    def default_runtime_class_name(self) -> Optional[str]:
        """
        defaultRuntimeClassName is the default RuntimeClassName to set on the pod.
        The default MUST be allowed by the allowedRuntimeClassNames list.
        A value of nil does not mutate the Pod.
        """
        return self.__default_runtime_class_name


class SELinuxStrategyOptions(types.Object):
    """
    SELinuxStrategyOptions defines the strategy type and any options used to create the strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        rule: SELinuxStrategy = None,
        se_linux_options: "k8sv1.SELinuxOptions" = None,
    ):
        super().__init__()
        self.__rule = rule
        self.__se_linux_options = se_linux_options

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, SELinuxStrategy)
        v["rule"] = rule
        se_linux_options = self.se_linux_options()
        check_type(
            "se_linux_options", se_linux_options, Optional["k8sv1.SELinuxOptions"]
        )
        if se_linux_options is not None:  # omit empty
            v["seLinuxOptions"] = se_linux_options
        return v

    def rule(self) -> SELinuxStrategy:
        """
        rule is the strategy that will dictate the allowable labels that may be set.
        """
        return self.__rule

    def se_linux_options(self) -> Optional["k8sv1.SELinuxOptions"]:
        """
        seLinuxOptions required to run as; required for MustRunAs
        More info: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
        """
        return self.__se_linux_options


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
        default_add_capabilities: List[k8sv1.Capability] = None,
        required_drop_capabilities: List[k8sv1.Capability] = None,
        allowed_capabilities: List[k8sv1.Capability] = None,
        volumes: List[FSType] = None,
        host_network: bool = None,
        host_ports: List["HostPortRange"] = None,
        host_pid: bool = None,
        host_ipc: bool = None,
        se_linux: "SELinuxStrategyOptions" = None,
        run_as_user: "RunAsUserStrategyOptions" = None,
        run_as_group: "RunAsGroupStrategyOptions" = None,
        supplemental_groups: "SupplementalGroupsStrategyOptions" = None,
        fs_group: "FSGroupStrategyOptions" = None,
        read_only_root_filesystem: bool = None,
        default_allow_privilege_escalation: bool = None,
        allow_privilege_escalation: bool = None,
        allowed_host_paths: List["AllowedHostPath"] = None,
        allowed_flex_volumes: List["AllowedFlexVolume"] = None,
        allowed_csi_drivers: List["AllowedCSIDriver"] = None,
        allowed_unsafe_sysctls: List[str] = None,
        forbidden_sysctls: List[str] = None,
        allowed_proc_mount_types: List[k8sv1.ProcMountType] = None,
        runtime_class: "RuntimeClassStrategyOptions" = None,
    ):
        super().__init__()
        self.__privileged = privileged
        self.__default_add_capabilities = (
            default_add_capabilities if default_add_capabilities is not None else []
        )
        self.__required_drop_capabilities = (
            required_drop_capabilities if required_drop_capabilities is not None else []
        )
        self.__allowed_capabilities = (
            allowed_capabilities if allowed_capabilities is not None else []
        )
        self.__volumes = volumes if volumes is not None else []
        self.__host_network = host_network
        self.__host_ports = host_ports if host_ports is not None else []
        self.__host_pid = host_pid
        self.__host_ipc = host_ipc
        self.__se_linux = se_linux if se_linux is not None else SELinuxStrategyOptions()
        self.__run_as_user = (
            run_as_user if run_as_user is not None else RunAsUserStrategyOptions()
        )
        self.__run_as_group = run_as_group
        self.__supplemental_groups = (
            supplemental_groups
            if supplemental_groups is not None
            else SupplementalGroupsStrategyOptions()
        )
        self.__fs_group = fs_group if fs_group is not None else FSGroupStrategyOptions()
        self.__read_only_root_filesystem = read_only_root_filesystem
        self.__default_allow_privilege_escalation = default_allow_privilege_escalation
        self.__allow_privilege_escalation = (
            allow_privilege_escalation
            if allow_privilege_escalation is not None
            else True
        )
        self.__allowed_host_paths = (
            allowed_host_paths if allowed_host_paths is not None else []
        )
        self.__allowed_flex_volumes = (
            allowed_flex_volumes if allowed_flex_volumes is not None else []
        )
        self.__allowed_csi_drivers = (
            allowed_csi_drivers if allowed_csi_drivers is not None else []
        )
        self.__allowed_unsafe_sysctls = (
            allowed_unsafe_sysctls if allowed_unsafe_sysctls is not None else []
        )
        self.__forbidden_sysctls = (
            forbidden_sysctls if forbidden_sysctls is not None else []
        )
        self.__allowed_proc_mount_types = (
            allowed_proc_mount_types if allowed_proc_mount_types is not None else []
        )
        self.__runtime_class = runtime_class

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        privileged = self.privileged()
        check_type("privileged", privileged, Optional[bool])
        if privileged:  # omit empty
            v["privileged"] = privileged
        default_add_capabilities = self.default_add_capabilities()
        check_type(
            "default_add_capabilities",
            default_add_capabilities,
            Optional[List[k8sv1.Capability]],
        )
        if default_add_capabilities:  # omit empty
            v["defaultAddCapabilities"] = default_add_capabilities
        required_drop_capabilities = self.required_drop_capabilities()
        check_type(
            "required_drop_capabilities",
            required_drop_capabilities,
            Optional[List[k8sv1.Capability]],
        )
        if required_drop_capabilities:  # omit empty
            v["requiredDropCapabilities"] = required_drop_capabilities
        allowed_capabilities = self.allowed_capabilities()
        check_type(
            "allowed_capabilities",
            allowed_capabilities,
            Optional[List[k8sv1.Capability]],
        )
        if allowed_capabilities:  # omit empty
            v["allowedCapabilities"] = allowed_capabilities
        volumes = self.volumes()
        check_type("volumes", volumes, Optional[List[FSType]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        host_network = self.host_network()
        check_type("host_network", host_network, Optional[bool])
        if host_network:  # omit empty
            v["hostNetwork"] = host_network
        host_ports = self.host_ports()
        check_type("host_ports", host_ports, Optional[List["HostPortRange"]])
        if host_ports:  # omit empty
            v["hostPorts"] = host_ports
        host_pid = self.host_pid()
        check_type("host_pid", host_pid, Optional[bool])
        if host_pid:  # omit empty
            v["hostPID"] = host_pid
        host_ipc = self.host_ipc()
        check_type("host_ipc", host_ipc, Optional[bool])
        if host_ipc:  # omit empty
            v["hostIPC"] = host_ipc
        se_linux = self.se_linux()
        check_type("se_linux", se_linux, "SELinuxStrategyOptions")
        v["seLinux"] = se_linux
        run_as_user = self.run_as_user()
        check_type("run_as_user", run_as_user, "RunAsUserStrategyOptions")
        v["runAsUser"] = run_as_user
        run_as_group = self.run_as_group()
        check_type("run_as_group", run_as_group, Optional["RunAsGroupStrategyOptions"])
        if run_as_group is not None:  # omit empty
            v["runAsGroup"] = run_as_group
        supplemental_groups = self.supplemental_groups()
        check_type(
            "supplemental_groups",
            supplemental_groups,
            "SupplementalGroupsStrategyOptions",
        )
        v["supplementalGroups"] = supplemental_groups
        fs_group = self.fs_group()
        check_type("fs_group", fs_group, "FSGroupStrategyOptions")
        v["fsGroup"] = fs_group
        read_only_root_filesystem = self.read_only_root_filesystem()
        check_type(
            "read_only_root_filesystem", read_only_root_filesystem, Optional[bool]
        )
        if read_only_root_filesystem:  # omit empty
            v["readOnlyRootFilesystem"] = read_only_root_filesystem
        default_allow_privilege_escalation = self.default_allow_privilege_escalation()
        check_type(
            "default_allow_privilege_escalation",
            default_allow_privilege_escalation,
            Optional[bool],
        )
        if default_allow_privilege_escalation is not None:  # omit empty
            v["defaultAllowPrivilegeEscalation"] = default_allow_privilege_escalation
        allow_privilege_escalation = self.allow_privilege_escalation()
        check_type(
            "allow_privilege_escalation", allow_privilege_escalation, Optional[bool]
        )
        if allow_privilege_escalation is not None:  # omit empty
            v["allowPrivilegeEscalation"] = allow_privilege_escalation
        allowed_host_paths = self.allowed_host_paths()
        check_type(
            "allowed_host_paths", allowed_host_paths, Optional[List["AllowedHostPath"]]
        )
        if allowed_host_paths:  # omit empty
            v["allowedHostPaths"] = allowed_host_paths
        allowed_flex_volumes = self.allowed_flex_volumes()
        check_type(
            "allowed_flex_volumes",
            allowed_flex_volumes,
            Optional[List["AllowedFlexVolume"]],
        )
        if allowed_flex_volumes:  # omit empty
            v["allowedFlexVolumes"] = allowed_flex_volumes
        allowed_csi_drivers = self.allowed_csi_drivers()
        check_type(
            "allowed_csi_drivers",
            allowed_csi_drivers,
            Optional[List["AllowedCSIDriver"]],
        )
        if allowed_csi_drivers:  # omit empty
            v["allowedCSIDrivers"] = allowed_csi_drivers
        allowed_unsafe_sysctls = self.allowed_unsafe_sysctls()
        check_type(
            "allowed_unsafe_sysctls", allowed_unsafe_sysctls, Optional[List[str]]
        )
        if allowed_unsafe_sysctls:  # omit empty
            v["allowedUnsafeSysctls"] = allowed_unsafe_sysctls
        forbidden_sysctls = self.forbidden_sysctls()
        check_type("forbidden_sysctls", forbidden_sysctls, Optional[List[str]])
        if forbidden_sysctls:  # omit empty
            v["forbiddenSysctls"] = forbidden_sysctls
        allowed_proc_mount_types = self.allowed_proc_mount_types()
        check_type(
            "allowed_proc_mount_types",
            allowed_proc_mount_types,
            Optional[List[k8sv1.ProcMountType]],
        )
        if allowed_proc_mount_types:  # omit empty
            v["allowedProcMountTypes"] = allowed_proc_mount_types
        runtime_class = self.runtime_class()
        check_type(
            "runtime_class", runtime_class, Optional["RuntimeClassStrategyOptions"]
        )
        if runtime_class is not None:  # omit empty
            v["runtimeClass"] = runtime_class
        return v

    def privileged(self) -> Optional[bool]:
        """
        privileged determines if a pod can request to be run as privileged.
        """
        return self.__privileged

    def default_add_capabilities(self) -> Optional[List[k8sv1.Capability]]:
        """
        defaultAddCapabilities is the default set of capabilities that will be added to the container
        unless the pod spec specifically drops the capability.  You may not list a capability in both
        defaultAddCapabilities and requiredDropCapabilities. Capabilities added here are implicitly
        allowed, and need not be included in the allowedCapabilities list.
        """
        return self.__default_add_capabilities

    def required_drop_capabilities(self) -> Optional[List[k8sv1.Capability]]:
        """
        requiredDropCapabilities are the capabilities that will be dropped from the container.  These
        are required to be dropped and cannot be added.
        """
        return self.__required_drop_capabilities

    def allowed_capabilities(self) -> Optional[List[k8sv1.Capability]]:
        """
        allowedCapabilities is a list of capabilities that can be requested to add to the container.
        Capabilities in this field may be added at the pod author's discretion.
        You must not list a capability in both allowedCapabilities and requiredDropCapabilities.
        """
        return self.__allowed_capabilities

    def volumes(self) -> Optional[List[FSType]]:
        """
        volumes is a white list of allowed volume plugins. Empty indicates that
        no volumes may be used. To allow all volumes you may use '*'.
        """
        return self.__volumes

    def host_network(self) -> Optional[bool]:
        """
        hostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
        """
        return self.__host_network

    def host_ports(self) -> Optional[List["HostPortRange"]]:
        """
        hostPorts determines which host port ranges are allowed to be exposed.
        """
        return self.__host_ports

    def host_pid(self) -> Optional[bool]:
        """
        hostPID determines if the policy allows the use of HostPID in the pod spec.
        """
        return self.__host_pid

    def host_ipc(self) -> Optional[bool]:
        """
        hostIPC determines if the policy allows the use of HostIPC in the pod spec.
        """
        return self.__host_ipc

    def se_linux(self) -> "SELinuxStrategyOptions":
        """
        seLinux is the strategy that will dictate the allowable labels that may be set.
        """
        return self.__se_linux

    def run_as_user(self) -> "RunAsUserStrategyOptions":
        """
        runAsUser is the strategy that will dictate the allowable RunAsUser values that may be set.
        """
        return self.__run_as_user

    def run_as_group(self) -> Optional["RunAsGroupStrategyOptions"]:
        """
        RunAsGroup is the strategy that will dictate the allowable RunAsGroup values that may be set.
        If this field is omitted, the pod's RunAsGroup can take any value. This field requires the
        RunAsGroup feature gate to be enabled.
        """
        return self.__run_as_group

    def supplemental_groups(self) -> "SupplementalGroupsStrategyOptions":
        """
        supplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
        """
        return self.__supplemental_groups

    def fs_group(self) -> "FSGroupStrategyOptions":
        """
        fsGroup is the strategy that will dictate what fs group is used by the SecurityContext.
        """
        return self.__fs_group

    def read_only_root_filesystem(self) -> Optional[bool]:
        """
        readOnlyRootFilesystem when set to true will force containers to run with a read only root file
        system.  If the container specifically requests to run with a non-read only root file system
        the PSP should deny the pod.
        If set to false the container may run with a read only root file system if it wishes but it
        will not be forced to.
        """
        return self.__read_only_root_filesystem

    def default_allow_privilege_escalation(self) -> Optional[bool]:
        """
        defaultAllowPrivilegeEscalation controls the default setting for whether a
        process can gain more privileges than its parent process.
        """
        return self.__default_allow_privilege_escalation

    def allow_privilege_escalation(self) -> Optional[bool]:
        """
        allowPrivilegeEscalation determines if a pod can request to allow
        privilege escalation. If unspecified, defaults to true.
        """
        return self.__allow_privilege_escalation

    def allowed_host_paths(self) -> Optional[List["AllowedHostPath"]]:
        """
        allowedHostPaths is a white list of allowed host paths. Empty indicates
        that all host paths may be used.
        """
        return self.__allowed_host_paths

    def allowed_flex_volumes(self) -> Optional[List["AllowedFlexVolume"]]:
        """
        allowedFlexVolumes is a whitelist of allowed Flexvolumes.  Empty or nil indicates that all
        Flexvolumes may be used.  This parameter is effective only when the usage of the Flexvolumes
        is allowed in the "volumes" field.
        """
        return self.__allowed_flex_volumes

    def allowed_csi_drivers(self) -> Optional[List["AllowedCSIDriver"]]:
        """
        AllowedCSIDrivers is a whitelist of inline CSI drivers that must be explicitly set to be embedded within a pod spec.
        An empty value indicates that any CSI driver can be used for inline ephemeral volumes.
        This is an alpha field, and is only honored if the API server enables the CSIInlineVolume feature gate.
        """
        return self.__allowed_csi_drivers

    def allowed_unsafe_sysctls(self) -> Optional[List[str]]:
        """
        allowedUnsafeSysctls is a list of explicitly allowed unsafe sysctls, defaults to none.
        Each entry is either a plain sysctl name or ends in "*" in which case it is considered
        as a prefix of allowed sysctls. Single * means all unsafe sysctls are allowed.
        Kubelet has to whitelist all allowed unsafe sysctls explicitly to avoid rejection.
        
        Examples:
        e.g. "foo/*" allows "foo/bar", "foo/baz", etc.
        e.g. "foo.*" allows "foo.bar", "foo.baz", etc.
        """
        return self.__allowed_unsafe_sysctls

    def forbidden_sysctls(self) -> Optional[List[str]]:
        """
        forbiddenSysctls is a list of explicitly forbidden sysctls, defaults to none.
        Each entry is either a plain sysctl name or ends in "*" in which case it is considered
        as a prefix of forbidden sysctls. Single * means all sysctls are forbidden.
        
        Examples:
        e.g. "foo/*" forbids "foo/bar", "foo/baz", etc.
        e.g. "foo.*" forbids "foo.bar", "foo.baz", etc.
        """
        return self.__forbidden_sysctls

    def allowed_proc_mount_types(self) -> Optional[List[k8sv1.ProcMountType]]:
        """
        AllowedProcMountTypes is a whitelist of allowed ProcMountTypes.
        Empty or nil indicates that only the DefaultProcMountType may be used.
        This requires the ProcMountType feature flag to be enabled.
        """
        return self.__allowed_proc_mount_types

    def runtime_class(self) -> Optional["RuntimeClassStrategyOptions"]:
        """
        runtimeClass is the strategy that will dictate the allowable RuntimeClasses for a pod.
        If this field is omitted, the pod's runtimeClassName field is unrestricted.
        Enforcement of this field depends on the RuntimeClass feature gate being enabled.
        """
        return self.__runtime_class


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
            api_version="policy/v1beta1",
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
