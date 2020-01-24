# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


# FSGroupStrategyType denotes strategy types for generating FSGroup values for a
# SecurityContext
FSGroupStrategyType = base.Enum(
    "FSGroupStrategyType",
    {
        # container must have FSGroup of X applied.
        "MustRunAs": "MustRunAs",
        # container may make requests for any FSGroup labels.
        "RunAsAny": "RunAsAny",
    },
)


# FS Type gives strong typing to different file systems that are used by volumes.
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
        "None": "none",
        "PersistentVolumeClaim": "persistentVolumeClaim",
        "PhotonPersistentDisk": "photonPersistentDisk",
        "PortworxVolume": "portworxVolume",
        "Projected": "projected",
        "Quobyte": "quobyte",
        "RBD": "rbd",
        "ScaleIO": "scaleIO",
        "Secret": "secret",
        "StorageOS": "storageOS",
        "Vsphere": "vsphere",
    },
)


# RunAsUserStrategyType denotes strategy types for generating RunAsUser values for a
# SecurityContext
RunAsUserStrategyType = base.Enum(
    "RunAsUserStrategyType",
    {
        # container must run as a particular uid.
        "MustRunAs": "MustRunAs",
        # container must run as a non-root uid
        "MustRunAsNonRoot": "MustRunAsNonRoot",
        # container must run as a particular uid.
        "MustRunAsRange": "MustRunAsRange",
        # container may make requests for any uid.
        "RunAsAny": "RunAsAny",
    },
)


# SELinuxContextStrategyType denotes strategy types for generating SELinux options for a
# SecurityContext
SELinuxContextStrategyType = base.Enum(
    "SELinuxContextStrategyType",
    {
        # container must have SELinux labels of X applied.
        "MustRunAs": "MustRunAs",
        # container may make requests for any SELinux context labels.
        "RunAsAny": "RunAsAny",
    },
)


# SupplementalGroupsStrategyType denotes strategy types for determining valid supplemental
# groups for a SecurityContext.
SupplementalGroupsStrategyType = base.Enum(
    "SupplementalGroupsStrategyType",
    {
        # container must run as a particular gid.
        "MustRunAs": "MustRunAs",
        # container may make requests for any gid.
        "RunAsAny": "RunAsAny",
    },
)


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
        Driver is the name of the Flexvolume driver.
        """
        return self.__driver


class IDRange(types.Object):
    """
    IDRange provides a min/max of an allowed range of IDs.
    TODO: this could be reused for UIDs.
    """

    @context.scoped
    @typechecked
    def __init__(self, min: int = None, max: int = None):
        super().__init__()
        self.__min = min
        self.__max = max

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        min = self.min()
        check_type("min", min, Optional[int])
        if min:  # omit empty
            v["min"] = min
        max = self.max()
        check_type("max", max, Optional[int])
        if max:  # omit empty
            v["max"] = max
        return v

    def min(self) -> Optional[int]:
        """
        Min is the start of the range, inclusive.
        """
        return self.__min

    def max(self) -> Optional[int]:
        """
        Max is the end of the range, inclusive.
        """
        return self.__max


class FSGroupStrategyOptions(types.Object):
    """
    FSGroupStrategyOptions defines the strategy type and options used to create the strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, type: FSGroupStrategyType = None, ranges: List["IDRange"] = None
    ):
        super().__init__()
        self.__type = type
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[FSGroupStrategyType])
        if type:  # omit empty
            v["type"] = type
        ranges = self.ranges()
        check_type("ranges", ranges, Optional[List["IDRange"]])
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    def type(self) -> Optional[FSGroupStrategyType]:
        """
        Type is the strategy that will dictate what FSGroup is used in the SecurityContext.
        """
        return self.__type

    def ranges(self) -> Optional[List["IDRange"]]:
        """
        Ranges are the allowed ranges of fs groups.  If you would like to force a single
        fs group then supply a single range with the same start and end.
        """
        return self.__ranges


class PodSecurityPolicyReviewSpec(types.Object):
    """
    PodSecurityPolicyReviewSpec defines specification for PodSecurityPolicyReview
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        template: "k8sv1.PodTemplateSpec" = None,
        service_account_names: List[str] = None,
    ):
        super().__init__()
        self.__template = template if template is not None else k8sv1.PodTemplateSpec()
        self.__service_account_names = (
            service_account_names if service_account_names is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        template = self.template()
        check_type("template", template, "k8sv1.PodTemplateSpec")
        v["template"] = template
        service_account_names = self.service_account_names()
        check_type("service_account_names", service_account_names, Optional[List[str]])
        if service_account_names:  # omit empty
            v["serviceAccountNames"] = service_account_names
        return v

    def template(self) -> "k8sv1.PodTemplateSpec":
        """
        template is the PodTemplateSpec to check. The template.spec.serviceAccountName field is used
        if serviceAccountNames is empty, unless the template.spec.serviceAccountName is empty,
        in which case "default" is used.
        If serviceAccountNames is specified, template.spec.serviceAccountName is ignored.
        """
        return self.__template

    def service_account_names(self) -> Optional[List[str]]:
        """
        serviceAccountNames is an optional set of ServiceAccounts to run the check with.
        If serviceAccountNames is empty, the template.spec.serviceAccountName is used,
        unless it's empty, in which case "default" is used instead.
        If serviceAccountNames is specified, template.spec.serviceAccountName is ignored.
        
        TODO: find a way to express 'all service accounts'
        """
        return self.__service_account_names


class PodSecurityPolicyReview(base.TypedObject):
    """
    PodSecurityPolicyReview checks which service accounts (not users, since that would be cluster-wide) can create the `PodTemplateSpec` in question.
    """

    @context.scoped
    @typechecked
    def __init__(self, spec: "PodSecurityPolicyReviewSpec" = None):
        super().__init__(
            api_version="security.openshift.io/v1", kind="PodSecurityPolicyReview"
        )
        self.__spec = spec if spec is not None else PodSecurityPolicyReviewSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "PodSecurityPolicyReviewSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "PodSecurityPolicyReviewSpec":
        """
        spec is the PodSecurityPolicy to check.
        """
        return self.__spec


class PodSecurityPolicySelfSubjectReviewSpec(types.Object):
    """
    PodSecurityPolicySelfSubjectReviewSpec contains specification for PodSecurityPolicySelfSubjectReview.
    """

    @context.scoped
    @typechecked
    def __init__(self, template: "k8sv1.PodTemplateSpec" = None):
        super().__init__()
        self.__template = template if template is not None else k8sv1.PodTemplateSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        template = self.template()
        check_type("template", template, "k8sv1.PodTemplateSpec")
        v["template"] = template
        return v

    def template(self) -> "k8sv1.PodTemplateSpec":
        """
        template is the PodTemplateSpec to check.
        """
        return self.__template


class PodSecurityPolicySelfSubjectReview(base.TypedObject):
    """
    PodSecurityPolicySelfSubjectReview checks whether this user/SA tuple can create the PodTemplateSpec
    """

    @context.scoped
    @typechecked
    def __init__(self, spec: "PodSecurityPolicySelfSubjectReviewSpec" = None):
        super().__init__(
            api_version="security.openshift.io/v1",
            kind="PodSecurityPolicySelfSubjectReview",
        )
        self.__spec = (
            spec if spec is not None else PodSecurityPolicySelfSubjectReviewSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "PodSecurityPolicySelfSubjectReviewSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "PodSecurityPolicySelfSubjectReviewSpec":
        """
        spec defines specification the PodSecurityPolicySelfSubjectReview.
        """
        return self.__spec


class PodSecurityPolicySubjectReviewSpec(types.Object):
    """
    PodSecurityPolicySubjectReviewSpec defines specification for PodSecurityPolicySubjectReview
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        template: "k8sv1.PodTemplateSpec" = None,
        user: str = None,
        groups: List[str] = None,
    ):
        super().__init__()
        self.__template = template if template is not None else k8sv1.PodTemplateSpec()
        self.__user = user
        self.__groups = groups if groups is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        template = self.template()
        check_type("template", template, "k8sv1.PodTemplateSpec")
        v["template"] = template
        user = self.user()
        check_type("user", user, Optional[str])
        if user:  # omit empty
            v["user"] = user
        groups = self.groups()
        check_type("groups", groups, Optional[List[str]])
        if groups:  # omit empty
            v["groups"] = groups
        return v

    def template(self) -> "k8sv1.PodTemplateSpec":
        """
        template is the PodTemplateSpec to check. If template.spec.serviceAccountName is empty it will not be defaulted.
        If its non-empty, it will be checked.
        """
        return self.__template

    def user(self) -> Optional[str]:
        """
        user is the user you're testing for.
        If you specify "user" but not "group", then is it interpreted as "What if user were not a member of any groups.
        If user and groups are empty, then the check is performed using *only* the serviceAccountName in the template.
        """
        return self.__user

    def groups(self) -> Optional[List[str]]:
        """
        groups is the groups you're testing for.
        """
        return self.__groups


class PodSecurityPolicySubjectReview(base.TypedObject):
    """
    PodSecurityPolicySubjectReview checks whether a particular user/SA tuple can create the PodTemplateSpec.
    """

    @context.scoped
    @typechecked
    def __init__(self, spec: "PodSecurityPolicySubjectReviewSpec" = None):
        super().__init__(
            api_version="security.openshift.io/v1",
            kind="PodSecurityPolicySubjectReview",
        )
        self.__spec = spec if spec is not None else PodSecurityPolicySubjectReviewSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "PodSecurityPolicySubjectReviewSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "PodSecurityPolicySubjectReviewSpec":
        """
        spec defines specification for the PodSecurityPolicySubjectReview.
        """
        return self.__spec


class RangeAllocation(base.TypedObject, base.MetadataObject):
    """
    RangeAllocation is used so we can easily expose a RangeAllocation typed for security group
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        range: str = "",
        data: bytes = None,
    ):
        super().__init__(
            api_version="security.openshift.io/v1",
            kind="RangeAllocation",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__range = range
        self.__data = data if data is not None else b""

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        range = self.range()
        check_type("range", range, str)
        v["range"] = range
        data = self.data()
        check_type("data", data, bytes)
        v["data"] = data
        return v

    def range(self) -> str:
        """
        range is a string representing a unique label for a range of uids, "1000000000-2000000000/10000".
        """
        return self.__range

    def data(self) -> bytes:
        """
        data is a byte array representing the serialized state of a range allocation.  It is a bitmap
        with each bit set to one to represent a range is taken.
        """
        return self.__data


class RunAsUserStrategyOptions(types.Object):
    """
    RunAsUserStrategyOptions defines the strategy type and any options used to create the strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: RunAsUserStrategyType = None,
        uid: int = None,
        uid_range_min: int = None,
        uid_range_max: int = None,
    ):
        super().__init__()
        self.__type = type
        self.__uid = uid
        self.__uid_range_min = uid_range_min
        self.__uid_range_max = uid_range_max

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[RunAsUserStrategyType])
        if type:  # omit empty
            v["type"] = type
        uid = self.uid()
        check_type("uid", uid, Optional[int])
        if uid is not None:  # omit empty
            v["uid"] = uid
        uid_range_min = self.uid_range_min()
        check_type("uid_range_min", uid_range_min, Optional[int])
        if uid_range_min is not None:  # omit empty
            v["uidRangeMin"] = uid_range_min
        uid_range_max = self.uid_range_max()
        check_type("uid_range_max", uid_range_max, Optional[int])
        if uid_range_max is not None:  # omit empty
            v["uidRangeMax"] = uid_range_max
        return v

    def type(self) -> Optional[RunAsUserStrategyType]:
        """
        Type is the strategy that will dictate what RunAsUser is used in the SecurityContext.
        """
        return self.__type

    def uid(self) -> Optional[int]:
        """
        UID is the user id that containers must run as.  Required for the MustRunAs strategy if not using
        namespace/service account allocated uids.
        """
        return self.__uid

    def uid_range_min(self) -> Optional[int]:
        """
        UIDRangeMin defines the min value for a strategy that allocates by range.
        """
        return self.__uid_range_min

    def uid_range_max(self) -> Optional[int]:
        """
        UIDRangeMax defines the max value for a strategy that allocates by range.
        """
        return self.__uid_range_max


class SELinuxContextStrategyOptions(types.Object):
    """
    SELinuxContextStrategyOptions defines the strategy type and any options used to create the strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: SELinuxContextStrategyType = None,
        se_linux_options: "k8sv1.SELinuxOptions" = None,
    ):
        super().__init__()
        self.__type = type
        self.__se_linux_options = se_linux_options

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[SELinuxContextStrategyType])
        if type:  # omit empty
            v["type"] = type
        se_linux_options = self.se_linux_options()
        check_type(
            "se_linux_options", se_linux_options, Optional["k8sv1.SELinuxOptions"]
        )
        if se_linux_options is not None:  # omit empty
            v["seLinuxOptions"] = se_linux_options
        return v

    def type(self) -> Optional[SELinuxContextStrategyType]:
        """
        Type is the strategy that will dictate what SELinux context is used in the SecurityContext.
        """
        return self.__type

    def se_linux_options(self) -> Optional["k8sv1.SELinuxOptions"]:
        """
        seLinuxOptions required to run as; required for MustRunAs
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
        type: SupplementalGroupsStrategyType = None,
        ranges: List["IDRange"] = None,
    ):
        super().__init__()
        self.__type = type
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[SupplementalGroupsStrategyType])
        if type:  # omit empty
            v["type"] = type
        ranges = self.ranges()
        check_type("ranges", ranges, Optional[List["IDRange"]])
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    def type(self) -> Optional[SupplementalGroupsStrategyType]:
        """
        Type is the strategy that will dictate what supplemental groups is used in the SecurityContext.
        """
        return self.__type

    def ranges(self) -> Optional[List["IDRange"]]:
        """
        Ranges are the allowed ranges of supplemental groups.  If you would like to force a single
        supplemental group then supply a single range with the same start and end.
        """
        return self.__ranges


class SecurityContextConstraints(base.TypedObject, base.MetadataObject):
    """
    SecurityContextConstraints governs the ability to make requests that affect the SecurityContext
    that will be applied to a container.
    For historical reasons SCC was exposed under the core Kubernetes API group.
    That exposure is deprecated and will be removed in a future release - users
    should instead use the security.openshift.io group to manage
    SecurityContextConstraints.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        priority: int = None,
        allow_privileged_container: bool = False,
        default_add_capabilities: List[k8sv1.Capability] = None,
        required_drop_capabilities: List[k8sv1.Capability] = None,
        allowed_capabilities: List[k8sv1.Capability] = None,
        allow_host_dir_volume_plugin: bool = False,
        volumes: List[FSType] = None,
        allowed_flex_volumes: List["AllowedFlexVolume"] = None,
        allow_host_network: bool = False,
        allow_host_ports: bool = False,
        allow_host_pid: bool = False,
        allow_host_ipc: bool = False,
        default_allow_privilege_escalation: bool = None,
        allow_privilege_escalation: bool = None,
        se_linux_context: "SELinuxContextStrategyOptions" = None,
        run_as_user: "RunAsUserStrategyOptions" = None,
        supplemental_groups: "SupplementalGroupsStrategyOptions" = None,
        fs_group: "FSGroupStrategyOptions" = None,
        read_only_root_filesystem: bool = False,
        users: List[str] = None,
        groups: List[str] = None,
        seccomp_profiles: List[str] = None,
        allowed_unsafe_sysctls: List[str] = None,
        forbidden_sysctls: List[str] = None,
    ):
        super().__init__(
            api_version="security.openshift.io/v1",
            kind="SecurityContextConstraints",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__priority = priority
        self.__allow_privileged_container = allow_privileged_container
        self.__default_add_capabilities = (
            default_add_capabilities if default_add_capabilities is not None else []
        )
        self.__required_drop_capabilities = (
            required_drop_capabilities if required_drop_capabilities is not None else []
        )
        self.__allowed_capabilities = (
            allowed_capabilities if allowed_capabilities is not None else []
        )
        self.__allow_host_dir_volume_plugin = allow_host_dir_volume_plugin
        self.__volumes = volumes if volumes is not None else []
        self.__allowed_flex_volumes = (
            allowed_flex_volumes if allowed_flex_volumes is not None else []
        )
        self.__allow_host_network = allow_host_network
        self.__allow_host_ports = allow_host_ports
        self.__allow_host_pid = allow_host_pid
        self.__allow_host_ipc = allow_host_ipc
        self.__default_allow_privilege_escalation = default_allow_privilege_escalation
        self.__allow_privilege_escalation = allow_privilege_escalation
        self.__se_linux_context = (
            se_linux_context
            if se_linux_context is not None
            else SELinuxContextStrategyOptions()
        )
        self.__run_as_user = (
            run_as_user if run_as_user is not None else RunAsUserStrategyOptions()
        )
        self.__supplemental_groups = (
            supplemental_groups
            if supplemental_groups is not None
            else SupplementalGroupsStrategyOptions()
        )
        self.__fs_group = fs_group if fs_group is not None else FSGroupStrategyOptions()
        self.__read_only_root_filesystem = read_only_root_filesystem
        self.__users = users if users is not None else []
        self.__groups = groups if groups is not None else []
        self.__seccomp_profiles = (
            seccomp_profiles if seccomp_profiles is not None else []
        )
        self.__allowed_unsafe_sysctls = (
            allowed_unsafe_sysctls if allowed_unsafe_sysctls is not None else []
        )
        self.__forbidden_sysctls = (
            forbidden_sysctls if forbidden_sysctls is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        priority = self.priority()
        check_type("priority", priority, Optional[int])
        v["priority"] = priority
        allow_privileged_container = self.allow_privileged_container()
        check_type("allow_privileged_container", allow_privileged_container, bool)
        v["allowPrivilegedContainer"] = allow_privileged_container
        default_add_capabilities = self.default_add_capabilities()
        check_type(
            "default_add_capabilities", default_add_capabilities, List[k8sv1.Capability]
        )
        v["defaultAddCapabilities"] = default_add_capabilities
        required_drop_capabilities = self.required_drop_capabilities()
        check_type(
            "required_drop_capabilities",
            required_drop_capabilities,
            List[k8sv1.Capability],
        )
        v["requiredDropCapabilities"] = required_drop_capabilities
        allowed_capabilities = self.allowed_capabilities()
        check_type("allowed_capabilities", allowed_capabilities, List[k8sv1.Capability])
        v["allowedCapabilities"] = allowed_capabilities
        allow_host_dir_volume_plugin = self.allow_host_dir_volume_plugin()
        check_type("allow_host_dir_volume_plugin", allow_host_dir_volume_plugin, bool)
        v["allowHostDirVolumePlugin"] = allow_host_dir_volume_plugin
        volumes = self.volumes()
        check_type("volumes", volumes, List[FSType])
        v["volumes"] = volumes
        allowed_flex_volumes = self.allowed_flex_volumes()
        check_type(
            "allowed_flex_volumes",
            allowed_flex_volumes,
            Optional[List["AllowedFlexVolume"]],
        )
        if allowed_flex_volumes:  # omit empty
            v["allowedFlexVolumes"] = allowed_flex_volumes
        allow_host_network = self.allow_host_network()
        check_type("allow_host_network", allow_host_network, bool)
        v["allowHostNetwork"] = allow_host_network
        allow_host_ports = self.allow_host_ports()
        check_type("allow_host_ports", allow_host_ports, bool)
        v["allowHostPorts"] = allow_host_ports
        allow_host_pid = self.allow_host_pid()
        check_type("allow_host_pid", allow_host_pid, bool)
        v["allowHostPID"] = allow_host_pid
        allow_host_ipc = self.allow_host_ipc()
        check_type("allow_host_ipc", allow_host_ipc, bool)
        v["allowHostIPC"] = allow_host_ipc
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
        se_linux_context = self.se_linux_context()
        check_type(
            "se_linux_context",
            se_linux_context,
            Optional["SELinuxContextStrategyOptions"],
        )
        v["seLinuxContext"] = se_linux_context
        run_as_user = self.run_as_user()
        check_type("run_as_user", run_as_user, Optional["RunAsUserStrategyOptions"])
        v["runAsUser"] = run_as_user
        supplemental_groups = self.supplemental_groups()
        check_type(
            "supplemental_groups",
            supplemental_groups,
            Optional["SupplementalGroupsStrategyOptions"],
        )
        v["supplementalGroups"] = supplemental_groups
        fs_group = self.fs_group()
        check_type("fs_group", fs_group, Optional["FSGroupStrategyOptions"])
        v["fsGroup"] = fs_group
        read_only_root_filesystem = self.read_only_root_filesystem()
        check_type("read_only_root_filesystem", read_only_root_filesystem, bool)
        v["readOnlyRootFilesystem"] = read_only_root_filesystem
        users = self.users()
        check_type("users", users, List[str])
        v["users"] = users
        groups = self.groups()
        check_type("groups", groups, List[str])
        v["groups"] = groups
        seccomp_profiles = self.seccomp_profiles()
        check_type("seccomp_profiles", seccomp_profiles, Optional[List[str]])
        if seccomp_profiles:  # omit empty
            v["seccompProfiles"] = seccomp_profiles
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
        return v

    def priority(self) -> Optional[int]:
        """
        Priority influences the sort order of SCCs when evaluating which SCCs to try first for
        a given pod request based on access in the Users and Groups fields.  The higher the int, the
        higher priority. An unset value is considered a 0 priority. If scores
        for multiple SCCs are equal they will be sorted from most restrictive to
        least restrictive. If both priorities and restrictions are equal the
        SCCs will be sorted by name.
        +nullable
        """
        return self.__priority

    def allow_privileged_container(self) -> bool:
        """
        AllowPrivilegedContainer determines if a container can request to be run as privileged.
        """
        return self.__allow_privileged_container

    def default_add_capabilities(self) -> List[k8sv1.Capability]:
        """
        DefaultAddCapabilities is the default set of capabilities that will be added to the container
        unless the pod spec specifically drops the capability.  You may not list a capabiility in both
        DefaultAddCapabilities and RequiredDropCapabilities.
        +nullable
        """
        return self.__default_add_capabilities

    def required_drop_capabilities(self) -> List[k8sv1.Capability]:
        """
        RequiredDropCapabilities are the capabilities that will be dropped from the container.  These
        are required to be dropped and cannot be added.
        +nullable
        """
        return self.__required_drop_capabilities

    def allowed_capabilities(self) -> List[k8sv1.Capability]:
        """
        AllowedCapabilities is a list of capabilities that can be requested to add to the container.
        Capabilities in this field maybe added at the pod author's discretion.
        You must not list a capability in both AllowedCapabilities and RequiredDropCapabilities.
        To allow all capabilities you may use '*'.
        +nullable
        """
        return self.__allowed_capabilities

    def allow_host_dir_volume_plugin(self) -> bool:
        """
        AllowHostDirVolumePlugin determines if the policy allow containers to use the HostDir volume plugin
        """
        return self.__allow_host_dir_volume_plugin

    def volumes(self) -> List[FSType]:
        """
        Volumes is a white list of allowed volume plugins.  FSType corresponds directly with the field names
        of a VolumeSource (azureFile, configMap, emptyDir).  To allow all volumes you may use "*".
        To allow no volumes, set to ["none"].
        +nullable
        """
        return self.__volumes

    def allowed_flex_volumes(self) -> Optional[List["AllowedFlexVolume"]]:
        """
        AllowedFlexVolumes is a whitelist of allowed Flexvolumes.  Empty or nil indicates that all
        Flexvolumes may be used.  This parameter is effective only when the usage of the Flexvolumes
        is allowed in the "Volumes" field.
        +nullable
        """
        return self.__allowed_flex_volumes

    def allow_host_network(self) -> bool:
        """
        AllowHostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
        """
        return self.__allow_host_network

    def allow_host_ports(self) -> bool:
        """
        AllowHostPorts determines if the policy allows host ports in the containers.
        """
        return self.__allow_host_ports

    def allow_host_pid(self) -> bool:
        """
        AllowHostPID determines if the policy allows host pid in the containers.
        """
        return self.__allow_host_pid

    def allow_host_ipc(self) -> bool:
        """
        AllowHostIPC determines if the policy allows host ipc in the containers.
        """
        return self.__allow_host_ipc

    def default_allow_privilege_escalation(self) -> Optional[bool]:
        """
        DefaultAllowPrivilegeEscalation controls the default setting for whether a
        process can gain more privileges than its parent process.
        +nullable
        """
        return self.__default_allow_privilege_escalation

    def allow_privilege_escalation(self) -> Optional[bool]:
        """
        AllowPrivilegeEscalation determines if a pod can request to allow
        privilege escalation. If unspecified, defaults to true.
        +nullable
        """
        return self.__allow_privilege_escalation

    def se_linux_context(self) -> Optional["SELinuxContextStrategyOptions"]:
        """
        SELinuxContext is the strategy that will dictate what labels will be set in the SecurityContext.
        +nullable
        """
        return self.__se_linux_context

    def run_as_user(self) -> Optional["RunAsUserStrategyOptions"]:
        """
        RunAsUser is the strategy that will dictate what RunAsUser is used in the SecurityContext.
        +nullable
        """
        return self.__run_as_user

    def supplemental_groups(self) -> Optional["SupplementalGroupsStrategyOptions"]:
        """
        SupplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
        +nullable
        """
        return self.__supplemental_groups

    def fs_group(self) -> Optional["FSGroupStrategyOptions"]:
        """
        FSGroup is the strategy that will dictate what fs group is used by the SecurityContext.
        +nullable
        """
        return self.__fs_group

    def read_only_root_filesystem(self) -> bool:
        """
        ReadOnlyRootFilesystem when set to true will force containers to run with a read only root file
        system.  If the container specifically requests to run with a non-read only root file system
        the SCC should deny the pod.
        If set to false the container may run with a read only root file system if it wishes but it
        will not be forced to.
        """
        return self.__read_only_root_filesystem

    def users(self) -> List[str]:
        """
        The users who have permissions to use this security context constraints
        +nullable
        """
        return self.__users

    def groups(self) -> List[str]:
        """
        The groups that have permission to use this security context constraints
        +nullable
        """
        return self.__groups

    def seccomp_profiles(self) -> Optional[List[str]]:
        """
        SeccompProfiles lists the allowed profiles that may be set for the pod or
        container's seccomp annotations.  An unset (nil) or empty value means that no profiles may
        be specifid by the pod or container.	The wildcard '*' may be used to allow all profiles.  When
        used to generate a value for a pod the first non-wildcard profile will be used as
        the default.
        +nullable
        """
        return self.__seccomp_profiles

    def allowed_unsafe_sysctls(self) -> Optional[List[str]]:
        """
        AllowedUnsafeSysctls is a list of explicitly allowed unsafe sysctls, defaults to none.
        Each entry is either a plain sysctl name or ends in "*" in which case it is considered
        as a prefix of allowed sysctls. Single * means all unsafe sysctls are allowed.
        Kubelet has to whitelist all allowed unsafe sysctls explicitly to avoid rejection.
        
        Examples:
        e.g. "foo/*" allows "foo/bar", "foo/baz", etc.
        e.g. "foo.*" allows "foo.bar", "foo.baz", etc.
        +nullable
        """
        return self.__allowed_unsafe_sysctls

    def forbidden_sysctls(self) -> Optional[List[str]]:
        """
        ForbiddenSysctls is a list of explicitly forbidden sysctls, defaults to none.
        Each entry is either a plain sysctl name or ends in "*" in which case it is considered
        as a prefix of forbidden sysctls. Single * means all sysctls are forbidden.
        
        Examples:
        e.g. "foo/*" forbids "foo/bar", "foo/baz", etc.
        e.g. "foo.*" forbids "foo.bar", "foo.baz", etc.
        +nullable
        """
        return self.__forbidden_sysctls
