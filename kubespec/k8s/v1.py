# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import resource
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional, Union


AzureDataDiskCachingMode = base.Enum(
    "AzureDataDiskCachingMode",
    {"None": "None", "ReadOnly": "ReadOnly", "ReadWrite": "ReadWrite"},
)


AzureDataDiskKind = base.Enum(
    "AzureDataDiskKind",
    {"Dedicated": "Dedicated", "Managed": "Managed", "Shared": "Shared"},
)


# See: https://en.wikibooks.org/wiki/Grsecurity/Appendix/Capability_Names_and_Descriptions
Capability = base.Enum(
    "Capability",
    {
        "ALL": "ALL",
        "AUDIT_CONTROL": "AUDIT_CONTROL",
        "AUDIT_WRITE": "AUDIT_WRITE",
        "CHOWN": "CHOWN",
        "DAC_OVERRIDE": "DAC_OVERRIDE",
        "DAC_READ_SEARCH": "DAC_READ_SEARCH",
        "FOWNER": "FOWNER",
        "FSETID": "FSETID",
        "IPC_LOCK": "IPC_LOCK",
        "IPC_OWNER": "IPC_OWNER",
        "KILL": "KILL",
        "LEASE": "LEASE",
        "LINUX_IMMUTABLE": "LINUX_IMMUTABLE",
        "MAC_ADMIN": "MAC_ADMIN",
        "MAC_OVERRIDE": "MAC_OVERRIDE",
        "MKNOD": "MKNOD",
        "NET_ADMIN": "NET_ADMIN",
        "NET_BIND_SERVICE": "NET_BIND_SERVICE",
        "NET_BROADCAST": "NET_BROADCAST",
        "NET_RAW": "NET_RAW",
        "SETFCAP": "SETFCAP",
        "SETGID": "SETGID",
        "SETPCAP": "SETPCAP",
        "SETUID": "SETUID",
        "SYSLOG": "SYSLOG",
        "SYS_ADMIN": "SYS_ADMIN",
        "SYS_BOOT": "SYS_BOOT",
        "SYS_CHROOT": "SYS_CHROOT",
        "SYS_MODULE": "SYS_MODULE",
        "SYS_NICE": "SYS_NICE",
        "SYS_PACCT": "SYS_PACCT",
        "SYS_PTRACE": "SYS_PTRACE",
        "SYS_RAWIO": "SYS_RAWIO",
        "SYS_RESOURCE": "SYS_RESOURCE",
        "SYS_TIME": "SYS_TIME",
        "SYS_TTY_CONFIG": "SYS_TTY_CONFIG",
        "WAKE_ALARM": "WAKE_ALARM",
    },
)


# Type and constants for component health validation.
ComponentConditionType = base.Enum(
    "ComponentConditionType",
    {
        # These are the valid conditions for the component.
        "Healthy": "Healthy"
    },
)


ConditionStatus = base.Enum(
    "ConditionStatus",
    {
        # These are valid condition statuses. "ConditionTrue" means a resource is in the condition.
        # "False" means a resource is not in the condition. "ConditionUnknown" means kubernetes
        # can't decide if a resource is in the condition or not. In the future, we could add other
        # intermediate conditions, e.g. ConditionDegraded.
        "False": "False",
        # These are valid condition statuses. "True" means a resource is in the condition.
        # "ConditionFalse" means a resource is not in the condition. "ConditionUnknown" means kubernetes
        # can't decide if a resource is in the condition or not. In the future, we could add other
        # intermediate conditions, e.g. ConditionDegraded.
        "True": "True",
        # These are valid condition statuses. "ConditionTrue" means a resource is in the condition.
        # "ConditionFalse" means a resource is not in the condition. "Unknown" means kubernetes
        # can't decide if a resource is in the condition or not. In the future, we could add other
        # intermediate conditions, e.g. ConditionDegraded.
        "Unknown": "Unknown",
    },
)


# DNSPolicy defines how a pod's DNS will be configured.
DNSPolicy = base.Enum(
    "DNSPolicy",
    {
        # ClusterFirst indicates that the pod should use cluster DNS
        # first unless hostNetwork is true, if it is available, then
        # fall back on the default (as determined by kubelet) DNS settings.
        "ClusterFirst": "ClusterFirst",
        # ClusterFirstWithHostNet indicates that the pod should use cluster DNS
        # first, if it is available, then fall back on the default
        # (as determined by kubelet) DNS settings.
        "ClusterFirstWithHostNet": "ClusterFirstWithHostNet",
        # Default indicates that the pod should use the default (as
        # determined by kubelet) DNS settings.
        "Default": "Default",
        # None indicates that the pod should use empty DNS settings. DNS
        # parameters such as nameservers and search paths should be defined via
        # DNSConfig.
        "None": "None",
    },
)


# FinalizerName is the name identifying a finalizer during namespace lifecycle.
FinalizerName = base.Enum(
    "FinalizerName",
    {
        # These are internal finalizer values to Kubernetes, must be qualified name unless defined here or
        # in metav1.
        "Kubernetes": "kubernetes"
    },
)


HostPathType = base.Enum(
    "HostPathType",
    {
        # A block device must exist at the given path
        "BlockDev": "BlockDevice",
        # A character device must exist at the given path
        "CharDev": "CharDevice",
        # A directory must exist at the given path
        "Directory": "Directory",
        # If nothing exists at the given path, an empty directory will be created there
        # as needed with file mode 0755, having the same group and ownership with Kubelet.
        "DirectoryOrCreate": "DirectoryOrCreate",
        # A file must exist at the given path
        "File": "File",
        # If nothing exists at the given path, an empty file will be created there
        # as needed with file mode 0644, having the same group and ownership with Kubelet.
        "FileOrCreate": "FileOrCreate",
        # A UNIX socket must exist at the given path
        "Socket": "Socket",
        # For backwards compatible, leave it empty if unset
        "Unset": "",
    },
)


# IPFamily represents the IP Family (IPv4 or IPv6). This type is used
# to express the family of an IP expressed by a type (i.e. service.Spec.IPFamily)
IPFamily = base.Enum(
    "IPFamily",
    {
        # IPv4 indicates that this IP is IPv4 protocol
        "IPv4": "IPv4",
        # IPv6 indicates that this IP is IPv6 protocol
        "IPv6": "IPv6",
    },
)


# LimitType is a type of object that is limited
LimitType = base.Enum(
    "LimitType",
    {
        # Limit that applies to all containers in a namespace
        "Container": "Container",
        # Limit that applies to all persistent volume claims in a namespace
        "PersistentVolumeClaim": "PersistentVolumeClaim",
        # Limit that applies to all pods in a namespace
        "Pod": "Pod",
    },
)


# MountPropagationMode describes mount propagation.
MountPropagationMode = base.Enum(
    "MountPropagationMode",
    {
        # Bidirectional means that the volume in a container will
        # receive new mounts from the host or other containers, and its own mounts
        # will be propagated from the container to the host or other containers.
        # Note that this mode is recursively applied to all mounts in the volume
        # ("rshared" in Linux terminology).
        "Bidirectional": "Bidirectional",
        # HostToContainer means that the volume in a container will
        # receive new mounts from the host or other containers, but filesystems
        # mounted inside the container won't be propagated to the host or other
        # containers.
        # Note that this mode is recursively applied to all mounts in the volume
        # ("rslave" in Linux terminology).
        "HostToContainer": "HostToContainer",
        # None means that the volume in a container will
        # not receive new mounts from the host or other containers, and filesystems
        # mounted inside the container won't be propagated to the host or other
        # containers.
        # Note that this mode corresponds to "private" in Linux terminology.
        "None": "None",
    },
)


# A node selector operator is the set of operators that can be used in
# a node selector requirement.
NodeSelectorOperator = base.Enum(
    "NodeSelectorOperator",
    {
        "DoesNotExist": "DoesNotExist",
        "Exists": "Exists",
        "Gt": "Gt",
        "In": "In",
        "Lt": "Lt",
        "NotIn": "NotIn",
    },
)


PersistentVolumeAccessMode = base.Enum(
    "PersistentVolumeAccessMode",
    {
        # can be mounted in read-only mode to many hosts
        "ReadOnlyMany": "ReadOnlyMany",
        # can be mounted in read/write mode to many hosts
        "ReadWriteMany": "ReadWriteMany",
        # can be mounted in read/write mode to exactly 1 host
        "ReadWriteOnce": "ReadWriteOnce",
    },
)


# PersistentVolumeMode describes how a volume is intended to be consumed, either Block or Filesystem.
PersistentVolumeMode = base.Enum(
    "PersistentVolumeMode",
    {
        # Block means the volume will not be formatted with a filesystem and will remain a raw block device.
        "Block": "Block",
        # Filesystem means the volume will be or is formatted with a filesystem.
        "Filesystem": "Filesystem",
    },
)


# PersistentVolumeReclaimPolicy describes a policy for end-of-life maintenance of persistent volumes.
PersistentVolumeReclaimPolicy = base.Enum(
    "PersistentVolumeReclaimPolicy",
    {
        # Delete means the volume will be deleted from Kubernetes on release from its claim.
        # The volume plugin must support Deletion.
        "Delete": "Delete",
        # Recycle means the volume will be recycled back into the pool of unbound persistent volumes on release from its claim.
        # The volume plugin must support Recycling.
        "Recycle": "Recycle",
        # Retain means the volume will be left in its current phase (Released) for manual reclamation by the administrator.
        # The default policy is Retain.
        "Retain": "Retain",
    },
)


# PodConditionType is a valid value for PodCondition.Type
PodConditionType = base.Enum(
    "PodConditionType",
    {
        # ContainersReady indicates whether all containers in the pod are ready.
        "ContainersReady": "ContainersReady",
        # Initialized means that all init containers in the pod have started successfully.
        "Initialized": "Initialized",
        # PodScheduled represents status of the scheduling process for this pod.
        "PodScheduled": "PodScheduled",
        # Ready means the pod is able to service requests and should be added to the
        # load balancing pools of all matching services.
        "Ready": "Ready",
    },
)


# PreemptionPolicy describes a policy for if/when to preempt a pod.
PreemptionPolicy = base.Enum(
    "PreemptionPolicy",
    {
        # Never means that pod never preempts other pods with lower priority.
        "Never": "Never",
        # PreemptLowerPriority means that pod can preempt other pods with lower priority.
        "PreemptLowerPriority": "PreemptLowerPriority",
    },
)


ProcMountType = base.Enum(
    "ProcMountType",
    {
        # Default uses the container runtime defaults for readonly and masked
        # paths for /proc.  Most container runtimes mask certain paths in /proc to avoid
        # accidental security exposure of special devices or information.
        "Default": "Default",
        # Unmasked bypasses the default masking behavior of the container
        # runtime and ensures the newly created /proc the container stays in tact with
        # no modifications.
        "Unmasked": "Unmasked",
    },
)


# Protocol defines network protocols supported for things like container ports.
Protocol = base.Enum(
    "Protocol",
    {
        # SCTP is the SCTP protocol.
        "SCTP": "SCTP",
        # TCP is the TCP protocol.
        "TCP": "TCP",
        # UDP is the UDP protocol.
        "UDP": "UDP",
    },
)


# PullPolicy describes a policy for if/when to pull a container image
PullPolicy = base.Enum(
    "PullPolicy",
    {
        # Always means that kubelet always attempts to pull the latest image. Container will fail If the pull fails.
        "Always": "Always",
        # IfNotPresent means that kubelet pulls if the image isn't present on disk. Container will fail if the image isn't present and the pull fails.
        "IfNotPresent": "IfNotPresent",
        # Never means that kubelet never pulls an image, but only uses a local image. Container will fail if the image isn't present
        "Never": "Never",
    },
)


# ResourceName is the name identifying various resources in a ResourceList.
ResourceName = base.Enum(
    "ResourceName",
    {
        # CPU, in cores. (500m = .5 cores)
        "CPU": "cpu",
        # ConfigMaps, number
        "ConfigMaps": "configmaps",
        # Local ephemeral storage, in bytes. (500Gi = 500GiB = 500 * 1024 * 1024 * 1024)
        # The resource name for EphemeralStorage is alpha and it can change across releases.
        "EphemeralStorage": "ephemeral-storage",
        # CPU limit, in cores. (500m = .5 cores)
        "LimitsCPU": "limits.cpu",
        # Local ephemeral storage limit, in bytes. (500Gi = 500GiB = 500 * 1024 * 1024 * 1024)
        "LimitsEphemeralStorage": "limits.ephemeral-storage",
        # Memory limit, in bytes. (500Gi = 500GiB = 500 * 1024 * 1024 * 1024)
        "LimitsMemory": "limits.memory",
        # Memory, in bytes. (500Gi = 500GiB = 500 * 1024 * 1024 * 1024)
        "Memory": "memory",
        # PersistentVolumeClaims, number
        "PersistentVolumeClaims": "persistentvolumeclaims",
        # Pods, number
        "Pods": "pods",
        # ReplicationControllers, number
        "ReplicationControllers": "replicationcontrollers",
        # CPU request, in cores. (500m = .5 cores)
        "RequestsCPU": "requests.cpu",
        # Local ephemeral storage request, in bytes. (500Gi = 500GiB = 500 * 1024 * 1024 * 1024)
        "RequestsEphemeralStorage": "requests.ephemeral-storage",
        # Memory request, in bytes. (500Gi = 500GiB = 500 * 1024 * 1024 * 1024)
        "RequestsMemory": "requests.memory",
        # Storage request, in bytes
        "RequestsStorage": "requests.storage",
        # ResourceQuotas, number
        "ResourceQuotas": "resourcequotas",
        # Secrets, number
        "Secrets": "secrets",
        # Services, number
        "Services": "services",
        # ServicesLoadBalancers, number
        "ServicesLoadBalancers": "services.loadbalancers",
        # ServicesNodePorts, number
        "ServicesNodePorts": "services.nodeports",
        # Volume size, in bytes (e,g. 5Gi = 5GiB = 5 * 1024 * 1024 * 1024)
        "Storage": "storage",
    },
)


# A ResourceQuotaScope defines a filter that must match each object tracked by a quota
ResourceQuotaScope = base.Enum(
    "ResourceQuotaScope",
    {
        # Match all pod objects that have best effort quality of service
        "BestEffort": "BestEffort",
        # Match all pod objects that do not have best effort quality of service
        "NotBestEffort": "NotBestEffort",
        # Match all pod objects where !spec.activeDeadlineSeconds
        "NotTerminating": "NotTerminating",
        # Match all pod objects that have priority class mentioned
        "PriorityClass": "PriorityClass",
        # Match all pod objects where spec.activeDeadlineSeconds
        "Terminating": "Terminating",
    },
)


# RestartPolicy describes how the container should be restarted.
# Only one of the following restart policies may be specified.
# If none of the following policies is specified, the default one
# is RestartPolicyAlways.
RestartPolicy = base.Enum(
    "RestartPolicy", {"Always": "Always", "Never": "Never", "OnFailure": "OnFailure"}
)


# A scope selector operator is the set of operators that can be used in
# a scope selector requirement.
ScopeSelectorOperator = base.Enum(
    "ScopeSelectorOperator",
    {"DoesNotExist": "DoesNotExist", "Exists": "Exists", "In": "In", "NotIn": "NotIn"},
)


SecretType = base.Enum(
    "SecretType",
    {
        # BasicAuth contains data needed for basic authentication.
        #
        # Required at least one of fields:
        # - Secret.Data["username"] - username used for authentication
        # - Secret.Data["password"] - password or token needed for authentication
        "BasicAuth": "kubernetes.io/basic-auth",
        # BootstrapToken is used during the automated bootstrap process (first
        # implemented by kubeadm). It stores tokens that are used to sign well known
        # ConfigMaps. They are used for authn.
        "BootstrapToken": "bootstrap.kubernetes.io/token",
        # DockerConfigJson contains a dockercfg file that follows the same format rules as ~/.docker/config.json
        #
        # Required fields:
        # - Secret.Data[".dockerconfigjson"] - a serialized ~/.docker/config.json file
        "DockerConfigJson": "kubernetes.io/dockerconfigjson",
        # Dockercfg contains a dockercfg file that follows the same format rules as ~/.dockercfg
        #
        # Required fields:
        # - Secret.Data[".dockercfg"] - a serialized ~/.dockercfg file
        "Dockercfg": "kubernetes.io/dockercfg",
        # Opaque is the default. Arbitrary user-defined data
        "Opaque": "Opaque",
        # SSHAuth contains data needed for SSH authetication.
        #
        # Required field:
        # - Secret.Data["ssh-privatekey"] - private SSH key needed for authentication
        "SSHAuth": "kubernetes.io/ssh-auth",
        # ServiceAccountToken contains a token that identifies a service account to the API
        #
        # Required fields:
        # - Secret.Annotations["kubernetes.io/service-account.name"] - the name of the ServiceAccount the token identifies
        # - Secret.Annotations["kubernetes.io/service-account.uid"] - the UID of the ServiceAccount the token identifies
        # - Secret.Data["token"] - a token that identifies the service account to the API
        "ServiceAccountToken": "kubernetes.io/service-account-token",
        # TLS contains information about a TLS client or server secret. It
        # is primarily used with TLS termination of the Ingress resource, but may be
        # used in other types.
        #
        # Required fields:
        # - Secret.Data["tls.key"] - TLS private key.
        #   Secret.Data["tls.crt"] - TLS certificate.
        # TODO: Consider supporting different formats, specifying CA/destinationCA.
        "TLS": "kubernetes.io/tls",
    },
)


# Session Affinity Type string
ServiceAffinity = base.Enum(
    "ServiceAffinity",
    {
        # ClientIP is the Client IP based.
        "ClientIP": "ClientIP",
        # None - no session affinity.
        "None": "None",
    },
)


# Service External Traffic Policy Type string
ServiceExternalTrafficPolicyType = base.Enum(
    "ServiceExternalTrafficPolicyType",
    {
        # Cluster specifies node-global (legacy) behavior.
        "Cluster": "Cluster",
        # Local specifies node-local endpoints behavior.
        "Local": "Local",
    },
)


# Service Type string describes ingress methods for a service
ServiceType = base.Enum(
    "ServiceType",
    {
        # ClusterIP means a service will only be accessible inside the
        # cluster, via the cluster IP.
        "ClusterIP": "ClusterIP",
        # ExternalName means a service consists of only a reference to
        # an external name that kubedns or equivalent will return as a CNAME
        # record, with no exposing or proxying of any pods involved.
        "ExternalName": "ExternalName",
        # LoadBalancer means a service will be exposed via an
        # external load balancer (if the cloud provider supports it), in addition
        # to 'NodePort' type.
        "LoadBalancer": "LoadBalancer",
        # NodePort means a service will be exposed on one port of
        # every node, in addition to 'ClusterIP' type.
        "NodePort": "NodePort",
    },
)


# StorageMedium defines ways that storage can be allocated to a volume.
StorageMedium = base.Enum(
    "StorageMedium",
    {
        # use whatever the default is for the node, assume anything we don't explicitly handle is this
        "Default": "",
        # use hugepages
        "HugePages": "HugePages",
        # use memory (e.g. tmpfs on linux)
        "Memory": "Memory",
    },
)


TaintEffect = base.Enum(
    "TaintEffect",
    {
        # Evict any already-running pods that do not tolerate the taint.
        # Currently enforced by NodeController.
        "NoExecute": "NoExecute",
        # Do not allow new pods to schedule onto the node unless they tolerate the taint,
        # but allow all pods submitted to Kubelet without going through the scheduler
        # to start, and allow all already-running pods to continue running.
        # Enforced by the scheduler.
        "NoSchedule": "NoSchedule",
        # Like TaintEffectNoSchedule, but the scheduler tries not to schedule
        # new pods onto the node, rather than prohibiting new pods from scheduling
        # onto the node entirely. Enforced by the scheduler.
        "PreferNoSchedule": "PreferNoSchedule",
    },
)


# TerminationMessagePolicy describes how termination messages are retrieved from a container.
TerminationMessagePolicy = base.Enum(
    "TerminationMessagePolicy",
    {
        # FallbackToLogsOnError will read the most recent contents of the container logs
        # for the container status message when the container exits with an error and the
        # terminationMessagePath has no contents.
        "FallbackToLogsOnError": "FallbackToLogsOnError",
        # File is the default behavior and will set the container status message to
        # the contents of the container's terminationMessagePath when the container exits.
        "File": "File",
    },
)


# A toleration operator is the set of operators that can be used in a toleration.
TolerationOperator = base.Enum(
    "TolerationOperator", {"Equal": "Equal", "Exists": "Exists"}
)


# URIScheme identifies the scheme used for connection to a host for Get actions
URIScheme = base.Enum(
    "URIScheme",
    {
        # HTTP means that the scheme used will be http://
        "HTTP": "HTTP",
        # HTTPS means that the scheme used will be https://
        "HTTPS": "HTTPS",
    },
)


UnsatisfiableConstraintAction = base.Enum(
    "UnsatisfiableConstraintAction",
    {
        # DoNotSchedule instructs the scheduler not to schedule the pod
        # when constraints are not satisfied.
        "DoNotSchedule": "DoNotSchedule",
        # ScheduleAnyway instructs the scheduler to schedule the pod
        # even if constraints are not satisfied.
        "ScheduleAnyway": "ScheduleAnyway",
    },
)


class AWSElasticBlockStoreVolumeSource(types.Object):
    """
    Represents a Persistent Disk resource in AWS.
    
    An AWS EBS disk must exist before mounting to a container. The disk
    must also be in the same AWS zone as the kubelet. An AWS EBS disk
    can only be mounted as read/write once. AWS EBS volumes support
    ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        volume_id: str = "",
        fs_type: str = None,
        partition: int = None,
        read_only: bool = None,
    ):
        super().__init__()
        self.__volume_id = volume_id
        self.__fs_type = fs_type
        self.__partition = partition
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volume_id = self.volume_id()
        check_type("volume_id", volume_id, str)
        v["volumeID"] = volume_id
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        partition = self.partition()
        check_type("partition", partition, Optional[int])
        if partition:  # omit empty
            v["partition"] = partition
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def volume_id(self) -> str:
        """
        Unique ID of the persistent disk resource in AWS (Amazon EBS volume).
        More info: https://kubernetes.io/docs/concepts/storage/volumes#awselasticblockstore
        """
        return self.__volume_id

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type of the volume that you want to mount.
        Tip: Ensure that the filesystem type is supported by the host operating system.
        Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#awselasticblockstore
        TODO: how do we prevent errors in the filesystem from compromising the machine
        """
        return self.__fs_type

    def partition(self) -> Optional[int]:
        """
        The partition in the volume that you want to mount.
        If omitted, the default is to mount by volume name.
        Examples: For volume /dev/sda1, you specify the partition as "1".
        Similarly, the volume partition for /dev/sda is "0" (or you can leave the property empty).
        """
        return self.__partition

    def read_only(self) -> Optional[bool]:
        """
        Specify "true" to force and set the ReadOnly property in VolumeMounts to "true".
        If omitted, the default is "false".
        More info: https://kubernetes.io/docs/concepts/storage/volumes#awselasticblockstore
        """
        return self.__read_only


class NodeSelectorRequirement(types.Object):
    """
    A node selector requirement is a selector that contains values, a key, and an operator
    that relates the key and values.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        key: str = "",
        operator: NodeSelectorOperator = None,
        values: List[str] = None,
    ):
        super().__init__()
        self.__key = key
        self.__operator = operator
        self.__values = values if values is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        key = self.key()
        check_type("key", key, str)
        v["key"] = key
        operator = self.operator()
        check_type("operator", operator, NodeSelectorOperator)
        v["operator"] = operator
        values = self.values()
        check_type("values", values, Optional[List[str]])
        if values:  # omit empty
            v["values"] = values
        return v

    def key(self) -> str:
        """
        The label key that the selector applies to.
        """
        return self.__key

    def operator(self) -> NodeSelectorOperator:
        """
        Represents a key's relationship to a set of values.
        Valid operators are In, NotIn, Exists, DoesNotExist. Gt, and Lt.
        """
        return self.__operator

    def values(self) -> Optional[List[str]]:
        """
        An array of string values. If the operator is In or NotIn,
        the values array must be non-empty. If the operator is Exists or DoesNotExist,
        the values array must be empty. If the operator is Gt or Lt, the values
        array must have a single element, which will be interpreted as an integer.
        This array is replaced during a strategic merge patch.
        """
        return self.__values


class NodeSelectorTerm(types.Object):
    """
    A null or empty node selector term matches no objects. The requirements of
    them are ANDed.
    The TopologySelectorTerm type implements a subset of the NodeSelectorTerm.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        match_expressions: List["NodeSelectorRequirement"] = None,
        match_fields: List["NodeSelectorRequirement"] = None,
    ):
        super().__init__()
        self.__match_expressions = (
            match_expressions if match_expressions is not None else []
        )
        self.__match_fields = match_fields if match_fields is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        match_expressions = self.match_expressions()
        check_type(
            "match_expressions",
            match_expressions,
            Optional[List["NodeSelectorRequirement"]],
        )
        if match_expressions:  # omit empty
            v["matchExpressions"] = match_expressions
        match_fields = self.match_fields()
        check_type(
            "match_fields", match_fields, Optional[List["NodeSelectorRequirement"]]
        )
        if match_fields:  # omit empty
            v["matchFields"] = match_fields
        return v

    def match_expressions(self) -> Optional[List["NodeSelectorRequirement"]]:
        """
        A list of node selector requirements by node's labels.
        """
        return self.__match_expressions

    def match_fields(self) -> Optional[List["NodeSelectorRequirement"]]:
        """
        A list of node selector requirements by node's fields.
        """
        return self.__match_fields


class NodeSelector(types.Object):
    """
    A node selector represents the union of the results of one or more label queries
    over a set of nodes; that is, it represents the OR of the selectors represented
    by the node selector terms.
    """

    @context.scoped
    @typechecked
    def __init__(self, node_selector_terms: List["NodeSelectorTerm"] = None):
        super().__init__()
        self.__node_selector_terms = (
            node_selector_terms if node_selector_terms is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        node_selector_terms = self.node_selector_terms()
        check_type("node_selector_terms", node_selector_terms, List["NodeSelectorTerm"])
        v["nodeSelectorTerms"] = node_selector_terms
        return v

    def node_selector_terms(self) -> List["NodeSelectorTerm"]:
        """
        Required. A list of node selector terms. The terms are ORed.
        """
        return self.__node_selector_terms


class PreferredSchedulingTerm(types.Object):
    """
    An empty preferred scheduling term matches all objects with implicit weight 0
    (i.e. it's a no-op). A null preferred scheduling term matches no objects (i.e. is also a no-op).
    """

    @context.scoped
    @typechecked
    def __init__(self, weight: int = 0, preference: "NodeSelectorTerm" = None):
        super().__init__()
        self.__weight = weight
        self.__preference = preference if preference is not None else NodeSelectorTerm()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        weight = self.weight()
        check_type("weight", weight, int)
        v["weight"] = weight
        preference = self.preference()
        check_type("preference", preference, "NodeSelectorTerm")
        v["preference"] = preference
        return v

    def weight(self) -> int:
        """
        Weight associated with matching the corresponding nodeSelectorTerm, in the range 1-100.
        """
        return self.__weight

    def preference(self) -> "NodeSelectorTerm":
        """
        A node selector term, associated with the corresponding weight.
        """
        return self.__preference


class NodeAffinity(types.Object):
    """
    Node affinity is a group of node affinity scheduling rules.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        required_during_scheduling_ignored_during_execution: "NodeSelector" = None,
        preferred_during_scheduling_ignored_during_execution: List[
            "PreferredSchedulingTerm"
        ] = None,
    ):
        super().__init__()
        self.__required_during_scheduling_ignored_during_execution = (
            required_during_scheduling_ignored_during_execution
        )
        self.__preferred_during_scheduling_ignored_during_execution = (
            preferred_during_scheduling_ignored_during_execution
            if preferred_during_scheduling_ignored_during_execution is not None
            else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        required_during_scheduling_ignored_during_execution = (
            self.required_during_scheduling_ignored_during_execution()
        )
        check_type(
            "required_during_scheduling_ignored_during_execution",
            required_during_scheduling_ignored_during_execution,
            Optional["NodeSelector"],
        )
        if (
            required_during_scheduling_ignored_during_execution is not None
        ):  # omit empty
            v[
                "requiredDuringSchedulingIgnoredDuringExecution"
            ] = required_during_scheduling_ignored_during_execution
        preferred_during_scheduling_ignored_during_execution = (
            self.preferred_during_scheduling_ignored_during_execution()
        )
        check_type(
            "preferred_during_scheduling_ignored_during_execution",
            preferred_during_scheduling_ignored_during_execution,
            Optional[List["PreferredSchedulingTerm"]],
        )
        if preferred_during_scheduling_ignored_during_execution:  # omit empty
            v[
                "preferredDuringSchedulingIgnoredDuringExecution"
            ] = preferred_during_scheduling_ignored_during_execution
        return v

    def required_during_scheduling_ignored_during_execution(
        self
    ) -> Optional["NodeSelector"]:
        """
        If the affinity requirements specified by this field are not met at
        scheduling time, the pod will not be scheduled onto the node.
        If the affinity requirements specified by this field cease to be met
        at some point during pod execution (e.g. due to an update), the system
        may or may not try to eventually evict the pod from its node.
        """
        return self.__required_during_scheduling_ignored_during_execution

    def preferred_during_scheduling_ignored_during_execution(
        self
    ) -> Optional[List["PreferredSchedulingTerm"]]:
        """
        The scheduler will prefer to schedule pods to nodes that satisfy
        the affinity expressions specified by this field, but it may choose
        a node that violates one or more of the expressions. The node that is
        most preferred is the one with the greatest sum of weights, i.e.
        for each node that meets all of the scheduling requirements (resource
        request, requiredDuringScheduling affinity expressions, etc.),
        compute a sum by iterating through the elements of this field and adding
        "weight" to the sum if the node matches the corresponding matchExpressions; the
        node(s) with the highest sum are the most preferred.
        """
        return self.__preferred_during_scheduling_ignored_during_execution


class PodAffinityTerm(types.Object):
    """
    Defines a set of pods (namely those matching the labelSelector
    relative to the given namespace(s)) that this pod should be
    co-located (affinity) or not co-located (anti-affinity) with,
    where co-located is defined as running on a node whose value of
    the label with key <topologyKey> matches that of any node on which
    a pod of the set of pods is running
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        label_selector: "metav1.LabelSelector" = None,
        namespaces: List[str] = None,
        topology_key: str = "",
    ):
        super().__init__()
        self.__label_selector = label_selector
        self.__namespaces = namespaces if namespaces is not None else []
        self.__topology_key = topology_key

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        label_selector = self.label_selector()
        check_type("label_selector", label_selector, Optional["metav1.LabelSelector"])
        if label_selector is not None:  # omit empty
            v["labelSelector"] = label_selector
        namespaces = self.namespaces()
        check_type("namespaces", namespaces, Optional[List[str]])
        if namespaces:  # omit empty
            v["namespaces"] = namespaces
        topology_key = self.topology_key()
        check_type("topology_key", topology_key, str)
        v["topologyKey"] = topology_key
        return v

    def label_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        A label query over a set of resources, in this case pods.
        """
        return self.__label_selector

    def namespaces(self) -> Optional[List[str]]:
        """
        namespaces specifies which namespaces the labelSelector applies to (matches against);
        null or empty list means "this pod's namespace"
        """
        return self.__namespaces

    def topology_key(self) -> str:
        """
        This pod should be co-located (affinity) or not co-located (anti-affinity) with the pods matching
        the labelSelector in the specified namespaces, where co-located is defined as running on a node
        whose value of the label with key topologyKey matches that of any node on which any of the
        selected pods is running.
        Empty topologyKey is not allowed.
        """
        return self.__topology_key


class WeightedPodAffinityTerm(types.Object):
    """
    The weights of all of the matched WeightedPodAffinityTerm fields are added per-node to find the most preferred node(s)
    """

    @context.scoped
    @typechecked
    def __init__(self, weight: int = 0, pod_affinity_term: "PodAffinityTerm" = None):
        super().__init__()
        self.__weight = weight
        self.__pod_affinity_term = (
            pod_affinity_term if pod_affinity_term is not None else PodAffinityTerm()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        weight = self.weight()
        check_type("weight", weight, int)
        v["weight"] = weight
        pod_affinity_term = self.pod_affinity_term()
        check_type("pod_affinity_term", pod_affinity_term, "PodAffinityTerm")
        v["podAffinityTerm"] = pod_affinity_term
        return v

    def weight(self) -> int:
        """
        weight associated with matching the corresponding podAffinityTerm,
        in the range 1-100.
        """
        return self.__weight

    def pod_affinity_term(self) -> "PodAffinityTerm":
        """
        Required. A pod affinity term, associated with the corresponding weight.
        """
        return self.__pod_affinity_term


class PodAffinity(types.Object):
    """
    Pod affinity is a group of inter pod affinity scheduling rules.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        required_during_scheduling_ignored_during_execution: List[
            "PodAffinityTerm"
        ] = None,
        preferred_during_scheduling_ignored_during_execution: List[
            "WeightedPodAffinityTerm"
        ] = None,
    ):
        super().__init__()
        self.__required_during_scheduling_ignored_during_execution = (
            required_during_scheduling_ignored_during_execution
            if required_during_scheduling_ignored_during_execution is not None
            else []
        )
        self.__preferred_during_scheduling_ignored_during_execution = (
            preferred_during_scheduling_ignored_during_execution
            if preferred_during_scheduling_ignored_during_execution is not None
            else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        required_during_scheduling_ignored_during_execution = (
            self.required_during_scheduling_ignored_during_execution()
        )
        check_type(
            "required_during_scheduling_ignored_during_execution",
            required_during_scheduling_ignored_during_execution,
            Optional[List["PodAffinityTerm"]],
        )
        if required_during_scheduling_ignored_during_execution:  # omit empty
            v[
                "requiredDuringSchedulingIgnoredDuringExecution"
            ] = required_during_scheduling_ignored_during_execution
        preferred_during_scheduling_ignored_during_execution = (
            self.preferred_during_scheduling_ignored_during_execution()
        )
        check_type(
            "preferred_during_scheduling_ignored_during_execution",
            preferred_during_scheduling_ignored_during_execution,
            Optional[List["WeightedPodAffinityTerm"]],
        )
        if preferred_during_scheduling_ignored_during_execution:  # omit empty
            v[
                "preferredDuringSchedulingIgnoredDuringExecution"
            ] = preferred_during_scheduling_ignored_during_execution
        return v

    def required_during_scheduling_ignored_during_execution(
        self
    ) -> Optional[List["PodAffinityTerm"]]:
        """
        If the affinity requirements specified by this field are not met at
        scheduling time, the pod will not be scheduled onto the node.
        If the affinity requirements specified by this field cease to be met
        at some point during pod execution (e.g. due to a pod label update), the
        system may or may not try to eventually evict the pod from its node.
        When there are multiple elements, the lists of nodes corresponding to each
        podAffinityTerm are intersected, i.e. all terms must be satisfied.
        """
        return self.__required_during_scheduling_ignored_during_execution

    def preferred_during_scheduling_ignored_during_execution(
        self
    ) -> Optional[List["WeightedPodAffinityTerm"]]:
        """
        The scheduler will prefer to schedule pods to nodes that satisfy
        the affinity expressions specified by this field, but it may choose
        a node that violates one or more of the expressions. The node that is
        most preferred is the one with the greatest sum of weights, i.e.
        for each node that meets all of the scheduling requirements (resource
        request, requiredDuringScheduling affinity expressions, etc.),
        compute a sum by iterating through the elements of this field and adding
        "weight" to the sum if the node has pods which matches the corresponding podAffinityTerm; the
        node(s) with the highest sum are the most preferred.
        """
        return self.__preferred_during_scheduling_ignored_during_execution


class PodAntiAffinity(types.Object):
    """
    Pod anti affinity is a group of inter pod anti affinity scheduling rules.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        required_during_scheduling_ignored_during_execution: List[
            "PodAffinityTerm"
        ] = None,
        preferred_during_scheduling_ignored_during_execution: List[
            "WeightedPodAffinityTerm"
        ] = None,
    ):
        super().__init__()
        self.__required_during_scheduling_ignored_during_execution = (
            required_during_scheduling_ignored_during_execution
            if required_during_scheduling_ignored_during_execution is not None
            else []
        )
        self.__preferred_during_scheduling_ignored_during_execution = (
            preferred_during_scheduling_ignored_during_execution
            if preferred_during_scheduling_ignored_during_execution is not None
            else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        required_during_scheduling_ignored_during_execution = (
            self.required_during_scheduling_ignored_during_execution()
        )
        check_type(
            "required_during_scheduling_ignored_during_execution",
            required_during_scheduling_ignored_during_execution,
            Optional[List["PodAffinityTerm"]],
        )
        if required_during_scheduling_ignored_during_execution:  # omit empty
            v[
                "requiredDuringSchedulingIgnoredDuringExecution"
            ] = required_during_scheduling_ignored_during_execution
        preferred_during_scheduling_ignored_during_execution = (
            self.preferred_during_scheduling_ignored_during_execution()
        )
        check_type(
            "preferred_during_scheduling_ignored_during_execution",
            preferred_during_scheduling_ignored_during_execution,
            Optional[List["WeightedPodAffinityTerm"]],
        )
        if preferred_during_scheduling_ignored_during_execution:  # omit empty
            v[
                "preferredDuringSchedulingIgnoredDuringExecution"
            ] = preferred_during_scheduling_ignored_during_execution
        return v

    def required_during_scheduling_ignored_during_execution(
        self
    ) -> Optional[List["PodAffinityTerm"]]:
        """
        If the anti-affinity requirements specified by this field are not met at
        scheduling time, the pod will not be scheduled onto the node.
        If the anti-affinity requirements specified by this field cease to be met
        at some point during pod execution (e.g. due to a pod label update), the
        system may or may not try to eventually evict the pod from its node.
        When there are multiple elements, the lists of nodes corresponding to each
        podAffinityTerm are intersected, i.e. all terms must be satisfied.
        """
        return self.__required_during_scheduling_ignored_during_execution

    def preferred_during_scheduling_ignored_during_execution(
        self
    ) -> Optional[List["WeightedPodAffinityTerm"]]:
        """
        The scheduler will prefer to schedule pods to nodes that satisfy
        the anti-affinity expressions specified by this field, but it may choose
        a node that violates one or more of the expressions. The node that is
        most preferred is the one with the greatest sum of weights, i.e.
        for each node that meets all of the scheduling requirements (resource
        request, requiredDuringScheduling anti-affinity expressions, etc.),
        compute a sum by iterating through the elements of this field and adding
        "weight" to the sum if the node has pods which matches the corresponding podAffinityTerm; the
        node(s) with the highest sum are the most preferred.
        """
        return self.__preferred_during_scheduling_ignored_during_execution


class Affinity(types.Object):
    """
    Affinity is a group of affinity scheduling rules.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        node_affinity: "NodeAffinity" = None,
        pod_affinity: "PodAffinity" = None,
        pod_anti_affinity: "PodAntiAffinity" = None,
    ):
        super().__init__()
        self.__node_affinity = node_affinity
        self.__pod_affinity = pod_affinity
        self.__pod_anti_affinity = pod_anti_affinity

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        node_affinity = self.node_affinity()
        check_type("node_affinity", node_affinity, Optional["NodeAffinity"])
        if node_affinity is not None:  # omit empty
            v["nodeAffinity"] = node_affinity
        pod_affinity = self.pod_affinity()
        check_type("pod_affinity", pod_affinity, Optional["PodAffinity"])
        if pod_affinity is not None:  # omit empty
            v["podAffinity"] = pod_affinity
        pod_anti_affinity = self.pod_anti_affinity()
        check_type("pod_anti_affinity", pod_anti_affinity, Optional["PodAntiAffinity"])
        if pod_anti_affinity is not None:  # omit empty
            v["podAntiAffinity"] = pod_anti_affinity
        return v

    def node_affinity(self) -> Optional["NodeAffinity"]:
        """
        Describes node affinity scheduling rules for the pod.
        """
        return self.__node_affinity

    def pod_affinity(self) -> Optional["PodAffinity"]:
        """
        Describes pod affinity scheduling rules (e.g. co-locate this pod in the same node, zone, etc. as some other pod(s)).
        """
        return self.__pod_affinity

    def pod_anti_affinity(self) -> Optional["PodAntiAffinity"]:
        """
        Describes pod anti-affinity scheduling rules (e.g. avoid putting this pod in the same node, zone, etc. as some other pod(s)).
        """
        return self.__pod_anti_affinity


class AzureDiskVolumeSource(types.Object):
    """
    AzureDisk represents an Azure Data Disk mount on the host and bind mount to the pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        disk_name: str = "",
        disk_uri: str = "",
        caching_mode: AzureDataDiskCachingMode = None,
        fs_type: str = None,
        read_only: bool = None,
        kind: AzureDataDiskKind = None,
    ):
        super().__init__()
        self.__disk_name = disk_name
        self.__disk_uri = disk_uri
        self.__caching_mode = (
            caching_mode
            if caching_mode is not None
            else AzureDataDiskCachingMode["ReadWrite"]
        )
        self.__fs_type = fs_type if fs_type is not None else "ext4"
        self.__read_only = read_only
        self.__kind = kind if kind is not None else AzureDataDiskKind["Shared"]

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        disk_name = self.disk_name()
        check_type("disk_name", disk_name, str)
        v["diskName"] = disk_name
        disk_uri = self.disk_uri()
        check_type("disk_uri", disk_uri, str)
        v["diskURI"] = disk_uri
        caching_mode = self.caching_mode()
        check_type("caching_mode", caching_mode, Optional[AzureDataDiskCachingMode])
        if caching_mode is not None:  # omit empty
            v["cachingMode"] = caching_mode
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type is not None:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only is not None:  # omit empty
            v["readOnly"] = read_only
        kind = self.kind()
        check_type("kind", kind, Optional[AzureDataDiskKind])
        if kind is not None:  # omit empty
            v["kind"] = kind
        return v

    def disk_name(self) -> str:
        """
        The Name of the data disk in the blob storage
        """
        return self.__disk_name

    def disk_uri(self) -> str:
        """
        The URI the data disk in the blob storage
        """
        return self.__disk_uri

    def caching_mode(self) -> Optional[AzureDataDiskCachingMode]:
        """
        Host Caching mode: None, Read Only, Read Write.
        """
        return self.__caching_mode

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only

    def kind(self) -> Optional[AzureDataDiskKind]:
        """
        Expected values Shared: multiple blob disks per storage account  Dedicated: single blob disk per storage account  Managed: azure managed data disk (only in managed availability set). defaults to shared
        """
        return self.__kind


class AzureFilePersistentVolumeSource(types.Object):
    """
    AzureFile represents an Azure File Service mount on the host and bind mount to the pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        secret_name: str = "",
        share_name: str = "",
        read_only: bool = None,
        secret_namespace: str = None,
    ):
        super().__init__()
        self.__secret_name = secret_name
        self.__share_name = share_name
        self.__read_only = read_only
        self.__secret_namespace = secret_namespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secret_name = self.secret_name()
        check_type("secret_name", secret_name, str)
        v["secretName"] = secret_name
        share_name = self.share_name()
        check_type("share_name", share_name, str)
        v["shareName"] = share_name
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        secret_namespace = self.secret_namespace()
        check_type("secret_namespace", secret_namespace, Optional[str])
        v["secretNamespace"] = secret_namespace
        return v

    def secret_name(self) -> str:
        """
        the name of secret that contains Azure Storage Account Name and Key
        """
        return self.__secret_name

    def share_name(self) -> str:
        """
        Share Name
        """
        return self.__share_name

    def read_only(self) -> Optional[bool]:
        """
        Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only

    def secret_namespace(self) -> Optional[str]:
        """
        the namespace of the secret that contains Azure Storage Account Name and Key
        default is the same as the Pod
        """
        return self.__secret_namespace


class AzureFileVolumeSource(types.Object):
    """
    AzureFile represents an Azure File Service mount on the host and bind mount to the pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, secret_name: str = "", share_name: str = "", read_only: bool = None
    ):
        super().__init__()
        self.__secret_name = secret_name
        self.__share_name = share_name
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secret_name = self.secret_name()
        check_type("secret_name", secret_name, str)
        v["secretName"] = secret_name
        share_name = self.share_name()
        check_type("share_name", share_name, str)
        v["shareName"] = share_name
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def secret_name(self) -> str:
        """
        the name of secret that contains Azure Storage Account Name and Key
        """
        return self.__secret_name

    def share_name(self) -> str:
        """
        Share Name
        """
        return self.__share_name

    def read_only(self) -> Optional[bool]:
        """
        Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only


class ObjectReference(types.Object):
    """
    ObjectReference contains enough information to let you inspect or modify the referred object.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        kind: str = None,
        namespace: str = None,
        name: str = None,
        uid: str = None,
        api_version: str = None,
        resource_version: str = None,
        field_path: str = None,
    ):
        super().__init__()
        self.__kind = kind
        self.__namespace = namespace
        self.__name = name
        self.__uid = uid
        self.__api_version = api_version
        self.__resource_version = resource_version
        self.__field_path = field_path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        check_type("kind", kind, Optional[str])
        if kind:  # omit empty
            v["kind"] = kind
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        uid = self.uid()
        check_type("uid", uid, Optional[str])
        if uid:  # omit empty
            v["uid"] = uid
        api_version = self.api_version()
        check_type("api_version", api_version, Optional[str])
        if api_version:  # omit empty
            v["apiVersion"] = api_version
        resource_version = self.resource_version()
        check_type("resource_version", resource_version, Optional[str])
        if resource_version:  # omit empty
            v["resourceVersion"] = resource_version
        field_path = self.field_path()
        check_type("field_path", field_path, Optional[str])
        if field_path:  # omit empty
            v["fieldPath"] = field_path
        return v

    def kind(self) -> Optional[str]:
        """
        Kind of the referent.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
        """
        return self.__kind

    def namespace(self) -> Optional[str]:
        """
        Namespace of the referent.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
        """
        return self.__namespace

    def name(self) -> Optional[str]:
        """
        Name of the referent.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
        """
        return self.__name

    def uid(self) -> Optional[str]:
        """
        UID of the referent.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
        """
        return self.__uid

    def api_version(self) -> Optional[str]:
        """
        API version of the referent.
        """
        return self.__api_version

    def resource_version(self) -> Optional[str]:
        """
        Specific resourceVersion to which this reference is made, if any.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
        """
        return self.__resource_version

    def field_path(self) -> Optional[str]:
        """
        If referring to a piece of an object instead of an entire object, this string
        should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2].
        For example, if the object reference is to a container within a pod, this would take on a value like:
        "spec.containers{name}" (where "name" refers to the name of the container that triggered
        the event) or if no container name is specified "spec.containers[2]" (container with
        index 2 in this pod). This syntax is chosen only to have some well-defined way of
        referencing a part of an object.
        TODO: this design is not final and this field is subject to change in the future.
        """
        return self.__field_path


class Binding(base.TypedObject, base.NamespacedMetadataObject):
    """
    Binding ties one object to another; for example, a pod is bound to a node by a scheduler.
    Deprecated in 1.7, please use the bindings subresource of pods instead.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        target: "ObjectReference" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="Binding",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__target = target if target is not None else ObjectReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        target = self.target()
        check_type("target", target, "ObjectReference")
        v["target"] = target
        return v

    def target(self) -> "ObjectReference":
        """
        The target object that you want to bind to the standard object.
        """
        return self.__target


class SecretReference(types.Object):
    """
    SecretReference represents a Secret Reference. It has enough information to retrieve secret
    in any namespace
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = None, namespace: str = None):
        super().__init__()
        self.__name = name
        self.__namespace = namespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        return v

    def name(self) -> Optional[str]:
        """
        Name is unique within a namespace to reference a secret resource.
        """
        return self.__name

    def namespace(self) -> Optional[str]:
        """
        Namespace defines the space within which the secret name must be unique.
        """
        return self.__namespace


class CSIPersistentVolumeSource(types.Object):
    """
    Represents storage that is managed by an external CSI volume driver (Beta feature)
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        driver: str = "",
        volume_handle: str = "",
        read_only: bool = None,
        fs_type: str = None,
        volume_attributes: Dict[str, str] = None,
        controller_publish_secret_ref: "SecretReference" = None,
        node_stage_secret_ref: "SecretReference" = None,
        node_publish_secret_ref: "SecretReference" = None,
        controller_expand_secret_ref: "SecretReference" = None,
    ):
        super().__init__()
        self.__driver = driver
        self.__volume_handle = volume_handle
        self.__read_only = read_only
        self.__fs_type = fs_type
        self.__volume_attributes = (
            volume_attributes if volume_attributes is not None else {}
        )
        self.__controller_publish_secret_ref = controller_publish_secret_ref
        self.__node_stage_secret_ref = node_stage_secret_ref
        self.__node_publish_secret_ref = node_publish_secret_ref
        self.__controller_expand_secret_ref = controller_expand_secret_ref

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        driver = self.driver()
        check_type("driver", driver, str)
        v["driver"] = driver
        volume_handle = self.volume_handle()
        check_type("volume_handle", volume_handle, str)
        v["volumeHandle"] = volume_handle
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        volume_attributes = self.volume_attributes()
        check_type("volume_attributes", volume_attributes, Optional[Dict[str, str]])
        if volume_attributes:  # omit empty
            v["volumeAttributes"] = volume_attributes
        controller_publish_secret_ref = self.controller_publish_secret_ref()
        check_type(
            "controller_publish_secret_ref",
            controller_publish_secret_ref,
            Optional["SecretReference"],
        )
        if controller_publish_secret_ref is not None:  # omit empty
            v["controllerPublishSecretRef"] = controller_publish_secret_ref
        node_stage_secret_ref = self.node_stage_secret_ref()
        check_type(
            "node_stage_secret_ref", node_stage_secret_ref, Optional["SecretReference"]
        )
        if node_stage_secret_ref is not None:  # omit empty
            v["nodeStageSecretRef"] = node_stage_secret_ref
        node_publish_secret_ref = self.node_publish_secret_ref()
        check_type(
            "node_publish_secret_ref",
            node_publish_secret_ref,
            Optional["SecretReference"],
        )
        if node_publish_secret_ref is not None:  # omit empty
            v["nodePublishSecretRef"] = node_publish_secret_ref
        controller_expand_secret_ref = self.controller_expand_secret_ref()
        check_type(
            "controller_expand_secret_ref",
            controller_expand_secret_ref,
            Optional["SecretReference"],
        )
        if controller_expand_secret_ref is not None:  # omit empty
            v["controllerExpandSecretRef"] = controller_expand_secret_ref
        return v

    def driver(self) -> str:
        """
        Driver is the name of the driver to use for this volume.
        Required.
        """
        return self.__driver

    def volume_handle(self) -> str:
        """
        VolumeHandle is the unique volume name returned by the CSI volume
        plugin’s CreateVolume to refer to the volume on all subsequent calls.
        Required.
        """
        return self.__volume_handle

    def read_only(self) -> Optional[bool]:
        """
        Optional: The value to pass to ControllerPublishVolumeRequest.
        Defaults to false (read/write).
        """
        return self.__read_only

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs".
        """
        return self.__fs_type

    def volume_attributes(self) -> Optional[Dict[str, str]]:
        """
        Attributes of the volume to publish.
        """
        return self.__volume_attributes

    def controller_publish_secret_ref(self) -> Optional["SecretReference"]:
        """
        ControllerPublishSecretRef is a reference to the secret object containing
        sensitive information to pass to the CSI driver to complete the CSI
        ControllerPublishVolume and ControllerUnpublishVolume calls.
        This field is optional, and may be empty if no secret is required. If the
        secret object contains more than one secret, all secrets are passed.
        """
        return self.__controller_publish_secret_ref

    def node_stage_secret_ref(self) -> Optional["SecretReference"]:
        """
        NodeStageSecretRef is a reference to the secret object containing sensitive
        information to pass to the CSI driver to complete the CSI NodeStageVolume
        and NodeStageVolume and NodeUnstageVolume calls.
        This field is optional, and may be empty if no secret is required. If the
        secret object contains more than one secret, all secrets are passed.
        """
        return self.__node_stage_secret_ref

    def node_publish_secret_ref(self) -> Optional["SecretReference"]:
        """
        NodePublishSecretRef is a reference to the secret object containing
        sensitive information to pass to the CSI driver to complete the CSI
        NodePublishVolume and NodeUnpublishVolume calls.
        This field is optional, and may be empty if no secret is required. If the
        secret object contains more than one secret, all secrets are passed.
        """
        return self.__node_publish_secret_ref

    def controller_expand_secret_ref(self) -> Optional["SecretReference"]:
        """
        ControllerExpandSecretRef is a reference to the secret object containing
        sensitive information to pass to the CSI driver to complete the CSI
        ControllerExpandVolume call.
        This is an alpha field and requires enabling ExpandCSIVolumes feature gate.
        This field is optional, and may be empty if no secret is required. If the
        secret object contains more than one secret, all secrets are passed.
        """
        return self.__controller_expand_secret_ref


class LocalObjectReference(types.Object):
    """
    LocalObjectReference contains enough information to let you locate the
    referenced object inside the same namespace.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = None):
        super().__init__()
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        return v

    def name(self) -> Optional[str]:
        """
        Name of the referent.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
        TODO: Add other useful fields. apiVersion, kind, uid?
        """
        return self.__name


class CSIVolumeSource(types.Object):
    """
    Represents a source location of a volume to mount, managed by an external CSI driver
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        driver: str = "",
        read_only: bool = None,
        fs_type: str = None,
        volume_attributes: Dict[str, str] = None,
        node_publish_secret_ref: "LocalObjectReference" = None,
    ):
        super().__init__()
        self.__driver = driver
        self.__read_only = read_only
        self.__fs_type = fs_type
        self.__volume_attributes = (
            volume_attributes if volume_attributes is not None else {}
        )
        self.__node_publish_secret_ref = node_publish_secret_ref

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        driver = self.driver()
        check_type("driver", driver, str)
        v["driver"] = driver
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only is not None:  # omit empty
            v["readOnly"] = read_only
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type is not None:  # omit empty
            v["fsType"] = fs_type
        volume_attributes = self.volume_attributes()
        check_type("volume_attributes", volume_attributes, Optional[Dict[str, str]])
        if volume_attributes:  # omit empty
            v["volumeAttributes"] = volume_attributes
        node_publish_secret_ref = self.node_publish_secret_ref()
        check_type(
            "node_publish_secret_ref",
            node_publish_secret_ref,
            Optional["LocalObjectReference"],
        )
        if node_publish_secret_ref is not None:  # omit empty
            v["nodePublishSecretRef"] = node_publish_secret_ref
        return v

    def driver(self) -> str:
        """
        Driver is the name of the CSI driver that handles this volume.
        Consult with your admin for the correct name as registered in the cluster.
        """
        return self.__driver

    def read_only(self) -> Optional[bool]:
        """
        Specifies a read-only configuration for the volume.
        Defaults to false (read/write).
        """
        return self.__read_only

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount. Ex. "ext4", "xfs", "ntfs".
        If not provided, the empty value is passed to the associated CSI driver
        which will determine the default filesystem to apply.
        """
        return self.__fs_type

    def volume_attributes(self) -> Optional[Dict[str, str]]:
        """
        VolumeAttributes stores driver-specific properties that are passed to the CSI
        driver. Consult your driver's documentation for supported values.
        """
        return self.__volume_attributes

    def node_publish_secret_ref(self) -> Optional["LocalObjectReference"]:
        """
        NodePublishSecretRef is a reference to the secret object containing
        sensitive information to pass to the CSI driver to complete the CSI
        NodePublishVolume and NodeUnpublishVolume calls.
        This field is optional, and  may be empty if no secret is required. If the
        secret object contains more than one secret, all secret references are passed.
        """
        return self.__node_publish_secret_ref


class Capabilities(types.Object):
    """
    Adds and removes POSIX capabilities from running containers.
    """

    @context.scoped
    @typechecked
    def __init__(self, add: List[Capability] = None, drop: List[Capability] = None):
        super().__init__()
        self.__add = add if add is not None else []
        self.__drop = drop if drop is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        add = self.add()
        check_type("add", add, Optional[List[Capability]])
        if add:  # omit empty
            v["add"] = add
        drop = self.drop()
        check_type("drop", drop, Optional[List[Capability]])
        if drop:  # omit empty
            v["drop"] = drop
        return v

    def add(self) -> Optional[List[Capability]]:
        """
        Added capabilities
        """
        return self.__add

    def drop(self) -> Optional[List[Capability]]:
        """
        Removed capabilities
        """
        return self.__drop


class CephFSPersistentVolumeSource(types.Object):
    """
    Represents a Ceph Filesystem mount that lasts the lifetime of a pod
    Cephfs volumes do not support ownership management or SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        monitors: List[str] = None,
        path: str = None,
        user: str = None,
        secret_file: str = None,
        secret_ref: "SecretReference" = None,
        read_only: bool = None,
    ):
        super().__init__()
        self.__monitors = monitors if monitors is not None else []
        self.__path = path
        self.__user = user
        self.__secret_file = secret_file
        self.__secret_ref = secret_ref
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        monitors = self.monitors()
        check_type("monitors", monitors, List[str])
        v["monitors"] = monitors
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        user = self.user()
        check_type("user", user, Optional[str])
        if user:  # omit empty
            v["user"] = user
        secret_file = self.secret_file()
        check_type("secret_file", secret_file, Optional[str])
        if secret_file:  # omit empty
            v["secretFile"] = secret_file
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["SecretReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def monitors(self) -> List[str]:
        """
        Required: Monitors is a collection of Ceph monitors
        More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
        """
        return self.__monitors

    def path(self) -> Optional[str]:
        """
        Optional: Used as the mounted root, rather than the full Ceph tree, default is /
        """
        return self.__path

    def user(self) -> Optional[str]:
        """
        Optional: User is the rados user name, default is admin
        More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
        """
        return self.__user

    def secret_file(self) -> Optional[str]:
        """
        Optional: SecretFile is the path to key ring for User, default is /etc/ceph/user.secret
        More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
        """
        return self.__secret_file

    def secret_ref(self) -> Optional["SecretReference"]:
        """
        Optional: SecretRef is reference to the authentication secret for User, default is empty.
        More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
        """
        return self.__secret_ref

    def read_only(self) -> Optional[bool]:
        """
        Optional: Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
        """
        return self.__read_only


class CephFSVolumeSource(types.Object):
    """
    Represents a Ceph Filesystem mount that lasts the lifetime of a pod
    Cephfs volumes do not support ownership management or SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        monitors: List[str] = None,
        path: str = None,
        user: str = None,
        secret_file: str = None,
        secret_ref: "LocalObjectReference" = None,
        read_only: bool = None,
    ):
        super().__init__()
        self.__monitors = monitors if monitors is not None else []
        self.__path = path
        self.__user = user
        self.__secret_file = secret_file
        self.__secret_ref = secret_ref
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        monitors = self.monitors()
        check_type("monitors", monitors, List[str])
        v["monitors"] = monitors
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        user = self.user()
        check_type("user", user, Optional[str])
        if user:  # omit empty
            v["user"] = user
        secret_file = self.secret_file()
        check_type("secret_file", secret_file, Optional[str])
        if secret_file:  # omit empty
            v["secretFile"] = secret_file
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["LocalObjectReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def monitors(self) -> List[str]:
        """
        Required: Monitors is a collection of Ceph monitors
        More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
        """
        return self.__monitors

    def path(self) -> Optional[str]:
        """
        Optional: Used as the mounted root, rather than the full Ceph tree, default is /
        """
        return self.__path

    def user(self) -> Optional[str]:
        """
        Optional: User is the rados user name, default is admin
        More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
        """
        return self.__user

    def secret_file(self) -> Optional[str]:
        """
        Optional: SecretFile is the path to key ring for User, default is /etc/ceph/user.secret
        More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
        """
        return self.__secret_file

    def secret_ref(self) -> Optional["LocalObjectReference"]:
        """
        Optional: SecretRef is reference to the authentication secret for User, default is empty.
        More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
        """
        return self.__secret_ref

    def read_only(self) -> Optional[bool]:
        """
        Optional: Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
        """
        return self.__read_only


class CinderPersistentVolumeSource(types.Object):
    """
    Represents a cinder volume resource in Openstack.
    A Cinder volume must exist before mounting to a container.
    The volume must also be in the same region as the kubelet.
    Cinder volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        volume_id: str = "",
        fs_type: str = None,
        read_only: bool = None,
        secret_ref: "SecretReference" = None,
    ):
        super().__init__()
        self.__volume_id = volume_id
        self.__fs_type = fs_type
        self.__read_only = read_only
        self.__secret_ref = secret_ref

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volume_id = self.volume_id()
        check_type("volume_id", volume_id, str)
        v["volumeID"] = volume_id
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["SecretReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        return v

    def volume_id(self) -> str:
        """
        volume id used to identify the volume in cinder.
        More info: https://examples.k8s.io/mysql-cinder-pd/README.md
        """
        return self.__volume_id

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        More info: https://examples.k8s.io/mysql-cinder-pd/README.md
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        Optional: Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        More info: https://examples.k8s.io/mysql-cinder-pd/README.md
        """
        return self.__read_only

    def secret_ref(self) -> Optional["SecretReference"]:
        """
        Optional: points to a secret object containing parameters used to connect
        to OpenStack.
        """
        return self.__secret_ref


class CinderVolumeSource(types.Object):
    """
    Represents a cinder volume resource in Openstack.
    A Cinder volume must exist before mounting to a container.
    The volume must also be in the same region as the kubelet.
    Cinder volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        volume_id: str = "",
        fs_type: str = None,
        read_only: bool = None,
        secret_ref: "LocalObjectReference" = None,
    ):
        super().__init__()
        self.__volume_id = volume_id
        self.__fs_type = fs_type
        self.__read_only = read_only
        self.__secret_ref = secret_ref

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volume_id = self.volume_id()
        check_type("volume_id", volume_id, str)
        v["volumeID"] = volume_id
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["LocalObjectReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        return v

    def volume_id(self) -> str:
        """
        volume id used to identify the volume in cinder.
        More info: https://examples.k8s.io/mysql-cinder-pd/README.md
        """
        return self.__volume_id

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        More info: https://examples.k8s.io/mysql-cinder-pd/README.md
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        Optional: Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        More info: https://examples.k8s.io/mysql-cinder-pd/README.md
        """
        return self.__read_only

    def secret_ref(self) -> Optional["LocalObjectReference"]:
        """
        Optional: points to a secret object containing parameters used to connect
        to OpenStack.
        """
        return self.__secret_ref


class ClientIPConfig(types.Object):
    """
    ClientIPConfig represents the configurations of Client IP based session affinity.
    """

    @context.scoped
    @typechecked
    def __init__(self, timeout_seconds: int = None):
        super().__init__()
        self.__timeout_seconds = timeout_seconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        timeout_seconds = self.timeout_seconds()
        check_type("timeout_seconds", timeout_seconds, Optional[int])
        if timeout_seconds is not None:  # omit empty
            v["timeoutSeconds"] = timeout_seconds
        return v

    def timeout_seconds(self) -> Optional[int]:
        """
        timeoutSeconds specifies the seconds of ClientIP type session sticky time.
        The value must be >0 && <=86400(for 1 day) if ServiceAffinity == "ClientIP".
        Default value is 10800(for 3 hours).
        """
        return self.__timeout_seconds


class ComponentCondition(types.Object):
    """
    Information about the condition of a component.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: ComponentConditionType = None,
        status: ConditionStatus = None,
        message: str = None,
        error: str = None,
    ):
        super().__init__()
        self.__type = type
        self.__status = status
        self.__message = message
        self.__error = error

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, ComponentConditionType)
        v["type"] = type
        status = self.status()
        check_type("status", status, ConditionStatus)
        v["status"] = status
        message = self.message()
        check_type("message", message, Optional[str])
        if message:  # omit empty
            v["message"] = message
        error = self.error()
        check_type("error", error, Optional[str])
        if error:  # omit empty
            v["error"] = error
        return v

    def type(self) -> ComponentConditionType:
        """
        Type of condition for a component.
        Valid value: "Healthy"
        """
        return self.__type

    def status(self) -> ConditionStatus:
        """
        Status of the condition for a component.
        Valid values for "Healthy": "True", "False", or "Unknown".
        """
        return self.__status

    def message(self) -> Optional[str]:
        """
        Message about the condition for a component.
        For example, information about a health check.
        """
        return self.__message

    def error(self) -> Optional[str]:
        """
        Condition error code for a component.
        For example, a health check error code.
        """
        return self.__error


class ComponentStatus(base.TypedObject, base.MetadataObject):
    """
    ComponentStatus (and ComponentStatusList) holds the cluster validation info.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        conditions: List["ComponentCondition"] = None,
    ):
        super().__init__(
            api_version="v1",
            kind="ComponentStatus",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__conditions = conditions if conditions is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        conditions = self.conditions()
        check_type("conditions", conditions, Optional[List["ComponentCondition"]])
        if conditions:  # omit empty
            v["conditions"] = conditions
        return v

    def conditions(self) -> Optional[List["ComponentCondition"]]:
        """
        List of component conditions observed
        """
        return self.__conditions


class ConfigMap(base.TypedObject, base.NamespacedMetadataObject):
    """
    ConfigMap holds configuration data for pods to consume.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        data: Dict[str, str] = None,
        binary_data: Dict[str, bytes] = None,
    ):
        super().__init__(
            api_version="v1",
            kind="ConfigMap",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__data = data if data is not None else {}
        self.__binary_data = binary_data if binary_data is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        data = self.data()
        check_type("data", data, Optional[Dict[str, str]])
        if data:  # omit empty
            v["data"] = data
        binary_data = self.binary_data()
        check_type("binary_data", binary_data, Optional[Dict[str, bytes]])
        if binary_data:  # omit empty
            v["binaryData"] = binary_data
        return v

    def data(self) -> Optional[Dict[str, str]]:
        """
        Data contains the configuration data.
        Each key must consist of alphanumeric characters, '-', '_' or '.'.
        Values with non-UTF-8 byte sequences must use the BinaryData field.
        The keys stored in Data must not overlap with the keys in
        the BinaryData field, this is enforced during validation process.
        """
        return self.__data

    def binary_data(self) -> Optional[Dict[str, bytes]]:
        """
        BinaryData contains the binary data.
        Each key must consist of alphanumeric characters, '-', '_' or '.'.
        BinaryData can contain byte sequences that are not in the UTF-8 range.
        The keys stored in BinaryData must not overlap with the ones in
        the Data field, this is enforced during validation process.
        Using this field will require 1.10+ apiserver and
        kubelet.
        """
        return self.__binary_data


class ConfigMapEnvSource(types.Object):
    """
    ConfigMapEnvSource selects a ConfigMap to populate the environment
    variables with.
    
    The contents of the target ConfigMap's Data field will represent the
    key-value pairs as environment variables.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        local_object_reference: "LocalObjectReference" = None,
        optional: bool = None,
    ):
        super().__init__()
        self.__local_object_reference = (
            local_object_reference
            if local_object_reference is not None
            else LocalObjectReference()
        )
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        local_object_reference = self.local_object_reference()
        check_type(
            "local_object_reference", local_object_reference, "LocalObjectReference"
        )
        v.update(local_object_reference._root())  # inline
        optional = self.optional()
        check_type("optional", optional, Optional[bool])
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    def local_object_reference(self) -> "LocalObjectReference":
        """
        The ConfigMap to select from.
        """
        return self.__local_object_reference

    def optional(self) -> Optional[bool]:
        """
        Specify whether the ConfigMap must be defined
        """
        return self.__optional


class ConfigMapKeySelector(types.Object):
    """
    Selects a key from a ConfigMap.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        local_object_reference: "LocalObjectReference" = None,
        key: str = "",
        optional: bool = None,
    ):
        super().__init__()
        self.__local_object_reference = (
            local_object_reference
            if local_object_reference is not None
            else LocalObjectReference()
        )
        self.__key = key
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        local_object_reference = self.local_object_reference()
        check_type(
            "local_object_reference", local_object_reference, "LocalObjectReference"
        )
        v.update(local_object_reference._root())  # inline
        key = self.key()
        check_type("key", key, str)
        v["key"] = key
        optional = self.optional()
        check_type("optional", optional, Optional[bool])
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    def local_object_reference(self) -> "LocalObjectReference":
        """
        The ConfigMap to select from.
        """
        return self.__local_object_reference

    def key(self) -> str:
        """
        The key to select.
        """
        return self.__key

    def optional(self) -> Optional[bool]:
        """
        Specify whether the ConfigMap or its key must be defined
        """
        return self.__optional


class ConfigMapNodeConfigSource(types.Object):
    """
    ConfigMapNodeConfigSource contains the information to reference a ConfigMap as a config source for the Node.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = "",
        name: str = "",
        uid: str = None,
        resource_version: str = None,
        kubelet_config_key: str = "",
    ):
        super().__init__()
        self.__namespace = namespace
        self.__name = name
        self.__uid = uid
        self.__resource_version = resource_version
        self.__kubelet_config_key = kubelet_config_key

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, str)
        v["namespace"] = namespace
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        uid = self.uid()
        check_type("uid", uid, Optional[str])
        if uid:  # omit empty
            v["uid"] = uid
        resource_version = self.resource_version()
        check_type("resource_version", resource_version, Optional[str])
        if resource_version:  # omit empty
            v["resourceVersion"] = resource_version
        kubelet_config_key = self.kubelet_config_key()
        check_type("kubelet_config_key", kubelet_config_key, str)
        v["kubeletConfigKey"] = kubelet_config_key
        return v

    def namespace(self) -> str:
        """
        Namespace is the metadata.namespace of the referenced ConfigMap.
        This field is required in all cases.
        """
        return self.__namespace

    def name(self) -> str:
        """
        Name is the metadata.name of the referenced ConfigMap.
        This field is required in all cases.
        """
        return self.__name

    def uid(self) -> Optional[str]:
        """
        UID is the metadata.UID of the referenced ConfigMap.
        This field is forbidden in Node.Spec, and required in Node.Status.
        """
        return self.__uid

    def resource_version(self) -> Optional[str]:
        """
        ResourceVersion is the metadata.ResourceVersion of the referenced ConfigMap.
        This field is forbidden in Node.Spec, and required in Node.Status.
        """
        return self.__resource_version

    def kubelet_config_key(self) -> str:
        """
        KubeletConfigKey declares which key of the referenced ConfigMap corresponds to the KubeletConfiguration structure
        This field is required in all cases.
        """
        return self.__kubelet_config_key


class KeyToPath(types.Object):
    """
    Maps a string key to a path within a volume.
    """

    @context.scoped
    @typechecked
    def __init__(self, key: str = "", path: str = "", mode: int = None):
        super().__init__()
        self.__key = key
        self.__path = path
        self.__mode = mode

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        key = self.key()
        check_type("key", key, str)
        v["key"] = key
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        mode = self.mode()
        check_type("mode", mode, Optional[int])
        if mode is not None:  # omit empty
            v["mode"] = mode
        return v

    def key(self) -> str:
        """
        The key to project.
        """
        return self.__key

    def path(self) -> str:
        """
        The relative path of the file to map the key to.
        May not be an absolute path.
        May not contain the path element '..'.
        May not start with the string '..'.
        """
        return self.__path

    def mode(self) -> Optional[int]:
        """
        Optional: mode bits to use on this file, must be a value between 0
        and 0777. If not specified, the volume defaultMode will be used.
        This might be in conflict with other options that affect the file
        mode, like fsGroup, and the result can be other mode bits set.
        """
        return self.__mode


class ConfigMapProjection(types.Object):
    """
    Adapts a ConfigMap into a projected volume.
    
    The contents of the target ConfigMap's Data field will be presented in a
    projected volume as files using the keys in the Data field as the file names,
    unless the items element is populated with specific mappings of keys to paths.
    Note that this is identical to a configmap volume source without the default
    mode.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        local_object_reference: "LocalObjectReference" = None,
        items: List["KeyToPath"] = None,
        optional: bool = None,
    ):
        super().__init__()
        self.__local_object_reference = (
            local_object_reference
            if local_object_reference is not None
            else LocalObjectReference()
        )
        self.__items = items if items is not None else []
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        local_object_reference = self.local_object_reference()
        check_type(
            "local_object_reference", local_object_reference, "LocalObjectReference"
        )
        v.update(local_object_reference._root())  # inline
        items = self.items()
        check_type("items", items, Optional[List["KeyToPath"]])
        if items:  # omit empty
            v["items"] = items
        optional = self.optional()
        check_type("optional", optional, Optional[bool])
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    def local_object_reference(self) -> "LocalObjectReference":
        return self.__local_object_reference

    def items(self) -> Optional[List["KeyToPath"]]:
        """
        If unspecified, each key-value pair in the Data field of the referenced
        ConfigMap will be projected into the volume as a file whose name is the
        key and content is the value. If specified, the listed keys will be
        projected into the specified paths, and unlisted keys will not be
        present. If a key is specified which is not present in the ConfigMap,
        the volume setup will error unless it is marked optional. Paths must be
        relative and may not contain the '..' path or start with '..'.
        """
        return self.__items

    def optional(self) -> Optional[bool]:
        """
        Specify whether the ConfigMap or its keys must be defined
        """
        return self.__optional


class ConfigMapVolumeSource(types.Object):
    """
    Adapts a ConfigMap into a volume.
    
    The contents of the target ConfigMap's Data field will be presented in a
    volume as files using the keys in the Data field as the file names, unless
    the items element is populated with specific mappings of keys to paths.
    ConfigMap volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        local_object_reference: "LocalObjectReference" = None,
        items: List["KeyToPath"] = None,
        default_mode: int = None,
        optional: bool = None,
    ):
        super().__init__()
        self.__local_object_reference = (
            local_object_reference
            if local_object_reference is not None
            else LocalObjectReference()
        )
        self.__items = items if items is not None else []
        self.__default_mode = default_mode if default_mode is not None else 420
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        local_object_reference = self.local_object_reference()
        check_type(
            "local_object_reference", local_object_reference, "LocalObjectReference"
        )
        v.update(local_object_reference._root())  # inline
        items = self.items()
        check_type("items", items, Optional[List["KeyToPath"]])
        if items:  # omit empty
            v["items"] = items
        default_mode = self.default_mode()
        check_type("default_mode", default_mode, Optional[int])
        if default_mode is not None:  # omit empty
            v["defaultMode"] = default_mode
        optional = self.optional()
        check_type("optional", optional, Optional[bool])
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    def local_object_reference(self) -> "LocalObjectReference":
        return self.__local_object_reference

    def items(self) -> Optional[List["KeyToPath"]]:
        """
        If unspecified, each key-value pair in the Data field of the referenced
        ConfigMap will be projected into the volume as a file whose name is the
        key and content is the value. If specified, the listed keys will be
        projected into the specified paths, and unlisted keys will not be
        present. If a key is specified which is not present in the ConfigMap,
        the volume setup will error unless it is marked optional. Paths must be
        relative and may not contain the '..' path or start with '..'.
        """
        return self.__items

    def default_mode(self) -> Optional[int]:
        """
        Optional: mode bits to use on created files by default. Must be a
        value between 0 and 0777. Defaults to 0644.
        Directories within the path are not affected by this setting.
        This might be in conflict with other options that affect the file
        mode, like fsGroup, and the result can be other mode bits set.
        """
        return self.__default_mode

    def optional(self) -> Optional[bool]:
        """
        Specify whether the ConfigMap or its keys must be defined
        """
        return self.__optional


class ContainerPort(types.Object):
    """
    ContainerPort represents a network port in a single container.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        host_port: int = None,
        container_port: int = 0,
        protocol: Protocol = Protocol["TCP"],
        host_ip: str = None,
    ):
        super().__init__()
        self.__name = name
        self.__host_port = host_port
        self.__container_port = container_port
        self.__protocol = protocol
        self.__host_ip = host_ip

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        host_port = self.host_port()
        check_type("host_port", host_port, Optional[int])
        if host_port:  # omit empty
            v["hostPort"] = host_port
        container_port = self.container_port()
        check_type("container_port", container_port, int)
        v["containerPort"] = container_port
        protocol = self.protocol()
        check_type("protocol", protocol, Optional[Protocol])
        if protocol:  # omit empty
            v["protocol"] = protocol
        host_ip = self.host_ip()
        check_type("host_ip", host_ip, Optional[str])
        if host_ip:  # omit empty
            v["hostIP"] = host_ip
        return v

    def name(self) -> Optional[str]:
        """
        If specified, this must be an IANA_SVC_NAME and unique within the pod. Each
        named port in a pod must have a unique name. Name for the port that can be
        referred to by services.
        """
        return self.__name

    def host_port(self) -> Optional[int]:
        """
        Number of port to expose on the host.
        If specified, this must be a valid port number, 0 < x < 65536.
        If HostNetwork is specified, this must match ContainerPort.
        Most containers do not need this.
        """
        return self.__host_port

    def container_port(self) -> int:
        """
        Number of port to expose on the pod's IP address.
        This must be a valid port number, 0 < x < 65536.
        """
        return self.__container_port

    def protocol(self) -> Optional[Protocol]:
        """
        Protocol for port. Must be UDP, TCP, or SCTP.
        Defaults to "TCP".
        """
        return self.__protocol

    def host_ip(self) -> Optional[str]:
        """
        What host IP to bind the external port to.
        """
        return self.__host_ip


class SecretEnvSource(types.Object):
    """
    SecretEnvSource selects a Secret to populate the environment
    variables with.
    
    The contents of the target Secret's Data field will represent the
    key-value pairs as environment variables.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        local_object_reference: "LocalObjectReference" = None,
        optional: bool = None,
    ):
        super().__init__()
        self.__local_object_reference = (
            local_object_reference
            if local_object_reference is not None
            else LocalObjectReference()
        )
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        local_object_reference = self.local_object_reference()
        check_type(
            "local_object_reference", local_object_reference, "LocalObjectReference"
        )
        v.update(local_object_reference._root())  # inline
        optional = self.optional()
        check_type("optional", optional, Optional[bool])
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    def local_object_reference(self) -> "LocalObjectReference":
        """
        The Secret to select from.
        """
        return self.__local_object_reference

    def optional(self) -> Optional[bool]:
        """
        Specify whether the Secret must be defined
        """
        return self.__optional


class EnvFromSource(types.Object):
    """
    EnvFromSource represents the source of a set of ConfigMaps
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        prefix: str = None,
        config_map_ref: "ConfigMapEnvSource" = None,
        secret_ref: "SecretEnvSource" = None,
    ):
        super().__init__()
        self.__prefix = prefix
        self.__config_map_ref = config_map_ref
        self.__secret_ref = secret_ref

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        prefix = self.prefix()
        check_type("prefix", prefix, Optional[str])
        if prefix:  # omit empty
            v["prefix"] = prefix
        config_map_ref = self.config_map_ref()
        check_type("config_map_ref", config_map_ref, Optional["ConfigMapEnvSource"])
        if config_map_ref is not None:  # omit empty
            v["configMapRef"] = config_map_ref
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["SecretEnvSource"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        return v

    def prefix(self) -> Optional[str]:
        """
        An optional identifier to prepend to each key in the ConfigMap. Must be a C_IDENTIFIER.
        """
        return self.__prefix

    def config_map_ref(self) -> Optional["ConfigMapEnvSource"]:
        """
        The ConfigMap to select from
        """
        return self.__config_map_ref

    def secret_ref(self) -> Optional["SecretEnvSource"]:
        """
        The Secret to select from
        """
        return self.__secret_ref


class ObjectFieldSelector(types.Object):
    """
    ObjectFieldSelector selects an APIVersioned field of an object.
    """

    @context.scoped
    @typechecked
    def __init__(self, api_version: str = "v1", field_path: str = ""):
        super().__init__()
        self.__api_version = api_version
        self.__field_path = field_path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        api_version = self.api_version()
        check_type("api_version", api_version, Optional[str])
        if api_version:  # omit empty
            v["apiVersion"] = api_version
        field_path = self.field_path()
        check_type("field_path", field_path, str)
        v["fieldPath"] = field_path
        return v

    def api_version(self) -> Optional[str]:
        """
        Version of the schema the FieldPath is written in terms of, defaults to "v1".
        """
        return self.__api_version

    def field_path(self) -> str:
        """
        Path of the field to select in the specified API version.
        """
        return self.__field_path


class ResourceFieldSelector(types.Object):
    """
    ResourceFieldSelector represents container resources (cpu, memory) and their output format
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        container_name: str = None,
        resource: str = "",
        divisor: "resource.Quantity" = None,
    ):
        super().__init__()
        self.__container_name = container_name
        self.__resource = resource
        self.__divisor = divisor

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        container_name = self.container_name()
        check_type("container_name", container_name, Optional[str])
        if container_name:  # omit empty
            v["containerName"] = container_name
        resource = self.resource()
        check_type("resource", resource, str)
        v["resource"] = resource
        divisor = self.divisor()
        check_type("divisor", divisor, Optional["resource.Quantity"])
        v["divisor"] = divisor
        return v

    def container_name(self) -> Optional[str]:
        """
        Container name: required for volumes, optional for env vars
        """
        return self.__container_name

    def resource(self) -> str:
        """
        Required: resource to select
        """
        return self.__resource

    def divisor(self) -> Optional["resource.Quantity"]:
        """
        Specifies the output format of the exposed resources, defaults to "1"
        """
        return self.__divisor


class SecretKeySelector(types.Object):
    """
    SecretKeySelector selects a key of a Secret.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        local_object_reference: "LocalObjectReference" = None,
        key: str = "",
        optional: bool = None,
    ):
        super().__init__()
        self.__local_object_reference = (
            local_object_reference
            if local_object_reference is not None
            else LocalObjectReference()
        )
        self.__key = key
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        local_object_reference = self.local_object_reference()
        check_type(
            "local_object_reference", local_object_reference, "LocalObjectReference"
        )
        v.update(local_object_reference._root())  # inline
        key = self.key()
        check_type("key", key, str)
        v["key"] = key
        optional = self.optional()
        check_type("optional", optional, Optional[bool])
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    def local_object_reference(self) -> "LocalObjectReference":
        """
        The name of the secret in the pod's namespace to select from.
        """
        return self.__local_object_reference

    def key(self) -> str:
        """
        The key of the secret to select from.  Must be a valid secret key.
        """
        return self.__key

    def optional(self) -> Optional[bool]:
        """
        Specify whether the Secret or its key must be defined
        """
        return self.__optional


class EnvVarSource(types.Object):
    """
    EnvVarSource represents a source for the value of an EnvVar.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        field_ref: "ObjectFieldSelector" = None,
        resource_field_ref: "ResourceFieldSelector" = None,
        config_map_key_ref: "ConfigMapKeySelector" = None,
        secret_key_ref: "SecretKeySelector" = None,
    ):
        super().__init__()
        self.__field_ref = field_ref
        self.__resource_field_ref = resource_field_ref
        self.__config_map_key_ref = config_map_key_ref
        self.__secret_key_ref = secret_key_ref

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        field_ref = self.field_ref()
        check_type("field_ref", field_ref, Optional["ObjectFieldSelector"])
        if field_ref is not None:  # omit empty
            v["fieldRef"] = field_ref
        resource_field_ref = self.resource_field_ref()
        check_type(
            "resource_field_ref", resource_field_ref, Optional["ResourceFieldSelector"]
        )
        if resource_field_ref is not None:  # omit empty
            v["resourceFieldRef"] = resource_field_ref
        config_map_key_ref = self.config_map_key_ref()
        check_type(
            "config_map_key_ref", config_map_key_ref, Optional["ConfigMapKeySelector"]
        )
        if config_map_key_ref is not None:  # omit empty
            v["configMapKeyRef"] = config_map_key_ref
        secret_key_ref = self.secret_key_ref()
        check_type("secret_key_ref", secret_key_ref, Optional["SecretKeySelector"])
        if secret_key_ref is not None:  # omit empty
            v["secretKeyRef"] = secret_key_ref
        return v

    def field_ref(self) -> Optional["ObjectFieldSelector"]:
        """
        Selects a field of the pod: supports metadata.name, metadata.namespace, metadata.labels, metadata.annotations,
        spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.
        """
        return self.__field_ref

    def resource_field_ref(self) -> Optional["ResourceFieldSelector"]:
        """
        Selects a resource of the container: only resources limits and requests
        (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.
        """
        return self.__resource_field_ref

    def config_map_key_ref(self) -> Optional["ConfigMapKeySelector"]:
        """
        Selects a key of a ConfigMap.
        """
        return self.__config_map_key_ref

    def secret_key_ref(self) -> Optional["SecretKeySelector"]:
        """
        Selects a key of a secret in the pod's namespace
        """
        return self.__secret_key_ref


class EnvVar(types.Object):
    """
    EnvVar represents an environment variable present in a Container.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, name: str = "", value: str = None, value_from: "EnvVarSource" = None
    ):
        super().__init__()
        self.__name = name
        self.__value = value
        self.__value_from = value_from

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        value = self.value()
        check_type("value", value, Optional[str])
        if value:  # omit empty
            v["value"] = value
        value_from = self.value_from()
        check_type("value_from", value_from, Optional["EnvVarSource"])
        if value_from is not None:  # omit empty
            v["valueFrom"] = value_from
        return v

    def name(self) -> str:
        """
        Name of the environment variable. Must be a C_IDENTIFIER.
        """
        return self.__name

    def value(self) -> Optional[str]:
        """
        Variable references $(VAR_NAME) are expanded
        using the previous defined environment variables in the container and
        any service environment variables. If a variable cannot be resolved,
        the reference in the input string will be unchanged. The $(VAR_NAME)
        syntax can be escaped with a double $$, ie: $$(VAR_NAME). Escaped
        references will never be expanded, regardless of whether the variable
        exists or not.
        Defaults to "".
        """
        return self.__value

    def value_from(self) -> Optional["EnvVarSource"]:
        """
        Source for the environment variable's value. Cannot be used if value is not empty.
        """
        return self.__value_from


class ExecAction(types.Object):
    """
    ExecAction describes a "run in container" action.
    """

    @context.scoped
    @typechecked
    def __init__(self, command: List[str] = None):
        super().__init__()
        self.__command = command if command is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        command = self.command()
        check_type("command", command, Optional[List[str]])
        if command:  # omit empty
            v["command"] = command
        return v

    def command(self) -> Optional[List[str]]:
        """
        Command is the command line to execute inside the container, the working directory for the
        command  is root ('/') in the container's filesystem. The command is simply exec'd, it is
        not run inside a shell, so traditional shell instructions ('|', etc) won't work. To use
        a shell, you need to explicitly call out to that shell.
        Exit status of 0 is treated as live/healthy and non-zero is unhealthy.
        """
        return self.__command


class HTTPHeader(types.Object):
    """
    HTTPHeader describes a custom header to be used in HTTP probes
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", value: str = ""):
        super().__init__()
        self.__name = name
        self.__value = value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        value = self.value()
        check_type("value", value, str)
        v["value"] = value
        return v

    def name(self) -> str:
        """
        The header field name
        """
        return self.__name

    def value(self) -> str:
        """
        The header field value
        """
        return self.__value


class HTTPGetAction(types.Object):
    """
    HTTPGetAction describes an action based on HTTP Get requests.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        path: str = "/",
        port: Union[int, str] = None,
        host: str = None,
        scheme: URIScheme = URIScheme["HTTP"],
        http_headers: List["HTTPHeader"] = None,
    ):
        super().__init__()
        self.__path = path
        self.__port = port if port is not None else 0
        self.__host = host
        self.__scheme = scheme
        self.__http_headers = http_headers if http_headers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        port = self.port()
        check_type("port", port, Union[int, str])
        v["port"] = port
        host = self.host()
        check_type("host", host, Optional[str])
        if host:  # omit empty
            v["host"] = host
        scheme = self.scheme()
        check_type("scheme", scheme, Optional[URIScheme])
        if scheme:  # omit empty
            v["scheme"] = scheme
        http_headers = self.http_headers()
        check_type("http_headers", http_headers, Optional[List["HTTPHeader"]])
        if http_headers:  # omit empty
            v["httpHeaders"] = http_headers
        return v

    def path(self) -> Optional[str]:
        """
        Path to access on the HTTP server.
        """
        return self.__path

    def port(self) -> Union[int, str]:
        """
        Name or number of the port to access on the container.
        Number must be in the range 1 to 65535.
        Name must be an IANA_SVC_NAME.
        """
        return self.__port

    def host(self) -> Optional[str]:
        """
        Host name to connect to, defaults to the pod IP. You probably want to set
        "Host" in httpHeaders instead.
        """
        return self.__host

    def scheme(self) -> Optional[URIScheme]:
        """
        Scheme to use for connecting to the host.
        Defaults to HTTP.
        """
        return self.__scheme

    def http_headers(self) -> Optional[List["HTTPHeader"]]:
        """
        Custom headers to set in the request. HTTP allows repeated headers.
        """
        return self.__http_headers


class TCPSocketAction(types.Object):
    """
    TCPSocketAction describes an action based on opening a socket
    """

    @context.scoped
    @typechecked
    def __init__(self, port: Union[int, str] = None, host: str = None):
        super().__init__()
        self.__port = port if port is not None else 0
        self.__host = host

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        port = self.port()
        check_type("port", port, Union[int, str])
        v["port"] = port
        host = self.host()
        check_type("host", host, Optional[str])
        if host:  # omit empty
            v["host"] = host
        return v

    def port(self) -> Union[int, str]:
        """
        Number or name of the port to access on the container.
        Number must be in the range 1 to 65535.
        Name must be an IANA_SVC_NAME.
        """
        return self.__port

    def host(self) -> Optional[str]:
        """
        Optional: Host name to connect to, defaults to the pod IP.
        """
        return self.__host


class Handler(types.Object):
    """
    Handler defines a specific action that should be taken
    TODO: pass structured data to these actions, and document that data here.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        exec_: "ExecAction" = None,
        http_get: "HTTPGetAction" = None,
        tcp_socket: "TCPSocketAction" = None,
    ):
        super().__init__()
        self.__exec_ = exec_
        self.__http_get = http_get
        self.__tcp_socket = tcp_socket

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        exec_ = self.exec_()
        check_type("exec_", exec_, Optional["ExecAction"])
        if exec_ is not None:  # omit empty
            v["exec"] = exec_
        http_get = self.http_get()
        check_type("http_get", http_get, Optional["HTTPGetAction"])
        if http_get is not None:  # omit empty
            v["httpGet"] = http_get
        tcp_socket = self.tcp_socket()
        check_type("tcp_socket", tcp_socket, Optional["TCPSocketAction"])
        if tcp_socket is not None:  # omit empty
            v["tcpSocket"] = tcp_socket
        return v

    def exec_(self) -> Optional["ExecAction"]:
        """
        One and only one of the following should be specified.
        Exec specifies the action to take.
        """
        return self.__exec_

    def http_get(self) -> Optional["HTTPGetAction"]:
        """
        HTTPGet specifies the http request to perform.
        """
        return self.__http_get

    def tcp_socket(self) -> Optional["TCPSocketAction"]:
        """
        TCPSocket specifies an action involving a TCP port.
        TCP hooks not yet supported
        TODO: implement a realistic TCP lifecycle hook
        """
        return self.__tcp_socket


class Lifecycle(types.Object):
    """
    Lifecycle describes actions that the management system should take in response to container lifecycle
    events. For the PostStart and PreStop lifecycle handlers, management of the container blocks
    until the action is complete, unless the container process fails, in which case the handler is aborted.
    """

    @context.scoped
    @typechecked
    def __init__(self, post_start: "Handler" = None, pre_stop: "Handler" = None):
        super().__init__()
        self.__post_start = post_start
        self.__pre_stop = pre_stop

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        post_start = self.post_start()
        check_type("post_start", post_start, Optional["Handler"])
        if post_start is not None:  # omit empty
            v["postStart"] = post_start
        pre_stop = self.pre_stop()
        check_type("pre_stop", pre_stop, Optional["Handler"])
        if pre_stop is not None:  # omit empty
            v["preStop"] = pre_stop
        return v

    def post_start(self) -> Optional["Handler"]:
        """
        PostStart is called immediately after a container is created. If the handler fails,
        the container is terminated and restarted according to its restart policy.
        Other management of the container blocks until the hook completes.
        More info: https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/#container-hooks
        """
        return self.__post_start

    def pre_stop(self) -> Optional["Handler"]:
        """
        PreStop is called immediately before a container is terminated due to an
        API request or management event such as liveness/startup probe failure,
        preemption, resource contention, etc. The handler is not called if the
        container crashes or exits. The reason for termination is passed to the
        handler. The Pod's termination grace period countdown begins before the
        PreStop hooked is executed. Regardless of the outcome of the handler, the
        container will eventually terminate within the Pod's termination grace
        period. Other management of the container blocks until the hook completes
        or until the termination grace period is reached.
        More info: https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/#container-hooks
        """
        return self.__pre_stop


class Probe(types.Object):
    """
    Probe describes a health check to be performed against a container to determine whether it is
    alive or ready to receive traffic.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        handler: "Handler" = None,
        initial_delay_seconds: int = None,
        timeout_seconds: int = 1,
        period_seconds: int = 10,
        success_threshold: int = 1,
        failure_threshold: int = 3,
    ):
        super().__init__()
        self.__handler = handler if handler is not None else Handler()
        self.__initial_delay_seconds = initial_delay_seconds
        self.__timeout_seconds = timeout_seconds
        self.__period_seconds = period_seconds
        self.__success_threshold = success_threshold
        self.__failure_threshold = failure_threshold

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        handler = self.handler()
        check_type("handler", handler, "Handler")
        v.update(handler._root())  # inline
        initial_delay_seconds = self.initial_delay_seconds()
        check_type("initial_delay_seconds", initial_delay_seconds, Optional[int])
        if initial_delay_seconds:  # omit empty
            v["initialDelaySeconds"] = initial_delay_seconds
        timeout_seconds = self.timeout_seconds()
        check_type("timeout_seconds", timeout_seconds, Optional[int])
        if timeout_seconds:  # omit empty
            v["timeoutSeconds"] = timeout_seconds
        period_seconds = self.period_seconds()
        check_type("period_seconds", period_seconds, Optional[int])
        if period_seconds:  # omit empty
            v["periodSeconds"] = period_seconds
        success_threshold = self.success_threshold()
        check_type("success_threshold", success_threshold, Optional[int])
        if success_threshold:  # omit empty
            v["successThreshold"] = success_threshold
        failure_threshold = self.failure_threshold()
        check_type("failure_threshold", failure_threshold, Optional[int])
        if failure_threshold:  # omit empty
            v["failureThreshold"] = failure_threshold
        return v

    def handler(self) -> "Handler":
        """
        The action taken to determine the health of a container
        """
        return self.__handler

    def initial_delay_seconds(self) -> Optional[int]:
        """
        Number of seconds after the container has started before liveness probes are initiated.
        More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
        """
        return self.__initial_delay_seconds

    def timeout_seconds(self) -> Optional[int]:
        """
        Number of seconds after which the probe times out.
        Defaults to 1 second. Minimum value is 1.
        More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
        """
        return self.__timeout_seconds

    def period_seconds(self) -> Optional[int]:
        """
        How often (in seconds) to perform the probe.
        Default to 10 seconds. Minimum value is 1.
        """
        return self.__period_seconds

    def success_threshold(self) -> Optional[int]:
        """
        Minimum consecutive successes for the probe to be considered successful after having failed.
        Defaults to 1. Must be 1 for liveness and startup. Minimum value is 1.
        """
        return self.__success_threshold

    def failure_threshold(self) -> Optional[int]:
        """
        Minimum consecutive failures for the probe to be considered failed after having succeeded.
        Defaults to 3. Minimum value is 1.
        """
        return self.__failure_threshold


class ResourceRequirements(types.Object):
    """
    ResourceRequirements describes the compute resource requirements.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        limits: Dict[ResourceName, "resource.Quantity"] = None,
        requests: Dict[ResourceName, "resource.Quantity"] = None,
    ):
        super().__init__()
        self.__limits = limits if limits is not None else {}
        self.__requests = requests if requests is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        limits = self.limits()
        check_type("limits", limits, Optional[Dict[ResourceName, "resource.Quantity"]])
        if limits:  # omit empty
            v["limits"] = limits
        requests = self.requests()
        check_type(
            "requests", requests, Optional[Dict[ResourceName, "resource.Quantity"]]
        )
        if requests:  # omit empty
            v["requests"] = requests
        return v

    def limits(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        """
        Limits describes the maximum amount of compute resources allowed.
        More info: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/
        """
        return self.__limits

    def requests(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        """
        Requests describes the minimum amount of compute resources required.
        If Requests is omitted for a container, it defaults to Limits if that is explicitly specified,
        otherwise to an implementation-defined value.
        More info: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/
        """
        return self.__requests


class SELinuxOptions(types.Object):
    """
    SELinuxOptions are the labels to be applied to the container
    """

    @context.scoped
    @typechecked
    def __init__(
        self, user: str = None, role: str = None, type: str = None, level: str = None
    ):
        super().__init__()
        self.__user = user
        self.__role = role
        self.__type = type
        self.__level = level

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        user = self.user()
        check_type("user", user, Optional[str])
        if user:  # omit empty
            v["user"] = user
        role = self.role()
        check_type("role", role, Optional[str])
        if role:  # omit empty
            v["role"] = role
        type = self.type()
        check_type("type", type, Optional[str])
        if type:  # omit empty
            v["type"] = type
        level = self.level()
        check_type("level", level, Optional[str])
        if level:  # omit empty
            v["level"] = level
        return v

    def user(self) -> Optional[str]:
        """
        User is a SELinux user label that applies to the container.
        """
        return self.__user

    def role(self) -> Optional[str]:
        """
        Role is a SELinux role label that applies to the container.
        """
        return self.__role

    def type(self) -> Optional[str]:
        """
        Type is a SELinux type label that applies to the container.
        """
        return self.__type

    def level(self) -> Optional[str]:
        """
        Level is SELinux level label that applies to the container.
        """
        return self.__level


class WindowsSecurityContextOptions(types.Object):
    """
    WindowsSecurityContextOptions contain Windows-specific options and credentials.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        gmsa_credential_spec_name: str = None,
        gmsa_credential_spec: str = None,
        run_as_user_name: str = None,
    ):
        super().__init__()
        self.__gmsa_credential_spec_name = gmsa_credential_spec_name
        self.__gmsa_credential_spec = gmsa_credential_spec
        self.__run_as_user_name = run_as_user_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        gmsa_credential_spec_name = self.gmsa_credential_spec_name()
        check_type(
            "gmsa_credential_spec_name", gmsa_credential_spec_name, Optional[str]
        )
        if gmsa_credential_spec_name is not None:  # omit empty
            v["gmsaCredentialSpecName"] = gmsa_credential_spec_name
        gmsa_credential_spec = self.gmsa_credential_spec()
        check_type("gmsa_credential_spec", gmsa_credential_spec, Optional[str])
        if gmsa_credential_spec is not None:  # omit empty
            v["gmsaCredentialSpec"] = gmsa_credential_spec
        run_as_user_name = self.run_as_user_name()
        check_type("run_as_user_name", run_as_user_name, Optional[str])
        if run_as_user_name is not None:  # omit empty
            v["runAsUserName"] = run_as_user_name
        return v

    def gmsa_credential_spec_name(self) -> Optional[str]:
        """
        GMSACredentialSpecName is the name of the GMSA credential spec to use.
        This field is alpha-level and is only honored by servers that enable the WindowsGMSA feature flag.
        """
        return self.__gmsa_credential_spec_name

    def gmsa_credential_spec(self) -> Optional[str]:
        """
        GMSACredentialSpec is where the GMSA admission webhook
        (https://github.com/kubernetes-sigs/windows-gmsa) inlines the contents of the
        GMSA credential spec named by the GMSACredentialSpecName field.
        This field is alpha-level and is only honored by servers that enable the WindowsGMSA feature flag.
        """
        return self.__gmsa_credential_spec

    def run_as_user_name(self) -> Optional[str]:
        """
        The UserName in Windows to run the entrypoint of the container process.
        Defaults to the user specified in image metadata if unspecified.
        May also be set in PodSecurityContext. If set in both SecurityContext and
        PodSecurityContext, the value specified in SecurityContext takes precedence.
        This field is beta-level and may be disabled with the WindowsRunAsUserName feature flag.
        """
        return self.__run_as_user_name


class SecurityContext(types.Object):
    """
    SecurityContext holds security configuration that will be applied to a container.
    Some fields are present in both SecurityContext and PodSecurityContext.  When both
    are set, the values in SecurityContext take precedence.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        capabilities: "Capabilities" = None,
        privileged: bool = None,
        se_linux_options: "SELinuxOptions" = None,
        windows_options: "WindowsSecurityContextOptions" = None,
        run_as_user: int = None,
        run_as_group: int = None,
        run_as_non_root: bool = None,
        read_only_root_filesystem: bool = None,
        allow_privilege_escalation: bool = None,
        proc_mount: ProcMountType = None,
    ):
        super().__init__()
        self.__capabilities = capabilities
        self.__privileged = privileged
        self.__se_linux_options = se_linux_options
        self.__windows_options = windows_options
        self.__run_as_user = run_as_user
        self.__run_as_group = run_as_group
        self.__run_as_non_root = run_as_non_root
        self.__read_only_root_filesystem = read_only_root_filesystem
        self.__allow_privilege_escalation = allow_privilege_escalation
        self.__proc_mount = proc_mount

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        capabilities = self.capabilities()
        check_type("capabilities", capabilities, Optional["Capabilities"])
        if capabilities is not None:  # omit empty
            v["capabilities"] = capabilities
        privileged = self.privileged()
        check_type("privileged", privileged, Optional[bool])
        if privileged is not None:  # omit empty
            v["privileged"] = privileged
        se_linux_options = self.se_linux_options()
        check_type("se_linux_options", se_linux_options, Optional["SELinuxOptions"])
        if se_linux_options is not None:  # omit empty
            v["seLinuxOptions"] = se_linux_options
        windows_options = self.windows_options()
        check_type(
            "windows_options",
            windows_options,
            Optional["WindowsSecurityContextOptions"],
        )
        if windows_options is not None:  # omit empty
            v["windowsOptions"] = windows_options
        run_as_user = self.run_as_user()
        check_type("run_as_user", run_as_user, Optional[int])
        if run_as_user is not None:  # omit empty
            v["runAsUser"] = run_as_user
        run_as_group = self.run_as_group()
        check_type("run_as_group", run_as_group, Optional[int])
        if run_as_group is not None:  # omit empty
            v["runAsGroup"] = run_as_group
        run_as_non_root = self.run_as_non_root()
        check_type("run_as_non_root", run_as_non_root, Optional[bool])
        if run_as_non_root is not None:  # omit empty
            v["runAsNonRoot"] = run_as_non_root
        read_only_root_filesystem = self.read_only_root_filesystem()
        check_type(
            "read_only_root_filesystem", read_only_root_filesystem, Optional[bool]
        )
        if read_only_root_filesystem is not None:  # omit empty
            v["readOnlyRootFilesystem"] = read_only_root_filesystem
        allow_privilege_escalation = self.allow_privilege_escalation()
        check_type(
            "allow_privilege_escalation", allow_privilege_escalation, Optional[bool]
        )
        if allow_privilege_escalation is not None:  # omit empty
            v["allowPrivilegeEscalation"] = allow_privilege_escalation
        proc_mount = self.proc_mount()
        check_type("proc_mount", proc_mount, Optional[ProcMountType])
        if proc_mount is not None:  # omit empty
            v["procMount"] = proc_mount
        return v

    def capabilities(self) -> Optional["Capabilities"]:
        """
        The capabilities to add/drop when running containers.
        Defaults to the default set of capabilities granted by the container runtime.
        """
        return self.__capabilities

    def privileged(self) -> Optional[bool]:
        """
        Run container in privileged mode.
        Processes in privileged containers are essentially equivalent to root on the host.
        Defaults to false.
        """
        return self.__privileged

    def se_linux_options(self) -> Optional["SELinuxOptions"]:
        """
        The SELinux context to be applied to the container.
        If unspecified, the container runtime will allocate a random SELinux context for each
        container.  May also be set in PodSecurityContext.  If set in both SecurityContext and
        PodSecurityContext, the value specified in SecurityContext takes precedence.
        """
        return self.__se_linux_options

    def windows_options(self) -> Optional["WindowsSecurityContextOptions"]:
        """
        The Windows specific settings applied to all containers.
        If unspecified, the options from the PodSecurityContext will be used.
        If set in both SecurityContext and PodSecurityContext, the value specified in SecurityContext takes precedence.
        """
        return self.__windows_options

    def run_as_user(self) -> Optional[int]:
        """
        The UID to run the entrypoint of the container process.
        Defaults to user specified in image metadata if unspecified.
        May also be set in PodSecurityContext.  If set in both SecurityContext and
        PodSecurityContext, the value specified in SecurityContext takes precedence.
        """
        return self.__run_as_user

    def run_as_group(self) -> Optional[int]:
        """
        The GID to run the entrypoint of the container process.
        Uses runtime default if unset.
        May also be set in PodSecurityContext.  If set in both SecurityContext and
        PodSecurityContext, the value specified in SecurityContext takes precedence.
        """
        return self.__run_as_group

    def run_as_non_root(self) -> Optional[bool]:
        """
        Indicates that the container must run as a non-root user.
        If true, the Kubelet will validate the image at runtime to ensure that it
        does not run as UID 0 (root) and fail to start the container if it does.
        If unset or false, no such validation will be performed.
        May also be set in PodSecurityContext.  If set in both SecurityContext and
        PodSecurityContext, the value specified in SecurityContext takes precedence.
        """
        return self.__run_as_non_root

    def read_only_root_filesystem(self) -> Optional[bool]:
        """
        Whether this container has a read-only root filesystem.
        Default is false.
        """
        return self.__read_only_root_filesystem

    def allow_privilege_escalation(self) -> Optional[bool]:
        """
        AllowPrivilegeEscalation controls whether a process can gain more
        privileges than its parent process. This bool directly controls if
        the no_new_privs flag will be set on the container process.
        AllowPrivilegeEscalation is true always when the container is:
        1) run as Privileged
        2) has CAP_SYS_ADMIN
        """
        return self.__allow_privilege_escalation

    def proc_mount(self) -> Optional[ProcMountType]:
        """
        procMount denotes the type of proc mount to use for the containers.
        The default is DefaultProcMount which uses the container runtime defaults for
        readonly paths and masked paths.
        This requires the ProcMountType feature flag to be enabled.
        """
        return self.__proc_mount


class VolumeDevice(types.Object):
    """
    volumeDevice describes a mapping of a raw block device within a container.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", device_path: str = ""):
        super().__init__()
        self.__name = name
        self.__device_path = device_path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        device_path = self.device_path()
        check_type("device_path", device_path, str)
        v["devicePath"] = device_path
        return v

    def name(self) -> str:
        """
        name must match the name of a persistentVolumeClaim in the pod
        """
        return self.__name

    def device_path(self) -> str:
        """
        devicePath is the path inside of the container that the device will be mapped to.
        """
        return self.__device_path


class VolumeMount(types.Object):
    """
    VolumeMount describes a mounting of a Volume within a container.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        read_only: bool = None,
        mount_path: str = "",
        sub_path: str = None,
        mount_propagation: MountPropagationMode = None,
        sub_path_expr: str = None,
    ):
        super().__init__()
        self.__name = name
        self.__read_only = read_only
        self.__mount_path = mount_path
        self.__sub_path = sub_path
        self.__mount_propagation = mount_propagation
        self.__sub_path_expr = sub_path_expr

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        mount_path = self.mount_path()
        check_type("mount_path", mount_path, str)
        v["mountPath"] = mount_path
        sub_path = self.sub_path()
        check_type("sub_path", sub_path, Optional[str])
        if sub_path:  # omit empty
            v["subPath"] = sub_path
        mount_propagation = self.mount_propagation()
        check_type(
            "mount_propagation", mount_propagation, Optional[MountPropagationMode]
        )
        if mount_propagation is not None:  # omit empty
            v["mountPropagation"] = mount_propagation
        sub_path_expr = self.sub_path_expr()
        check_type("sub_path_expr", sub_path_expr, Optional[str])
        if sub_path_expr:  # omit empty
            v["subPathExpr"] = sub_path_expr
        return v

    def name(self) -> str:
        """
        This must match the Name of a Volume.
        """
        return self.__name

    def read_only(self) -> Optional[bool]:
        """
        Mounted read-only if true, read-write otherwise (false or unspecified).
        Defaults to false.
        """
        return self.__read_only

    def mount_path(self) -> str:
        """
        Path within the container at which the volume should be mounted.  Must
        not contain ':'.
        """
        return self.__mount_path

    def sub_path(self) -> Optional[str]:
        """
        Path within the volume from which the container's volume should be mounted.
        Defaults to "" (volume's root).
        """
        return self.__sub_path

    def mount_propagation(self) -> Optional[MountPropagationMode]:
        """
        mountPropagation determines how mounts are propagated from the host
        to container and the other way around.
        When not set, MountPropagationNone is used.
        This field is beta in 1.10.
        """
        return self.__mount_propagation

    def sub_path_expr(self) -> Optional[str]:
        """
        Expanded path within the volume from which the container's volume should be mounted.
        Behaves similarly to SubPath but environment variable references $(VAR_NAME) are expanded using the container's environment.
        Defaults to "" (volume's root).
        SubPathExpr and SubPath are mutually exclusive.
        """
        return self.__sub_path_expr


class Container(types.Object):
    """
    A single application container that you want to run within a pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        image: str = None,
        command: List[str] = None,
        args: List[str] = None,
        working_dir: str = None,
        ports: List["ContainerPort"] = None,
        env_from: List["EnvFromSource"] = None,
        env: List["EnvVar"] = None,
        resources: "ResourceRequirements" = None,
        volume_mounts: List["VolumeMount"] = None,
        volume_devices: List["VolumeDevice"] = None,
        liveness_probe: "Probe" = None,
        readiness_probe: "Probe" = None,
        startup_probe: "Probe" = None,
        lifecycle: "Lifecycle" = None,
        termination_message_path: str = "/dev/termination-log",
        termination_message_policy: TerminationMessagePolicy = TerminationMessagePolicy[
            "File"
        ],
        image_pull_policy: PullPolicy = PullPolicy["IfNotPresent"],
        security_context: "SecurityContext" = None,
        stdin: bool = None,
        stdin_once: bool = None,
        tty: bool = None,
    ):
        super().__init__()
        self.__name = name
        self.__image = image
        self.__command = command if command is not None else []
        self.__args = args if args is not None else []
        self.__working_dir = working_dir
        self.__ports = ports if ports is not None else []
        self.__env_from = env_from if env_from is not None else []
        self.__env = env if env is not None else []
        self.__resources = (
            resources if resources is not None else ResourceRequirements()
        )
        self.__volume_mounts = volume_mounts if volume_mounts is not None else []
        self.__volume_devices = volume_devices if volume_devices is not None else []
        self.__liveness_probe = liveness_probe
        self.__readiness_probe = readiness_probe
        self.__startup_probe = startup_probe
        self.__lifecycle = lifecycle
        self.__termination_message_path = termination_message_path
        self.__termination_message_policy = termination_message_policy
        self.__image_pull_policy = image_pull_policy
        self.__security_context = security_context
        self.__stdin = stdin
        self.__stdin_once = stdin_once
        self.__tty = tty

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        image = self.image()
        check_type("image", image, Optional[str])
        if image:  # omit empty
            v["image"] = image
        command = self.command()
        check_type("command", command, Optional[List[str]])
        if command:  # omit empty
            v["command"] = command
        args = self.args()
        check_type("args", args, Optional[List[str]])
        if args:  # omit empty
            v["args"] = args
        working_dir = self.working_dir()
        check_type("working_dir", working_dir, Optional[str])
        if working_dir:  # omit empty
            v["workingDir"] = working_dir
        ports = self.ports()
        check_type("ports", ports, Optional[List["ContainerPort"]])
        if ports:  # omit empty
            v["ports"] = ports
        env_from = self.env_from()
        check_type("env_from", env_from, Optional[List["EnvFromSource"]])
        if env_from:  # omit empty
            v["envFrom"] = env_from
        env = self.env()
        check_type("env", env, Optional[List["EnvVar"]])
        if env:  # omit empty
            v["env"] = env
        resources = self.resources()
        check_type("resources", resources, Optional["ResourceRequirements"])
        v["resources"] = resources
        volume_mounts = self.volume_mounts()
        check_type("volume_mounts", volume_mounts, Optional[List["VolumeMount"]])
        if volume_mounts:  # omit empty
            v["volumeMounts"] = volume_mounts
        volume_devices = self.volume_devices()
        check_type("volume_devices", volume_devices, Optional[List["VolumeDevice"]])
        if volume_devices:  # omit empty
            v["volumeDevices"] = volume_devices
        liveness_probe = self.liveness_probe()
        check_type("liveness_probe", liveness_probe, Optional["Probe"])
        if liveness_probe is not None:  # omit empty
            v["livenessProbe"] = liveness_probe
        readiness_probe = self.readiness_probe()
        check_type("readiness_probe", readiness_probe, Optional["Probe"])
        if readiness_probe is not None:  # omit empty
            v["readinessProbe"] = readiness_probe
        startup_probe = self.startup_probe()
        check_type("startup_probe", startup_probe, Optional["Probe"])
        if startup_probe is not None:  # omit empty
            v["startupProbe"] = startup_probe
        lifecycle = self.lifecycle()
        check_type("lifecycle", lifecycle, Optional["Lifecycle"])
        if lifecycle is not None:  # omit empty
            v["lifecycle"] = lifecycle
        termination_message_path = self.termination_message_path()
        check_type("termination_message_path", termination_message_path, Optional[str])
        if termination_message_path:  # omit empty
            v["terminationMessagePath"] = termination_message_path
        termination_message_policy = self.termination_message_policy()
        check_type(
            "termination_message_policy",
            termination_message_policy,
            Optional[TerminationMessagePolicy],
        )
        if termination_message_policy:  # omit empty
            v["terminationMessagePolicy"] = termination_message_policy
        image_pull_policy = self.image_pull_policy()
        check_type("image_pull_policy", image_pull_policy, Optional[PullPolicy])
        if image_pull_policy:  # omit empty
            v["imagePullPolicy"] = image_pull_policy
        security_context = self.security_context()
        check_type("security_context", security_context, Optional["SecurityContext"])
        if security_context is not None:  # omit empty
            v["securityContext"] = security_context
        stdin = self.stdin()
        check_type("stdin", stdin, Optional[bool])
        if stdin:  # omit empty
            v["stdin"] = stdin
        stdin_once = self.stdin_once()
        check_type("stdin_once", stdin_once, Optional[bool])
        if stdin_once:  # omit empty
            v["stdinOnce"] = stdin_once
        tty = self.tty()
        check_type("tty", tty, Optional[bool])
        if tty:  # omit empty
            v["tty"] = tty
        return v

    def name(self) -> str:
        """
        Name of the container specified as a DNS_LABEL.
        Each container in a pod must have a unique name (DNS_LABEL).
        Cannot be updated.
        """
        return self.__name

    def image(self) -> Optional[str]:
        """
        Docker image name.
        More info: https://kubernetes.io/docs/concepts/containers/images
        This field is optional to allow higher level config management to default or override
        container images in workload controllers like Deployments and StatefulSets.
        """
        return self.__image

    def command(self) -> Optional[List[str]]:
        """
        Entrypoint array. Not executed within a shell.
        The docker image's ENTRYPOINT is used if this is not provided.
        Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
        cannot be resolved, the reference in the input string will be unchanged. The $(VAR_NAME) syntax
        can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
        regardless of whether the variable exists or not.
        Cannot be updated.
        More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
        """
        return self.__command

    def args(self) -> Optional[List[str]]:
        """
        Arguments to the entrypoint.
        The docker image's CMD is used if this is not provided.
        Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
        cannot be resolved, the reference in the input string will be unchanged. The $(VAR_NAME) syntax
        can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
        regardless of whether the variable exists or not.
        Cannot be updated.
        More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
        """
        return self.__args

    def working_dir(self) -> Optional[str]:
        """
        Container's working directory.
        If not specified, the container runtime's default will be used, which
        might be configured in the container image.
        Cannot be updated.
        """
        return self.__working_dir

    def ports(self) -> Optional[List["ContainerPort"]]:
        """
        List of ports to expose from the container. Exposing a port here gives
        the system additional information about the network connections a
        container uses, but is primarily informational. Not specifying a port here
        DOES NOT prevent that port from being exposed. Any port which is
        listening on the default "0.0.0.0" address inside a container will be
        accessible from the network.
        Cannot be updated.
        +listType=map
        +listMapKey=containerPort
        +listMapKey=protocol
        """
        return self.__ports

    def env_from(self) -> Optional[List["EnvFromSource"]]:
        """
        List of sources to populate environment variables in the container.
        The keys defined within a source must be a C_IDENTIFIER. All invalid keys
        will be reported as an event when the container is starting. When a key exists in multiple
        sources, the value associated with the last source will take precedence.
        Values defined by an Env with a duplicate key will take precedence.
        Cannot be updated.
        """
        return self.__env_from

    def env(self) -> Optional[List["EnvVar"]]:
        """
        List of environment variables to set in the container.
        Cannot be updated.
        """
        return self.__env

    def resources(self) -> Optional["ResourceRequirements"]:
        """
        Compute Resources required by this container.
        Cannot be updated.
        More info: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/
        """
        return self.__resources

    def volume_mounts(self) -> Optional[List["VolumeMount"]]:
        """
        Pod volumes to mount into the container's filesystem.
        Cannot be updated.
        """
        return self.__volume_mounts

    def volume_devices(self) -> Optional[List["VolumeDevice"]]:
        """
        volumeDevices is the list of block devices to be used by the container.
        This is a beta feature.
        """
        return self.__volume_devices

    def liveness_probe(self) -> Optional["Probe"]:
        """
        Periodic probe of container liveness.
        Container will be restarted if the probe fails.
        Cannot be updated.
        More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
        """
        return self.__liveness_probe

    def readiness_probe(self) -> Optional["Probe"]:
        """
        Periodic probe of container service readiness.
        Container will be removed from service endpoints if the probe fails.
        Cannot be updated.
        More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
        """
        return self.__readiness_probe

    def startup_probe(self) -> Optional["Probe"]:
        """
        StartupProbe indicates that the Pod has successfully initialized.
        If specified, no other probes are executed until this completes successfully.
        If this probe fails, the Pod will be restarted, just as if the livenessProbe failed.
        This can be used to provide different probe parameters at the beginning of a Pod's lifecycle,
        when it might take a long time to load data or warm a cache, than during steady-state operation.
        This cannot be updated.
        This is an alpha feature enabled by the StartupProbe feature flag.
        More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
        """
        return self.__startup_probe

    def lifecycle(self) -> Optional["Lifecycle"]:
        """
        Actions that the management system should take in response to container lifecycle events.
        Cannot be updated.
        """
        return self.__lifecycle

    def termination_message_path(self) -> Optional[str]:
        """
        Optional: Path at which the file to which the container's termination message
        will be written is mounted into the container's filesystem.
        Message written is intended to be brief final status, such as an assertion failure message.
        Will be truncated by the node if greater than 4096 bytes. The total message length across
        all containers will be limited to 12kb.
        Defaults to /dev/termination-log.
        Cannot be updated.
        """
        return self.__termination_message_path

    def termination_message_policy(self) -> Optional[TerminationMessagePolicy]:
        """
        Indicate how the termination message should be populated. File will use the contents of
        terminationMessagePath to populate the container status message on both success and failure.
        FallbackToLogsOnError will use the last chunk of container log output if the termination
        message file is empty and the container exited with an error.
        The log output is limited to 2048 bytes or 80 lines, whichever is smaller.
        Defaults to File.
        Cannot be updated.
        """
        return self.__termination_message_policy

    def image_pull_policy(self) -> Optional[PullPolicy]:
        """
        Image pull policy.
        One of Always, Never, IfNotPresent.
        Defaults to Always if :latest tag is specified, or IfNotPresent otherwise.
        Cannot be updated.
        More info: https://kubernetes.io/docs/concepts/containers/images#updating-images
        """
        return self.__image_pull_policy

    def security_context(self) -> Optional["SecurityContext"]:
        """
        Security options the pod should run with.
        More info: https://kubernetes.io/docs/concepts/policy/security-context/
        More info: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
        """
        return self.__security_context

    def stdin(self) -> Optional[bool]:
        """
        Whether this container should allocate a buffer for stdin in the container runtime. If this
        is not set, reads from stdin in the container will always result in EOF.
        Default is false.
        """
        return self.__stdin

    def stdin_once(self) -> Optional[bool]:
        """
        Whether the container runtime should close the stdin channel after it has been opened by
        a single attach. When stdin is true the stdin stream will remain open across multiple attach
        sessions. If stdinOnce is set to true, stdin is opened on container start, is empty until the
        first client attaches to stdin, and then remains open and accepts data until the client disconnects,
        at which time stdin is closed and remains closed until the container is restarted. If this
        flag is false, a container processes that reads from stdin will never receive an EOF.
        Default is false
        """
        return self.__stdin_once

    def tty(self) -> Optional[bool]:
        """
        Whether this container should allocate a TTY for itself, also requires 'stdin' to be true.
        Default is false.
        """
        return self.__tty


class DownwardAPIVolumeFile(types.Object):
    """
    DownwardAPIVolumeFile represents information to create the file containing the pod field
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        path: str = "",
        field_ref: "ObjectFieldSelector" = None,
        resource_field_ref: "ResourceFieldSelector" = None,
        mode: int = None,
    ):
        super().__init__()
        self.__path = path
        self.__field_ref = field_ref
        self.__resource_field_ref = resource_field_ref
        self.__mode = mode

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        field_ref = self.field_ref()
        check_type("field_ref", field_ref, Optional["ObjectFieldSelector"])
        if field_ref is not None:  # omit empty
            v["fieldRef"] = field_ref
        resource_field_ref = self.resource_field_ref()
        check_type(
            "resource_field_ref", resource_field_ref, Optional["ResourceFieldSelector"]
        )
        if resource_field_ref is not None:  # omit empty
            v["resourceFieldRef"] = resource_field_ref
        mode = self.mode()
        check_type("mode", mode, Optional[int])
        if mode is not None:  # omit empty
            v["mode"] = mode
        return v

    def path(self) -> str:
        """
        Required: Path is  the relative path name of the file to be created. Must not be absolute or contain the '..' path. Must be utf-8 encoded. The first item of the relative path must not start with '..'
        """
        return self.__path

    def field_ref(self) -> Optional["ObjectFieldSelector"]:
        """
        Required: Selects a field of the pod: only annotations, labels, name and namespace are supported.
        """
        return self.__field_ref

    def resource_field_ref(self) -> Optional["ResourceFieldSelector"]:
        """
        Selects a resource of the container: only resources limits and requests
        (limits.cpu, limits.memory, requests.cpu and requests.memory) are currently supported.
        """
        return self.__resource_field_ref

    def mode(self) -> Optional[int]:
        """
        Optional: mode bits to use on this file, must be a value between 0
        and 0777. If not specified, the volume defaultMode will be used.
        This might be in conflict with other options that affect the file
        mode, like fsGroup, and the result can be other mode bits set.
        """
        return self.__mode


class DownwardAPIProjection(types.Object):
    """
    Represents downward API info for projecting into a projected volume.
    Note that this is identical to a downwardAPI volume source without the default
    mode.
    """

    @context.scoped
    @typechecked
    def __init__(self, items: List["DownwardAPIVolumeFile"] = None):
        super().__init__()
        self.__items = items if items is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        items = self.items()
        check_type("items", items, Optional[List["DownwardAPIVolumeFile"]])
        if items:  # omit empty
            v["items"] = items
        return v

    def items(self) -> Optional[List["DownwardAPIVolumeFile"]]:
        """
        Items is a list of DownwardAPIVolume file
        """
        return self.__items


class DownwardAPIVolumeSource(types.Object):
    """
    DownwardAPIVolumeSource represents a volume containing downward API info.
    Downward API volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, items: List["DownwardAPIVolumeFile"] = None, default_mode: int = None
    ):
        super().__init__()
        self.__items = items if items is not None else []
        self.__default_mode = default_mode if default_mode is not None else 420

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        items = self.items()
        check_type("items", items, Optional[List["DownwardAPIVolumeFile"]])
        if items:  # omit empty
            v["items"] = items
        default_mode = self.default_mode()
        check_type("default_mode", default_mode, Optional[int])
        if default_mode is not None:  # omit empty
            v["defaultMode"] = default_mode
        return v

    def items(self) -> Optional[List["DownwardAPIVolumeFile"]]:
        """
        Items is a list of downward API volume file
        """
        return self.__items

    def default_mode(self) -> Optional[int]:
        """
        Optional: mode bits to use on created files by default. Must be a
        value between 0 and 0777. Defaults to 0644.
        Directories within the path are not affected by this setting.
        This might be in conflict with other options that affect the file
        mode, like fsGroup, and the result can be other mode bits set.
        """
        return self.__default_mode


class EmptyDirVolumeSource(types.Object):
    """
    Represents an empty directory for a pod.
    Empty directory volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, medium: StorageMedium = None, size_limit: "resource.Quantity" = None
    ):
        super().__init__()
        self.__medium = medium
        self.__size_limit = size_limit

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        medium = self.medium()
        check_type("medium", medium, Optional[StorageMedium])
        if medium:  # omit empty
            v["medium"] = medium
        size_limit = self.size_limit()
        check_type("size_limit", size_limit, Optional["resource.Quantity"])
        if size_limit is not None:  # omit empty
            v["sizeLimit"] = size_limit
        return v

    def medium(self) -> Optional[StorageMedium]:
        """
        What type of storage medium should back this directory.
        The default is "" which means to use the node's default medium.
        Must be an empty string (default) or Memory.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#emptydir
        """
        return self.__medium

    def size_limit(self) -> Optional["resource.Quantity"]:
        """
        Total amount of local storage required for this EmptyDir volume.
        The size limit is also applicable for memory medium.
        The maximum usage on memory medium EmptyDir would be the minimum value between
        the SizeLimit specified here and the sum of memory limits of all containers in a pod.
        The default is nil which means that the limit is undefined.
        More info: http://kubernetes.io/docs/user-guide/volumes#emptydir
        """
        return self.__size_limit


class EndpointAddress(types.Object):
    """
    EndpointAddress is a tuple that describes single IP address.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ip: str = "",
        hostname: str = None,
        node_name: str = None,
        target_ref: "ObjectReference" = None,
    ):
        super().__init__()
        self.__ip = ip
        self.__hostname = hostname
        self.__node_name = node_name
        self.__target_ref = target_ref

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ip = self.ip()
        check_type("ip", ip, str)
        v["ip"] = ip
        hostname = self.hostname()
        check_type("hostname", hostname, Optional[str])
        if hostname:  # omit empty
            v["hostname"] = hostname
        node_name = self.node_name()
        check_type("node_name", node_name, Optional[str])
        if node_name is not None:  # omit empty
            v["nodeName"] = node_name
        target_ref = self.target_ref()
        check_type("target_ref", target_ref, Optional["ObjectReference"])
        if target_ref is not None:  # omit empty
            v["targetRef"] = target_ref
        return v

    def ip(self) -> str:
        """
        The IP of this endpoint.
        May not be loopback (127.0.0.0/8), link-local (169.254.0.0/16),
        or link-local multicast ((224.0.0.0/24).
        IPv6 is also accepted but not fully supported on all platforms. Also, certain
        kubernetes components, like kube-proxy, are not IPv6 ready.
        TODO: This should allow hostname or IP, See #4447.
        """
        return self.__ip

    def hostname(self) -> Optional[str]:
        """
        The Hostname of this endpoint
        """
        return self.__hostname

    def node_name(self) -> Optional[str]:
        """
        Optional: Node hosting this endpoint. This can be used to determine endpoints local to a node.
        """
        return self.__node_name

    def target_ref(self) -> Optional["ObjectReference"]:
        """
        Reference to object providing the endpoint.
        """
        return self.__target_ref


class EndpointPort(types.Object):
    """
    EndpointPort is a tuple that describes a single port.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = None, port: int = 0, protocol: Protocol = None):
        super().__init__()
        self.__name = name
        self.__port = port
        self.__protocol = protocol

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        port = self.port()
        check_type("port", port, int)
        v["port"] = port
        protocol = self.protocol()
        check_type("protocol", protocol, Optional[Protocol])
        if protocol:  # omit empty
            v["protocol"] = protocol
        return v

    def name(self) -> Optional[str]:
        """
        The name of this port.  This must match the 'name' field in the
        corresponding ServicePort.
        Must be a DNS_LABEL.
        Optional only if one port is defined.
        """
        return self.__name

    def port(self) -> int:
        """
        The port number of the endpoint.
        """
        return self.__port

    def protocol(self) -> Optional[Protocol]:
        """
        The IP protocol for this port.
        Must be UDP, TCP, or SCTP.
        Default is TCP.
        """
        return self.__protocol


class EndpointSubset(types.Object):
    """
    EndpointSubset is a group of addresses with a common set of ports. The
    expanded set of endpoints is the Cartesian product of Addresses x Ports.
    For example, given:
      {
        Addresses: [{"ip": "10.10.1.1"}, {"ip": "10.10.2.2"}],
        Ports:     [{"name": "a", "port": 8675}, {"name": "b", "port": 309}]
      }
    The resulting set of endpoints can be viewed as:
        a: [ 10.10.1.1:8675, 10.10.2.2:8675 ],
        b: [ 10.10.1.1:309, 10.10.2.2:309 ]
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        addresses: List["EndpointAddress"] = None,
        not_ready_addresses: List["EndpointAddress"] = None,
        ports: List["EndpointPort"] = None,
    ):
        super().__init__()
        self.__addresses = addresses if addresses is not None else []
        self.__not_ready_addresses = (
            not_ready_addresses if not_ready_addresses is not None else []
        )
        self.__ports = ports if ports is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        addresses = self.addresses()
        check_type("addresses", addresses, Optional[List["EndpointAddress"]])
        if addresses:  # omit empty
            v["addresses"] = addresses
        not_ready_addresses = self.not_ready_addresses()
        check_type(
            "not_ready_addresses",
            not_ready_addresses,
            Optional[List["EndpointAddress"]],
        )
        if not_ready_addresses:  # omit empty
            v["notReadyAddresses"] = not_ready_addresses
        ports = self.ports()
        check_type("ports", ports, Optional[List["EndpointPort"]])
        if ports:  # omit empty
            v["ports"] = ports
        return v

    def addresses(self) -> Optional[List["EndpointAddress"]]:
        """
        IP addresses which offer the related ports that are marked as ready. These endpoints
        should be considered safe for load balancers and clients to utilize.
        """
        return self.__addresses

    def not_ready_addresses(self) -> Optional[List["EndpointAddress"]]:
        """
        IP addresses which offer the related ports but are not currently marked as ready
        because they have not yet finished starting, have recently failed a readiness check,
        or have recently failed a liveness check.
        """
        return self.__not_ready_addresses

    def ports(self) -> Optional[List["EndpointPort"]]:
        """
        Port numbers available on the related IP addresses.
        """
        return self.__ports


class Endpoints(base.TypedObject, base.NamespacedMetadataObject):
    """
    Endpoints is a collection of endpoints that implement the actual service. Example:
      Name: "mysvc",
      Subsets: [
        {
          Addresses: [{"ip": "10.10.1.1"}, {"ip": "10.10.2.2"}],
          Ports: [{"name": "a", "port": 8675}, {"name": "b", "port": 309}]
        },
        {
          Addresses: [{"ip": "10.10.3.3"}],
          Ports: [{"name": "a", "port": 93}, {"name": "b", "port": 76}]
        },
     ]
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        subsets: List["EndpointSubset"] = None,
    ):
        super().__init__(
            api_version="v1",
            kind="Endpoints",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__subsets = subsets if subsets is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        subsets = self.subsets()
        check_type("subsets", subsets, Optional[List["EndpointSubset"]])
        if subsets:  # omit empty
            v["subsets"] = subsets
        return v

    def subsets(self) -> Optional[List["EndpointSubset"]]:
        """
        The set of all endpoints is the union of all subsets. Addresses are placed into
        subsets according to the IPs they share. A single address with multiple ports,
        some of which are ready and some of which are not (because they come from
        different containers) will result in the address being displayed in different
        subsets for the different ports. No address will appear in both Addresses and
        NotReadyAddresses in the same subset.
        Sets of addresses and ports that comprise a service.
        """
        return self.__subsets


class EphemeralContainerCommon(types.Object):
    """
    EphemeralContainerCommon is a copy of all fields in Container to be inlined in
    EphemeralContainer. This separate type allows easy conversion from EphemeralContainer
    to Container and allows separate documentation for the fields of EphemeralContainer.
    When a new field is added to Container it must be added here as well.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        image: str = None,
        command: List[str] = None,
        args: List[str] = None,
        working_dir: str = None,
        ports: List["ContainerPort"] = None,
        env_from: List["EnvFromSource"] = None,
        env: List["EnvVar"] = None,
        resources: "ResourceRequirements" = None,
        volume_mounts: List["VolumeMount"] = None,
        volume_devices: List["VolumeDevice"] = None,
        liveness_probe: "Probe" = None,
        readiness_probe: "Probe" = None,
        startup_probe: "Probe" = None,
        lifecycle: "Lifecycle" = None,
        termination_message_path: str = None,
        termination_message_policy: TerminationMessagePolicy = None,
        image_pull_policy: PullPolicy = None,
        security_context: "SecurityContext" = None,
        stdin: bool = None,
        stdin_once: bool = None,
        tty: bool = None,
    ):
        super().__init__()
        self.__name = name
        self.__image = image
        self.__command = command if command is not None else []
        self.__args = args if args is not None else []
        self.__working_dir = working_dir
        self.__ports = ports if ports is not None else []
        self.__env_from = env_from if env_from is not None else []
        self.__env = env if env is not None else []
        self.__resources = (
            resources if resources is not None else ResourceRequirements()
        )
        self.__volume_mounts = volume_mounts if volume_mounts is not None else []
        self.__volume_devices = volume_devices if volume_devices is not None else []
        self.__liveness_probe = liveness_probe
        self.__readiness_probe = readiness_probe
        self.__startup_probe = startup_probe
        self.__lifecycle = lifecycle
        self.__termination_message_path = termination_message_path
        self.__termination_message_policy = termination_message_policy
        self.__image_pull_policy = image_pull_policy
        self.__security_context = security_context
        self.__stdin = stdin
        self.__stdin_once = stdin_once
        self.__tty = tty

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        image = self.image()
        check_type("image", image, Optional[str])
        if image:  # omit empty
            v["image"] = image
        command = self.command()
        check_type("command", command, Optional[List[str]])
        if command:  # omit empty
            v["command"] = command
        args = self.args()
        check_type("args", args, Optional[List[str]])
        if args:  # omit empty
            v["args"] = args
        working_dir = self.working_dir()
        check_type("working_dir", working_dir, Optional[str])
        if working_dir:  # omit empty
            v["workingDir"] = working_dir
        ports = self.ports()
        check_type("ports", ports, Optional[List["ContainerPort"]])
        if ports:  # omit empty
            v["ports"] = ports
        env_from = self.env_from()
        check_type("env_from", env_from, Optional[List["EnvFromSource"]])
        if env_from:  # omit empty
            v["envFrom"] = env_from
        env = self.env()
        check_type("env", env, Optional[List["EnvVar"]])
        if env:  # omit empty
            v["env"] = env
        resources = self.resources()
        check_type("resources", resources, Optional["ResourceRequirements"])
        v["resources"] = resources
        volume_mounts = self.volume_mounts()
        check_type("volume_mounts", volume_mounts, Optional[List["VolumeMount"]])
        if volume_mounts:  # omit empty
            v["volumeMounts"] = volume_mounts
        volume_devices = self.volume_devices()
        check_type("volume_devices", volume_devices, Optional[List["VolumeDevice"]])
        if volume_devices:  # omit empty
            v["volumeDevices"] = volume_devices
        liveness_probe = self.liveness_probe()
        check_type("liveness_probe", liveness_probe, Optional["Probe"])
        if liveness_probe is not None:  # omit empty
            v["livenessProbe"] = liveness_probe
        readiness_probe = self.readiness_probe()
        check_type("readiness_probe", readiness_probe, Optional["Probe"])
        if readiness_probe is not None:  # omit empty
            v["readinessProbe"] = readiness_probe
        startup_probe = self.startup_probe()
        check_type("startup_probe", startup_probe, Optional["Probe"])
        if startup_probe is not None:  # omit empty
            v["startupProbe"] = startup_probe
        lifecycle = self.lifecycle()
        check_type("lifecycle", lifecycle, Optional["Lifecycle"])
        if lifecycle is not None:  # omit empty
            v["lifecycle"] = lifecycle
        termination_message_path = self.termination_message_path()
        check_type("termination_message_path", termination_message_path, Optional[str])
        if termination_message_path:  # omit empty
            v["terminationMessagePath"] = termination_message_path
        termination_message_policy = self.termination_message_policy()
        check_type(
            "termination_message_policy",
            termination_message_policy,
            Optional[TerminationMessagePolicy],
        )
        if termination_message_policy:  # omit empty
            v["terminationMessagePolicy"] = termination_message_policy
        image_pull_policy = self.image_pull_policy()
        check_type("image_pull_policy", image_pull_policy, Optional[PullPolicy])
        if image_pull_policy:  # omit empty
            v["imagePullPolicy"] = image_pull_policy
        security_context = self.security_context()
        check_type("security_context", security_context, Optional["SecurityContext"])
        if security_context is not None:  # omit empty
            v["securityContext"] = security_context
        stdin = self.stdin()
        check_type("stdin", stdin, Optional[bool])
        if stdin:  # omit empty
            v["stdin"] = stdin
        stdin_once = self.stdin_once()
        check_type("stdin_once", stdin_once, Optional[bool])
        if stdin_once:  # omit empty
            v["stdinOnce"] = stdin_once
        tty = self.tty()
        check_type("tty", tty, Optional[bool])
        if tty:  # omit empty
            v["tty"] = tty
        return v

    def name(self) -> str:
        """
        Name of the ephemeral container specified as a DNS_LABEL.
        This name must be unique among all containers, init containers and ephemeral containers.
        """
        return self.__name

    def image(self) -> Optional[str]:
        """
        Docker image name.
        More info: https://kubernetes.io/docs/concepts/containers/images
        """
        return self.__image

    def command(self) -> Optional[List[str]]:
        """
        Entrypoint array. Not executed within a shell.
        The docker image's ENTRYPOINT is used if this is not provided.
        Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
        cannot be resolved, the reference in the input string will be unchanged. The $(VAR_NAME) syntax
        can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
        regardless of whether the variable exists or not.
        Cannot be updated.
        More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
        """
        return self.__command

    def args(self) -> Optional[List[str]]:
        """
        Arguments to the entrypoint.
        The docker image's CMD is used if this is not provided.
        Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
        cannot be resolved, the reference in the input string will be unchanged. The $(VAR_NAME) syntax
        can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
        regardless of whether the variable exists or not.
        Cannot be updated.
        More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
        """
        return self.__args

    def working_dir(self) -> Optional[str]:
        """
        Container's working directory.
        If not specified, the container runtime's default will be used, which
        might be configured in the container image.
        Cannot be updated.
        """
        return self.__working_dir

    def ports(self) -> Optional[List["ContainerPort"]]:
        """
        Ports are not allowed for ephemeral containers.
        """
        return self.__ports

    def env_from(self) -> Optional[List["EnvFromSource"]]:
        """
        List of sources to populate environment variables in the container.
        The keys defined within a source must be a C_IDENTIFIER. All invalid keys
        will be reported as an event when the container is starting. When a key exists in multiple
        sources, the value associated with the last source will take precedence.
        Values defined by an Env with a duplicate key will take precedence.
        Cannot be updated.
        """
        return self.__env_from

    def env(self) -> Optional[List["EnvVar"]]:
        """
        List of environment variables to set in the container.
        Cannot be updated.
        """
        return self.__env

    def resources(self) -> Optional["ResourceRequirements"]:
        """
        Resources are not allowed for ephemeral containers. Ephemeral containers use spare resources
        already allocated to the pod.
        """
        return self.__resources

    def volume_mounts(self) -> Optional[List["VolumeMount"]]:
        """
        Pod volumes to mount into the container's filesystem.
        Cannot be updated.
        """
        return self.__volume_mounts

    def volume_devices(self) -> Optional[List["VolumeDevice"]]:
        """
        volumeDevices is the list of block devices to be used by the container.
        This is a beta feature.
        """
        return self.__volume_devices

    def liveness_probe(self) -> Optional["Probe"]:
        """
        Probes are not allowed for ephemeral containers.
        """
        return self.__liveness_probe

    def readiness_probe(self) -> Optional["Probe"]:
        """
        Probes are not allowed for ephemeral containers.
        """
        return self.__readiness_probe

    def startup_probe(self) -> Optional["Probe"]:
        """
        Probes are not allowed for ephemeral containers.
        """
        return self.__startup_probe

    def lifecycle(self) -> Optional["Lifecycle"]:
        """
        Lifecycle is not allowed for ephemeral containers.
        """
        return self.__lifecycle

    def termination_message_path(self) -> Optional[str]:
        """
        Optional: Path at which the file to which the container's termination message
        will be written is mounted into the container's filesystem.
        Message written is intended to be brief final status, such as an assertion failure message.
        Will be truncated by the node if greater than 4096 bytes. The total message length across
        all containers will be limited to 12kb.
        Defaults to /dev/termination-log.
        Cannot be updated.
        """
        return self.__termination_message_path

    def termination_message_policy(self) -> Optional[TerminationMessagePolicy]:
        """
        Indicate how the termination message should be populated. File will use the contents of
        terminationMessagePath to populate the container status message on both success and failure.
        FallbackToLogsOnError will use the last chunk of container log output if the termination
        message file is empty and the container exited with an error.
        The log output is limited to 2048 bytes or 80 lines, whichever is smaller.
        Defaults to File.
        Cannot be updated.
        """
        return self.__termination_message_policy

    def image_pull_policy(self) -> Optional[PullPolicy]:
        """
        Image pull policy.
        One of Always, Never, IfNotPresent.
        Defaults to Always if :latest tag is specified, or IfNotPresent otherwise.
        Cannot be updated.
        More info: https://kubernetes.io/docs/concepts/containers/images#updating-images
        """
        return self.__image_pull_policy

    def security_context(self) -> Optional["SecurityContext"]:
        """
        SecurityContext is not allowed for ephemeral containers.
        """
        return self.__security_context

    def stdin(self) -> Optional[bool]:
        """
        Whether this container should allocate a buffer for stdin in the container runtime. If this
        is not set, reads from stdin in the container will always result in EOF.
        Default is false.
        """
        return self.__stdin

    def stdin_once(self) -> Optional[bool]:
        """
        Whether the container runtime should close the stdin channel after it has been opened by
        a single attach. When stdin is true the stdin stream will remain open across multiple attach
        sessions. If stdinOnce is set to true, stdin is opened on container start, is empty until the
        first client attaches to stdin, and then remains open and accepts data until the client disconnects,
        at which time stdin is closed and remains closed until the container is restarted. If this
        flag is false, a container processes that reads from stdin will never receive an EOF.
        Default is false
        """
        return self.__stdin_once

    def tty(self) -> Optional[bool]:
        """
        Whether this container should allocate a TTY for itself, also requires 'stdin' to be true.
        Default is false.
        """
        return self.__tty


class EphemeralContainer(types.Object):
    """
    An EphemeralContainer is a container that may be added temporarily to an existing pod for
    user-initiated activities such as debugging. Ephemeral containers have no resource or
    scheduling guarantees, and they will not be restarted when they exit or when a pod is
    removed or restarted. If an ephemeral container causes a pod to exceed its resource
    allocation, the pod may be evicted.
    Ephemeral containers may not be added by directly updating the pod spec. They must be added
    via the pod's ephemeralcontainers subresource, and they will appear in the pod spec
    once added.
    This is an alpha feature enabled by the EphemeralContainers feature flag.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ephemeral_container_common: "EphemeralContainerCommon" = None,
        target_container_name: str = None,
    ):
        super().__init__()
        self.__ephemeral_container_common = (
            ephemeral_container_common
            if ephemeral_container_common is not None
            else EphemeralContainerCommon()
        )
        self.__target_container_name = target_container_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ephemeral_container_common = self.ephemeral_container_common()
        check_type(
            "ephemeral_container_common",
            ephemeral_container_common,
            "EphemeralContainerCommon",
        )
        v.update(ephemeral_container_common._root())  # inline
        target_container_name = self.target_container_name()
        check_type("target_container_name", target_container_name, Optional[str])
        if target_container_name:  # omit empty
            v["targetContainerName"] = target_container_name
        return v

    def ephemeral_container_common(self) -> "EphemeralContainerCommon":
        """
        Ephemeral containers have all of the fields of Container, plus additional fields
        specific to ephemeral containers. Fields in common with Container are in the
        following inlined struct so than an EphemeralContainer may easily be converted
        to a Container.
        """
        return self.__ephemeral_container_common

    def target_container_name(self) -> Optional[str]:
        """
        If set, the name of the container from PodSpec that this ephemeral container targets.
        The ephemeral container will be run in the namespaces (IPC, PID, etc) of this container.
        If not set then the ephemeral container is run in whatever namespaces are shared
        for the pod. Note that the container runtime must support this feature.
        """
        return self.__target_container_name


class EphemeralContainers(base.TypedObject, base.NamespacedMetadataObject):
    """
    A list of ephemeral containers used with the Pod ephemeralcontainers subresource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        ephemeral_containers: List["EphemeralContainer"] = None,
    ):
        super().__init__(
            api_version="v1",
            kind="EphemeralContainers",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__ephemeral_containers = (
            ephemeral_containers if ephemeral_containers is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ephemeral_containers = self.ephemeral_containers()
        check_type(
            "ephemeral_containers", ephemeral_containers, List["EphemeralContainer"]
        )
        v["ephemeralContainers"] = ephemeral_containers
        return v

    def ephemeral_containers(self) -> List["EphemeralContainer"]:
        """
        A list of ephemeral containers associated with this pod. New ephemeral containers
        may be appended to this list, but existing ephemeral containers may not be removed
        or modified.
        """
        return self.__ephemeral_containers


class EventSeries(types.Object):
    """
    EventSeries contain information on series of events, i.e. thing that was/is happening
    continuously for some time.
    """

    @context.scoped
    @typechecked
    def __init__(self, count: int = None, last_observed_time: "base.MicroTime" = None):
        super().__init__()
        self.__count = count
        self.__last_observed_time = last_observed_time

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        count = self.count()
        check_type("count", count, Optional[int])
        if count:  # omit empty
            v["count"] = count
        last_observed_time = self.last_observed_time()
        check_type("last_observed_time", last_observed_time, Optional["base.MicroTime"])
        v["lastObservedTime"] = last_observed_time
        return v

    def count(self) -> Optional[int]:
        """
        Number of occurrences in this series up to the last heartbeat time
        """
        return self.__count

    def last_observed_time(self) -> Optional["base.MicroTime"]:
        """
        Time of the last occurrence observed
        """
        return self.__last_observed_time


class EventSource(types.Object):
    """
    EventSource contains information for an event.
    """

    @context.scoped
    @typechecked
    def __init__(self, component: str = None, host: str = None):
        super().__init__()
        self.__component = component
        self.__host = host

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        component = self.component()
        check_type("component", component, Optional[str])
        if component:  # omit empty
            v["component"] = component
        host = self.host()
        check_type("host", host, Optional[str])
        if host:  # omit empty
            v["host"] = host
        return v

    def component(self) -> Optional[str]:
        """
        Component from which the event is generated.
        """
        return self.__component

    def host(self) -> Optional[str]:
        """
        Node name on which the event is generated.
        """
        return self.__host


class Event(base.TypedObject, base.NamespacedMetadataObject):
    """
    Event is a report of an event somewhere in the cluster.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        involved_object: "ObjectReference" = None,
        reason: str = None,
        message: str = None,
        source: "EventSource" = None,
        first_timestamp: "base.Time" = None,
        last_timestamp: "base.Time" = None,
        count: int = None,
        type: str = None,
        event_time: "base.MicroTime" = None,
        series: "EventSeries" = None,
        action: str = None,
        related: "ObjectReference" = None,
        reporting_component: str = "",
        reporting_instance: str = "",
    ):
        super().__init__(
            api_version="v1",
            kind="Event",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__involved_object = (
            involved_object if involved_object is not None else ObjectReference()
        )
        self.__reason = reason
        self.__message = message
        self.__source = source if source is not None else EventSource()
        self.__first_timestamp = first_timestamp
        self.__last_timestamp = last_timestamp
        self.__count = count
        self.__type = type
        self.__event_time = event_time
        self.__series = series
        self.__action = action
        self.__related = related
        self.__reporting_component = reporting_component
        self.__reporting_instance = reporting_instance

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        involved_object = self.involved_object()
        check_type("involved_object", involved_object, "ObjectReference")
        v["involvedObject"] = involved_object
        reason = self.reason()
        check_type("reason", reason, Optional[str])
        if reason:  # omit empty
            v["reason"] = reason
        message = self.message()
        check_type("message", message, Optional[str])
        if message:  # omit empty
            v["message"] = message
        source = self.source()
        check_type("source", source, Optional["EventSource"])
        v["source"] = source
        first_timestamp = self.first_timestamp()
        check_type("first_timestamp", first_timestamp, Optional["base.Time"])
        v["firstTimestamp"] = first_timestamp
        last_timestamp = self.last_timestamp()
        check_type("last_timestamp", last_timestamp, Optional["base.Time"])
        v["lastTimestamp"] = last_timestamp
        count = self.count()
        check_type("count", count, Optional[int])
        if count:  # omit empty
            v["count"] = count
        type = self.type()
        check_type("type", type, Optional[str])
        if type:  # omit empty
            v["type"] = type
        event_time = self.event_time()
        check_type("event_time", event_time, Optional["base.MicroTime"])
        v["eventTime"] = event_time
        series = self.series()
        check_type("series", series, Optional["EventSeries"])
        if series is not None:  # omit empty
            v["series"] = series
        action = self.action()
        check_type("action", action, Optional[str])
        if action:  # omit empty
            v["action"] = action
        related = self.related()
        check_type("related", related, Optional["ObjectReference"])
        if related is not None:  # omit empty
            v["related"] = related
        reporting_component = self.reporting_component()
        check_type("reporting_component", reporting_component, str)
        v["reportingComponent"] = reporting_component
        reporting_instance = self.reporting_instance()
        check_type("reporting_instance", reporting_instance, str)
        v["reportingInstance"] = reporting_instance
        return v

    def involved_object(self) -> "ObjectReference":
        """
        The object that this event is about.
        """
        return self.__involved_object

    def reason(self) -> Optional[str]:
        """
        This should be a short, machine understandable string that gives the reason
        for the transition into the object's current status.
        TODO: provide exact specification for format.
        """
        return self.__reason

    def message(self) -> Optional[str]:
        """
        A human-readable description of the status of this operation.
        TODO: decide on maximum length.
        """
        return self.__message

    def source(self) -> Optional["EventSource"]:
        """
        The component reporting this event. Should be a short machine understandable string.
        """
        return self.__source

    def first_timestamp(self) -> Optional["base.Time"]:
        """
        The time at which the event was first recorded. (Time of server receipt is in TypeMeta.)
        """
        return self.__first_timestamp

    def last_timestamp(self) -> Optional["base.Time"]:
        """
        The time at which the most recent occurrence of this event was recorded.
        """
        return self.__last_timestamp

    def count(self) -> Optional[int]:
        """
        The number of times this event has occurred.
        """
        return self.__count

    def type(self) -> Optional[str]:
        """
        Type of this event (Normal, Warning), new types could be added in the future
        """
        return self.__type

    def event_time(self) -> Optional["base.MicroTime"]:
        """
        Time when this Event was first observed.
        """
        return self.__event_time

    def series(self) -> Optional["EventSeries"]:
        """
        Data about the Event series this event represents or nil if it's a singleton Event.
        """
        return self.__series

    def action(self) -> Optional[str]:
        """
        What action was taken/failed regarding to the Regarding object.
        """
        return self.__action

    def related(self) -> Optional["ObjectReference"]:
        """
        Optional secondary object for more complex actions.
        """
        return self.__related

    def reporting_component(self) -> str:
        """
        Name of the controller that emitted this Event, e.g. `kubernetes.io/kubelet`.
        """
        return self.__reporting_component

    def reporting_instance(self) -> str:
        """
        ID of the controller instance, e.g. `kubelet-xyzf`.
        """
        return self.__reporting_instance


class FCVolumeSource(types.Object):
    """
    Represents a Fibre Channel volume.
    Fibre Channel volumes can only be mounted as read/write once.
    Fibre Channel volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        target_wwns: List[str] = None,
        lun: int = None,
        fs_type: str = None,
        read_only: bool = None,
        wwids: List[str] = None,
    ):
        super().__init__()
        self.__target_wwns = target_wwns if target_wwns is not None else []
        self.__lun = lun
        self.__fs_type = fs_type
        self.__read_only = read_only
        self.__wwids = wwids if wwids is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        target_wwns = self.target_wwns()
        check_type("target_wwns", target_wwns, Optional[List[str]])
        if target_wwns:  # omit empty
            v["targetWWNs"] = target_wwns
        lun = self.lun()
        check_type("lun", lun, Optional[int])
        if lun is not None:  # omit empty
            v["lun"] = lun
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        wwids = self.wwids()
        check_type("wwids", wwids, Optional[List[str]])
        if wwids:  # omit empty
            v["wwids"] = wwids
        return v

    def target_wwns(self) -> Optional[List[str]]:
        """
        Optional: FC target worldwide names (WWNs)
        """
        return self.__target_wwns

    def lun(self) -> Optional[int]:
        """
        Optional: FC target lun number
        """
        return self.__lun

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        TODO: how do we prevent errors in the filesystem from compromising the machine
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        Optional: Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only

    def wwids(self) -> Optional[List[str]]:
        """
        Optional: FC volume world wide identifiers (wwids)
        Either wwids or combination of targetWWNs and lun must be set, but not both simultaneously.
        """
        return self.__wwids


class FlexPersistentVolumeSource(types.Object):
    """
    FlexPersistentVolumeSource represents a generic persistent volume resource that is
    provisioned/attached using an exec based plugin.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        driver: str = "",
        fs_type: str = None,
        secret_ref: "SecretReference" = None,
        read_only: bool = None,
        options: Dict[str, str] = None,
    ):
        super().__init__()
        self.__driver = driver
        self.__fs_type = fs_type
        self.__secret_ref = secret_ref
        self.__read_only = read_only
        self.__options = options if options is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        driver = self.driver()
        check_type("driver", driver, str)
        v["driver"] = driver
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["SecretReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        options = self.options()
        check_type("options", options, Optional[Dict[str, str]])
        if options:  # omit empty
            v["options"] = options
        return v

    def driver(self) -> str:
        """
        Driver is the name of the driver to use for this volume.
        """
        return self.__driver

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs". The default filesystem depends on FlexVolume script.
        """
        return self.__fs_type

    def secret_ref(self) -> Optional["SecretReference"]:
        """
        Optional: SecretRef is reference to the secret object containing
        sensitive information to pass to the plugin scripts. This may be
        empty if no secret object is specified. If the secret object
        contains more than one secret, all secrets are passed to the plugin
        scripts.
        """
        return self.__secret_ref

    def read_only(self) -> Optional[bool]:
        """
        Optional: Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only

    def options(self) -> Optional[Dict[str, str]]:
        """
        Optional: Extra command options if any.
        """
        return self.__options


class FlexVolumeSource(types.Object):
    """
    FlexVolume represents a generic volume resource that is
    provisioned/attached using an exec based plugin.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        driver: str = "",
        fs_type: str = None,
        secret_ref: "LocalObjectReference" = None,
        read_only: bool = None,
        options: Dict[str, str] = None,
    ):
        super().__init__()
        self.__driver = driver
        self.__fs_type = fs_type
        self.__secret_ref = secret_ref
        self.__read_only = read_only
        self.__options = options if options is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        driver = self.driver()
        check_type("driver", driver, str)
        v["driver"] = driver
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["LocalObjectReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        options = self.options()
        check_type("options", options, Optional[Dict[str, str]])
        if options:  # omit empty
            v["options"] = options
        return v

    def driver(self) -> str:
        """
        Driver is the name of the driver to use for this volume.
        """
        return self.__driver

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs". The default filesystem depends on FlexVolume script.
        """
        return self.__fs_type

    def secret_ref(self) -> Optional["LocalObjectReference"]:
        """
        Optional: SecretRef is reference to the secret object containing
        sensitive information to pass to the plugin scripts. This may be
        empty if no secret object is specified. If the secret object
        contains more than one secret, all secrets are passed to the plugin
        scripts.
        """
        return self.__secret_ref

    def read_only(self) -> Optional[bool]:
        """
        Optional: Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only

    def options(self) -> Optional[Dict[str, str]]:
        """
        Optional: Extra command options if any.
        """
        return self.__options


class FlockerVolumeSource(types.Object):
    """
    Represents a Flocker volume mounted by the Flocker agent.
    One and only one of datasetName and datasetUUID should be set.
    Flocker volumes do not support ownership management or SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(self, dataset_name: str = None, dataset_uuid: str = None):
        super().__init__()
        self.__dataset_name = dataset_name
        self.__dataset_uuid = dataset_uuid

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        dataset_name = self.dataset_name()
        check_type("dataset_name", dataset_name, Optional[str])
        if dataset_name:  # omit empty
            v["datasetName"] = dataset_name
        dataset_uuid = self.dataset_uuid()
        check_type("dataset_uuid", dataset_uuid, Optional[str])
        if dataset_uuid:  # omit empty
            v["datasetUUID"] = dataset_uuid
        return v

    def dataset_name(self) -> Optional[str]:
        """
        Name of the dataset stored as metadata -> name on the dataset for Flocker
        should be considered as deprecated
        """
        return self.__dataset_name

    def dataset_uuid(self) -> Optional[str]:
        """
        UUID of the dataset. This is unique identifier of a Flocker dataset
        """
        return self.__dataset_uuid


class GCEPersistentDiskVolumeSource(types.Object):
    """
    Represents a Persistent Disk resource in Google Compute Engine.
    
    A GCE PD must exist before mounting to a container. The disk must
    also be in the same GCE project and zone as the kubelet. A GCE PD
    can only be mounted as read/write once or read-only many times. GCE
    PDs support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        pd_name: str = "",
        fs_type: str = None,
        partition: int = None,
        read_only: bool = None,
    ):
        super().__init__()
        self.__pd_name = pd_name
        self.__fs_type = fs_type
        self.__partition = partition
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pd_name = self.pd_name()
        check_type("pd_name", pd_name, str)
        v["pdName"] = pd_name
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        partition = self.partition()
        check_type("partition", partition, Optional[int])
        if partition:  # omit empty
            v["partition"] = partition
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def pd_name(self) -> str:
        """
        Unique name of the PD resource in GCE. Used to identify the disk in GCE.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
        """
        return self.__pd_name

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type of the volume that you want to mount.
        Tip: Ensure that the filesystem type is supported by the host operating system.
        Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
        TODO: how do we prevent errors in the filesystem from compromising the machine
        """
        return self.__fs_type

    def partition(self) -> Optional[int]:
        """
        The partition in the volume that you want to mount.
        If omitted, the default is to mount by volume name.
        Examples: For volume /dev/sda1, you specify the partition as "1".
        Similarly, the volume partition for /dev/sda is "0" (or you can leave the property empty).
        More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
        """
        return self.__partition

    def read_only(self) -> Optional[bool]:
        """
        ReadOnly here will force the ReadOnly setting in VolumeMounts.
        Defaults to false.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
        """
        return self.__read_only


class GlusterfsPersistentVolumeSource(types.Object):
    """
    Represents a Glusterfs mount that lasts the lifetime of a pod.
    Glusterfs volumes do not support ownership management or SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        endpoints: str = "",
        path: str = "",
        read_only: bool = None,
        endpoints_namespace: str = None,
    ):
        super().__init__()
        self.__endpoints = endpoints
        self.__path = path
        self.__read_only = read_only
        self.__endpoints_namespace = endpoints_namespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        endpoints = self.endpoints()
        check_type("endpoints", endpoints, str)
        v["endpoints"] = endpoints
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        endpoints_namespace = self.endpoints_namespace()
        check_type("endpoints_namespace", endpoints_namespace, Optional[str])
        if endpoints_namespace is not None:  # omit empty
            v["endpointsNamespace"] = endpoints_namespace
        return v

    def endpoints(self) -> str:
        """
        EndpointsName is the endpoint name that details Glusterfs topology.
        More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
        """
        return self.__endpoints

    def path(self) -> str:
        """
        Path is the Glusterfs volume path.
        More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
        """
        return self.__path

    def read_only(self) -> Optional[bool]:
        """
        ReadOnly here will force the Glusterfs volume to be mounted with read-only permissions.
        Defaults to false.
        More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
        """
        return self.__read_only

    def endpoints_namespace(self) -> Optional[str]:
        """
        EndpointsNamespace is the namespace that contains Glusterfs endpoint.
        If this field is empty, the EndpointNamespace defaults to the same namespace as the bound PVC.
        More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
        """
        return self.__endpoints_namespace


class GlusterfsVolumeSource(types.Object):
    """
    Represents a Glusterfs mount that lasts the lifetime of a pod.
    Glusterfs volumes do not support ownership management or SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(self, endpoints: str = "", path: str = "", read_only: bool = None):
        super().__init__()
        self.__endpoints = endpoints
        self.__path = path
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        endpoints = self.endpoints()
        check_type("endpoints", endpoints, str)
        v["endpoints"] = endpoints
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def endpoints(self) -> str:
        """
        EndpointsName is the endpoint name that details Glusterfs topology.
        More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
        """
        return self.__endpoints

    def path(self) -> str:
        """
        Path is the Glusterfs volume path.
        More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
        """
        return self.__path

    def read_only(self) -> Optional[bool]:
        """
        ReadOnly here will force the Glusterfs volume to be mounted with read-only permissions.
        Defaults to false.
        More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
        """
        return self.__read_only


class HostAlias(types.Object):
    """
    HostAlias holds the mapping between IP and hostnames that will be injected as an entry in the
    pod's hosts file.
    """

    @context.scoped
    @typechecked
    def __init__(self, ip: str = None, hostnames: List[str] = None):
        super().__init__()
        self.__ip = ip
        self.__hostnames = hostnames if hostnames is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ip = self.ip()
        check_type("ip", ip, Optional[str])
        if ip:  # omit empty
            v["ip"] = ip
        hostnames = self.hostnames()
        check_type("hostnames", hostnames, Optional[List[str]])
        if hostnames:  # omit empty
            v["hostnames"] = hostnames
        return v

    def ip(self) -> Optional[str]:
        """
        IP address of the host file entry.
        """
        return self.__ip

    def hostnames(self) -> Optional[List[str]]:
        """
        Hostnames for the above IP address.
        """
        return self.__hostnames


class HostPathVolumeSource(types.Object):
    """
    Represents a host path mapped into a pod.
    Host path volumes do not support ownership management or SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(self, path: str = "", type: HostPathType = None):
        super().__init__()
        self.__path = path
        self.__type = type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        type = self.type()
        check_type("type", type, Optional[HostPathType])
        if type is not None:  # omit empty
            v["type"] = type
        return v

    def path(self) -> str:
        """
        Path of the directory on the host.
        If the path is a symlink, it will follow the link to the real path.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#hostpath
        """
        return self.__path

    def type(self) -> Optional[HostPathType]:
        """
        Type for HostPath Volume
        Defaults to ""
        More info: https://kubernetes.io/docs/concepts/storage/volumes#hostpath
        """
        return self.__type


class ISCSIPersistentVolumeSource(types.Object):
    """
    ISCSIPersistentVolumeSource represents an ISCSI disk.
    ISCSI volumes can only be mounted as read/write once.
    ISCSI volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        target_portal: str = "",
        iqn: str = "",
        lun: int = 0,
        iscsi_interface: str = "default",
        fs_type: str = None,
        read_only: bool = None,
        portals: List[str] = None,
        chap_auth_discovery: bool = None,
        chap_auth_session: bool = None,
        secret_ref: "SecretReference" = None,
        initiator_name: str = None,
    ):
        super().__init__()
        self.__target_portal = target_portal
        self.__iqn = iqn
        self.__lun = lun
        self.__iscsi_interface = iscsi_interface
        self.__fs_type = fs_type
        self.__read_only = read_only
        self.__portals = portals if portals is not None else []
        self.__chap_auth_discovery = chap_auth_discovery
        self.__chap_auth_session = chap_auth_session
        self.__secret_ref = secret_ref
        self.__initiator_name = initiator_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        target_portal = self.target_portal()
        check_type("target_portal", target_portal, str)
        v["targetPortal"] = target_portal
        iqn = self.iqn()
        check_type("iqn", iqn, str)
        v["iqn"] = iqn
        lun = self.lun()
        check_type("lun", lun, int)
        v["lun"] = lun
        iscsi_interface = self.iscsi_interface()
        check_type("iscsi_interface", iscsi_interface, Optional[str])
        if iscsi_interface:  # omit empty
            v["iscsiInterface"] = iscsi_interface
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        portals = self.portals()
        check_type("portals", portals, Optional[List[str]])
        if portals:  # omit empty
            v["portals"] = portals
        chap_auth_discovery = self.chap_auth_discovery()
        check_type("chap_auth_discovery", chap_auth_discovery, Optional[bool])
        if chap_auth_discovery:  # omit empty
            v["chapAuthDiscovery"] = chap_auth_discovery
        chap_auth_session = self.chap_auth_session()
        check_type("chap_auth_session", chap_auth_session, Optional[bool])
        if chap_auth_session:  # omit empty
            v["chapAuthSession"] = chap_auth_session
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["SecretReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        initiator_name = self.initiator_name()
        check_type("initiator_name", initiator_name, Optional[str])
        if initiator_name is not None:  # omit empty
            v["initiatorName"] = initiator_name
        return v

    def target_portal(self) -> str:
        """
        iSCSI Target Portal. The Portal is either an IP or ip_addr:port if the port
        is other than default (typically TCP ports 860 and 3260).
        """
        return self.__target_portal

    def iqn(self) -> str:
        """
        Target iSCSI Qualified Name.
        """
        return self.__iqn

    def lun(self) -> int:
        """
        iSCSI Target Lun number.
        """
        return self.__lun

    def iscsi_interface(self) -> Optional[str]:
        """
        iSCSI Interface Name that uses an iSCSI transport.
        Defaults to 'default' (tcp).
        """
        return self.__iscsi_interface

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type of the volume that you want to mount.
        Tip: Ensure that the filesystem type is supported by the host operating system.
        Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#iscsi
        TODO: how do we prevent errors in the filesystem from compromising the machine
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        ReadOnly here will force the ReadOnly setting in VolumeMounts.
        Defaults to false.
        """
        return self.__read_only

    def portals(self) -> Optional[List[str]]:
        """
        iSCSI Target Portal List. The Portal is either an IP or ip_addr:port if the port
        is other than default (typically TCP ports 860 and 3260).
        """
        return self.__portals

    def chap_auth_discovery(self) -> Optional[bool]:
        """
        whether support iSCSI Discovery CHAP authentication
        """
        return self.__chap_auth_discovery

    def chap_auth_session(self) -> Optional[bool]:
        """
        whether support iSCSI Session CHAP authentication
        """
        return self.__chap_auth_session

    def secret_ref(self) -> Optional["SecretReference"]:
        """
        CHAP Secret for iSCSI target and initiator authentication
        """
        return self.__secret_ref

    def initiator_name(self) -> Optional[str]:
        """
        Custom iSCSI Initiator Name.
        If initiatorName is specified with iscsiInterface simultaneously, new iSCSI interface
        <target portal>:<volume name> will be created for the connection.
        """
        return self.__initiator_name


class ISCSIVolumeSource(types.Object):
    """
    Represents an ISCSI disk.
    ISCSI volumes can only be mounted as read/write once.
    ISCSI volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        target_portal: str = "",
        iqn: str = "",
        lun: int = 0,
        iscsi_interface: str = "default",
        fs_type: str = None,
        read_only: bool = None,
        portals: List[str] = None,
        chap_auth_discovery: bool = None,
        chap_auth_session: bool = None,
        secret_ref: "LocalObjectReference" = None,
        initiator_name: str = None,
    ):
        super().__init__()
        self.__target_portal = target_portal
        self.__iqn = iqn
        self.__lun = lun
        self.__iscsi_interface = iscsi_interface
        self.__fs_type = fs_type
        self.__read_only = read_only
        self.__portals = portals if portals is not None else []
        self.__chap_auth_discovery = chap_auth_discovery
        self.__chap_auth_session = chap_auth_session
        self.__secret_ref = secret_ref
        self.__initiator_name = initiator_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        target_portal = self.target_portal()
        check_type("target_portal", target_portal, str)
        v["targetPortal"] = target_portal
        iqn = self.iqn()
        check_type("iqn", iqn, str)
        v["iqn"] = iqn
        lun = self.lun()
        check_type("lun", lun, int)
        v["lun"] = lun
        iscsi_interface = self.iscsi_interface()
        check_type("iscsi_interface", iscsi_interface, Optional[str])
        if iscsi_interface:  # omit empty
            v["iscsiInterface"] = iscsi_interface
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        portals = self.portals()
        check_type("portals", portals, Optional[List[str]])
        if portals:  # omit empty
            v["portals"] = portals
        chap_auth_discovery = self.chap_auth_discovery()
        check_type("chap_auth_discovery", chap_auth_discovery, Optional[bool])
        if chap_auth_discovery:  # omit empty
            v["chapAuthDiscovery"] = chap_auth_discovery
        chap_auth_session = self.chap_auth_session()
        check_type("chap_auth_session", chap_auth_session, Optional[bool])
        if chap_auth_session:  # omit empty
            v["chapAuthSession"] = chap_auth_session
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["LocalObjectReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        initiator_name = self.initiator_name()
        check_type("initiator_name", initiator_name, Optional[str])
        if initiator_name is not None:  # omit empty
            v["initiatorName"] = initiator_name
        return v

    def target_portal(self) -> str:
        """
        iSCSI Target Portal. The Portal is either an IP or ip_addr:port if the port
        is other than default (typically TCP ports 860 and 3260).
        """
        return self.__target_portal

    def iqn(self) -> str:
        """
        Target iSCSI Qualified Name.
        """
        return self.__iqn

    def lun(self) -> int:
        """
        iSCSI Target Lun number.
        """
        return self.__lun

    def iscsi_interface(self) -> Optional[str]:
        """
        iSCSI Interface Name that uses an iSCSI transport.
        Defaults to 'default' (tcp).
        """
        return self.__iscsi_interface

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type of the volume that you want to mount.
        Tip: Ensure that the filesystem type is supported by the host operating system.
        Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#iscsi
        TODO: how do we prevent errors in the filesystem from compromising the machine
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        ReadOnly here will force the ReadOnly setting in VolumeMounts.
        Defaults to false.
        """
        return self.__read_only

    def portals(self) -> Optional[List[str]]:
        """
        iSCSI Target Portal List. The portal is either an IP or ip_addr:port if the port
        is other than default (typically TCP ports 860 and 3260).
        """
        return self.__portals

    def chap_auth_discovery(self) -> Optional[bool]:
        """
        whether support iSCSI Discovery CHAP authentication
        """
        return self.__chap_auth_discovery

    def chap_auth_session(self) -> Optional[bool]:
        """
        whether support iSCSI Session CHAP authentication
        """
        return self.__chap_auth_session

    def secret_ref(self) -> Optional["LocalObjectReference"]:
        """
        CHAP Secret for iSCSI target and initiator authentication
        """
        return self.__secret_ref

    def initiator_name(self) -> Optional[str]:
        """
        Custom iSCSI Initiator Name.
        If initiatorName is specified with iscsiInterface simultaneously, new iSCSI interface
        <target portal>:<volume name> will be created for the connection.
        """
        return self.__initiator_name


class LimitRangeItem(types.Object):
    """
    LimitRangeItem defines a min/max usage limit for any resource that matches on kind.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: LimitType = None,
        max: Dict[ResourceName, "resource.Quantity"] = None,
        min: Dict[ResourceName, "resource.Quantity"] = None,
        default: Dict[ResourceName, "resource.Quantity"] = None,
        default_request: Dict[ResourceName, "resource.Quantity"] = None,
        max_limit_request_ratio: Dict[ResourceName, "resource.Quantity"] = None,
    ):
        super().__init__()
        self.__type = type
        self.__max = max if max is not None else {}
        self.__min = min if min is not None else {}
        self.__default = default if default is not None else {}
        self.__default_request = default_request if default_request is not None else {}
        self.__max_limit_request_ratio = (
            max_limit_request_ratio if max_limit_request_ratio is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[LimitType])
        if type:  # omit empty
            v["type"] = type
        max = self.max()
        check_type("max", max, Optional[Dict[ResourceName, "resource.Quantity"]])
        if max:  # omit empty
            v["max"] = max
        min = self.min()
        check_type("min", min, Optional[Dict[ResourceName, "resource.Quantity"]])
        if min:  # omit empty
            v["min"] = min
        default = self.default()
        check_type(
            "default", default, Optional[Dict[ResourceName, "resource.Quantity"]]
        )
        if default:  # omit empty
            v["default"] = default
        default_request = self.default_request()
        check_type(
            "default_request",
            default_request,
            Optional[Dict[ResourceName, "resource.Quantity"]],
        )
        if default_request:  # omit empty
            v["defaultRequest"] = default_request
        max_limit_request_ratio = self.max_limit_request_ratio()
        check_type(
            "max_limit_request_ratio",
            max_limit_request_ratio,
            Optional[Dict[ResourceName, "resource.Quantity"]],
        )
        if max_limit_request_ratio:  # omit empty
            v["maxLimitRequestRatio"] = max_limit_request_ratio
        return v

    def type(self) -> Optional[LimitType]:
        """
        Type of resource that this limit applies to.
        """
        return self.__type

    def max(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        """
        Max usage constraints on this kind by resource name.
        """
        return self.__max

    def min(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        """
        Min usage constraints on this kind by resource name.
        """
        return self.__min

    def default(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        """
        Default resource requirement limit value by resource name if resource limit is omitted.
        """
        return self.__default

    def default_request(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        """
        DefaultRequest is the default resource requirement request value by resource name if resource request is omitted.
        """
        return self.__default_request

    def max_limit_request_ratio(
        self
    ) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        """
        MaxLimitRequestRatio if specified, the named resource must have a request and limit that are both non-zero where limit divided by request is less than or equal to the enumerated value; this represents the max burst for the named resource.
        """
        return self.__max_limit_request_ratio


class LimitRangeSpec(types.Object):
    """
    LimitRangeSpec defines a min/max usage limit for resources that match on kind.
    """

    @context.scoped
    @typechecked
    def __init__(self, limits: List["LimitRangeItem"] = None):
        super().__init__()
        self.__limits = limits if limits is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        limits = self.limits()
        check_type("limits", limits, List["LimitRangeItem"])
        v["limits"] = limits
        return v

    def limits(self) -> List["LimitRangeItem"]:
        """
        Limits is the list of LimitRangeItem objects that are enforced.
        """
        return self.__limits


class LimitRange(base.TypedObject, base.NamespacedMetadataObject):
    """
    LimitRange sets resource usage limits for each kind of resource in a Namespace.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "LimitRangeSpec" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="LimitRange",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else LimitRangeSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["LimitRangeSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["LimitRangeSpec"]:
        """
        Spec defines the limits enforced.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class LocalVolumeSource(types.Object):
    """
    Local represents directly-attached storage with node affinity (Beta feature)
    """

    @context.scoped
    @typechecked
    def __init__(self, path: str = "", fs_type: str = None):
        super().__init__()
        self.__path = path
        self.__fs_type = fs_type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type is not None:  # omit empty
            v["fsType"] = fs_type
        return v

    def path(self) -> str:
        """
        The full path to the volume on the node.
        It can be either a directory or block device (disk, partition, ...).
        """
        return self.__path

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        It applies only when the Path is a block device.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs". The default value is to auto-select a fileystem if unspecified.
        """
        return self.__fs_type


class NFSVolumeSource(types.Object):
    """
    Represents an NFS mount that lasts the lifetime of a pod.
    NFS volumes do not support ownership management or SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(self, server: str = "", path: str = "", read_only: bool = None):
        super().__init__()
        self.__server = server
        self.__path = path
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        server = self.server()
        check_type("server", server, str)
        v["server"] = server
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def server(self) -> str:
        """
        Server is the hostname or IP address of the NFS server.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#nfs
        """
        return self.__server

    def path(self) -> str:
        """
        Path that is exported by the NFS server.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#nfs
        """
        return self.__path

    def read_only(self) -> Optional[bool]:
        """
        ReadOnly here will force
        the NFS export to be mounted with read-only permissions.
        Defaults to false.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#nfs
        """
        return self.__read_only


class NamespaceSpec(types.Object):
    """
    NamespaceSpec describes the attributes on a Namespace.
    """

    @context.scoped
    @typechecked
    def __init__(self, finalizers: List[FinalizerName] = None):
        super().__init__()
        self.__finalizers = finalizers if finalizers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        finalizers = self.finalizers()
        check_type("finalizers", finalizers, Optional[List[FinalizerName]])
        if finalizers:  # omit empty
            v["finalizers"] = finalizers
        return v

    def finalizers(self) -> Optional[List[FinalizerName]]:
        """
        Finalizers is an opaque list of values that must be empty to permanently remove object from storage.
        More info: https://kubernetes.io/docs/tasks/administer-cluster/namespaces/
        """
        return self.__finalizers


class Namespace(base.TypedObject, base.MetadataObject):
    """
    Namespace provides a scope for Names.
    Use of multiple namespaces is optional.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "NamespaceSpec" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="Namespace",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else NamespaceSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["NamespaceSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["NamespaceSpec"]:
        """
        Spec defines the behavior of the Namespace.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class NodeConfigSource(types.Object):
    """
    NodeConfigSource specifies a source of node configuration. Exactly one subfield (excluding metadata) must be non-nil.
    """

    @context.scoped
    @typechecked
    def __init__(self, config_map: "ConfigMapNodeConfigSource" = None):
        super().__init__()
        self.__config_map = config_map

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        config_map = self.config_map()
        check_type("config_map", config_map, Optional["ConfigMapNodeConfigSource"])
        if config_map is not None:  # omit empty
            v["configMap"] = config_map
        return v

    def config_map(self) -> Optional["ConfigMapNodeConfigSource"]:
        """
        ConfigMap is a reference to a Node's ConfigMap
        """
        return self.__config_map


class Taint(types.Object):
    """
    The node this Taint is attached to has the "effect" on
    any pod that does not tolerate the Taint.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        key: str = "",
        value: str = None,
        effect: TaintEffect = None,
        time_added: "base.Time" = None,
    ):
        super().__init__()
        self.__key = key
        self.__value = value
        self.__effect = effect
        self.__time_added = time_added

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        key = self.key()
        check_type("key", key, str)
        v["key"] = key
        value = self.value()
        check_type("value", value, Optional[str])
        if value:  # omit empty
            v["value"] = value
        effect = self.effect()
        check_type("effect", effect, TaintEffect)
        v["effect"] = effect
        time_added = self.time_added()
        check_type("time_added", time_added, Optional["base.Time"])
        if time_added is not None:  # omit empty
            v["timeAdded"] = time_added
        return v

    def key(self) -> str:
        """
        Required. The taint key to be applied to a node.
        """
        return self.__key

    def value(self) -> Optional[str]:
        """
        Required. The taint value corresponding to the taint key.
        """
        return self.__value

    def effect(self) -> TaintEffect:
        """
        Required. The effect of the taint on pods
        that do not tolerate the taint.
        Valid effects are NoSchedule, PreferNoSchedule and NoExecute.
        """
        return self.__effect

    def time_added(self) -> Optional["base.Time"]:
        """
        TimeAdded represents the time at which the taint was added.
        It is only written for NoExecute taints.
        """
        return self.__time_added


class NodeSpec(types.Object):
    """
    NodeSpec describes the attributes that a node is created with.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        pod_cidr: str = None,
        pod_cidrs: List[str] = None,
        provider_id: str = None,
        unschedulable: bool = None,
        taints: List["Taint"] = None,
        config_source: "NodeConfigSource" = None,
    ):
        super().__init__()
        self.__pod_cidr = pod_cidr
        self.__pod_cidrs = pod_cidrs if pod_cidrs is not None else []
        self.__provider_id = provider_id
        self.__unschedulable = unschedulable
        self.__taints = taints if taints is not None else []
        self.__config_source = config_source

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pod_cidr = self.pod_cidr()
        check_type("pod_cidr", pod_cidr, Optional[str])
        if pod_cidr:  # omit empty
            v["podCIDR"] = pod_cidr
        pod_cidrs = self.pod_cidrs()
        check_type("pod_cidrs", pod_cidrs, Optional[List[str]])
        if pod_cidrs:  # omit empty
            v["podCIDRs"] = pod_cidrs
        provider_id = self.provider_id()
        check_type("provider_id", provider_id, Optional[str])
        if provider_id:  # omit empty
            v["providerID"] = provider_id
        unschedulable = self.unschedulable()
        check_type("unschedulable", unschedulable, Optional[bool])
        if unschedulable:  # omit empty
            v["unschedulable"] = unschedulable
        taints = self.taints()
        check_type("taints", taints, Optional[List["Taint"]])
        if taints:  # omit empty
            v["taints"] = taints
        config_source = self.config_source()
        check_type("config_source", config_source, Optional["NodeConfigSource"])
        if config_source is not None:  # omit empty
            v["configSource"] = config_source
        return v

    def pod_cidr(self) -> Optional[str]:
        """
        PodCIDR represents the pod IP range assigned to the node.
        """
        return self.__pod_cidr

    def pod_cidrs(self) -> Optional[List[str]]:
        """
        podCIDRs represents the IP ranges assigned to the node for usage by Pods on that node. If this
        field is specified, the 0th entry must match the podCIDR field. It may contain at most 1 value for
        each of IPv4 and IPv6.
        """
        return self.__pod_cidrs

    def provider_id(self) -> Optional[str]:
        """
        ID of the node assigned by the cloud provider in the format: <ProviderName>://<ProviderSpecificNodeID>
        """
        return self.__provider_id

    def unschedulable(self) -> Optional[bool]:
        """
        Unschedulable controls node schedulability of new pods. By default, node is schedulable.
        More info: https://kubernetes.io/docs/concepts/nodes/node/#manual-node-administration
        """
        return self.__unschedulable

    def taints(self) -> Optional[List["Taint"]]:
        """
        If specified, the node's taints.
        """
        return self.__taints

    def config_source(self) -> Optional["NodeConfigSource"]:
        """
        If specified, the source to get node configuration from
        The DynamicKubeletConfig feature gate must be enabled for the Kubelet to use this field
        """
        return self.__config_source


class Node(base.TypedObject, base.MetadataObject):
    """
    Node is a worker node in Kubernetes.
    Each node will have a unique identifier in the cache (i.e. in etcd).
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "NodeSpec" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="Node",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else NodeSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["NodeSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["NodeSpec"]:
        """
        Spec defines the behavior of a node.
        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class NodeProxyOptions(base.TypedObject):
    """
    NodeProxyOptions is the query options to a Node's proxy call.
    """

    @context.scoped
    @typechecked
    def __init__(self, path: str = None):
        super().__init__(api_version="v1", kind="NodeProxyOptions")
        self.__path = path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        return v

    def path(self) -> Optional[str]:
        """
        Path is the URL path to use for the current proxy request to node.
        """
        return self.__path


class PhotonPersistentDiskVolumeSource(types.Object):
    """
    Represents a Photon Controller persistent disk resource.
    """

    @context.scoped
    @typechecked
    def __init__(self, pd_id: str = "", fs_type: str = None):
        super().__init__()
        self.__pd_id = pd_id
        self.__fs_type = fs_type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pd_id = self.pd_id()
        check_type("pd_id", pd_id, str)
        v["pdID"] = pd_id
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        return v

    def pd_id(self) -> str:
        """
        ID that identifies Photon Controller persistent disk
        """
        return self.__pd_id

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        """
        return self.__fs_type


class PortworxVolumeSource(types.Object):
    """
    PortworxVolumeSource represents a Portworx volume resource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, volume_id: str = "", fs_type: str = None, read_only: bool = None
    ):
        super().__init__()
        self.__volume_id = volume_id
        self.__fs_type = fs_type
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volume_id = self.volume_id()
        check_type("volume_id", volume_id, str)
        v["volumeID"] = volume_id
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def volume_id(self) -> str:
        """
        VolumeID uniquely identifies a Portworx volume
        """
        return self.__volume_id

    def fs_type(self) -> Optional[str]:
        """
        FSType represents the filesystem type to mount
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs". Implicitly inferred to be "ext4" if unspecified.
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only


class QuobyteVolumeSource(types.Object):
    """
    Represents a Quobyte mount that lasts the lifetime of a pod.
    Quobyte volumes do not support ownership management or SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        registry: str = "",
        volume: str = "",
        read_only: bool = None,
        user: str = None,
        group: str = None,
        tenant: str = None,
    ):
        super().__init__()
        self.__registry = registry
        self.__volume = volume
        self.__read_only = read_only
        self.__user = user
        self.__group = group
        self.__tenant = tenant

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        registry = self.registry()
        check_type("registry", registry, str)
        v["registry"] = registry
        volume = self.volume()
        check_type("volume", volume, str)
        v["volume"] = volume
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        user = self.user()
        check_type("user", user, Optional[str])
        if user:  # omit empty
            v["user"] = user
        group = self.group()
        check_type("group", group, Optional[str])
        if group:  # omit empty
            v["group"] = group
        tenant = self.tenant()
        check_type("tenant", tenant, Optional[str])
        if tenant:  # omit empty
            v["tenant"] = tenant
        return v

    def registry(self) -> str:
        """
        Registry represents a single or multiple Quobyte Registry services
        specified as a string as host:port pair (multiple entries are separated with commas)
        which acts as the central registry for volumes
        """
        return self.__registry

    def volume(self) -> str:
        """
        Volume is a string that references an already created Quobyte volume by name.
        """
        return self.__volume

    def read_only(self) -> Optional[bool]:
        """
        ReadOnly here will force the Quobyte volume to be mounted with read-only permissions.
        Defaults to false.
        """
        return self.__read_only

    def user(self) -> Optional[str]:
        """
        User to map volume access to
        Defaults to serivceaccount user
        """
        return self.__user

    def group(self) -> Optional[str]:
        """
        Group to map volume access to
        Default is no group
        """
        return self.__group

    def tenant(self) -> Optional[str]:
        """
        Tenant owning the given Quobyte volume in the Backend
        Used with dynamically provisioned Quobyte volumes, value is set by the plugin
        """
        return self.__tenant


class RBDPersistentVolumeSource(types.Object):
    """
    Represents a Rados Block Device mount that lasts the lifetime of a pod.
    RBD volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        monitors: List[str] = None,
        image: str = "",
        fs_type: str = None,
        pool: str = "rbd",
        user: str = "admin",
        keyring: str = "/etc/ceph/keyring",
        secret_ref: "SecretReference" = None,
        read_only: bool = None,
    ):
        super().__init__()
        self.__monitors = monitors if monitors is not None else []
        self.__image = image
        self.__fs_type = fs_type
        self.__pool = pool
        self.__user = user
        self.__keyring = keyring
        self.__secret_ref = secret_ref
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        monitors = self.monitors()
        check_type("monitors", monitors, List[str])
        v["monitors"] = monitors
        image = self.image()
        check_type("image", image, str)
        v["image"] = image
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        pool = self.pool()
        check_type("pool", pool, Optional[str])
        if pool:  # omit empty
            v["pool"] = pool
        user = self.user()
        check_type("user", user, Optional[str])
        if user:  # omit empty
            v["user"] = user
        keyring = self.keyring()
        check_type("keyring", keyring, Optional[str])
        if keyring:  # omit empty
            v["keyring"] = keyring
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["SecretReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def monitors(self) -> List[str]:
        """
        A collection of Ceph monitors.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__monitors

    def image(self) -> str:
        """
        The rados image name.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__image

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type of the volume that you want to mount.
        Tip: Ensure that the filesystem type is supported by the host operating system.
        Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#rbd
        TODO: how do we prevent errors in the filesystem from compromising the machine
        """
        return self.__fs_type

    def pool(self) -> Optional[str]:
        """
        The rados pool name.
        Default is rbd.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__pool

    def user(self) -> Optional[str]:
        """
        The rados user name.
        Default is admin.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__user

    def keyring(self) -> Optional[str]:
        """
        Keyring is the path to key ring for RBDUser.
        Default is /etc/ceph/keyring.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__keyring

    def secret_ref(self) -> Optional["SecretReference"]:
        """
        SecretRef is name of the authentication secret for RBDUser. If provided
        overrides keyring.
        Default is nil.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__secret_ref

    def read_only(self) -> Optional[bool]:
        """
        ReadOnly here will force the ReadOnly setting in VolumeMounts.
        Defaults to false.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__read_only


class ScaleIOPersistentVolumeSource(types.Object):
    """
    ScaleIOPersistentVolumeSource represents a persistent ScaleIO volume
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        gateway: str = "",
        system: str = "",
        secret_ref: "SecretReference" = None,
        ssl_enabled: bool = None,
        protection_domain: str = None,
        storage_pool: str = None,
        storage_mode: str = "ThinProvisioned",
        volume_name: str = None,
        fs_type: str = "xfs",
        read_only: bool = None,
    ):
        super().__init__()
        self.__gateway = gateway
        self.__system = system
        self.__secret_ref = secret_ref
        self.__ssl_enabled = ssl_enabled
        self.__protection_domain = protection_domain
        self.__storage_pool = storage_pool
        self.__storage_mode = storage_mode
        self.__volume_name = volume_name
        self.__fs_type = fs_type
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        gateway = self.gateway()
        check_type("gateway", gateway, str)
        v["gateway"] = gateway
        system = self.system()
        check_type("system", system, str)
        v["system"] = system
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["SecretReference"])
        v["secretRef"] = secret_ref
        ssl_enabled = self.ssl_enabled()
        check_type("ssl_enabled", ssl_enabled, Optional[bool])
        if ssl_enabled:  # omit empty
            v["sslEnabled"] = ssl_enabled
        protection_domain = self.protection_domain()
        check_type("protection_domain", protection_domain, Optional[str])
        if protection_domain:  # omit empty
            v["protectionDomain"] = protection_domain
        storage_pool = self.storage_pool()
        check_type("storage_pool", storage_pool, Optional[str])
        if storage_pool:  # omit empty
            v["storagePool"] = storage_pool
        storage_mode = self.storage_mode()
        check_type("storage_mode", storage_mode, Optional[str])
        if storage_mode:  # omit empty
            v["storageMode"] = storage_mode
        volume_name = self.volume_name()
        check_type("volume_name", volume_name, Optional[str])
        if volume_name:  # omit empty
            v["volumeName"] = volume_name
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def gateway(self) -> str:
        """
        The host address of the ScaleIO API Gateway.
        """
        return self.__gateway

    def system(self) -> str:
        """
        The name of the storage system as configured in ScaleIO.
        """
        return self.__system

    def secret_ref(self) -> Optional["SecretReference"]:
        """
        SecretRef references to the secret for ScaleIO user and other
        sensitive information. If this is not provided, Login operation will fail.
        """
        return self.__secret_ref

    def ssl_enabled(self) -> Optional[bool]:
        """
        Flag to enable/disable SSL communication with Gateway, default false
        """
        return self.__ssl_enabled

    def protection_domain(self) -> Optional[str]:
        """
        The name of the ScaleIO Protection Domain for the configured storage.
        """
        return self.__protection_domain

    def storage_pool(self) -> Optional[str]:
        """
        The ScaleIO Storage Pool associated with the protection domain.
        """
        return self.__storage_pool

    def storage_mode(self) -> Optional[str]:
        """
        Indicates whether the storage for a volume should be ThickProvisioned or ThinProvisioned.
        Default is ThinProvisioned.
        """
        return self.__storage_mode

    def volume_name(self) -> Optional[str]:
        """
        The name of a volume already created in the ScaleIO system
        that is associated with this volume source.
        """
        return self.__volume_name

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs".
        Default is "xfs"
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only


class StorageOSPersistentVolumeSource(types.Object):
    """
    Represents a StorageOS persistent volume resource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        volume_name: str = None,
        volume_namespace: str = None,
        fs_type: str = None,
        read_only: bool = None,
        secret_ref: "ObjectReference" = None,
    ):
        super().__init__()
        self.__volume_name = volume_name
        self.__volume_namespace = volume_namespace
        self.__fs_type = fs_type
        self.__read_only = read_only
        self.__secret_ref = secret_ref

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volume_name = self.volume_name()
        check_type("volume_name", volume_name, Optional[str])
        if volume_name:  # omit empty
            v["volumeName"] = volume_name
        volume_namespace = self.volume_namespace()
        check_type("volume_namespace", volume_namespace, Optional[str])
        if volume_namespace:  # omit empty
            v["volumeNamespace"] = volume_namespace
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["ObjectReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        return v

    def volume_name(self) -> Optional[str]:
        """
        VolumeName is the human-readable name of the StorageOS volume.  Volume
        names are only unique within a namespace.
        """
        return self.__volume_name

    def volume_namespace(self) -> Optional[str]:
        """
        VolumeNamespace specifies the scope of the volume within StorageOS.  If no
        namespace is specified then the Pod's namespace will be used.  This allows the
        Kubernetes name scoping to be mirrored within StorageOS for tighter integration.
        Set VolumeName to any name to override the default behaviour.
        Set to "default" if you are not using namespaces within StorageOS.
        Namespaces that do not pre-exist within StorageOS will be created.
        """
        return self.__volume_namespace

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only

    def secret_ref(self) -> Optional["ObjectReference"]:
        """
        SecretRef specifies the secret to use for obtaining the StorageOS API
        credentials.  If not specified, default values will be attempted.
        """
        return self.__secret_ref


class VsphereVirtualDiskVolumeSource(types.Object):
    """
    Represents a vSphere volume resource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        volume_path: str = "",
        fs_type: str = None,
        storage_policy_name: str = None,
        storage_policy_id: str = None,
    ):
        super().__init__()
        self.__volume_path = volume_path
        self.__fs_type = fs_type
        self.__storage_policy_name = storage_policy_name
        self.__storage_policy_id = storage_policy_id

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volume_path = self.volume_path()
        check_type("volume_path", volume_path, str)
        v["volumePath"] = volume_path
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        storage_policy_name = self.storage_policy_name()
        check_type("storage_policy_name", storage_policy_name, Optional[str])
        if storage_policy_name:  # omit empty
            v["storagePolicyName"] = storage_policy_name
        storage_policy_id = self.storage_policy_id()
        check_type("storage_policy_id", storage_policy_id, Optional[str])
        if storage_policy_id:  # omit empty
            v["storagePolicyID"] = storage_policy_id
        return v

    def volume_path(self) -> str:
        """
        Path that identifies vSphere volume vmdk
        """
        return self.__volume_path

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        """
        return self.__fs_type

    def storage_policy_name(self) -> Optional[str]:
        """
        Storage Policy Based Management (SPBM) profile name.
        """
        return self.__storage_policy_name

    def storage_policy_id(self) -> Optional[str]:
        """
        Storage Policy Based Management (SPBM) profile ID associated with the StoragePolicyName.
        """
        return self.__storage_policy_id


class PersistentVolumeSource(types.Object):
    """
    PersistentVolumeSource is similar to VolumeSource but meant for the
    administrator who creates PVs. Exactly one of its members must be set.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        gce_persistent_disk: "GCEPersistentDiskVolumeSource" = None,
        aws_elastic_block_store: "AWSElasticBlockStoreVolumeSource" = None,
        host_path: "HostPathVolumeSource" = None,
        glusterfs: "GlusterfsPersistentVolumeSource" = None,
        nfs: "NFSVolumeSource" = None,
        rbd: "RBDPersistentVolumeSource" = None,
        iscsi: "ISCSIPersistentVolumeSource" = None,
        cinder: "CinderPersistentVolumeSource" = None,
        cephfs: "CephFSPersistentVolumeSource" = None,
        fc: "FCVolumeSource" = None,
        flocker: "FlockerVolumeSource" = None,
        flex_volume: "FlexPersistentVolumeSource" = None,
        azure_file: "AzureFilePersistentVolumeSource" = None,
        vsphere_volume: "VsphereVirtualDiskVolumeSource" = None,
        quobyte: "QuobyteVolumeSource" = None,
        azure_disk: "AzureDiskVolumeSource" = None,
        photon_persistent_disk: "PhotonPersistentDiskVolumeSource" = None,
        portworx_volume: "PortworxVolumeSource" = None,
        scale_io: "ScaleIOPersistentVolumeSource" = None,
        local: "LocalVolumeSource" = None,
        storageos: "StorageOSPersistentVolumeSource" = None,
        csi: "CSIPersistentVolumeSource" = None,
    ):
        super().__init__()
        self.__gce_persistent_disk = gce_persistent_disk
        self.__aws_elastic_block_store = aws_elastic_block_store
        self.__host_path = host_path
        self.__glusterfs = glusterfs
        self.__nfs = nfs
        self.__rbd = rbd
        self.__iscsi = iscsi
        self.__cinder = cinder
        self.__cephfs = cephfs
        self.__fc = fc
        self.__flocker = flocker
        self.__flex_volume = flex_volume
        self.__azure_file = azure_file
        self.__vsphere_volume = vsphere_volume
        self.__quobyte = quobyte
        self.__azure_disk = azure_disk
        self.__photon_persistent_disk = photon_persistent_disk
        self.__portworx_volume = portworx_volume
        self.__scale_io = scale_io
        self.__local = local
        self.__storageos = storageos
        self.__csi = csi

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        gce_persistent_disk = self.gce_persistent_disk()
        check_type(
            "gce_persistent_disk",
            gce_persistent_disk,
            Optional["GCEPersistentDiskVolumeSource"],
        )
        if gce_persistent_disk is not None:  # omit empty
            v["gcePersistentDisk"] = gce_persistent_disk
        aws_elastic_block_store = self.aws_elastic_block_store()
        check_type(
            "aws_elastic_block_store",
            aws_elastic_block_store,
            Optional["AWSElasticBlockStoreVolumeSource"],
        )
        if aws_elastic_block_store is not None:  # omit empty
            v["awsElasticBlockStore"] = aws_elastic_block_store
        host_path = self.host_path()
        check_type("host_path", host_path, Optional["HostPathVolumeSource"])
        if host_path is not None:  # omit empty
            v["hostPath"] = host_path
        glusterfs = self.glusterfs()
        check_type("glusterfs", glusterfs, Optional["GlusterfsPersistentVolumeSource"])
        if glusterfs is not None:  # omit empty
            v["glusterfs"] = glusterfs
        nfs = self.nfs()
        check_type("nfs", nfs, Optional["NFSVolumeSource"])
        if nfs is not None:  # omit empty
            v["nfs"] = nfs
        rbd = self.rbd()
        check_type("rbd", rbd, Optional["RBDPersistentVolumeSource"])
        if rbd is not None:  # omit empty
            v["rbd"] = rbd
        iscsi = self.iscsi()
        check_type("iscsi", iscsi, Optional["ISCSIPersistentVolumeSource"])
        if iscsi is not None:  # omit empty
            v["iscsi"] = iscsi
        cinder = self.cinder()
        check_type("cinder", cinder, Optional["CinderPersistentVolumeSource"])
        if cinder is not None:  # omit empty
            v["cinder"] = cinder
        cephfs = self.cephfs()
        check_type("cephfs", cephfs, Optional["CephFSPersistentVolumeSource"])
        if cephfs is not None:  # omit empty
            v["cephfs"] = cephfs
        fc = self.fc()
        check_type("fc", fc, Optional["FCVolumeSource"])
        if fc is not None:  # omit empty
            v["fc"] = fc
        flocker = self.flocker()
        check_type("flocker", flocker, Optional["FlockerVolumeSource"])
        if flocker is not None:  # omit empty
            v["flocker"] = flocker
        flex_volume = self.flex_volume()
        check_type("flex_volume", flex_volume, Optional["FlexPersistentVolumeSource"])
        if flex_volume is not None:  # omit empty
            v["flexVolume"] = flex_volume
        azure_file = self.azure_file()
        check_type(
            "azure_file", azure_file, Optional["AzureFilePersistentVolumeSource"]
        )
        if azure_file is not None:  # omit empty
            v["azureFile"] = azure_file
        vsphere_volume = self.vsphere_volume()
        check_type(
            "vsphere_volume", vsphere_volume, Optional["VsphereVirtualDiskVolumeSource"]
        )
        if vsphere_volume is not None:  # omit empty
            v["vsphereVolume"] = vsphere_volume
        quobyte = self.quobyte()
        check_type("quobyte", quobyte, Optional["QuobyteVolumeSource"])
        if quobyte is not None:  # omit empty
            v["quobyte"] = quobyte
        azure_disk = self.azure_disk()
        check_type("azure_disk", azure_disk, Optional["AzureDiskVolumeSource"])
        if azure_disk is not None:  # omit empty
            v["azureDisk"] = azure_disk
        photon_persistent_disk = self.photon_persistent_disk()
        check_type(
            "photon_persistent_disk",
            photon_persistent_disk,
            Optional["PhotonPersistentDiskVolumeSource"],
        )
        if photon_persistent_disk is not None:  # omit empty
            v["photonPersistentDisk"] = photon_persistent_disk
        portworx_volume = self.portworx_volume()
        check_type("portworx_volume", portworx_volume, Optional["PortworxVolumeSource"])
        if portworx_volume is not None:  # omit empty
            v["portworxVolume"] = portworx_volume
        scale_io = self.scale_io()
        check_type("scale_io", scale_io, Optional["ScaleIOPersistentVolumeSource"])
        if scale_io is not None:  # omit empty
            v["scaleIO"] = scale_io
        local = self.local()
        check_type("local", local, Optional["LocalVolumeSource"])
        if local is not None:  # omit empty
            v["local"] = local
        storageos = self.storageos()
        check_type("storageos", storageos, Optional["StorageOSPersistentVolumeSource"])
        if storageos is not None:  # omit empty
            v["storageos"] = storageos
        csi = self.csi()
        check_type("csi", csi, Optional["CSIPersistentVolumeSource"])
        if csi is not None:  # omit empty
            v["csi"] = csi
        return v

    def gce_persistent_disk(self) -> Optional["GCEPersistentDiskVolumeSource"]:
        """
        GCEPersistentDisk represents a GCE Disk resource that is attached to a
        kubelet's host machine and then exposed to the pod. Provisioned by an admin.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
        """
        return self.__gce_persistent_disk

    def aws_elastic_block_store(self) -> Optional["AWSElasticBlockStoreVolumeSource"]:
        """
        AWSElasticBlockStore represents an AWS Disk resource that is attached to a
        kubelet's host machine and then exposed to the pod.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#awselasticblockstore
        """
        return self.__aws_elastic_block_store

    def host_path(self) -> Optional["HostPathVolumeSource"]:
        """
        HostPath represents a directory on the host.
        Provisioned by a developer or tester.
        This is useful for single-node development and testing only!
        On-host storage is not supported in any way and WILL NOT WORK in a multi-node cluster.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#hostpath
        """
        return self.__host_path

    def glusterfs(self) -> Optional["GlusterfsPersistentVolumeSource"]:
        """
        Glusterfs represents a Glusterfs volume that is attached to a host and
        exposed to the pod. Provisioned by an admin.
        More info: https://examples.k8s.io/volumes/glusterfs/README.md
        """
        return self.__glusterfs

    def nfs(self) -> Optional["NFSVolumeSource"]:
        """
        NFS represents an NFS mount on the host. Provisioned by an admin.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#nfs
        """
        return self.__nfs

    def rbd(self) -> Optional["RBDPersistentVolumeSource"]:
        """
        RBD represents a Rados Block Device mount on the host that shares a pod's lifetime.
        More info: https://examples.k8s.io/volumes/rbd/README.md
        """
        return self.__rbd

    def iscsi(self) -> Optional["ISCSIPersistentVolumeSource"]:
        """
        ISCSI represents an ISCSI Disk resource that is attached to a
        kubelet's host machine and then exposed to the pod. Provisioned by an admin.
        """
        return self.__iscsi

    def cinder(self) -> Optional["CinderPersistentVolumeSource"]:
        """
        Cinder represents a cinder volume attached and mounted on kubelets host machine.
        More info: https://examples.k8s.io/mysql-cinder-pd/README.md
        """
        return self.__cinder

    def cephfs(self) -> Optional["CephFSPersistentVolumeSource"]:
        """
        CephFS represents a Ceph FS mount on the host that shares a pod's lifetime
        """
        return self.__cephfs

    def fc(self) -> Optional["FCVolumeSource"]:
        """
        FC represents a Fibre Channel resource that is attached to a kubelet's host machine and then exposed to the pod.
        """
        return self.__fc

    def flocker(self) -> Optional["FlockerVolumeSource"]:
        """
        Flocker represents a Flocker volume attached to a kubelet's host machine and exposed to the pod for its usage. This depends on the Flocker control service being running
        """
        return self.__flocker

    def flex_volume(self) -> Optional["FlexPersistentVolumeSource"]:
        """
        FlexVolume represents a generic volume resource that is
        provisioned/attached using an exec based plugin.
        """
        return self.__flex_volume

    def azure_file(self) -> Optional["AzureFilePersistentVolumeSource"]:
        """
        AzureFile represents an Azure File Service mount on the host and bind mount to the pod.
        """
        return self.__azure_file

    def vsphere_volume(self) -> Optional["VsphereVirtualDiskVolumeSource"]:
        """
        VsphereVolume represents a vSphere volume attached and mounted on kubelets host machine
        """
        return self.__vsphere_volume

    def quobyte(self) -> Optional["QuobyteVolumeSource"]:
        """
        Quobyte represents a Quobyte mount on the host that shares a pod's lifetime
        """
        return self.__quobyte

    def azure_disk(self) -> Optional["AzureDiskVolumeSource"]:
        """
        AzureDisk represents an Azure Data Disk mount on the host and bind mount to the pod.
        """
        return self.__azure_disk

    def photon_persistent_disk(self) -> Optional["PhotonPersistentDiskVolumeSource"]:
        """
        PhotonPersistentDisk represents a PhotonController persistent disk attached and mounted on kubelets host machine
        """
        return self.__photon_persistent_disk

    def portworx_volume(self) -> Optional["PortworxVolumeSource"]:
        """
        PortworxVolume represents a portworx volume attached and mounted on kubelets host machine
        """
        return self.__portworx_volume

    def scale_io(self) -> Optional["ScaleIOPersistentVolumeSource"]:
        """
        ScaleIO represents a ScaleIO persistent volume attached and mounted on Kubernetes nodes.
        """
        return self.__scale_io

    def local(self) -> Optional["LocalVolumeSource"]:
        """
        Local represents directly-attached storage with node affinity
        """
        return self.__local

    def storageos(self) -> Optional["StorageOSPersistentVolumeSource"]:
        """
        StorageOS represents a StorageOS volume that is attached to the kubelet's host machine and mounted into the pod
        More info: https://examples.k8s.io/volumes/storageos/README.md
        """
        return self.__storageos

    def csi(self) -> Optional["CSIPersistentVolumeSource"]:
        """
        CSI represents storage that is handled by an external CSI driver (Beta feature).
        """
        return self.__csi


class VolumeNodeAffinity(types.Object):
    """
    VolumeNodeAffinity defines constraints that limit what nodes this volume can be accessed from.
    """

    @context.scoped
    @typechecked
    def __init__(self, required: "NodeSelector" = None):
        super().__init__()
        self.__required = required

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        required = self.required()
        check_type("required", required, Optional["NodeSelector"])
        if required is not None:  # omit empty
            v["required"] = required
        return v

    def required(self) -> Optional["NodeSelector"]:
        """
        Required specifies hard node constraints that must be met.
        """
        return self.__required


class PersistentVolumeSpec(types.Object):
    """
    PersistentVolumeSpec is the specification of a persistent volume.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        capacity: Dict[ResourceName, "resource.Quantity"] = None,
        persistent_volume_source: "PersistentVolumeSource" = None,
        access_modes: List[PersistentVolumeAccessMode] = None,
        claim_ref: "ObjectReference" = None,
        persistent_volume_reclaim_policy: PersistentVolumeReclaimPolicy = PersistentVolumeReclaimPolicy[
            "Retain"
        ],
        storage_class_name: str = None,
        mount_options: List[str] = None,
        volume_mode: PersistentVolumeMode = None,
        node_affinity: "VolumeNodeAffinity" = None,
    ):
        super().__init__()
        self.__capacity = capacity if capacity is not None else {}
        self.__persistent_volume_source = (
            persistent_volume_source
            if persistent_volume_source is not None
            else PersistentVolumeSource()
        )
        self.__access_modes = access_modes if access_modes is not None else []
        self.__claim_ref = claim_ref
        self.__persistent_volume_reclaim_policy = persistent_volume_reclaim_policy
        self.__storage_class_name = storage_class_name
        self.__mount_options = mount_options if mount_options is not None else []
        self.__volume_mode = (
            volume_mode
            if volume_mode is not None
            else PersistentVolumeMode["Filesystem"]
        )
        self.__node_affinity = node_affinity

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        capacity = self.capacity()
        check_type(
            "capacity", capacity, Optional[Dict[ResourceName, "resource.Quantity"]]
        )
        if capacity:  # omit empty
            v["capacity"] = capacity
        persistent_volume_source = self.persistent_volume_source()
        check_type(
            "persistent_volume_source",
            persistent_volume_source,
            "PersistentVolumeSource",
        )
        v.update(persistent_volume_source._root())  # inline
        access_modes = self.access_modes()
        check_type(
            "access_modes", access_modes, Optional[List[PersistentVolumeAccessMode]]
        )
        if access_modes:  # omit empty
            v["accessModes"] = access_modes
        claim_ref = self.claim_ref()
        check_type("claim_ref", claim_ref, Optional["ObjectReference"])
        if claim_ref is not None:  # omit empty
            v["claimRef"] = claim_ref
        persistent_volume_reclaim_policy = self.persistent_volume_reclaim_policy()
        check_type(
            "persistent_volume_reclaim_policy",
            persistent_volume_reclaim_policy,
            Optional[PersistentVolumeReclaimPolicy],
        )
        if persistent_volume_reclaim_policy:  # omit empty
            v["persistentVolumeReclaimPolicy"] = persistent_volume_reclaim_policy
        storage_class_name = self.storage_class_name()
        check_type("storage_class_name", storage_class_name, Optional[str])
        if storage_class_name:  # omit empty
            v["storageClassName"] = storage_class_name
        mount_options = self.mount_options()
        check_type("mount_options", mount_options, Optional[List[str]])
        if mount_options:  # omit empty
            v["mountOptions"] = mount_options
        volume_mode = self.volume_mode()
        check_type("volume_mode", volume_mode, Optional[PersistentVolumeMode])
        if volume_mode is not None:  # omit empty
            v["volumeMode"] = volume_mode
        node_affinity = self.node_affinity()
        check_type("node_affinity", node_affinity, Optional["VolumeNodeAffinity"])
        if node_affinity is not None:  # omit empty
            v["nodeAffinity"] = node_affinity
        return v

    def capacity(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        """
        A description of the persistent volume's resources and capacity.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#capacity
        """
        return self.__capacity

    def persistent_volume_source(self) -> "PersistentVolumeSource":
        """
        The actual volume backing the persistent volume.
        """
        return self.__persistent_volume_source

    def access_modes(self) -> Optional[List[PersistentVolumeAccessMode]]:
        """
        AccessModes contains all ways the volume can be mounted.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#access-modes
        """
        return self.__access_modes

    def claim_ref(self) -> Optional["ObjectReference"]:
        """
        ClaimRef is part of a bi-directional binding between PersistentVolume and PersistentVolumeClaim.
        Expected to be non-nil when bound.
        claim.VolumeName is the authoritative bind between PV and PVC.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#binding
        """
        return self.__claim_ref

    def persistent_volume_reclaim_policy(
        self
    ) -> Optional[PersistentVolumeReclaimPolicy]:
        """
        What happens to a persistent volume when released from its claim.
        Valid options are Retain (default for manually created PersistentVolumes), Delete (default
        for dynamically provisioned PersistentVolumes), and Recycle (deprecated).
        Recycle must be supported by the volume plugin underlying this PersistentVolume.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#reclaiming
        """
        return self.__persistent_volume_reclaim_policy

    def storage_class_name(self) -> Optional[str]:
        """
        Name of StorageClass to which this persistent volume belongs. Empty value
        means that this volume does not belong to any StorageClass.
        """
        return self.__storage_class_name

    def mount_options(self) -> Optional[List[str]]:
        """
        A list of mount options, e.g. ["ro", "soft"]. Not validated - mount will
        simply fail if one is invalid.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes/#mount-options
        """
        return self.__mount_options

    def volume_mode(self) -> Optional[PersistentVolumeMode]:
        """
        volumeMode defines if a volume is intended to be used with a formatted filesystem
        or to remain in raw block state. Value of Filesystem is implied when not included in spec.
        This is a beta feature.
        """
        return self.__volume_mode

    def node_affinity(self) -> Optional["VolumeNodeAffinity"]:
        """
        NodeAffinity defines constraints that limit what nodes this volume can be accessed from.
        This field influences the scheduling of pods that use this volume.
        """
        return self.__node_affinity


class PersistentVolume(base.TypedObject, base.MetadataObject):
    """
    PersistentVolume (PV) is a storage resource provisioned by an administrator.
    It is analogous to a node.
    More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PersistentVolumeSpec" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="PersistentVolume",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PersistentVolumeSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["PersistentVolumeSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["PersistentVolumeSpec"]:
        """
        Spec defines a specification of a persistent volume owned by the cluster.
        Provisioned by an administrator.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistent-volumes
        """
        return self.__spec


class TypedLocalObjectReference(types.Object):
    """
    TypedLocalObjectReference contains enough information to let you locate the
    typed referenced object inside the same namespace.
    """

    @context.scoped
    @typechecked
    def __init__(self, api_group: str = None, kind: str = "", name: str = ""):
        super().__init__()
        self.__api_group = api_group
        self.__kind = kind
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        api_group = self.api_group()
        check_type("api_group", api_group, Optional[str])
        v["apiGroup"] = api_group
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def api_group(self) -> Optional[str]:
        """
        APIGroup is the group for the resource being referenced.
        If APIGroup is not specified, the specified Kind must be in the core API group.
        For any other third-party types, APIGroup is required.
        """
        return self.__api_group

    def kind(self) -> str:
        """
        Kind is the type of resource being referenced
        """
        return self.__kind

    def name(self) -> str:
        """
        Name is the name of resource being referenced
        """
        return self.__name


class PersistentVolumeClaimSpec(types.Object):
    """
    PersistentVolumeClaimSpec describes the common attributes of storage devices
    and allows a Source for provider-specific attributes
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        access_modes: List[PersistentVolumeAccessMode] = None,
        selector: "metav1.LabelSelector" = None,
        resources: "ResourceRequirements" = None,
        volume_name: str = None,
        storage_class_name: str = None,
        volume_mode: PersistentVolumeMode = None,
        data_source: "TypedLocalObjectReference" = None,
    ):
        super().__init__()
        self.__access_modes = access_modes if access_modes is not None else []
        self.__selector = selector
        self.__resources = (
            resources if resources is not None else ResourceRequirements()
        )
        self.__volume_name = volume_name
        self.__storage_class_name = storage_class_name
        self.__volume_mode = (
            volume_mode
            if volume_mode is not None
            else PersistentVolumeMode["Filesystem"]
        )
        self.__data_source = data_source

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        access_modes = self.access_modes()
        check_type(
            "access_modes", access_modes, Optional[List[PersistentVolumeAccessMode]]
        )
        if access_modes:  # omit empty
            v["accessModes"] = access_modes
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        resources = self.resources()
        check_type("resources", resources, Optional["ResourceRequirements"])
        v["resources"] = resources
        volume_name = self.volume_name()
        check_type("volume_name", volume_name, Optional[str])
        if volume_name:  # omit empty
            v["volumeName"] = volume_name
        storage_class_name = self.storage_class_name()
        check_type("storage_class_name", storage_class_name, Optional[str])
        if storage_class_name is not None:  # omit empty
            v["storageClassName"] = storage_class_name
        volume_mode = self.volume_mode()
        check_type("volume_mode", volume_mode, Optional[PersistentVolumeMode])
        if volume_mode is not None:  # omit empty
            v["volumeMode"] = volume_mode
        data_source = self.data_source()
        check_type("data_source", data_source, Optional["TypedLocalObjectReference"])
        if data_source is not None:  # omit empty
            v["dataSource"] = data_source
        return v

    def access_modes(self) -> Optional[List[PersistentVolumeAccessMode]]:
        """
        AccessModes contains the desired access modes the volume should have.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#access-modes-1
        """
        return self.__access_modes

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        A label query over volumes to consider for binding.
        """
        return self.__selector

    def resources(self) -> Optional["ResourceRequirements"]:
        """
        Resources represents the minimum resources the volume should have.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#resources
        """
        return self.__resources

    def volume_name(self) -> Optional[str]:
        """
        VolumeName is the binding reference to the PersistentVolume backing this claim.
        """
        return self.__volume_name

    def storage_class_name(self) -> Optional[str]:
        """
        Name of the StorageClass required by the claim.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#class-1
        """
        return self.__storage_class_name

    def volume_mode(self) -> Optional[PersistentVolumeMode]:
        """
        volumeMode defines what type of volume is required by the claim.
        Value of Filesystem is implied when not included in claim spec.
        This is a beta feature.
        """
        return self.__volume_mode

    def data_source(self) -> Optional["TypedLocalObjectReference"]:
        """
        This field requires the VolumeSnapshotDataSource alpha feature gate to be
        enabled and currently VolumeSnapshot is the only supported data source.
        If the provisioner can support VolumeSnapshot data source, it will create
        a new volume and data will be restored to the volume at the same time.
        If the provisioner does not support VolumeSnapshot data source, volume will
        not be created and the failure will be reported as an event.
        In the future, we plan to support more data source types and the behavior
        of the provisioner may change.
        """
        return self.__data_source


class PersistentVolumeClaim(base.TypedObject, base.NamespacedMetadataObject):
    """
    PersistentVolumeClaim is a user's request for and claim to a persistent volume
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PersistentVolumeClaimSpec" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="PersistentVolumeClaim",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PersistentVolumeClaimSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["PersistentVolumeClaimSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["PersistentVolumeClaimSpec"]:
        """
        Spec defines the desired characteristics of a volume requested by a pod author.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims
        """
        return self.__spec


class PersistentVolumeClaimVolumeSource(types.Object):
    """
    PersistentVolumeClaimVolumeSource references the user's PVC in the same namespace.
    This volume finds the bound PV and mounts that volume for the pod. A
    PersistentVolumeClaimVolumeSource is, essentially, a wrapper around another
    type of volume that is owned by someone else (the system).
    """

    @context.scoped
    @typechecked
    def __init__(self, claim_name: str = "", read_only: bool = None):
        super().__init__()
        self.__claim_name = claim_name
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        claim_name = self.claim_name()
        check_type("claim_name", claim_name, str)
        v["claimName"] = claim_name
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def claim_name(self) -> str:
        """
        ClaimName is the name of a PersistentVolumeClaim in the same namespace as the pod using this volume.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims
        """
        return self.__claim_name

    def read_only(self) -> Optional[bool]:
        """
        Will force the ReadOnly setting in VolumeMounts.
        Default false.
        """
        return self.__read_only


class PodDNSConfigOption(types.Object):
    """
    PodDNSConfigOption defines DNS resolver options of a pod.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = None, value: str = None):
        super().__init__()
        self.__name = name
        self.__value = value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        value = self.value()
        check_type("value", value, Optional[str])
        if value is not None:  # omit empty
            v["value"] = value
        return v

    def name(self) -> Optional[str]:
        """
        Required.
        """
        return self.__name

    def value(self) -> Optional[str]:
        return self.__value


class PodDNSConfig(types.Object):
    """
    PodDNSConfig defines the DNS parameters of a pod in addition to
    those generated from DNSPolicy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        nameservers: List[str] = None,
        searches: List[str] = None,
        options: List["PodDNSConfigOption"] = None,
    ):
        super().__init__()
        self.__nameservers = nameservers if nameservers is not None else []
        self.__searches = searches if searches is not None else []
        self.__options = options if options is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        nameservers = self.nameservers()
        check_type("nameservers", nameservers, Optional[List[str]])
        if nameservers:  # omit empty
            v["nameservers"] = nameservers
        searches = self.searches()
        check_type("searches", searches, Optional[List[str]])
        if searches:  # omit empty
            v["searches"] = searches
        options = self.options()
        check_type("options", options, Optional[List["PodDNSConfigOption"]])
        if options:  # omit empty
            v["options"] = options
        return v

    def nameservers(self) -> Optional[List[str]]:
        """
        A list of DNS name server IP addresses.
        This will be appended to the base nameservers generated from DNSPolicy.
        Duplicated nameservers will be removed.
        """
        return self.__nameservers

    def searches(self) -> Optional[List[str]]:
        """
        A list of DNS search domains for host-name lookup.
        This will be appended to the base search paths generated from DNSPolicy.
        Duplicated search paths will be removed.
        """
        return self.__searches

    def options(self) -> Optional[List["PodDNSConfigOption"]]:
        """
        A list of DNS resolver options.
        This will be merged with the base options generated from DNSPolicy.
        Duplicated entries will be removed. Resolution options given in Options
        will override those that appear in the base DNSPolicy.
        """
        return self.__options


class PodReadinessGate(types.Object):
    """
    PodReadinessGate contains the reference to a pod condition
    """

    @context.scoped
    @typechecked
    def __init__(self, condition_type: PodConditionType = None):
        super().__init__()
        self.__condition_type = condition_type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        condition_type = self.condition_type()
        check_type("condition_type", condition_type, PodConditionType)
        v["conditionType"] = condition_type
        return v

    def condition_type(self) -> PodConditionType:
        """
        ConditionType refers to a condition in the pod's condition list with matching type.
        """
        return self.__condition_type


class Sysctl(types.Object):
    """
    Sysctl defines a kernel parameter to be set
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", value: str = ""):
        super().__init__()
        self.__name = name
        self.__value = value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        value = self.value()
        check_type("value", value, str)
        v["value"] = value
        return v

    def name(self) -> str:
        """
        Name of a property to set
        """
        return self.__name

    def value(self) -> str:
        """
        Value of a property to set
        """
        return self.__value


class PodSecurityContext(types.Object):
    """
    PodSecurityContext holds pod-level security attributes and common container settings.
    Some fields are also present in container.securityContext.  Field values of
    container.securityContext take precedence over field values of PodSecurityContext.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        se_linux_options: "SELinuxOptions" = None,
        windows_options: "WindowsSecurityContextOptions" = None,
        run_as_user: int = None,
        run_as_group: int = None,
        run_as_non_root: bool = None,
        supplemental_groups: List[int] = None,
        fs_group: int = None,
        sysctls: List["Sysctl"] = None,
    ):
        super().__init__()
        self.__se_linux_options = se_linux_options
        self.__windows_options = windows_options
        self.__run_as_user = run_as_user
        self.__run_as_group = run_as_group
        self.__run_as_non_root = run_as_non_root
        self.__supplemental_groups = (
            supplemental_groups if supplemental_groups is not None else []
        )
        self.__fs_group = fs_group
        self.__sysctls = sysctls if sysctls is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        se_linux_options = self.se_linux_options()
        check_type("se_linux_options", se_linux_options, Optional["SELinuxOptions"])
        if se_linux_options is not None:  # omit empty
            v["seLinuxOptions"] = se_linux_options
        windows_options = self.windows_options()
        check_type(
            "windows_options",
            windows_options,
            Optional["WindowsSecurityContextOptions"],
        )
        if windows_options is not None:  # omit empty
            v["windowsOptions"] = windows_options
        run_as_user = self.run_as_user()
        check_type("run_as_user", run_as_user, Optional[int])
        if run_as_user is not None:  # omit empty
            v["runAsUser"] = run_as_user
        run_as_group = self.run_as_group()
        check_type("run_as_group", run_as_group, Optional[int])
        if run_as_group is not None:  # omit empty
            v["runAsGroup"] = run_as_group
        run_as_non_root = self.run_as_non_root()
        check_type("run_as_non_root", run_as_non_root, Optional[bool])
        if run_as_non_root is not None:  # omit empty
            v["runAsNonRoot"] = run_as_non_root
        supplemental_groups = self.supplemental_groups()
        check_type("supplemental_groups", supplemental_groups, Optional[List[int]])
        if supplemental_groups:  # omit empty
            v["supplementalGroups"] = supplemental_groups
        fs_group = self.fs_group()
        check_type("fs_group", fs_group, Optional[int])
        if fs_group is not None:  # omit empty
            v["fsGroup"] = fs_group
        sysctls = self.sysctls()
        check_type("sysctls", sysctls, Optional[List["Sysctl"]])
        if sysctls:  # omit empty
            v["sysctls"] = sysctls
        return v

    def se_linux_options(self) -> Optional["SELinuxOptions"]:
        """
        The SELinux context to be applied to all containers.
        If unspecified, the container runtime will allocate a random SELinux context for each
        container.  May also be set in SecurityContext.  If set in
        both SecurityContext and PodSecurityContext, the value specified in SecurityContext
        takes precedence for that container.
        """
        return self.__se_linux_options

    def windows_options(self) -> Optional["WindowsSecurityContextOptions"]:
        """
        The Windows specific settings applied to all containers.
        If unspecified, the options within a container's SecurityContext will be used.
        If set in both SecurityContext and PodSecurityContext, the value specified in SecurityContext takes precedence.
        """
        return self.__windows_options

    def run_as_user(self) -> Optional[int]:
        """
        The UID to run the entrypoint of the container process.
        Defaults to user specified in image metadata if unspecified.
        May also be set in SecurityContext.  If set in both SecurityContext and
        PodSecurityContext, the value specified in SecurityContext takes precedence
        for that container.
        """
        return self.__run_as_user

    def run_as_group(self) -> Optional[int]:
        """
        The GID to run the entrypoint of the container process.
        Uses runtime default if unset.
        May also be set in SecurityContext.  If set in both SecurityContext and
        PodSecurityContext, the value specified in SecurityContext takes precedence
        for that container.
        """
        return self.__run_as_group

    def run_as_non_root(self) -> Optional[bool]:
        """
        Indicates that the container must run as a non-root user.
        If true, the Kubelet will validate the image at runtime to ensure that it
        does not run as UID 0 (root) and fail to start the container if it does.
        If unset or false, no such validation will be performed.
        May also be set in SecurityContext.  If set in both SecurityContext and
        PodSecurityContext, the value specified in SecurityContext takes precedence.
        """
        return self.__run_as_non_root

    def supplemental_groups(self) -> Optional[List[int]]:
        """
        A list of groups applied to the first process run in each container, in addition
        to the container's primary GID.  If unspecified, no groups will be added to
        any container.
        """
        return self.__supplemental_groups

    def fs_group(self) -> Optional[int]:
        """
        A special supplemental group that applies to all containers in a pod.
        Some volume types allow the Kubelet to change the ownership of that volume
        to be owned by the pod:
        
        1. The owning GID will be the FSGroup
        2. The setgid bit is set (new files created in the volume will be owned by FSGroup)
        3. The permission bits are OR'd with rw-rw----
        
        If unset, the Kubelet will not modify the ownership and permissions of any volume.
        """
        return self.__fs_group

    def sysctls(self) -> Optional[List["Sysctl"]]:
        """
        Sysctls hold a list of namespaced sysctls used for the pod. Pods with unsupported
        sysctls (by the container runtime) might fail to launch.
        """
        return self.__sysctls


class Toleration(types.Object):
    """
    The pod this Toleration is attached to tolerates any taint that matches
    the triple <key,value,effect> using the matching operator <operator>.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        key: str = None,
        operator: TolerationOperator = None,
        value: str = None,
        effect: TaintEffect = None,
        toleration_seconds: int = None,
    ):
        super().__init__()
        self.__key = key
        self.__operator = operator
        self.__value = value
        self.__effect = effect
        self.__toleration_seconds = toleration_seconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        key = self.key()
        check_type("key", key, Optional[str])
        if key:  # omit empty
            v["key"] = key
        operator = self.operator()
        check_type("operator", operator, Optional[TolerationOperator])
        if operator:  # omit empty
            v["operator"] = operator
        value = self.value()
        check_type("value", value, Optional[str])
        if value:  # omit empty
            v["value"] = value
        effect = self.effect()
        check_type("effect", effect, Optional[TaintEffect])
        if effect:  # omit empty
            v["effect"] = effect
        toleration_seconds = self.toleration_seconds()
        check_type("toleration_seconds", toleration_seconds, Optional[int])
        if toleration_seconds is not None:  # omit empty
            v["tolerationSeconds"] = toleration_seconds
        return v

    def key(self) -> Optional[str]:
        """
        Key is the taint key that the toleration applies to. Empty means match all taint keys.
        If the key is empty, operator must be Exists; this combination means to match all values and all keys.
        """
        return self.__key

    def operator(self) -> Optional[TolerationOperator]:
        """
        Operator represents a key's relationship to the value.
        Valid operators are Exists and Equal. Defaults to Equal.
        Exists is equivalent to wildcard for value, so that a pod can
        tolerate all taints of a particular category.
        """
        return self.__operator

    def value(self) -> Optional[str]:
        """
        Value is the taint value the toleration matches to.
        If the operator is Exists, the value should be empty, otherwise just a regular string.
        """
        return self.__value

    def effect(self) -> Optional[TaintEffect]:
        """
        Effect indicates the taint effect to match. Empty means match all taint effects.
        When specified, allowed values are NoSchedule, PreferNoSchedule and NoExecute.
        """
        return self.__effect

    def toleration_seconds(self) -> Optional[int]:
        """
        TolerationSeconds represents the period of time the toleration (which must be
        of effect NoExecute, otherwise this field is ignored) tolerates the taint. By default,
        it is not set, which means tolerate the taint forever (do not evict). Zero and
        negative values will be treated as 0 (evict immediately) by the system.
        """
        return self.__toleration_seconds


class TopologySpreadConstraint(types.Object):
    """
    TopologySpreadConstraint specifies how to spread matching pods among the given topology.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        max_skew: int = 0,
        topology_key: str = "",
        when_unsatisfiable: UnsatisfiableConstraintAction = None,
        label_selector: "metav1.LabelSelector" = None,
    ):
        super().__init__()
        self.__max_skew = max_skew
        self.__topology_key = topology_key
        self.__when_unsatisfiable = when_unsatisfiable
        self.__label_selector = label_selector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        max_skew = self.max_skew()
        check_type("max_skew", max_skew, int)
        v["maxSkew"] = max_skew
        topology_key = self.topology_key()
        check_type("topology_key", topology_key, str)
        v["topologyKey"] = topology_key
        when_unsatisfiable = self.when_unsatisfiable()
        check_type(
            "when_unsatisfiable", when_unsatisfiable, UnsatisfiableConstraintAction
        )
        v["whenUnsatisfiable"] = when_unsatisfiable
        label_selector = self.label_selector()
        check_type("label_selector", label_selector, Optional["metav1.LabelSelector"])
        if label_selector is not None:  # omit empty
            v["labelSelector"] = label_selector
        return v

    def max_skew(self) -> int:
        """
        MaxSkew describes the degree to which pods may be unevenly distributed.
        It's the maximum permitted difference between the number of matching pods in
        any two topology domains of a given topology type.
        For example, in a 3-zone cluster, MaxSkew is set to 1, and pods with the same
        labelSelector spread as 1/1/0:
        +-------+-------+-------+
        | zone1 | zone2 | zone3 |
        +-------+-------+-------+
        |   P   |   P   |       |
        +-------+-------+-------+
        - if MaxSkew is 1, incoming pod can only be scheduled to zone3 to become 1/1/1;
        scheduling it onto zone1(zone2) would make the ActualSkew(2-0) on zone1(zone2)
        violate MaxSkew(1).
        - if MaxSkew is 2, incoming pod can be scheduled onto any zone.
        It's a required field. Default value is 1 and 0 is not allowed.
        """
        return self.__max_skew

    def topology_key(self) -> str:
        """
        TopologyKey is the key of node labels. Nodes that have a label with this key
        and identical values are considered to be in the same topology.
        We consider each <key, value> as a "bucket", and try to put balanced number
        of pods into each bucket.
        It's a required field.
        """
        return self.__topology_key

    def when_unsatisfiable(self) -> UnsatisfiableConstraintAction:
        """
        WhenUnsatisfiable indicates how to deal with a pod if it doesn't satisfy
        the spread constraint.
        - DoNotSchedule (default) tells the scheduler not to schedule it
        - ScheduleAnyway tells the scheduler to still schedule it
        It's considered as "Unsatisfiable" if and only if placing incoming pod on any
        topology violates "MaxSkew".
        For example, in a 3-zone cluster, MaxSkew is set to 1, and pods with the same
        labelSelector spread as 3/1/1:
        +-------+-------+-------+
        | zone1 | zone2 | zone3 |
        +-------+-------+-------+
        | P P P |   P   |   P   |
        +-------+-------+-------+
        If WhenUnsatisfiable is set to DoNotSchedule, incoming pod can only be scheduled
        to zone2(zone3) to become 3/2/1(3/1/2) as ActualSkew(2-1) on zone2(zone3) satisfies
        MaxSkew(1). In other words, the cluster can still be imbalanced, but scheduler
        won't make it *more* imbalanced.
        It's a required field.
        """
        return self.__when_unsatisfiable

    def label_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        LabelSelector is used to find matching pods.
        Pods that match this label selector are counted to determine the number of pods
        in their corresponding topology domain.
        """
        return self.__label_selector


class SecretProjection(types.Object):
    """
    Adapts a secret into a projected volume.
    
    The contents of the target Secret's Data field will be presented in a
    projected volume as files using the keys in the Data field as the file names.
    Note that this is identical to a secret volume source without the default
    mode.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        local_object_reference: "LocalObjectReference" = None,
        items: List["KeyToPath"] = None,
        optional: bool = None,
    ):
        super().__init__()
        self.__local_object_reference = (
            local_object_reference
            if local_object_reference is not None
            else LocalObjectReference()
        )
        self.__items = items if items is not None else []
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        local_object_reference = self.local_object_reference()
        check_type(
            "local_object_reference", local_object_reference, "LocalObjectReference"
        )
        v.update(local_object_reference._root())  # inline
        items = self.items()
        check_type("items", items, Optional[List["KeyToPath"]])
        if items:  # omit empty
            v["items"] = items
        optional = self.optional()
        check_type("optional", optional, Optional[bool])
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    def local_object_reference(self) -> "LocalObjectReference":
        return self.__local_object_reference

    def items(self) -> Optional[List["KeyToPath"]]:
        """
        If unspecified, each key-value pair in the Data field of the referenced
        Secret will be projected into the volume as a file whose name is the
        key and content is the value. If specified, the listed keys will be
        projected into the specified paths, and unlisted keys will not be
        present. If a key is specified which is not present in the Secret,
        the volume setup will error unless it is marked optional. Paths must be
        relative and may not contain the '..' path or start with '..'.
        """
        return self.__items

    def optional(self) -> Optional[bool]:
        """
        Specify whether the Secret or its key must be defined
        """
        return self.__optional


class ServiceAccountTokenProjection(types.Object):
    """
    ServiceAccountTokenProjection represents a projected service account token
    volume. This projection can be used to insert a service account token into
    the pods runtime filesystem for use against APIs (Kubernetes API Server or
    otherwise).
    """

    @context.scoped
    @typechecked
    def __init__(
        self, audience: str = None, expiration_seconds: int = None, path: str = ""
    ):
        super().__init__()
        self.__audience = audience
        self.__expiration_seconds = (
            expiration_seconds if expiration_seconds is not None else 3600
        )
        self.__path = path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        audience = self.audience()
        check_type("audience", audience, Optional[str])
        if audience:  # omit empty
            v["audience"] = audience
        expiration_seconds = self.expiration_seconds()
        check_type("expiration_seconds", expiration_seconds, Optional[int])
        if expiration_seconds is not None:  # omit empty
            v["expirationSeconds"] = expiration_seconds
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        return v

    def audience(self) -> Optional[str]:
        """
        Audience is the intended audience of the token. A recipient of a token
        must identify itself with an identifier specified in the audience of the
        token, and otherwise should reject the token. The audience defaults to the
        identifier of the apiserver.
        """
        return self.__audience

    def expiration_seconds(self) -> Optional[int]:
        """
        ExpirationSeconds is the requested duration of validity of the service
        account token. As the token approaches expiration, the kubelet volume
        plugin will proactively rotate the service account token. The kubelet will
        start trying to rotate the token if the token is older than 80 percent of
        its time to live or if the token is older than 24 hours.Defaults to 1 hour
        and must be at least 10 minutes.
        """
        return self.__expiration_seconds

    def path(self) -> str:
        """
        Path is the path relative to the mount point of the file to project the
        token into.
        """
        return self.__path


class VolumeProjection(types.Object):
    """
    Projection that may be projected along with other supported volume types
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        secret: "SecretProjection" = None,
        downward_api: "DownwardAPIProjection" = None,
        config_map: "ConfigMapProjection" = None,
        service_account_token: "ServiceAccountTokenProjection" = None,
    ):
        super().__init__()
        self.__secret = secret
        self.__downward_api = downward_api
        self.__config_map = config_map
        self.__service_account_token = service_account_token

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secret = self.secret()
        check_type("secret", secret, Optional["SecretProjection"])
        if secret is not None:  # omit empty
            v["secret"] = secret
        downward_api = self.downward_api()
        check_type("downward_api", downward_api, Optional["DownwardAPIProjection"])
        if downward_api is not None:  # omit empty
            v["downwardAPI"] = downward_api
        config_map = self.config_map()
        check_type("config_map", config_map, Optional["ConfigMapProjection"])
        if config_map is not None:  # omit empty
            v["configMap"] = config_map
        service_account_token = self.service_account_token()
        check_type(
            "service_account_token",
            service_account_token,
            Optional["ServiceAccountTokenProjection"],
        )
        if service_account_token is not None:  # omit empty
            v["serviceAccountToken"] = service_account_token
        return v

    def secret(self) -> Optional["SecretProjection"]:
        """
        information about the secret data to project
        """
        return self.__secret

    def downward_api(self) -> Optional["DownwardAPIProjection"]:
        """
        information about the downwardAPI data to project
        """
        return self.__downward_api

    def config_map(self) -> Optional["ConfigMapProjection"]:
        """
        information about the configMap data to project
        """
        return self.__config_map

    def service_account_token(self) -> Optional["ServiceAccountTokenProjection"]:
        """
        information about the serviceAccountToken data to project
        """
        return self.__service_account_token


class ProjectedVolumeSource(types.Object):
    """
    Represents a projected volume source
    """

    @context.scoped
    @typechecked
    def __init__(
        self, sources: List["VolumeProjection"] = None, default_mode: int = None
    ):
        super().__init__()
        self.__sources = sources if sources is not None else []
        self.__default_mode = default_mode if default_mode is not None else 420

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        sources = self.sources()
        check_type("sources", sources, List["VolumeProjection"])
        v["sources"] = sources
        default_mode = self.default_mode()
        check_type("default_mode", default_mode, Optional[int])
        if default_mode is not None:  # omit empty
            v["defaultMode"] = default_mode
        return v

    def sources(self) -> List["VolumeProjection"]:
        """
        list of volume projections
        """
        return self.__sources

    def default_mode(self) -> Optional[int]:
        """
        Mode bits to use on created files by default. Must be a value between
        0 and 0777.
        Directories within the path are not affected by this setting.
        This might be in conflict with other options that affect the file
        mode, like fsGroup, and the result can be other mode bits set.
        """
        return self.__default_mode


class RBDVolumeSource(types.Object):
    """
    Represents a Rados Block Device mount that lasts the lifetime of a pod.
    RBD volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        monitors: List[str] = None,
        image: str = "",
        fs_type: str = None,
        pool: str = "rbd",
        user: str = "admin",
        keyring: str = "/etc/ceph/keyring",
        secret_ref: "LocalObjectReference" = None,
        read_only: bool = None,
    ):
        super().__init__()
        self.__monitors = monitors if monitors is not None else []
        self.__image = image
        self.__fs_type = fs_type
        self.__pool = pool
        self.__user = user
        self.__keyring = keyring
        self.__secret_ref = secret_ref
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        monitors = self.monitors()
        check_type("monitors", monitors, List[str])
        v["monitors"] = monitors
        image = self.image()
        check_type("image", image, str)
        v["image"] = image
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        pool = self.pool()
        check_type("pool", pool, Optional[str])
        if pool:  # omit empty
            v["pool"] = pool
        user = self.user()
        check_type("user", user, Optional[str])
        if user:  # omit empty
            v["user"] = user
        keyring = self.keyring()
        check_type("keyring", keyring, Optional[str])
        if keyring:  # omit empty
            v["keyring"] = keyring
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["LocalObjectReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def monitors(self) -> List[str]:
        """
        A collection of Ceph monitors.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__monitors

    def image(self) -> str:
        """
        The rados image name.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__image

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type of the volume that you want to mount.
        Tip: Ensure that the filesystem type is supported by the host operating system.
        Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#rbd
        TODO: how do we prevent errors in the filesystem from compromising the machine
        """
        return self.__fs_type

    def pool(self) -> Optional[str]:
        """
        The rados pool name.
        Default is rbd.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__pool

    def user(self) -> Optional[str]:
        """
        The rados user name.
        Default is admin.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__user

    def keyring(self) -> Optional[str]:
        """
        Keyring is the path to key ring for RBDUser.
        Default is /etc/ceph/keyring.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__keyring

    def secret_ref(self) -> Optional["LocalObjectReference"]:
        """
        SecretRef is name of the authentication secret for RBDUser. If provided
        overrides keyring.
        Default is nil.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__secret_ref

    def read_only(self) -> Optional[bool]:
        """
        ReadOnly here will force the ReadOnly setting in VolumeMounts.
        Defaults to false.
        More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
        """
        return self.__read_only


class ScaleIOVolumeSource(types.Object):
    """
    ScaleIOVolumeSource represents a persistent ScaleIO volume
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        gateway: str = "",
        system: str = "",
        secret_ref: "LocalObjectReference" = None,
        ssl_enabled: bool = None,
        protection_domain: str = None,
        storage_pool: str = None,
        storage_mode: str = "ThinProvisioned",
        volume_name: str = None,
        fs_type: str = "xfs",
        read_only: bool = None,
    ):
        super().__init__()
        self.__gateway = gateway
        self.__system = system
        self.__secret_ref = secret_ref
        self.__ssl_enabled = ssl_enabled
        self.__protection_domain = protection_domain
        self.__storage_pool = storage_pool
        self.__storage_mode = storage_mode
        self.__volume_name = volume_name
        self.__fs_type = fs_type
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        gateway = self.gateway()
        check_type("gateway", gateway, str)
        v["gateway"] = gateway
        system = self.system()
        check_type("system", system, str)
        v["system"] = system
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["LocalObjectReference"])
        v["secretRef"] = secret_ref
        ssl_enabled = self.ssl_enabled()
        check_type("ssl_enabled", ssl_enabled, Optional[bool])
        if ssl_enabled:  # omit empty
            v["sslEnabled"] = ssl_enabled
        protection_domain = self.protection_domain()
        check_type("protection_domain", protection_domain, Optional[str])
        if protection_domain:  # omit empty
            v["protectionDomain"] = protection_domain
        storage_pool = self.storage_pool()
        check_type("storage_pool", storage_pool, Optional[str])
        if storage_pool:  # omit empty
            v["storagePool"] = storage_pool
        storage_mode = self.storage_mode()
        check_type("storage_mode", storage_mode, Optional[str])
        if storage_mode:  # omit empty
            v["storageMode"] = storage_mode
        volume_name = self.volume_name()
        check_type("volume_name", volume_name, Optional[str])
        if volume_name:  # omit empty
            v["volumeName"] = volume_name
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def gateway(self) -> str:
        """
        The host address of the ScaleIO API Gateway.
        """
        return self.__gateway

    def system(self) -> str:
        """
        The name of the storage system as configured in ScaleIO.
        """
        return self.__system

    def secret_ref(self) -> Optional["LocalObjectReference"]:
        """
        SecretRef references to the secret for ScaleIO user and other
        sensitive information. If this is not provided, Login operation will fail.
        """
        return self.__secret_ref

    def ssl_enabled(self) -> Optional[bool]:
        """
        Flag to enable/disable SSL communication with Gateway, default false
        """
        return self.__ssl_enabled

    def protection_domain(self) -> Optional[str]:
        """
        The name of the ScaleIO Protection Domain for the configured storage.
        """
        return self.__protection_domain

    def storage_pool(self) -> Optional[str]:
        """
        The ScaleIO Storage Pool associated with the protection domain.
        """
        return self.__storage_pool

    def storage_mode(self) -> Optional[str]:
        """
        Indicates whether the storage for a volume should be ThickProvisioned or ThinProvisioned.
        Default is ThinProvisioned.
        """
        return self.__storage_mode

    def volume_name(self) -> Optional[str]:
        """
        The name of a volume already created in the ScaleIO system
        that is associated with this volume source.
        """
        return self.__volume_name

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs".
        Default is "xfs".
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only


class SecretVolumeSource(types.Object):
    """
    Adapts a Secret into a volume.
    
    The contents of the target Secret's Data field will be presented in a volume
    as files using the keys in the Data field as the file names.
    Secret volumes support ownership management and SELinux relabeling.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        secret_name: str = None,
        items: List["KeyToPath"] = None,
        default_mode: int = None,
        optional: bool = None,
    ):
        super().__init__()
        self.__secret_name = secret_name
        self.__items = items if items is not None else []
        self.__default_mode = default_mode if default_mode is not None else 420
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secret_name = self.secret_name()
        check_type("secret_name", secret_name, Optional[str])
        if secret_name:  # omit empty
            v["secretName"] = secret_name
        items = self.items()
        check_type("items", items, Optional[List["KeyToPath"]])
        if items:  # omit empty
            v["items"] = items
        default_mode = self.default_mode()
        check_type("default_mode", default_mode, Optional[int])
        if default_mode is not None:  # omit empty
            v["defaultMode"] = default_mode
        optional = self.optional()
        check_type("optional", optional, Optional[bool])
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    def secret_name(self) -> Optional[str]:
        """
        Name of the secret in the pod's namespace to use.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#secret
        """
        return self.__secret_name

    def items(self) -> Optional[List["KeyToPath"]]:
        """
        If unspecified, each key-value pair in the Data field of the referenced
        Secret will be projected into the volume as a file whose name is the
        key and content is the value. If specified, the listed keys will be
        projected into the specified paths, and unlisted keys will not be
        present. If a key is specified which is not present in the Secret,
        the volume setup will error unless it is marked optional. Paths must be
        relative and may not contain the '..' path or start with '..'.
        """
        return self.__items

    def default_mode(self) -> Optional[int]:
        """
        Optional: mode bits to use on created files by default. Must be a
        value between 0 and 0777. Defaults to 0644.
        Directories within the path are not affected by this setting.
        This might be in conflict with other options that affect the file
        mode, like fsGroup, and the result can be other mode bits set.
        """
        return self.__default_mode

    def optional(self) -> Optional[bool]:
        """
        Specify whether the Secret or its keys must be defined
        """
        return self.__optional


class StorageOSVolumeSource(types.Object):
    """
    Represents a StorageOS persistent volume resource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        volume_name: str = None,
        volume_namespace: str = None,
        fs_type: str = None,
        read_only: bool = None,
        secret_ref: "LocalObjectReference" = None,
    ):
        super().__init__()
        self.__volume_name = volume_name
        self.__volume_namespace = volume_namespace
        self.__fs_type = fs_type
        self.__read_only = read_only
        self.__secret_ref = secret_ref

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volume_name = self.volume_name()
        check_type("volume_name", volume_name, Optional[str])
        if volume_name:  # omit empty
            v["volumeName"] = volume_name
        volume_namespace = self.volume_namespace()
        check_type("volume_namespace", volume_namespace, Optional[str])
        if volume_namespace:  # omit empty
            v["volumeNamespace"] = volume_namespace
        fs_type = self.fs_type()
        check_type("fs_type", fs_type, Optional[str])
        if fs_type:  # omit empty
            v["fsType"] = fs_type
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, Optional["LocalObjectReference"])
        if secret_ref is not None:  # omit empty
            v["secretRef"] = secret_ref
        return v

    def volume_name(self) -> Optional[str]:
        """
        VolumeName is the human-readable name of the StorageOS volume.  Volume
        names are only unique within a namespace.
        """
        return self.__volume_name

    def volume_namespace(self) -> Optional[str]:
        """
        VolumeNamespace specifies the scope of the volume within StorageOS.  If no
        namespace is specified then the Pod's namespace will be used.  This allows the
        Kubernetes name scoping to be mirrored within StorageOS for tighter integration.
        Set VolumeName to any name to override the default behaviour.
        Set to "default" if you are not using namespaces within StorageOS.
        Namespaces that do not pre-exist within StorageOS will be created.
        """
        return self.__volume_namespace

    def fs_type(self) -> Optional[str]:
        """
        Filesystem type to mount.
        Must be a filesystem type supported by the host operating system.
        Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
        """
        return self.__fs_type

    def read_only(self) -> Optional[bool]:
        """
        Defaults to false (read/write). ReadOnly here will force
        the ReadOnly setting in VolumeMounts.
        """
        return self.__read_only

    def secret_ref(self) -> Optional["LocalObjectReference"]:
        """
        SecretRef specifies the secret to use for obtaining the StorageOS API
        credentials.  If not specified, default values will be attempted.
        """
        return self.__secret_ref


class VolumeSource(types.Object):
    """
    Represents the source of a volume to mount.
    Only one of its members may be specified.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        host_path: "HostPathVolumeSource" = None,
        empty_dir: "EmptyDirVolumeSource" = None,
        gce_persistent_disk: "GCEPersistentDiskVolumeSource" = None,
        aws_elastic_block_store: "AWSElasticBlockStoreVolumeSource" = None,
        secret: "SecretVolumeSource" = None,
        nfs: "NFSVolumeSource" = None,
        iscsi: "ISCSIVolumeSource" = None,
        glusterfs: "GlusterfsVolumeSource" = None,
        persistent_volume_claim: "PersistentVolumeClaimVolumeSource" = None,
        rbd: "RBDVolumeSource" = None,
        flex_volume: "FlexVolumeSource" = None,
        cinder: "CinderVolumeSource" = None,
        cephfs: "CephFSVolumeSource" = None,
        flocker: "FlockerVolumeSource" = None,
        downward_api: "DownwardAPIVolumeSource" = None,
        fc: "FCVolumeSource" = None,
        azure_file: "AzureFileVolumeSource" = None,
        config_map: "ConfigMapVolumeSource" = None,
        vsphere_volume: "VsphereVirtualDiskVolumeSource" = None,
        quobyte: "QuobyteVolumeSource" = None,
        azure_disk: "AzureDiskVolumeSource" = None,
        photon_persistent_disk: "PhotonPersistentDiskVolumeSource" = None,
        projected: "ProjectedVolumeSource" = None,
        portworx_volume: "PortworxVolumeSource" = None,
        scale_io: "ScaleIOVolumeSource" = None,
        storageos: "StorageOSVolumeSource" = None,
        csi: "CSIVolumeSource" = None,
    ):
        super().__init__()
        self.__host_path = host_path
        self.__empty_dir = empty_dir
        self.__gce_persistent_disk = gce_persistent_disk
        self.__aws_elastic_block_store = aws_elastic_block_store
        self.__secret = secret
        self.__nfs = nfs
        self.__iscsi = iscsi
        self.__glusterfs = glusterfs
        self.__persistent_volume_claim = persistent_volume_claim
        self.__rbd = rbd
        self.__flex_volume = flex_volume
        self.__cinder = cinder
        self.__cephfs = cephfs
        self.__flocker = flocker
        self.__downward_api = downward_api
        self.__fc = fc
        self.__azure_file = azure_file
        self.__config_map = config_map
        self.__vsphere_volume = vsphere_volume
        self.__quobyte = quobyte
        self.__azure_disk = azure_disk
        self.__photon_persistent_disk = photon_persistent_disk
        self.__projected = projected
        self.__portworx_volume = portworx_volume
        self.__scale_io = scale_io
        self.__storageos = storageos
        self.__csi = csi

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        host_path = self.host_path()
        check_type("host_path", host_path, Optional["HostPathVolumeSource"])
        if host_path is not None:  # omit empty
            v["hostPath"] = host_path
        empty_dir = self.empty_dir()
        check_type("empty_dir", empty_dir, Optional["EmptyDirVolumeSource"])
        if empty_dir is not None:  # omit empty
            v["emptyDir"] = empty_dir
        gce_persistent_disk = self.gce_persistent_disk()
        check_type(
            "gce_persistent_disk",
            gce_persistent_disk,
            Optional["GCEPersistentDiskVolumeSource"],
        )
        if gce_persistent_disk is not None:  # omit empty
            v["gcePersistentDisk"] = gce_persistent_disk
        aws_elastic_block_store = self.aws_elastic_block_store()
        check_type(
            "aws_elastic_block_store",
            aws_elastic_block_store,
            Optional["AWSElasticBlockStoreVolumeSource"],
        )
        if aws_elastic_block_store is not None:  # omit empty
            v["awsElasticBlockStore"] = aws_elastic_block_store
        secret = self.secret()
        check_type("secret", secret, Optional["SecretVolumeSource"])
        if secret is not None:  # omit empty
            v["secret"] = secret
        nfs = self.nfs()
        check_type("nfs", nfs, Optional["NFSVolumeSource"])
        if nfs is not None:  # omit empty
            v["nfs"] = nfs
        iscsi = self.iscsi()
        check_type("iscsi", iscsi, Optional["ISCSIVolumeSource"])
        if iscsi is not None:  # omit empty
            v["iscsi"] = iscsi
        glusterfs = self.glusterfs()
        check_type("glusterfs", glusterfs, Optional["GlusterfsVolumeSource"])
        if glusterfs is not None:  # omit empty
            v["glusterfs"] = glusterfs
        persistent_volume_claim = self.persistent_volume_claim()
        check_type(
            "persistent_volume_claim",
            persistent_volume_claim,
            Optional["PersistentVolumeClaimVolumeSource"],
        )
        if persistent_volume_claim is not None:  # omit empty
            v["persistentVolumeClaim"] = persistent_volume_claim
        rbd = self.rbd()
        check_type("rbd", rbd, Optional["RBDVolumeSource"])
        if rbd is not None:  # omit empty
            v["rbd"] = rbd
        flex_volume = self.flex_volume()
        check_type("flex_volume", flex_volume, Optional["FlexVolumeSource"])
        if flex_volume is not None:  # omit empty
            v["flexVolume"] = flex_volume
        cinder = self.cinder()
        check_type("cinder", cinder, Optional["CinderVolumeSource"])
        if cinder is not None:  # omit empty
            v["cinder"] = cinder
        cephfs = self.cephfs()
        check_type("cephfs", cephfs, Optional["CephFSVolumeSource"])
        if cephfs is not None:  # omit empty
            v["cephfs"] = cephfs
        flocker = self.flocker()
        check_type("flocker", flocker, Optional["FlockerVolumeSource"])
        if flocker is not None:  # omit empty
            v["flocker"] = flocker
        downward_api = self.downward_api()
        check_type("downward_api", downward_api, Optional["DownwardAPIVolumeSource"])
        if downward_api is not None:  # omit empty
            v["downwardAPI"] = downward_api
        fc = self.fc()
        check_type("fc", fc, Optional["FCVolumeSource"])
        if fc is not None:  # omit empty
            v["fc"] = fc
        azure_file = self.azure_file()
        check_type("azure_file", azure_file, Optional["AzureFileVolumeSource"])
        if azure_file is not None:  # omit empty
            v["azureFile"] = azure_file
        config_map = self.config_map()
        check_type("config_map", config_map, Optional["ConfigMapVolumeSource"])
        if config_map is not None:  # omit empty
            v["configMap"] = config_map
        vsphere_volume = self.vsphere_volume()
        check_type(
            "vsphere_volume", vsphere_volume, Optional["VsphereVirtualDiskVolumeSource"]
        )
        if vsphere_volume is not None:  # omit empty
            v["vsphereVolume"] = vsphere_volume
        quobyte = self.quobyte()
        check_type("quobyte", quobyte, Optional["QuobyteVolumeSource"])
        if quobyte is not None:  # omit empty
            v["quobyte"] = quobyte
        azure_disk = self.azure_disk()
        check_type("azure_disk", azure_disk, Optional["AzureDiskVolumeSource"])
        if azure_disk is not None:  # omit empty
            v["azureDisk"] = azure_disk
        photon_persistent_disk = self.photon_persistent_disk()
        check_type(
            "photon_persistent_disk",
            photon_persistent_disk,
            Optional["PhotonPersistentDiskVolumeSource"],
        )
        if photon_persistent_disk is not None:  # omit empty
            v["photonPersistentDisk"] = photon_persistent_disk
        projected = self.projected()
        check_type("projected", projected, Optional["ProjectedVolumeSource"])
        if projected is not None:  # omit empty
            v["projected"] = projected
        portworx_volume = self.portworx_volume()
        check_type("portworx_volume", portworx_volume, Optional["PortworxVolumeSource"])
        if portworx_volume is not None:  # omit empty
            v["portworxVolume"] = portworx_volume
        scale_io = self.scale_io()
        check_type("scale_io", scale_io, Optional["ScaleIOVolumeSource"])
        if scale_io is not None:  # omit empty
            v["scaleIO"] = scale_io
        storageos = self.storageos()
        check_type("storageos", storageos, Optional["StorageOSVolumeSource"])
        if storageos is not None:  # omit empty
            v["storageos"] = storageos
        csi = self.csi()
        check_type("csi", csi, Optional["CSIVolumeSource"])
        if csi is not None:  # omit empty
            v["csi"] = csi
        return v

    def host_path(self) -> Optional["HostPathVolumeSource"]:
        """
        HostPath represents a pre-existing file or directory on the host
        machine that is directly exposed to the container. This is generally
        used for system agents or other privileged things that are allowed
        to see the host machine. Most containers will NOT need this.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#hostpath
        ---
        TODO(jonesdl) We need to restrict who can use host directory mounts and who can/can not
        mount host directories as read/write.
        """
        return self.__host_path

    def empty_dir(self) -> Optional["EmptyDirVolumeSource"]:
        """
        EmptyDir represents a temporary directory that shares a pod's lifetime.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#emptydir
        """
        return self.__empty_dir

    def gce_persistent_disk(self) -> Optional["GCEPersistentDiskVolumeSource"]:
        """
        GCEPersistentDisk represents a GCE Disk resource that is attached to a
        kubelet's host machine and then exposed to the pod.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
        """
        return self.__gce_persistent_disk

    def aws_elastic_block_store(self) -> Optional["AWSElasticBlockStoreVolumeSource"]:
        """
        AWSElasticBlockStore represents an AWS Disk resource that is attached to a
        kubelet's host machine and then exposed to the pod.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#awselasticblockstore
        """
        return self.__aws_elastic_block_store

    def secret(self) -> Optional["SecretVolumeSource"]:
        """
        Secret represents a secret that should populate this volume.
        More info: https://kubernetes.io/docs/concepts/storage/volumes#secret
        """
        return self.__secret

    def nfs(self) -> Optional["NFSVolumeSource"]:
        """
        NFS represents an NFS mount on the host that shares a pod's lifetime
        More info: https://kubernetes.io/docs/concepts/storage/volumes#nfs
        """
        return self.__nfs

    def iscsi(self) -> Optional["ISCSIVolumeSource"]:
        """
        ISCSI represents an ISCSI Disk resource that is attached to a
        kubelet's host machine and then exposed to the pod.
        More info: https://examples.k8s.io/volumes/iscsi/README.md
        """
        return self.__iscsi

    def glusterfs(self) -> Optional["GlusterfsVolumeSource"]:
        """
        Glusterfs represents a Glusterfs mount on the host that shares a pod's lifetime.
        More info: https://examples.k8s.io/volumes/glusterfs/README.md
        """
        return self.__glusterfs

    def persistent_volume_claim(self) -> Optional["PersistentVolumeClaimVolumeSource"]:
        """
        PersistentVolumeClaimVolumeSource represents a reference to a
        PersistentVolumeClaim in the same namespace.
        More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims
        """
        return self.__persistent_volume_claim

    def rbd(self) -> Optional["RBDVolumeSource"]:
        """
        RBD represents a Rados Block Device mount on the host that shares a pod's lifetime.
        More info: https://examples.k8s.io/volumes/rbd/README.md
        """
        return self.__rbd

    def flex_volume(self) -> Optional["FlexVolumeSource"]:
        """
        FlexVolume represents a generic volume resource that is
        provisioned/attached using an exec based plugin.
        """
        return self.__flex_volume

    def cinder(self) -> Optional["CinderVolumeSource"]:
        """
        Cinder represents a cinder volume attached and mounted on kubelets host machine.
        More info: https://examples.k8s.io/mysql-cinder-pd/README.md
        """
        return self.__cinder

    def cephfs(self) -> Optional["CephFSVolumeSource"]:
        """
        CephFS represents a Ceph FS mount on the host that shares a pod's lifetime
        """
        return self.__cephfs

    def flocker(self) -> Optional["FlockerVolumeSource"]:
        """
        Flocker represents a Flocker volume attached to a kubelet's host machine. This depends on the Flocker control service being running
        """
        return self.__flocker

    def downward_api(self) -> Optional["DownwardAPIVolumeSource"]:
        """
        DownwardAPI represents downward API about the pod that should populate this volume
        """
        return self.__downward_api

    def fc(self) -> Optional["FCVolumeSource"]:
        """
        FC represents a Fibre Channel resource that is attached to a kubelet's host machine and then exposed to the pod.
        """
        return self.__fc

    def azure_file(self) -> Optional["AzureFileVolumeSource"]:
        """
        AzureFile represents an Azure File Service mount on the host and bind mount to the pod.
        """
        return self.__azure_file

    def config_map(self) -> Optional["ConfigMapVolumeSource"]:
        """
        ConfigMap represents a configMap that should populate this volume
        """
        return self.__config_map

    def vsphere_volume(self) -> Optional["VsphereVirtualDiskVolumeSource"]:
        """
        VsphereVolume represents a vSphere volume attached and mounted on kubelets host machine
        """
        return self.__vsphere_volume

    def quobyte(self) -> Optional["QuobyteVolumeSource"]:
        """
        Quobyte represents a Quobyte mount on the host that shares a pod's lifetime
        """
        return self.__quobyte

    def azure_disk(self) -> Optional["AzureDiskVolumeSource"]:
        """
        AzureDisk represents an Azure Data Disk mount on the host and bind mount to the pod.
        """
        return self.__azure_disk

    def photon_persistent_disk(self) -> Optional["PhotonPersistentDiskVolumeSource"]:
        """
        PhotonPersistentDisk represents a PhotonController persistent disk attached and mounted on kubelets host machine
        """
        return self.__photon_persistent_disk

    def projected(self) -> Optional["ProjectedVolumeSource"]:
        """
        Items for all in one resources secrets, configmaps, and downward API
        """
        return self.__projected

    def portworx_volume(self) -> Optional["PortworxVolumeSource"]:
        """
        PortworxVolume represents a portworx volume attached and mounted on kubelets host machine
        """
        return self.__portworx_volume

    def scale_io(self) -> Optional["ScaleIOVolumeSource"]:
        """
        ScaleIO represents a ScaleIO persistent volume attached and mounted on Kubernetes nodes.
        """
        return self.__scale_io

    def storageos(self) -> Optional["StorageOSVolumeSource"]:
        """
        StorageOS represents a StorageOS volume attached and mounted on Kubernetes nodes.
        """
        return self.__storageos

    def csi(self) -> Optional["CSIVolumeSource"]:
        """
        CSI (Container Storage Interface) represents storage that is handled by an external CSI driver (Alpha feature).
        """
        return self.__csi


class Volume(types.Object):
    """
    Volume represents a named volume in a pod that may be accessed by any container in the pod.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", volume_source: "VolumeSource" = None):
        super().__init__()
        self.__name = name
        self.__volume_source = (
            volume_source if volume_source is not None else VolumeSource()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        volume_source = self.volume_source()
        check_type("volume_source", volume_source, "VolumeSource")
        v.update(volume_source._root())  # inline
        return v

    def name(self) -> str:
        """
        Volume's name.
        Must be a DNS_LABEL and unique within the pod.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
        """
        return self.__name

    def volume_source(self) -> "VolumeSource":
        """
        VolumeSource represents the location and type of the mounted volume.
        If not specified, the Volume is implied to be an EmptyDir.
        This implied behavior is deprecated and will be removed in a future version.
        """
        return self.__volume_source


class PodSpec(types.Object):
    """
    PodSpec is a description of a pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        volumes: List["Volume"] = None,
        init_containers: List["Container"] = None,
        containers: List["Container"] = None,
        ephemeral_containers: List["EphemeralContainer"] = None,
        restart_policy: RestartPolicy = RestartPolicy["Always"],
        termination_grace_period_seconds: int = None,
        active_deadline_seconds: int = None,
        dns_policy: DNSPolicy = DNSPolicy["ClusterFirst"],
        node_selector: Dict[str, str] = None,
        service_account_name: str = None,
        automount_service_account_token: bool = None,
        node_name: str = None,
        host_network: bool = None,
        host_pid: bool = None,
        host_ipc: bool = None,
        share_process_namespace: bool = None,
        security_context: "PodSecurityContext" = None,
        image_pull_secrets: List["LocalObjectReference"] = None,
        hostname: str = None,
        subdomain: str = None,
        affinity: "Affinity" = None,
        scheduler_name: str = "default-scheduler",
        tolerations: List["Toleration"] = None,
        host_aliases: List["HostAlias"] = None,
        priority_class_name: str = None,
        priority: int = None,
        dns_config: "PodDNSConfig" = None,
        readiness_gates: List["PodReadinessGate"] = None,
        runtime_class_name: str = None,
        enable_service_links: bool = None,
        preemption_policy: PreemptionPolicy = None,
        overhead: Dict[ResourceName, "resource.Quantity"] = None,
        topology_spread_constraints: List["TopologySpreadConstraint"] = None,
    ):
        super().__init__()
        self.__volumes = volumes if volumes is not None else []
        self.__init_containers = init_containers if init_containers is not None else []
        self.__containers = containers if containers is not None else []
        self.__ephemeral_containers = (
            ephemeral_containers if ephemeral_containers is not None else []
        )
        self.__restart_policy = restart_policy
        self.__termination_grace_period_seconds = (
            termination_grace_period_seconds
            if termination_grace_period_seconds is not None
            else 30
        )
        self.__active_deadline_seconds = active_deadline_seconds
        self.__dns_policy = dns_policy
        self.__node_selector = node_selector if node_selector is not None else {}
        self.__service_account_name = service_account_name
        self.__automount_service_account_token = automount_service_account_token
        self.__node_name = node_name
        self.__host_network = host_network
        self.__host_pid = host_pid
        self.__host_ipc = host_ipc
        self.__share_process_namespace = share_process_namespace
        self.__security_context = security_context
        self.__image_pull_secrets = (
            image_pull_secrets if image_pull_secrets is not None else []
        )
        self.__hostname = hostname
        self.__subdomain = subdomain
        self.__affinity = affinity
        self.__scheduler_name = scheduler_name
        self.__tolerations = tolerations if tolerations is not None else []
        self.__host_aliases = host_aliases if host_aliases is not None else []
        self.__priority_class_name = priority_class_name
        self.__priority = priority
        self.__dns_config = dns_config
        self.__readiness_gates = readiness_gates if readiness_gates is not None else []
        self.__runtime_class_name = runtime_class_name
        self.__enable_service_links = (
            enable_service_links if enable_service_links is not None else True
        )
        self.__preemption_policy = preemption_policy
        self.__overhead = overhead if overhead is not None else {}
        self.__topology_spread_constraints = (
            topology_spread_constraints
            if topology_spread_constraints is not None
            else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volumes = self.volumes()
        check_type("volumes", volumes, Optional[List["Volume"]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        init_containers = self.init_containers()
        check_type("init_containers", init_containers, Optional[List["Container"]])
        if init_containers:  # omit empty
            v["initContainers"] = init_containers
        containers = self.containers()
        check_type("containers", containers, List["Container"])
        v["containers"] = containers
        ephemeral_containers = self.ephemeral_containers()
        check_type(
            "ephemeral_containers",
            ephemeral_containers,
            Optional[List["EphemeralContainer"]],
        )
        if ephemeral_containers:  # omit empty
            v["ephemeralContainers"] = ephemeral_containers
        restart_policy = self.restart_policy()
        check_type("restart_policy", restart_policy, Optional[RestartPolicy])
        if restart_policy:  # omit empty
            v["restartPolicy"] = restart_policy
        termination_grace_period_seconds = self.termination_grace_period_seconds()
        check_type(
            "termination_grace_period_seconds",
            termination_grace_period_seconds,
            Optional[int],
        )
        if termination_grace_period_seconds is not None:  # omit empty
            v["terminationGracePeriodSeconds"] = termination_grace_period_seconds
        active_deadline_seconds = self.active_deadline_seconds()
        check_type("active_deadline_seconds", active_deadline_seconds, Optional[int])
        if active_deadline_seconds is not None:  # omit empty
            v["activeDeadlineSeconds"] = active_deadline_seconds
        dns_policy = self.dns_policy()
        check_type("dns_policy", dns_policy, Optional[DNSPolicy])
        if dns_policy:  # omit empty
            v["dnsPolicy"] = dns_policy
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional[Dict[str, str]])
        if node_selector:  # omit empty
            v["nodeSelector"] = node_selector
        service_account_name = self.service_account_name()
        check_type("service_account_name", service_account_name, Optional[str])
        if service_account_name:  # omit empty
            v["serviceAccountName"] = service_account_name
        automount_service_account_token = self.automount_service_account_token()
        check_type(
            "automount_service_account_token",
            automount_service_account_token,
            Optional[bool],
        )
        if automount_service_account_token is not None:  # omit empty
            v["automountServiceAccountToken"] = automount_service_account_token
        node_name = self.node_name()
        check_type("node_name", node_name, Optional[str])
        if node_name:  # omit empty
            v["nodeName"] = node_name
        host_network = self.host_network()
        check_type("host_network", host_network, Optional[bool])
        if host_network:  # omit empty
            v["hostNetwork"] = host_network
        host_pid = self.host_pid()
        check_type("host_pid", host_pid, Optional[bool])
        if host_pid:  # omit empty
            v["hostPID"] = host_pid
        host_ipc = self.host_ipc()
        check_type("host_ipc", host_ipc, Optional[bool])
        if host_ipc:  # omit empty
            v["hostIPC"] = host_ipc
        share_process_namespace = self.share_process_namespace()
        check_type("share_process_namespace", share_process_namespace, Optional[bool])
        if share_process_namespace is not None:  # omit empty
            v["shareProcessNamespace"] = share_process_namespace
        security_context = self.security_context()
        check_type("security_context", security_context, Optional["PodSecurityContext"])
        if security_context is not None:  # omit empty
            v["securityContext"] = security_context
        image_pull_secrets = self.image_pull_secrets()
        check_type(
            "image_pull_secrets",
            image_pull_secrets,
            Optional[List["LocalObjectReference"]],
        )
        if image_pull_secrets:  # omit empty
            v["imagePullSecrets"] = image_pull_secrets
        hostname = self.hostname()
        check_type("hostname", hostname, Optional[str])
        if hostname:  # omit empty
            v["hostname"] = hostname
        subdomain = self.subdomain()
        check_type("subdomain", subdomain, Optional[str])
        if subdomain:  # omit empty
            v["subdomain"] = subdomain
        affinity = self.affinity()
        check_type("affinity", affinity, Optional["Affinity"])
        if affinity is not None:  # omit empty
            v["affinity"] = affinity
        scheduler_name = self.scheduler_name()
        check_type("scheduler_name", scheduler_name, Optional[str])
        if scheduler_name:  # omit empty
            v["schedulerName"] = scheduler_name
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        host_aliases = self.host_aliases()
        check_type("host_aliases", host_aliases, Optional[List["HostAlias"]])
        if host_aliases:  # omit empty
            v["hostAliases"] = host_aliases
        priority_class_name = self.priority_class_name()
        check_type("priority_class_name", priority_class_name, Optional[str])
        if priority_class_name:  # omit empty
            v["priorityClassName"] = priority_class_name
        priority = self.priority()
        check_type("priority", priority, Optional[int])
        if priority is not None:  # omit empty
            v["priority"] = priority
        dns_config = self.dns_config()
        check_type("dns_config", dns_config, Optional["PodDNSConfig"])
        if dns_config is not None:  # omit empty
            v["dnsConfig"] = dns_config
        readiness_gates = self.readiness_gates()
        check_type(
            "readiness_gates", readiness_gates, Optional[List["PodReadinessGate"]]
        )
        if readiness_gates:  # omit empty
            v["readinessGates"] = readiness_gates
        runtime_class_name = self.runtime_class_name()
        check_type("runtime_class_name", runtime_class_name, Optional[str])
        if runtime_class_name is not None:  # omit empty
            v["runtimeClassName"] = runtime_class_name
        enable_service_links = self.enable_service_links()
        check_type("enable_service_links", enable_service_links, Optional[bool])
        if enable_service_links is not None:  # omit empty
            v["enableServiceLinks"] = enable_service_links
        preemption_policy = self.preemption_policy()
        check_type("preemption_policy", preemption_policy, Optional[PreemptionPolicy])
        if preemption_policy is not None:  # omit empty
            v["preemptionPolicy"] = preemption_policy
        overhead = self.overhead()
        check_type(
            "overhead", overhead, Optional[Dict[ResourceName, "resource.Quantity"]]
        )
        if overhead:  # omit empty
            v["overhead"] = overhead
        topology_spread_constraints = self.topology_spread_constraints()
        check_type(
            "topology_spread_constraints",
            topology_spread_constraints,
            Optional[List["TopologySpreadConstraint"]],
        )
        if topology_spread_constraints:  # omit empty
            v["topologySpreadConstraints"] = topology_spread_constraints
        return v

    def volumes(self) -> Optional[List["Volume"]]:
        """
        List of volumes that can be mounted by containers belonging to the pod.
        More info: https://kubernetes.io/docs/concepts/storage/volumes
        """
        return self.__volumes

    def init_containers(self) -> Optional[List["Container"]]:
        """
        List of initialization containers belonging to the pod.
        Init containers are executed in order prior to containers being started. If any
        init container fails, the pod is considered to have failed and is handled according
        to its restartPolicy. The name for an init container or normal container must be
        unique among all containers.
        Init containers may not have Lifecycle actions, Readiness probes, Liveness probes, or Startup probes.
        The resourceRequirements of an init container are taken into account during scheduling
        by finding the highest request/limit for each resource type, and then using the max of
        of that value or the sum of the normal containers. Limits are applied to init containers
        in a similar fashion.
        Init containers cannot currently be added or removed.
        Cannot be updated.
        More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
        """
        return self.__init_containers

    def containers(self) -> List["Container"]:
        """
        List of containers belonging to the pod.
        Containers cannot currently be added or removed.
        There must be at least one container in a Pod.
        Cannot be updated.
        """
        return self.__containers

    def ephemeral_containers(self) -> Optional[List["EphemeralContainer"]]:
        """
        List of ephemeral containers run in this pod. Ephemeral containers may be run in an existing
        pod to perform user-initiated actions such as debugging. This list cannot be specified when
        creating a pod, and it cannot be modified by updating the pod spec. In order to add an
        ephemeral container to an existing pod, use the pod's ephemeralcontainers subresource.
        This field is alpha-level and is only honored by servers that enable the EphemeralContainers feature.
        """
        return self.__ephemeral_containers

    def restart_policy(self) -> Optional[RestartPolicy]:
        """
        Restart policy for all containers within the pod.
        One of Always, OnFailure, Never.
        Default to Always.
        More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#restart-policy
        """
        return self.__restart_policy

    def termination_grace_period_seconds(self) -> Optional[int]:
        """
        Optional duration in seconds the pod needs to terminate gracefully. May be decreased in delete request.
        Value must be non-negative integer. The value zero indicates delete immediately.
        If this value is nil, the default grace period will be used instead.
        The grace period is the duration in seconds after the processes running in the pod are sent
        a termination signal and the time when the processes are forcibly halted with a kill signal.
        Set this value longer than the expected cleanup time for your process.
        Defaults to 30 seconds.
        """
        return self.__termination_grace_period_seconds

    def active_deadline_seconds(self) -> Optional[int]:
        """
        Optional duration in seconds the pod may be active on the node relative to
        StartTime before the system will actively try to mark it failed and kill associated containers.
        Value must be a positive integer.
        """
        return self.__active_deadline_seconds

    def dns_policy(self) -> Optional[DNSPolicy]:
        """
        Set DNS policy for the pod.
        Defaults to "ClusterFirst".
        Valid values are 'ClusterFirstWithHostNet', 'ClusterFirst', 'Default' or 'None'.
        DNS parameters given in DNSConfig will be merged with the policy selected with DNSPolicy.
        To have DNS options set along with hostNetwork, you have to specify DNS policy
        explicitly to 'ClusterFirstWithHostNet'.
        """
        return self.__dns_policy

    def node_selector(self) -> Optional[Dict[str, str]]:
        """
        NodeSelector is a selector which must be true for the pod to fit on a node.
        Selector which must match a node's labels for the pod to be scheduled on that node.
        More info: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
        """
        return self.__node_selector

    def service_account_name(self) -> Optional[str]:
        """
        ServiceAccountName is the name of the ServiceAccount to use to run this pod.
        More info: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
        """
        return self.__service_account_name

    def automount_service_account_token(self) -> Optional[bool]:
        """
        AutomountServiceAccountToken indicates whether a service account token should be automatically mounted.
        """
        return self.__automount_service_account_token

    def node_name(self) -> Optional[str]:
        """
        NodeName is a request to schedule this pod onto a specific node. If it is non-empty,
        the scheduler simply schedules this pod onto that node, assuming that it fits resource
        requirements.
        """
        return self.__node_name

    def host_network(self) -> Optional[bool]:
        """
        Host networking requested for this pod. Use the host's network namespace.
        If this option is set, the ports that will be used must be specified.
        Default to false.
        """
        return self.__host_network

    def host_pid(self) -> Optional[bool]:
        """
        Use the host's pid namespace.
        Optional: Default to false.
        """
        return self.__host_pid

    def host_ipc(self) -> Optional[bool]:
        """
        Use the host's ipc namespace.
        Optional: Default to false.
        """
        return self.__host_ipc

    def share_process_namespace(self) -> Optional[bool]:
        """
        Share a single process namespace between all of the containers in a pod.
        When this is set containers will be able to view and signal processes from other containers
        in the same pod, and the first process in each container will not be assigned PID 1.
        HostPID and ShareProcessNamespace cannot both be set.
        Optional: Default to false.
        """
        return self.__share_process_namespace

    def security_context(self) -> Optional["PodSecurityContext"]:
        """
        SecurityContext holds pod-level security attributes and common container settings.
        Optional: Defaults to empty.  See type description for default values of each field.
        """
        return self.__security_context

    def image_pull_secrets(self) -> Optional[List["LocalObjectReference"]]:
        """
        ImagePullSecrets is an optional list of references to secrets in the same namespace to use for pulling any of the images used by this PodSpec.
        If specified, these secrets will be passed to individual puller implementations for them to use. For example,
        in the case of docker, only DockerConfig type secrets are honored.
        More info: https://kubernetes.io/docs/concepts/containers/images#specifying-imagepullsecrets-on-a-pod
        """
        return self.__image_pull_secrets

    def hostname(self) -> Optional[str]:
        """
        Specifies the hostname of the Pod
        If not specified, the pod's hostname will be set to a system-defined value.
        """
        return self.__hostname

    def subdomain(self) -> Optional[str]:
        """
        If specified, the fully qualified Pod hostname will be "<hostname>.<subdomain>.<pod namespace>.svc.<cluster domain>".
        If not specified, the pod will not have a domainname at all.
        """
        return self.__subdomain

    def affinity(self) -> Optional["Affinity"]:
        """
        If specified, the pod's scheduling constraints
        """
        return self.__affinity

    def scheduler_name(self) -> Optional[str]:
        """
        If specified, the pod will be dispatched by specified scheduler.
        If not specified, the pod will be dispatched by default scheduler.
        """
        return self.__scheduler_name

    def tolerations(self) -> Optional[List["Toleration"]]:
        """
        If specified, the pod's tolerations.
        """
        return self.__tolerations

    def host_aliases(self) -> Optional[List["HostAlias"]]:
        """
        HostAliases is an optional list of hosts and IPs that will be injected into the pod's hosts
        file if specified. This is only valid for non-hostNetwork pods.
        """
        return self.__host_aliases

    def priority_class_name(self) -> Optional[str]:
        """
        If specified, indicates the pod's priority. "system-node-critical" and
        "system-cluster-critical" are two special keywords which indicate the
        highest priorities with the former being the highest priority. Any other
        name must be defined by creating a PriorityClass object with that name.
        If not specified, the pod priority will be default or zero if there is no
        default.
        """
        return self.__priority_class_name

    def priority(self) -> Optional[int]:
        """
        The priority value. Various system components use this field to find the
        priority of the pod. When Priority Admission Controller is enabled, it
        prevents users from setting this field. The admission controller populates
        this field from PriorityClassName.
        The higher the value, the higher the priority.
        """
        return self.__priority

    def dns_config(self) -> Optional["PodDNSConfig"]:
        """
        Specifies the DNS parameters of a pod.
        Parameters specified here will be merged to the generated DNS
        configuration based on DNSPolicy.
        """
        return self.__dns_config

    def readiness_gates(self) -> Optional[List["PodReadinessGate"]]:
        """
        If specified, all readiness gates will be evaluated for pod readiness.
        A pod is ready when all its containers are ready AND
        all conditions specified in the readiness gates have status equal to "True"
        More info: https://git.k8s.io/enhancements/keps/sig-network/0007-pod-ready%2B%2B.md
        """
        return self.__readiness_gates

    def runtime_class_name(self) -> Optional[str]:
        """
        RuntimeClassName refers to a RuntimeClass object in the node.k8s.io group, which should be used
        to run this pod.  If no RuntimeClass resource matches the named class, the pod will not be run.
        If unset or empty, the "legacy" RuntimeClass will be used, which is an implicit class with an
        empty definition that uses the default runtime handler.
        More info: https://git.k8s.io/enhancements/keps/sig-node/runtime-class.md
        This is a beta feature as of Kubernetes v1.14.
        """
        return self.__runtime_class_name

    def enable_service_links(self) -> Optional[bool]:
        """
        EnableServiceLinks indicates whether information about services should be injected into pod's
        environment variables, matching the syntax of Docker links.
        Optional: Defaults to true.
        """
        return self.__enable_service_links

    def preemption_policy(self) -> Optional[PreemptionPolicy]:
        """
        PreemptionPolicy is the Policy for preempting pods with lower priority.
        One of Never, PreemptLowerPriority.
        Defaults to PreemptLowerPriority if unset.
        This field is alpha-level and is only honored by servers that enable the NonPreemptingPriority feature.
        """
        return self.__preemption_policy

    def overhead(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        """
        Overhead represents the resource overhead associated with running a pod for a given RuntimeClass.
        This field will be autopopulated at admission time by the RuntimeClass admission controller. If
        the RuntimeClass admission controller is enabled, overhead must not be set in Pod create requests.
        The RuntimeClass admission controller will reject Pod create requests which have the overhead already
        set. If RuntimeClass is configured and selected in the PodSpec, Overhead will be set to the value
        defined in the corresponding RuntimeClass, otherwise it will remain unset and treated as zero.
        More info: https://git.k8s.io/enhancements/keps/sig-node/20190226-pod-overhead.md
        This field is alpha-level as of Kubernetes v1.16, and is only honored by servers that enable the PodOverhead feature.
        """
        return self.__overhead

    def topology_spread_constraints(self) -> Optional[List["TopologySpreadConstraint"]]:
        """
        TopologySpreadConstraints describes how a group of pods ought to spread across topology
        domains. Scheduler will schedule pods in a way which abides by the constraints.
        This field is alpha-level and is only honored by clusters that enables the EvenPodsSpread
        feature.
        All topologySpreadConstraints are ANDed.
        +listType=map
        +listMapKey=topologyKey
        +listMapKey=whenUnsatisfiable
        """
        return self.__topology_spread_constraints


class Pod(base.TypedObject, base.NamespacedMetadataObject):
    """
    Pod is a collection of containers that can run on a host. This resource is created
    by clients and scheduled onto hosts.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PodSpec" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="Pod",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PodSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["PodSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["PodSpec"]:
        """
        Specification of the desired behavior of the pod.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class PodAttachOptions(base.TypedObject):
    """
    PodAttachOptions is the query options to a Pod's remote attach call.
    ---
    TODO: merge w/ PodExecOptions below for stdin, stdout, etc
    and also when we cut V2, we should export a "StreamOptions" or somesuch that contains Stdin, Stdout, Stder and TTY
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        stdin: bool = None,
        stdout: bool = None,
        stderr: bool = None,
        tty: bool = None,
        container: str = None,
    ):
        super().__init__(api_version="v1", kind="PodAttachOptions")
        self.__stdin = stdin
        self.__stdout = stdout
        self.__stderr = stderr
        self.__tty = tty
        self.__container = container

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        stdin = self.stdin()
        check_type("stdin", stdin, Optional[bool])
        if stdin:  # omit empty
            v["stdin"] = stdin
        stdout = self.stdout()
        check_type("stdout", stdout, Optional[bool])
        if stdout:  # omit empty
            v["stdout"] = stdout
        stderr = self.stderr()
        check_type("stderr", stderr, Optional[bool])
        if stderr:  # omit empty
            v["stderr"] = stderr
        tty = self.tty()
        check_type("tty", tty, Optional[bool])
        if tty:  # omit empty
            v["tty"] = tty
        container = self.container()
        check_type("container", container, Optional[str])
        if container:  # omit empty
            v["container"] = container
        return v

    def stdin(self) -> Optional[bool]:
        """
        Stdin if true, redirects the standard input stream of the pod for this call.
        Defaults to false.
        """
        return self.__stdin

    def stdout(self) -> Optional[bool]:
        """
        Stdout if true indicates that stdout is to be redirected for the attach call.
        Defaults to true.
        """
        return self.__stdout

    def stderr(self) -> Optional[bool]:
        """
        Stderr if true indicates that stderr is to be redirected for the attach call.
        Defaults to true.
        """
        return self.__stderr

    def tty(self) -> Optional[bool]:
        """
        TTY if true indicates that a tty will be allocated for the attach call.
        This is passed through the container runtime so the tty
        is allocated on the worker node by the container runtime.
        Defaults to false.
        """
        return self.__tty

    def container(self) -> Optional[str]:
        """
        The container in which to execute the command.
        Defaults to only container if there is only one container in the pod.
        """
        return self.__container


class PodExecOptions(base.TypedObject):
    """
    PodExecOptions is the query options to a Pod's remote exec call.
    ---
    TODO: This is largely identical to PodAttachOptions above, make sure they stay in sync and see about merging
    and also when we cut V2, we should export a "StreamOptions" or somesuch that contains Stdin, Stdout, Stder and TTY
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        stdin: bool = None,
        stdout: bool = None,
        stderr: bool = None,
        tty: bool = None,
        container: str = None,
        command: List[str] = None,
    ):
        super().__init__(api_version="v1", kind="PodExecOptions")
        self.__stdin = stdin
        self.__stdout = stdout
        self.__stderr = stderr
        self.__tty = tty
        self.__container = container
        self.__command = command if command is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        stdin = self.stdin()
        check_type("stdin", stdin, Optional[bool])
        if stdin:  # omit empty
            v["stdin"] = stdin
        stdout = self.stdout()
        check_type("stdout", stdout, Optional[bool])
        if stdout:  # omit empty
            v["stdout"] = stdout
        stderr = self.stderr()
        check_type("stderr", stderr, Optional[bool])
        if stderr:  # omit empty
            v["stderr"] = stderr
        tty = self.tty()
        check_type("tty", tty, Optional[bool])
        if tty:  # omit empty
            v["tty"] = tty
        container = self.container()
        check_type("container", container, Optional[str])
        if container:  # omit empty
            v["container"] = container
        command = self.command()
        check_type("command", command, List[str])
        v["command"] = command
        return v

    def stdin(self) -> Optional[bool]:
        """
        Redirect the standard input stream of the pod for this call.
        Defaults to false.
        """
        return self.__stdin

    def stdout(self) -> Optional[bool]:
        """
        Redirect the standard output stream of the pod for this call.
        Defaults to true.
        """
        return self.__stdout

    def stderr(self) -> Optional[bool]:
        """
        Redirect the standard error stream of the pod for this call.
        Defaults to true.
        """
        return self.__stderr

    def tty(self) -> Optional[bool]:
        """
        TTY if true indicates that a tty will be allocated for the exec call.
        Defaults to false.
        """
        return self.__tty

    def container(self) -> Optional[str]:
        """
        Container in which to execute the command.
        Defaults to only container if there is only one container in the pod.
        """
        return self.__container

    def command(self) -> List[str]:
        """
        Command is the remote command to execute. argv array. Not executed within a shell.
        """
        return self.__command


class PodLogOptions(base.TypedObject):
    """
    PodLogOptions is the query options for a Pod's logs REST call.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        container: str = None,
        follow: bool = None,
        previous: bool = None,
        since_seconds: int = None,
        since_time: "base.Time" = None,
        timestamps: bool = None,
        tail_lines: int = None,
        limit_bytes: int = None,
        insecure_skip_tls_verify_backend: bool = None,
    ):
        super().__init__(api_version="v1", kind="PodLogOptions")
        self.__container = container
        self.__follow = follow
        self.__previous = previous
        self.__since_seconds = since_seconds
        self.__since_time = since_time
        self.__timestamps = timestamps
        self.__tail_lines = tail_lines
        self.__limit_bytes = limit_bytes
        self.__insecure_skip_tls_verify_backend = insecure_skip_tls_verify_backend

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        container = self.container()
        check_type("container", container, Optional[str])
        if container:  # omit empty
            v["container"] = container
        follow = self.follow()
        check_type("follow", follow, Optional[bool])
        if follow:  # omit empty
            v["follow"] = follow
        previous = self.previous()
        check_type("previous", previous, Optional[bool])
        if previous:  # omit empty
            v["previous"] = previous
        since_seconds = self.since_seconds()
        check_type("since_seconds", since_seconds, Optional[int])
        if since_seconds is not None:  # omit empty
            v["sinceSeconds"] = since_seconds
        since_time = self.since_time()
        check_type("since_time", since_time, Optional["base.Time"])
        if since_time is not None:  # omit empty
            v["sinceTime"] = since_time
        timestamps = self.timestamps()
        check_type("timestamps", timestamps, Optional[bool])
        if timestamps:  # omit empty
            v["timestamps"] = timestamps
        tail_lines = self.tail_lines()
        check_type("tail_lines", tail_lines, Optional[int])
        if tail_lines is not None:  # omit empty
            v["tailLines"] = tail_lines
        limit_bytes = self.limit_bytes()
        check_type("limit_bytes", limit_bytes, Optional[int])
        if limit_bytes is not None:  # omit empty
            v["limitBytes"] = limit_bytes
        insecure_skip_tls_verify_backend = self.insecure_skip_tls_verify_backend()
        check_type(
            "insecure_skip_tls_verify_backend",
            insecure_skip_tls_verify_backend,
            Optional[bool],
        )
        if insecure_skip_tls_verify_backend:  # omit empty
            v["insecureSkipTLSVerifyBackend"] = insecure_skip_tls_verify_backend
        return v

    def container(self) -> Optional[str]:
        """
        The container for which to stream logs. Defaults to only container if there is one container in the pod.
        """
        return self.__container

    def follow(self) -> Optional[bool]:
        """
        Follow the log stream of the pod. Defaults to false.
        """
        return self.__follow

    def previous(self) -> Optional[bool]:
        """
        Return previous terminated container logs. Defaults to false.
        """
        return self.__previous

    def since_seconds(self) -> Optional[int]:
        """
        A relative time in seconds before the current time from which to show logs. If this value
        precedes the time a pod was started, only logs since the pod start will be returned.
        If this value is in the future, no logs will be returned.
        Only one of sinceSeconds or sinceTime may be specified.
        """
        return self.__since_seconds

    def since_time(self) -> Optional["base.Time"]:
        """
        An RFC3339 timestamp from which to show logs. If this value
        precedes the time a pod was started, only logs since the pod start will be returned.
        If this value is in the future, no logs will be returned.
        Only one of sinceSeconds or sinceTime may be specified.
        """
        return self.__since_time

    def timestamps(self) -> Optional[bool]:
        """
        If true, add an RFC3339 or RFC3339Nano timestamp at the beginning of every line
        of log output. Defaults to false.
        """
        return self.__timestamps

    def tail_lines(self) -> Optional[int]:
        """
        If set, the number of lines from the end of the logs to show. If not specified,
        logs are shown from the creation of the container or sinceSeconds or sinceTime
        """
        return self.__tail_lines

    def limit_bytes(self) -> Optional[int]:
        """
        If set, the number of bytes to read from the server before terminating the
        log output. This may not display a complete final line of logging, and may return
        slightly more or slightly less than the specified limit.
        """
        return self.__limit_bytes

    def insecure_skip_tls_verify_backend(self) -> Optional[bool]:
        """
        insecureSkipTLSVerifyBackend indicates that the apiserver should not confirm the validity of the
        serving certificate of the backend it is connecting to.  This will make the HTTPS connection between the apiserver
        and the backend insecure. This means the apiserver cannot verify the log data it is receiving came from the real
        kubelet.  If the kubelet is configured to verify the apiserver's TLS credentials, it does not mean the
        connection to the real kubelet is vulnerable to a man in the middle attack (e.g. an attacker could not intercept
        the actual log data coming from the real kubelet).
        """
        return self.__insecure_skip_tls_verify_backend


class PodPortForwardOptions(base.TypedObject):
    """
    PodPortForwardOptions is the query options to a Pod's port forward call
    when using WebSockets.
    The `port` query parameter must specify the port or
    ports (comma separated) to forward over.
    Port forwarding over SPDY does not use these options. It requires the port
    to be passed in the `port` header as part of request.
    """

    @context.scoped
    @typechecked
    def __init__(self, ports: List[int] = None):
        super().__init__(api_version="v1", kind="PodPortForwardOptions")
        self.__ports = ports if ports is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ports = self.ports()
        check_type("ports", ports, Optional[List[int]])
        if ports:  # omit empty
            v["ports"] = ports
        return v

    def ports(self) -> Optional[List[int]]:
        """
        List of ports to forward
        Required when using WebSockets
        """
        return self.__ports


class PodProxyOptions(base.TypedObject):
    """
    PodProxyOptions is the query options to a Pod's proxy call.
    """

    @context.scoped
    @typechecked
    def __init__(self, path: str = None):
        super().__init__(api_version="v1", kind="PodProxyOptions")
        self.__path = path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        return v

    def path(self) -> Optional[str]:
        """
        Path is the URL path to use for the current proxy request to pod.
        """
        return self.__path


class PodStatusResult(base.TypedObject, base.NamespacedMetadataObject):
    """
    PodStatusResult is a wrapper for PodStatus returned by kubelet that can be encode/decoded
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
    ):
        super().__init__(
            api_version="v1",
            kind="PodStatusResult",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        return v


class PodTemplateSpec(base.NamespacedMetadataObject):
    """
    PodTemplateSpec describes the data a pod should have when created from a template
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PodSpec" = None,
    ):
        super().__init__(
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PodSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["PodSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["PodSpec"]:
        """
        Specification of the desired behavior of the pod.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class PodTemplate(base.TypedObject, base.NamespacedMetadataObject):
    """
    PodTemplate describes a template for creating copies of a predefined pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        template: "PodTemplateSpec" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="PodTemplate",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__template = template if template is not None else PodTemplateSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        template = self.template()
        check_type("template", template, Optional["PodTemplateSpec"])
        v["template"] = template
        return v

    def template(self) -> Optional["PodTemplateSpec"]:
        """
        Template defines the pods that will be created from this pod template.
        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__template


class RangeAllocation(base.TypedObject, base.NamespacedMetadataObject):
    """
    RangeAllocation is not a public type.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        range: str = "",
        data: bytes = None,
    ):
        super().__init__(
            api_version="v1",
            kind="RangeAllocation",
            **({"namespace": namespace} if namespace is not None else {}),
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
        Range is string that identifies the range represented by 'data'.
        """
        return self.__range

    def data(self) -> bytes:
        """
        Data is a bit array containing all allocated addresses in the previous segment.
        """
        return self.__data


class ReplicationControllerSpec(types.Object):
    """
    ReplicationControllerSpec is the specification of a replication controller.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        replicas: int = None,
        min_ready_seconds: int = None,
        selector: Dict[str, str] = None,
        template: "PodTemplateSpec" = None,
    ):
        super().__init__()
        self.__replicas = replicas if replicas is not None else 1
        self.__min_ready_seconds = min_ready_seconds
        self.__selector = selector if selector is not None else {}
        self.__template = template

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas is not None:  # omit empty
            v["replicas"] = replicas
        min_ready_seconds = self.min_ready_seconds()
        check_type("min_ready_seconds", min_ready_seconds, Optional[int])
        if min_ready_seconds:  # omit empty
            v["minReadySeconds"] = min_ready_seconds
        selector = self.selector()
        check_type("selector", selector, Optional[Dict[str, str]])
        if selector:  # omit empty
            v["selector"] = selector
        template = self.template()
        check_type("template", template, Optional["PodTemplateSpec"])
        if template is not None:  # omit empty
            v["template"] = template
        return v

    def replicas(self) -> Optional[int]:
        """
        Replicas is the number of desired replicas.
        This is a pointer to distinguish between explicit zero and unspecified.
        Defaults to 1.
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#what-is-a-replicationcontroller
        """
        return self.__replicas

    def min_ready_seconds(self) -> Optional[int]:
        """
        Minimum number of seconds for which a newly created pod should be ready
        without any of its container crashing, for it to be considered available.
        Defaults to 0 (pod will be considered available as soon as it is ready)
        """
        return self.__min_ready_seconds

    def selector(self) -> Optional[Dict[str, str]]:
        """
        Selector is a label query over pods that should match the Replicas count.
        If Selector is empty, it is defaulted to the labels present on the Pod template.
        Label keys and values that must match in order to be controlled by this replication
        controller, if empty defaulted to labels on Pod template.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
        """
        return self.__selector

    def template(self) -> Optional["PodTemplateSpec"]:
        """
        Template is the object that describes the pod that will be created if
        insufficient replicas are detected. This takes precedence over a TemplateRef.
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#pod-template
        """
        return self.__template


class ReplicationController(base.TypedObject, base.NamespacedMetadataObject):
    """
    ReplicationController represents the configuration of a replication controller.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ReplicationControllerSpec" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="ReplicationController",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ReplicationControllerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["ReplicationControllerSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["ReplicationControllerSpec"]:
        """
        Spec defines the specification of the desired behavior of the replication controller.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class ScopedResourceSelectorRequirement(types.Object):
    """
    A scoped-resource selector requirement is a selector that contains values, a scope name, and an operator
    that relates the scope name and values.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        scope_name: ResourceQuotaScope = None,
        operator: ScopeSelectorOperator = None,
        values: List[str] = None,
    ):
        super().__init__()
        self.__scope_name = scope_name
        self.__operator = operator
        self.__values = values if values is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        scope_name = self.scope_name()
        check_type("scope_name", scope_name, ResourceQuotaScope)
        v["scopeName"] = scope_name
        operator = self.operator()
        check_type("operator", operator, ScopeSelectorOperator)
        v["operator"] = operator
        values = self.values()
        check_type("values", values, Optional[List[str]])
        if values:  # omit empty
            v["values"] = values
        return v

    def scope_name(self) -> ResourceQuotaScope:
        """
        The name of the scope that the selector applies to.
        """
        return self.__scope_name

    def operator(self) -> ScopeSelectorOperator:
        """
        Represents a scope's relationship to a set of values.
        Valid operators are In, NotIn, Exists, DoesNotExist.
        """
        return self.__operator

    def values(self) -> Optional[List[str]]:
        """
        An array of string values. If the operator is In or NotIn,
        the values array must be non-empty. If the operator is Exists or DoesNotExist,
        the values array must be empty.
        This array is replaced during a strategic merge patch.
        """
        return self.__values


class ScopeSelector(types.Object):
    """
    A scope selector represents the AND of the selectors represented
    by the scoped-resource selector requirements.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, match_expressions: List["ScopedResourceSelectorRequirement"] = None
    ):
        super().__init__()
        self.__match_expressions = (
            match_expressions if match_expressions is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        match_expressions = self.match_expressions()
        check_type(
            "match_expressions",
            match_expressions,
            Optional[List["ScopedResourceSelectorRequirement"]],
        )
        if match_expressions:  # omit empty
            v["matchExpressions"] = match_expressions
        return v

    def match_expressions(self) -> Optional[List["ScopedResourceSelectorRequirement"]]:
        """
        A list of scope selector requirements by scope of the resources.
        """
        return self.__match_expressions


class ResourceQuotaSpec(types.Object):
    """
    ResourceQuotaSpec defines the desired hard limits to enforce for Quota.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        hard: Dict[ResourceName, "resource.Quantity"] = None,
        scopes: List[ResourceQuotaScope] = None,
        scope_selector: "ScopeSelector" = None,
    ):
        super().__init__()
        self.__hard = hard if hard is not None else {}
        self.__scopes = scopes if scopes is not None else []
        self.__scope_selector = scope_selector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        hard = self.hard()
        check_type("hard", hard, Optional[Dict[ResourceName, "resource.Quantity"]])
        if hard:  # omit empty
            v["hard"] = hard
        scopes = self.scopes()
        check_type("scopes", scopes, Optional[List[ResourceQuotaScope]])
        if scopes:  # omit empty
            v["scopes"] = scopes
        scope_selector = self.scope_selector()
        check_type("scope_selector", scope_selector, Optional["ScopeSelector"])
        if scope_selector is not None:  # omit empty
            v["scopeSelector"] = scope_selector
        return v

    def hard(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        """
        hard is the set of desired hard limits for each named resource.
        More info: https://kubernetes.io/docs/concepts/policy/resource-quotas/
        """
        return self.__hard

    def scopes(self) -> Optional[List[ResourceQuotaScope]]:
        """
        A collection of filters that must match each object tracked by a quota.
        If not specified, the quota matches all objects.
        """
        return self.__scopes

    def scope_selector(self) -> Optional["ScopeSelector"]:
        """
        scopeSelector is also a collection of filters like scopes that must match each object tracked by a quota
        but expressed using ScopeSelectorOperator in combination with possible values.
        For a resource to match, both scopes AND scopeSelector (if specified in spec), must be matched.
        """
        return self.__scope_selector


class ResourceQuota(base.TypedObject, base.NamespacedMetadataObject):
    """
    ResourceQuota sets aggregate quota restrictions enforced per namespace
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ResourceQuotaSpec" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="ResourceQuota",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ResourceQuotaSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["ResourceQuotaSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["ResourceQuotaSpec"]:
        """
        Spec defines the desired quota.
        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class Secret(base.TypedObject, base.NamespacedMetadataObject):
    """
    Secret holds secret data of a certain type. The total bytes of the values in
    the Data field must be less than MaxSecretSize bytes.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        data: Dict[str, bytes] = None,
        string_data: Dict[str, str] = None,
        type: SecretType = SecretType["Opaque"],
    ):
        super().__init__(
            api_version="v1",
            kind="Secret",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__data = data if data is not None else {}
        self.__string_data = string_data if string_data is not None else {}
        self.__type = type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        data = self.data()
        check_type("data", data, Optional[Dict[str, bytes]])
        if data:  # omit empty
            v["data"] = data
        string_data = self.string_data()
        check_type("string_data", string_data, Optional[Dict[str, str]])
        if string_data:  # omit empty
            v["stringData"] = string_data
        type = self.type()
        check_type("type", type, Optional[SecretType])
        if type:  # omit empty
            v["type"] = type
        return v

    def data(self) -> Optional[Dict[str, bytes]]:
        """
        Data contains the secret data. Each key must consist of alphanumeric
        characters, '-', '_' or '.'. The serialized form of the secret data is a
        base64 encoded string, representing the arbitrary (possibly non-string)
        data value here. Described in https://tools.ietf.org/html/rfc4648#section-4
        """
        return self.__data

    def string_data(self) -> Optional[Dict[str, str]]:
        """
        stringData allows specifying non-binary secret data in string form.
        It is provided as a write-only convenience method.
        All keys and values are merged into the data field on write, overwriting any existing values.
        It is never output when reading from the API.
        """
        return self.__string_data

    def type(self) -> Optional[SecretType]:
        """
        Used to facilitate programmatic handling of secret data.
        """
        return self.__type


class SerializedReference(base.TypedObject):
    """
    SerializedReference is a reference to serialized object.
    """

    @context.scoped
    @typechecked
    def __init__(self, reference: "ObjectReference" = None):
        super().__init__(api_version="v1", kind="SerializedReference")
        self.__reference = reference if reference is not None else ObjectReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        reference = self.reference()
        check_type("reference", reference, Optional["ObjectReference"])
        v["reference"] = reference
        return v

    def reference(self) -> Optional["ObjectReference"]:
        """
        The reference to an object in the system.
        """
        return self.__reference


class ServicePort(types.Object):
    """
    ServicePort contains information on service's port.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        protocol: Protocol = None,
        port: int = 0,
        target_port: Union[int, str] = None,
        node_port: int = None,
    ):
        super().__init__()
        self.__name = name
        self.__protocol = protocol
        self.__port = port
        self.__target_port = target_port if target_port is not None else 0
        self.__node_port = node_port

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        protocol = self.protocol()
        check_type("protocol", protocol, Optional[Protocol])
        if protocol:  # omit empty
            v["protocol"] = protocol
        port = self.port()
        check_type("port", port, int)
        v["port"] = port
        target_port = self.target_port()
        check_type("target_port", target_port, Optional[Union[int, str]])
        v["targetPort"] = target_port
        node_port = self.node_port()
        check_type("node_port", node_port, Optional[int])
        if node_port:  # omit empty
            v["nodePort"] = node_port
        return v

    def name(self) -> Optional[str]:
        """
        The name of this port within the service. This must be a DNS_LABEL.
        All ports within a ServiceSpec must have unique names. When considering
        the endpoints for a Service, this must match the 'name' field in the
        EndpointPort.
        Optional if only one ServicePort is defined on this service.
        """
        return self.__name

    def protocol(self) -> Optional[Protocol]:
        """
        The IP protocol for this port. Supports "TCP", "UDP", and "SCTP".
        Default is TCP.
        """
        return self.__protocol

    def port(self) -> int:
        """
        The port that will be exposed by this service.
        """
        return self.__port

    def target_port(self) -> Optional[Union[int, str]]:
        """
        Number or name of the port to access on the pods targeted by the service.
        Number must be in the range 1 to 65535. Name must be an IANA_SVC_NAME.
        If this is a string, it will be looked up as a named port in the
        target Pod's container ports. If this is not specified, the value
        of the 'port' field is used (an identity map).
        This field is ignored for services with clusterIP=None, and should be
        omitted or set equal to the 'port' field.
        More info: https://kubernetes.io/docs/concepts/services-networking/service/#defining-a-service
        """
        return self.__target_port

    def node_port(self) -> Optional[int]:
        """
        The port on each node on which this service is exposed when type=NodePort or LoadBalancer.
        Usually assigned by the system. If specified, it will be allocated to the service
        if unused or else creation of the service will fail.
        Default is to auto-allocate a port if the ServiceType of this Service requires one.
        More info: https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport
        """
        return self.__node_port


class SessionAffinityConfig(types.Object):
    """
    SessionAffinityConfig represents the configurations of session affinity.
    """

    @context.scoped
    @typechecked
    def __init__(self, client_ip: "ClientIPConfig" = None):
        super().__init__()
        self.__client_ip = client_ip

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_ip = self.client_ip()
        check_type("client_ip", client_ip, Optional["ClientIPConfig"])
        if client_ip is not None:  # omit empty
            v["clientIP"] = client_ip
        return v

    def client_ip(self) -> Optional["ClientIPConfig"]:
        """
        clientIP contains the configurations of Client IP based session affinity.
        """
        return self.__client_ip


class ServiceSpec(types.Object):
    """
    ServiceSpec describes the attributes that a user creates on a service.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ports: List["ServicePort"] = None,
        selector: Dict[str, str] = None,
        cluster_ip: str = None,
        type: ServiceType = ServiceType["ClusterIP"],
        external_ips: List[str] = None,
        session_affinity: ServiceAffinity = ServiceAffinity["None"],
        load_balancer_ip: str = None,
        load_balancer_source_ranges: List[str] = None,
        external_name: str = None,
        external_traffic_policy: ServiceExternalTrafficPolicyType = None,
        health_check_node_port: int = None,
        publish_not_ready_addresses: bool = None,
        session_affinity_config: "SessionAffinityConfig" = None,
        ip_family: IPFamily = None,
        topology_keys: List[str] = None,
    ):
        super().__init__()
        self.__ports = ports if ports is not None else []
        self.__selector = selector if selector is not None else {}
        self.__cluster_ip = cluster_ip
        self.__type = type
        self.__external_ips = external_ips if external_ips is not None else []
        self.__session_affinity = session_affinity
        self.__load_balancer_ip = load_balancer_ip
        self.__load_balancer_source_ranges = (
            load_balancer_source_ranges
            if load_balancer_source_ranges is not None
            else []
        )
        self.__external_name = external_name
        self.__external_traffic_policy = external_traffic_policy
        self.__health_check_node_port = health_check_node_port
        self.__publish_not_ready_addresses = publish_not_ready_addresses
        self.__session_affinity_config = session_affinity_config
        self.__ip_family = ip_family
        self.__topology_keys = topology_keys if topology_keys is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ports = self.ports()
        check_type("ports", ports, Optional[List["ServicePort"]])
        if ports:  # omit empty
            v["ports"] = ports
        selector = self.selector()
        check_type("selector", selector, Optional[Dict[str, str]])
        if selector:  # omit empty
            v["selector"] = selector
        cluster_ip = self.cluster_ip()
        check_type("cluster_ip", cluster_ip, Optional[str])
        if cluster_ip:  # omit empty
            v["clusterIP"] = cluster_ip
        type = self.type()
        check_type("type", type, Optional[ServiceType])
        if type:  # omit empty
            v["type"] = type
        external_ips = self.external_ips()
        check_type("external_ips", external_ips, Optional[List[str]])
        if external_ips:  # omit empty
            v["externalIPs"] = external_ips
        session_affinity = self.session_affinity()
        check_type("session_affinity", session_affinity, Optional[ServiceAffinity])
        if session_affinity:  # omit empty
            v["sessionAffinity"] = session_affinity
        load_balancer_ip = self.load_balancer_ip()
        check_type("load_balancer_ip", load_balancer_ip, Optional[str])
        if load_balancer_ip:  # omit empty
            v["loadBalancerIP"] = load_balancer_ip
        load_balancer_source_ranges = self.load_balancer_source_ranges()
        check_type(
            "load_balancer_source_ranges",
            load_balancer_source_ranges,
            Optional[List[str]],
        )
        if load_balancer_source_ranges:  # omit empty
            v["loadBalancerSourceRanges"] = load_balancer_source_ranges
        external_name = self.external_name()
        check_type("external_name", external_name, Optional[str])
        if external_name:  # omit empty
            v["externalName"] = external_name
        external_traffic_policy = self.external_traffic_policy()
        check_type(
            "external_traffic_policy",
            external_traffic_policy,
            Optional[ServiceExternalTrafficPolicyType],
        )
        if external_traffic_policy:  # omit empty
            v["externalTrafficPolicy"] = external_traffic_policy
        health_check_node_port = self.health_check_node_port()
        check_type("health_check_node_port", health_check_node_port, Optional[int])
        if health_check_node_port:  # omit empty
            v["healthCheckNodePort"] = health_check_node_port
        publish_not_ready_addresses = self.publish_not_ready_addresses()
        check_type(
            "publish_not_ready_addresses", publish_not_ready_addresses, Optional[bool]
        )
        if publish_not_ready_addresses:  # omit empty
            v["publishNotReadyAddresses"] = publish_not_ready_addresses
        session_affinity_config = self.session_affinity_config()
        check_type(
            "session_affinity_config",
            session_affinity_config,
            Optional["SessionAffinityConfig"],
        )
        if session_affinity_config is not None:  # omit empty
            v["sessionAffinityConfig"] = session_affinity_config
        ip_family = self.ip_family()
        check_type("ip_family", ip_family, Optional[IPFamily])
        if ip_family is not None:  # omit empty
            v["ipFamily"] = ip_family
        topology_keys = self.topology_keys()
        check_type("topology_keys", topology_keys, Optional[List[str]])
        if topology_keys:  # omit empty
            v["topologyKeys"] = topology_keys
        return v

    def ports(self) -> Optional[List["ServicePort"]]:
        """
        The list of ports that are exposed by this service.
        More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
        +listType=map
        +listMapKey=port
        +listMapKey=protocol
        """
        return self.__ports

    def selector(self) -> Optional[Dict[str, str]]:
        """
        Route service traffic to pods with label keys and values matching this
        selector. If empty or not present, the service is assumed to have an
        external process managing its endpoints, which Kubernetes will not
        modify. Only applies to types ClusterIP, NodePort, and LoadBalancer.
        Ignored if type is ExternalName.
        More info: https://kubernetes.io/docs/concepts/services-networking/service/
        """
        return self.__selector

    def cluster_ip(self) -> Optional[str]:
        """
        clusterIP is the IP address of the service and is usually assigned
        randomly by the master. If an address is specified manually and is not in
        use by others, it will be allocated to the service; otherwise, creation
        of the service will fail. This field can not be changed through updates.
        Valid values are "None", empty string (""), or a valid IP address. "None"
        can be specified for headless services when proxying is not required.
        Only applies to types ClusterIP, NodePort, and LoadBalancer. Ignored if
        type is ExternalName.
        More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
        """
        return self.__cluster_ip

    def type(self) -> Optional[ServiceType]:
        """
        type determines how the Service is exposed. Defaults to ClusterIP. Valid
        options are ExternalName, ClusterIP, NodePort, and LoadBalancer.
        "ExternalName" maps to the specified externalName.
        "ClusterIP" allocates a cluster-internal IP address for load-balancing to
        endpoints. Endpoints are determined by the selector or if that is not
        specified, by manual construction of an Endpoints object. If clusterIP is
        "None", no virtual IP is allocated and the endpoints are published as a
        set of endpoints rather than a stable IP.
        "NodePort" builds on ClusterIP and allocates a port on every node which
        routes to the clusterIP.
        "LoadBalancer" builds on NodePort and creates an
        external load-balancer (if supported in the current cloud) which routes
        to the clusterIP.
        More info: https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types
        """
        return self.__type

    def external_ips(self) -> Optional[List[str]]:
        """
        externalIPs is a list of IP addresses for which nodes in the cluster
        will also accept traffic for this service.  These IPs are not managed by
        Kubernetes.  The user is responsible for ensuring that traffic arrives
        at a node with this IP.  A common example is external load-balancers
        that are not part of the Kubernetes system.
        """
        return self.__external_ips

    def session_affinity(self) -> Optional[ServiceAffinity]:
        """
        Supports "ClientIP" and "None". Used to maintain session affinity.
        Enable client IP based session affinity.
        Must be ClientIP or None.
        Defaults to None.
        More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
        """
        return self.__session_affinity

    def load_balancer_ip(self) -> Optional[str]:
        """
        Only applies to Service Type: LoadBalancer
        LoadBalancer will get created with the IP specified in this field.
        This feature depends on whether the underlying cloud-provider supports specifying
        the loadBalancerIP when a load balancer is created.
        This field will be ignored if the cloud-provider does not support the feature.
        """
        return self.__load_balancer_ip

    def load_balancer_source_ranges(self) -> Optional[List[str]]:
        """
        If specified and supported by the platform, this will restrict traffic through the cloud-provider
        load-balancer will be restricted to the specified client IPs. This field will be ignored if the
        cloud-provider does not support the feature."
        More info: https://kubernetes.io/docs/tasks/access-application-cluster/configure-cloud-provider-firewall/
        """
        return self.__load_balancer_source_ranges

    def external_name(self) -> Optional[str]:
        """
        externalName is the external reference that kubedns or equivalent will
        return as a CNAME record for this service. No proxying will be involved.
        Must be a valid RFC-1123 hostname (https://tools.ietf.org/html/rfc1123)
        and requires Type to be ExternalName.
        """
        return self.__external_name

    def external_traffic_policy(self) -> Optional[ServiceExternalTrafficPolicyType]:
        """
        externalTrafficPolicy denotes if this Service desires to route external
        traffic to node-local or cluster-wide endpoints. "Local" preserves the
        client source IP and avoids a second hop for LoadBalancer and Nodeport
        type services, but risks potentially imbalanced traffic spreading.
        "Cluster" obscures the client source IP and may cause a second hop to
        another node, but should have good overall load-spreading.
        """
        return self.__external_traffic_policy

    def health_check_node_port(self) -> Optional[int]:
        """
        healthCheckNodePort specifies the healthcheck nodePort for the service.
        If not specified, HealthCheckNodePort is created by the service api
        backend with the allocated nodePort. Will use user-specified nodePort value
        if specified by the client. Only effects when Type is set to LoadBalancer
        and ExternalTrafficPolicy is set to Local.
        """
        return self.__health_check_node_port

    def publish_not_ready_addresses(self) -> Optional[bool]:
        """
        publishNotReadyAddresses, when set to true, indicates that DNS implementations
        must publish the notReadyAddresses of subsets for the Endpoints associated with
        the Service. The default value is false.
        The primary use case for setting this field is to use a StatefulSet's Headless Service
        to propagate SRV records for its Pods without respect to their readiness for purpose
        of peer discovery.
        """
        return self.__publish_not_ready_addresses

    def session_affinity_config(self) -> Optional["SessionAffinityConfig"]:
        """
        sessionAffinityConfig contains the configurations of session affinity.
        """
        return self.__session_affinity_config

    def ip_family(self) -> Optional[IPFamily]:
        """
        ipFamily specifies whether this Service has a preference for a particular IP family (e.g. IPv4 vs.
        IPv6).  If a specific IP family is requested, the clusterIP field will be allocated from that family, if it is
        available in the cluster.  If no IP family is requested, the cluster's primary IP family will be used.
        Other IP fields (loadBalancerIP, loadBalancerSourceRanges, externalIPs) and controllers which
        allocate external load-balancers should use the same IP family.  Endpoints for this Service will be of
        this family.  This field is immutable after creation. Assigning a ServiceIPFamily not available in the
        cluster (e.g. IPv6 in IPv4 only cluster) is an error condition and will fail during clusterIP assignment.
        """
        return self.__ip_family

    def topology_keys(self) -> Optional[List[str]]:
        """
        topologyKeys is a preference-order list of topology keys which
        implementations of services should use to preferentially sort endpoints
        when accessing this Service, it can not be used at the same time as
        externalTrafficPolicy=Local.
        Topology keys must be valid label keys and at most 16 keys may be specified.
        Endpoints are chosen based on the first topology key with available backends.
        If this field is specified and all entries have no backends that match
        the topology of the client, the service has no backends for that client
        and connections should fail.
        The special value "*" may be used to mean "any topology". This catch-all
        value, if used, only makes sense as the last value in the list.
        If this is not specified or empty, no topology constraints will be applied.
        """
        return self.__topology_keys


class Service(base.TypedObject, base.NamespacedMetadataObject):
    """
    Service is a named abstraction of software service (for example, mysql) consisting of local port
    (for example 3306) that the proxy listens on, and the selector that determines which pods
    will answer requests sent through the proxy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ServiceSpec" = None,
    ):
        super().__init__(
            api_version="v1",
            kind="Service",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ServiceSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["ServiceSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["ServiceSpec"]:
        """
        Spec defines the behavior of a service.
        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class ServiceAccount(base.TypedObject, base.NamespacedMetadataObject):
    """
    ServiceAccount binds together:
    * a name, understood by users, and perhaps by peripheral systems, for an identity
    * a principal that can be authenticated and authorized
    * a set of secrets
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        secrets: List["ObjectReference"] = None,
        image_pull_secrets: List["LocalObjectReference"] = None,
        automount_service_account_token: bool = None,
    ):
        super().__init__(
            api_version="v1",
            kind="ServiceAccount",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__secrets = secrets if secrets is not None else []
        self.__image_pull_secrets = (
            image_pull_secrets if image_pull_secrets is not None else []
        )
        self.__automount_service_account_token = automount_service_account_token

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secrets = self.secrets()
        check_type("secrets", secrets, Optional[List["ObjectReference"]])
        if secrets:  # omit empty
            v["secrets"] = secrets
        image_pull_secrets = self.image_pull_secrets()
        check_type(
            "image_pull_secrets",
            image_pull_secrets,
            Optional[List["LocalObjectReference"]],
        )
        if image_pull_secrets:  # omit empty
            v["imagePullSecrets"] = image_pull_secrets
        automount_service_account_token = self.automount_service_account_token()
        check_type(
            "automount_service_account_token",
            automount_service_account_token,
            Optional[bool],
        )
        if automount_service_account_token is not None:  # omit empty
            v["automountServiceAccountToken"] = automount_service_account_token
        return v

    def secrets(self) -> Optional[List["ObjectReference"]]:
        """
        Secrets is the list of secrets allowed to be used by pods running using this ServiceAccount.
        More info: https://kubernetes.io/docs/concepts/configuration/secret
        """
        return self.__secrets

    def image_pull_secrets(self) -> Optional[List["LocalObjectReference"]]:
        """
        ImagePullSecrets is a list of references to secrets in the same namespace to use for pulling any images
        in pods that reference this ServiceAccount. ImagePullSecrets are distinct from Secrets because Secrets
        can be mounted in the pod, but ImagePullSecrets are only accessed by the kubelet.
        More info: https://kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod
        """
        return self.__image_pull_secrets

    def automount_service_account_token(self) -> Optional[bool]:
        """
        AutomountServiceAccountToken indicates whether pods running as this service account should have an API token automatically mounted.
        Can be overridden at the pod level.
        """
        return self.__automount_service_account_token


class ServiceProxyOptions(base.TypedObject):
    """
    ServiceProxyOptions is the query options to a Service's proxy call.
    """

    @context.scoped
    @typechecked
    def __init__(self, path: str = None):
        super().__init__(api_version="v1", kind="ServiceProxyOptions")
        self.__path = path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        return v

    def path(self) -> Optional[str]:
        """
        Path is the part of URLs that include service endpoints, suffixes,
        and parameters to use for the current proxy request to service.
        For example, the whole request URL is
        http://localhost/api/v1/namespaces/kube-system/services/elasticsearch-logging/_search?q=user:kimchy.
        Path is _search?q=user:kimchy.
        """
        return self.__path


class TopologySelectorLabelRequirement(types.Object):
    """
    A topology selector requirement is a selector that matches given label.
    This is an alpha feature and may change in the future.
    """

    @context.scoped
    @typechecked
    def __init__(self, key: str = "", values: List[str] = None):
        super().__init__()
        self.__key = key
        self.__values = values if values is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        key = self.key()
        check_type("key", key, str)
        v["key"] = key
        values = self.values()
        check_type("values", values, List[str])
        v["values"] = values
        return v

    def key(self) -> str:
        """
        The label key that the selector applies to.
        """
        return self.__key

    def values(self) -> List[str]:
        """
        An array of string values. One value must match the label to be selected.
        Each entry in Values is ORed.
        """
        return self.__values


class TopologySelectorTerm(types.Object):
    """
    A topology selector term represents the result of label queries.
    A null or empty topology selector term matches no objects.
    The requirements of them are ANDed.
    It provides a subset of functionality as NodeSelectorTerm.
    This is an alpha feature and may change in the future.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, match_label_expressions: List["TopologySelectorLabelRequirement"] = None
    ):
        super().__init__()
        self.__match_label_expressions = (
            match_label_expressions if match_label_expressions is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        match_label_expressions = self.match_label_expressions()
        check_type(
            "match_label_expressions",
            match_label_expressions,
            Optional[List["TopologySelectorLabelRequirement"]],
        )
        if match_label_expressions:  # omit empty
            v["matchLabelExpressions"] = match_label_expressions
        return v

    def match_label_expressions(
        self
    ) -> Optional[List["TopologySelectorLabelRequirement"]]:
        """
        A list of topology selector requirements by labels.
        """
        return self.__match_label_expressions
