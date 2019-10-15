# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional, Union

from k8s import base
from k8s.apimachinery import resource
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import typechecked


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
    "ConditionStatus", {"False": "False", "True": "True", "Unknown": "Unknown"}
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


# Represents a Persistent Disk resource in AWS.
#
# An AWS EBS disk must exist before mounting to a container. The disk
# must also be in the same AWS zone as the kubelet. An AWS EBS disk
# can only be mounted as read/write once. AWS EBS volumes support
# ownership management and SELinux relabeling.
class AWSElasticBlockStoreVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        volumeID: str = "",
        fsType: str = None,
        partition: int = None,
        readOnly: bool = None,
    ):
        super().__init__(**{})
        self.__volumeID = volumeID
        self.__fsType = fsType
        self.__partition = partition
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["volumeID"] = self.volumeID()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        partition = self.partition()
        if partition:  # omit empty
            v["partition"] = partition
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # Unique ID of the persistent disk resource in AWS (Amazon EBS volume).
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#awselasticblockstore
    @typechecked
    def volumeID(self) -> str:
        return self.__volumeID

    # Filesystem type of the volume that you want to mount.
    # Tip: Ensure that the filesystem type is supported by the host operating system.
    # Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#awselasticblockstore
    # TODO: how do we prevent errors in the filesystem from compromising the machine
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # The partition in the volume that you want to mount.
    # If omitted, the default is to mount by volume name.
    # Examples: For volume /dev/sda1, you specify the partition as "1".
    # Similarly, the volume partition for /dev/sda is "0" (or you can leave the property empty).
    @typechecked
    def partition(self) -> Optional[int]:
        return self.__partition

    # Specify "true" to force and set the ReadOnly property in VolumeMounts to "true".
    # If omitted, the default is "false".
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#awselasticblockstore
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# A node selector requirement is a selector that contains values, a key, and an operator
# that relates the key and values.
class NodeSelectorRequirement(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        key: str = "",
        operator: NodeSelectorOperator = None,
        values: List[str] = None,
    ):
        super().__init__(**{})
        self.__key = key
        self.__operator = operator
        self.__values = values if values is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["key"] = self.key()
        v["operator"] = self.operator()
        values = self.values()
        if values:  # omit empty
            v["values"] = values
        return v

    # The label key that the selector applies to.
    @typechecked
    def key(self) -> str:
        return self.__key

    # Represents a key's relationship to a set of values.
    # Valid operators are In, NotIn, Exists, DoesNotExist. Gt, and Lt.
    @typechecked
    def operator(self) -> NodeSelectorOperator:
        return self.__operator

    # An array of string values. If the operator is In or NotIn,
    # the values array must be non-empty. If the operator is Exists or DoesNotExist,
    # the values array must be empty. If the operator is Gt or Lt, the values
    # array must have a single element, which will be interpreted as an integer.
    # This array is replaced during a strategic merge patch.
    @typechecked
    def values(self) -> Optional[List[str]]:
        return self.__values


# A null or empty node selector term matches no objects. The requirements of
# them are ANDed.
# The TopologySelectorTerm type implements a subset of the NodeSelectorTerm.
class NodeSelectorTerm(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        matchExpressions: List[NodeSelectorRequirement] = None,
        matchFields: List[NodeSelectorRequirement] = None,
    ):
        super().__init__(**{})
        self.__matchExpressions = (
            matchExpressions if matchExpressions is not None else []
        )
        self.__matchFields = matchFields if matchFields is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        matchExpressions = self.matchExpressions()
        if matchExpressions:  # omit empty
            v["matchExpressions"] = matchExpressions
        matchFields = self.matchFields()
        if matchFields:  # omit empty
            v["matchFields"] = matchFields
        return v

    # A list of node selector requirements by node's labels.
    @typechecked
    def matchExpressions(self) -> Optional[List[NodeSelectorRequirement]]:
        return self.__matchExpressions

    # A list of node selector requirements by node's fields.
    @typechecked
    def matchFields(self) -> Optional[List[NodeSelectorRequirement]]:
        return self.__matchFields


# A node selector represents the union of the results of one or more label queries
# over a set of nodes; that is, it represents the OR of the selectors represented
# by the node selector terms.
class NodeSelector(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, nodeSelectorTerms: List[NodeSelectorTerm] = None):
        super().__init__(**{})
        self.__nodeSelectorTerms = (
            nodeSelectorTerms if nodeSelectorTerms is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["nodeSelectorTerms"] = self.nodeSelectorTerms()
        return v

    # Required. A list of node selector terms. The terms are ORed.
    @typechecked
    def nodeSelectorTerms(self) -> List[NodeSelectorTerm]:
        return self.__nodeSelectorTerms


# An empty preferred scheduling term matches all objects with implicit weight 0
# (i.e. it's a no-op). A null preferred scheduling term matches no objects (i.e. is also a no-op).
class PreferredSchedulingTerm(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, weight: int = 0, preference: NodeSelectorTerm = None):
        super().__init__(**{})
        self.__weight = weight
        self.__preference = preference if preference is not None else NodeSelectorTerm()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["weight"] = self.weight()
        v["preference"] = self.preference()
        return v

    # Weight associated with matching the corresponding nodeSelectorTerm, in the range 1-100.
    @typechecked
    def weight(self) -> int:
        return self.__weight

    # A node selector term, associated with the corresponding weight.
    @typechecked
    def preference(self) -> NodeSelectorTerm:
        return self.__preference


# Node affinity is a group of node affinity scheduling rules.
class NodeAffinity(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        requiredDuringSchedulingIgnoredDuringExecution: NodeSelector = None,
        preferredDuringSchedulingIgnoredDuringExecution: List[
            PreferredSchedulingTerm
        ] = None,
    ):
        super().__init__(**{})
        self.__requiredDuringSchedulingIgnoredDuringExecution = (
            requiredDuringSchedulingIgnoredDuringExecution
        )
        self.__preferredDuringSchedulingIgnoredDuringExecution = (
            preferredDuringSchedulingIgnoredDuringExecution
            if preferredDuringSchedulingIgnoredDuringExecution is not None
            else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        requiredDuringSchedulingIgnoredDuringExecution = (
            self.requiredDuringSchedulingIgnoredDuringExecution()
        )
        if requiredDuringSchedulingIgnoredDuringExecution is not None:  # omit empty
            v[
                "requiredDuringSchedulingIgnoredDuringExecution"
            ] = requiredDuringSchedulingIgnoredDuringExecution
        preferredDuringSchedulingIgnoredDuringExecution = (
            self.preferredDuringSchedulingIgnoredDuringExecution()
        )
        if preferredDuringSchedulingIgnoredDuringExecution:  # omit empty
            v[
                "preferredDuringSchedulingIgnoredDuringExecution"
            ] = preferredDuringSchedulingIgnoredDuringExecution
        return v

    # If the affinity requirements specified by this field are not met at
    # scheduling time, the pod will not be scheduled onto the node.
    # If the affinity requirements specified by this field cease to be met
    # at some point during pod execution (e.g. due to an update), the system
    # may or may not try to eventually evict the pod from its node.
    @typechecked
    def requiredDuringSchedulingIgnoredDuringExecution(self) -> Optional[NodeSelector]:
        return self.__requiredDuringSchedulingIgnoredDuringExecution

    # The scheduler will prefer to schedule pods to nodes that satisfy
    # the affinity expressions specified by this field, but it may choose
    # a node that violates one or more of the expressions. The node that is
    # most preferred is the one with the greatest sum of weights, i.e.
    # for each node that meets all of the scheduling requirements (resource
    # request, requiredDuringScheduling affinity expressions, etc.),
    # compute a sum by iterating through the elements of this field and adding
    # "weight" to the sum if the node matches the corresponding matchExpressions; the
    # node(s) with the highest sum are the most preferred.
    @typechecked
    def preferredDuringSchedulingIgnoredDuringExecution(
        self
    ) -> Optional[List[PreferredSchedulingTerm]]:
        return self.__preferredDuringSchedulingIgnoredDuringExecution


# Defines a set of pods (namely those matching the labelSelector
# relative to the given namespace(s)) that this pod should be
# co-located (affinity) or not co-located (anti-affinity) with,
# where co-located is defined as running on a node whose value of
# the label with key <topologyKey> matches that of any node on which
# a pod of the set of pods is running
class PodAffinityTerm(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        labelSelector: "metav1.LabelSelector" = None,
        namespaces: List[str] = None,
        topologyKey: str = "",
    ):
        super().__init__(**{})
        self.__labelSelector = labelSelector
        self.__namespaces = namespaces if namespaces is not None else []
        self.__topologyKey = topologyKey

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        labelSelector = self.labelSelector()
        if labelSelector is not None:  # omit empty
            v["labelSelector"] = labelSelector
        namespaces = self.namespaces()
        if namespaces:  # omit empty
            v["namespaces"] = namespaces
        v["topologyKey"] = self.topologyKey()
        return v

    # A label query over a set of resources, in this case pods.
    @typechecked
    def labelSelector(self) -> Optional["metav1.LabelSelector"]:
        return self.__labelSelector

    # namespaces specifies which namespaces the labelSelector applies to (matches against);
    # null or empty list means "this pod's namespace"
    @typechecked
    def namespaces(self) -> Optional[List[str]]:
        return self.__namespaces

    # This pod should be co-located (affinity) or not co-located (anti-affinity) with the pods matching
    # the labelSelector in the specified namespaces, where co-located is defined as running on a node
    # whose value of the label with key topologyKey matches that of any node on which any of the
    # selected pods is running.
    # Empty topologyKey is not allowed.
    @typechecked
    def topologyKey(self) -> str:
        return self.__topologyKey


# The weights of all of the matched WeightedPodAffinityTerm fields are added per-node to find the most preferred node(s)
class WeightedPodAffinityTerm(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, weight: int = 0, podAffinityTerm: PodAffinityTerm = None):
        super().__init__(**{})
        self.__weight = weight
        self.__podAffinityTerm = (
            podAffinityTerm if podAffinityTerm is not None else PodAffinityTerm()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["weight"] = self.weight()
        v["podAffinityTerm"] = self.podAffinityTerm()
        return v

    # weight associated with matching the corresponding podAffinityTerm,
    # in the range 1-100.
    @typechecked
    def weight(self) -> int:
        return self.__weight

    # Required. A pod affinity term, associated with the corresponding weight.
    @typechecked
    def podAffinityTerm(self) -> PodAffinityTerm:
        return self.__podAffinityTerm


# Pod affinity is a group of inter pod affinity scheduling rules.
class PodAffinity(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        requiredDuringSchedulingIgnoredDuringExecution: List[PodAffinityTerm] = None,
        preferredDuringSchedulingIgnoredDuringExecution: List[
            WeightedPodAffinityTerm
        ] = None,
    ):
        super().__init__(**{})
        self.__requiredDuringSchedulingIgnoredDuringExecution = (
            requiredDuringSchedulingIgnoredDuringExecution
            if requiredDuringSchedulingIgnoredDuringExecution is not None
            else []
        )
        self.__preferredDuringSchedulingIgnoredDuringExecution = (
            preferredDuringSchedulingIgnoredDuringExecution
            if preferredDuringSchedulingIgnoredDuringExecution is not None
            else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        requiredDuringSchedulingIgnoredDuringExecution = (
            self.requiredDuringSchedulingIgnoredDuringExecution()
        )
        if requiredDuringSchedulingIgnoredDuringExecution:  # omit empty
            v[
                "requiredDuringSchedulingIgnoredDuringExecution"
            ] = requiredDuringSchedulingIgnoredDuringExecution
        preferredDuringSchedulingIgnoredDuringExecution = (
            self.preferredDuringSchedulingIgnoredDuringExecution()
        )
        if preferredDuringSchedulingIgnoredDuringExecution:  # omit empty
            v[
                "preferredDuringSchedulingIgnoredDuringExecution"
            ] = preferredDuringSchedulingIgnoredDuringExecution
        return v

    # If the affinity requirements specified by this field are not met at
    # scheduling time, the pod will not be scheduled onto the node.
    # If the affinity requirements specified by this field cease to be met
    # at some point during pod execution (e.g. due to a pod label update), the
    # system may or may not try to eventually evict the pod from its node.
    # When there are multiple elements, the lists of nodes corresponding to each
    # podAffinityTerm are intersected, i.e. all terms must be satisfied.
    @typechecked
    def requiredDuringSchedulingIgnoredDuringExecution(
        self
    ) -> Optional[List[PodAffinityTerm]]:
        return self.__requiredDuringSchedulingIgnoredDuringExecution

    # The scheduler will prefer to schedule pods to nodes that satisfy
    # the affinity expressions specified by this field, but it may choose
    # a node that violates one or more of the expressions. The node that is
    # most preferred is the one with the greatest sum of weights, i.e.
    # for each node that meets all of the scheduling requirements (resource
    # request, requiredDuringScheduling affinity expressions, etc.),
    # compute a sum by iterating through the elements of this field and adding
    # "weight" to the sum if the node has pods which matches the corresponding podAffinityTerm; the
    # node(s) with the highest sum are the most preferred.
    @typechecked
    def preferredDuringSchedulingIgnoredDuringExecution(
        self
    ) -> Optional[List[WeightedPodAffinityTerm]]:
        return self.__preferredDuringSchedulingIgnoredDuringExecution


# Pod anti affinity is a group of inter pod anti affinity scheduling rules.
class PodAntiAffinity(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        requiredDuringSchedulingIgnoredDuringExecution: List[PodAffinityTerm] = None,
        preferredDuringSchedulingIgnoredDuringExecution: List[
            WeightedPodAffinityTerm
        ] = None,
    ):
        super().__init__(**{})
        self.__requiredDuringSchedulingIgnoredDuringExecution = (
            requiredDuringSchedulingIgnoredDuringExecution
            if requiredDuringSchedulingIgnoredDuringExecution is not None
            else []
        )
        self.__preferredDuringSchedulingIgnoredDuringExecution = (
            preferredDuringSchedulingIgnoredDuringExecution
            if preferredDuringSchedulingIgnoredDuringExecution is not None
            else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        requiredDuringSchedulingIgnoredDuringExecution = (
            self.requiredDuringSchedulingIgnoredDuringExecution()
        )
        if requiredDuringSchedulingIgnoredDuringExecution:  # omit empty
            v[
                "requiredDuringSchedulingIgnoredDuringExecution"
            ] = requiredDuringSchedulingIgnoredDuringExecution
        preferredDuringSchedulingIgnoredDuringExecution = (
            self.preferredDuringSchedulingIgnoredDuringExecution()
        )
        if preferredDuringSchedulingIgnoredDuringExecution:  # omit empty
            v[
                "preferredDuringSchedulingIgnoredDuringExecution"
            ] = preferredDuringSchedulingIgnoredDuringExecution
        return v

    # If the anti-affinity requirements specified by this field are not met at
    # scheduling time, the pod will not be scheduled onto the node.
    # If the anti-affinity requirements specified by this field cease to be met
    # at some point during pod execution (e.g. due to a pod label update), the
    # system may or may not try to eventually evict the pod from its node.
    # When there are multiple elements, the lists of nodes corresponding to each
    # podAffinityTerm are intersected, i.e. all terms must be satisfied.
    @typechecked
    def requiredDuringSchedulingIgnoredDuringExecution(
        self
    ) -> Optional[List[PodAffinityTerm]]:
        return self.__requiredDuringSchedulingIgnoredDuringExecution

    # The scheduler will prefer to schedule pods to nodes that satisfy
    # the anti-affinity expressions specified by this field, but it may choose
    # a node that violates one or more of the expressions. The node that is
    # most preferred is the one with the greatest sum of weights, i.e.
    # for each node that meets all of the scheduling requirements (resource
    # request, requiredDuringScheduling anti-affinity expressions, etc.),
    # compute a sum by iterating through the elements of this field and adding
    # "weight" to the sum if the node has pods which matches the corresponding podAffinityTerm; the
    # node(s) with the highest sum are the most preferred.
    @typechecked
    def preferredDuringSchedulingIgnoredDuringExecution(
        self
    ) -> Optional[List[WeightedPodAffinityTerm]]:
        return self.__preferredDuringSchedulingIgnoredDuringExecution


# Affinity is a group of affinity scheduling rules.
class Affinity(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        nodeAffinity: NodeAffinity = None,
        podAffinity: PodAffinity = None,
        podAntiAffinity: PodAntiAffinity = None,
    ):
        super().__init__(**{})
        self.__nodeAffinity = nodeAffinity
        self.__podAffinity = podAffinity
        self.__podAntiAffinity = podAntiAffinity

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        nodeAffinity = self.nodeAffinity()
        if nodeAffinity is not None:  # omit empty
            v["nodeAffinity"] = nodeAffinity
        podAffinity = self.podAffinity()
        if podAffinity is not None:  # omit empty
            v["podAffinity"] = podAffinity
        podAntiAffinity = self.podAntiAffinity()
        if podAntiAffinity is not None:  # omit empty
            v["podAntiAffinity"] = podAntiAffinity
        return v

    # Describes node affinity scheduling rules for the pod.
    @typechecked
    def nodeAffinity(self) -> Optional[NodeAffinity]:
        return self.__nodeAffinity

    # Describes pod affinity scheduling rules (e.g. co-locate this pod in the same node, zone, etc. as some other pod(s)).
    @typechecked
    def podAffinity(self) -> Optional[PodAffinity]:
        return self.__podAffinity

    # Describes pod anti-affinity scheduling rules (e.g. avoid putting this pod in the same node, zone, etc. as some other pod(s)).
    @typechecked
    def podAntiAffinity(self) -> Optional[PodAntiAffinity]:
        return self.__podAntiAffinity


# AzureDisk represents an Azure Data Disk mount on the host and bind mount to the pod.
class AzureDiskVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        diskName: str = "",
        diskURI: str = "",
        cachingMode: AzureDataDiskCachingMode = None,
        fsType: str = None,
        readOnly: bool = None,
        kind: AzureDataDiskKind = None,
    ):
        super().__init__(**{})
        self.__diskName = diskName
        self.__diskURI = diskURI
        self.__cachingMode = (
            cachingMode
            if cachingMode is not None
            else AzureDataDiskCachingMode["ReadWrite"]
        )
        self.__fsType = fsType if fsType is not None else "ext4"
        self.__readOnly = readOnly
        self.__kind = kind if kind is not None else AzureDataDiskKind["Shared"]

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["diskName"] = self.diskName()
        v["diskURI"] = self.diskURI()
        cachingMode = self.cachingMode()
        if cachingMode is not None:  # omit empty
            v["cachingMode"] = cachingMode
        fsType = self.fsType()
        if fsType is not None:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly is not None:  # omit empty
            v["readOnly"] = readOnly
        kind = self.kind()
        if kind is not None:  # omit empty
            v["kind"] = kind
        return v

    # The Name of the data disk in the blob storage
    @typechecked
    def diskName(self) -> str:
        return self.__diskName

    # The URI the data disk in the blob storage
    @typechecked
    def diskURI(self) -> str:
        return self.__diskURI

    # Host Caching mode: None, Read Only, Read Write.
    @typechecked
    def cachingMode(self) -> Optional[AzureDataDiskCachingMode]:
        return self.__cachingMode

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # Expected values Shared: multiple blob disks per storage account  Dedicated: single blob disk per storage account  Managed: azure managed data disk (only in managed availability set). defaults to shared
    @typechecked
    def kind(self) -> Optional[AzureDataDiskKind]:
        return self.__kind


# AzureFile represents an Azure File Service mount on the host and bind mount to the pod.
class AzureFilePersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        secretName: str = "",
        shareName: str = "",
        readOnly: bool = None,
        secretNamespace: str = None,
    ):
        super().__init__(**{})
        self.__secretName = secretName
        self.__shareName = shareName
        self.__readOnly = readOnly
        self.__secretNamespace = secretNamespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["secretName"] = self.secretName()
        v["shareName"] = self.shareName()
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        v["secretNamespace"] = self.secretNamespace()
        return v

    # the name of secret that contains Azure Storage Account Name and Key
    @typechecked
    def secretName(self) -> str:
        return self.__secretName

    # Share Name
    @typechecked
    def shareName(self) -> str:
        return self.__shareName

    # Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # the namespace of the secret that contains Azure Storage Account Name and Key
    # default is the same as the Pod
    @typechecked
    def secretNamespace(self) -> Optional[str]:
        return self.__secretNamespace


# AzureFile represents an Azure File Service mount on the host and bind mount to the pod.
class AzureFileVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, secretName: str = "", shareName: str = "", readOnly: bool = None
    ):
        super().__init__(**{})
        self.__secretName = secretName
        self.__shareName = shareName
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["secretName"] = self.secretName()
        v["shareName"] = self.shareName()
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # the name of secret that contains Azure Storage Account Name and Key
    @typechecked
    def secretName(self) -> str:
        return self.__secretName

    # Share Name
    @typechecked
    def shareName(self) -> str:
        return self.__shareName

    # Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# ObjectReference contains enough information to let you inspect or modify the referred object.
class ObjectReference(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        kind: str = None,
        namespace: str = None,
        name: str = None,
        uid: str = None,
        apiVersion: str = None,
        resourceVersion: str = None,
        fieldPath: str = None,
    ):
        super().__init__(**{})
        self.__kind = kind
        self.__namespace = namespace
        self.__name = name
        self.__uid = uid
        self.__apiVersion = apiVersion
        self.__resourceVersion = resourceVersion
        self.__fieldPath = fieldPath

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        if kind:  # omit empty
            v["kind"] = kind
        namespace = self.namespace()
        if namespace:  # omit empty
            v["namespace"] = namespace
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        uid = self.uid()
        if uid:  # omit empty
            v["uid"] = uid
        apiVersion = self.apiVersion()
        if apiVersion:  # omit empty
            v["apiVersion"] = apiVersion
        resourceVersion = self.resourceVersion()
        if resourceVersion:  # omit empty
            v["resourceVersion"] = resourceVersion
        fieldPath = self.fieldPath()
        if fieldPath:  # omit empty
            v["fieldPath"] = fieldPath
        return v

    # Kind of the referent.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    @typechecked
    def kind(self) -> Optional[str]:
        return self.__kind

    # Namespace of the referent.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
    @typechecked
    def namespace(self) -> Optional[str]:
        return self.__namespace

    # Name of the referent.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    @typechecked
    def name(self) -> Optional[str]:
        return self.__name

    # UID of the referent.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids
    @typechecked
    def uid(self) -> Optional[str]:
        return self.__uid

    # API version of the referent.
    @typechecked
    def apiVersion(self) -> Optional[str]:
        return self.__apiVersion

    # Specific resourceVersion to which this reference is made, if any.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
    @typechecked
    def resourceVersion(self) -> Optional[str]:
        return self.__resourceVersion

    # If referring to a piece of an object instead of an entire object, this string
    # should contain a valid JSON/Go field access statement, such as desiredState.manifest.containers[2].
    # For example, if the object reference is to a container within a pod, this would take on a value like:
    # "spec.containers{name}" (where "name" refers to the name of the container that triggered
    # the event) or if no container name is specified "spec.containers[2]" (container with
    # index 2 in this pod). This syntax is chosen only to have some well-defined way of
    # referencing a part of an object.
    # TODO: this design is not final and this field is subject to change in the future.
    @typechecked
    def fieldPath(self) -> Optional[str]:
        return self.__fieldPath


# Binding ties one object to another; for example, a pod is bound to a node by a scheduler.
# Deprecated in 1.7, please use the bindings subresource of pods instead.
class Binding(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        target: ObjectReference = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "Binding",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__target = target if target is not None else ObjectReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["target"] = self.target()
        return v

    # The target object that you want to bind to the standard object.
    @typechecked
    def target(self) -> ObjectReference:
        return self.__target


# SecretReference represents a Secret Reference. It has enough information to retrieve secret
# in any namespace
class SecretReference(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = None, namespace: str = None):
        super().__init__(**{})
        self.__name = name
        self.__namespace = namespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        namespace = self.namespace()
        if namespace:  # omit empty
            v["namespace"] = namespace
        return v

    # Name is unique within a namespace to reference a secret resource.
    @typechecked
    def name(self) -> Optional[str]:
        return self.__name

    # Namespace defines the space within which the secret name must be unique.
    @typechecked
    def namespace(self) -> Optional[str]:
        return self.__namespace


# Represents storage that is managed by an external CSI volume driver (Beta feature)
class CSIPersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        driver: str = "",
        volumeHandle: str = "",
        readOnly: bool = None,
        fsType: str = None,
        volumeAttributes: Dict[str, str] = None,
        controllerPublishSecretRef: SecretReference = None,
        nodeStageSecretRef: SecretReference = None,
        nodePublishSecretRef: SecretReference = None,
        controllerExpandSecretRef: SecretReference = None,
    ):
        super().__init__(**{})
        self.__driver = driver
        self.__volumeHandle = volumeHandle
        self.__readOnly = readOnly
        self.__fsType = fsType
        self.__volumeAttributes = (
            volumeAttributes if volumeAttributes is not None else {}
        )
        self.__controllerPublishSecretRef = controllerPublishSecretRef
        self.__nodeStageSecretRef = nodeStageSecretRef
        self.__nodePublishSecretRef = nodePublishSecretRef
        self.__controllerExpandSecretRef = controllerExpandSecretRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["driver"] = self.driver()
        v["volumeHandle"] = self.volumeHandle()
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        volumeAttributes = self.volumeAttributes()
        if volumeAttributes:  # omit empty
            v["volumeAttributes"] = volumeAttributes
        controllerPublishSecretRef = self.controllerPublishSecretRef()
        if controllerPublishSecretRef is not None:  # omit empty
            v["controllerPublishSecretRef"] = controllerPublishSecretRef
        nodeStageSecretRef = self.nodeStageSecretRef()
        if nodeStageSecretRef is not None:  # omit empty
            v["nodeStageSecretRef"] = nodeStageSecretRef
        nodePublishSecretRef = self.nodePublishSecretRef()
        if nodePublishSecretRef is not None:  # omit empty
            v["nodePublishSecretRef"] = nodePublishSecretRef
        controllerExpandSecretRef = self.controllerExpandSecretRef()
        if controllerExpandSecretRef is not None:  # omit empty
            v["controllerExpandSecretRef"] = controllerExpandSecretRef
        return v

    # Driver is the name of the driver to use for this volume.
    # Required.
    @typechecked
    def driver(self) -> str:
        return self.__driver

    # VolumeHandle is the unique volume name returned by the CSI volume
    # plugin’s CreateVolume to refer to the volume on all subsequent calls.
    # Required.
    @typechecked
    def volumeHandle(self) -> str:
        return self.__volumeHandle

    # Optional: The value to pass to ControllerPublishVolumeRequest.
    # Defaults to false (read/write).
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs".
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Attributes of the volume to publish.
    @typechecked
    def volumeAttributes(self) -> Optional[Dict[str, str]]:
        return self.__volumeAttributes

    # ControllerPublishSecretRef is a reference to the secret object containing
    # sensitive information to pass to the CSI driver to complete the CSI
    # ControllerPublishVolume and ControllerUnpublishVolume calls.
    # This field is optional, and may be empty if no secret is required. If the
    # secret object contains more than one secret, all secrets are passed.
    @typechecked
    def controllerPublishSecretRef(self) -> Optional[SecretReference]:
        return self.__controllerPublishSecretRef

    # NodeStageSecretRef is a reference to the secret object containing sensitive
    # information to pass to the CSI driver to complete the CSI NodeStageVolume
    # and NodeStageVolume and NodeUnstageVolume calls.
    # This field is optional, and may be empty if no secret is required. If the
    # secret object contains more than one secret, all secrets are passed.
    @typechecked
    def nodeStageSecretRef(self) -> Optional[SecretReference]:
        return self.__nodeStageSecretRef

    # NodePublishSecretRef is a reference to the secret object containing
    # sensitive information to pass to the CSI driver to complete the CSI
    # NodePublishVolume and NodeUnpublishVolume calls.
    # This field is optional, and may be empty if no secret is required. If the
    # secret object contains more than one secret, all secrets are passed.
    @typechecked
    def nodePublishSecretRef(self) -> Optional[SecretReference]:
        return self.__nodePublishSecretRef

    # ControllerExpandSecretRef is a reference to the secret object containing
    # sensitive information to pass to the CSI driver to complete the CSI
    # ControllerExpandVolume call.
    # This is an alpha field and requires enabling ExpandCSIVolumes feature gate.
    # This field is optional, and may be empty if no secret is required. If the
    # secret object contains more than one secret, all secrets are passed.
    @typechecked
    def controllerExpandSecretRef(self) -> Optional[SecretReference]:
        return self.__controllerExpandSecretRef


# LocalObjectReference contains enough information to let you locate the
# referenced object inside the same namespace.
class LocalObjectReference(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = None):
        super().__init__(**{})
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        return v

    # Name of the referent.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    # TODO: Add other useful fields. apiVersion, kind, uid?
    @typechecked
    def name(self) -> Optional[str]:
        return self.__name


# Represents a source location of a volume to mount, managed by an external CSI driver
class CSIVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        driver: str = "",
        readOnly: bool = None,
        fsType: str = None,
        volumeAttributes: Dict[str, str] = None,
        nodePublishSecretRef: LocalObjectReference = None,
    ):
        super().__init__(**{})
        self.__driver = driver
        self.__readOnly = readOnly
        self.__fsType = fsType
        self.__volumeAttributes = (
            volumeAttributes if volumeAttributes is not None else {}
        )
        self.__nodePublishSecretRef = nodePublishSecretRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["driver"] = self.driver()
        readOnly = self.readOnly()
        if readOnly is not None:  # omit empty
            v["readOnly"] = readOnly
        fsType = self.fsType()
        if fsType is not None:  # omit empty
            v["fsType"] = fsType
        volumeAttributes = self.volumeAttributes()
        if volumeAttributes:  # omit empty
            v["volumeAttributes"] = volumeAttributes
        nodePublishSecretRef = self.nodePublishSecretRef()
        if nodePublishSecretRef is not None:  # omit empty
            v["nodePublishSecretRef"] = nodePublishSecretRef
        return v

    # Driver is the name of the CSI driver that handles this volume.
    # Consult with your admin for the correct name as registered in the cluster.
    @typechecked
    def driver(self) -> str:
        return self.__driver

    # Specifies a read-only configuration for the volume.
    # Defaults to false (read/write).
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # Filesystem type to mount. Ex. "ext4", "xfs", "ntfs".
    # If not provided, the empty value is passed to the associated CSI driver
    # which will determine the default filesystem to apply.
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # VolumeAttributes stores driver-specific properties that are passed to the CSI
    # driver. Consult your driver's documentation for supported values.
    @typechecked
    def volumeAttributes(self) -> Optional[Dict[str, str]]:
        return self.__volumeAttributes

    # NodePublishSecretRef is a reference to the secret object containing
    # sensitive information to pass to the CSI driver to complete the CSI
    # NodePublishVolume and NodeUnpublishVolume calls.
    # This field is optional, and  may be empty if no secret is required. If the
    # secret object contains more than one secret, all secret references are passed.
    @typechecked
    def nodePublishSecretRef(self) -> Optional[LocalObjectReference]:
        return self.__nodePublishSecretRef


# Adds and removes POSIX capabilities from running containers.
class Capabilities(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, add: List[Capability] = None, drop: List[Capability] = None):
        super().__init__(**{})
        self.__add = add if add is not None else []
        self.__drop = drop if drop is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        add = self.add()
        if add:  # omit empty
            v["add"] = add
        drop = self.drop()
        if drop:  # omit empty
            v["drop"] = drop
        return v

    # Added capabilities
    @typechecked
    def add(self) -> Optional[List[Capability]]:
        return self.__add

    # Removed capabilities
    @typechecked
    def drop(self) -> Optional[List[Capability]]:
        return self.__drop


# Represents a Ceph Filesystem mount that lasts the lifetime of a pod
# Cephfs volumes do not support ownership management or SELinux relabeling.
class CephFSPersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        monitors: List[str] = None,
        path: str = None,
        user: str = None,
        secretFile: str = None,
        secretRef: SecretReference = None,
        readOnly: bool = None,
    ):
        super().__init__(**{})
        self.__monitors = monitors if monitors is not None else []
        self.__path = path
        self.__user = user
        self.__secretFile = secretFile
        self.__secretRef = secretRef
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["monitors"] = self.monitors()
        path = self.path()
        if path:  # omit empty
            v["path"] = path
        user = self.user()
        if user:  # omit empty
            v["user"] = user
        secretFile = self.secretFile()
        if secretFile:  # omit empty
            v["secretFile"] = secretFile
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # Required: Monitors is a collection of Ceph monitors
    # More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
    @typechecked
    def monitors(self) -> List[str]:
        return self.__monitors

    # Optional: Used as the mounted root, rather than the full Ceph tree, default is /
    @typechecked
    def path(self) -> Optional[str]:
        return self.__path

    # Optional: User is the rados user name, default is admin
    # More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
    @typechecked
    def user(self) -> Optional[str]:
        return self.__user

    # Optional: SecretFile is the path to key ring for User, default is /etc/ceph/user.secret
    # More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
    @typechecked
    def secretFile(self) -> Optional[str]:
        return self.__secretFile

    # Optional: SecretRef is reference to the authentication secret for User, default is empty.
    # More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
    @typechecked
    def secretRef(self) -> Optional[SecretReference]:
        return self.__secretRef

    # Optional: Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    # More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# Represents a Ceph Filesystem mount that lasts the lifetime of a pod
# Cephfs volumes do not support ownership management or SELinux relabeling.
class CephFSVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        monitors: List[str] = None,
        path: str = None,
        user: str = None,
        secretFile: str = None,
        secretRef: LocalObjectReference = None,
        readOnly: bool = None,
    ):
        super().__init__(**{})
        self.__monitors = monitors if monitors is not None else []
        self.__path = path
        self.__user = user
        self.__secretFile = secretFile
        self.__secretRef = secretRef
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["monitors"] = self.monitors()
        path = self.path()
        if path:  # omit empty
            v["path"] = path
        user = self.user()
        if user:  # omit empty
            v["user"] = user
        secretFile = self.secretFile()
        if secretFile:  # omit empty
            v["secretFile"] = secretFile
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # Required: Monitors is a collection of Ceph monitors
    # More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
    @typechecked
    def monitors(self) -> List[str]:
        return self.__monitors

    # Optional: Used as the mounted root, rather than the full Ceph tree, default is /
    @typechecked
    def path(self) -> Optional[str]:
        return self.__path

    # Optional: User is the rados user name, default is admin
    # More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
    @typechecked
    def user(self) -> Optional[str]:
        return self.__user

    # Optional: SecretFile is the path to key ring for User, default is /etc/ceph/user.secret
    # More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
    @typechecked
    def secretFile(self) -> Optional[str]:
        return self.__secretFile

    # Optional: SecretRef is reference to the authentication secret for User, default is empty.
    # More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
    @typechecked
    def secretRef(self) -> Optional[LocalObjectReference]:
        return self.__secretRef

    # Optional: Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    # More info: https://examples.k8s.io/volumes/cephfs/README.md#how-to-use-it
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# Represents a cinder volume resource in Openstack.
# A Cinder volume must exist before mounting to a container.
# The volume must also be in the same region as the kubelet.
# Cinder volumes support ownership management and SELinux relabeling.
class CinderPersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        volumeID: str = "",
        fsType: str = None,
        readOnly: bool = None,
        secretRef: SecretReference = None,
    ):
        super().__init__(**{})
        self.__volumeID = volumeID
        self.__fsType = fsType
        self.__readOnly = readOnly
        self.__secretRef = secretRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["volumeID"] = self.volumeID()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        return v

    # volume id used to identify the volume in cinder.
    # More info: https://examples.k8s.io/mysql-cinder-pd/README.md
    @typechecked
    def volumeID(self) -> str:
        return self.__volumeID

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    # More info: https://examples.k8s.io/mysql-cinder-pd/README.md
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Optional: Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    # More info: https://examples.k8s.io/mysql-cinder-pd/README.md
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # Optional: points to a secret object containing parameters used to connect
    # to OpenStack.
    @typechecked
    def secretRef(self) -> Optional[SecretReference]:
        return self.__secretRef


# Represents a cinder volume resource in Openstack.
# A Cinder volume must exist before mounting to a container.
# The volume must also be in the same region as the kubelet.
# Cinder volumes support ownership management and SELinux relabeling.
class CinderVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        volumeID: str = "",
        fsType: str = None,
        readOnly: bool = None,
        secretRef: LocalObjectReference = None,
    ):
        super().__init__(**{})
        self.__volumeID = volumeID
        self.__fsType = fsType
        self.__readOnly = readOnly
        self.__secretRef = secretRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["volumeID"] = self.volumeID()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        return v

    # volume id used to identify the volume in cinder.
    # More info: https://examples.k8s.io/mysql-cinder-pd/README.md
    @typechecked
    def volumeID(self) -> str:
        return self.__volumeID

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    # More info: https://examples.k8s.io/mysql-cinder-pd/README.md
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Optional: Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    # More info: https://examples.k8s.io/mysql-cinder-pd/README.md
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # Optional: points to a secret object containing parameters used to connect
    # to OpenStack.
    @typechecked
    def secretRef(self) -> Optional[LocalObjectReference]:
        return self.__secretRef


# ClientIPConfig represents the configurations of Client IP based session affinity.
class ClientIPConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, timeoutSeconds: int = None):
        super().__init__(**{})
        self.__timeoutSeconds = timeoutSeconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        timeoutSeconds = self.timeoutSeconds()
        if timeoutSeconds is not None:  # omit empty
            v["timeoutSeconds"] = timeoutSeconds
        return v

    # timeoutSeconds specifies the seconds of ClientIP type session sticky time.
    # The value must be >0 && <=86400(for 1 day) if ServiceAffinity == "ClientIP".
    # Default value is 10800(for 3 hours).
    @typechecked
    def timeoutSeconds(self) -> Optional[int]:
        return self.__timeoutSeconds


# Information about the condition of a component.
class ComponentCondition(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        type: ComponentConditionType = None,
        status: ConditionStatus = None,
        message: str = None,
        error: str = None,
    ):
        super().__init__(**{})
        self.__type = type
        self.__status = status
        self.__message = message
        self.__error = error

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["type"] = self.type()
        v["status"] = self.status()
        message = self.message()
        if message:  # omit empty
            v["message"] = message
        error = self.error()
        if error:  # omit empty
            v["error"] = error
        return v

    # Type of condition for a component.
    # Valid value: "Healthy"
    @typechecked
    def type(self) -> ComponentConditionType:
        return self.__type

    # Status of the condition for a component.
    # Valid values for "Healthy": "True", "False", or "Unknown".
    @typechecked
    def status(self) -> ConditionStatus:
        return self.__status

    # Message about the condition for a component.
    # For example, information about a health check.
    @typechecked
    def message(self) -> Optional[str]:
        return self.__message

    # Condition error code for a component.
    # For example, a health check error code.
    @typechecked
    def error(self) -> Optional[str]:
        return self.__error


# ComponentStatus (and ComponentStatusList) holds the cluster validation info.
class ComponentStatus(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        conditions: List[ComponentCondition] = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "ComponentStatus",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__conditions = conditions if conditions is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        conditions = self.conditions()
        if conditions:  # omit empty
            v["conditions"] = conditions
        return v

    # List of component conditions observed
    @typechecked
    def conditions(self) -> Optional[List[ComponentCondition]]:
        return self.__conditions


# ConfigMap holds configuration data for pods to consume.
class ConfigMap(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        data: Dict[str, str] = None,
        binaryData: Dict[str, bytes] = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "ConfigMap",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__data = data if data is not None else {}
        self.__binaryData = binaryData if binaryData is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        data = self.data()
        if data:  # omit empty
            v["data"] = data
        binaryData = self.binaryData()
        if binaryData:  # omit empty
            v["binaryData"] = binaryData
        return v

    # Data contains the configuration data.
    # Each key must consist of alphanumeric characters, '-', '_' or '.'.
    # Values with non-UTF-8 byte sequences must use the BinaryData field.
    # The keys stored in Data must not overlap with the keys in
    # the BinaryData field, this is enforced during validation process.
    @typechecked
    def data(self) -> Optional[Dict[str, str]]:
        return self.__data

    # BinaryData contains the binary data.
    # Each key must consist of alphanumeric characters, '-', '_' or '.'.
    # BinaryData can contain byte sequences that are not in the UTF-8 range.
    # The keys stored in BinaryData must not overlap with the ones in
    # the Data field, this is enforced during validation process.
    # Using this field will require 1.10+ apiserver and
    # kubelet.
    @typechecked
    def binaryData(self) -> Optional[Dict[str, bytes]]:
        return self.__binaryData


# ConfigMapEnvSource selects a ConfigMap to populate the environment
# variables with.
#
# The contents of the target ConfigMap's Data field will represent the
# key-value pairs as environment variables.
class ConfigMapEnvSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, localObjectReference: LocalObjectReference = None, optional: bool = None
    ):
        super().__init__(**{})
        self.__localObjectReference = (
            localObjectReference
            if localObjectReference is not None
            else LocalObjectReference()
        )
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v.update(self.localObjectReference()._root())  # inline
        optional = self.optional()
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    # The ConfigMap to select from.
    @typechecked
    def localObjectReference(self) -> LocalObjectReference:
        return self.__localObjectReference

    # Specify whether the ConfigMap must be defined
    @typechecked
    def optional(self) -> Optional[bool]:
        return self.__optional


# Selects a key from a ConfigMap.
class ConfigMapKeySelector(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        localObjectReference: LocalObjectReference = None,
        key: str = "",
        optional: bool = None,
    ):
        super().__init__(**{})
        self.__localObjectReference = (
            localObjectReference
            if localObjectReference is not None
            else LocalObjectReference()
        )
        self.__key = key
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v.update(self.localObjectReference()._root())  # inline
        v["key"] = self.key()
        optional = self.optional()
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    # The ConfigMap to select from.
    @typechecked
    def localObjectReference(self) -> LocalObjectReference:
        return self.__localObjectReference

    # The key to select.
    @typechecked
    def key(self) -> str:
        return self.__key

    # Specify whether the ConfigMap or its key must be defined
    @typechecked
    def optional(self) -> Optional[bool]:
        return self.__optional


# ConfigMapNodeConfigSource contains the information to reference a ConfigMap as a config source for the Node.
class ConfigMapNodeConfigSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = "",
        name: str = "",
        uid: str = None,
        resourceVersion: str = None,
        kubeletConfigKey: str = "",
    ):
        super().__init__(**{})
        self.__namespace = namespace
        self.__name = name
        self.__uid = uid
        self.__resourceVersion = resourceVersion
        self.__kubeletConfigKey = kubeletConfigKey

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["namespace"] = self.namespace()
        v["name"] = self.name()
        uid = self.uid()
        if uid:  # omit empty
            v["uid"] = uid
        resourceVersion = self.resourceVersion()
        if resourceVersion:  # omit empty
            v["resourceVersion"] = resourceVersion
        v["kubeletConfigKey"] = self.kubeletConfigKey()
        return v

    # Namespace is the metadata.namespace of the referenced ConfigMap.
    # This field is required in all cases.
    @typechecked
    def namespace(self) -> str:
        return self.__namespace

    # Name is the metadata.name of the referenced ConfigMap.
    # This field is required in all cases.
    @typechecked
    def name(self) -> str:
        return self.__name

    # UID is the metadata.UID of the referenced ConfigMap.
    # This field is forbidden in Node.Spec, and required in Node.Status.
    @typechecked
    def uid(self) -> Optional[str]:
        return self.__uid

    # ResourceVersion is the metadata.ResourceVersion of the referenced ConfigMap.
    # This field is forbidden in Node.Spec, and required in Node.Status.
    @typechecked
    def resourceVersion(self) -> Optional[str]:
        return self.__resourceVersion

    # KubeletConfigKey declares which key of the referenced ConfigMap corresponds to the KubeletConfiguration structure
    # This field is required in all cases.
    @typechecked
    def kubeletConfigKey(self) -> str:
        return self.__kubeletConfigKey


# Maps a string key to a path within a volume.
class KeyToPath(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, key: str = "", path: str = "", mode: int = None):
        super().__init__(**{})
        self.__key = key
        self.__path = path
        self.__mode = mode

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["key"] = self.key()
        v["path"] = self.path()
        mode = self.mode()
        if mode is not None:  # omit empty
            v["mode"] = mode
        return v

    # The key to project.
    @typechecked
    def key(self) -> str:
        return self.__key

    # The relative path of the file to map the key to.
    # May not be an absolute path.
    # May not contain the path element '..'.
    # May not start with the string '..'.
    @typechecked
    def path(self) -> str:
        return self.__path

    # Optional: mode bits to use on this file, must be a value between 0
    # and 0777. If not specified, the volume defaultMode will be used.
    # This might be in conflict with other options that affect the file
    # mode, like fsGroup, and the result can be other mode bits set.
    @typechecked
    def mode(self) -> Optional[int]:
        return self.__mode


# Adapts a ConfigMap into a projected volume.
#
# The contents of the target ConfigMap's Data field will be presented in a
# projected volume as files using the keys in the Data field as the file names,
# unless the items element is populated with specific mappings of keys to paths.
# Note that this is identical to a configmap volume source without the default
# mode.
class ConfigMapProjection(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        localObjectReference: LocalObjectReference = None,
        items: List[KeyToPath] = None,
        optional: bool = None,
    ):
        super().__init__(**{})
        self.__localObjectReference = (
            localObjectReference
            if localObjectReference is not None
            else LocalObjectReference()
        )
        self.__items = items if items is not None else []
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v.update(self.localObjectReference()._root())  # inline
        items = self.items()
        if items:  # omit empty
            v["items"] = items
        optional = self.optional()
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    @typechecked
    def localObjectReference(self) -> LocalObjectReference:
        return self.__localObjectReference

    # If unspecified, each key-value pair in the Data field of the referenced
    # ConfigMap will be projected into the volume as a file whose name is the
    # key and content is the value. If specified, the listed keys will be
    # projected into the specified paths, and unlisted keys will not be
    # present. If a key is specified which is not present in the ConfigMap,
    # the volume setup will error unless it is marked optional. Paths must be
    # relative and may not contain the '..' path or start with '..'.
    @typechecked
    def items(self) -> Optional[List[KeyToPath]]:
        return self.__items

    # Specify whether the ConfigMap or its keys must be defined
    @typechecked
    def optional(self) -> Optional[bool]:
        return self.__optional


# Adapts a ConfigMap into a volume.
#
# The contents of the target ConfigMap's Data field will be presented in a
# volume as files using the keys in the Data field as the file names, unless
# the items element is populated with specific mappings of keys to paths.
# ConfigMap volumes support ownership management and SELinux relabeling.
class ConfigMapVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        localObjectReference: LocalObjectReference = None,
        items: List[KeyToPath] = None,
        defaultMode: int = None,
        optional: bool = None,
    ):
        super().__init__(**{})
        self.__localObjectReference = (
            localObjectReference
            if localObjectReference is not None
            else LocalObjectReference()
        )
        self.__items = items if items is not None else []
        self.__defaultMode = defaultMode if defaultMode is not None else 420
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v.update(self.localObjectReference()._root())  # inline
        items = self.items()
        if items:  # omit empty
            v["items"] = items
        defaultMode = self.defaultMode()
        if defaultMode is not None:  # omit empty
            v["defaultMode"] = defaultMode
        optional = self.optional()
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    @typechecked
    def localObjectReference(self) -> LocalObjectReference:
        return self.__localObjectReference

    # If unspecified, each key-value pair in the Data field of the referenced
    # ConfigMap will be projected into the volume as a file whose name is the
    # key and content is the value. If specified, the listed keys will be
    # projected into the specified paths, and unlisted keys will not be
    # present. If a key is specified which is not present in the ConfigMap,
    # the volume setup will error unless it is marked optional. Paths must be
    # relative and may not contain the '..' path or start with '..'.
    @typechecked
    def items(self) -> Optional[List[KeyToPath]]:
        return self.__items

    # Optional: mode bits to use on created files by default. Must be a
    # value between 0 and 0777. Defaults to 0644.
    # Directories within the path are not affected by this setting.
    # This might be in conflict with other options that affect the file
    # mode, like fsGroup, and the result can be other mode bits set.
    @typechecked
    def defaultMode(self) -> Optional[int]:
        return self.__defaultMode

    # Specify whether the ConfigMap or its keys must be defined
    @typechecked
    def optional(self) -> Optional[bool]:
        return self.__optional


# ContainerPort represents a network port in a single container.
class ContainerPort(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        hostPort: int = None,
        containerPort: int = 0,
        protocol: Protocol = Protocol["TCP"],
        hostIP: str = None,
    ):
        super().__init__(**{})
        self.__name = name
        self.__hostPort = hostPort
        self.__containerPort = containerPort
        self.__protocol = protocol
        self.__hostIP = hostIP

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        hostPort = self.hostPort()
        if hostPort:  # omit empty
            v["hostPort"] = hostPort
        v["containerPort"] = self.containerPort()
        protocol = self.protocol()
        if protocol:  # omit empty
            v["protocol"] = protocol
        hostIP = self.hostIP()
        if hostIP:  # omit empty
            v["hostIP"] = hostIP
        return v

    # If specified, this must be an IANA_SVC_NAME and unique within the pod. Each
    # named port in a pod must have a unique name. Name for the port that can be
    # referred to by services.
    @typechecked
    def name(self) -> Optional[str]:
        return self.__name

    # Number of port to expose on the host.
    # If specified, this must be a valid port number, 0 < x < 65536.
    # If HostNetwork is specified, this must match ContainerPort.
    # Most containers do not need this.
    @typechecked
    def hostPort(self) -> Optional[int]:
        return self.__hostPort

    # Number of port to expose on the pod's IP address.
    # This must be a valid port number, 0 < x < 65536.
    @typechecked
    def containerPort(self) -> int:
        return self.__containerPort

    # Protocol for port. Must be UDP, TCP, or SCTP.
    # Defaults to "TCP".
    @typechecked
    def protocol(self) -> Optional[Protocol]:
        return self.__protocol

    # What host IP to bind the external port to.
    @typechecked
    def hostIP(self) -> Optional[str]:
        return self.__hostIP


# SecretEnvSource selects a Secret to populate the environment
# variables with.
#
# The contents of the target Secret's Data field will represent the
# key-value pairs as environment variables.
class SecretEnvSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, localObjectReference: LocalObjectReference = None, optional: bool = None
    ):
        super().__init__(**{})
        self.__localObjectReference = (
            localObjectReference
            if localObjectReference is not None
            else LocalObjectReference()
        )
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v.update(self.localObjectReference()._root())  # inline
        optional = self.optional()
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    # The Secret to select from.
    @typechecked
    def localObjectReference(self) -> LocalObjectReference:
        return self.__localObjectReference

    # Specify whether the Secret must be defined
    @typechecked
    def optional(self) -> Optional[bool]:
        return self.__optional


# EnvFromSource represents the source of a set of ConfigMaps
class EnvFromSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        prefix: str = None,
        configMapRef: ConfigMapEnvSource = None,
        secretRef: SecretEnvSource = None,
    ):
        super().__init__(**{})
        self.__prefix = prefix
        self.__configMapRef = configMapRef
        self.__secretRef = secretRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        prefix = self.prefix()
        if prefix:  # omit empty
            v["prefix"] = prefix
        configMapRef = self.configMapRef()
        if configMapRef is not None:  # omit empty
            v["configMapRef"] = configMapRef
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        return v

    # An optional identifier to prepend to each key in the ConfigMap. Must be a C_IDENTIFIER.
    @typechecked
    def prefix(self) -> Optional[str]:
        return self.__prefix

    # The ConfigMap to select from
    @typechecked
    def configMapRef(self) -> Optional[ConfigMapEnvSource]:
        return self.__configMapRef

    # The Secret to select from
    @typechecked
    def secretRef(self) -> Optional[SecretEnvSource]:
        return self.__secretRef


# ObjectFieldSelector selects an APIVersioned field of an object.
class ObjectFieldSelector(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, apiVersion: str = "v1", fieldPath: str = ""):
        super().__init__(**{})
        self.__apiVersion = apiVersion
        self.__fieldPath = fieldPath

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        apiVersion = self.apiVersion()
        if apiVersion:  # omit empty
            v["apiVersion"] = apiVersion
        v["fieldPath"] = self.fieldPath()
        return v

    # Version of the schema the FieldPath is written in terms of, defaults to "v1".
    @typechecked
    def apiVersion(self) -> Optional[str]:
        return self.__apiVersion

    # Path of the field to select in the specified API version.
    @typechecked
    def fieldPath(self) -> str:
        return self.__fieldPath


# ResourceFieldSelector represents container resources (cpu, memory) and their output format
class ResourceFieldSelector(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        containerName: str = None,
        resource: str = "",
        divisor: "resource.Quantity" = None,
    ):
        super().__init__(**{})
        self.__containerName = containerName
        self.__resource = resource
        self.__divisor = divisor if divisor is not None else resource.Quantity()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        containerName = self.containerName()
        if containerName:  # omit empty
            v["containerName"] = containerName
        v["resource"] = self.resource()
        v["divisor"] = self.divisor()
        return v

    # Container name: required for volumes, optional for env vars
    @typechecked
    def containerName(self) -> Optional[str]:
        return self.__containerName

    # Required: resource to select
    @typechecked
    def resource(self) -> str:
        return self.__resource

    # Specifies the output format of the exposed resources, defaults to "1"
    @typechecked
    def divisor(self) -> Optional["resource.Quantity"]:
        return self.__divisor


# SecretKeySelector selects a key of a Secret.
class SecretKeySelector(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        localObjectReference: LocalObjectReference = None,
        key: str = "",
        optional: bool = None,
    ):
        super().__init__(**{})
        self.__localObjectReference = (
            localObjectReference
            if localObjectReference is not None
            else LocalObjectReference()
        )
        self.__key = key
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v.update(self.localObjectReference()._root())  # inline
        v["key"] = self.key()
        optional = self.optional()
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    # The name of the secret in the pod's namespace to select from.
    @typechecked
    def localObjectReference(self) -> LocalObjectReference:
        return self.__localObjectReference

    # The key of the secret to select from.  Must be a valid secret key.
    @typechecked
    def key(self) -> str:
        return self.__key

    # Specify whether the Secret or its key must be defined
    @typechecked
    def optional(self) -> Optional[bool]:
        return self.__optional


# EnvVarSource represents a source for the value of an EnvVar.
class EnvVarSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        fieldRef: ObjectFieldSelector = None,
        resourceFieldRef: ResourceFieldSelector = None,
        configMapKeyRef: ConfigMapKeySelector = None,
        secretKeyRef: SecretKeySelector = None,
    ):
        super().__init__(**{})
        self.__fieldRef = fieldRef
        self.__resourceFieldRef = resourceFieldRef
        self.__configMapKeyRef = configMapKeyRef
        self.__secretKeyRef = secretKeyRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        fieldRef = self.fieldRef()
        if fieldRef is not None:  # omit empty
            v["fieldRef"] = fieldRef
        resourceFieldRef = self.resourceFieldRef()
        if resourceFieldRef is not None:  # omit empty
            v["resourceFieldRef"] = resourceFieldRef
        configMapKeyRef = self.configMapKeyRef()
        if configMapKeyRef is not None:  # omit empty
            v["configMapKeyRef"] = configMapKeyRef
        secretKeyRef = self.secretKeyRef()
        if secretKeyRef is not None:  # omit empty
            v["secretKeyRef"] = secretKeyRef
        return v

    # Selects a field of the pod: supports metadata.name, metadata.namespace, metadata.labels, metadata.annotations,
    # spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP.
    @typechecked
    def fieldRef(self) -> Optional[ObjectFieldSelector]:
        return self.__fieldRef

    # Selects a resource of the container: only resources limits and requests
    # (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.
    @typechecked
    def resourceFieldRef(self) -> Optional[ResourceFieldSelector]:
        return self.__resourceFieldRef

    # Selects a key of a ConfigMap.
    @typechecked
    def configMapKeyRef(self) -> Optional[ConfigMapKeySelector]:
        return self.__configMapKeyRef

    # Selects a key of a secret in the pod's namespace
    @typechecked
    def secretKeyRef(self) -> Optional[SecretKeySelector]:
        return self.__secretKeyRef


# EnvVar represents an environment variable present in a Container.
class EnvVar(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, name: str = "", value: str = None, valueFrom: EnvVarSource = None
    ):
        super().__init__(**{})
        self.__name = name
        self.__value = value
        self.__valueFrom = valueFrom

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        value = self.value()
        if value:  # omit empty
            v["value"] = value
        valueFrom = self.valueFrom()
        if valueFrom is not None:  # omit empty
            v["valueFrom"] = valueFrom
        return v

    # Name of the environment variable. Must be a C_IDENTIFIER.
    @typechecked
    def name(self) -> str:
        return self.__name

    # Variable references $(VAR_NAME) are expanded
    # using the previous defined environment variables in the container and
    # any service environment variables. If a variable cannot be resolved,
    # the reference in the input string will be unchanged. The $(VAR_NAME)
    # syntax can be escaped with a double $$, ie: $$(VAR_NAME). Escaped
    # references will never be expanded, regardless of whether the variable
    # exists or not.
    # Defaults to "".
    @typechecked
    def value(self) -> Optional[str]:
        return self.__value

    # Source for the environment variable's value. Cannot be used if value is not empty.
    @typechecked
    def valueFrom(self) -> Optional[EnvVarSource]:
        return self.__valueFrom


# ExecAction describes a "run in container" action.
class ExecAction(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, command: List[str] = None):
        super().__init__(**{})
        self.__command = command if command is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        command = self.command()
        if command:  # omit empty
            v["command"] = command
        return v

    # Command is the command line to execute inside the container, the working directory for the
    # command  is root ('/') in the container's filesystem. The command is simply exec'd, it is
    # not run inside a shell, so traditional shell instructions ('|', etc) won't work. To use
    # a shell, you need to explicitly call out to that shell.
    # Exit status of 0 is treated as live/healthy and non-zero is unhealthy.
    @typechecked
    def command(self) -> Optional[List[str]]:
        return self.__command


# HTTPHeader describes a custom header to be used in HTTP probes
class HTTPHeader(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = "", value: str = ""):
        super().__init__(**{})
        self.__name = name
        self.__value = value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        v["value"] = self.value()
        return v

    # The header field name
    @typechecked
    def name(self) -> str:
        return self.__name

    # The header field value
    @typechecked
    def value(self) -> str:
        return self.__value


# HTTPGetAction describes an action based on HTTP Get requests.
class HTTPGetAction(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        path: str = "/",
        port: Union[int, str] = None,
        host: str = None,
        scheme: URIScheme = URIScheme["HTTP"],
        httpHeaders: Dict[str, HTTPHeader] = None,
    ):
        super().__init__(**{})
        self.__path = path
        self.__port = port if port is not None else 0
        self.__host = host
        self.__scheme = scheme
        self.__httpHeaders = httpHeaders if httpHeaders is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        if path:  # omit empty
            v["path"] = path
        v["port"] = self.port()
        host = self.host()
        if host:  # omit empty
            v["host"] = host
        scheme = self.scheme()
        if scheme:  # omit empty
            v["scheme"] = scheme
        httpHeaders = self.httpHeaders()
        if httpHeaders:  # omit empty
            v["httpHeaders"] = httpHeaders.values()  # named list
        return v

    # Path to access on the HTTP server.
    @typechecked
    def path(self) -> Optional[str]:
        return self.__path

    # Name or number of the port to access on the container.
    # Number must be in the range 1 to 65535.
    # Name must be an IANA_SVC_NAME.
    @typechecked
    def port(self) -> Union[int, str]:
        return self.__port

    # Host name to connect to, defaults to the pod IP. You probably want to set
    # "Host" in httpHeaders instead.
    @typechecked
    def host(self) -> Optional[str]:
        return self.__host

    # Scheme to use for connecting to the host.
    # Defaults to HTTP.
    @typechecked
    def scheme(self) -> Optional[URIScheme]:
        return self.__scheme

    # Custom headers to set in the request. HTTP allows repeated headers.
    @typechecked
    def httpHeaders(self) -> Optional[Dict[str, HTTPHeader]]:
        return self.__httpHeaders


# TCPSocketAction describes an action based on opening a socket
class TCPSocketAction(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, port: Union[int, str] = None, host: str = None):
        super().__init__(**{})
        self.__port = port if port is not None else 0
        self.__host = host

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["port"] = self.port()
        host = self.host()
        if host:  # omit empty
            v["host"] = host
        return v

    # Number or name of the port to access on the container.
    # Number must be in the range 1 to 65535.
    # Name must be an IANA_SVC_NAME.
    @typechecked
    def port(self) -> Union[int, str]:
        return self.__port

    # Optional: Host name to connect to, defaults to the pod IP.
    @typechecked
    def host(self) -> Optional[str]:
        return self.__host


# Handler defines a specific action that should be taken
# TODO: pass structured data to these actions, and document that data here.
class Handler(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        exec_: ExecAction = None,
        httpGet: HTTPGetAction = None,
        tcpSocket: TCPSocketAction = None,
    ):
        super().__init__(**{})
        self.__exec_ = exec_
        self.__httpGet = httpGet
        self.__tcpSocket = tcpSocket

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        exec_ = self.exec_()
        if exec_ is not None:  # omit empty
            v["exec"] = exec_
        httpGet = self.httpGet()
        if httpGet is not None:  # omit empty
            v["httpGet"] = httpGet
        tcpSocket = self.tcpSocket()
        if tcpSocket is not None:  # omit empty
            v["tcpSocket"] = tcpSocket
        return v

    # One and only one of the following should be specified.
    # Exec specifies the action to take.
    @typechecked
    def exec_(self) -> Optional[ExecAction]:
        return self.__exec_

    # HTTPGet specifies the http request to perform.
    @typechecked
    def httpGet(self) -> Optional[HTTPGetAction]:
        return self.__httpGet

    # TCPSocket specifies an action involving a TCP port.
    # TCP hooks not yet supported
    # TODO: implement a realistic TCP lifecycle hook
    @typechecked
    def tcpSocket(self) -> Optional[TCPSocketAction]:
        return self.__tcpSocket


# Lifecycle describes actions that the management system should take in response to container lifecycle
# events. For the PostStart and PreStop lifecycle handlers, management of the container blocks
# until the action is complete, unless the container process fails, in which case the handler is aborted.
class Lifecycle(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, postStart: Handler = None, preStop: Handler = None):
        super().__init__(**{})
        self.__postStart = postStart
        self.__preStop = preStop

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        postStart = self.postStart()
        if postStart is not None:  # omit empty
            v["postStart"] = postStart
        preStop = self.preStop()
        if preStop is not None:  # omit empty
            v["preStop"] = preStop
        return v

    # PostStart is called immediately after a container is created. If the handler fails,
    # the container is terminated and restarted according to its restart policy.
    # Other management of the container blocks until the hook completes.
    # More info: https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/#container-hooks
    @typechecked
    def postStart(self) -> Optional[Handler]:
        return self.__postStart

    # PreStop is called immediately before a container is terminated due to an
    # API request or management event such as liveness/startup probe failure,
    # preemption, resource contention, etc. The handler is not called if the
    # container crashes or exits. The reason for termination is passed to the
    # handler. The Pod's termination grace period countdown begins before the
    # PreStop hooked is executed. Regardless of the outcome of the handler, the
    # container will eventually terminate within the Pod's termination grace
    # period. Other management of the container blocks until the hook completes
    # or until the termination grace period is reached.
    # More info: https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/#container-hooks
    @typechecked
    def preStop(self) -> Optional[Handler]:
        return self.__preStop


# Probe describes a health check to be performed against a container to determine whether it is
# alive or ready to receive traffic.
class Probe(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        handler: Handler = None,
        initialDelaySeconds: int = None,
        timeoutSeconds: int = 1,
        periodSeconds: int = 10,
        successThreshold: int = 1,
        failureThreshold: int = 3,
    ):
        super().__init__(**{})
        self.__handler = handler if handler is not None else Handler()
        self.__initialDelaySeconds = initialDelaySeconds
        self.__timeoutSeconds = timeoutSeconds
        self.__periodSeconds = periodSeconds
        self.__successThreshold = successThreshold
        self.__failureThreshold = failureThreshold

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v.update(self.handler()._root())  # inline
        initialDelaySeconds = self.initialDelaySeconds()
        if initialDelaySeconds:  # omit empty
            v["initialDelaySeconds"] = initialDelaySeconds
        timeoutSeconds = self.timeoutSeconds()
        if timeoutSeconds:  # omit empty
            v["timeoutSeconds"] = timeoutSeconds
        periodSeconds = self.periodSeconds()
        if periodSeconds:  # omit empty
            v["periodSeconds"] = periodSeconds
        successThreshold = self.successThreshold()
        if successThreshold:  # omit empty
            v["successThreshold"] = successThreshold
        failureThreshold = self.failureThreshold()
        if failureThreshold:  # omit empty
            v["failureThreshold"] = failureThreshold
        return v

    # The action taken to determine the health of a container
    @typechecked
    def handler(self) -> Handler:
        return self.__handler

    # Number of seconds after the container has started before liveness probes are initiated.
    # More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    @typechecked
    def initialDelaySeconds(self) -> Optional[int]:
        return self.__initialDelaySeconds

    # Number of seconds after which the probe times out.
    # Defaults to 1 second. Minimum value is 1.
    # More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    @typechecked
    def timeoutSeconds(self) -> Optional[int]:
        return self.__timeoutSeconds

    # How often (in seconds) to perform the probe.
    # Default to 10 seconds. Minimum value is 1.
    @typechecked
    def periodSeconds(self) -> Optional[int]:
        return self.__periodSeconds

    # Minimum consecutive successes for the probe to be considered successful after having failed.
    # Defaults to 1. Must be 1 for liveness and startup. Minimum value is 1.
    @typechecked
    def successThreshold(self) -> Optional[int]:
        return self.__successThreshold

    # Minimum consecutive failures for the probe to be considered failed after having succeeded.
    # Defaults to 3. Minimum value is 1.
    @typechecked
    def failureThreshold(self) -> Optional[int]:
        return self.__failureThreshold


# ResourceRequirements describes the compute resource requirements.
class ResourceRequirements(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        limits: Dict[ResourceName, "resource.Quantity"] = None,
        requests: Dict[ResourceName, "resource.Quantity"] = None,
    ):
        super().__init__(**{})
        self.__limits = limits if limits is not None else {}
        self.__requests = requests if requests is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        limits = self.limits()
        if limits:  # omit empty
            v["limits"] = limits
        requests = self.requests()
        if requests:  # omit empty
            v["requests"] = requests
        return v

    # Limits describes the maximum amount of compute resources allowed.
    # More info: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/
    @typechecked
    def limits(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        return self.__limits

    # Requests describes the minimum amount of compute resources required.
    # If Requests is omitted for a container, it defaults to Limits if that is explicitly specified,
    # otherwise to an implementation-defined value.
    # More info: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/
    @typechecked
    def requests(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        return self.__requests


# SELinuxOptions are the labels to be applied to the container
class SELinuxOptions(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, user: str = None, role: str = None, type: str = None, level: str = None
    ):
        super().__init__(**{})
        self.__user = user
        self.__role = role
        self.__type = type
        self.__level = level

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        user = self.user()
        if user:  # omit empty
            v["user"] = user
        role = self.role()
        if role:  # omit empty
            v["role"] = role
        type = self.type()
        if type:  # omit empty
            v["type"] = type
        level = self.level()
        if level:  # omit empty
            v["level"] = level
        return v

    # User is a SELinux user label that applies to the container.
    @typechecked
    def user(self) -> Optional[str]:
        return self.__user

    # Role is a SELinux role label that applies to the container.
    @typechecked
    def role(self) -> Optional[str]:
        return self.__role

    # Type is a SELinux type label that applies to the container.
    @typechecked
    def type(self) -> Optional[str]:
        return self.__type

    # Level is SELinux level label that applies to the container.
    @typechecked
    def level(self) -> Optional[str]:
        return self.__level


# WindowsSecurityContextOptions contain Windows-specific options and credentials.
class WindowsSecurityContextOptions(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        gmsaCredentialSpecName: str = None,
        gmsaCredentialSpec: str = None,
        runAsUserName: str = None,
    ):
        super().__init__(**{})
        self.__gmsaCredentialSpecName = gmsaCredentialSpecName
        self.__gmsaCredentialSpec = gmsaCredentialSpec
        self.__runAsUserName = runAsUserName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        gmsaCredentialSpecName = self.gmsaCredentialSpecName()
        if gmsaCredentialSpecName is not None:  # omit empty
            v["gmsaCredentialSpecName"] = gmsaCredentialSpecName
        gmsaCredentialSpec = self.gmsaCredentialSpec()
        if gmsaCredentialSpec is not None:  # omit empty
            v["gmsaCredentialSpec"] = gmsaCredentialSpec
        runAsUserName = self.runAsUserName()
        if runAsUserName is not None:  # omit empty
            v["runAsUserName"] = runAsUserName
        return v

    # GMSACredentialSpecName is the name of the GMSA credential spec to use.
    # This field is alpha-level and is only honored by servers that enable the WindowsGMSA feature flag.
    @typechecked
    def gmsaCredentialSpecName(self) -> Optional[str]:
        return self.__gmsaCredentialSpecName

    # GMSACredentialSpec is where the GMSA admission webhook
    # (https://github.com/kubernetes-sigs/windows-gmsa) inlines the contents of the
    # GMSA credential spec named by the GMSACredentialSpecName field.
    # This field is alpha-level and is only honored by servers that enable the WindowsGMSA feature flag.
    @typechecked
    def gmsaCredentialSpec(self) -> Optional[str]:
        return self.__gmsaCredentialSpec

    # The UserName in Windows to run the entrypoint of the container process.
    # Defaults to the user specified in image metadata if unspecified.
    # May also be set in PodSecurityContext. If set in both SecurityContext and
    # PodSecurityContext, the value specified in SecurityContext takes precedence.
    # This field is alpha-level and it is only honored by servers that enable the WindowsRunAsUserName feature flag.
    @typechecked
    def runAsUserName(self) -> Optional[str]:
        return self.__runAsUserName


# SecurityContext holds security configuration that will be applied to a container.
# Some fields are present in both SecurityContext and PodSecurityContext.  When both
# are set, the values in SecurityContext take precedence.
class SecurityContext(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        capabilities: Capabilities = None,
        privileged: bool = None,
        seLinuxOptions: SELinuxOptions = None,
        windowsOptions: WindowsSecurityContextOptions = None,
        runAsUser: int = None,
        runAsGroup: int = None,
        runAsNonRoot: bool = None,
        readOnlyRootFilesystem: bool = None,
        allowPrivilegeEscalation: bool = None,
        procMount: ProcMountType = None,
    ):
        super().__init__(**{})
        self.__capabilities = capabilities
        self.__privileged = privileged
        self.__seLinuxOptions = seLinuxOptions
        self.__windowsOptions = windowsOptions
        self.__runAsUser = runAsUser
        self.__runAsGroup = runAsGroup
        self.__runAsNonRoot = runAsNonRoot
        self.__readOnlyRootFilesystem = readOnlyRootFilesystem
        self.__allowPrivilegeEscalation = allowPrivilegeEscalation
        self.__procMount = procMount

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        capabilities = self.capabilities()
        if capabilities is not None:  # omit empty
            v["capabilities"] = capabilities
        privileged = self.privileged()
        if privileged is not None:  # omit empty
            v["privileged"] = privileged
        seLinuxOptions = self.seLinuxOptions()
        if seLinuxOptions is not None:  # omit empty
            v["seLinuxOptions"] = seLinuxOptions
        windowsOptions = self.windowsOptions()
        if windowsOptions is not None:  # omit empty
            v["windowsOptions"] = windowsOptions
        runAsUser = self.runAsUser()
        if runAsUser is not None:  # omit empty
            v["runAsUser"] = runAsUser
        runAsGroup = self.runAsGroup()
        if runAsGroup is not None:  # omit empty
            v["runAsGroup"] = runAsGroup
        runAsNonRoot = self.runAsNonRoot()
        if runAsNonRoot is not None:  # omit empty
            v["runAsNonRoot"] = runAsNonRoot
        readOnlyRootFilesystem = self.readOnlyRootFilesystem()
        if readOnlyRootFilesystem is not None:  # omit empty
            v["readOnlyRootFilesystem"] = readOnlyRootFilesystem
        allowPrivilegeEscalation = self.allowPrivilegeEscalation()
        if allowPrivilegeEscalation is not None:  # omit empty
            v["allowPrivilegeEscalation"] = allowPrivilegeEscalation
        procMount = self.procMount()
        if procMount is not None:  # omit empty
            v["procMount"] = procMount
        return v

    # The capabilities to add/drop when running containers.
    # Defaults to the default set of capabilities granted by the container runtime.
    @typechecked
    def capabilities(self) -> Optional[Capabilities]:
        return self.__capabilities

    # Run container in privileged mode.
    # Processes in privileged containers are essentially equivalent to root on the host.
    # Defaults to false.
    @typechecked
    def privileged(self) -> Optional[bool]:
        return self.__privileged

    # The SELinux context to be applied to the container.
    # If unspecified, the container runtime will allocate a random SELinux context for each
    # container.  May also be set in PodSecurityContext.  If set in both SecurityContext and
    # PodSecurityContext, the value specified in SecurityContext takes precedence.
    @typechecked
    def seLinuxOptions(self) -> Optional[SELinuxOptions]:
        return self.__seLinuxOptions

    # The Windows specific settings applied to all containers.
    # If unspecified, the options from the PodSecurityContext will be used.
    # If set in both SecurityContext and PodSecurityContext, the value specified in SecurityContext takes precedence.
    @typechecked
    def windowsOptions(self) -> Optional[WindowsSecurityContextOptions]:
        return self.__windowsOptions

    # The UID to run the entrypoint of the container process.
    # Defaults to user specified in image metadata if unspecified.
    # May also be set in PodSecurityContext.  If set in both SecurityContext and
    # PodSecurityContext, the value specified in SecurityContext takes precedence.
    @typechecked
    def runAsUser(self) -> Optional[int]:
        return self.__runAsUser

    # The GID to run the entrypoint of the container process.
    # Uses runtime default if unset.
    # May also be set in PodSecurityContext.  If set in both SecurityContext and
    # PodSecurityContext, the value specified in SecurityContext takes precedence.
    @typechecked
    def runAsGroup(self) -> Optional[int]:
        return self.__runAsGroup

    # Indicates that the container must run as a non-root user.
    # If true, the Kubelet will validate the image at runtime to ensure that it
    # does not run as UID 0 (root) and fail to start the container if it does.
    # If unset or false, no such validation will be performed.
    # May also be set in PodSecurityContext.  If set in both SecurityContext and
    # PodSecurityContext, the value specified in SecurityContext takes precedence.
    @typechecked
    def runAsNonRoot(self) -> Optional[bool]:
        return self.__runAsNonRoot

    # Whether this container has a read-only root filesystem.
    # Default is false.
    @typechecked
    def readOnlyRootFilesystem(self) -> Optional[bool]:
        return self.__readOnlyRootFilesystem

    # AllowPrivilegeEscalation controls whether a process can gain more
    # privileges than its parent process. This bool directly controls if
    # the no_new_privs flag will be set on the container process.
    # AllowPrivilegeEscalation is true always when the container is:
    # 1) run as Privileged
    # 2) has CAP_SYS_ADMIN
    @typechecked
    def allowPrivilegeEscalation(self) -> Optional[bool]:
        return self.__allowPrivilegeEscalation

    # procMount denotes the type of proc mount to use for the containers.
    # The default is DefaultProcMount which uses the container runtime defaults for
    # readonly paths and masked paths.
    # This requires the ProcMountType feature flag to be enabled.
    @typechecked
    def procMount(self) -> Optional[ProcMountType]:
        return self.__procMount


# volumeDevice describes a mapping of a raw block device within a container.
class VolumeDevice(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = "", devicePath: str = ""):
        super().__init__(**{})
        self.__name = name
        self.__devicePath = devicePath

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        v["devicePath"] = self.devicePath()
        return v

    # name must match the name of a persistentVolumeClaim in the pod
    @typechecked
    def name(self) -> str:
        return self.__name

    # devicePath is the path inside of the container that the device will be mapped to.
    @typechecked
    def devicePath(self) -> str:
        return self.__devicePath


# VolumeMount describes a mounting of a Volume within a container.
class VolumeMount(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        readOnly: bool = None,
        mountPath: str = "",
        subPath: str = None,
        mountPropagation: MountPropagationMode = None,
        subPathExpr: str = None,
    ):
        super().__init__(**{})
        self.__name = name
        self.__readOnly = readOnly
        self.__mountPath = mountPath
        self.__subPath = subPath
        self.__mountPropagation = mountPropagation
        self.__subPathExpr = subPathExpr

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        v["mountPath"] = self.mountPath()
        subPath = self.subPath()
        if subPath:  # omit empty
            v["subPath"] = subPath
        mountPropagation = self.mountPropagation()
        if mountPropagation is not None:  # omit empty
            v["mountPropagation"] = mountPropagation
        subPathExpr = self.subPathExpr()
        if subPathExpr:  # omit empty
            v["subPathExpr"] = subPathExpr
        return v

    # This must match the Name of a Volume.
    @typechecked
    def name(self) -> str:
        return self.__name

    # Mounted read-only if true, read-write otherwise (false or unspecified).
    # Defaults to false.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # Path within the container at which the volume should be mounted.  Must
    # not contain ':'.
    @typechecked
    def mountPath(self) -> str:
        return self.__mountPath

    # Path within the volume from which the container's volume should be mounted.
    # Defaults to "" (volume's root).
    @typechecked
    def subPath(self) -> Optional[str]:
        return self.__subPath

    # mountPropagation determines how mounts are propagated from the host
    # to container and the other way around.
    # When not set, MountPropagationNone is used.
    # This field is beta in 1.10.
    @typechecked
    def mountPropagation(self) -> Optional[MountPropagationMode]:
        return self.__mountPropagation

    # Expanded path within the volume from which the container's volume should be mounted.
    # Behaves similarly to SubPath but environment variable references $(VAR_NAME) are expanded using the container's environment.
    # Defaults to "" (volume's root).
    # SubPathExpr and SubPath are mutually exclusive.
    # This field is beta in 1.15.
    @typechecked
    def subPathExpr(self) -> Optional[str]:
        return self.__subPathExpr


# A single application container that you want to run within a pod.
class Container(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        image: str = None,
        command: List[str] = None,
        args: List[str] = None,
        workingDir: str = None,
        ports: Dict[str, ContainerPort] = None,
        envFrom: List[EnvFromSource] = None,
        env: Dict[str, EnvVar] = None,
        resources: ResourceRequirements = None,
        volumeMounts: Dict[str, VolumeMount] = None,
        volumeDevices: Dict[str, VolumeDevice] = None,
        livenessProbe: Probe = None,
        readinessProbe: Probe = None,
        startupProbe: Probe = None,
        lifecycle: Lifecycle = None,
        terminationMessagePath: str = "/dev/termination-log",
        terminationMessagePolicy: TerminationMessagePolicy = TerminationMessagePolicy[
            "File"
        ],
        imagePullPolicy: PullPolicy = PullPolicy["IfNotPresent"],
        securityContext: SecurityContext = None,
        stdin: bool = None,
        stdinOnce: bool = None,
        tty: bool = None,
    ):
        super().__init__(**{})
        self.__name = name
        self.__image = image
        self.__command = command if command is not None else []
        self.__args = args if args is not None else []
        self.__workingDir = workingDir
        self.__ports = ports if ports is not None else {}
        self.__envFrom = envFrom if envFrom is not None else []
        self.__env = env if env is not None else {}
        self.__resources = (
            resources if resources is not None else ResourceRequirements()
        )
        self.__volumeMounts = volumeMounts if volumeMounts is not None else {}
        self.__volumeDevices = volumeDevices if volumeDevices is not None else {}
        self.__livenessProbe = livenessProbe
        self.__readinessProbe = readinessProbe
        self.__startupProbe = startupProbe
        self.__lifecycle = lifecycle
        self.__terminationMessagePath = terminationMessagePath
        self.__terminationMessagePolicy = terminationMessagePolicy
        self.__imagePullPolicy = imagePullPolicy
        self.__securityContext = securityContext
        self.__stdin = stdin
        self.__stdinOnce = stdinOnce
        self.__tty = tty

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        image = self.image()
        if image:  # omit empty
            v["image"] = image
        command = self.command()
        if command:  # omit empty
            v["command"] = command
        args = self.args()
        if args:  # omit empty
            v["args"] = args
        workingDir = self.workingDir()
        if workingDir:  # omit empty
            v["workingDir"] = workingDir
        ports = self.ports()
        if ports:  # omit empty
            v["ports"] = ports.values()  # named list
        envFrom = self.envFrom()
        if envFrom:  # omit empty
            v["envFrom"] = envFrom
        env = self.env()
        if env:  # omit empty
            v["env"] = env.values()  # named list
        v["resources"] = self.resources()
        volumeMounts = self.volumeMounts()
        if volumeMounts:  # omit empty
            v["volumeMounts"] = volumeMounts.values()  # named list
        volumeDevices = self.volumeDevices()
        if volumeDevices:  # omit empty
            v["volumeDevices"] = volumeDevices.values()  # named list
        livenessProbe = self.livenessProbe()
        if livenessProbe is not None:  # omit empty
            v["livenessProbe"] = livenessProbe
        readinessProbe = self.readinessProbe()
        if readinessProbe is not None:  # omit empty
            v["readinessProbe"] = readinessProbe
        startupProbe = self.startupProbe()
        if startupProbe is not None:  # omit empty
            v["startupProbe"] = startupProbe
        lifecycle = self.lifecycle()
        if lifecycle is not None:  # omit empty
            v["lifecycle"] = lifecycle
        terminationMessagePath = self.terminationMessagePath()
        if terminationMessagePath:  # omit empty
            v["terminationMessagePath"] = terminationMessagePath
        terminationMessagePolicy = self.terminationMessagePolicy()
        if terminationMessagePolicy:  # omit empty
            v["terminationMessagePolicy"] = terminationMessagePolicy
        imagePullPolicy = self.imagePullPolicy()
        if imagePullPolicy:  # omit empty
            v["imagePullPolicy"] = imagePullPolicy
        securityContext = self.securityContext()
        if securityContext is not None:  # omit empty
            v["securityContext"] = securityContext
        stdin = self.stdin()
        if stdin:  # omit empty
            v["stdin"] = stdin
        stdinOnce = self.stdinOnce()
        if stdinOnce:  # omit empty
            v["stdinOnce"] = stdinOnce
        tty = self.tty()
        if tty:  # omit empty
            v["tty"] = tty
        return v

    # Name of the container specified as a DNS_LABEL.
    # Each container in a pod must have a unique name (DNS_LABEL).
    # Cannot be updated.
    @typechecked
    def name(self) -> str:
        return self.__name

    # Docker image name.
    # More info: https://kubernetes.io/docs/concepts/containers/images
    # This field is optional to allow higher level config management to default or override
    # container images in workload controllers like Deployments and StatefulSets.
    @typechecked
    def image(self) -> Optional[str]:
        return self.__image

    # Entrypoint array. Not executed within a shell.
    # The docker image's ENTRYPOINT is used if this is not provided.
    # Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
    # cannot be resolved, the reference in the input string will be unchanged. The $(VAR_NAME) syntax
    # can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
    # regardless of whether the variable exists or not.
    # Cannot be updated.
    # More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
    @typechecked
    def command(self) -> Optional[List[str]]:
        return self.__command

    # Arguments to the entrypoint.
    # The docker image's CMD is used if this is not provided.
    # Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
    # cannot be resolved, the reference in the input string will be unchanged. The $(VAR_NAME) syntax
    # can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
    # regardless of whether the variable exists or not.
    # Cannot be updated.
    # More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
    @typechecked
    def args(self) -> Optional[List[str]]:
        return self.__args

    # Container's working directory.
    # If not specified, the container runtime's default will be used, which
    # might be configured in the container image.
    # Cannot be updated.
    @typechecked
    def workingDir(self) -> Optional[str]:
        return self.__workingDir

    # List of ports to expose from the container. Exposing a port here gives
    # the system additional information about the network connections a
    # container uses, but is primarily informational. Not specifying a port here
    # DOES NOT prevent that port from being exposed. Any port which is
    # listening on the default "0.0.0.0" address inside a container will be
    # accessible from the network.
    # Cannot be updated.
    # +listType=map
    # +listMapKey=containerPort
    # +listMapKey=protocol
    @typechecked
    def ports(self) -> Optional[Dict[str, ContainerPort]]:
        return self.__ports

    # List of sources to populate environment variables in the container.
    # The keys defined within a source must be a C_IDENTIFIER. All invalid keys
    # will be reported as an event when the container is starting. When a key exists in multiple
    # sources, the value associated with the last source will take precedence.
    # Values defined by an Env with a duplicate key will take precedence.
    # Cannot be updated.
    @typechecked
    def envFrom(self) -> Optional[List[EnvFromSource]]:
        return self.__envFrom

    # List of environment variables to set in the container.
    # Cannot be updated.
    @typechecked
    def env(self) -> Optional[Dict[str, EnvVar]]:
        return self.__env

    # Compute Resources required by this container.
    # Cannot be updated.
    # More info: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/
    @typechecked
    def resources(self) -> Optional[ResourceRequirements]:
        return self.__resources

    # Pod volumes to mount into the container's filesystem.
    # Cannot be updated.
    @typechecked
    def volumeMounts(self) -> Optional[Dict[str, VolumeMount]]:
        return self.__volumeMounts

    # volumeDevices is the list of block devices to be used by the container.
    # This is a beta feature.
    @typechecked
    def volumeDevices(self) -> Optional[Dict[str, VolumeDevice]]:
        return self.__volumeDevices

    # Periodic probe of container liveness.
    # Container will be restarted if the probe fails.
    # Cannot be updated.
    # More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    @typechecked
    def livenessProbe(self) -> Optional[Probe]:
        return self.__livenessProbe

    # Periodic probe of container service readiness.
    # Container will be removed from service endpoints if the probe fails.
    # Cannot be updated.
    # More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    @typechecked
    def readinessProbe(self) -> Optional[Probe]:
        return self.__readinessProbe

    # StartupProbe indicates that the Pod has successfully initialized.
    # If specified, no other probes are executed until this completes successfully.
    # If this probe fails, the Pod will be restarted, just as if the livenessProbe failed.
    # This can be used to provide different probe parameters at the beginning of a Pod's lifecycle,
    # when it might take a long time to load data or warm a cache, than during steady-state operation.
    # This cannot be updated.
    # This is an alpha feature enabled by the StartupProbe feature flag.
    # More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
    @typechecked
    def startupProbe(self) -> Optional[Probe]:
        return self.__startupProbe

    # Actions that the management system should take in response to container lifecycle events.
    # Cannot be updated.
    @typechecked
    def lifecycle(self) -> Optional[Lifecycle]:
        return self.__lifecycle

    # Optional: Path at which the file to which the container's termination message
    # will be written is mounted into the container's filesystem.
    # Message written is intended to be brief final status, such as an assertion failure message.
    # Will be truncated by the node if greater than 4096 bytes. The total message length across
    # all containers will be limited to 12kb.
    # Defaults to /dev/termination-log.
    # Cannot be updated.
    @typechecked
    def terminationMessagePath(self) -> Optional[str]:
        return self.__terminationMessagePath

    # Indicate how the termination message should be populated. File will use the contents of
    # terminationMessagePath to populate the container status message on both success and failure.
    # FallbackToLogsOnError will use the last chunk of container log output if the termination
    # message file is empty and the container exited with an error.
    # The log output is limited to 2048 bytes or 80 lines, whichever is smaller.
    # Defaults to File.
    # Cannot be updated.
    @typechecked
    def terminationMessagePolicy(self) -> Optional[TerminationMessagePolicy]:
        return self.__terminationMessagePolicy

    # Image pull policy.
    # One of Always, Never, IfNotPresent.
    # Defaults to Always if :latest tag is specified, or IfNotPresent otherwise.
    # Cannot be updated.
    # More info: https://kubernetes.io/docs/concepts/containers/images#updating-images
    @typechecked
    def imagePullPolicy(self) -> Optional[PullPolicy]:
        return self.__imagePullPolicy

    # Security options the pod should run with.
    # More info: https://kubernetes.io/docs/concepts/policy/security-context/
    # More info: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
    @typechecked
    def securityContext(self) -> Optional[SecurityContext]:
        return self.__securityContext

    # Whether this container should allocate a buffer for stdin in the container runtime. If this
    # is not set, reads from stdin in the container will always result in EOF.
    # Default is false.
    @typechecked
    def stdin(self) -> Optional[bool]:
        return self.__stdin

    # Whether the container runtime should close the stdin channel after it has been opened by
    # a single attach. When stdin is true the stdin stream will remain open across multiple attach
    # sessions. If stdinOnce is set to true, stdin is opened on container start, is empty until the
    # first client attaches to stdin, and then remains open and accepts data until the client disconnects,
    # at which time stdin is closed and remains closed until the container is restarted. If this
    # flag is false, a container processes that reads from stdin will never receive an EOF.
    # Default is false
    @typechecked
    def stdinOnce(self) -> Optional[bool]:
        return self.__stdinOnce

    # Whether this container should allocate a TTY for itself, also requires 'stdin' to be true.
    # Default is false.
    @typechecked
    def tty(self) -> Optional[bool]:
        return self.__tty


# DownwardAPIVolumeFile represents information to create the file containing the pod field
class DownwardAPIVolumeFile(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        path: str = "",
        fieldRef: ObjectFieldSelector = None,
        resourceFieldRef: ResourceFieldSelector = None,
        mode: int = None,
    ):
        super().__init__(**{})
        self.__path = path
        self.__fieldRef = fieldRef
        self.__resourceFieldRef = resourceFieldRef
        self.__mode = mode

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["path"] = self.path()
        fieldRef = self.fieldRef()
        if fieldRef is not None:  # omit empty
            v["fieldRef"] = fieldRef
        resourceFieldRef = self.resourceFieldRef()
        if resourceFieldRef is not None:  # omit empty
            v["resourceFieldRef"] = resourceFieldRef
        mode = self.mode()
        if mode is not None:  # omit empty
            v["mode"] = mode
        return v

    # Required: Path is  the relative path name of the file to be created. Must not be absolute or contain the '..' path. Must be utf-8 encoded. The first item of the relative path must not start with '..'
    @typechecked
    def path(self) -> str:
        return self.__path

    # Required: Selects a field of the pod: only annotations, labels, name and namespace are supported.
    @typechecked
    def fieldRef(self) -> Optional[ObjectFieldSelector]:
        return self.__fieldRef

    # Selects a resource of the container: only resources limits and requests
    # (limits.cpu, limits.memory, requests.cpu and requests.memory) are currently supported.
    @typechecked
    def resourceFieldRef(self) -> Optional[ResourceFieldSelector]:
        return self.__resourceFieldRef

    # Optional: mode bits to use on this file, must be a value between 0
    # and 0777. If not specified, the volume defaultMode will be used.
    # This might be in conflict with other options that affect the file
    # mode, like fsGroup, and the result can be other mode bits set.
    @typechecked
    def mode(self) -> Optional[int]:
        return self.__mode


# Represents downward API info for projecting into a projected volume.
# Note that this is identical to a downwardAPI volume source without the default
# mode.
class DownwardAPIProjection(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, items: List[DownwardAPIVolumeFile] = None):
        super().__init__(**{})
        self.__items = items if items is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        items = self.items()
        if items:  # omit empty
            v["items"] = items
        return v

    # Items is a list of DownwardAPIVolume file
    @typechecked
    def items(self) -> Optional[List[DownwardAPIVolumeFile]]:
        return self.__items


# DownwardAPIVolumeSource represents a volume containing downward API info.
# Downward API volumes support ownership management and SELinux relabeling.
class DownwardAPIVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, items: List[DownwardAPIVolumeFile] = None, defaultMode: int = None
    ):
        super().__init__(**{})
        self.__items = items if items is not None else []
        self.__defaultMode = defaultMode if defaultMode is not None else 420

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        items = self.items()
        if items:  # omit empty
            v["items"] = items
        defaultMode = self.defaultMode()
        if defaultMode is not None:  # omit empty
            v["defaultMode"] = defaultMode
        return v

    # Items is a list of downward API volume file
    @typechecked
    def items(self) -> Optional[List[DownwardAPIVolumeFile]]:
        return self.__items

    # Optional: mode bits to use on created files by default. Must be a
    # value between 0 and 0777. Defaults to 0644.
    # Directories within the path are not affected by this setting.
    # This might be in conflict with other options that affect the file
    # mode, like fsGroup, and the result can be other mode bits set.
    @typechecked
    def defaultMode(self) -> Optional[int]:
        return self.__defaultMode


# Represents an empty directory for a pod.
# Empty directory volumes support ownership management and SELinux relabeling.
class EmptyDirVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, medium: StorageMedium = None, sizeLimit: "resource.Quantity" = None
    ):
        super().__init__(**{})
        self.__medium = medium
        self.__sizeLimit = sizeLimit

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        medium = self.medium()
        if medium:  # omit empty
            v["medium"] = medium
        sizeLimit = self.sizeLimit()
        if sizeLimit is not None:  # omit empty
            v["sizeLimit"] = sizeLimit
        return v

    # What type of storage medium should back this directory.
    # The default is "" which means to use the node's default medium.
    # Must be an empty string (default) or Memory.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#emptydir
    @typechecked
    def medium(self) -> Optional[StorageMedium]:
        return self.__medium

    # Total amount of local storage required for this EmptyDir volume.
    # The size limit is also applicable for memory medium.
    # The maximum usage on memory medium EmptyDir would be the minimum value between
    # the SizeLimit specified here and the sum of memory limits of all containers in a pod.
    # The default is nil which means that the limit is undefined.
    # More info: http://kubernetes.io/docs/user-guide/volumes#emptydir
    @typechecked
    def sizeLimit(self) -> Optional["resource.Quantity"]:
        return self.__sizeLimit


# EndpointAddress is a tuple that describes single IP address.
class EndpointAddress(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        ip: str = "",
        hostname: str = None,
        nodeName: str = None,
        targetRef: ObjectReference = None,
    ):
        super().__init__(**{})
        self.__ip = ip
        self.__hostname = hostname
        self.__nodeName = nodeName
        self.__targetRef = targetRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["ip"] = self.ip()
        hostname = self.hostname()
        if hostname:  # omit empty
            v["hostname"] = hostname
        nodeName = self.nodeName()
        if nodeName is not None:  # omit empty
            v["nodeName"] = nodeName
        targetRef = self.targetRef()
        if targetRef is not None:  # omit empty
            v["targetRef"] = targetRef
        return v

    # The IP of this endpoint.
    # May not be loopback (127.0.0.0/8), link-local (169.254.0.0/16),
    # or link-local multicast ((224.0.0.0/24).
    # IPv6 is also accepted but not fully supported on all platforms. Also, certain
    # kubernetes components, like kube-proxy, are not IPv6 ready.
    # TODO: This should allow hostname or IP, See #4447.
    @typechecked
    def ip(self) -> str:
        return self.__ip

    # The Hostname of this endpoint
    @typechecked
    def hostname(self) -> Optional[str]:
        return self.__hostname

    # Optional: Node hosting this endpoint. This can be used to determine endpoints local to a node.
    @typechecked
    def nodeName(self) -> Optional[str]:
        return self.__nodeName

    # Reference to object providing the endpoint.
    @typechecked
    def targetRef(self) -> Optional[ObjectReference]:
        return self.__targetRef


# EndpointPort is a tuple that describes a single port.
class EndpointPort(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = None, port: int = 0, protocol: Protocol = None):
        super().__init__(**{})
        self.__name = name
        self.__port = port
        self.__protocol = protocol

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        v["port"] = self.port()
        protocol = self.protocol()
        if protocol:  # omit empty
            v["protocol"] = protocol
        return v

    # The name of this port.  This must match the 'name' field in the
    # corresponding ServicePort.
    # Must be a DNS_LABEL.
    # Optional only if one port is defined.
    @typechecked
    def name(self) -> Optional[str]:
        return self.__name

    # The port number of the endpoint.
    @typechecked
    def port(self) -> int:
        return self.__port

    # The IP protocol for this port.
    # Must be UDP, TCP, or SCTP.
    # Default is TCP.
    @typechecked
    def protocol(self) -> Optional[Protocol]:
        return self.__protocol


# EndpointSubset is a group of addresses with a common set of ports. The
# expanded set of endpoints is the Cartesian product of Addresses x Ports.
# For example, given:
#   {
#     Addresses: [{"ip": "10.10.1.1"}, {"ip": "10.10.2.2"}],
#     Ports:     [{"name": "a", "port": 8675}, {"name": "b", "port": 309}]
#   }
# The resulting set of endpoints can be viewed as:
#     a: [ 10.10.1.1:8675, 10.10.2.2:8675 ],
#     b: [ 10.10.1.1:309, 10.10.2.2:309 ]
class EndpointSubset(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        addresses: List[EndpointAddress] = None,
        notReadyAddresses: List[EndpointAddress] = None,
        ports: Dict[str, EndpointPort] = None,
    ):
        super().__init__(**{})
        self.__addresses = addresses if addresses is not None else []
        self.__notReadyAddresses = (
            notReadyAddresses if notReadyAddresses is not None else []
        )
        self.__ports = ports if ports is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        addresses = self.addresses()
        if addresses:  # omit empty
            v["addresses"] = addresses
        notReadyAddresses = self.notReadyAddresses()
        if notReadyAddresses:  # omit empty
            v["notReadyAddresses"] = notReadyAddresses
        ports = self.ports()
        if ports:  # omit empty
            v["ports"] = ports.values()  # named list
        return v

    # IP addresses which offer the related ports that are marked as ready. These endpoints
    # should be considered safe for load balancers and clients to utilize.
    @typechecked
    def addresses(self) -> Optional[List[EndpointAddress]]:
        return self.__addresses

    # IP addresses which offer the related ports but are not currently marked as ready
    # because they have not yet finished starting, have recently failed a readiness check,
    # or have recently failed a liveness check.
    @typechecked
    def notReadyAddresses(self) -> Optional[List[EndpointAddress]]:
        return self.__notReadyAddresses

    # Port numbers available on the related IP addresses.
    @typechecked
    def ports(self) -> Optional[Dict[str, EndpointPort]]:
        return self.__ports


# Endpoints is a collection of endpoints that implement the actual service. Example:
#   Name: "mysvc",
#   Subsets: [
#     {
#       Addresses: [{"ip": "10.10.1.1"}, {"ip": "10.10.2.2"}],
#       Ports: [{"name": "a", "port": 8675}, {"name": "b", "port": 309}]
#     },
#     {
#       Addresses: [{"ip": "10.10.3.3"}],
#       Ports: [{"name": "a", "port": 93}, {"name": "b", "port": 76}]
#     },
#  ]
class Endpoints(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        subsets: List[EndpointSubset] = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "Endpoints",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__subsets = subsets if subsets is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        subsets = self.subsets()
        if subsets:  # omit empty
            v["subsets"] = subsets
        return v

    # The set of all endpoints is the union of all subsets. Addresses are placed into
    # subsets according to the IPs they share. A single address with multiple ports,
    # some of which are ready and some of which are not (because they come from
    # different containers) will result in the address being displayed in different
    # subsets for the different ports. No address will appear in both Addresses and
    # NotReadyAddresses in the same subset.
    # Sets of addresses and ports that comprise a service.
    @typechecked
    def subsets(self) -> Optional[List[EndpointSubset]]:
        return self.__subsets


# EphemeralContainerCommon is a copy of all fields in Container to be inlined in
# EphemeralContainer. This separate type allows easy conversion from EphemeralContainer
# to Container and allows separate documentation for the fields of EphemeralContainer.
# When a new field is added to Container it must be added here as well.
class EphemeralContainerCommon(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        image: str = None,
        command: List[str] = None,
        args: List[str] = None,
        workingDir: str = None,
        ports: Dict[str, ContainerPort] = None,
        envFrom: List[EnvFromSource] = None,
        env: Dict[str, EnvVar] = None,
        resources: ResourceRequirements = None,
        volumeMounts: Dict[str, VolumeMount] = None,
        volumeDevices: Dict[str, VolumeDevice] = None,
        livenessProbe: Probe = None,
        readinessProbe: Probe = None,
        startupProbe: Probe = None,
        lifecycle: Lifecycle = None,
        terminationMessagePath: str = None,
        terminationMessagePolicy: TerminationMessagePolicy = None,
        imagePullPolicy: PullPolicy = None,
        securityContext: SecurityContext = None,
        stdin: bool = None,
        stdinOnce: bool = None,
        tty: bool = None,
    ):
        super().__init__(**{})
        self.__name = name
        self.__image = image
        self.__command = command if command is not None else []
        self.__args = args if args is not None else []
        self.__workingDir = workingDir
        self.__ports = ports if ports is not None else {}
        self.__envFrom = envFrom if envFrom is not None else []
        self.__env = env if env is not None else {}
        self.__resources = (
            resources if resources is not None else ResourceRequirements()
        )
        self.__volumeMounts = volumeMounts if volumeMounts is not None else {}
        self.__volumeDevices = volumeDevices if volumeDevices is not None else {}
        self.__livenessProbe = livenessProbe
        self.__readinessProbe = readinessProbe
        self.__startupProbe = startupProbe
        self.__lifecycle = lifecycle
        self.__terminationMessagePath = terminationMessagePath
        self.__terminationMessagePolicy = terminationMessagePolicy
        self.__imagePullPolicy = imagePullPolicy
        self.__securityContext = securityContext
        self.__stdin = stdin
        self.__stdinOnce = stdinOnce
        self.__tty = tty

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        image = self.image()
        if image:  # omit empty
            v["image"] = image
        command = self.command()
        if command:  # omit empty
            v["command"] = command
        args = self.args()
        if args:  # omit empty
            v["args"] = args
        workingDir = self.workingDir()
        if workingDir:  # omit empty
            v["workingDir"] = workingDir
        ports = self.ports()
        if ports:  # omit empty
            v["ports"] = ports.values()  # named list
        envFrom = self.envFrom()
        if envFrom:  # omit empty
            v["envFrom"] = envFrom
        env = self.env()
        if env:  # omit empty
            v["env"] = env.values()  # named list
        v["resources"] = self.resources()
        volumeMounts = self.volumeMounts()
        if volumeMounts:  # omit empty
            v["volumeMounts"] = volumeMounts.values()  # named list
        volumeDevices = self.volumeDevices()
        if volumeDevices:  # omit empty
            v["volumeDevices"] = volumeDevices.values()  # named list
        livenessProbe = self.livenessProbe()
        if livenessProbe is not None:  # omit empty
            v["livenessProbe"] = livenessProbe
        readinessProbe = self.readinessProbe()
        if readinessProbe is not None:  # omit empty
            v["readinessProbe"] = readinessProbe
        startupProbe = self.startupProbe()
        if startupProbe is not None:  # omit empty
            v["startupProbe"] = startupProbe
        lifecycle = self.lifecycle()
        if lifecycle is not None:  # omit empty
            v["lifecycle"] = lifecycle
        terminationMessagePath = self.terminationMessagePath()
        if terminationMessagePath:  # omit empty
            v["terminationMessagePath"] = terminationMessagePath
        terminationMessagePolicy = self.terminationMessagePolicy()
        if terminationMessagePolicy:  # omit empty
            v["terminationMessagePolicy"] = terminationMessagePolicy
        imagePullPolicy = self.imagePullPolicy()
        if imagePullPolicy:  # omit empty
            v["imagePullPolicy"] = imagePullPolicy
        securityContext = self.securityContext()
        if securityContext is not None:  # omit empty
            v["securityContext"] = securityContext
        stdin = self.stdin()
        if stdin:  # omit empty
            v["stdin"] = stdin
        stdinOnce = self.stdinOnce()
        if stdinOnce:  # omit empty
            v["stdinOnce"] = stdinOnce
        tty = self.tty()
        if tty:  # omit empty
            v["tty"] = tty
        return v

    # Name of the ephemeral container specified as a DNS_LABEL.
    # This name must be unique among all containers, init containers and ephemeral containers.
    @typechecked
    def name(self) -> str:
        return self.__name

    # Docker image name.
    # More info: https://kubernetes.io/docs/concepts/containers/images
    @typechecked
    def image(self) -> Optional[str]:
        return self.__image

    # Entrypoint array. Not executed within a shell.
    # The docker image's ENTRYPOINT is used if this is not provided.
    # Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
    # cannot be resolved, the reference in the input string will be unchanged. The $(VAR_NAME) syntax
    # can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
    # regardless of whether the variable exists or not.
    # Cannot be updated.
    # More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
    @typechecked
    def command(self) -> Optional[List[str]]:
        return self.__command

    # Arguments to the entrypoint.
    # The docker image's CMD is used if this is not provided.
    # Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
    # cannot be resolved, the reference in the input string will be unchanged. The $(VAR_NAME) syntax
    # can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
    # regardless of whether the variable exists or not.
    # Cannot be updated.
    # More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
    @typechecked
    def args(self) -> Optional[List[str]]:
        return self.__args

    # Container's working directory.
    # If not specified, the container runtime's default will be used, which
    # might be configured in the container image.
    # Cannot be updated.
    @typechecked
    def workingDir(self) -> Optional[str]:
        return self.__workingDir

    # Ports are not allowed for ephemeral containers.
    @typechecked
    def ports(self) -> Optional[Dict[str, ContainerPort]]:
        return self.__ports

    # List of sources to populate environment variables in the container.
    # The keys defined within a source must be a C_IDENTIFIER. All invalid keys
    # will be reported as an event when the container is starting. When a key exists in multiple
    # sources, the value associated with the last source will take precedence.
    # Values defined by an Env with a duplicate key will take precedence.
    # Cannot be updated.
    @typechecked
    def envFrom(self) -> Optional[List[EnvFromSource]]:
        return self.__envFrom

    # List of environment variables to set in the container.
    # Cannot be updated.
    @typechecked
    def env(self) -> Optional[Dict[str, EnvVar]]:
        return self.__env

    # Resources are not allowed for ephemeral containers. Ephemeral containers use spare resources
    # already allocated to the pod.
    @typechecked
    def resources(self) -> Optional[ResourceRequirements]:
        return self.__resources

    # Pod volumes to mount into the container's filesystem.
    # Cannot be updated.
    @typechecked
    def volumeMounts(self) -> Optional[Dict[str, VolumeMount]]:
        return self.__volumeMounts

    # volumeDevices is the list of block devices to be used by the container.
    # This is a beta feature.
    @typechecked
    def volumeDevices(self) -> Optional[Dict[str, VolumeDevice]]:
        return self.__volumeDevices

    # Probes are not allowed for ephemeral containers.
    @typechecked
    def livenessProbe(self) -> Optional[Probe]:
        return self.__livenessProbe

    # Probes are not allowed for ephemeral containers.
    @typechecked
    def readinessProbe(self) -> Optional[Probe]:
        return self.__readinessProbe

    # Probes are not allowed for ephemeral containers.
    @typechecked
    def startupProbe(self) -> Optional[Probe]:
        return self.__startupProbe

    # Lifecycle is not allowed for ephemeral containers.
    @typechecked
    def lifecycle(self) -> Optional[Lifecycle]:
        return self.__lifecycle

    # Optional: Path at which the file to which the container's termination message
    # will be written is mounted into the container's filesystem.
    # Message written is intended to be brief final status, such as an assertion failure message.
    # Will be truncated by the node if greater than 4096 bytes. The total message length across
    # all containers will be limited to 12kb.
    # Defaults to /dev/termination-log.
    # Cannot be updated.
    @typechecked
    def terminationMessagePath(self) -> Optional[str]:
        return self.__terminationMessagePath

    # Indicate how the termination message should be populated. File will use the contents of
    # terminationMessagePath to populate the container status message on both success and failure.
    # FallbackToLogsOnError will use the last chunk of container log output if the termination
    # message file is empty and the container exited with an error.
    # The log output is limited to 2048 bytes or 80 lines, whichever is smaller.
    # Defaults to File.
    # Cannot be updated.
    @typechecked
    def terminationMessagePolicy(self) -> Optional[TerminationMessagePolicy]:
        return self.__terminationMessagePolicy

    # Image pull policy.
    # One of Always, Never, IfNotPresent.
    # Defaults to Always if :latest tag is specified, or IfNotPresent otherwise.
    # Cannot be updated.
    # More info: https://kubernetes.io/docs/concepts/containers/images#updating-images
    @typechecked
    def imagePullPolicy(self) -> Optional[PullPolicy]:
        return self.__imagePullPolicy

    # SecurityContext is not allowed for ephemeral containers.
    @typechecked
    def securityContext(self) -> Optional[SecurityContext]:
        return self.__securityContext

    # Whether this container should allocate a buffer for stdin in the container runtime. If this
    # is not set, reads from stdin in the container will always result in EOF.
    # Default is false.
    @typechecked
    def stdin(self) -> Optional[bool]:
        return self.__stdin

    # Whether the container runtime should close the stdin channel after it has been opened by
    # a single attach. When stdin is true the stdin stream will remain open across multiple attach
    # sessions. If stdinOnce is set to true, stdin is opened on container start, is empty until the
    # first client attaches to stdin, and then remains open and accepts data until the client disconnects,
    # at which time stdin is closed and remains closed until the container is restarted. If this
    # flag is false, a container processes that reads from stdin will never receive an EOF.
    # Default is false
    @typechecked
    def stdinOnce(self) -> Optional[bool]:
        return self.__stdinOnce

    # Whether this container should allocate a TTY for itself, also requires 'stdin' to be true.
    # Default is false.
    @typechecked
    def tty(self) -> Optional[bool]:
        return self.__tty


# An EphemeralContainer is a container that may be added temporarily to an existing pod for
# user-initiated activities such as debugging. Ephemeral containers have no resource or
# scheduling guarantees, and they will not be restarted when they exit or when a pod is
# removed or restarted. If an ephemeral container causes a pod to exceed its resource
# allocation, the pod may be evicted.
# Ephemeral containers may not be added by directly updating the pod spec. They must be added
# via the pod's ephemeralcontainers subresource, and they will appear in the pod spec
# once added.
# This is an alpha feature enabled by the EphemeralContainers feature flag.
class EphemeralContainer(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        ephemeralContainerCommon: EphemeralContainerCommon = None,
        targetContainerName: str = None,
    ):
        super().__init__(**{})
        self.__ephemeralContainerCommon = (
            ephemeralContainerCommon
            if ephemeralContainerCommon is not None
            else EphemeralContainerCommon()
        )
        self.__targetContainerName = targetContainerName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v.update(self.ephemeralContainerCommon()._root())  # inline
        targetContainerName = self.targetContainerName()
        if targetContainerName:  # omit empty
            v["targetContainerName"] = targetContainerName
        return v

    # Ephemeral containers have all of the fields of Container, plus additional fields
    # specific to ephemeral containers. Fields in common with Container are in the
    # following inlined struct so than an EphemeralContainer may easily be converted
    # to a Container.
    @typechecked
    def ephemeralContainerCommon(self) -> EphemeralContainerCommon:
        return self.__ephemeralContainerCommon

    # If set, the name of the container from PodSpec that this ephemeral container targets.
    # The ephemeral container will be run in the namespaces (IPC, PID, etc) of this container.
    # If not set then the ephemeral container is run in whatever namespaces are shared
    # for the pod. Note that the container runtime must support this feature.
    @typechecked
    def targetContainerName(self) -> Optional[str]:
        return self.__targetContainerName


# A list of ephemeral containers used with the Pod ephemeralcontainers subresource.
class EphemeralContainers(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        ephemeralContainers: List[EphemeralContainer] = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "EphemeralContainers",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__ephemeralContainers = (
            ephemeralContainers if ephemeralContainers is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["ephemeralContainers"] = self.ephemeralContainers()
        return v

    # A list of ephemeral containers associated with this pod. New ephemeral containers
    # may be appended to this list, but existing ephemeral containers may not be removed
    # or modified.
    @typechecked
    def ephemeralContainers(self) -> List[EphemeralContainer]:
        return self.__ephemeralContainers


# EventSeries contain information on series of events, i.e. thing that was/is happening
# continuously for some time.
class EventSeries(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, count: int = None, lastObservedTime: "base.MicroTime" = None):
        super().__init__(**{})
        self.__count = count
        self.__lastObservedTime = lastObservedTime

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        count = self.count()
        if count:  # omit empty
            v["count"] = count
        v["lastObservedTime"] = self.lastObservedTime()
        return v

    # Number of occurrences in this series up to the last heartbeat time
    @typechecked
    def count(self) -> Optional[int]:
        return self.__count

    # Time of the last occurrence observed
    @typechecked
    def lastObservedTime(self) -> Optional["base.MicroTime"]:
        return self.__lastObservedTime


# EventSource contains information for an event.
class EventSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, component: str = None, host: str = None):
        super().__init__(**{})
        self.__component = component
        self.__host = host

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        component = self.component()
        if component:  # omit empty
            v["component"] = component
        host = self.host()
        if host:  # omit empty
            v["host"] = host
        return v

    # Component from which the event is generated.
    @typechecked
    def component(self) -> Optional[str]:
        return self.__component

    # Node name on which the event is generated.
    @typechecked
    def host(self) -> Optional[str]:
        return self.__host


# Event is a report of an event somewhere in the cluster.
class Event(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        involvedObject: ObjectReference = None,
        reason: str = None,
        message: str = None,
        source: EventSource = None,
        firstTimestamp: "base.Time" = None,
        lastTimestamp: "base.Time" = None,
        count: int = None,
        type: str = None,
        eventTime: "base.MicroTime" = None,
        series: EventSeries = None,
        action: str = None,
        related: ObjectReference = None,
        reportingComponent: str = "",
        reportingInstance: str = "",
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "Event",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__involvedObject = (
            involvedObject if involvedObject is not None else ObjectReference()
        )
        self.__reason = reason
        self.__message = message
        self.__source = source if source is not None else EventSource()
        self.__firstTimestamp = firstTimestamp
        self.__lastTimestamp = lastTimestamp
        self.__count = count
        self.__type = type
        self.__eventTime = eventTime
        self.__series = series
        self.__action = action
        self.__related = related
        self.__reportingComponent = reportingComponent
        self.__reportingInstance = reportingInstance

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["involvedObject"] = self.involvedObject()
        reason = self.reason()
        if reason:  # omit empty
            v["reason"] = reason
        message = self.message()
        if message:  # omit empty
            v["message"] = message
        v["source"] = self.source()
        v["firstTimestamp"] = self.firstTimestamp()
        v["lastTimestamp"] = self.lastTimestamp()
        count = self.count()
        if count:  # omit empty
            v["count"] = count
        type = self.type()
        if type:  # omit empty
            v["type"] = type
        v["eventTime"] = self.eventTime()
        series = self.series()
        if series is not None:  # omit empty
            v["series"] = series
        action = self.action()
        if action:  # omit empty
            v["action"] = action
        related = self.related()
        if related is not None:  # omit empty
            v["related"] = related
        v["reportingComponent"] = self.reportingComponent()
        v["reportingInstance"] = self.reportingInstance()
        return v

    # The object that this event is about.
    @typechecked
    def involvedObject(self) -> ObjectReference:
        return self.__involvedObject

    # This should be a short, machine understandable string that gives the reason
    # for the transition into the object's current status.
    # TODO: provide exact specification for format.
    @typechecked
    def reason(self) -> Optional[str]:
        return self.__reason

    # A human-readable description of the status of this operation.
    # TODO: decide on maximum length.
    @typechecked
    def message(self) -> Optional[str]:
        return self.__message

    # The component reporting this event. Should be a short machine understandable string.
    @typechecked
    def source(self) -> Optional[EventSource]:
        return self.__source

    # The time at which the event was first recorded. (Time of server receipt is in TypeMeta.)
    @typechecked
    def firstTimestamp(self) -> Optional["base.Time"]:
        return self.__firstTimestamp

    # The time at which the most recent occurrence of this event was recorded.
    @typechecked
    def lastTimestamp(self) -> Optional["base.Time"]:
        return self.__lastTimestamp

    # The number of times this event has occurred.
    @typechecked
    def count(self) -> Optional[int]:
        return self.__count

    # Type of this event (Normal, Warning), new types could be added in the future
    @typechecked
    def type(self) -> Optional[str]:
        return self.__type

    # Time when this Event was first observed.
    @typechecked
    def eventTime(self) -> Optional["base.MicroTime"]:
        return self.__eventTime

    # Data about the Event series this event represents or nil if it's a singleton Event.
    @typechecked
    def series(self) -> Optional[EventSeries]:
        return self.__series

    # What action was taken/failed regarding to the Regarding object.
    @typechecked
    def action(self) -> Optional[str]:
        return self.__action

    # Optional secondary object for more complex actions.
    @typechecked
    def related(self) -> Optional[ObjectReference]:
        return self.__related

    # Name of the controller that emitted this Event, e.g. `kubernetes.io/kubelet`.
    @typechecked
    def reportingComponent(self) -> str:
        return self.__reportingComponent

    # ID of the controller instance, e.g. `kubelet-xyzf`.
    @typechecked
    def reportingInstance(self) -> str:
        return self.__reportingInstance


# Represents a Fibre Channel volume.
# Fibre Channel volumes can only be mounted as read/write once.
# Fibre Channel volumes support ownership management and SELinux relabeling.
class FCVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        targetWWNs: List[str] = None,
        lun: int = None,
        fsType: str = None,
        readOnly: bool = None,
        wwids: List[str] = None,
    ):
        super().__init__(**{})
        self.__targetWWNs = targetWWNs if targetWWNs is not None else []
        self.__lun = lun
        self.__fsType = fsType
        self.__readOnly = readOnly
        self.__wwids = wwids if wwids is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        targetWWNs = self.targetWWNs()
        if targetWWNs:  # omit empty
            v["targetWWNs"] = targetWWNs
        lun = self.lun()
        if lun is not None:  # omit empty
            v["lun"] = lun
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        wwids = self.wwids()
        if wwids:  # omit empty
            v["wwids"] = wwids
        return v

    # Optional: FC target worldwide names (WWNs)
    @typechecked
    def targetWWNs(self) -> Optional[List[str]]:
        return self.__targetWWNs

    # Optional: FC target lun number
    @typechecked
    def lun(self) -> Optional[int]:
        return self.__lun

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    # TODO: how do we prevent errors in the filesystem from compromising the machine
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Optional: Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # Optional: FC volume world wide identifiers (wwids)
    # Either wwids or combination of targetWWNs and lun must be set, but not both simultaneously.
    @typechecked
    def wwids(self) -> Optional[List[str]]:
        return self.__wwids


# FlexPersistentVolumeSource represents a generic persistent volume resource that is
# provisioned/attached using an exec based plugin.
class FlexPersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        driver: str = "",
        fsType: str = None,
        secretRef: SecretReference = None,
        readOnly: bool = None,
        options: Dict[str, str] = None,
    ):
        super().__init__(**{})
        self.__driver = driver
        self.__fsType = fsType
        self.__secretRef = secretRef
        self.__readOnly = readOnly
        self.__options = options if options is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["driver"] = self.driver()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        options = self.options()
        if options:  # omit empty
            v["options"] = options
        return v

    # Driver is the name of the driver to use for this volume.
    @typechecked
    def driver(self) -> str:
        return self.__driver

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs". The default filesystem depends on FlexVolume script.
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Optional: SecretRef is reference to the secret object containing
    # sensitive information to pass to the plugin scripts. This may be
    # empty if no secret object is specified. If the secret object
    # contains more than one secret, all secrets are passed to the plugin
    # scripts.
    @typechecked
    def secretRef(self) -> Optional[SecretReference]:
        return self.__secretRef

    # Optional: Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # Optional: Extra command options if any.
    @typechecked
    def options(self) -> Optional[Dict[str, str]]:
        return self.__options


# FlexVolume represents a generic volume resource that is
# provisioned/attached using an exec based plugin.
class FlexVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        driver: str = "",
        fsType: str = None,
        secretRef: LocalObjectReference = None,
        readOnly: bool = None,
        options: Dict[str, str] = None,
    ):
        super().__init__(**{})
        self.__driver = driver
        self.__fsType = fsType
        self.__secretRef = secretRef
        self.__readOnly = readOnly
        self.__options = options if options is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["driver"] = self.driver()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        options = self.options()
        if options:  # omit empty
            v["options"] = options
        return v

    # Driver is the name of the driver to use for this volume.
    @typechecked
    def driver(self) -> str:
        return self.__driver

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs". The default filesystem depends on FlexVolume script.
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Optional: SecretRef is reference to the secret object containing
    # sensitive information to pass to the plugin scripts. This may be
    # empty if no secret object is specified. If the secret object
    # contains more than one secret, all secrets are passed to the plugin
    # scripts.
    @typechecked
    def secretRef(self) -> Optional[LocalObjectReference]:
        return self.__secretRef

    # Optional: Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # Optional: Extra command options if any.
    @typechecked
    def options(self) -> Optional[Dict[str, str]]:
        return self.__options


# Represents a Flocker volume mounted by the Flocker agent.
# One and only one of datasetName and datasetUUID should be set.
# Flocker volumes do not support ownership management or SELinux relabeling.
class FlockerVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, datasetName: str = None, datasetUUID: str = None):
        super().__init__(**{})
        self.__datasetName = datasetName
        self.__datasetUUID = datasetUUID

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        datasetName = self.datasetName()
        if datasetName:  # omit empty
            v["datasetName"] = datasetName
        datasetUUID = self.datasetUUID()
        if datasetUUID:  # omit empty
            v["datasetUUID"] = datasetUUID
        return v

    # Name of the dataset stored as metadata -> name on the dataset for Flocker
    # should be considered as deprecated
    @typechecked
    def datasetName(self) -> Optional[str]:
        return self.__datasetName

    # UUID of the dataset. This is unique identifier of a Flocker dataset
    @typechecked
    def datasetUUID(self) -> Optional[str]:
        return self.__datasetUUID


# Represents a Persistent Disk resource in Google Compute Engine.
#
# A GCE PD must exist before mounting to a container. The disk must
# also be in the same GCE project and zone as the kubelet. A GCE PD
# can only be mounted as read/write once or read-only many times. GCE
# PDs support ownership management and SELinux relabeling.
class GCEPersistentDiskVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        pdName: str = "",
        fsType: str = None,
        partition: int = None,
        readOnly: bool = None,
    ):
        super().__init__(**{})
        self.__pdName = pdName
        self.__fsType = fsType
        self.__partition = partition
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["pdName"] = self.pdName()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        partition = self.partition()
        if partition:  # omit empty
            v["partition"] = partition
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # Unique name of the PD resource in GCE. Used to identify the disk in GCE.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
    @typechecked
    def pdName(self) -> str:
        return self.__pdName

    # Filesystem type of the volume that you want to mount.
    # Tip: Ensure that the filesystem type is supported by the host operating system.
    # Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
    # TODO: how do we prevent errors in the filesystem from compromising the machine
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # The partition in the volume that you want to mount.
    # If omitted, the default is to mount by volume name.
    # Examples: For volume /dev/sda1, you specify the partition as "1".
    # Similarly, the volume partition for /dev/sda is "0" (or you can leave the property empty).
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
    @typechecked
    def partition(self) -> Optional[int]:
        return self.__partition

    # ReadOnly here will force the ReadOnly setting in VolumeMounts.
    # Defaults to false.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# Represents a Glusterfs mount that lasts the lifetime of a pod.
# Glusterfs volumes do not support ownership management or SELinux relabeling.
class GlusterfsPersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        endpoints: str = "",
        path: str = "",
        readOnly: bool = None,
        endpointsNamespace: str = None,
    ):
        super().__init__(**{})
        self.__endpoints = endpoints
        self.__path = path
        self.__readOnly = readOnly
        self.__endpointsNamespace = endpointsNamespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["endpoints"] = self.endpoints()
        v["path"] = self.path()
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        endpointsNamespace = self.endpointsNamespace()
        if endpointsNamespace is not None:  # omit empty
            v["endpointsNamespace"] = endpointsNamespace
        return v

    # EndpointsName is the endpoint name that details Glusterfs topology.
    # More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
    @typechecked
    def endpoints(self) -> str:
        return self.__endpoints

    # Path is the Glusterfs volume path.
    # More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
    @typechecked
    def path(self) -> str:
        return self.__path

    # ReadOnly here will force the Glusterfs volume to be mounted with read-only permissions.
    # Defaults to false.
    # More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # EndpointsNamespace is the namespace that contains Glusterfs endpoint.
    # If this field is empty, the EndpointNamespace defaults to the same namespace as the bound PVC.
    # More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
    @typechecked
    def endpointsNamespace(self) -> Optional[str]:
        return self.__endpointsNamespace


# Represents a Glusterfs mount that lasts the lifetime of a pod.
# Glusterfs volumes do not support ownership management or SELinux relabeling.
class GlusterfsVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, endpoints: str = "", path: str = "", readOnly: bool = None):
        super().__init__(**{})
        self.__endpoints = endpoints
        self.__path = path
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["endpoints"] = self.endpoints()
        v["path"] = self.path()
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # EndpointsName is the endpoint name that details Glusterfs topology.
    # More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
    @typechecked
    def endpoints(self) -> str:
        return self.__endpoints

    # Path is the Glusterfs volume path.
    # More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
    @typechecked
    def path(self) -> str:
        return self.__path

    # ReadOnly here will force the Glusterfs volume to be mounted with read-only permissions.
    # Defaults to false.
    # More info: https://examples.k8s.io/volumes/glusterfs/README.md#create-a-pod
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# HostAlias holds the mapping between IP and hostnames that will be injected as an entry in the
# pod's hosts file.
class HostAlias(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, ip: str = None, hostnames: List[str] = None):
        super().__init__(**{})
        self.__ip = ip
        self.__hostnames = hostnames if hostnames is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ip = self.ip()
        if ip:  # omit empty
            v["ip"] = ip
        hostnames = self.hostnames()
        if hostnames:  # omit empty
            v["hostnames"] = hostnames
        return v

    # IP address of the host file entry.
    @typechecked
    def ip(self) -> Optional[str]:
        return self.__ip

    # Hostnames for the above IP address.
    @typechecked
    def hostnames(self) -> Optional[List[str]]:
        return self.__hostnames


# Represents a host path mapped into a pod.
# Host path volumes do not support ownership management or SELinux relabeling.
class HostPathVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, path: str = "", type: HostPathType = None):
        super().__init__(**{})
        self.__path = path
        self.__type = type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["path"] = self.path()
        type = self.type()
        if type is not None:  # omit empty
            v["type"] = type
        return v

    # Path of the directory on the host.
    # If the path is a symlink, it will follow the link to the real path.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#hostpath
    @typechecked
    def path(self) -> str:
        return self.__path

    # Type for HostPath Volume
    # Defaults to ""
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#hostpath
    @typechecked
    def type(self) -> Optional[HostPathType]:
        return self.__type


# ISCSIPersistentVolumeSource represents an ISCSI disk.
# ISCSI volumes can only be mounted as read/write once.
# ISCSI volumes support ownership management and SELinux relabeling.
class ISCSIPersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        targetPortal: str = "",
        iqn: str = "",
        lun: int = 0,
        iscsiInterface: str = "default",
        fsType: str = None,
        readOnly: bool = None,
        portals: List[str] = None,
        chapAuthDiscovery: bool = None,
        chapAuthSession: bool = None,
        secretRef: SecretReference = None,
        initiatorName: str = None,
    ):
        super().__init__(**{})
        self.__targetPortal = targetPortal
        self.__iqn = iqn
        self.__lun = lun
        self.__iscsiInterface = iscsiInterface
        self.__fsType = fsType
        self.__readOnly = readOnly
        self.__portals = portals if portals is not None else []
        self.__chapAuthDiscovery = chapAuthDiscovery
        self.__chapAuthSession = chapAuthSession
        self.__secretRef = secretRef
        self.__initiatorName = initiatorName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["targetPortal"] = self.targetPortal()
        v["iqn"] = self.iqn()
        v["lun"] = self.lun()
        iscsiInterface = self.iscsiInterface()
        if iscsiInterface:  # omit empty
            v["iscsiInterface"] = iscsiInterface
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        portals = self.portals()
        if portals:  # omit empty
            v["portals"] = portals
        chapAuthDiscovery = self.chapAuthDiscovery()
        if chapAuthDiscovery:  # omit empty
            v["chapAuthDiscovery"] = chapAuthDiscovery
        chapAuthSession = self.chapAuthSession()
        if chapAuthSession:  # omit empty
            v["chapAuthSession"] = chapAuthSession
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        initiatorName = self.initiatorName()
        if initiatorName is not None:  # omit empty
            v["initiatorName"] = initiatorName
        return v

    # iSCSI Target Portal. The Portal is either an IP or ip_addr:port if the port
    # is other than default (typically TCP ports 860 and 3260).
    @typechecked
    def targetPortal(self) -> str:
        return self.__targetPortal

    # Target iSCSI Qualified Name.
    @typechecked
    def iqn(self) -> str:
        return self.__iqn

    # iSCSI Target Lun number.
    @typechecked
    def lun(self) -> int:
        return self.__lun

    # iSCSI Interface Name that uses an iSCSI transport.
    # Defaults to 'default' (tcp).
    @typechecked
    def iscsiInterface(self) -> Optional[str]:
        return self.__iscsiInterface

    # Filesystem type of the volume that you want to mount.
    # Tip: Ensure that the filesystem type is supported by the host operating system.
    # Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#iscsi
    # TODO: how do we prevent errors in the filesystem from compromising the machine
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # ReadOnly here will force the ReadOnly setting in VolumeMounts.
    # Defaults to false.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # iSCSI Target Portal List. The Portal is either an IP or ip_addr:port if the port
    # is other than default (typically TCP ports 860 and 3260).
    @typechecked
    def portals(self) -> Optional[List[str]]:
        return self.__portals

    # whether support iSCSI Discovery CHAP authentication
    @typechecked
    def chapAuthDiscovery(self) -> Optional[bool]:
        return self.__chapAuthDiscovery

    # whether support iSCSI Session CHAP authentication
    @typechecked
    def chapAuthSession(self) -> Optional[bool]:
        return self.__chapAuthSession

    # CHAP Secret for iSCSI target and initiator authentication
    @typechecked
    def secretRef(self) -> Optional[SecretReference]:
        return self.__secretRef

    # Custom iSCSI Initiator Name.
    # If initiatorName is specified with iscsiInterface simultaneously, new iSCSI interface
    # <target portal>:<volume name> will be created for the connection.
    @typechecked
    def initiatorName(self) -> Optional[str]:
        return self.__initiatorName


# Represents an ISCSI disk.
# ISCSI volumes can only be mounted as read/write once.
# ISCSI volumes support ownership management and SELinux relabeling.
class ISCSIVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        targetPortal: str = "",
        iqn: str = "",
        lun: int = 0,
        iscsiInterface: str = "default",
        fsType: str = None,
        readOnly: bool = None,
        portals: List[str] = None,
        chapAuthDiscovery: bool = None,
        chapAuthSession: bool = None,
        secretRef: LocalObjectReference = None,
        initiatorName: str = None,
    ):
        super().__init__(**{})
        self.__targetPortal = targetPortal
        self.__iqn = iqn
        self.__lun = lun
        self.__iscsiInterface = iscsiInterface
        self.__fsType = fsType
        self.__readOnly = readOnly
        self.__portals = portals if portals is not None else []
        self.__chapAuthDiscovery = chapAuthDiscovery
        self.__chapAuthSession = chapAuthSession
        self.__secretRef = secretRef
        self.__initiatorName = initiatorName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["targetPortal"] = self.targetPortal()
        v["iqn"] = self.iqn()
        v["lun"] = self.lun()
        iscsiInterface = self.iscsiInterface()
        if iscsiInterface:  # omit empty
            v["iscsiInterface"] = iscsiInterface
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        portals = self.portals()
        if portals:  # omit empty
            v["portals"] = portals
        chapAuthDiscovery = self.chapAuthDiscovery()
        if chapAuthDiscovery:  # omit empty
            v["chapAuthDiscovery"] = chapAuthDiscovery
        chapAuthSession = self.chapAuthSession()
        if chapAuthSession:  # omit empty
            v["chapAuthSession"] = chapAuthSession
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        initiatorName = self.initiatorName()
        if initiatorName is not None:  # omit empty
            v["initiatorName"] = initiatorName
        return v

    # iSCSI Target Portal. The Portal is either an IP or ip_addr:port if the port
    # is other than default (typically TCP ports 860 and 3260).
    @typechecked
    def targetPortal(self) -> str:
        return self.__targetPortal

    # Target iSCSI Qualified Name.
    @typechecked
    def iqn(self) -> str:
        return self.__iqn

    # iSCSI Target Lun number.
    @typechecked
    def lun(self) -> int:
        return self.__lun

    # iSCSI Interface Name that uses an iSCSI transport.
    # Defaults to 'default' (tcp).
    @typechecked
    def iscsiInterface(self) -> Optional[str]:
        return self.__iscsiInterface

    # Filesystem type of the volume that you want to mount.
    # Tip: Ensure that the filesystem type is supported by the host operating system.
    # Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#iscsi
    # TODO: how do we prevent errors in the filesystem from compromising the machine
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # ReadOnly here will force the ReadOnly setting in VolumeMounts.
    # Defaults to false.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # iSCSI Target Portal List. The portal is either an IP or ip_addr:port if the port
    # is other than default (typically TCP ports 860 and 3260).
    @typechecked
    def portals(self) -> Optional[List[str]]:
        return self.__portals

    # whether support iSCSI Discovery CHAP authentication
    @typechecked
    def chapAuthDiscovery(self) -> Optional[bool]:
        return self.__chapAuthDiscovery

    # whether support iSCSI Session CHAP authentication
    @typechecked
    def chapAuthSession(self) -> Optional[bool]:
        return self.__chapAuthSession

    # CHAP Secret for iSCSI target and initiator authentication
    @typechecked
    def secretRef(self) -> Optional[LocalObjectReference]:
        return self.__secretRef

    # Custom iSCSI Initiator Name.
    # If initiatorName is specified with iscsiInterface simultaneously, new iSCSI interface
    # <target portal>:<volume name> will be created for the connection.
    @typechecked
    def initiatorName(self) -> Optional[str]:
        return self.__initiatorName


# LimitRangeItem defines a min/max usage limit for any resource that matches on kind.
class LimitRangeItem(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        type: LimitType = None,
        max: Dict[ResourceName, "resource.Quantity"] = None,
        min: Dict[ResourceName, "resource.Quantity"] = None,
        default: Dict[ResourceName, "resource.Quantity"] = None,
        defaultRequest: Dict[ResourceName, "resource.Quantity"] = None,
        maxLimitRequestRatio: Dict[ResourceName, "resource.Quantity"] = None,
    ):
        super().__init__(**{})
        self.__type = type
        self.__max = max if max is not None else {}
        self.__min = min if min is not None else {}
        self.__default = default if default is not None else {}
        self.__defaultRequest = defaultRequest if defaultRequest is not None else {}
        self.__maxLimitRequestRatio = (
            maxLimitRequestRatio if maxLimitRequestRatio is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        if type:  # omit empty
            v["type"] = type
        max = self.max()
        if max:  # omit empty
            v["max"] = max
        min = self.min()
        if min:  # omit empty
            v["min"] = min
        default = self.default()
        if default:  # omit empty
            v["default"] = default
        defaultRequest = self.defaultRequest()
        if defaultRequest:  # omit empty
            v["defaultRequest"] = defaultRequest
        maxLimitRequestRatio = self.maxLimitRequestRatio()
        if maxLimitRequestRatio:  # omit empty
            v["maxLimitRequestRatio"] = maxLimitRequestRatio
        return v

    # Type of resource that this limit applies to.
    @typechecked
    def type(self) -> Optional[LimitType]:
        return self.__type

    # Max usage constraints on this kind by resource name.
    @typechecked
    def max(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        return self.__max

    # Min usage constraints on this kind by resource name.
    @typechecked
    def min(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        return self.__min

    # Default resource requirement limit value by resource name if resource limit is omitted.
    @typechecked
    def default(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        return self.__default

    # DefaultRequest is the default resource requirement request value by resource name if resource request is omitted.
    @typechecked
    def defaultRequest(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        return self.__defaultRequest

    # MaxLimitRequestRatio if specified, the named resource must have a request and limit that are both non-zero where limit divided by request is less than or equal to the enumerated value; this represents the max burst for the named resource.
    @typechecked
    def maxLimitRequestRatio(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        return self.__maxLimitRequestRatio


# LimitRangeSpec defines a min/max usage limit for resources that match on kind.
class LimitRangeSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, limits: List[LimitRangeItem] = None):
        super().__init__(**{})
        self.__limits = limits if limits is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["limits"] = self.limits()
        return v

    # Limits is the list of LimitRangeItem objects that are enforced.
    @typechecked
    def limits(self) -> List[LimitRangeItem]:
        return self.__limits


# LimitRange sets resource usage limits for each kind of resource in a Namespace.
class LimitRange(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: LimitRangeSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "LimitRange",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else LimitRangeSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Spec defines the limits enforced.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> Optional[LimitRangeSpec]:
        return self.__spec


# Local represents directly-attached storage with node affinity (Beta feature)
class LocalVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, path: str = "", fsType: str = None):
        super().__init__(**{})
        self.__path = path
        self.__fsType = fsType

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["path"] = self.path()
        fsType = self.fsType()
        if fsType is not None:  # omit empty
            v["fsType"] = fsType
        return v

    # The full path to the volume on the node.
    # It can be either a directory or block device (disk, partition, ...).
    @typechecked
    def path(self) -> str:
        return self.__path

    # Filesystem type to mount.
    # It applies only when the Path is a block device.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs". The default value is to auto-select a fileystem if unspecified.
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType


# Represents an NFS mount that lasts the lifetime of a pod.
# NFS volumes do not support ownership management or SELinux relabeling.
class NFSVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, server: str = "", path: str = "", readOnly: bool = None):
        super().__init__(**{})
        self.__server = server
        self.__path = path
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["server"] = self.server()
        v["path"] = self.path()
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # Server is the hostname or IP address of the NFS server.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#nfs
    @typechecked
    def server(self) -> str:
        return self.__server

    # Path that is exported by the NFS server.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#nfs
    @typechecked
    def path(self) -> str:
        return self.__path

    # ReadOnly here will force
    # the NFS export to be mounted with read-only permissions.
    # Defaults to false.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#nfs
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# NamespaceSpec describes the attributes on a Namespace.
class NamespaceSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, finalizers: List[FinalizerName] = None):
        super().__init__(**{})
        self.__finalizers = finalizers if finalizers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        finalizers = self.finalizers()
        if finalizers:  # omit empty
            v["finalizers"] = finalizers
        return v

    # Finalizers is an opaque list of values that must be empty to permanently remove object from storage.
    # More info: https://kubernetes.io/docs/tasks/administer-cluster/namespaces/
    @typechecked
    def finalizers(self) -> Optional[List[FinalizerName]]:
        return self.__finalizers


# Namespace provides a scope for Names.
# Use of multiple namespaces is optional.
class Namespace(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: NamespaceSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "Namespace",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else NamespaceSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Spec defines the behavior of the Namespace.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> Optional[NamespaceSpec]:
        return self.__spec


# NodeConfigSource specifies a source of node configuration. Exactly one subfield (excluding metadata) must be non-nil.
class NodeConfigSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, configMap: ConfigMapNodeConfigSource = None):
        super().__init__(**{})
        self.__configMap = configMap

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        configMap = self.configMap()
        if configMap is not None:  # omit empty
            v["configMap"] = configMap
        return v

    # ConfigMap is a reference to a Node's ConfigMap
    @typechecked
    def configMap(self) -> Optional[ConfigMapNodeConfigSource]:
        return self.__configMap


# The node this Taint is attached to has the "effect" on
# any pod that does not tolerate the Taint.
class Taint(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        key: str = "",
        value: str = None,
        effect: TaintEffect = None,
        timeAdded: "base.Time" = None,
    ):
        super().__init__(**{})
        self.__key = key
        self.__value = value
        self.__effect = effect
        self.__timeAdded = timeAdded

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["key"] = self.key()
        value = self.value()
        if value:  # omit empty
            v["value"] = value
        v["effect"] = self.effect()
        timeAdded = self.timeAdded()
        if timeAdded is not None:  # omit empty
            v["timeAdded"] = timeAdded
        return v

    # Required. The taint key to be applied to a node.
    @typechecked
    def key(self) -> str:
        return self.__key

    # Required. The taint value corresponding to the taint key.
    @typechecked
    def value(self) -> Optional[str]:
        return self.__value

    # Required. The effect of the taint on pods
    # that do not tolerate the taint.
    # Valid effects are NoSchedule, PreferNoSchedule and NoExecute.
    @typechecked
    def effect(self) -> TaintEffect:
        return self.__effect

    # TimeAdded represents the time at which the taint was added.
    # It is only written for NoExecute taints.
    @typechecked
    def timeAdded(self) -> Optional["base.Time"]:
        return self.__timeAdded


# NodeSpec describes the attributes that a node is created with.
class NodeSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        podCIDR: str = None,
        podCIDRs: List[str] = None,
        providerID: str = None,
        unschedulable: bool = None,
        taints: List[Taint] = None,
        configSource: NodeConfigSource = None,
    ):
        super().__init__(**{})
        self.__podCIDR = podCIDR
        self.__podCIDRs = podCIDRs if podCIDRs is not None else []
        self.__providerID = providerID
        self.__unschedulable = unschedulable
        self.__taints = taints if taints is not None else []
        self.__configSource = configSource

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        podCIDR = self.podCIDR()
        if podCIDR:  # omit empty
            v["podCIDR"] = podCIDR
        podCIDRs = self.podCIDRs()
        if podCIDRs:  # omit empty
            v["podCIDRs"] = podCIDRs
        providerID = self.providerID()
        if providerID:  # omit empty
            v["providerID"] = providerID
        unschedulable = self.unschedulable()
        if unschedulable:  # omit empty
            v["unschedulable"] = unschedulable
        taints = self.taints()
        if taints:  # omit empty
            v["taints"] = taints
        configSource = self.configSource()
        if configSource is not None:  # omit empty
            v["configSource"] = configSource
        return v

    # PodCIDR represents the pod IP range assigned to the node.
    @typechecked
    def podCIDR(self) -> Optional[str]:
        return self.__podCIDR

    # podCIDRs represents the IP ranges assigned to the node for usage by Pods on that node. If this
    # field is specified, the 0th entry must match the podCIDR field. It may contain at most 1 value for
    # each of IPv4 and IPv6.
    @typechecked
    def podCIDRs(self) -> Optional[List[str]]:
        return self.__podCIDRs

    # ID of the node assigned by the cloud provider in the format: <ProviderName>://<ProviderSpecificNodeID>
    @typechecked
    def providerID(self) -> Optional[str]:
        return self.__providerID

    # Unschedulable controls node schedulability of new pods. By default, node is schedulable.
    # More info: https://kubernetes.io/docs/concepts/nodes/node/#manual-node-administration
    @typechecked
    def unschedulable(self) -> Optional[bool]:
        return self.__unschedulable

    # If specified, the node's taints.
    @typechecked
    def taints(self) -> Optional[List[Taint]]:
        return self.__taints

    # If specified, the source to get node configuration from
    # The DynamicKubeletConfig feature gate must be enabled for the Kubelet to use this field
    @typechecked
    def configSource(self) -> Optional[NodeConfigSource]:
        return self.__configSource


# Node is a worker node in Kubernetes.
# Each node will have a unique identifier in the cache (i.e. in etcd).
class Node(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: NodeSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "Node",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else NodeSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Spec defines the behavior of a node.
    # https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> Optional[NodeSpec]:
        return self.__spec


# NodeProxyOptions is the query options to a Node's proxy call.
class NodeProxyOptions(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(self, path: str = None):
        super().__init__(**{"apiVersion": "v1", "kind": "NodeProxyOptions"})
        self.__path = path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        if path:  # omit empty
            v["path"] = path
        return v

    # Path is the URL path to use for the current proxy request to node.
    @typechecked
    def path(self) -> Optional[str]:
        return self.__path


# Represents a Photon Controller persistent disk resource.
class PhotonPersistentDiskVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, pdID: str = "", fsType: str = None):
        super().__init__(**{})
        self.__pdID = pdID
        self.__fsType = fsType

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["pdID"] = self.pdID()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        return v

    # ID that identifies Photon Controller persistent disk
    @typechecked
    def pdID(self) -> str:
        return self.__pdID

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType


# PortworxVolumeSource represents a Portworx volume resource.
class PortworxVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, volumeID: str = "", fsType: str = None, readOnly: bool = None):
        super().__init__(**{})
        self.__volumeID = volumeID
        self.__fsType = fsType
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["volumeID"] = self.volumeID()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # VolumeID uniquely identifies a Portworx volume
    @typechecked
    def volumeID(self) -> str:
        return self.__volumeID

    # FSType represents the filesystem type to mount
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs". Implicitly inferred to be "ext4" if unspecified.
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# Represents a Quobyte mount that lasts the lifetime of a pod.
# Quobyte volumes do not support ownership management or SELinux relabeling.
class QuobyteVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        registry: str = "",
        volume: str = "",
        readOnly: bool = None,
        user: str = None,
        group: str = None,
        tenant: str = None,
    ):
        super().__init__(**{})
        self.__registry = registry
        self.__volume = volume
        self.__readOnly = readOnly
        self.__user = user
        self.__group = group
        self.__tenant = tenant

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["registry"] = self.registry()
        v["volume"] = self.volume()
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        user = self.user()
        if user:  # omit empty
            v["user"] = user
        group = self.group()
        if group:  # omit empty
            v["group"] = group
        tenant = self.tenant()
        if tenant:  # omit empty
            v["tenant"] = tenant
        return v

    # Registry represents a single or multiple Quobyte Registry services
    # specified as a string as host:port pair (multiple entries are separated with commas)
    # which acts as the central registry for volumes
    @typechecked
    def registry(self) -> str:
        return self.__registry

    # Volume is a string that references an already created Quobyte volume by name.
    @typechecked
    def volume(self) -> str:
        return self.__volume

    # ReadOnly here will force the Quobyte volume to be mounted with read-only permissions.
    # Defaults to false.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # User to map volume access to
    # Defaults to serivceaccount user
    @typechecked
    def user(self) -> Optional[str]:
        return self.__user

    # Group to map volume access to
    # Default is no group
    @typechecked
    def group(self) -> Optional[str]:
        return self.__group

    # Tenant owning the given Quobyte volume in the Backend
    # Used with dynamically provisioned Quobyte volumes, value is set by the plugin
    @typechecked
    def tenant(self) -> Optional[str]:
        return self.__tenant


# Represents a Rados Block Device mount that lasts the lifetime of a pod.
# RBD volumes support ownership management and SELinux relabeling.
class RBDPersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        monitors: List[str] = None,
        image: str = "",
        fsType: str = None,
        pool: str = "rbd",
        user: str = "admin",
        keyring: str = "/etc/ceph/keyring",
        secretRef: SecretReference = None,
        readOnly: bool = None,
    ):
        super().__init__(**{})
        self.__monitors = monitors if monitors is not None else []
        self.__image = image
        self.__fsType = fsType
        self.__pool = pool
        self.__user = user
        self.__keyring = keyring
        self.__secretRef = secretRef
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["monitors"] = self.monitors()
        v["image"] = self.image()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        pool = self.pool()
        if pool:  # omit empty
            v["pool"] = pool
        user = self.user()
        if user:  # omit empty
            v["user"] = user
        keyring = self.keyring()
        if keyring:  # omit empty
            v["keyring"] = keyring
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # A collection of Ceph monitors.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def monitors(self) -> List[str]:
        return self.__monitors

    # The rados image name.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def image(self) -> str:
        return self.__image

    # Filesystem type of the volume that you want to mount.
    # Tip: Ensure that the filesystem type is supported by the host operating system.
    # Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#rbd
    # TODO: how do we prevent errors in the filesystem from compromising the machine
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # The rados pool name.
    # Default is rbd.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def pool(self) -> Optional[str]:
        return self.__pool

    # The rados user name.
    # Default is admin.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def user(self) -> Optional[str]:
        return self.__user

    # Keyring is the path to key ring for RBDUser.
    # Default is /etc/ceph/keyring.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def keyring(self) -> Optional[str]:
        return self.__keyring

    # SecretRef is name of the authentication secret for RBDUser. If provided
    # overrides keyring.
    # Default is nil.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def secretRef(self) -> Optional[SecretReference]:
        return self.__secretRef

    # ReadOnly here will force the ReadOnly setting in VolumeMounts.
    # Defaults to false.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# ScaleIOPersistentVolumeSource represents a persistent ScaleIO volume
class ScaleIOPersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        gateway: str = "",
        system: str = "",
        secretRef: SecretReference = None,
        sslEnabled: bool = None,
        protectionDomain: str = None,
        storagePool: str = None,
        storageMode: str = "ThinProvisioned",
        volumeName: str = None,
        fsType: str = "xfs",
        readOnly: bool = None,
    ):
        super().__init__(**{})
        self.__gateway = gateway
        self.__system = system
        self.__secretRef = secretRef
        self.__sslEnabled = sslEnabled
        self.__protectionDomain = protectionDomain
        self.__storagePool = storagePool
        self.__storageMode = storageMode
        self.__volumeName = volumeName
        self.__fsType = fsType
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["gateway"] = self.gateway()
        v["system"] = self.system()
        v["secretRef"] = self.secretRef()
        sslEnabled = self.sslEnabled()
        if sslEnabled:  # omit empty
            v["sslEnabled"] = sslEnabled
        protectionDomain = self.protectionDomain()
        if protectionDomain:  # omit empty
            v["protectionDomain"] = protectionDomain
        storagePool = self.storagePool()
        if storagePool:  # omit empty
            v["storagePool"] = storagePool
        storageMode = self.storageMode()
        if storageMode:  # omit empty
            v["storageMode"] = storageMode
        volumeName = self.volumeName()
        if volumeName:  # omit empty
            v["volumeName"] = volumeName
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # The host address of the ScaleIO API Gateway.
    @typechecked
    def gateway(self) -> str:
        return self.__gateway

    # The name of the storage system as configured in ScaleIO.
    @typechecked
    def system(self) -> str:
        return self.__system

    # SecretRef references to the secret for ScaleIO user and other
    # sensitive information. If this is not provided, Login operation will fail.
    @typechecked
    def secretRef(self) -> Optional[SecretReference]:
        return self.__secretRef

    # Flag to enable/disable SSL communication with Gateway, default false
    @typechecked
    def sslEnabled(self) -> Optional[bool]:
        return self.__sslEnabled

    # The name of the ScaleIO Protection Domain for the configured storage.
    @typechecked
    def protectionDomain(self) -> Optional[str]:
        return self.__protectionDomain

    # The ScaleIO Storage Pool associated with the protection domain.
    @typechecked
    def storagePool(self) -> Optional[str]:
        return self.__storagePool

    # Indicates whether the storage for a volume should be ThickProvisioned or ThinProvisioned.
    # Default is ThinProvisioned.
    @typechecked
    def storageMode(self) -> Optional[str]:
        return self.__storageMode

    # The name of a volume already created in the ScaleIO system
    # that is associated with this volume source.
    @typechecked
    def volumeName(self) -> Optional[str]:
        return self.__volumeName

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs".
    # Default is "xfs"
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# Represents a StorageOS persistent volume resource.
class StorageOSPersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        volumeName: str = None,
        volumeNamespace: str = None,
        fsType: str = None,
        readOnly: bool = None,
        secretRef: ObjectReference = None,
    ):
        super().__init__(**{})
        self.__volumeName = volumeName
        self.__volumeNamespace = volumeNamespace
        self.__fsType = fsType
        self.__readOnly = readOnly
        self.__secretRef = secretRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volumeName = self.volumeName()
        if volumeName:  # omit empty
            v["volumeName"] = volumeName
        volumeNamespace = self.volumeNamespace()
        if volumeNamespace:  # omit empty
            v["volumeNamespace"] = volumeNamespace
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        return v

    # VolumeName is the human-readable name of the StorageOS volume.  Volume
    # names are only unique within a namespace.
    @typechecked
    def volumeName(self) -> Optional[str]:
        return self.__volumeName

    # VolumeNamespace specifies the scope of the volume within StorageOS.  If no
    # namespace is specified then the Pod's namespace will be used.  This allows the
    # Kubernetes name scoping to be mirrored within StorageOS for tighter integration.
    # Set VolumeName to any name to override the default behaviour.
    # Set to "default" if you are not using namespaces within StorageOS.
    # Namespaces that do not pre-exist within StorageOS will be created.
    @typechecked
    def volumeNamespace(self) -> Optional[str]:
        return self.__volumeNamespace

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # SecretRef specifies the secret to use for obtaining the StorageOS API
    # credentials.  If not specified, default values will be attempted.
    @typechecked
    def secretRef(self) -> Optional[ObjectReference]:
        return self.__secretRef


# Represents a vSphere volume resource.
class VsphereVirtualDiskVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        volumePath: str = "",
        fsType: str = None,
        storagePolicyName: str = None,
        storagePolicyID: str = None,
    ):
        super().__init__(**{})
        self.__volumePath = volumePath
        self.__fsType = fsType
        self.__storagePolicyName = storagePolicyName
        self.__storagePolicyID = storagePolicyID

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["volumePath"] = self.volumePath()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        storagePolicyName = self.storagePolicyName()
        if storagePolicyName:  # omit empty
            v["storagePolicyName"] = storagePolicyName
        storagePolicyID = self.storagePolicyID()
        if storagePolicyID:  # omit empty
            v["storagePolicyID"] = storagePolicyID
        return v

    # Path that identifies vSphere volume vmdk
    @typechecked
    def volumePath(self) -> str:
        return self.__volumePath

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Storage Policy Based Management (SPBM) profile name.
    @typechecked
    def storagePolicyName(self) -> Optional[str]:
        return self.__storagePolicyName

    # Storage Policy Based Management (SPBM) profile ID associated with the StoragePolicyName.
    @typechecked
    def storagePolicyID(self) -> Optional[str]:
        return self.__storagePolicyID


# PersistentVolumeSource is similar to VolumeSource but meant for the
# administrator who creates PVs. Exactly one of its members must be set.
class PersistentVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        gcePersistentDisk: GCEPersistentDiskVolumeSource = None,
        awsElasticBlockStore: AWSElasticBlockStoreVolumeSource = None,
        hostPath: HostPathVolumeSource = None,
        glusterfs: GlusterfsPersistentVolumeSource = None,
        nfs: NFSVolumeSource = None,
        rbd: RBDPersistentVolumeSource = None,
        iscsi: ISCSIPersistentVolumeSource = None,
        cinder: CinderPersistentVolumeSource = None,
        cephfs: CephFSPersistentVolumeSource = None,
        fc: FCVolumeSource = None,
        flocker: FlockerVolumeSource = None,
        flexVolume: FlexPersistentVolumeSource = None,
        azureFile: AzureFilePersistentVolumeSource = None,
        vsphereVolume: VsphereVirtualDiskVolumeSource = None,
        quobyte: QuobyteVolumeSource = None,
        azureDisk: AzureDiskVolumeSource = None,
        photonPersistentDisk: PhotonPersistentDiskVolumeSource = None,
        portworxVolume: PortworxVolumeSource = None,
        scaleIO: ScaleIOPersistentVolumeSource = None,
        local: LocalVolumeSource = None,
        storageos: StorageOSPersistentVolumeSource = None,
        csi: CSIPersistentVolumeSource = None,
    ):
        super().__init__(**{})
        self.__gcePersistentDisk = gcePersistentDisk
        self.__awsElasticBlockStore = awsElasticBlockStore
        self.__hostPath = hostPath
        self.__glusterfs = glusterfs
        self.__nfs = nfs
        self.__rbd = rbd
        self.__iscsi = iscsi
        self.__cinder = cinder
        self.__cephfs = cephfs
        self.__fc = fc
        self.__flocker = flocker
        self.__flexVolume = flexVolume
        self.__azureFile = azureFile
        self.__vsphereVolume = vsphereVolume
        self.__quobyte = quobyte
        self.__azureDisk = azureDisk
        self.__photonPersistentDisk = photonPersistentDisk
        self.__portworxVolume = portworxVolume
        self.__scaleIO = scaleIO
        self.__local = local
        self.__storageos = storageos
        self.__csi = csi

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        gcePersistentDisk = self.gcePersistentDisk()
        if gcePersistentDisk is not None:  # omit empty
            v["gcePersistentDisk"] = gcePersistentDisk
        awsElasticBlockStore = self.awsElasticBlockStore()
        if awsElasticBlockStore is not None:  # omit empty
            v["awsElasticBlockStore"] = awsElasticBlockStore
        hostPath = self.hostPath()
        if hostPath is not None:  # omit empty
            v["hostPath"] = hostPath
        glusterfs = self.glusterfs()
        if glusterfs is not None:  # omit empty
            v["glusterfs"] = glusterfs
        nfs = self.nfs()
        if nfs is not None:  # omit empty
            v["nfs"] = nfs
        rbd = self.rbd()
        if rbd is not None:  # omit empty
            v["rbd"] = rbd
        iscsi = self.iscsi()
        if iscsi is not None:  # omit empty
            v["iscsi"] = iscsi
        cinder = self.cinder()
        if cinder is not None:  # omit empty
            v["cinder"] = cinder
        cephfs = self.cephfs()
        if cephfs is not None:  # omit empty
            v["cephfs"] = cephfs
        fc = self.fc()
        if fc is not None:  # omit empty
            v["fc"] = fc
        flocker = self.flocker()
        if flocker is not None:  # omit empty
            v["flocker"] = flocker
        flexVolume = self.flexVolume()
        if flexVolume is not None:  # omit empty
            v["flexVolume"] = flexVolume
        azureFile = self.azureFile()
        if azureFile is not None:  # omit empty
            v["azureFile"] = azureFile
        vsphereVolume = self.vsphereVolume()
        if vsphereVolume is not None:  # omit empty
            v["vsphereVolume"] = vsphereVolume
        quobyte = self.quobyte()
        if quobyte is not None:  # omit empty
            v["quobyte"] = quobyte
        azureDisk = self.azureDisk()
        if azureDisk is not None:  # omit empty
            v["azureDisk"] = azureDisk
        photonPersistentDisk = self.photonPersistentDisk()
        if photonPersistentDisk is not None:  # omit empty
            v["photonPersistentDisk"] = photonPersistentDisk
        portworxVolume = self.portworxVolume()
        if portworxVolume is not None:  # omit empty
            v["portworxVolume"] = portworxVolume
        scaleIO = self.scaleIO()
        if scaleIO is not None:  # omit empty
            v["scaleIO"] = scaleIO
        local = self.local()
        if local is not None:  # omit empty
            v["local"] = local
        storageos = self.storageos()
        if storageos is not None:  # omit empty
            v["storageos"] = storageos
        csi = self.csi()
        if csi is not None:  # omit empty
            v["csi"] = csi
        return v

    # GCEPersistentDisk represents a GCE Disk resource that is attached to a
    # kubelet's host machine and then exposed to the pod. Provisioned by an admin.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
    @typechecked
    def gcePersistentDisk(self) -> Optional[GCEPersistentDiskVolumeSource]:
        return self.__gcePersistentDisk

    # AWSElasticBlockStore represents an AWS Disk resource that is attached to a
    # kubelet's host machine and then exposed to the pod.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#awselasticblockstore
    @typechecked
    def awsElasticBlockStore(self) -> Optional[AWSElasticBlockStoreVolumeSource]:
        return self.__awsElasticBlockStore

    # HostPath represents a directory on the host.
    # Provisioned by a developer or tester.
    # This is useful for single-node development and testing only!
    # On-host storage is not supported in any way and WILL NOT WORK in a multi-node cluster.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#hostpath
    @typechecked
    def hostPath(self) -> Optional[HostPathVolumeSource]:
        return self.__hostPath

    # Glusterfs represents a Glusterfs volume that is attached to a host and
    # exposed to the pod. Provisioned by an admin.
    # More info: https://examples.k8s.io/volumes/glusterfs/README.md
    @typechecked
    def glusterfs(self) -> Optional[GlusterfsPersistentVolumeSource]:
        return self.__glusterfs

    # NFS represents an NFS mount on the host. Provisioned by an admin.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#nfs
    @typechecked
    def nfs(self) -> Optional[NFSVolumeSource]:
        return self.__nfs

    # RBD represents a Rados Block Device mount on the host that shares a pod's lifetime.
    # More info: https://examples.k8s.io/volumes/rbd/README.md
    @typechecked
    def rbd(self) -> Optional[RBDPersistentVolumeSource]:
        return self.__rbd

    # ISCSI represents an ISCSI Disk resource that is attached to a
    # kubelet's host machine and then exposed to the pod. Provisioned by an admin.
    @typechecked
    def iscsi(self) -> Optional[ISCSIPersistentVolumeSource]:
        return self.__iscsi

    # Cinder represents a cinder volume attached and mounted on kubelets host machine.
    # More info: https://examples.k8s.io/mysql-cinder-pd/README.md
    @typechecked
    def cinder(self) -> Optional[CinderPersistentVolumeSource]:
        return self.__cinder

    # CephFS represents a Ceph FS mount on the host that shares a pod's lifetime
    @typechecked
    def cephfs(self) -> Optional[CephFSPersistentVolumeSource]:
        return self.__cephfs

    # FC represents a Fibre Channel resource that is attached to a kubelet's host machine and then exposed to the pod.
    @typechecked
    def fc(self) -> Optional[FCVolumeSource]:
        return self.__fc

    # Flocker represents a Flocker volume attached to a kubelet's host machine and exposed to the pod for its usage. This depends on the Flocker control service being running
    @typechecked
    def flocker(self) -> Optional[FlockerVolumeSource]:
        return self.__flocker

    # FlexVolume represents a generic volume resource that is
    # provisioned/attached using an exec based plugin.
    @typechecked
    def flexVolume(self) -> Optional[FlexPersistentVolumeSource]:
        return self.__flexVolume

    # AzureFile represents an Azure File Service mount on the host and bind mount to the pod.
    @typechecked
    def azureFile(self) -> Optional[AzureFilePersistentVolumeSource]:
        return self.__azureFile

    # VsphereVolume represents a vSphere volume attached and mounted on kubelets host machine
    @typechecked
    def vsphereVolume(self) -> Optional[VsphereVirtualDiskVolumeSource]:
        return self.__vsphereVolume

    # Quobyte represents a Quobyte mount on the host that shares a pod's lifetime
    @typechecked
    def quobyte(self) -> Optional[QuobyteVolumeSource]:
        return self.__quobyte

    # AzureDisk represents an Azure Data Disk mount on the host and bind mount to the pod.
    @typechecked
    def azureDisk(self) -> Optional[AzureDiskVolumeSource]:
        return self.__azureDisk

    # PhotonPersistentDisk represents a PhotonController persistent disk attached and mounted on kubelets host machine
    @typechecked
    def photonPersistentDisk(self) -> Optional[PhotonPersistentDiskVolumeSource]:
        return self.__photonPersistentDisk

    # PortworxVolume represents a portworx volume attached and mounted on kubelets host machine
    @typechecked
    def portworxVolume(self) -> Optional[PortworxVolumeSource]:
        return self.__portworxVolume

    # ScaleIO represents a ScaleIO persistent volume attached and mounted on Kubernetes nodes.
    @typechecked
    def scaleIO(self) -> Optional[ScaleIOPersistentVolumeSource]:
        return self.__scaleIO

    # Local represents directly-attached storage with node affinity
    @typechecked
    def local(self) -> Optional[LocalVolumeSource]:
        return self.__local

    # StorageOS represents a StorageOS volume that is attached to the kubelet's host machine and mounted into the pod
    # More info: https://examples.k8s.io/volumes/storageos/README.md
    @typechecked
    def storageos(self) -> Optional[StorageOSPersistentVolumeSource]:
        return self.__storageos

    # CSI represents storage that is handled by an external CSI driver (Beta feature).
    @typechecked
    def csi(self) -> Optional[CSIPersistentVolumeSource]:
        return self.__csi


# VolumeNodeAffinity defines constraints that limit what nodes this volume can be accessed from.
class VolumeNodeAffinity(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, required: NodeSelector = None):
        super().__init__(**{})
        self.__required = required

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        required = self.required()
        if required is not None:  # omit empty
            v["required"] = required
        return v

    # Required specifies hard node constraints that must be met.
    @typechecked
    def required(self) -> Optional[NodeSelector]:
        return self.__required


# PersistentVolumeSpec is the specification of a persistent volume.
class PersistentVolumeSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        capacity: Dict[ResourceName, "resource.Quantity"] = None,
        persistentVolumeSource: PersistentVolumeSource = None,
        accessModes: List[PersistentVolumeAccessMode] = None,
        claimRef: ObjectReference = None,
        persistentVolumeReclaimPolicy: PersistentVolumeReclaimPolicy = PersistentVolumeReclaimPolicy[
            "Retain"
        ],
        storageClassName: str = None,
        mountOptions: List[str] = None,
        volumeMode: PersistentVolumeMode = None,
        nodeAffinity: VolumeNodeAffinity = None,
    ):
        super().__init__(**{})
        self.__capacity = capacity if capacity is not None else {}
        self.__persistentVolumeSource = (
            persistentVolumeSource
            if persistentVolumeSource is not None
            else PersistentVolumeSource()
        )
        self.__accessModes = accessModes if accessModes is not None else []
        self.__claimRef = claimRef
        self.__persistentVolumeReclaimPolicy = persistentVolumeReclaimPolicy
        self.__storageClassName = storageClassName
        self.__mountOptions = mountOptions if mountOptions is not None else []
        self.__volumeMode = (
            volumeMode if volumeMode is not None else PersistentVolumeMode["Filesystem"]
        )
        self.__nodeAffinity = nodeAffinity

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        capacity = self.capacity()
        if capacity:  # omit empty
            v["capacity"] = capacity
        v.update(self.persistentVolumeSource()._root())  # inline
        accessModes = self.accessModes()
        if accessModes:  # omit empty
            v["accessModes"] = accessModes
        claimRef = self.claimRef()
        if claimRef is not None:  # omit empty
            v["claimRef"] = claimRef
        persistentVolumeReclaimPolicy = self.persistentVolumeReclaimPolicy()
        if persistentVolumeReclaimPolicy:  # omit empty
            v["persistentVolumeReclaimPolicy"] = persistentVolumeReclaimPolicy
        storageClassName = self.storageClassName()
        if storageClassName:  # omit empty
            v["storageClassName"] = storageClassName
        mountOptions = self.mountOptions()
        if mountOptions:  # omit empty
            v["mountOptions"] = mountOptions
        volumeMode = self.volumeMode()
        if volumeMode is not None:  # omit empty
            v["volumeMode"] = volumeMode
        nodeAffinity = self.nodeAffinity()
        if nodeAffinity is not None:  # omit empty
            v["nodeAffinity"] = nodeAffinity
        return v

    # A description of the persistent volume's resources and capacity.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#capacity
    @typechecked
    def capacity(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        return self.__capacity

    # The actual volume backing the persistent volume.
    @typechecked
    def persistentVolumeSource(self) -> PersistentVolumeSource:
        return self.__persistentVolumeSource

    # AccessModes contains all ways the volume can be mounted.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#access-modes
    @typechecked
    def accessModes(self) -> Optional[List[PersistentVolumeAccessMode]]:
        return self.__accessModes

    # ClaimRef is part of a bi-directional binding between PersistentVolume and PersistentVolumeClaim.
    # Expected to be non-nil when bound.
    # claim.VolumeName is the authoritative bind between PV and PVC.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#binding
    @typechecked
    def claimRef(self) -> Optional[ObjectReference]:
        return self.__claimRef

    # What happens to a persistent volume when released from its claim.
    # Valid options are Retain (default for manually created PersistentVolumes), Delete (default
    # for dynamically provisioned PersistentVolumes), and Recycle (deprecated).
    # Recycle must be supported by the volume plugin underlying this PersistentVolume.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#reclaiming
    @typechecked
    def persistentVolumeReclaimPolicy(self) -> Optional[PersistentVolumeReclaimPolicy]:
        return self.__persistentVolumeReclaimPolicy

    # Name of StorageClass to which this persistent volume belongs. Empty value
    # means that this volume does not belong to any StorageClass.
    @typechecked
    def storageClassName(self) -> Optional[str]:
        return self.__storageClassName

    # A list of mount options, e.g. ["ro", "soft"]. Not validated - mount will
    # simply fail if one is invalid.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes/#mount-options
    @typechecked
    def mountOptions(self) -> Optional[List[str]]:
        return self.__mountOptions

    # volumeMode defines if a volume is intended to be used with a formatted filesystem
    # or to remain in raw block state. Value of Filesystem is implied when not included in spec.
    # This is a beta feature.
    @typechecked
    def volumeMode(self) -> Optional[PersistentVolumeMode]:
        return self.__volumeMode

    # NodeAffinity defines constraints that limit what nodes this volume can be accessed from.
    # This field influences the scheduling of pods that use this volume.
    @typechecked
    def nodeAffinity(self) -> Optional[VolumeNodeAffinity]:
        return self.__nodeAffinity


# PersistentVolume (PV) is a storage resource provisioned by an administrator.
# It is analogous to a node.
# More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes
class PersistentVolume(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: PersistentVolumeSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "PersistentVolume",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else PersistentVolumeSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Spec defines a specification of a persistent volume owned by the cluster.
    # Provisioned by an administrator.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistent-volumes
    @typechecked
    def spec(self) -> Optional[PersistentVolumeSpec]:
        return self.__spec


# TypedLocalObjectReference contains enough information to let you locate the
# typed referenced object inside the same namespace.
class TypedLocalObjectReference(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, apiGroup: str = None, kind: str = "", name: str = ""):
        super().__init__(**{})
        self.__apiGroup = apiGroup
        self.__kind = kind
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["apiGroup"] = self.apiGroup()
        v["kind"] = self.kind()
        v["name"] = self.name()
        return v

    # APIGroup is the group for the resource being referenced.
    # If APIGroup is not specified, the specified Kind must be in the core API group.
    # For any other third-party types, APIGroup is required.
    @typechecked
    def apiGroup(self) -> Optional[str]:
        return self.__apiGroup

    # Kind is the type of resource being referenced
    @typechecked
    def kind(self) -> str:
        return self.__kind

    # Name is the name of resource being referenced
    @typechecked
    def name(self) -> str:
        return self.__name


# PersistentVolumeClaimSpec describes the common attributes of storage devices
# and allows a Source for provider-specific attributes
class PersistentVolumeClaimSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        accessModes: List[PersistentVolumeAccessMode] = None,
        selector: "metav1.LabelSelector" = None,
        resources: ResourceRequirements = None,
        volumeName: str = None,
        storageClassName: str = None,
        volumeMode: PersistentVolumeMode = None,
        dataSource: TypedLocalObjectReference = None,
    ):
        super().__init__(**{})
        self.__accessModes = accessModes if accessModes is not None else []
        self.__selector = selector
        self.__resources = (
            resources if resources is not None else ResourceRequirements()
        )
        self.__volumeName = volumeName
        self.__storageClassName = storageClassName
        self.__volumeMode = (
            volumeMode if volumeMode is not None else PersistentVolumeMode["Filesystem"]
        )
        self.__dataSource = dataSource

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        accessModes = self.accessModes()
        if accessModes:  # omit empty
            v["accessModes"] = accessModes
        selector = self.selector()
        if selector is not None:  # omit empty
            v["selector"] = selector
        v["resources"] = self.resources()
        volumeName = self.volumeName()
        if volumeName:  # omit empty
            v["volumeName"] = volumeName
        storageClassName = self.storageClassName()
        if storageClassName is not None:  # omit empty
            v["storageClassName"] = storageClassName
        volumeMode = self.volumeMode()
        if volumeMode is not None:  # omit empty
            v["volumeMode"] = volumeMode
        dataSource = self.dataSource()
        if dataSource is not None:  # omit empty
            v["dataSource"] = dataSource
        return v

    # AccessModes contains the desired access modes the volume should have.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#access-modes-1
    @typechecked
    def accessModes(self) -> Optional[List[PersistentVolumeAccessMode]]:
        return self.__accessModes

    # A label query over volumes to consider for binding.
    @typechecked
    def selector(self) -> Optional["metav1.LabelSelector"]:
        return self.__selector

    # Resources represents the minimum resources the volume should have.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#resources
    @typechecked
    def resources(self) -> Optional[ResourceRequirements]:
        return self.__resources

    # VolumeName is the binding reference to the PersistentVolume backing this claim.
    @typechecked
    def volumeName(self) -> Optional[str]:
        return self.__volumeName

    # Name of the StorageClass required by the claim.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#class-1
    @typechecked
    def storageClassName(self) -> Optional[str]:
        return self.__storageClassName

    # volumeMode defines what type of volume is required by the claim.
    # Value of Filesystem is implied when not included in claim spec.
    # This is a beta feature.
    @typechecked
    def volumeMode(self) -> Optional[PersistentVolumeMode]:
        return self.__volumeMode

    # This field requires the VolumeSnapshotDataSource alpha feature gate to be
    # enabled and currently VolumeSnapshot is the only supported data source.
    # If the provisioner can support VolumeSnapshot data source, it will create
    # a new volume and data will be restored to the volume at the same time.
    # If the provisioner does not support VolumeSnapshot data source, volume will
    # not be created and the failure will be reported as an event.
    # In the future, we plan to support more data source types and the behavior
    # of the provisioner may change.
    @typechecked
    def dataSource(self) -> Optional[TypedLocalObjectReference]:
        return self.__dataSource


# PersistentVolumeClaim is a user's request for and claim to a persistent volume
class PersistentVolumeClaim(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: PersistentVolumeClaimSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else PersistentVolumeClaimSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Spec defines the desired characteristics of a volume requested by a pod author.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims
    @typechecked
    def spec(self) -> Optional[PersistentVolumeClaimSpec]:
        return self.__spec


# PersistentVolumeClaimVolumeSource references the user's PVC in the same namespace.
# This volume finds the bound PV and mounts that volume for the pod. A
# PersistentVolumeClaimVolumeSource is, essentially, a wrapper around another
# type of volume that is owned by someone else (the system).
class PersistentVolumeClaimVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, claimName: str = "", readOnly: bool = None):
        super().__init__(**{})
        self.__claimName = claimName
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["claimName"] = self.claimName()
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # ClaimName is the name of a PersistentVolumeClaim in the same namespace as the pod using this volume.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims
    @typechecked
    def claimName(self) -> str:
        return self.__claimName

    # Will force the ReadOnly setting in VolumeMounts.
    # Default false.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# PodDNSConfigOption defines DNS resolver options of a pod.
class PodDNSConfigOption(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = None, value: str = None):
        super().__init__(**{})
        self.__name = name
        self.__value = value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        value = self.value()
        if value is not None:  # omit empty
            v["value"] = value
        return v

    # Required.
    @typechecked
    def name(self) -> Optional[str]:
        return self.__name

    @typechecked
    def value(self) -> Optional[str]:
        return self.__value


# PodDNSConfig defines the DNS parameters of a pod in addition to
# those generated from DNSPolicy.
class PodDNSConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        nameservers: List[str] = None,
        searches: List[str] = None,
        options: Dict[str, PodDNSConfigOption] = None,
    ):
        super().__init__(**{})
        self.__nameservers = nameservers if nameservers is not None else []
        self.__searches = searches if searches is not None else []
        self.__options = options if options is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        nameservers = self.nameservers()
        if nameservers:  # omit empty
            v["nameservers"] = nameservers
        searches = self.searches()
        if searches:  # omit empty
            v["searches"] = searches
        options = self.options()
        if options:  # omit empty
            v["options"] = options.values()  # named list
        return v

    # A list of DNS name server IP addresses.
    # This will be appended to the base nameservers generated from DNSPolicy.
    # Duplicated nameservers will be removed.
    @typechecked
    def nameservers(self) -> Optional[List[str]]:
        return self.__nameservers

    # A list of DNS search domains for host-name lookup.
    # This will be appended to the base search paths generated from DNSPolicy.
    # Duplicated search paths will be removed.
    @typechecked
    def searches(self) -> Optional[List[str]]:
        return self.__searches

    # A list of DNS resolver options.
    # This will be merged with the base options generated from DNSPolicy.
    # Duplicated entries will be removed. Resolution options given in Options
    # will override those that appear in the base DNSPolicy.
    @typechecked
    def options(self) -> Optional[Dict[str, PodDNSConfigOption]]:
        return self.__options


# PodReadinessGate contains the reference to a pod condition
class PodReadinessGate(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, conditionType: PodConditionType = None):
        super().__init__(**{})
        self.__conditionType = conditionType

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["conditionType"] = self.conditionType()
        return v

    # ConditionType refers to a condition in the pod's condition list with matching type.
    @typechecked
    def conditionType(self) -> PodConditionType:
        return self.__conditionType


# Sysctl defines a kernel parameter to be set
class Sysctl(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = "", value: str = ""):
        super().__init__(**{})
        self.__name = name
        self.__value = value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        v["value"] = self.value()
        return v

    # Name of a property to set
    @typechecked
    def name(self) -> str:
        return self.__name

    # Value of a property to set
    @typechecked
    def value(self) -> str:
        return self.__value


# PodSecurityContext holds pod-level security attributes and common container settings.
# Some fields are also present in container.securityContext.  Field values of
# container.securityContext take precedence over field values of PodSecurityContext.
class PodSecurityContext(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        seLinuxOptions: SELinuxOptions = None,
        windowsOptions: WindowsSecurityContextOptions = None,
        runAsUser: int = None,
        runAsGroup: int = None,
        runAsNonRoot: bool = None,
        supplementalGroups: List[int] = None,
        fsGroup: int = None,
        sysctls: Dict[str, Sysctl] = None,
    ):
        super().__init__(**{})
        self.__seLinuxOptions = seLinuxOptions
        self.__windowsOptions = windowsOptions
        self.__runAsUser = runAsUser
        self.__runAsGroup = runAsGroup
        self.__runAsNonRoot = runAsNonRoot
        self.__supplementalGroups = (
            supplementalGroups if supplementalGroups is not None else []
        )
        self.__fsGroup = fsGroup
        self.__sysctls = sysctls if sysctls is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        seLinuxOptions = self.seLinuxOptions()
        if seLinuxOptions is not None:  # omit empty
            v["seLinuxOptions"] = seLinuxOptions
        windowsOptions = self.windowsOptions()
        if windowsOptions is not None:  # omit empty
            v["windowsOptions"] = windowsOptions
        runAsUser = self.runAsUser()
        if runAsUser is not None:  # omit empty
            v["runAsUser"] = runAsUser
        runAsGroup = self.runAsGroup()
        if runAsGroup is not None:  # omit empty
            v["runAsGroup"] = runAsGroup
        runAsNonRoot = self.runAsNonRoot()
        if runAsNonRoot is not None:  # omit empty
            v["runAsNonRoot"] = runAsNonRoot
        supplementalGroups = self.supplementalGroups()
        if supplementalGroups:  # omit empty
            v["supplementalGroups"] = supplementalGroups
        fsGroup = self.fsGroup()
        if fsGroup is not None:  # omit empty
            v["fsGroup"] = fsGroup
        sysctls = self.sysctls()
        if sysctls:  # omit empty
            v["sysctls"] = sysctls.values()  # named list
        return v

    # The SELinux context to be applied to all containers.
    # If unspecified, the container runtime will allocate a random SELinux context for each
    # container.  May also be set in SecurityContext.  If set in
    # both SecurityContext and PodSecurityContext, the value specified in SecurityContext
    # takes precedence for that container.
    @typechecked
    def seLinuxOptions(self) -> Optional[SELinuxOptions]:
        return self.__seLinuxOptions

    # The Windows specific settings applied to all containers.
    # If unspecified, the options within a container's SecurityContext will be used.
    # If set in both SecurityContext and PodSecurityContext, the value specified in SecurityContext takes precedence.
    @typechecked
    def windowsOptions(self) -> Optional[WindowsSecurityContextOptions]:
        return self.__windowsOptions

    # The UID to run the entrypoint of the container process.
    # Defaults to user specified in image metadata if unspecified.
    # May also be set in SecurityContext.  If set in both SecurityContext and
    # PodSecurityContext, the value specified in SecurityContext takes precedence
    # for that container.
    @typechecked
    def runAsUser(self) -> Optional[int]:
        return self.__runAsUser

    # The GID to run the entrypoint of the container process.
    # Uses runtime default if unset.
    # May also be set in SecurityContext.  If set in both SecurityContext and
    # PodSecurityContext, the value specified in SecurityContext takes precedence
    # for that container.
    @typechecked
    def runAsGroup(self) -> Optional[int]:
        return self.__runAsGroup

    # Indicates that the container must run as a non-root user.
    # If true, the Kubelet will validate the image at runtime to ensure that it
    # does not run as UID 0 (root) and fail to start the container if it does.
    # If unset or false, no such validation will be performed.
    # May also be set in SecurityContext.  If set in both SecurityContext and
    # PodSecurityContext, the value specified in SecurityContext takes precedence.
    @typechecked
    def runAsNonRoot(self) -> Optional[bool]:
        return self.__runAsNonRoot

    # A list of groups applied to the first process run in each container, in addition
    # to the container's primary GID.  If unspecified, no groups will be added to
    # any container.
    @typechecked
    def supplementalGroups(self) -> Optional[List[int]]:
        return self.__supplementalGroups

    # A special supplemental group that applies to all containers in a pod.
    # Some volume types allow the Kubelet to change the ownership of that volume
    # to be owned by the pod:
    #
    # 1. The owning GID will be the FSGroup
    # 2. The setgid bit is set (new files created in the volume will be owned by FSGroup)
    # 3. The permission bits are OR'd with rw-rw----
    #
    # If unset, the Kubelet will not modify the ownership and permissions of any volume.
    @typechecked
    def fsGroup(self) -> Optional[int]:
        return self.__fsGroup

    # Sysctls hold a list of namespaced sysctls used for the pod. Pods with unsupported
    # sysctls (by the container runtime) might fail to launch.
    @typechecked
    def sysctls(self) -> Optional[Dict[str, Sysctl]]:
        return self.__sysctls


# The pod this Toleration is attached to tolerates any taint that matches
# the triple <key,value,effect> using the matching operator <operator>.
class Toleration(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        key: str = None,
        operator: TolerationOperator = None,
        value: str = None,
        effect: TaintEffect = None,
        tolerationSeconds: int = None,
    ):
        super().__init__(**{})
        self.__key = key
        self.__operator = operator
        self.__value = value
        self.__effect = effect
        self.__tolerationSeconds = tolerationSeconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        key = self.key()
        if key:  # omit empty
            v["key"] = key
        operator = self.operator()
        if operator:  # omit empty
            v["operator"] = operator
        value = self.value()
        if value:  # omit empty
            v["value"] = value
        effect = self.effect()
        if effect:  # omit empty
            v["effect"] = effect
        tolerationSeconds = self.tolerationSeconds()
        if tolerationSeconds is not None:  # omit empty
            v["tolerationSeconds"] = tolerationSeconds
        return v

    # Key is the taint key that the toleration applies to. Empty means match all taint keys.
    # If the key is empty, operator must be Exists; this combination means to match all values and all keys.
    @typechecked
    def key(self) -> Optional[str]:
        return self.__key

    # Operator represents a key's relationship to the value.
    # Valid operators are Exists and Equal. Defaults to Equal.
    # Exists is equivalent to wildcard for value, so that a pod can
    # tolerate all taints of a particular category.
    @typechecked
    def operator(self) -> Optional[TolerationOperator]:
        return self.__operator

    # Value is the taint value the toleration matches to.
    # If the operator is Exists, the value should be empty, otherwise just a regular string.
    @typechecked
    def value(self) -> Optional[str]:
        return self.__value

    # Effect indicates the taint effect to match. Empty means match all taint effects.
    # When specified, allowed values are NoSchedule, PreferNoSchedule and NoExecute.
    @typechecked
    def effect(self) -> Optional[TaintEffect]:
        return self.__effect

    # TolerationSeconds represents the period of time the toleration (which must be
    # of effect NoExecute, otherwise this field is ignored) tolerates the taint. By default,
    # it is not set, which means tolerate the taint forever (do not evict). Zero and
    # negative values will be treated as 0 (evict immediately) by the system.
    @typechecked
    def tolerationSeconds(self) -> Optional[int]:
        return self.__tolerationSeconds


# TopologySpreadConstraint specifies how to spread matching pods among the given topology.
class TopologySpreadConstraint(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        maxSkew: int = 0,
        topologyKey: str = "",
        whenUnsatisfiable: UnsatisfiableConstraintAction = None,
        labelSelector: "metav1.LabelSelector" = None,
    ):
        super().__init__(**{})
        self.__maxSkew = maxSkew
        self.__topologyKey = topologyKey
        self.__whenUnsatisfiable = whenUnsatisfiable
        self.__labelSelector = labelSelector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["maxSkew"] = self.maxSkew()
        v["topologyKey"] = self.topologyKey()
        v["whenUnsatisfiable"] = self.whenUnsatisfiable()
        labelSelector = self.labelSelector()
        if labelSelector is not None:  # omit empty
            v["labelSelector"] = labelSelector
        return v

    # MaxSkew describes the degree to which pods may be unevenly distributed.
    # It's the maximum permitted difference between the number of matching pods in
    # any two topology domains of a given topology type.
    # For example, in a 3-zone cluster, MaxSkew is set to 1, and pods with the same
    # labelSelector spread as 1/1/0:
    # +-------+-------+-------+
    # | zone1 | zone2 | zone3 |
    # +-------+-------+-------+
    # |   P   |   P   |       |
    # +-------+-------+-------+
    # - if MaxSkew is 1, incoming pod can only be scheduled to zone3 to become 1/1/1;
    # scheduling it onto zone1(zone2) would make the ActualSkew(2-0) on zone1(zone2)
    # violate MaxSkew(1).
    # - if MaxSkew is 2, incoming pod can be scheduled onto any zone.
    # It's a required field. Default value is 1 and 0 is not allowed.
    @typechecked
    def maxSkew(self) -> int:
        return self.__maxSkew

    # TopologyKey is the key of node labels. Nodes that have a label with this key
    # and identical values are considered to be in the same topology.
    # We consider each <key, value> as a "bucket", and try to put balanced number
    # of pods into each bucket.
    # It's a required field.
    @typechecked
    def topologyKey(self) -> str:
        return self.__topologyKey

    # WhenUnsatisfiable indicates how to deal with a pod if it doesn't satisfy
    # the spread constraint.
    # - DoNotSchedule (default) tells the scheduler not to schedule it
    # - ScheduleAnyway tells the scheduler to still schedule it
    # It's considered as "Unsatisfiable" if and only if placing incoming pod on any
    # topology violates "MaxSkew".
    # For example, in a 3-zone cluster, MaxSkew is set to 1, and pods with the same
    # labelSelector spread as 3/1/1:
    # +-------+-------+-------+
    # | zone1 | zone2 | zone3 |
    # +-------+-------+-------+
    # | P P P |   P   |   P   |
    # +-------+-------+-------+
    # If WhenUnsatisfiable is set to DoNotSchedule, incoming pod can only be scheduled
    # to zone2(zone3) to become 3/2/1(3/1/2) as ActualSkew(2-1) on zone2(zone3) satisfies
    # MaxSkew(1). In other words, the cluster can still be imbalanced, but scheduler
    # won't make it *more* imbalanced.
    # It's a required field.
    @typechecked
    def whenUnsatisfiable(self) -> UnsatisfiableConstraintAction:
        return self.__whenUnsatisfiable

    # LabelSelector is used to find matching pods.
    # Pods that match this label selector are counted to determine the number of pods
    # in their corresponding topology domain.
    @typechecked
    def labelSelector(self) -> Optional["metav1.LabelSelector"]:
        return self.__labelSelector


# Adapts a secret into a projected volume.
#
# The contents of the target Secret's Data field will be presented in a
# projected volume as files using the keys in the Data field as the file names.
# Note that this is identical to a secret volume source without the default
# mode.
class SecretProjection(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        localObjectReference: LocalObjectReference = None,
        items: List[KeyToPath] = None,
        optional: bool = None,
    ):
        super().__init__(**{})
        self.__localObjectReference = (
            localObjectReference
            if localObjectReference is not None
            else LocalObjectReference()
        )
        self.__items = items if items is not None else []
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v.update(self.localObjectReference()._root())  # inline
        items = self.items()
        if items:  # omit empty
            v["items"] = items
        optional = self.optional()
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    @typechecked
    def localObjectReference(self) -> LocalObjectReference:
        return self.__localObjectReference

    # If unspecified, each key-value pair in the Data field of the referenced
    # Secret will be projected into the volume as a file whose name is the
    # key and content is the value. If specified, the listed keys will be
    # projected into the specified paths, and unlisted keys will not be
    # present. If a key is specified which is not present in the Secret,
    # the volume setup will error unless it is marked optional. Paths must be
    # relative and may not contain the '..' path or start with '..'.
    @typechecked
    def items(self) -> Optional[List[KeyToPath]]:
        return self.__items

    # Specify whether the Secret or its key must be defined
    @typechecked
    def optional(self) -> Optional[bool]:
        return self.__optional


# ServiceAccountTokenProjection represents a projected service account token
# volume. This projection can be used to insert a service account token into
# the pods runtime filesystem for use against APIs (Kubernetes API Server or
# otherwise).
class ServiceAccountTokenProjection(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, audience: str = None, expirationSeconds: int = None, path: str = ""
    ):
        super().__init__(**{})
        self.__audience = audience
        self.__expirationSeconds = (
            expirationSeconds if expirationSeconds is not None else 3600
        )
        self.__path = path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        audience = self.audience()
        if audience:  # omit empty
            v["audience"] = audience
        expirationSeconds = self.expirationSeconds()
        if expirationSeconds is not None:  # omit empty
            v["expirationSeconds"] = expirationSeconds
        v["path"] = self.path()
        return v

    # Audience is the intended audience of the token. A recipient of a token
    # must identify itself with an identifier specified in the audience of the
    # token, and otherwise should reject the token. The audience defaults to the
    # identifier of the apiserver.
    @typechecked
    def audience(self) -> Optional[str]:
        return self.__audience

    # ExpirationSeconds is the requested duration of validity of the service
    # account token. As the token approaches expiration, the kubelet volume
    # plugin will proactively rotate the service account token. The kubelet will
    # start trying to rotate the token if the token is older than 80 percent of
    # its time to live or if the token is older than 24 hours.Defaults to 1 hour
    # and must be at least 10 minutes.
    @typechecked
    def expirationSeconds(self) -> Optional[int]:
        return self.__expirationSeconds

    # Path is the path relative to the mount point of the file to project the
    # token into.
    @typechecked
    def path(self) -> str:
        return self.__path


# Projection that may be projected along with other supported volume types
class VolumeProjection(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        secret: SecretProjection = None,
        downwardAPI: DownwardAPIProjection = None,
        configMap: ConfigMapProjection = None,
        serviceAccountToken: ServiceAccountTokenProjection = None,
    ):
        super().__init__(**{})
        self.__secret = secret
        self.__downwardAPI = downwardAPI
        self.__configMap = configMap
        self.__serviceAccountToken = serviceAccountToken

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secret = self.secret()
        if secret is not None:  # omit empty
            v["secret"] = secret
        downwardAPI = self.downwardAPI()
        if downwardAPI is not None:  # omit empty
            v["downwardAPI"] = downwardAPI
        configMap = self.configMap()
        if configMap is not None:  # omit empty
            v["configMap"] = configMap
        serviceAccountToken = self.serviceAccountToken()
        if serviceAccountToken is not None:  # omit empty
            v["serviceAccountToken"] = serviceAccountToken
        return v

    # information about the secret data to project
    @typechecked
    def secret(self) -> Optional[SecretProjection]:
        return self.__secret

    # information about the downwardAPI data to project
    @typechecked
    def downwardAPI(self) -> Optional[DownwardAPIProjection]:
        return self.__downwardAPI

    # information about the configMap data to project
    @typechecked
    def configMap(self) -> Optional[ConfigMapProjection]:
        return self.__configMap

    # information about the serviceAccountToken data to project
    @typechecked
    def serviceAccountToken(self) -> Optional[ServiceAccountTokenProjection]:
        return self.__serviceAccountToken


# Represents a projected volume source
class ProjectedVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, sources: List[VolumeProjection] = None, defaultMode: int = None):
        super().__init__(**{})
        self.__sources = sources if sources is not None else []
        self.__defaultMode = defaultMode if defaultMode is not None else 420

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["sources"] = self.sources()
        defaultMode = self.defaultMode()
        if defaultMode is not None:  # omit empty
            v["defaultMode"] = defaultMode
        return v

    # list of volume projections
    @typechecked
    def sources(self) -> List[VolumeProjection]:
        return self.__sources

    # Mode bits to use on created files by default. Must be a value between
    # 0 and 0777.
    # Directories within the path are not affected by this setting.
    # This might be in conflict with other options that affect the file
    # mode, like fsGroup, and the result can be other mode bits set.
    @typechecked
    def defaultMode(self) -> Optional[int]:
        return self.__defaultMode


# Represents a Rados Block Device mount that lasts the lifetime of a pod.
# RBD volumes support ownership management and SELinux relabeling.
class RBDVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        monitors: List[str] = None,
        image: str = "",
        fsType: str = None,
        pool: str = "rbd",
        user: str = "admin",
        keyring: str = "/etc/ceph/keyring",
        secretRef: LocalObjectReference = None,
        readOnly: bool = None,
    ):
        super().__init__(**{})
        self.__monitors = monitors if monitors is not None else []
        self.__image = image
        self.__fsType = fsType
        self.__pool = pool
        self.__user = user
        self.__keyring = keyring
        self.__secretRef = secretRef
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["monitors"] = self.monitors()
        v["image"] = self.image()
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        pool = self.pool()
        if pool:  # omit empty
            v["pool"] = pool
        user = self.user()
        if user:  # omit empty
            v["user"] = user
        keyring = self.keyring()
        if keyring:  # omit empty
            v["keyring"] = keyring
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # A collection of Ceph monitors.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def monitors(self) -> List[str]:
        return self.__monitors

    # The rados image name.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def image(self) -> str:
        return self.__image

    # Filesystem type of the volume that you want to mount.
    # Tip: Ensure that the filesystem type is supported by the host operating system.
    # Examples: "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#rbd
    # TODO: how do we prevent errors in the filesystem from compromising the machine
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # The rados pool name.
    # Default is rbd.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def pool(self) -> Optional[str]:
        return self.__pool

    # The rados user name.
    # Default is admin.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def user(self) -> Optional[str]:
        return self.__user

    # Keyring is the path to key ring for RBDUser.
    # Default is /etc/ceph/keyring.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def keyring(self) -> Optional[str]:
        return self.__keyring

    # SecretRef is name of the authentication secret for RBDUser. If provided
    # overrides keyring.
    # Default is nil.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def secretRef(self) -> Optional[LocalObjectReference]:
        return self.__secretRef

    # ReadOnly here will force the ReadOnly setting in VolumeMounts.
    # Defaults to false.
    # More info: https://examples.k8s.io/volumes/rbd/README.md#how-to-use-it
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# ScaleIOVolumeSource represents a persistent ScaleIO volume
class ScaleIOVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        gateway: str = "",
        system: str = "",
        secretRef: LocalObjectReference = None,
        sslEnabled: bool = None,
        protectionDomain: str = None,
        storagePool: str = None,
        storageMode: str = "ThinProvisioned",
        volumeName: str = None,
        fsType: str = "xfs",
        readOnly: bool = None,
    ):
        super().__init__(**{})
        self.__gateway = gateway
        self.__system = system
        self.__secretRef = secretRef
        self.__sslEnabled = sslEnabled
        self.__protectionDomain = protectionDomain
        self.__storagePool = storagePool
        self.__storageMode = storageMode
        self.__volumeName = volumeName
        self.__fsType = fsType
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["gateway"] = self.gateway()
        v["system"] = self.system()
        v["secretRef"] = self.secretRef()
        sslEnabled = self.sslEnabled()
        if sslEnabled:  # omit empty
            v["sslEnabled"] = sslEnabled
        protectionDomain = self.protectionDomain()
        if protectionDomain:  # omit empty
            v["protectionDomain"] = protectionDomain
        storagePool = self.storagePool()
        if storagePool:  # omit empty
            v["storagePool"] = storagePool
        storageMode = self.storageMode()
        if storageMode:  # omit empty
            v["storageMode"] = storageMode
        volumeName = self.volumeName()
        if volumeName:  # omit empty
            v["volumeName"] = volumeName
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    # The host address of the ScaleIO API Gateway.
    @typechecked
    def gateway(self) -> str:
        return self.__gateway

    # The name of the storage system as configured in ScaleIO.
    @typechecked
    def system(self) -> str:
        return self.__system

    # SecretRef references to the secret for ScaleIO user and other
    # sensitive information. If this is not provided, Login operation will fail.
    @typechecked
    def secretRef(self) -> Optional[LocalObjectReference]:
        return self.__secretRef

    # Flag to enable/disable SSL communication with Gateway, default false
    @typechecked
    def sslEnabled(self) -> Optional[bool]:
        return self.__sslEnabled

    # The name of the ScaleIO Protection Domain for the configured storage.
    @typechecked
    def protectionDomain(self) -> Optional[str]:
        return self.__protectionDomain

    # The ScaleIO Storage Pool associated with the protection domain.
    @typechecked
    def storagePool(self) -> Optional[str]:
        return self.__storagePool

    # Indicates whether the storage for a volume should be ThickProvisioned or ThinProvisioned.
    # Default is ThinProvisioned.
    @typechecked
    def storageMode(self) -> Optional[str]:
        return self.__storageMode

    # The name of a volume already created in the ScaleIO system
    # that is associated with this volume source.
    @typechecked
    def volumeName(self) -> Optional[str]:
        return self.__volumeName

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs".
    # Default is "xfs".
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly


# Adapts a Secret into a volume.
#
# The contents of the target Secret's Data field will be presented in a volume
# as files using the keys in the Data field as the file names.
# Secret volumes support ownership management and SELinux relabeling.
class SecretVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        secretName: str = None,
        items: List[KeyToPath] = None,
        defaultMode: int = None,
        optional: bool = None,
    ):
        super().__init__(**{})
        self.__secretName = secretName
        self.__items = items if items is not None else []
        self.__defaultMode = defaultMode if defaultMode is not None else 420
        self.__optional = optional

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secretName = self.secretName()
        if secretName:  # omit empty
            v["secretName"] = secretName
        items = self.items()
        if items:  # omit empty
            v["items"] = items
        defaultMode = self.defaultMode()
        if defaultMode is not None:  # omit empty
            v["defaultMode"] = defaultMode
        optional = self.optional()
        if optional is not None:  # omit empty
            v["optional"] = optional
        return v

    # Name of the secret in the pod's namespace to use.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#secret
    @typechecked
    def secretName(self) -> Optional[str]:
        return self.__secretName

    # If unspecified, each key-value pair in the Data field of the referenced
    # Secret will be projected into the volume as a file whose name is the
    # key and content is the value. If specified, the listed keys will be
    # projected into the specified paths, and unlisted keys will not be
    # present. If a key is specified which is not present in the Secret,
    # the volume setup will error unless it is marked optional. Paths must be
    # relative and may not contain the '..' path or start with '..'.
    @typechecked
    def items(self) -> Optional[List[KeyToPath]]:
        return self.__items

    # Optional: mode bits to use on created files by default. Must be a
    # value between 0 and 0777. Defaults to 0644.
    # Directories within the path are not affected by this setting.
    # This might be in conflict with other options that affect the file
    # mode, like fsGroup, and the result can be other mode bits set.
    @typechecked
    def defaultMode(self) -> Optional[int]:
        return self.__defaultMode

    # Specify whether the Secret or its keys must be defined
    @typechecked
    def optional(self) -> Optional[bool]:
        return self.__optional


# Represents a StorageOS persistent volume resource.
class StorageOSVolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        volumeName: str = None,
        volumeNamespace: str = None,
        fsType: str = None,
        readOnly: bool = None,
        secretRef: LocalObjectReference = None,
    ):
        super().__init__(**{})
        self.__volumeName = volumeName
        self.__volumeNamespace = volumeNamespace
        self.__fsType = fsType
        self.__readOnly = readOnly
        self.__secretRef = secretRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volumeName = self.volumeName()
        if volumeName:  # omit empty
            v["volumeName"] = volumeName
        volumeNamespace = self.volumeNamespace()
        if volumeNamespace:  # omit empty
            v["volumeNamespace"] = volumeNamespace
        fsType = self.fsType()
        if fsType:  # omit empty
            v["fsType"] = fsType
        readOnly = self.readOnly()
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        secretRef = self.secretRef()
        if secretRef is not None:  # omit empty
            v["secretRef"] = secretRef
        return v

    # VolumeName is the human-readable name of the StorageOS volume.  Volume
    # names are only unique within a namespace.
    @typechecked
    def volumeName(self) -> Optional[str]:
        return self.__volumeName

    # VolumeNamespace specifies the scope of the volume within StorageOS.  If no
    # namespace is specified then the Pod's namespace will be used.  This allows the
    # Kubernetes name scoping to be mirrored within StorageOS for tighter integration.
    # Set VolumeName to any name to override the default behaviour.
    # Set to "default" if you are not using namespaces within StorageOS.
    # Namespaces that do not pre-exist within StorageOS will be created.
    @typechecked
    def volumeNamespace(self) -> Optional[str]:
        return self.__volumeNamespace

    # Filesystem type to mount.
    # Must be a filesystem type supported by the host operating system.
    # Ex. "ext4", "xfs", "ntfs". Implicitly inferred to be "ext4" if unspecified.
    @typechecked
    def fsType(self) -> Optional[str]:
        return self.__fsType

    # Defaults to false (read/write). ReadOnly here will force
    # the ReadOnly setting in VolumeMounts.
    @typechecked
    def readOnly(self) -> Optional[bool]:
        return self.__readOnly

    # SecretRef specifies the secret to use for obtaining the StorageOS API
    # credentials.  If not specified, default values will be attempted.
    @typechecked
    def secretRef(self) -> Optional[LocalObjectReference]:
        return self.__secretRef


# Represents the source of a volume to mount.
# Only one of its members may be specified.
class VolumeSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        hostPath: HostPathVolumeSource = None,
        emptyDir: EmptyDirVolumeSource = None,
        gcePersistentDisk: GCEPersistentDiskVolumeSource = None,
        awsElasticBlockStore: AWSElasticBlockStoreVolumeSource = None,
        secret: SecretVolumeSource = None,
        nfs: NFSVolumeSource = None,
        iscsi: ISCSIVolumeSource = None,
        glusterfs: GlusterfsVolumeSource = None,
        persistentVolumeClaim: PersistentVolumeClaimVolumeSource = None,
        rbd: RBDVolumeSource = None,
        flexVolume: FlexVolumeSource = None,
        cinder: CinderVolumeSource = None,
        cephfs: CephFSVolumeSource = None,
        flocker: FlockerVolumeSource = None,
        downwardAPI: DownwardAPIVolumeSource = None,
        fc: FCVolumeSource = None,
        azureFile: AzureFileVolumeSource = None,
        configMap: ConfigMapVolumeSource = None,
        vsphereVolume: VsphereVirtualDiskVolumeSource = None,
        quobyte: QuobyteVolumeSource = None,
        azureDisk: AzureDiskVolumeSource = None,
        photonPersistentDisk: PhotonPersistentDiskVolumeSource = None,
        projected: ProjectedVolumeSource = None,
        portworxVolume: PortworxVolumeSource = None,
        scaleIO: ScaleIOVolumeSource = None,
        storageos: StorageOSVolumeSource = None,
        csi: CSIVolumeSource = None,
    ):
        super().__init__(**{})
        self.__hostPath = hostPath
        self.__emptyDir = emptyDir
        self.__gcePersistentDisk = gcePersistentDisk
        self.__awsElasticBlockStore = awsElasticBlockStore
        self.__secret = secret
        self.__nfs = nfs
        self.__iscsi = iscsi
        self.__glusterfs = glusterfs
        self.__persistentVolumeClaim = persistentVolumeClaim
        self.__rbd = rbd
        self.__flexVolume = flexVolume
        self.__cinder = cinder
        self.__cephfs = cephfs
        self.__flocker = flocker
        self.__downwardAPI = downwardAPI
        self.__fc = fc
        self.__azureFile = azureFile
        self.__configMap = configMap
        self.__vsphereVolume = vsphereVolume
        self.__quobyte = quobyte
        self.__azureDisk = azureDisk
        self.__photonPersistentDisk = photonPersistentDisk
        self.__projected = projected
        self.__portworxVolume = portworxVolume
        self.__scaleIO = scaleIO
        self.__storageos = storageos
        self.__csi = csi

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        hostPath = self.hostPath()
        if hostPath is not None:  # omit empty
            v["hostPath"] = hostPath
        emptyDir = self.emptyDir()
        if emptyDir is not None:  # omit empty
            v["emptyDir"] = emptyDir
        gcePersistentDisk = self.gcePersistentDisk()
        if gcePersistentDisk is not None:  # omit empty
            v["gcePersistentDisk"] = gcePersistentDisk
        awsElasticBlockStore = self.awsElasticBlockStore()
        if awsElasticBlockStore is not None:  # omit empty
            v["awsElasticBlockStore"] = awsElasticBlockStore
        secret = self.secret()
        if secret is not None:  # omit empty
            v["secret"] = secret
        nfs = self.nfs()
        if nfs is not None:  # omit empty
            v["nfs"] = nfs
        iscsi = self.iscsi()
        if iscsi is not None:  # omit empty
            v["iscsi"] = iscsi
        glusterfs = self.glusterfs()
        if glusterfs is not None:  # omit empty
            v["glusterfs"] = glusterfs
        persistentVolumeClaim = self.persistentVolumeClaim()
        if persistentVolumeClaim is not None:  # omit empty
            v["persistentVolumeClaim"] = persistentVolumeClaim
        rbd = self.rbd()
        if rbd is not None:  # omit empty
            v["rbd"] = rbd
        flexVolume = self.flexVolume()
        if flexVolume is not None:  # omit empty
            v["flexVolume"] = flexVolume
        cinder = self.cinder()
        if cinder is not None:  # omit empty
            v["cinder"] = cinder
        cephfs = self.cephfs()
        if cephfs is not None:  # omit empty
            v["cephfs"] = cephfs
        flocker = self.flocker()
        if flocker is not None:  # omit empty
            v["flocker"] = flocker
        downwardAPI = self.downwardAPI()
        if downwardAPI is not None:  # omit empty
            v["downwardAPI"] = downwardAPI
        fc = self.fc()
        if fc is not None:  # omit empty
            v["fc"] = fc
        azureFile = self.azureFile()
        if azureFile is not None:  # omit empty
            v["azureFile"] = azureFile
        configMap = self.configMap()
        if configMap is not None:  # omit empty
            v["configMap"] = configMap
        vsphereVolume = self.vsphereVolume()
        if vsphereVolume is not None:  # omit empty
            v["vsphereVolume"] = vsphereVolume
        quobyte = self.quobyte()
        if quobyte is not None:  # omit empty
            v["quobyte"] = quobyte
        azureDisk = self.azureDisk()
        if azureDisk is not None:  # omit empty
            v["azureDisk"] = azureDisk
        photonPersistentDisk = self.photonPersistentDisk()
        if photonPersistentDisk is not None:  # omit empty
            v["photonPersistentDisk"] = photonPersistentDisk
        projected = self.projected()
        if projected is not None:  # omit empty
            v["projected"] = projected
        portworxVolume = self.portworxVolume()
        if portworxVolume is not None:  # omit empty
            v["portworxVolume"] = portworxVolume
        scaleIO = self.scaleIO()
        if scaleIO is not None:  # omit empty
            v["scaleIO"] = scaleIO
        storageos = self.storageos()
        if storageos is not None:  # omit empty
            v["storageos"] = storageos
        csi = self.csi()
        if csi is not None:  # omit empty
            v["csi"] = csi
        return v

    # HostPath represents a pre-existing file or directory on the host
    # machine that is directly exposed to the container. This is generally
    # used for system agents or other privileged things that are allowed
    # to see the host machine. Most containers will NOT need this.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#hostpath
    # ---
    # TODO(jonesdl) We need to restrict who can use host directory mounts and who can/can not
    # mount host directories as read/write.
    @typechecked
    def hostPath(self) -> Optional[HostPathVolumeSource]:
        return self.__hostPath

    # EmptyDir represents a temporary directory that shares a pod's lifetime.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#emptydir
    @typechecked
    def emptyDir(self) -> Optional[EmptyDirVolumeSource]:
        return self.__emptyDir

    # GCEPersistentDisk represents a GCE Disk resource that is attached to a
    # kubelet's host machine and then exposed to the pod.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#gcepersistentdisk
    @typechecked
    def gcePersistentDisk(self) -> Optional[GCEPersistentDiskVolumeSource]:
        return self.__gcePersistentDisk

    # AWSElasticBlockStore represents an AWS Disk resource that is attached to a
    # kubelet's host machine and then exposed to the pod.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#awselasticblockstore
    @typechecked
    def awsElasticBlockStore(self) -> Optional[AWSElasticBlockStoreVolumeSource]:
        return self.__awsElasticBlockStore

    # Secret represents a secret that should populate this volume.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#secret
    @typechecked
    def secret(self) -> Optional[SecretVolumeSource]:
        return self.__secret

    # NFS represents an NFS mount on the host that shares a pod's lifetime
    # More info: https://kubernetes.io/docs/concepts/storage/volumes#nfs
    @typechecked
    def nfs(self) -> Optional[NFSVolumeSource]:
        return self.__nfs

    # ISCSI represents an ISCSI Disk resource that is attached to a
    # kubelet's host machine and then exposed to the pod.
    # More info: https://examples.k8s.io/volumes/iscsi/README.md
    @typechecked
    def iscsi(self) -> Optional[ISCSIVolumeSource]:
        return self.__iscsi

    # Glusterfs represents a Glusterfs mount on the host that shares a pod's lifetime.
    # More info: https://examples.k8s.io/volumes/glusterfs/README.md
    @typechecked
    def glusterfs(self) -> Optional[GlusterfsVolumeSource]:
        return self.__glusterfs

    # PersistentVolumeClaimVolumeSource represents a reference to a
    # PersistentVolumeClaim in the same namespace.
    # More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims
    @typechecked
    def persistentVolumeClaim(self) -> Optional[PersistentVolumeClaimVolumeSource]:
        return self.__persistentVolumeClaim

    # RBD represents a Rados Block Device mount on the host that shares a pod's lifetime.
    # More info: https://examples.k8s.io/volumes/rbd/README.md
    @typechecked
    def rbd(self) -> Optional[RBDVolumeSource]:
        return self.__rbd

    # FlexVolume represents a generic volume resource that is
    # provisioned/attached using an exec based plugin.
    @typechecked
    def flexVolume(self) -> Optional[FlexVolumeSource]:
        return self.__flexVolume

    # Cinder represents a cinder volume attached and mounted on kubelets host machine.
    # More info: https://examples.k8s.io/mysql-cinder-pd/README.md
    @typechecked
    def cinder(self) -> Optional[CinderVolumeSource]:
        return self.__cinder

    # CephFS represents a Ceph FS mount on the host that shares a pod's lifetime
    @typechecked
    def cephfs(self) -> Optional[CephFSVolumeSource]:
        return self.__cephfs

    # Flocker represents a Flocker volume attached to a kubelet's host machine. This depends on the Flocker control service being running
    @typechecked
    def flocker(self) -> Optional[FlockerVolumeSource]:
        return self.__flocker

    # DownwardAPI represents downward API about the pod that should populate this volume
    @typechecked
    def downwardAPI(self) -> Optional[DownwardAPIVolumeSource]:
        return self.__downwardAPI

    # FC represents a Fibre Channel resource that is attached to a kubelet's host machine and then exposed to the pod.
    @typechecked
    def fc(self) -> Optional[FCVolumeSource]:
        return self.__fc

    # AzureFile represents an Azure File Service mount on the host and bind mount to the pod.
    @typechecked
    def azureFile(self) -> Optional[AzureFileVolumeSource]:
        return self.__azureFile

    # ConfigMap represents a configMap that should populate this volume
    @typechecked
    def configMap(self) -> Optional[ConfigMapVolumeSource]:
        return self.__configMap

    # VsphereVolume represents a vSphere volume attached and mounted on kubelets host machine
    @typechecked
    def vsphereVolume(self) -> Optional[VsphereVirtualDiskVolumeSource]:
        return self.__vsphereVolume

    # Quobyte represents a Quobyte mount on the host that shares a pod's lifetime
    @typechecked
    def quobyte(self) -> Optional[QuobyteVolumeSource]:
        return self.__quobyte

    # AzureDisk represents an Azure Data Disk mount on the host and bind mount to the pod.
    @typechecked
    def azureDisk(self) -> Optional[AzureDiskVolumeSource]:
        return self.__azureDisk

    # PhotonPersistentDisk represents a PhotonController persistent disk attached and mounted on kubelets host machine
    @typechecked
    def photonPersistentDisk(self) -> Optional[PhotonPersistentDiskVolumeSource]:
        return self.__photonPersistentDisk

    # Items for all in one resources secrets, configmaps, and downward API
    @typechecked
    def projected(self) -> Optional[ProjectedVolumeSource]:
        return self.__projected

    # PortworxVolume represents a portworx volume attached and mounted on kubelets host machine
    @typechecked
    def portworxVolume(self) -> Optional[PortworxVolumeSource]:
        return self.__portworxVolume

    # ScaleIO represents a ScaleIO persistent volume attached and mounted on Kubernetes nodes.
    @typechecked
    def scaleIO(self) -> Optional[ScaleIOVolumeSource]:
        return self.__scaleIO

    # StorageOS represents a StorageOS volume attached and mounted on Kubernetes nodes.
    @typechecked
    def storageos(self) -> Optional[StorageOSVolumeSource]:
        return self.__storageos

    # CSI (Container Storage Interface) represents storage that is handled by an external CSI driver (Alpha feature).
    @typechecked
    def csi(self) -> Optional[CSIVolumeSource]:
        return self.__csi


# Volume represents a named volume in a pod that may be accessed by any container in the pod.
class Volume(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = "", volumeSource: VolumeSource = None):
        super().__init__(**{})
        self.__name = name
        self.__volumeSource = (
            volumeSource if volumeSource is not None else VolumeSource()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        v.update(self.volumeSource()._root())  # inline
        return v

    # Volume's name.
    # Must be a DNS_LABEL and unique within the pod.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    @typechecked
    def name(self) -> str:
        return self.__name

    # VolumeSource represents the location and type of the mounted volume.
    # If not specified, the Volume is implied to be an EmptyDir.
    # This implied behavior is deprecated and will be removed in a future version.
    @typechecked
    def volumeSource(self) -> VolumeSource:
        return self.__volumeSource


# PodSpec is a description of a pod.
class PodSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        volumes: Dict[str, Volume] = None,
        initContainers: Dict[str, Container] = None,
        containers: Dict[str, Container] = None,
        ephemeralContainers: List[EphemeralContainer] = None,
        restartPolicy: RestartPolicy = RestartPolicy["Always"],
        terminationGracePeriodSeconds: int = None,
        activeDeadlineSeconds: int = None,
        dnsPolicy: DNSPolicy = DNSPolicy["ClusterFirst"],
        nodeSelector: Dict[str, str] = None,
        serviceAccountName: str = None,
        automountServiceAccountToken: bool = None,
        nodeName: str = None,
        hostNetwork: bool = None,
        hostPID: bool = None,
        hostIPC: bool = None,
        shareProcessNamespace: bool = None,
        securityContext: PodSecurityContext = None,
        imagePullSecrets: Dict[str, LocalObjectReference] = None,
        hostname: str = None,
        subdomain: str = None,
        affinity: Affinity = None,
        schedulerName: str = "default-scheduler",
        tolerations: List[Toleration] = None,
        hostAliases: List[HostAlias] = None,
        priorityClassName: str = None,
        priority: int = None,
        dnsConfig: PodDNSConfig = None,
        readinessGates: List[PodReadinessGate] = None,
        runtimeClassName: str = None,
        enableServiceLinks: bool = None,
        preemptionPolicy: PreemptionPolicy = None,
        overhead: Dict[ResourceName, "resource.Quantity"] = None,
        topologySpreadConstraints: List[TopologySpreadConstraint] = None,
    ):
        super().__init__(**{})
        self.__volumes = volumes if volumes is not None else {}
        self.__initContainers = initContainers if initContainers is not None else {}
        self.__containers = containers if containers is not None else {}
        self.__ephemeralContainers = (
            ephemeralContainers if ephemeralContainers is not None else []
        )
        self.__restartPolicy = restartPolicy
        self.__terminationGracePeriodSeconds = (
            terminationGracePeriodSeconds
            if terminationGracePeriodSeconds is not None
            else 30
        )
        self.__activeDeadlineSeconds = activeDeadlineSeconds
        self.__dnsPolicy = dnsPolicy
        self.__nodeSelector = nodeSelector if nodeSelector is not None else {}
        self.__serviceAccountName = serviceAccountName
        self.__automountServiceAccountToken = automountServiceAccountToken
        self.__nodeName = nodeName
        self.__hostNetwork = hostNetwork
        self.__hostPID = hostPID
        self.__hostIPC = hostIPC
        self.__shareProcessNamespace = shareProcessNamespace
        self.__securityContext = securityContext
        self.__imagePullSecrets = (
            imagePullSecrets if imagePullSecrets is not None else {}
        )
        self.__hostname = hostname
        self.__subdomain = subdomain
        self.__affinity = affinity
        self.__schedulerName = schedulerName
        self.__tolerations = tolerations if tolerations is not None else []
        self.__hostAliases = hostAliases if hostAliases is not None else []
        self.__priorityClassName = priorityClassName
        self.__priority = priority
        self.__dnsConfig = dnsConfig
        self.__readinessGates = readinessGates if readinessGates is not None else []
        self.__runtimeClassName = runtimeClassName
        self.__enableServiceLinks = enableServiceLinks
        self.__preemptionPolicy = preemptionPolicy
        self.__overhead = overhead if overhead is not None else {}
        self.__topologySpreadConstraints = (
            topologySpreadConstraints if topologySpreadConstraints is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        volumes = self.volumes()
        if volumes:  # omit empty
            v["volumes"] = volumes.values()  # named list
        initContainers = self.initContainers()
        if initContainers:  # omit empty
            v["initContainers"] = initContainers.values()  # named list
        v["containers"] = self.containers().values()  # named list
        ephemeralContainers = self.ephemeralContainers()
        if ephemeralContainers:  # omit empty
            v["ephemeralContainers"] = ephemeralContainers
        restartPolicy = self.restartPolicy()
        if restartPolicy:  # omit empty
            v["restartPolicy"] = restartPolicy
        terminationGracePeriodSeconds = self.terminationGracePeriodSeconds()
        if terminationGracePeriodSeconds is not None:  # omit empty
            v["terminationGracePeriodSeconds"] = terminationGracePeriodSeconds
        activeDeadlineSeconds = self.activeDeadlineSeconds()
        if activeDeadlineSeconds is not None:  # omit empty
            v["activeDeadlineSeconds"] = activeDeadlineSeconds
        dnsPolicy = self.dnsPolicy()
        if dnsPolicy:  # omit empty
            v["dnsPolicy"] = dnsPolicy
        nodeSelector = self.nodeSelector()
        if nodeSelector:  # omit empty
            v["nodeSelector"] = nodeSelector
        serviceAccountName = self.serviceAccountName()
        if serviceAccountName:  # omit empty
            v["serviceAccountName"] = serviceAccountName
        automountServiceAccountToken = self.automountServiceAccountToken()
        if automountServiceAccountToken is not None:  # omit empty
            v["automountServiceAccountToken"] = automountServiceAccountToken
        nodeName = self.nodeName()
        if nodeName:  # omit empty
            v["nodeName"] = nodeName
        hostNetwork = self.hostNetwork()
        if hostNetwork:  # omit empty
            v["hostNetwork"] = hostNetwork
        hostPID = self.hostPID()
        if hostPID:  # omit empty
            v["hostPID"] = hostPID
        hostIPC = self.hostIPC()
        if hostIPC:  # omit empty
            v["hostIPC"] = hostIPC
        shareProcessNamespace = self.shareProcessNamespace()
        if shareProcessNamespace is not None:  # omit empty
            v["shareProcessNamespace"] = shareProcessNamespace
        securityContext = self.securityContext()
        if securityContext is not None:  # omit empty
            v["securityContext"] = securityContext
        imagePullSecrets = self.imagePullSecrets()
        if imagePullSecrets:  # omit empty
            v["imagePullSecrets"] = imagePullSecrets.values()  # named list
        hostname = self.hostname()
        if hostname:  # omit empty
            v["hostname"] = hostname
        subdomain = self.subdomain()
        if subdomain:  # omit empty
            v["subdomain"] = subdomain
        affinity = self.affinity()
        if affinity is not None:  # omit empty
            v["affinity"] = affinity
        schedulerName = self.schedulerName()
        if schedulerName:  # omit empty
            v["schedulerName"] = schedulerName
        tolerations = self.tolerations()
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        hostAliases = self.hostAliases()
        if hostAliases:  # omit empty
            v["hostAliases"] = hostAliases
        priorityClassName = self.priorityClassName()
        if priorityClassName:  # omit empty
            v["priorityClassName"] = priorityClassName
        priority = self.priority()
        if priority is not None:  # omit empty
            v["priority"] = priority
        dnsConfig = self.dnsConfig()
        if dnsConfig is not None:  # omit empty
            v["dnsConfig"] = dnsConfig
        readinessGates = self.readinessGates()
        if readinessGates:  # omit empty
            v["readinessGates"] = readinessGates
        runtimeClassName = self.runtimeClassName()
        if runtimeClassName is not None:  # omit empty
            v["runtimeClassName"] = runtimeClassName
        enableServiceLinks = self.enableServiceLinks()
        if enableServiceLinks is not None:  # omit empty
            v["enableServiceLinks"] = enableServiceLinks
        preemptionPolicy = self.preemptionPolicy()
        if preemptionPolicy is not None:  # omit empty
            v["preemptionPolicy"] = preemptionPolicy
        overhead = self.overhead()
        if overhead:  # omit empty
            v["overhead"] = overhead
        topologySpreadConstraints = self.topologySpreadConstraints()
        if topologySpreadConstraints:  # omit empty
            v["topologySpreadConstraints"] = topologySpreadConstraints
        return v

    # List of volumes that can be mounted by containers belonging to the pod.
    # More info: https://kubernetes.io/docs/concepts/storage/volumes
    @typechecked
    def volumes(self) -> Optional[Dict[str, Volume]]:
        return self.__volumes

    # List of initialization containers belonging to the pod.
    # Init containers are executed in order prior to containers being started. If any
    # init container fails, the pod is considered to have failed and is handled according
    # to its restartPolicy. The name for an init container or normal container must be
    # unique among all containers.
    # Init containers may not have Lifecycle actions, Readiness probes, Liveness probes, or Startup probes.
    # The resourceRequirements of an init container are taken into account during scheduling
    # by finding the highest request/limit for each resource type, and then using the max of
    # of that value or the sum of the normal containers. Limits are applied to init containers
    # in a similar fashion.
    # Init containers cannot currently be added or removed.
    # Cannot be updated.
    # More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
    @typechecked
    def initContainers(self) -> Optional[Dict[str, Container]]:
        return self.__initContainers

    # List of containers belonging to the pod.
    # Containers cannot currently be added or removed.
    # There must be at least one container in a Pod.
    # Cannot be updated.
    @typechecked
    def containers(self) -> Dict[str, Container]:
        return self.__containers

    # List of ephemeral containers run in this pod. Ephemeral containers may be run in an existing
    # pod to perform user-initiated actions such as debugging. This list cannot be specified when
    # creating a pod, and it cannot be modified by updating the pod spec. In order to add an
    # ephemeral container to an existing pod, use the pod's ephemeralcontainers subresource.
    # This field is alpha-level and is only honored by servers that enable the EphemeralContainers feature.
    @typechecked
    def ephemeralContainers(self) -> Optional[List[EphemeralContainer]]:
        return self.__ephemeralContainers

    # Restart policy for all containers within the pod.
    # One of Always, OnFailure, Never.
    # Default to Always.
    # More info: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#restart-policy
    @typechecked
    def restartPolicy(self) -> Optional[RestartPolicy]:
        return self.__restartPolicy

    # Optional duration in seconds the pod needs to terminate gracefully. May be decreased in delete request.
    # Value must be non-negative integer. The value zero indicates delete immediately.
    # If this value is nil, the default grace period will be used instead.
    # The grace period is the duration in seconds after the processes running in the pod are sent
    # a termination signal and the time when the processes are forcibly halted with a kill signal.
    # Set this value longer than the expected cleanup time for your process.
    # Defaults to 30 seconds.
    @typechecked
    def terminationGracePeriodSeconds(self) -> Optional[int]:
        return self.__terminationGracePeriodSeconds

    # Optional duration in seconds the pod may be active on the node relative to
    # StartTime before the system will actively try to mark it failed and kill associated containers.
    # Value must be a positive integer.
    @typechecked
    def activeDeadlineSeconds(self) -> Optional[int]:
        return self.__activeDeadlineSeconds

    # Set DNS policy for the pod.
    # Defaults to "ClusterFirst".
    # Valid values are 'ClusterFirstWithHostNet', 'ClusterFirst', 'Default' or 'None'.
    # DNS parameters given in DNSConfig will be merged with the policy selected with DNSPolicy.
    # To have DNS options set along with hostNetwork, you have to specify DNS policy
    # explicitly to 'ClusterFirstWithHostNet'.
    @typechecked
    def dnsPolicy(self) -> Optional[DNSPolicy]:
        return self.__dnsPolicy

    # NodeSelector is a selector which must be true for the pod to fit on a node.
    # Selector which must match a node's labels for the pod to be scheduled on that node.
    # More info: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
    @typechecked
    def nodeSelector(self) -> Optional[Dict[str, str]]:
        return self.__nodeSelector

    # ServiceAccountName is the name of the ServiceAccount to use to run this pod.
    # More info: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
    @typechecked
    def serviceAccountName(self) -> Optional[str]:
        return self.__serviceAccountName

    # AutomountServiceAccountToken indicates whether a service account token should be automatically mounted.
    @typechecked
    def automountServiceAccountToken(self) -> Optional[bool]:
        return self.__automountServiceAccountToken

    # NodeName is a request to schedule this pod onto a specific node. If it is non-empty,
    # the scheduler simply schedules this pod onto that node, assuming that it fits resource
    # requirements.
    @typechecked
    def nodeName(self) -> Optional[str]:
        return self.__nodeName

    # Host networking requested for this pod. Use the host's network namespace.
    # If this option is set, the ports that will be used must be specified.
    # Default to false.
    @typechecked
    def hostNetwork(self) -> Optional[bool]:
        return self.__hostNetwork

    # Use the host's pid namespace.
    # Optional: Default to false.
    @typechecked
    def hostPID(self) -> Optional[bool]:
        return self.__hostPID

    # Use the host's ipc namespace.
    # Optional: Default to false.
    @typechecked
    def hostIPC(self) -> Optional[bool]:
        return self.__hostIPC

    # Share a single process namespace between all of the containers in a pod.
    # When this is set containers will be able to view and signal processes from other containers
    # in the same pod, and the first process in each container will not be assigned PID 1.
    # HostPID and ShareProcessNamespace cannot both be set.
    # Optional: Default to false.
    # This field is beta-level and may be disabled with the PodShareProcessNamespace feature.
    @typechecked
    def shareProcessNamespace(self) -> Optional[bool]:
        return self.__shareProcessNamespace

    # SecurityContext holds pod-level security attributes and common container settings.
    # Optional: Defaults to empty.  See type description for default values of each field.
    @typechecked
    def securityContext(self) -> Optional[PodSecurityContext]:
        return self.__securityContext

    # ImagePullSecrets is an optional list of references to secrets in the same namespace to use for pulling any of the images used by this PodSpec.
    # If specified, these secrets will be passed to individual puller implementations for them to use. For example,
    # in the case of docker, only DockerConfig type secrets are honored.
    # More info: https://kubernetes.io/docs/concepts/containers/images#specifying-imagepullsecrets-on-a-pod
    @typechecked
    def imagePullSecrets(self) -> Optional[Dict[str, LocalObjectReference]]:
        return self.__imagePullSecrets

    # Specifies the hostname of the Pod
    # If not specified, the pod's hostname will be set to a system-defined value.
    @typechecked
    def hostname(self) -> Optional[str]:
        return self.__hostname

    # If specified, the fully qualified Pod hostname will be "<hostname>.<subdomain>.<pod namespace>.svc.<cluster domain>".
    # If not specified, the pod will not have a domainname at all.
    @typechecked
    def subdomain(self) -> Optional[str]:
        return self.__subdomain

    # If specified, the pod's scheduling constraints
    @typechecked
    def affinity(self) -> Optional[Affinity]:
        return self.__affinity

    # If specified, the pod will be dispatched by specified scheduler.
    # If not specified, the pod will be dispatched by default scheduler.
    @typechecked
    def schedulerName(self) -> Optional[str]:
        return self.__schedulerName

    # If specified, the pod's tolerations.
    @typechecked
    def tolerations(self) -> Optional[List[Toleration]]:
        return self.__tolerations

    # HostAliases is an optional list of hosts and IPs that will be injected into the pod's hosts
    # file if specified. This is only valid for non-hostNetwork pods.
    @typechecked
    def hostAliases(self) -> Optional[List[HostAlias]]:
        return self.__hostAliases

    # If specified, indicates the pod's priority. "system-node-critical" and
    # "system-cluster-critical" are two special keywords which indicate the
    # highest priorities with the former being the highest priority. Any other
    # name must be defined by creating a PriorityClass object with that name.
    # If not specified, the pod priority will be default or zero if there is no
    # default.
    @typechecked
    def priorityClassName(self) -> Optional[str]:
        return self.__priorityClassName

    # The priority value. Various system components use this field to find the
    # priority of the pod. When Priority Admission Controller is enabled, it
    # prevents users from setting this field. The admission controller populates
    # this field from PriorityClassName.
    # The higher the value, the higher the priority.
    @typechecked
    def priority(self) -> Optional[int]:
        return self.__priority

    # Specifies the DNS parameters of a pod.
    # Parameters specified here will be merged to the generated DNS
    # configuration based on DNSPolicy.
    @typechecked
    def dnsConfig(self) -> Optional[PodDNSConfig]:
        return self.__dnsConfig

    # If specified, all readiness gates will be evaluated for pod readiness.
    # A pod is ready when all its containers are ready AND
    # all conditions specified in the readiness gates have status equal to "True"
    # More info: https://git.k8s.io/enhancements/keps/sig-network/0007-pod-ready%2B%2B.md
    @typechecked
    def readinessGates(self) -> Optional[List[PodReadinessGate]]:
        return self.__readinessGates

    # RuntimeClassName refers to a RuntimeClass object in the node.k8s.io group, which should be used
    # to run this pod.  If no RuntimeClass resource matches the named class, the pod will not be run.
    # If unset or empty, the "legacy" RuntimeClass will be used, which is an implicit class with an
    # empty definition that uses the default runtime handler.
    # More info: https://git.k8s.io/enhancements/keps/sig-node/runtime-class.md
    # This is a beta feature as of Kubernetes v1.14.
    @typechecked
    def runtimeClassName(self) -> Optional[str]:
        return self.__runtimeClassName

    # EnableServiceLinks indicates whether information about services should be injected into pod's
    # environment variables, matching the syntax of Docker links.
    # Optional: Defaults to true.
    @typechecked
    def enableServiceLinks(self) -> Optional[bool]:
        return self.__enableServiceLinks

    # PreemptionPolicy is the Policy for preempting pods with lower priority.
    # One of Never, PreemptLowerPriority.
    # Defaults to PreemptLowerPriority if unset.
    # This field is alpha-level and is only honored by servers that enable the NonPreemptingPriority feature.
    @typechecked
    def preemptionPolicy(self) -> Optional[PreemptionPolicy]:
        return self.__preemptionPolicy

    # Overhead represents the resource overhead associated with running a pod for a given RuntimeClass.
    # This field will be autopopulated at admission time by the RuntimeClass admission controller. If
    # the RuntimeClass admission controller is enabled, overhead must not be set in Pod create requests.
    # The RuntimeClass admission controller will reject Pod create requests which have the overhead already
    # set. If RuntimeClass is configured and selected in the PodSpec, Overhead will be set to the value
    # defined in the corresponding RuntimeClass, otherwise it will remain unset and treated as zero.
    # More info: https://git.k8s.io/enhancements/keps/sig-node/20190226-pod-overhead.md
    # This field is alpha-level as of Kubernetes v1.16, and is only honored by servers that enable the PodOverhead feature.
    @typechecked
    def overhead(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        return self.__overhead

    # TopologySpreadConstraints describes how a group of pods ought to spread across topology
    # domains. Scheduler will schedule pods in a way which abides by the constraints.
    # This field is alpha-level and is only honored by clusters that enables the EvenPodsSpread
    # feature.
    # All topologySpreadConstraints are ANDed.
    # +listType=map
    # +listMapKey=topologyKey
    # +listMapKey=whenUnsatisfiable
    @typechecked
    def topologySpreadConstraints(self) -> Optional[List[TopologySpreadConstraint]]:
        return self.__topologySpreadConstraints


# Pod is a collection of containers that can run on a host. This resource is created
# by clients and scheduled onto hosts.
class Pod(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: PodSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "Pod",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else PodSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Specification of the desired behavior of the pod.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> Optional[PodSpec]:
        return self.__spec


# PodAttachOptions is the query options to a Pod's remote attach call.
# ---
# TODO: merge w/ PodExecOptions below for stdin, stdout, etc
# and also when we cut V2, we should export a "StreamOptions" or somesuch that contains Stdin, Stdout, Stder and TTY
class PodAttachOptions(base.TypedObject):
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
        super().__init__(**{"apiVersion": "v1", "kind": "PodAttachOptions"})
        self.__stdin = stdin
        self.__stdout = stdout
        self.__stderr = stderr
        self.__tty = tty
        self.__container = container

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        stdin = self.stdin()
        if stdin:  # omit empty
            v["stdin"] = stdin
        stdout = self.stdout()
        if stdout:  # omit empty
            v["stdout"] = stdout
        stderr = self.stderr()
        if stderr:  # omit empty
            v["stderr"] = stderr
        tty = self.tty()
        if tty:  # omit empty
            v["tty"] = tty
        container = self.container()
        if container:  # omit empty
            v["container"] = container
        return v

    # Stdin if true, redirects the standard input stream of the pod for this call.
    # Defaults to false.
    @typechecked
    def stdin(self) -> Optional[bool]:
        return self.__stdin

    # Stdout if true indicates that stdout is to be redirected for the attach call.
    # Defaults to true.
    @typechecked
    def stdout(self) -> Optional[bool]:
        return self.__stdout

    # Stderr if true indicates that stderr is to be redirected for the attach call.
    # Defaults to true.
    @typechecked
    def stderr(self) -> Optional[bool]:
        return self.__stderr

    # TTY if true indicates that a tty will be allocated for the attach call.
    # This is passed through the container runtime so the tty
    # is allocated on the worker node by the container runtime.
    # Defaults to false.
    @typechecked
    def tty(self) -> Optional[bool]:
        return self.__tty

    # The container in which to execute the command.
    # Defaults to only container if there is only one container in the pod.
    @typechecked
    def container(self) -> Optional[str]:
        return self.__container


# PodExecOptions is the query options to a Pod's remote exec call.
# ---
# TODO: This is largely identical to PodAttachOptions above, make sure they stay in sync and see about merging
# and also when we cut V2, we should export a "StreamOptions" or somesuch that contains Stdin, Stdout, Stder and TTY
class PodExecOptions(base.TypedObject):
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
        super().__init__(**{"apiVersion": "v1", "kind": "PodExecOptions"})
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
        if stdin:  # omit empty
            v["stdin"] = stdin
        stdout = self.stdout()
        if stdout:  # omit empty
            v["stdout"] = stdout
        stderr = self.stderr()
        if stderr:  # omit empty
            v["stderr"] = stderr
        tty = self.tty()
        if tty:  # omit empty
            v["tty"] = tty
        container = self.container()
        if container:  # omit empty
            v["container"] = container
        v["command"] = self.command()
        return v

    # Redirect the standard input stream of the pod for this call.
    # Defaults to false.
    @typechecked
    def stdin(self) -> Optional[bool]:
        return self.__stdin

    # Redirect the standard output stream of the pod for this call.
    # Defaults to true.
    @typechecked
    def stdout(self) -> Optional[bool]:
        return self.__stdout

    # Redirect the standard error stream of the pod for this call.
    # Defaults to true.
    @typechecked
    def stderr(self) -> Optional[bool]:
        return self.__stderr

    # TTY if true indicates that a tty will be allocated for the exec call.
    # Defaults to false.
    @typechecked
    def tty(self) -> Optional[bool]:
        return self.__tty

    # Container in which to execute the command.
    # Defaults to only container if there is only one container in the pod.
    @typechecked
    def container(self) -> Optional[str]:
        return self.__container

    # Command is the remote command to execute. argv array. Not executed within a shell.
    @typechecked
    def command(self) -> List[str]:
        return self.__command


# PodLogOptions is the query options for a Pod's logs REST call.
class PodLogOptions(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        container: str = None,
        follow: bool = None,
        previous: bool = None,
        sinceSeconds: int = None,
        sinceTime: "base.Time" = None,
        timestamps: bool = None,
        tailLines: int = None,
        limitBytes: int = None,
    ):
        super().__init__(**{"apiVersion": "v1", "kind": "PodLogOptions"})
        self.__container = container
        self.__follow = follow
        self.__previous = previous
        self.__sinceSeconds = sinceSeconds
        self.__sinceTime = sinceTime
        self.__timestamps = timestamps
        self.__tailLines = tailLines
        self.__limitBytes = limitBytes

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        container = self.container()
        if container:  # omit empty
            v["container"] = container
        follow = self.follow()
        if follow:  # omit empty
            v["follow"] = follow
        previous = self.previous()
        if previous:  # omit empty
            v["previous"] = previous
        sinceSeconds = self.sinceSeconds()
        if sinceSeconds is not None:  # omit empty
            v["sinceSeconds"] = sinceSeconds
        sinceTime = self.sinceTime()
        if sinceTime is not None:  # omit empty
            v["sinceTime"] = sinceTime
        timestamps = self.timestamps()
        if timestamps:  # omit empty
            v["timestamps"] = timestamps
        tailLines = self.tailLines()
        if tailLines is not None:  # omit empty
            v["tailLines"] = tailLines
        limitBytes = self.limitBytes()
        if limitBytes is not None:  # omit empty
            v["limitBytes"] = limitBytes
        return v

    # The container for which to stream logs. Defaults to only container if there is one container in the pod.
    @typechecked
    def container(self) -> Optional[str]:
        return self.__container

    # Follow the log stream of the pod. Defaults to false.
    @typechecked
    def follow(self) -> Optional[bool]:
        return self.__follow

    # Return previous terminated container logs. Defaults to false.
    @typechecked
    def previous(self) -> Optional[bool]:
        return self.__previous

    # A relative time in seconds before the current time from which to show logs. If this value
    # precedes the time a pod was started, only logs since the pod start will be returned.
    # If this value is in the future, no logs will be returned.
    # Only one of sinceSeconds or sinceTime may be specified.
    @typechecked
    def sinceSeconds(self) -> Optional[int]:
        return self.__sinceSeconds

    # An RFC3339 timestamp from which to show logs. If this value
    # precedes the time a pod was started, only logs since the pod start will be returned.
    # If this value is in the future, no logs will be returned.
    # Only one of sinceSeconds or sinceTime may be specified.
    @typechecked
    def sinceTime(self) -> Optional["base.Time"]:
        return self.__sinceTime

    # If true, add an RFC3339 or RFC3339Nano timestamp at the beginning of every line
    # of log output. Defaults to false.
    @typechecked
    def timestamps(self) -> Optional[bool]:
        return self.__timestamps

    # If set, the number of lines from the end of the logs to show. If not specified,
    # logs are shown from the creation of the container or sinceSeconds or sinceTime
    @typechecked
    def tailLines(self) -> Optional[int]:
        return self.__tailLines

    # If set, the number of bytes to read from the server before terminating the
    # log output. This may not display a complete final line of logging, and may return
    # slightly more or slightly less than the specified limit.
    @typechecked
    def limitBytes(self) -> Optional[int]:
        return self.__limitBytes


# PodPortForwardOptions is the query options to a Pod's port forward call
# when using WebSockets.
# The `port` query parameter must specify the port or
# ports (comma separated) to forward over.
# Port forwarding over SPDY does not use these options. It requires the port
# to be passed in the `port` header as part of request.
class PodPortForwardOptions(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(self, ports: List[int] = None):
        super().__init__(**{"apiVersion": "v1", "kind": "PodPortForwardOptions"})
        self.__ports = ports if ports is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ports = self.ports()
        if ports:  # omit empty
            v["ports"] = ports
        return v

    # List of ports to forward
    # Required when using WebSockets
    @typechecked
    def ports(self) -> Optional[List[int]]:
        return self.__ports


# PodProxyOptions is the query options to a Pod's proxy call.
class PodProxyOptions(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(self, path: str = None):
        super().__init__(**{"apiVersion": "v1", "kind": "PodProxyOptions"})
        self.__path = path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        if path:  # omit empty
            v["path"] = path
        return v

    # Path is the URL path to use for the current proxy request to pod.
    @typechecked
    def path(self) -> Optional[str]:
        return self.__path


# PodStatusResult is a wrapper for PodStatus returned by kubelet that can be encode/decoded
class PodStatusResult(base.TypedObject, base.NamespacedMetadataObject):
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
            **{
                "apiVersion": "v1",
                "kind": "PodStatusResult",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        return v


# PodTemplateSpec describes the data a pod should have when created from a template
class PodTemplateSpec(base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: PodSpec = None,
    ):
        super().__init__(
            **{
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else PodSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Specification of the desired behavior of the pod.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> Optional[PodSpec]:
        return self.__spec


# PodTemplate describes a template for creating copies of a predefined pod.
class PodTemplate(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        template: PodTemplateSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "PodTemplate",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__template = template if template is not None else PodTemplateSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["template"] = self.template()
        return v

    # Template defines the pods that will be created from this pod template.
    # https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def template(self) -> Optional[PodTemplateSpec]:
        return self.__template


# RangeAllocation is not a public type.
class RangeAllocation(base.TypedObject, base.NamespacedMetadataObject):
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
            **{
                "apiVersion": "v1",
                "kind": "RangeAllocation",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__range = range
        self.__data = data if data is not None else b""

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["range"] = self.range()
        v["data"] = self.data()
        return v

    # Range is string that identifies the range represented by 'data'.
    @typechecked
    def range(self) -> str:
        return self.__range

    # Data is a bit array containing all allocated addresses in the previous segment.
    @typechecked
    def data(self) -> bytes:
        return self.__data


# ReplicationControllerSpec is the specification of a replication controller.
class ReplicationControllerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        replicas: int = None,
        minReadySeconds: int = None,
        selector: Dict[str, str] = None,
        template: PodTemplateSpec = None,
    ):
        super().__init__(**{})
        self.__replicas = replicas if replicas is not None else 1
        self.__minReadySeconds = minReadySeconds
        self.__selector = selector if selector is not None else {}
        self.__template = template

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        replicas = self.replicas()
        if replicas is not None:  # omit empty
            v["replicas"] = replicas
        minReadySeconds = self.minReadySeconds()
        if minReadySeconds:  # omit empty
            v["minReadySeconds"] = minReadySeconds
        selector = self.selector()
        if selector:  # omit empty
            v["selector"] = selector
        template = self.template()
        if template is not None:  # omit empty
            v["template"] = template
        return v

    # Replicas is the number of desired replicas.
    # This is a pointer to distinguish between explicit zero and unspecified.
    # Defaults to 1.
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#what-is-a-replicationcontroller
    @typechecked
    def replicas(self) -> Optional[int]:
        return self.__replicas

    # Minimum number of seconds for which a newly created pod should be ready
    # without any of its container crashing, for it to be considered available.
    # Defaults to 0 (pod will be considered available as soon as it is ready)
    @typechecked
    def minReadySeconds(self) -> Optional[int]:
        return self.__minReadySeconds

    # Selector is a label query over pods that should match the Replicas count.
    # If Selector is empty, it is defaulted to the labels present on the Pod template.
    # Label keys and values that must match in order to be controlled by this replication
    # controller, if empty defaulted to labels on Pod template.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
    @typechecked
    def selector(self) -> Optional[Dict[str, str]]:
        return self.__selector

    # Template is the object that describes the pod that will be created if
    # insufficient replicas are detected. This takes precedence over a TemplateRef.
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#pod-template
    @typechecked
    def template(self) -> Optional[PodTemplateSpec]:
        return self.__template


# ReplicationController represents the configuration of a replication controller.
class ReplicationController(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: ReplicationControllerSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "ReplicationController",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else ReplicationControllerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Spec defines the specification of the desired behavior of the replication controller.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> Optional[ReplicationControllerSpec]:
        return self.__spec


# A scoped-resource selector requirement is a selector that contains values, a scope name, and an operator
# that relates the scope name and values.
class ScopedResourceSelectorRequirement(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        scopeName: ResourceQuotaScope = None,
        operator: ScopeSelectorOperator = None,
        values: List[str] = None,
    ):
        super().__init__(**{})
        self.__scopeName = scopeName
        self.__operator = operator
        self.__values = values if values is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["scopeName"] = self.scopeName()
        v["operator"] = self.operator()
        values = self.values()
        if values:  # omit empty
            v["values"] = values
        return v

    # The name of the scope that the selector applies to.
    @typechecked
    def scopeName(self) -> ResourceQuotaScope:
        return self.__scopeName

    # Represents a scope's relationship to a set of values.
    # Valid operators are In, NotIn, Exists, DoesNotExist.
    @typechecked
    def operator(self) -> ScopeSelectorOperator:
        return self.__operator

    # An array of string values. If the operator is In or NotIn,
    # the values array must be non-empty. If the operator is Exists or DoesNotExist,
    # the values array must be empty.
    # This array is replaced during a strategic merge patch.
    @typechecked
    def values(self) -> Optional[List[str]]:
        return self.__values


# A scope selector represents the AND of the selectors represented
# by the scoped-resource selector requirements.
class ScopeSelector(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, matchExpressions: List[ScopedResourceSelectorRequirement] = None
    ):
        super().__init__(**{})
        self.__matchExpressions = (
            matchExpressions if matchExpressions is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        matchExpressions = self.matchExpressions()
        if matchExpressions:  # omit empty
            v["matchExpressions"] = matchExpressions
        return v

    # A list of scope selector requirements by scope of the resources.
    @typechecked
    def matchExpressions(self) -> Optional[List[ScopedResourceSelectorRequirement]]:
        return self.__matchExpressions


# ResourceQuotaSpec defines the desired hard limits to enforce for Quota.
class ResourceQuotaSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        hard: Dict[ResourceName, "resource.Quantity"] = None,
        scopes: List[ResourceQuotaScope] = None,
        scopeSelector: ScopeSelector = None,
    ):
        super().__init__(**{})
        self.__hard = hard if hard is not None else {}
        self.__scopes = scopes if scopes is not None else []
        self.__scopeSelector = scopeSelector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        hard = self.hard()
        if hard:  # omit empty
            v["hard"] = hard
        scopes = self.scopes()
        if scopes:  # omit empty
            v["scopes"] = scopes
        scopeSelector = self.scopeSelector()
        if scopeSelector is not None:  # omit empty
            v["scopeSelector"] = scopeSelector
        return v

    # hard is the set of desired hard limits for each named resource.
    # More info: https://kubernetes.io/docs/concepts/policy/resource-quotas/
    @typechecked
    def hard(self) -> Optional[Dict[ResourceName, "resource.Quantity"]]:
        return self.__hard

    # A collection of filters that must match each object tracked by a quota.
    # If not specified, the quota matches all objects.
    @typechecked
    def scopes(self) -> Optional[List[ResourceQuotaScope]]:
        return self.__scopes

    # scopeSelector is also a collection of filters like scopes that must match each object tracked by a quota
    # but expressed using ScopeSelectorOperator in combination with possible values.
    # For a resource to match, both scopes AND scopeSelector (if specified in spec), must be matched.
    @typechecked
    def scopeSelector(self) -> Optional[ScopeSelector]:
        return self.__scopeSelector


# ResourceQuota sets aggregate quota restrictions enforced per namespace
class ResourceQuota(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: ResourceQuotaSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "ResourceQuota",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else ResourceQuotaSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Spec defines the desired quota.
    # https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> Optional[ResourceQuotaSpec]:
        return self.__spec


# Secret holds secret data of a certain type. The total bytes of the values in
# the Data field must be less than MaxSecretSize bytes.
class Secret(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        data: Dict[str, bytes] = None,
        stringData: Dict[str, str] = None,
        type: SecretType = SecretType["Opaque"],
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "Secret",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__data = data if data is not None else {}
        self.__stringData = stringData if stringData is not None else {}
        self.__type = type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        data = self.data()
        if data:  # omit empty
            v["data"] = data
        stringData = self.stringData()
        if stringData:  # omit empty
            v["stringData"] = stringData
        type = self.type()
        if type:  # omit empty
            v["type"] = type
        return v

    # Data contains the secret data. Each key must consist of alphanumeric
    # characters, '-', '_' or '.'. The serialized form of the secret data is a
    # base64 encoded string, representing the arbitrary (possibly non-string)
    # data value here. Described in https://tools.ietf.org/html/rfc4648#section-4
    @typechecked
    def data(self) -> Optional[Dict[str, bytes]]:
        return self.__data

    # stringData allows specifying non-binary secret data in string form.
    # It is provided as a write-only convenience method.
    # All keys and values are merged into the data field on write, overwriting any existing values.
    # It is never output when reading from the API.
    @typechecked
    def stringData(self) -> Optional[Dict[str, str]]:
        return self.__stringData

    # Used to facilitate programmatic handling of secret data.
    @typechecked
    def type(self) -> Optional[SecretType]:
        return self.__type


# SerializedReference is a reference to serialized object.
class SerializedReference(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(self, reference: ObjectReference = None):
        super().__init__(**{"apiVersion": "v1", "kind": "SerializedReference"})
        self.__reference = reference if reference is not None else ObjectReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["reference"] = self.reference()
        return v

    # The reference to an object in the system.
    @typechecked
    def reference(self) -> Optional[ObjectReference]:
        return self.__reference


# ServicePort contains information on service's port.
class ServicePort(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        protocol: Protocol = None,
        port: int = 0,
        targetPort: Union[int, str] = None,
        nodePort: int = None,
    ):
        super().__init__(**{})
        self.__name = name
        self.__protocol = protocol
        self.__port = port
        self.__targetPort = targetPort if targetPort is not None else 0
        self.__nodePort = nodePort

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        protocol = self.protocol()
        if protocol:  # omit empty
            v["protocol"] = protocol
        v["port"] = self.port()
        v["targetPort"] = self.targetPort()
        nodePort = self.nodePort()
        if nodePort:  # omit empty
            v["nodePort"] = nodePort
        return v

    # The name of this port within the service. This must be a DNS_LABEL.
    # All ports within a ServiceSpec must have unique names. When considering
    # the endpoints for a Service, this must match the 'name' field in the
    # EndpointPort.
    # Optional if only one ServicePort is defined on this service.
    @typechecked
    def name(self) -> Optional[str]:
        return self.__name

    # The IP protocol for this port. Supports "TCP", "UDP", and "SCTP".
    # Default is TCP.
    @typechecked
    def protocol(self) -> Optional[Protocol]:
        return self.__protocol

    # The port that will be exposed by this service.
    @typechecked
    def port(self) -> int:
        return self.__port

    # Number or name of the port to access on the pods targeted by the service.
    # Number must be in the range 1 to 65535. Name must be an IANA_SVC_NAME.
    # If this is a string, it will be looked up as a named port in the
    # target Pod's container ports. If this is not specified, the value
    # of the 'port' field is used (an identity map).
    # This field is ignored for services with clusterIP=None, and should be
    # omitted or set equal to the 'port' field.
    # More info: https://kubernetes.io/docs/concepts/services-networking/service/#defining-a-service
    @typechecked
    def targetPort(self) -> Optional[Union[int, str]]:
        return self.__targetPort

    # The port on each node on which this service is exposed when type=NodePort or LoadBalancer.
    # Usually assigned by the system. If specified, it will be allocated to the service
    # if unused or else creation of the service will fail.
    # Default is to auto-allocate a port if the ServiceType of this Service requires one.
    # More info: https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport
    @typechecked
    def nodePort(self) -> Optional[int]:
        return self.__nodePort


# SessionAffinityConfig represents the configurations of session affinity.
class SessionAffinityConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, clientIP: ClientIPConfig = None):
        super().__init__(**{})
        self.__clientIP = clientIP

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientIP = self.clientIP()
        if clientIP is not None:  # omit empty
            v["clientIP"] = clientIP
        return v

    # clientIP contains the configurations of Client IP based session affinity.
    @typechecked
    def clientIP(self) -> Optional[ClientIPConfig]:
        return self.__clientIP


# ServiceSpec describes the attributes that a user creates on a service.
class ServiceSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        ports: Dict[str, ServicePort] = None,
        selector: Dict[str, str] = None,
        clusterIP: str = None,
        type: ServiceType = ServiceType["ClusterIP"],
        externalIPs: List[str] = None,
        sessionAffinity: ServiceAffinity = ServiceAffinity["None"],
        loadBalancerIP: str = None,
        loadBalancerSourceRanges: List[str] = None,
        externalName: str = None,
        externalTrafficPolicy: ServiceExternalTrafficPolicyType = None,
        healthCheckNodePort: int = None,
        publishNotReadyAddresses: bool = None,
        sessionAffinityConfig: SessionAffinityConfig = None,
        ipFamily: IPFamily = None,
    ):
        super().__init__(**{})
        self.__ports = ports if ports is not None else {}
        self.__selector = selector if selector is not None else {}
        self.__clusterIP = clusterIP
        self.__type = type
        self.__externalIPs = externalIPs if externalIPs is not None else []
        self.__sessionAffinity = sessionAffinity
        self.__loadBalancerIP = loadBalancerIP
        self.__loadBalancerSourceRanges = (
            loadBalancerSourceRanges if loadBalancerSourceRanges is not None else []
        )
        self.__externalName = externalName
        self.__externalTrafficPolicy = externalTrafficPolicy
        self.__healthCheckNodePort = healthCheckNodePort
        self.__publishNotReadyAddresses = publishNotReadyAddresses
        self.__sessionAffinityConfig = sessionAffinityConfig
        self.__ipFamily = ipFamily

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ports = self.ports()
        if ports:  # omit empty
            v["ports"] = ports.values()  # named list
        selector = self.selector()
        if selector:  # omit empty
            v["selector"] = selector
        clusterIP = self.clusterIP()
        if clusterIP:  # omit empty
            v["clusterIP"] = clusterIP
        type = self.type()
        if type:  # omit empty
            v["type"] = type
        externalIPs = self.externalIPs()
        if externalIPs:  # omit empty
            v["externalIPs"] = externalIPs
        sessionAffinity = self.sessionAffinity()
        if sessionAffinity:  # omit empty
            v["sessionAffinity"] = sessionAffinity
        loadBalancerIP = self.loadBalancerIP()
        if loadBalancerIP:  # omit empty
            v["loadBalancerIP"] = loadBalancerIP
        loadBalancerSourceRanges = self.loadBalancerSourceRanges()
        if loadBalancerSourceRanges:  # omit empty
            v["loadBalancerSourceRanges"] = loadBalancerSourceRanges
        externalName = self.externalName()
        if externalName:  # omit empty
            v["externalName"] = externalName
        externalTrafficPolicy = self.externalTrafficPolicy()
        if externalTrafficPolicy:  # omit empty
            v["externalTrafficPolicy"] = externalTrafficPolicy
        healthCheckNodePort = self.healthCheckNodePort()
        if healthCheckNodePort:  # omit empty
            v["healthCheckNodePort"] = healthCheckNodePort
        publishNotReadyAddresses = self.publishNotReadyAddresses()
        if publishNotReadyAddresses:  # omit empty
            v["publishNotReadyAddresses"] = publishNotReadyAddresses
        sessionAffinityConfig = self.sessionAffinityConfig()
        if sessionAffinityConfig is not None:  # omit empty
            v["sessionAffinityConfig"] = sessionAffinityConfig
        ipFamily = self.ipFamily()
        if ipFamily is not None:  # omit empty
            v["ipFamily"] = ipFamily
        return v

    # The list of ports that are exposed by this service.
    # More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
    # +listType=map
    # +listMapKey=port
    # +listMapKey=protocol
    @typechecked
    def ports(self) -> Optional[Dict[str, ServicePort]]:
        return self.__ports

    # Route service traffic to pods with label keys and values matching this
    # selector. If empty or not present, the service is assumed to have an
    # external process managing its endpoints, which Kubernetes will not
    # modify. Only applies to types ClusterIP, NodePort, and LoadBalancer.
    # Ignored if type is ExternalName.
    # More info: https://kubernetes.io/docs/concepts/services-networking/service/
    @typechecked
    def selector(self) -> Optional[Dict[str, str]]:
        return self.__selector

    # clusterIP is the IP address of the service and is usually assigned
    # randomly by the master. If an address is specified manually and is not in
    # use by others, it will be allocated to the service; otherwise, creation
    # of the service will fail. This field can not be changed through updates.
    # Valid values are "None", empty string (""), or a valid IP address. "None"
    # can be specified for headless services when proxying is not required.
    # Only applies to types ClusterIP, NodePort, and LoadBalancer. Ignored if
    # type is ExternalName.
    # More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
    @typechecked
    def clusterIP(self) -> Optional[str]:
        return self.__clusterIP

    # type determines how the Service is exposed. Defaults to ClusterIP. Valid
    # options are ExternalName, ClusterIP, NodePort, and LoadBalancer.
    # "ExternalName" maps to the specified externalName.
    # "ClusterIP" allocates a cluster-internal IP address for load-balancing to
    # endpoints. Endpoints are determined by the selector or if that is not
    # specified, by manual construction of an Endpoints object. If clusterIP is
    # "None", no virtual IP is allocated and the endpoints are published as a
    # set of endpoints rather than a stable IP.
    # "NodePort" builds on ClusterIP and allocates a port on every node which
    # routes to the clusterIP.
    # "LoadBalancer" builds on NodePort and creates an
    # external load-balancer (if supported in the current cloud) which routes
    # to the clusterIP.
    # More info: https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types
    @typechecked
    def type(self) -> Optional[ServiceType]:
        return self.__type

    # externalIPs is a list of IP addresses for which nodes in the cluster
    # will also accept traffic for this service.  These IPs are not managed by
    # Kubernetes.  The user is responsible for ensuring that traffic arrives
    # at a node with this IP.  A common example is external load-balancers
    # that are not part of the Kubernetes system.
    @typechecked
    def externalIPs(self) -> Optional[List[str]]:
        return self.__externalIPs

    # Supports "ClientIP" and "None". Used to maintain session affinity.
    # Enable client IP based session affinity.
    # Must be ClientIP or None.
    # Defaults to None.
    # More info: https://kubernetes.io/docs/concepts/services-networking/service/#virtual-ips-and-service-proxies
    @typechecked
    def sessionAffinity(self) -> Optional[ServiceAffinity]:
        return self.__sessionAffinity

    # Only applies to Service Type: LoadBalancer
    # LoadBalancer will get created with the IP specified in this field.
    # This feature depends on whether the underlying cloud-provider supports specifying
    # the loadBalancerIP when a load balancer is created.
    # This field will be ignored if the cloud-provider does not support the feature.
    @typechecked
    def loadBalancerIP(self) -> Optional[str]:
        return self.__loadBalancerIP

    # If specified and supported by the platform, this will restrict traffic through the cloud-provider
    # load-balancer will be restricted to the specified client IPs. This field will be ignored if the
    # cloud-provider does not support the feature."
    # More info: https://kubernetes.io/docs/tasks/access-application-cluster/configure-cloud-provider-firewall/
    @typechecked
    def loadBalancerSourceRanges(self) -> Optional[List[str]]:
        return self.__loadBalancerSourceRanges

    # externalName is the external reference that kubedns or equivalent will
    # return as a CNAME record for this service. No proxying will be involved.
    # Must be a valid RFC-1123 hostname (https://tools.ietf.org/html/rfc1123)
    # and requires Type to be ExternalName.
    @typechecked
    def externalName(self) -> Optional[str]:
        return self.__externalName

    # externalTrafficPolicy denotes if this Service desires to route external
    # traffic to node-local or cluster-wide endpoints. "Local" preserves the
    # client source IP and avoids a second hop for LoadBalancer and Nodeport
    # type services, but risks potentially imbalanced traffic spreading.
    # "Cluster" obscures the client source IP and may cause a second hop to
    # another node, but should have good overall load-spreading.
    @typechecked
    def externalTrafficPolicy(self) -> Optional[ServiceExternalTrafficPolicyType]:
        return self.__externalTrafficPolicy

    # healthCheckNodePort specifies the healthcheck nodePort for the service.
    # If not specified, HealthCheckNodePort is created by the service api
    # backend with the allocated nodePort. Will use user-specified nodePort value
    # if specified by the client. Only effects when Type is set to LoadBalancer
    # and ExternalTrafficPolicy is set to Local.
    @typechecked
    def healthCheckNodePort(self) -> Optional[int]:
        return self.__healthCheckNodePort

    # publishNotReadyAddresses, when set to true, indicates that DNS implementations
    # must publish the notReadyAddresses of subsets for the Endpoints associated with
    # the Service. The default value is false.
    # The primary use case for setting this field is to use a StatefulSet's Headless Service
    # to propagate SRV records for its Pods without respect to their readiness for purpose
    # of peer discovery.
    @typechecked
    def publishNotReadyAddresses(self) -> Optional[bool]:
        return self.__publishNotReadyAddresses

    # sessionAffinityConfig contains the configurations of session affinity.
    @typechecked
    def sessionAffinityConfig(self) -> Optional[SessionAffinityConfig]:
        return self.__sessionAffinityConfig

    # ipFamily specifies whether this Service has a preference for a particular IP family (e.g. IPv4 vs.
    # IPv6).  If a specific IP family is requested, the clusterIP field will be allocated from that family, if it is
    # available in the cluster.  If no IP family is requested, the cluster's primary IP family will be used.
    # Other IP fields (loadBalancerIP, loadBalancerSourceRanges, externalIPs) and controllers which
    # allocate external load-balancers should use the same IP family.  Endpoints for this Service will be of
    # this family.  This field is immutable after creation. Assigning a ServiceIPFamily not available in the
    # cluster (e.g. IPv6 in IPv4 only cluster) is an error condition and will fail during clusterIP assignment.
    @typechecked
    def ipFamily(self) -> Optional[IPFamily]:
        return self.__ipFamily


# Service is a named abstraction of software service (for example, mysql) consisting of local port
# (for example 3306) that the proxy listens on, and the selector that determines which pods
# will answer requests sent through the proxy.
class Service(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: ServiceSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "Service",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else ServiceSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Spec defines the behavior of a service.
    # https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> Optional[ServiceSpec]:
        return self.__spec


# ServiceAccount binds together:
# * a name, understood by users, and perhaps by peripheral systems, for an identity
# * a principal that can be authenticated and authorized
# * a set of secrets
class ServiceAccount(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        secrets: Dict[str, ObjectReference] = None,
        imagePullSecrets: Dict[str, LocalObjectReference] = None,
        automountServiceAccountToken: bool = None,
    ):
        super().__init__(
            **{
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__secrets = secrets if secrets is not None else {}
        self.__imagePullSecrets = (
            imagePullSecrets if imagePullSecrets is not None else {}
        )
        self.__automountServiceAccountToken = automountServiceAccountToken

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secrets = self.secrets()
        if secrets:  # omit empty
            v["secrets"] = secrets.values()  # named list
        imagePullSecrets = self.imagePullSecrets()
        if imagePullSecrets:  # omit empty
            v["imagePullSecrets"] = imagePullSecrets.values()  # named list
        automountServiceAccountToken = self.automountServiceAccountToken()
        if automountServiceAccountToken is not None:  # omit empty
            v["automountServiceAccountToken"] = automountServiceAccountToken
        return v

    # Secrets is the list of secrets allowed to be used by pods running using this ServiceAccount.
    # More info: https://kubernetes.io/docs/concepts/configuration/secret
    @typechecked
    def secrets(self) -> Optional[Dict[str, ObjectReference]]:
        return self.__secrets

    # ImagePullSecrets is a list of references to secrets in the same namespace to use for pulling any images
    # in pods that reference this ServiceAccount. ImagePullSecrets are distinct from Secrets because Secrets
    # can be mounted in the pod, but ImagePullSecrets are only accessed by the kubelet.
    # More info: https://kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod
    @typechecked
    def imagePullSecrets(self) -> Optional[Dict[str, LocalObjectReference]]:
        return self.__imagePullSecrets

    # AutomountServiceAccountToken indicates whether pods running as this service account should have an API token automatically mounted.
    # Can be overridden at the pod level.
    @typechecked
    def automountServiceAccountToken(self) -> Optional[bool]:
        return self.__automountServiceAccountToken


# ServiceProxyOptions is the query options to a Service's proxy call.
class ServiceProxyOptions(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(self, path: str = None):
        super().__init__(**{"apiVersion": "v1", "kind": "ServiceProxyOptions"})
        self.__path = path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        if path:  # omit empty
            v["path"] = path
        return v

    # Path is the part of URLs that include service endpoints, suffixes,
    # and parameters to use for the current proxy request to service.
    # For example, the whole request URL is
    # http://localhost/api/v1/namespaces/kube-system/services/elasticsearch-logging/_search?q=user:kimchy.
    # Path is _search?q=user:kimchy.
    @typechecked
    def path(self) -> Optional[str]:
        return self.__path


# A topology selector requirement is a selector that matches given label.
# This is an alpha feature and may change in the future.
class TopologySelectorLabelRequirement(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, key: str = "", values: List[str] = None):
        super().__init__(**{})
        self.__key = key
        self.__values = values if values is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["key"] = self.key()
        v["values"] = self.values()
        return v

    # The label key that the selector applies to.
    @typechecked
    def key(self) -> str:
        return self.__key

    # An array of string values. One value must match the label to be selected.
    # Each entry in Values is ORed.
    @typechecked
    def values(self) -> List[str]:
        return self.__values


# A topology selector term represents the result of label queries.
# A null or empty topology selector term matches no objects.
# The requirements of them are ANDed.
# It provides a subset of functionality as NodeSelectorTerm.
# This is an alpha feature and may change in the future.
class TopologySelectorTerm(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, matchLabelExpressions: List[TopologySelectorLabelRequirement] = None
    ):
        super().__init__(**{})
        self.__matchLabelExpressions = (
            matchLabelExpressions if matchLabelExpressions is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        matchLabelExpressions = self.matchLabelExpressions()
        if matchLabelExpressions:  # omit empty
            v["matchLabelExpressions"] = matchLabelExpressions
        return v

    # A list of topology selector requirements by labels.
    @typechecked
    def matchLabelExpressions(self) -> Optional[List[TopologySelectorLabelRequirement]]:
        return self.__matchLabelExpressions
