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


# VolumeBindingMode indicates how PersistentVolumeClaims should be bound.
VolumeBindingMode = base.Enum(
    "VolumeBindingMode",
    {
        # Immediate indicates that PersistentVolumeClaims should be
        # immediately provisioned and bound.  This is the default mode.
        "Immediate": "Immediate",
        # WaitForFirstConsumer indicates that PersistentVolumeClaims
        # should not be provisioned and bound until the first Pod is created that
        # references the PeristentVolumeClaim.  The volume provisioning and
        # binding will occur during Pod scheduing.
        "WaitForFirstConsumer": "WaitForFirstConsumer",
    },
)


# VolumeLifecycleMode is an enumeration of possible usage modes for a volume
# provided by a CSI driver. More modes may be added in the future.
VolumeLifecycleMode = base.Enum(
    "VolumeLifecycleMode",
    {
        # Ephemeral indicates that the driver can be used for
        # ephemeral inline volumes. Such volumes are specified inside the pod
        # spec with a CSIVolumeSource and, as far as Kubernetes is concerned, have
        # a lifecycle that is tied to the lifecycle of the pod. For example, such
        # a volume might contain data that gets created specifically for that pod,
        # like secrets.
        # But how the volume actually gets created and managed is entirely up to
        # the driver. It might also use reference counting to share the same volume
        # instance among different pods if the CSIVolumeSource of those pods is
        # identical.
        "Ephemeral": "Ephemeral",
        # Persistent explicitly confirms that the driver implements
        # the full CSI spec. It is the default when CSIDriverSpec.VolumeLifecycleModes is not
        # set. Such volumes are managed in Kubernetes via the persistent volume
        # claim mechanism and have a lifecycle that is independent of the pods which
        # use them.
        "Persistent": "Persistent",
    },
)


class CSIDriverSpec(types.Object):
    """
    CSIDriverSpec is the specification of a CSIDriver.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        attach_required: bool = None,
        pod_info_on_mount: bool = None,
        volume_lifecycle_modes: List[VolumeLifecycleMode] = None,
    ):
        super().__init__()
        self.__attach_required = (
            attach_required if attach_required is not None else True
        )
        self.__pod_info_on_mount = pod_info_on_mount
        self.__volume_lifecycle_modes = (
            volume_lifecycle_modes if volume_lifecycle_modes is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        attach_required = self.attach_required()
        check_type("attach_required", attach_required, Optional[bool])
        if attach_required is not None:  # omit empty
            v["attachRequired"] = attach_required
        pod_info_on_mount = self.pod_info_on_mount()
        check_type("pod_info_on_mount", pod_info_on_mount, Optional[bool])
        if pod_info_on_mount is not None:  # omit empty
            v["podInfoOnMount"] = pod_info_on_mount
        volume_lifecycle_modes = self.volume_lifecycle_modes()
        check_type(
            "volume_lifecycle_modes",
            volume_lifecycle_modes,
            Optional[List[VolumeLifecycleMode]],
        )
        if volume_lifecycle_modes:  # omit empty
            v["volumeLifecycleModes"] = volume_lifecycle_modes
        return v

    def attach_required(self) -> Optional[bool]:
        """
        attachRequired indicates this CSI volume driver requires an attach
        operation (because it implements the CSI ControllerPublishVolume()
        method), and that the Kubernetes attach detach controller should call
        the attach volume interface which checks the volumeattachment status
        and waits until the volume is attached before proceeding to mounting.
        The CSI external-attacher coordinates with CSI volume driver and updates
        the volumeattachment status when the attach operation is complete.
        If the CSIDriverRegistry feature gate is enabled and the value is
        specified to false, the attach operation will be skipped.
        Otherwise the attach operation will be called.
        """
        return self.__attach_required

    def pod_info_on_mount(self) -> Optional[bool]:
        """
        If set to true, podInfoOnMount indicates this CSI volume driver
        requires additional pod information (like podName, podUID, etc.) during
        mount operations.
        If set to false, pod information will not be passed on mount.
        Default is false.
        The CSI driver specifies podInfoOnMount as part of driver deployment.
        If true, Kubelet will pass pod information as VolumeContext in the CSI
        NodePublishVolume() calls.
        The CSI driver is responsible for parsing and validating the information
        passed in as VolumeContext.
        The following VolumeConext will be passed if podInfoOnMount is set to true.
        This list might grow, but the prefix will be used.
        "csi.storage.k8s.io/pod.name": pod.Name
        "csi.storage.k8s.io/pod.namespace": pod.Namespace
        "csi.storage.k8s.io/pod.uid": string(pod.UID)
        "csi.storage.k8s.io/ephemeral": "true" iff the volume is an ephemeral inline volume
                                        defined by a CSIVolumeSource, otherwise "false"
        
        "csi.storage.k8s.io/ephemeral" is a new feature in Kubernetes 1.16. It is only
        required for drivers which support both the "Persistent" and "Ephemeral" VolumeLifecycleMode.
        Other drivers can leave pod info disabled and/or ignore this field.
        As Kubernetes 1.15 doesn't support this field, drivers can only support one mode when
        deployed on such a cluster and the deployment determines which mode that is, for example
        via a command line parameter of the driver.
        """
        return self.__pod_info_on_mount

    def volume_lifecycle_modes(self) -> Optional[List[VolumeLifecycleMode]]:
        """
        VolumeLifecycleModes defines what kind of volumes this CSI volume driver supports.
        The default if the list is empty is "Persistent", which is the usage
        defined by the CSI specification and implemented in Kubernetes via the usual
        PV/PVC mechanism.
        The other mode is "Ephemeral". In this mode, volumes are defined inline
        inside the pod spec with CSIVolumeSource and their lifecycle is tied to
        the lifecycle of that pod. A driver has to be aware of this
        because it is only going to get a NodePublishVolume call for such a volume.
        For more information about implementing this mode, see
        https://kubernetes-csi.github.io/docs/ephemeral-local-volumes.html
        A driver can support one or more of these modes and
        more modes may be added in the future.
        """
        return self.__volume_lifecycle_modes


class CSIDriver(base.TypedObject, base.MetadataObject):
    """
    CSIDriver captures information about a Container Storage Interface (CSI)
    volume driver deployed on the cluster.
    CSI drivers do not need to create the CSIDriver object directly. Instead they may use the
    cluster-driver-registrar sidecar container. When deployed with a CSI driver it automatically
    creates a CSIDriver object representing the driver.
    Kubernetes attach detach controller uses this object to determine whether attach is required.
    Kubelet uses this object to determine whether pod information needs to be passed on mount.
    CSIDriver objects are non-namespaced.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "CSIDriverSpec" = None,
    ):
        super().__init__(
            api_version="storage.k8s.io/v1beta1",
            kind="CSIDriver",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else CSIDriverSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "CSIDriverSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "CSIDriverSpec":
        """
        Specification of the CSI Driver.
        """
        return self.__spec


class VolumeNodeResources(types.Object):
    """
    VolumeNodeResources is a set of resource limits for scheduling of volumes.
    """

    @context.scoped
    @typechecked
    def __init__(self, count: int = None):
        super().__init__()
        self.__count = count

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        count = self.count()
        check_type("count", count, Optional[int])
        if count is not None:  # omit empty
            v["count"] = count
        return v

    def count(self) -> Optional[int]:
        """
        Maximum number of unique volumes managed by the CSI driver that can be used on a node.
        A volume that is both attached and mounted on a node is considered to be used once, not twice.
        The same rule applies for a unique volume that is shared among multiple pods on the same node.
        If this field is nil, then the supported number of volumes on this node is unbounded.
        """
        return self.__count


class CSINodeDriver(types.Object):
    """
    CSINodeDriver holds information about the specification of one CSI driver installed on a node
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        node_id: str = "",
        topology_keys: List[str] = None,
        allocatable: "VolumeNodeResources" = None,
    ):
        super().__init__()
        self.__name = name
        self.__node_id = node_id
        self.__topology_keys = topology_keys if topology_keys is not None else []
        self.__allocatable = allocatable

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        node_id = self.node_id()
        check_type("node_id", node_id, str)
        v["nodeID"] = node_id
        topology_keys = self.topology_keys()
        check_type("topology_keys", topology_keys, List[str])
        v["topologyKeys"] = topology_keys
        allocatable = self.allocatable()
        check_type("allocatable", allocatable, Optional["VolumeNodeResources"])
        if allocatable is not None:  # omit empty
            v["allocatable"] = allocatable
        return v

    def name(self) -> str:
        """
        This is the name of the CSI driver that this object refers to.
        This MUST be the same name returned by the CSI GetPluginName() call for
        that driver.
        """
        return self.__name

    def node_id(self) -> str:
        """
        nodeID of the node from the driver point of view.
        This field enables Kubernetes to communicate with storage systems that do
        not share the same nomenclature for nodes. For example, Kubernetes may
        refer to a given node as "node1", but the storage system may refer to
        the same node as "nodeA". When Kubernetes issues a command to the storage
        system to attach a volume to a specific node, it can use this field to
        refer to the node name using the ID that the storage system will
        understand, e.g. "nodeA" instead of "node1". This field is required.
        """
        return self.__node_id

    def topology_keys(self) -> List[str]:
        """
        topologyKeys is the list of keys supported by the driver.
        When a driver is initialized on a cluster, it provides a set of topology
        keys that it understands (e.g. "company.com/zone", "company.com/region").
        When a driver is initialized on a node, it provides the same topology keys
        along with values. Kubelet will expose these topology keys as labels
        on its own node object.
        When Kubernetes does topology aware provisioning, it can use this list to
        determine which labels it should retrieve from the node object and pass
        back to the driver.
        It is possible for different nodes to use different topology keys.
        This can be empty if driver does not support topology.
        """
        return self.__topology_keys

    def allocatable(self) -> Optional["VolumeNodeResources"]:
        """
        allocatable represents the volume resources of a node that are available for scheduling.
        """
        return self.__allocatable


class CSINodeSpec(types.Object):
    """
    CSINodeSpec holds information about the specification of all CSI drivers installed on a node
    """

    @context.scoped
    @typechecked
    def __init__(self, drivers: List["CSINodeDriver"] = None):
        super().__init__()
        self.__drivers = drivers if drivers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        drivers = self.drivers()
        check_type("drivers", drivers, List["CSINodeDriver"])
        v["drivers"] = drivers
        return v

    def drivers(self) -> List["CSINodeDriver"]:
        """
        drivers is a list of information of all CSI Drivers existing on a node.
        If all drivers in the list are uninstalled, this can become empty.
        """
        return self.__drivers


class CSINode(base.TypedObject, base.MetadataObject):
    """
    DEPRECATED - This group version of CSINode is deprecated by storage/v1/CSINode.
    See the release notes for more information.
    CSINode holds information about all CSI drivers installed on a node.
    CSI drivers do not need to create the CSINode object directly. As long as
    they use the node-driver-registrar sidecar container, the kubelet will
    automatically populate the CSINode object for the CSI driver as part of
    kubelet plugin registration.
    CSINode has the same name as a node. If the object is missing, it means either
    there are no CSI Drivers available on the node, or the Kubelet version is low
    enough that it doesn't create this object.
    CSINode has an OwnerReference that points to the corresponding node object.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "CSINodeSpec" = None,
    ):
        super().__init__(
            api_version="storage.k8s.io/v1beta1",
            kind="CSINode",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else CSINodeSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "CSINodeSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "CSINodeSpec":
        """
        spec is the specification of CSINode
        """
        return self.__spec


class StorageClass(base.TypedObject, base.MetadataObject):
    """
    StorageClass describes the parameters for a class of storage for
    which PersistentVolumes can be dynamically provisioned.
    
    StorageClasses are non-namespaced; the name of the storage class
    according to etcd is in ObjectMeta.Name.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        provisioner: str = "",
        parameters: Dict[str, str] = None,
        reclaim_policy: k8sv1.PersistentVolumeReclaimPolicy = None,
        mount_options: List[str] = None,
        allow_volume_expansion: bool = None,
        volume_binding_mode: VolumeBindingMode = None,
        allowed_topologies: List["k8sv1.TopologySelectorTerm"] = None,
    ):
        super().__init__(
            api_version="storage.k8s.io/v1beta1",
            kind="StorageClass",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__provisioner = provisioner
        self.__parameters = parameters if parameters is not None else {}
        self.__reclaim_policy = (
            reclaim_policy
            if reclaim_policy is not None
            else k8sv1.PersistentVolumeReclaimPolicy["Delete"]
        )
        self.__mount_options = mount_options if mount_options is not None else []
        self.__allow_volume_expansion = allow_volume_expansion
        self.__volume_binding_mode = (
            volume_binding_mode
            if volume_binding_mode is not None
            else VolumeBindingMode["Immediate"]
        )
        self.__allowed_topologies = (
            allowed_topologies if allowed_topologies is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        provisioner = self.provisioner()
        check_type("provisioner", provisioner, str)
        v["provisioner"] = provisioner
        parameters = self.parameters()
        check_type("parameters", parameters, Optional[Dict[str, str]])
        if parameters:  # omit empty
            v["parameters"] = parameters
        reclaim_policy = self.reclaim_policy()
        check_type(
            "reclaim_policy",
            reclaim_policy,
            Optional[k8sv1.PersistentVolumeReclaimPolicy],
        )
        if reclaim_policy is not None:  # omit empty
            v["reclaimPolicy"] = reclaim_policy
        mount_options = self.mount_options()
        check_type("mount_options", mount_options, Optional[List[str]])
        if mount_options:  # omit empty
            v["mountOptions"] = mount_options
        allow_volume_expansion = self.allow_volume_expansion()
        check_type("allow_volume_expansion", allow_volume_expansion, Optional[bool])
        if allow_volume_expansion is not None:  # omit empty
            v["allowVolumeExpansion"] = allow_volume_expansion
        volume_binding_mode = self.volume_binding_mode()
        check_type(
            "volume_binding_mode", volume_binding_mode, Optional[VolumeBindingMode]
        )
        if volume_binding_mode is not None:  # omit empty
            v["volumeBindingMode"] = volume_binding_mode
        allowed_topologies = self.allowed_topologies()
        check_type(
            "allowed_topologies",
            allowed_topologies,
            Optional[List["k8sv1.TopologySelectorTerm"]],
        )
        if allowed_topologies:  # omit empty
            v["allowedTopologies"] = allowed_topologies
        return v

    def provisioner(self) -> str:
        """
        Provisioner indicates the type of the provisioner.
        """
        return self.__provisioner

    def parameters(self) -> Optional[Dict[str, str]]:
        """
        Parameters holds the parameters for the provisioner that should
        create volumes of this storage class.
        """
        return self.__parameters

    def reclaim_policy(self) -> Optional[k8sv1.PersistentVolumeReclaimPolicy]:
        """
        Dynamically provisioned PersistentVolumes of this storage class are
        created with this reclaimPolicy. Defaults to Delete.
        """
        return self.__reclaim_policy

    def mount_options(self) -> Optional[List[str]]:
        """
        Dynamically provisioned PersistentVolumes of this storage class are
        created with these mountOptions, e.g. ["ro", "soft"]. Not validated -
        mount of the PVs will simply fail if one is invalid.
        """
        return self.__mount_options

    def allow_volume_expansion(self) -> Optional[bool]:
        """
        AllowVolumeExpansion shows whether the storage class allow volume expand
        """
        return self.__allow_volume_expansion

    def volume_binding_mode(self) -> Optional[VolumeBindingMode]:
        """
        VolumeBindingMode indicates how PersistentVolumeClaims should be
        provisioned and bound.  When unset, VolumeBindingImmediate is used.
        This field is only honored by servers that enable the VolumeScheduling feature.
        """
        return self.__volume_binding_mode

    def allowed_topologies(self) -> Optional[List["k8sv1.TopologySelectorTerm"]]:
        """
        Restrict the node topologies where volumes can be dynamically provisioned.
        Each volume plugin defines its own supported topology specifications.
        An empty TopologySelectorTerm list means there is no topology restriction.
        This field is only honored by servers that enable the VolumeScheduling feature.
        """
        return self.__allowed_topologies


class VolumeAttachmentSource(types.Object):
    """
    VolumeAttachmentSource represents a volume that should be attached.
    Right now only PersistenVolumes can be attached via external attacher,
    in future we may allow also inline volumes in pods.
    Exactly one member can be set.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        persistent_volume_name: str = None,
        inline_volume_spec: "k8sv1.PersistentVolumeSpec" = None,
    ):
        super().__init__()
        self.__persistent_volume_name = persistent_volume_name
        self.__inline_volume_spec = inline_volume_spec

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        persistent_volume_name = self.persistent_volume_name()
        check_type("persistent_volume_name", persistent_volume_name, Optional[str])
        if persistent_volume_name is not None:  # omit empty
            v["persistentVolumeName"] = persistent_volume_name
        inline_volume_spec = self.inline_volume_spec()
        check_type(
            "inline_volume_spec",
            inline_volume_spec,
            Optional["k8sv1.PersistentVolumeSpec"],
        )
        if inline_volume_spec is not None:  # omit empty
            v["inlineVolumeSpec"] = inline_volume_spec
        return v

    def persistent_volume_name(self) -> Optional[str]:
        """
        Name of the persistent volume to attach.
        """
        return self.__persistent_volume_name

    def inline_volume_spec(self) -> Optional["k8sv1.PersistentVolumeSpec"]:
        """
        inlineVolumeSpec contains all the information necessary to attach
        a persistent volume defined by a pod's inline VolumeSource. This field
        is populated only for the CSIMigration feature. It contains
        translated fields from a pod's inline VolumeSource to a
        PersistentVolumeSpec. This field is alpha-level and is only
        honored by servers that enabled the CSIMigration feature.
        """
        return self.__inline_volume_spec


class VolumeAttachmentSpec(types.Object):
    """
    VolumeAttachmentSpec is the specification of a VolumeAttachment request.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        attacher: str = "",
        source: "VolumeAttachmentSource" = None,
        node_name: str = "",
    ):
        super().__init__()
        self.__attacher = attacher
        self.__source = source if source is not None else VolumeAttachmentSource()
        self.__node_name = node_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        attacher = self.attacher()
        check_type("attacher", attacher, str)
        v["attacher"] = attacher
        source = self.source()
        check_type("source", source, "VolumeAttachmentSource")
        v["source"] = source
        node_name = self.node_name()
        check_type("node_name", node_name, str)
        v["nodeName"] = node_name
        return v

    def attacher(self) -> str:
        """
        Attacher indicates the name of the volume driver that MUST handle this
        request. This is the name returned by GetPluginName().
        """
        return self.__attacher

    def source(self) -> "VolumeAttachmentSource":
        """
        Source represents the volume that should be attached.
        """
        return self.__source

    def node_name(self) -> str:
        """
        The node that the volume should be attached to.
        """
        return self.__node_name


class VolumeAttachment(base.TypedObject, base.MetadataObject):
    """
    VolumeAttachment captures the intent to attach or detach the specified volume
    to/from the specified node.
    
    VolumeAttachment objects are non-namespaced.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "VolumeAttachmentSpec" = None,
    ):
        super().__init__(
            api_version="storage.k8s.io/v1beta1",
            kind="VolumeAttachment",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else VolumeAttachmentSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "VolumeAttachmentSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "VolumeAttachmentSpec":
        """
        Specification of the desired attach/detach volume behavior.
        Populated by the Kubernetes system.
        """
        return self.__spec
