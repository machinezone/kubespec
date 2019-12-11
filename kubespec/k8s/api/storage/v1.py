# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


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
        If this field is not specified, then the supported number of volumes on this node is unbounded.
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
        nodeID: str = "",
        topologyKeys: List[str] = None,
        allocatable: "VolumeNodeResources" = None,
    ):
        super().__init__()
        self.__name = name
        self.__nodeID = nodeID
        self.__topologyKeys = topologyKeys if topologyKeys is not None else []
        self.__allocatable = allocatable

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        nodeID = self.nodeID()
        check_type("nodeID", nodeID, str)
        v["nodeID"] = nodeID
        topologyKeys = self.topologyKeys()
        check_type("topologyKeys", topologyKeys, List[str])
        v["topologyKeys"] = topologyKeys
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

    def nodeID(self) -> str:
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
        return self.__nodeID

    def topologyKeys(self) -> List[str]:
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
        return self.__topologyKeys

    def allocatable(self) -> Optional["VolumeNodeResources"]:
        """
        allocatable represents the volume resources of a node that are available for scheduling.
        This field is beta.
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
            apiVersion="storage.k8s.io/v1",
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
        reclaimPolicy: corev1.PersistentVolumeReclaimPolicy = None,
        mountOptions: List[str] = None,
        allowVolumeExpansion: bool = None,
        volumeBindingMode: VolumeBindingMode = None,
        allowedTopologies: List["corev1.TopologySelectorTerm"] = None,
    ):
        super().__init__(
            apiVersion="storage.k8s.io/v1",
            kind="StorageClass",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__provisioner = provisioner
        self.__parameters = parameters if parameters is not None else {}
        self.__reclaimPolicy = (
            reclaimPolicy
            if reclaimPolicy is not None
            else corev1.PersistentVolumeReclaimPolicy["Delete"]
        )
        self.__mountOptions = mountOptions if mountOptions is not None else []
        self.__allowVolumeExpansion = allowVolumeExpansion
        self.__volumeBindingMode = (
            volumeBindingMode
            if volumeBindingMode is not None
            else VolumeBindingMode["Immediate"]
        )
        self.__allowedTopologies = (
            allowedTopologies if allowedTopologies is not None else []
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
        reclaimPolicy = self.reclaimPolicy()
        check_type(
            "reclaimPolicy",
            reclaimPolicy,
            Optional[corev1.PersistentVolumeReclaimPolicy],
        )
        if reclaimPolicy is not None:  # omit empty
            v["reclaimPolicy"] = reclaimPolicy
        mountOptions = self.mountOptions()
        check_type("mountOptions", mountOptions, Optional[List[str]])
        if mountOptions:  # omit empty
            v["mountOptions"] = mountOptions
        allowVolumeExpansion = self.allowVolumeExpansion()
        check_type("allowVolumeExpansion", allowVolumeExpansion, Optional[bool])
        if allowVolumeExpansion is not None:  # omit empty
            v["allowVolumeExpansion"] = allowVolumeExpansion
        volumeBindingMode = self.volumeBindingMode()
        check_type("volumeBindingMode", volumeBindingMode, Optional[VolumeBindingMode])
        if volumeBindingMode is not None:  # omit empty
            v["volumeBindingMode"] = volumeBindingMode
        allowedTopologies = self.allowedTopologies()
        check_type(
            "allowedTopologies",
            allowedTopologies,
            Optional[List["corev1.TopologySelectorTerm"]],
        )
        if allowedTopologies:  # omit empty
            v["allowedTopologies"] = allowedTopologies
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

    def reclaimPolicy(self) -> Optional[corev1.PersistentVolumeReclaimPolicy]:
        """
        Dynamically provisioned PersistentVolumes of this storage class are
        created with this reclaimPolicy. Defaults to Delete.
        """
        return self.__reclaimPolicy

    def mountOptions(self) -> Optional[List[str]]:
        """
        Dynamically provisioned PersistentVolumes of this storage class are
        created with these mountOptions, e.g. ["ro", "soft"]. Not validated -
        mount of the PVs will simply fail if one is invalid.
        """
        return self.__mountOptions

    def allowVolumeExpansion(self) -> Optional[bool]:
        """
        AllowVolumeExpansion shows whether the storage class allow volume expand
        """
        return self.__allowVolumeExpansion

    def volumeBindingMode(self) -> Optional[VolumeBindingMode]:
        """
        VolumeBindingMode indicates how PersistentVolumeClaims should be
        provisioned and bound.  When unset, VolumeBindingImmediate is used.
        This field is only honored by servers that enable the VolumeScheduling feature.
        """
        return self.__volumeBindingMode

    def allowedTopologies(self) -> Optional[List["corev1.TopologySelectorTerm"]]:
        """
        Restrict the node topologies where volumes can be dynamically provisioned.
        Each volume plugin defines its own supported topology specifications.
        An empty TopologySelectorTerm list means there is no topology restriction.
        This field is only honored by servers that enable the VolumeScheduling feature.
        """
        return self.__allowedTopologies


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
        persistentVolumeName: str = None,
        inlineVolumeSpec: "corev1.PersistentVolumeSpec" = None,
    ):
        super().__init__()
        self.__persistentVolumeName = persistentVolumeName
        self.__inlineVolumeSpec = inlineVolumeSpec

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        persistentVolumeName = self.persistentVolumeName()
        check_type("persistentVolumeName", persistentVolumeName, Optional[str])
        if persistentVolumeName is not None:  # omit empty
            v["persistentVolumeName"] = persistentVolumeName
        inlineVolumeSpec = self.inlineVolumeSpec()
        check_type(
            "inlineVolumeSpec",
            inlineVolumeSpec,
            Optional["corev1.PersistentVolumeSpec"],
        )
        if inlineVolumeSpec is not None:  # omit empty
            v["inlineVolumeSpec"] = inlineVolumeSpec
        return v

    def persistentVolumeName(self) -> Optional[str]:
        """
        Name of the persistent volume to attach.
        """
        return self.__persistentVolumeName

    def inlineVolumeSpec(self) -> Optional["corev1.PersistentVolumeSpec"]:
        """
        inlineVolumeSpec contains all the information necessary to attach
        a persistent volume defined by a pod's inline VolumeSource. This field
        is populated only for the CSIMigration feature. It contains
        translated fields from a pod's inline VolumeSource to a
        PersistentVolumeSpec. This field is alpha-level and is only
        honored by servers that enabled the CSIMigration feature.
        """
        return self.__inlineVolumeSpec


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
        nodeName: str = "",
    ):
        super().__init__()
        self.__attacher = attacher
        self.__source = source if source is not None else VolumeAttachmentSource()
        self.__nodeName = nodeName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        attacher = self.attacher()
        check_type("attacher", attacher, str)
        v["attacher"] = attacher
        source = self.source()
        check_type("source", source, "VolumeAttachmentSource")
        v["source"] = source
        nodeName = self.nodeName()
        check_type("nodeName", nodeName, str)
        v["nodeName"] = nodeName
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

    def nodeName(self) -> str:
        """
        The node that the volume should be attached to.
        """
        return self.__nodeName


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
            apiVersion="storage.k8s.io/v1",
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
