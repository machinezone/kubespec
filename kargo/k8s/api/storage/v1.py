# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kargo.k8s import base
from kargo.k8s.api.core import v1 as corev1
from kargo import context
from kargo import types
from typeguard import typechecked


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


# StorageClass describes the parameters for a class of storage for
# which PersistentVolumes can be dynamically provisioned.
#
# StorageClasses are non-namespaced; the name of the storage class
# according to etcd is in ObjectMeta.Name.
class StorageClass(base.TypedObject, base.MetadataObject):
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
            **{
                "apiVersion": "storage.k8s.io/v1",
                "kind": "StorageClass",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
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
        v["provisioner"] = self.provisioner()
        parameters = self.parameters()
        if parameters:  # omit empty
            v["parameters"] = parameters
        reclaimPolicy = self.reclaimPolicy()
        if reclaimPolicy is not None:  # omit empty
            v["reclaimPolicy"] = reclaimPolicy
        mountOptions = self.mountOptions()
        if mountOptions:  # omit empty
            v["mountOptions"] = mountOptions
        allowVolumeExpansion = self.allowVolumeExpansion()
        if allowVolumeExpansion is not None:  # omit empty
            v["allowVolumeExpansion"] = allowVolumeExpansion
        volumeBindingMode = self.volumeBindingMode()
        if volumeBindingMode is not None:  # omit empty
            v["volumeBindingMode"] = volumeBindingMode
        allowedTopologies = self.allowedTopologies()
        if allowedTopologies:  # omit empty
            v["allowedTopologies"] = allowedTopologies
        return v

    # Provisioner indicates the type of the provisioner.
    @typechecked
    def provisioner(self) -> str:
        return self.__provisioner

    # Parameters holds the parameters for the provisioner that should
    # create volumes of this storage class.
    @typechecked
    def parameters(self) -> Optional[Dict[str, str]]:
        return self.__parameters

    # Dynamically provisioned PersistentVolumes of this storage class are
    # created with this reclaimPolicy. Defaults to Delete.
    @typechecked
    def reclaimPolicy(self) -> Optional[corev1.PersistentVolumeReclaimPolicy]:
        return self.__reclaimPolicy

    # Dynamically provisioned PersistentVolumes of this storage class are
    # created with these mountOptions, e.g. ["ro", "soft"]. Not validated -
    # mount of the PVs will simply fail if one is invalid.
    @typechecked
    def mountOptions(self) -> Optional[List[str]]:
        return self.__mountOptions

    # AllowVolumeExpansion shows whether the storage class allow volume expand
    @typechecked
    def allowVolumeExpansion(self) -> Optional[bool]:
        return self.__allowVolumeExpansion

    # VolumeBindingMode indicates how PersistentVolumeClaims should be
    # provisioned and bound.  When unset, VolumeBindingImmediate is used.
    # This field is only honored by servers that enable the VolumeScheduling feature.
    @typechecked
    def volumeBindingMode(self) -> Optional[VolumeBindingMode]:
        return self.__volumeBindingMode

    # Restrict the node topologies where volumes can be dynamically provisioned.
    # Each volume plugin defines its own supported topology specifications.
    # An empty TopologySelectorTerm list means there is no topology restriction.
    # This field is only honored by servers that enable the VolumeScheduling feature.
    @typechecked
    def allowedTopologies(self) -> Optional[List["corev1.TopologySelectorTerm"]]:
        return self.__allowedTopologies


# VolumeAttachmentSource represents a volume that should be attached.
# Right now only PersistenVolumes can be attached via external attacher,
# in future we may allow also inline volumes in pods.
# Exactly one member can be set.
class VolumeAttachmentSource(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        persistentVolumeName: str = None,
        inlineVolumeSpec: "corev1.PersistentVolumeSpec" = None,
    ):
        super().__init__(**{})
        self.__persistentVolumeName = persistentVolumeName
        self.__inlineVolumeSpec = inlineVolumeSpec

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        persistentVolumeName = self.persistentVolumeName()
        if persistentVolumeName is not None:  # omit empty
            v["persistentVolumeName"] = persistentVolumeName
        inlineVolumeSpec = self.inlineVolumeSpec()
        if inlineVolumeSpec is not None:  # omit empty
            v["inlineVolumeSpec"] = inlineVolumeSpec
        return v

    # Name of the persistent volume to attach.
    @typechecked
    def persistentVolumeName(self) -> Optional[str]:
        return self.__persistentVolumeName

    # inlineVolumeSpec contains all the information necessary to attach
    # a persistent volume defined by a pod's inline VolumeSource. This field
    # is populated only for the CSIMigration feature. It contains
    # translated fields from a pod's inline VolumeSource to a
    # PersistentVolumeSpec. This field is alpha-level and is only
    # honored by servers that enabled the CSIMigration feature.
    @typechecked
    def inlineVolumeSpec(self) -> Optional["corev1.PersistentVolumeSpec"]:
        return self.__inlineVolumeSpec


# VolumeAttachmentSpec is the specification of a VolumeAttachment request.
class VolumeAttachmentSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        attacher: str = "",
        source: VolumeAttachmentSource = None,
        nodeName: str = "",
    ):
        super().__init__(**{})
        self.__attacher = attacher
        self.__source = source if source is not None else VolumeAttachmentSource()
        self.__nodeName = nodeName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["attacher"] = self.attacher()
        v["source"] = self.source()
        v["nodeName"] = self.nodeName()
        return v

    # Attacher indicates the name of the volume driver that MUST handle this
    # request. This is the name returned by GetPluginName().
    @typechecked
    def attacher(self) -> str:
        return self.__attacher

    # Source represents the volume that should be attached.
    @typechecked
    def source(self) -> VolumeAttachmentSource:
        return self.__source

    # The node that the volume should be attached to.
    @typechecked
    def nodeName(self) -> str:
        return self.__nodeName


# VolumeAttachment captures the intent to attach or detach the specified volume
# to/from the specified node.
#
# VolumeAttachment objects are non-namespaced.
class VolumeAttachment(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: VolumeAttachmentSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "storage.k8s.io/v1",
                "kind": "VolumeAttachment",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else VolumeAttachmentSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Specification of the desired attach/detach volume behavior.
    # Populated by the Kubernetes system.
    @typechecked
    def spec(self) -> VolumeAttachmentSpec:
        return self.__spec
