# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from kubespec.k8s import v1 as k8sv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


# / SignatureConditionType is a type of image signature condition.
SignatureConditionType = base.Enum("SignatureConditionType", {})


TagEventConditionType = base.Enum(
    "TagEventConditionType",
    {
        # ImportSuccess with status False means the import of the specific tag failed
        "ImportSuccess": "ImportSuccess"
    },
)


# TagReferencePolicyType describes how pull-specs for images in an image stream tag are generated when
# image change triggers are fired.
TagReferencePolicyType = base.Enum(
    "TagReferencePolicyType",
    {
        # Local indicates the image should prefer to pull via the local integrated registry,
        # falling back to the remote location if the integrated registry has not been configured. The reference will
        # use the internal DNS name or registry service IP.
        "Local": "Local",
        # Source indicates the image's original location should be used when the image stream tag
        # is resolved into other resources (builds and deployment configurations).
        "Source": "Source",
    },
)


class ImageLayer(types.Object):
    """
    ImageLayer represents a single layer of the image. Some images may have multiple layers. Some may have none.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", size: int = 0, mediaType: str = ""):
        super().__init__()
        self.__name = name
        self.__size = size
        self.__mediaType = mediaType

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        size = self.size()
        check_type("size", size, int)
        v["size"] = size
        mediaType = self.mediaType()
        check_type("mediaType", mediaType, str)
        v["mediaType"] = mediaType
        return v

    def name(self) -> str:
        """
        Name of the layer as defined by the underlying store.
        """
        return self.__name

    def size(self) -> int:
        """
        Size of the layer in bytes as defined by the underlying store.
        """
        return self.__size

    def mediaType(self) -> str:
        """
        MediaType of the referenced object.
        """
        return self.__mediaType


class SignatureCondition(types.Object):
    """
    SignatureCondition describes an image signature condition of particular kind at particular probe time.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: SignatureConditionType = None,
        status: k8sv1.ConditionStatus = None,
        lastProbeTime: "base.Time" = None,
        lastTransitionTime: "base.Time" = None,
        reason: str = None,
        message: str = None,
    ):
        super().__init__()
        self.__type = type
        self.__status = status
        self.__lastProbeTime = lastProbeTime
        self.__lastTransitionTime = lastTransitionTime
        self.__reason = reason
        self.__message = message

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, SignatureConditionType)
        v["type"] = type
        status = self.status()
        check_type("status", status, k8sv1.ConditionStatus)
        v["status"] = status
        lastProbeTime = self.lastProbeTime()
        check_type("lastProbeTime", lastProbeTime, Optional["base.Time"])
        v["lastProbeTime"] = lastProbeTime
        lastTransitionTime = self.lastTransitionTime()
        check_type("lastTransitionTime", lastTransitionTime, Optional["base.Time"])
        v["lastTransitionTime"] = lastTransitionTime
        reason = self.reason()
        check_type("reason", reason, Optional[str])
        if reason:  # omit empty
            v["reason"] = reason
        message = self.message()
        check_type("message", message, Optional[str])
        if message:  # omit empty
            v["message"] = message
        return v

    def type(self) -> SignatureConditionType:
        """
        Type of signature condition, Complete or Failed.
        """
        return self.__type

    def status(self) -> k8sv1.ConditionStatus:
        """
        Status of the condition, one of True, False, Unknown.
        """
        return self.__status

    def lastProbeTime(self) -> Optional["base.Time"]:
        """
        Last time the condition was checked.
        """
        return self.__lastProbeTime

    def lastTransitionTime(self) -> Optional["base.Time"]:
        """
        Last time the condition transit from one status to another.
        """
        return self.__lastTransitionTime

    def reason(self) -> Optional[str]:
        """
        (brief) reason for the condition's last transition.
        """
        return self.__reason

    def message(self) -> Optional[str]:
        """
        Human readable message indicating details about last transition.
        """
        return self.__message


class SignatureGenericEntity(types.Object):
    """
    SignatureGenericEntity holds a generic information about a person or entity who is an issuer or a subject
    of signing certificate or key.
    """

    @context.scoped
    @typechecked
    def __init__(self, organization: str = None, commonName: str = None):
        super().__init__()
        self.__organization = organization
        self.__commonName = commonName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        organization = self.organization()
        check_type("organization", organization, Optional[str])
        if organization:  # omit empty
            v["organization"] = organization
        commonName = self.commonName()
        check_type("commonName", commonName, Optional[str])
        if commonName:  # omit empty
            v["commonName"] = commonName
        return v

    def organization(self) -> Optional[str]:
        """
        Organization name.
        """
        return self.__organization

    def commonName(self) -> Optional[str]:
        """
        Common name (e.g. openshift-signing-service).
        """
        return self.__commonName


class SignatureIssuer(types.Object):
    """
    SignatureIssuer holds information about an issuer of signing certificate or key.
    """

    @context.scoped
    @typechecked
    def __init__(self, signatureGenericEntity: "SignatureGenericEntity" = None):
        super().__init__()
        self.__signatureGenericEntity = (
            signatureGenericEntity
            if signatureGenericEntity is not None
            else SignatureGenericEntity()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        signatureGenericEntity = self.signatureGenericEntity()
        check_type(
            "signatureGenericEntity", signatureGenericEntity, "SignatureGenericEntity"
        )
        v.update(signatureGenericEntity._root())  # inline
        return v

    def signatureGenericEntity(self) -> "SignatureGenericEntity":
        return self.__signatureGenericEntity


class SignatureSubject(types.Object):
    """
    SignatureSubject holds information about a person or entity who created the signature.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        signatureGenericEntity: "SignatureGenericEntity" = None,
        publicKeyID: str = "",
    ):
        super().__init__()
        self.__signatureGenericEntity = (
            signatureGenericEntity
            if signatureGenericEntity is not None
            else SignatureGenericEntity()
        )
        self.__publicKeyID = publicKeyID

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        signatureGenericEntity = self.signatureGenericEntity()
        check_type(
            "signatureGenericEntity", signatureGenericEntity, "SignatureGenericEntity"
        )
        v.update(signatureGenericEntity._root())  # inline
        publicKeyID = self.publicKeyID()
        check_type("publicKeyID", publicKeyID, str)
        v["publicKeyID"] = publicKeyID
        return v

    def signatureGenericEntity(self) -> "SignatureGenericEntity":
        return self.__signatureGenericEntity

    def publicKeyID(self) -> str:
        """
        If present, it is a human readable key id of public key belonging to the subject used to verify image
        signature. It should contain at least 64 lowest bits of public key's fingerprint (e.g.
        0x685ebe62bf278440).
        """
        return self.__publicKeyID


class ImageSignature(base.TypedObject, base.MetadataObject):
    """
    ImageSignature holds a signature of an image. It allows to verify image identity and possibly other claims
    as long as the signature is trusted. Based on this information it is possible to restrict runnable images
    to those matching cluster-wide policy.
    Mandatory fields should be parsed by clients doing image verification. The others are parsed from
    signature's content by the server. They serve just an informative purpose.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        type: str = "",
        content: bytes = None,
        conditions: List["SignatureCondition"] = None,
        imageIdentity: str = None,
        signedClaims: Dict[str, str] = None,
        created: "base.Time" = None,
        issuedBy: "SignatureIssuer" = None,
        issuedTo: "SignatureSubject" = None,
    ):
        super().__init__(
            apiVersion="image.openshift.io/v1",
            kind="ImageSignature",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__type = type
        self.__content = content if content is not None else b""
        self.__conditions = conditions if conditions is not None else []
        self.__imageIdentity = imageIdentity
        self.__signedClaims = signedClaims if signedClaims is not None else {}
        self.__created = created
        self.__issuedBy = issuedBy
        self.__issuedTo = issuedTo

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, str)
        v["type"] = type
        content = self.content()
        check_type("content", content, bytes)
        v["content"] = content
        conditions = self.conditions()
        check_type("conditions", conditions, Optional[List["SignatureCondition"]])
        if conditions:  # omit empty
            v["conditions"] = conditions
        imageIdentity = self.imageIdentity()
        check_type("imageIdentity", imageIdentity, Optional[str])
        if imageIdentity:  # omit empty
            v["imageIdentity"] = imageIdentity
        signedClaims = self.signedClaims()
        check_type("signedClaims", signedClaims, Optional[Dict[str, str]])
        if signedClaims:  # omit empty
            v["signedClaims"] = signedClaims
        created = self.created()
        check_type("created", created, Optional["base.Time"])
        if created is not None:  # omit empty
            v["created"] = created
        issuedBy = self.issuedBy()
        check_type("issuedBy", issuedBy, Optional["SignatureIssuer"])
        if issuedBy is not None:  # omit empty
            v["issuedBy"] = issuedBy
        issuedTo = self.issuedTo()
        check_type("issuedTo", issuedTo, Optional["SignatureSubject"])
        if issuedTo is not None:  # omit empty
            v["issuedTo"] = issuedTo
        return v

    def type(self) -> str:
        """
        Required: Describes a type of stored blob.
        """
        return self.__type

    def content(self) -> bytes:
        """
        Required: An opaque binary string which is an image's signature.
        """
        return self.__content

    def conditions(self) -> Optional[List["SignatureCondition"]]:
        """
        Conditions represent the latest available observations of a signature's current state.
        """
        return self.__conditions

    def imageIdentity(self) -> Optional[str]:
        """
        A human readable string representing image's identity. It could be a product name and version, or an
        image pull spec (e.g. "registry.access.redhat.com/rhel7/rhel:7.2").
        """
        return self.__imageIdentity

    def signedClaims(self) -> Optional[Dict[str, str]]:
        """
        Contains claims from the signature.
        """
        return self.__signedClaims

    def created(self) -> Optional["base.Time"]:
        """
        If specified, it is the time of signature's creation.
        """
        return self.__created

    def issuedBy(self) -> Optional["SignatureIssuer"]:
        """
        If specified, it holds information about an issuer of signing certificate or key (a person or entity
        who signed the signing certificate or key).
        """
        return self.__issuedBy

    def issuedTo(self) -> Optional["SignatureSubject"]:
        """
        If specified, it holds information about a subject of signing certificate or key (a person or entity
        who signed the image).
        """
        return self.__issuedTo


class Image(base.TypedObject, base.MetadataObject):
    """
    Image is an immutable representation of a container image and metadata at a point in time.
    Images are named by taking a hash of their contents (metadata and content) and any change
    in format, content, or metadata results in a new name. The images resource is primarily
    for use by cluster administrators and integrations like the cluster image registry - end
    users instead access images via the imagestreamtags or imagestreamimages resources. While
    image metadata is stored in the API, any integration that implements the container image
    registry API must provide its own storage for the raw manifest data, image config, and
    layer contents.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        dockerImageReference: str = None,
        dockerImageMetadata: "runtime.RawExtension" = None,
        dockerImageMetadataVersion: str = None,
        dockerImageManifest: str = None,
        dockerImageLayers: List["ImageLayer"] = None,
        signatures: List["ImageSignature"] = None,
        dockerImageSignatures: List[bytes] = None,
        dockerImageManifestMediaType: str = None,
        dockerImageConfig: str = None,
    ):
        super().__init__(
            apiVersion="image.openshift.io/v1",
            kind="Image",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__dockerImageReference = dockerImageReference
        self.__dockerImageMetadata = dockerImageMetadata
        self.__dockerImageMetadataVersion = dockerImageMetadataVersion
        self.__dockerImageManifest = dockerImageManifest
        self.__dockerImageLayers = (
            dockerImageLayers if dockerImageLayers is not None else []
        )
        self.__signatures = signatures if signatures is not None else []
        self.__dockerImageSignatures = (
            dockerImageSignatures if dockerImageSignatures is not None else []
        )
        self.__dockerImageManifestMediaType = dockerImageManifestMediaType
        self.__dockerImageConfig = dockerImageConfig

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        dockerImageReference = self.dockerImageReference()
        check_type("dockerImageReference", dockerImageReference, Optional[str])
        if dockerImageReference:  # omit empty
            v["dockerImageReference"] = dockerImageReference
        dockerImageMetadata = self.dockerImageMetadata()
        check_type(
            "dockerImageMetadata", dockerImageMetadata, Optional["runtime.RawExtension"]
        )
        v["dockerImageMetadata"] = dockerImageMetadata
        dockerImageMetadataVersion = self.dockerImageMetadataVersion()
        check_type(
            "dockerImageMetadataVersion", dockerImageMetadataVersion, Optional[str]
        )
        if dockerImageMetadataVersion:  # omit empty
            v["dockerImageMetadataVersion"] = dockerImageMetadataVersion
        dockerImageManifest = self.dockerImageManifest()
        check_type("dockerImageManifest", dockerImageManifest, Optional[str])
        if dockerImageManifest:  # omit empty
            v["dockerImageManifest"] = dockerImageManifest
        dockerImageLayers = self.dockerImageLayers()
        check_type("dockerImageLayers", dockerImageLayers, List["ImageLayer"])
        v["dockerImageLayers"] = dockerImageLayers
        signatures = self.signatures()
        check_type("signatures", signatures, Optional[List["ImageSignature"]])
        if signatures:  # omit empty
            v["signatures"] = signatures
        dockerImageSignatures = self.dockerImageSignatures()
        check_type(
            "dockerImageSignatures", dockerImageSignatures, Optional[List[bytes]]
        )
        if dockerImageSignatures:  # omit empty
            v["dockerImageSignatures"] = dockerImageSignatures
        dockerImageManifestMediaType = self.dockerImageManifestMediaType()
        check_type(
            "dockerImageManifestMediaType", dockerImageManifestMediaType, Optional[str]
        )
        if dockerImageManifestMediaType:  # omit empty
            v["dockerImageManifestMediaType"] = dockerImageManifestMediaType
        dockerImageConfig = self.dockerImageConfig()
        check_type("dockerImageConfig", dockerImageConfig, Optional[str])
        if dockerImageConfig:  # omit empty
            v["dockerImageConfig"] = dockerImageConfig
        return v

    def dockerImageReference(self) -> Optional[str]:
        """
        DockerImageReference is the string that can be used to pull this image.
        """
        return self.__dockerImageReference

    def dockerImageMetadata(self) -> Optional["runtime.RawExtension"]:
        """
        DockerImageMetadata contains metadata about this image
        """
        return self.__dockerImageMetadata

    def dockerImageMetadataVersion(self) -> Optional[str]:
        """
        DockerImageMetadataVersion conveys the version of the object, which if empty defaults to "1.0"
        """
        return self.__dockerImageMetadataVersion

    def dockerImageManifest(self) -> Optional[str]:
        """
        DockerImageManifest is the raw JSON of the manifest
        """
        return self.__dockerImageManifest

    def dockerImageLayers(self) -> List["ImageLayer"]:
        """
        DockerImageLayers represents the layers in the image. May not be set if the image does not define that data.
        """
        return self.__dockerImageLayers

    def signatures(self) -> Optional[List["ImageSignature"]]:
        """
        Signatures holds all signatures of the image.
        """
        return self.__signatures

    def dockerImageSignatures(self) -> Optional[List[bytes]]:
        """
        DockerImageSignatures provides the signatures as opaque blobs. This is a part of manifest schema v1.
        """
        return self.__dockerImageSignatures

    def dockerImageManifestMediaType(self) -> Optional[str]:
        """
        DockerImageManifestMediaType specifies the mediaType of manifest. This is a part of manifest schema v2.
        """
        return self.__dockerImageManifestMediaType

    def dockerImageConfig(self) -> Optional[str]:
        """
        DockerImageConfig is a JSON blob that the runtime uses to set up the container. This is a part of manifest schema v2.
        """
        return self.__dockerImageConfig


class ImageBlobReferences(types.Object):
    """
    ImageBlobReferences describes the blob references within an image.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, imageMissing: bool = False, layers: List[str] = None, config: str = None
    ):
        super().__init__()
        self.__imageMissing = imageMissing
        self.__layers = layers if layers is not None else []
        self.__config = config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        imageMissing = self.imageMissing()
        check_type("imageMissing", imageMissing, bool)
        v["imageMissing"] = imageMissing
        layers = self.layers()
        check_type("layers", layers, List[str])
        v["layers"] = layers
        config = self.config()
        check_type("config", config, Optional[str])
        v["config"] = config
        return v

    def imageMissing(self) -> bool:
        """
        imageMissing is true if the image is referenced by the image stream but the image
        object has been deleted from the API by an administrator. When this field is set,
        layers and config fields may be empty and callers that depend on the image metadata
        should consider the image to be unavailable for download or viewing.
        """
        return self.__imageMissing

    def layers(self) -> List[str]:
        """
        layers is the list of blobs that compose this image, from base layer to top layer.
        All layers referenced by this array will be defined in the blobs map. Some images
        may have zero layers.
        """
        return self.__layers

    def config(self) -> Optional[str]:
        """
        config, if set, is the blob that contains the image config. Some images do
        not have separate config blobs and this field will be set to nil if so.
        """
        return self.__config


class TagImportPolicy(types.Object):
    """
    TagImportPolicy controls how images related to this tag will be imported.
    """

    @context.scoped
    @typechecked
    def __init__(self, insecure: bool = None, scheduled: bool = None):
        super().__init__()
        self.__insecure = insecure
        self.__scheduled = scheduled

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        insecure = self.insecure()
        check_type("insecure", insecure, Optional[bool])
        if insecure:  # omit empty
            v["insecure"] = insecure
        scheduled = self.scheduled()
        check_type("scheduled", scheduled, Optional[bool])
        if scheduled:  # omit empty
            v["scheduled"] = scheduled
        return v

    def insecure(self) -> Optional[bool]:
        """
        Insecure is true if the server may bypass certificate verification or connect directly over HTTP during image import.
        """
        return self.__insecure

    def scheduled(self) -> Optional[bool]:
        """
        Scheduled indicates to the server that this tag should be periodically checked to ensure it is up to date, and imported
        """
        return self.__scheduled


class TagReferencePolicy(types.Object):
    """
    TagReferencePolicy describes how pull-specs for images in this image stream tag are generated when
    image change triggers in deployment configs or builds are resolved. This allows the image stream
    author to control how images are accessed.
    """

    @context.scoped
    @typechecked
    def __init__(self, type: TagReferencePolicyType = TagReferencePolicyType["Source"]):
        super().__init__()
        self.__type = type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, TagReferencePolicyType)
        v["type"] = type
        return v

    def type(self) -> TagReferencePolicyType:
        """
        Type determines how the image pull spec should be transformed when the image stream tag is used in
        deployment config triggers or new builds. The default value is `Source`, indicating the original
        location of the image should be used (if imported). The user may also specify `Local`, indicating
        that the pull spec should point to the integrated container image registry and leverage the registry's
        ability to proxy the pull to an upstream registry. `Local` allows the credentials used to pull this
        image to be managed from the image stream's namespace, so others on the platform can access a remote
        image but have no access to the remote secret. It also allows the image layers to be mirrored into
        the local registry which the images can still be pulled even if the upstream registry is unavailable.
        """
        return self.__type


class ImageImportSpec(types.Object):
    """
    ImageImportSpec describes a request to import a specific image.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        from_: "k8sv1.ObjectReference" = None,
        to: "k8sv1.LocalObjectReference" = None,
        importPolicy: "TagImportPolicy" = None,
        referencePolicy: "TagReferencePolicy" = None,
        includeManifest: bool = None,
    ):
        super().__init__()
        self.__from_ = from_ if from_ is not None else k8sv1.ObjectReference()
        self.__to = to
        self.__importPolicy = (
            importPolicy if importPolicy is not None else TagImportPolicy()
        )
        self.__referencePolicy = (
            referencePolicy if referencePolicy is not None else TagReferencePolicy()
        )
        self.__includeManifest = includeManifest

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        from_ = self.from_()
        check_type("from_", from_, "k8sv1.ObjectReference")
        v["from"] = from_
        to = self.to()
        check_type("to", to, Optional["k8sv1.LocalObjectReference"])
        if to is not None:  # omit empty
            v["to"] = to
        importPolicy = self.importPolicy()
        check_type("importPolicy", importPolicy, Optional["TagImportPolicy"])
        v["importPolicy"] = importPolicy
        referencePolicy = self.referencePolicy()
        check_type("referencePolicy", referencePolicy, Optional["TagReferencePolicy"])
        v["referencePolicy"] = referencePolicy
        includeManifest = self.includeManifest()
        check_type("includeManifest", includeManifest, Optional[bool])
        if includeManifest:  # omit empty
            v["includeManifest"] = includeManifest
        return v

    def from_(self) -> "k8sv1.ObjectReference":
        """
        From is the source of an image to import; only kind DockerImage is allowed
        """
        return self.__from_

    def to(self) -> Optional["k8sv1.LocalObjectReference"]:
        """
        To is a tag in the current image stream to assign the imported image to, if name is not specified the default tag from from.name will be used
        """
        return self.__to

    def importPolicy(self) -> Optional["TagImportPolicy"]:
        """
        ImportPolicy is the policy controlling how the image is imported
        """
        return self.__importPolicy

    def referencePolicy(self) -> Optional["TagReferencePolicy"]:
        """
        ReferencePolicy defines how other components should consume the image
        """
        return self.__referencePolicy

    def includeManifest(self) -> Optional[bool]:
        """
        IncludeManifest determines if the manifest for each image is returned in the response
        """
        return self.__includeManifest


class ImageLayerData(types.Object):
    """
    ImageLayerData contains metadata about an image layer.
    """

    @context.scoped
    @typechecked
    def __init__(self, size: int = None, mediaType: str = ""):
        super().__init__()
        self.__size = size
        self.__mediaType = mediaType

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        size = self.size()
        check_type("size", size, Optional[int])
        v["size"] = size
        mediaType = self.mediaType()
        check_type("mediaType", mediaType, str)
        v["mediaType"] = mediaType
        return v

    def size(self) -> Optional[int]:
        """
        Size of the layer in bytes as defined by the underlying store. This field is
        optional if the necessary information about size is not available.
        """
        return self.__size

    def mediaType(self) -> str:
        """
        MediaType of the referenced object.
        """
        return self.__mediaType


class ImageLookupPolicy(types.Object):
    """
    ImageLookupPolicy describes how an image stream can be used to override the image references
    used by pods, builds, and other resources in a namespace.
    """

    @context.scoped
    @typechecked
    def __init__(self, local: bool = False):
        super().__init__()
        self.__local = local

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        local = self.local()
        check_type("local", local, bool)
        v["local"] = local
        return v

    def local(self) -> bool:
        """
        local will change the docker short image references (like "mysql" or
        "php:latest") on objects in this namespace to the image ID whenever they match
        this image stream, instead of reaching out to a remote registry. The name will
        be fully qualified to an image ID if found. The tag's referencePolicy is taken
        into account on the replaced value. Only works within the current namespace.
        """
        return self.__local


class TagReference(types.Object):
    """
    TagReference specifies optional annotations for images using this tag and an optional reference to an ImageStreamTag, ImageStreamImage, or DockerImage this tag should track.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        annotations: Dict[str, str] = None,
        from_: "k8sv1.ObjectReference" = None,
        reference: bool = None,
        generation: int = None,
        importPolicy: "TagImportPolicy" = None,
        referencePolicy: "TagReferencePolicy" = None,
    ):
        super().__init__()
        self.__name = name
        self.__annotations = annotations if annotations is not None else {}
        self.__from_ = from_
        self.__reference = reference
        self.__generation = generation
        self.__importPolicy = (
            importPolicy if importPolicy is not None else TagImportPolicy()
        )
        self.__referencePolicy = (
            referencePolicy if referencePolicy is not None else TagReferencePolicy()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        annotations = self.annotations()
        check_type("annotations", annotations, Dict[str, str])
        v["annotations"] = annotations
        from_ = self.from_()
        check_type("from_", from_, Optional["k8sv1.ObjectReference"])
        if from_ is not None:  # omit empty
            v["from"] = from_
        reference = self.reference()
        check_type("reference", reference, Optional[bool])
        if reference:  # omit empty
            v["reference"] = reference
        generation = self.generation()
        check_type("generation", generation, Optional[int])
        v["generation"] = generation
        importPolicy = self.importPolicy()
        check_type("importPolicy", importPolicy, Optional["TagImportPolicy"])
        v["importPolicy"] = importPolicy
        referencePolicy = self.referencePolicy()
        check_type("referencePolicy", referencePolicy, Optional["TagReferencePolicy"])
        v["referencePolicy"] = referencePolicy
        return v

    def name(self) -> str:
        """
        Name of the tag
        """
        return self.__name

    def annotations(self) -> Dict[str, str]:
        """
        Optional; if specified, annotations that are applied to images retrieved via ImageStreamTags.
        """
        return self.__annotations

    def from_(self) -> Optional["k8sv1.ObjectReference"]:
        """
        Optional; if specified, a reference to another image that this tag should point to. Valid values
        are ImageStreamTag, ImageStreamImage, and DockerImage.  ImageStreamTag references
        can only reference a tag within this same ImageStream.
        """
        return self.__from_

    def reference(self) -> Optional[bool]:
        """
        Reference states if the tag will be imported. Default value is false, which means the tag will
        be imported.
        """
        return self.__reference

    def generation(self) -> Optional[int]:
        """
        Generation is a counter that tracks mutations to the spec tag (user intent). When a tag reference
        is changed the generation is set to match the current stream generation (which is incremented every
        time spec is changed). Other processes in the system like the image importer observe that the
        generation of spec tag is newer than the generation recorded in the status and use that as a trigger
        to import the newest remote tag. To trigger a new import, clients may set this value to zero which
        will reset the generation to the latest stream generation. Legacy clients will send this value as
        nil which will be merged with the current tag generation.
        """
        return self.__generation

    def importPolicy(self) -> Optional["TagImportPolicy"]:
        """
        ImportPolicy is information that controls how images may be imported by the server.
        """
        return self.__importPolicy

    def referencePolicy(self) -> Optional["TagReferencePolicy"]:
        """
        ReferencePolicy defines how other components should consume the image.
        """
        return self.__referencePolicy


class ImageStreamSpec(types.Object):
    """
    ImageStreamSpec represents options for ImageStreams.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        lookupPolicy: "ImageLookupPolicy" = None,
        tags: List["TagReference"] = None,
    ):
        super().__init__()
        self.__lookupPolicy = (
            lookupPolicy if lookupPolicy is not None else ImageLookupPolicy()
        )
        self.__tags = tags if tags is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        lookupPolicy = self.lookupPolicy()
        check_type("lookupPolicy", lookupPolicy, Optional["ImageLookupPolicy"])
        v["lookupPolicy"] = lookupPolicy
        tags = self.tags()
        check_type("tags", tags, Optional[List["TagReference"]])
        if tags:  # omit empty
            v["tags"] = tags
        return v

    def lookupPolicy(self) -> Optional["ImageLookupPolicy"]:
        """
        lookupPolicy controls how other resources reference images within this namespace.
        """
        return self.__lookupPolicy

    def tags(self) -> Optional[List["TagReference"]]:
        """
        tags map arbitrary string values to specific image locators
        """
        return self.__tags


class ImageStream(base.TypedObject, base.NamespacedMetadataObject):
    """
    An ImageStream stores a mapping of tags to images, metadata overrides that are applied
    when images are tagged in a stream, and an optional reference to a container image
    repository on a registry. Users typically update the spec.tags field to point to external
    images which are imported from container registries using credentials in your namespace
    with the pull secret type, or to existing image stream tags and images which are
    immediately accessible for tagging or pulling. The history of images applied to a tag
    is visible in the status.tags field and any user who can view an image stream is allowed
    to tag that image into their own image streams. Access to pull images from the integrated
    registry is granted by having the "get imagestreams/layers" permission on a given image
    stream. Users may remove a tag by deleting the imagestreamtag resource, which causes both
    spec and status for that tag to be removed. Image stream history is retained until an
    administrator runs the prune operation, which removes references that are no longer in
    use. To preserve a historical image, ensure there is a tag in spec pointing to that image
    by its digest.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ImageStreamSpec" = None,
    ):
        super().__init__(
            apiVersion="image.openshift.io/v1",
            kind="ImageStream",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ImageStreamSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ImageStreamSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ImageStreamSpec":
        """
        Spec describes the desired state of this stream
        """
        return self.__spec


class ImageStreamImage(base.TypedObject, base.NamespacedMetadataObject):
    """
    ImageStreamImage represents an Image that is retrieved by image name from an ImageStream.
    User interfaces and regular users can use this resource to access the metadata details of
    a tagged image in the image stream history for viewing, since Image resources are not
    directly accessible to end users. A not found error will be returned if no such image is
    referenced by a tag within the ImageStream. Images are created when spec tags are set on
    an image stream that represent an image in an external registry, when pushing to the
    integrated registry, or when tagging an existing image from one image stream to another.
    The name of an image stream image is in the form "<STREAM>@<DIGEST>", where the digest is
    the content addressible identifier for the image (sha256:xxxxx...). You can use
    ImageStreamImages as the from.kind of an image stream spec tag to reference an image
    exactly. The only operations supported on the imagestreamimage endpoint are retrieving
    the image.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        image: "Image" = None,
    ):
        super().__init__(
            apiVersion="image.openshift.io/v1",
            kind="ImageStreamImage",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__image = image if image is not None else Image()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        image = self.image()
        check_type("image", image, "Image")
        v["image"] = image
        return v

    def image(self) -> "Image":
        """
        Image associated with the ImageStream and image name.
        """
        return self.__image


class RepositoryImportSpec(types.Object):
    """
    RepositoryImportSpec describes a request to import images from a container image repository.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        from_: "k8sv1.ObjectReference" = None,
        importPolicy: "TagImportPolicy" = None,
        referencePolicy: "TagReferencePolicy" = None,
        includeManifest: bool = None,
    ):
        super().__init__()
        self.__from_ = from_ if from_ is not None else k8sv1.ObjectReference()
        self.__importPolicy = (
            importPolicy if importPolicy is not None else TagImportPolicy()
        )
        self.__referencePolicy = (
            referencePolicy if referencePolicy is not None else TagReferencePolicy()
        )
        self.__includeManifest = includeManifest

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        from_ = self.from_()
        check_type("from_", from_, "k8sv1.ObjectReference")
        v["from"] = from_
        importPolicy = self.importPolicy()
        check_type("importPolicy", importPolicy, Optional["TagImportPolicy"])
        v["importPolicy"] = importPolicy
        referencePolicy = self.referencePolicy()
        check_type("referencePolicy", referencePolicy, Optional["TagReferencePolicy"])
        v["referencePolicy"] = referencePolicy
        includeManifest = self.includeManifest()
        check_type("includeManifest", includeManifest, Optional[bool])
        if includeManifest:  # omit empty
            v["includeManifest"] = includeManifest
        return v

    def from_(self) -> "k8sv1.ObjectReference":
        """
        From is the source for the image repository to import; only kind DockerImage and a name of a container image repository is allowed
        """
        return self.__from_

    def importPolicy(self) -> Optional["TagImportPolicy"]:
        """
        ImportPolicy is the policy controlling how the image is imported
        """
        return self.__importPolicy

    def referencePolicy(self) -> Optional["TagReferencePolicy"]:
        """
        ReferencePolicy defines how other components should consume the image
        """
        return self.__referencePolicy

    def includeManifest(self) -> Optional[bool]:
        """
        IncludeManifest determines if the manifest for each image is returned in the response
        """
        return self.__includeManifest


class ImageStreamImportSpec(types.Object):
    """
    ImageStreamImportSpec defines what images should be imported.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        import_: bool = False,
        repository: "RepositoryImportSpec" = None,
        images: List["ImageImportSpec"] = None,
    ):
        super().__init__()
        self.__import_ = import_
        self.__repository = repository
        self.__images = images if images is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        import_ = self.import_()
        check_type("import_", import_, bool)
        v["import"] = import_
        repository = self.repository()
        check_type("repository", repository, Optional["RepositoryImportSpec"])
        if repository is not None:  # omit empty
            v["repository"] = repository
        images = self.images()
        check_type("images", images, Optional[List["ImageImportSpec"]])
        if images:  # omit empty
            v["images"] = images
        return v

    def import_(self) -> bool:
        """
        Import indicates whether to perform an import - if so, the specified tags are set on the spec
        and status of the image stream defined by the type meta.
        """
        return self.__import_

    def repository(self) -> Optional["RepositoryImportSpec"]:
        """
        Repository is an optional import of an entire container image repository. A maximum limit on the
        number of tags imported this way is imposed by the server.
        """
        return self.__repository

    def images(self) -> Optional[List["ImageImportSpec"]]:
        """
        Images are a list of individual images to import.
        """
        return self.__images


class ImageStreamImport(base.TypedObject, base.NamespacedMetadataObject):
    """
    The image stream import resource provides an easy way for a user to find and import container images
    from other container image registries into the server. Individual images or an entire image repository may
    be imported, and users may choose to see the results of the import prior to tagging the resulting
    images into the specified image stream.
    
    This API is intended for end-user tools that need to see the metadata of the image prior to import
    (for instance, to generate an application from it). Clients that know the desired image can continue
    to create spec.tags directly into their image streams.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ImageStreamImportSpec" = None,
    ):
        super().__init__(
            apiVersion="image.openshift.io/v1",
            kind="ImageStreamImport",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ImageStreamImportSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ImageStreamImportSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ImageStreamImportSpec":
        """
        Spec is a description of the images that the user wishes to import
        """
        return self.__spec


class ImageStreamLayers(base.TypedObject, base.NamespacedMetadataObject):
    """
    ImageStreamLayers describes information about the layers referenced by images in this
    image stream.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        blobs: Dict[str, "ImageLayerData"] = None,
        images: Dict[str, "ImageBlobReferences"] = None,
    ):
        super().__init__(
            apiVersion="image.openshift.io/v1",
            kind="ImageStreamLayers",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__blobs = blobs if blobs is not None else {}
        self.__images = images if images is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        blobs = self.blobs()
        check_type("blobs", blobs, Dict[str, "ImageLayerData"])
        v["blobs"] = blobs
        images = self.images()
        check_type("images", images, Dict[str, "ImageBlobReferences"])
        v["images"] = images
        return v

    def blobs(self) -> Dict[str, "ImageLayerData"]:
        """
        blobs is a map of blob name to metadata about the blob.
        """
        return self.__blobs

    def images(self) -> Dict[str, "ImageBlobReferences"]:
        """
        images is a map between an image name and the names of the blobs and config that
        comprise the image.
        """
        return self.__images


class ImageStreamMapping(base.TypedObject, base.NamespacedMetadataObject):
    """
    ImageStreamMapping represents a mapping from a single image stream tag to a container
    image as well as the reference to the container image stream the image came from. This
    resource is used by privileged integrators to create an image resource and to associate
    it with an image stream in the status tags field. Creating an ImageStreamMapping will
    allow any user who can view the image stream to tag or pull that image, so only create
    mappings where the user has proven they have access to the image contents directly.
    The only operation supported for this resource is create and the metadata name and
    namespace should be set to the image stream containing the tag that should be updated.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        image: "Image" = None,
        tag: str = "",
    ):
        super().__init__(
            apiVersion="image.openshift.io/v1",
            kind="ImageStreamMapping",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__image = image if image is not None else Image()
        self.__tag = tag

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        image = self.image()
        check_type("image", image, "Image")
        v["image"] = image
        tag = self.tag()
        check_type("tag", tag, str)
        v["tag"] = tag
        return v

    def image(self) -> "Image":
        """
        Image is a container image.
        """
        return self.__image

    def tag(self) -> str:
        """
        Tag is a string value this image can be located with inside the stream.
        """
        return self.__tag


class TagEventCondition(types.Object):
    """
    TagEventCondition contains condition information for a tag event.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: TagEventConditionType = None,
        status: k8sv1.ConditionStatus = None,
        lastTransitionTime: "base.Time" = None,
        reason: str = None,
        message: str = None,
        generation: int = 0,
    ):
        super().__init__()
        self.__type = type
        self.__status = status
        self.__lastTransitionTime = lastTransitionTime
        self.__reason = reason
        self.__message = message
        self.__generation = generation

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, TagEventConditionType)
        v["type"] = type
        status = self.status()
        check_type("status", status, k8sv1.ConditionStatus)
        v["status"] = status
        lastTransitionTime = self.lastTransitionTime()
        check_type("lastTransitionTime", lastTransitionTime, Optional["base.Time"])
        v["lastTransitionTime"] = lastTransitionTime
        reason = self.reason()
        check_type("reason", reason, Optional[str])
        if reason:  # omit empty
            v["reason"] = reason
        message = self.message()
        check_type("message", message, Optional[str])
        if message:  # omit empty
            v["message"] = message
        generation = self.generation()
        check_type("generation", generation, int)
        v["generation"] = generation
        return v

    def type(self) -> TagEventConditionType:
        """
        Type of tag event condition, currently only ImportSuccess
        """
        return self.__type

    def status(self) -> k8sv1.ConditionStatus:
        """
        Status of the condition, one of True, False, Unknown.
        """
        return self.__status

    def lastTransitionTime(self) -> Optional["base.Time"]:
        """
        LastTransitionTIme is the time the condition transitioned from one status to another.
        """
        return self.__lastTransitionTime

    def reason(self) -> Optional[str]:
        """
        Reason is a brief machine readable explanation for the condition's last transition.
        """
        return self.__reason

    def message(self) -> Optional[str]:
        """
        Message is a human readable description of the details about last transition, complementing reason.
        """
        return self.__message

    def generation(self) -> int:
        """
        Generation is the spec tag generation that this status corresponds to
        """
        return self.__generation


class ImageStreamTag(base.TypedObject, base.NamespacedMetadataObject):
    """
    ImageStreamTag represents an Image that is retrieved by tag name from an ImageStream.
    Use this resource to interact with the tags and images in an image stream by tag, or
    to see the image details for a particular tag. The image associated with this resource
    is the most recently successfully tagged, imported, or pushed image (as described in the
    image stream status.tags.items list for this tag). If an import is in progress or has
    failed the previous image will be shown. Deleting an image stream tag clears both the
    status and spec fields of an image stream. If no image can be retrieved for a given tag,
    a not found error will be returned.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        tag: "TagReference" = None,
        generation: int = 0,
        lookupPolicy: "ImageLookupPolicy" = None,
        conditions: List["TagEventCondition"] = None,
        image: "Image" = None,
    ):
        super().__init__(
            apiVersion="image.openshift.io/v1",
            kind="ImageStreamTag",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__tag = tag
        self.__generation = generation
        self.__lookupPolicy = (
            lookupPolicy if lookupPolicy is not None else ImageLookupPolicy()
        )
        self.__conditions = conditions if conditions is not None else []
        self.__image = image if image is not None else Image()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        tag = self.tag()
        check_type("tag", tag, Optional["TagReference"])
        v["tag"] = tag
        generation = self.generation()
        check_type("generation", generation, int)
        v["generation"] = generation
        lookupPolicy = self.lookupPolicy()
        check_type("lookupPolicy", lookupPolicy, "ImageLookupPolicy")
        v["lookupPolicy"] = lookupPolicy
        conditions = self.conditions()
        check_type("conditions", conditions, Optional[List["TagEventCondition"]])
        if conditions:  # omit empty
            v["conditions"] = conditions
        image = self.image()
        check_type("image", image, "Image")
        v["image"] = image
        return v

    def tag(self) -> Optional["TagReference"]:
        """
        tag is the spec tag associated with this image stream tag, and it may be null
        if only pushes have occurred to this image stream.
        """
        return self.__tag

    def generation(self) -> int:
        """
        generation is the current generation of the tagged image - if tag is provided
        and this value is not equal to the tag generation, a user has requested an
        import that has not completed, or conditions will be filled out indicating any
        error.
        """
        return self.__generation

    def lookupPolicy(self) -> "ImageLookupPolicy":
        """
        lookupPolicy indicates whether this tag will handle image references in this
        namespace.
        """
        return self.__lookupPolicy

    def conditions(self) -> Optional[List["TagEventCondition"]]:
        """
        conditions is an array of conditions that apply to the image stream tag.
        """
        return self.__conditions

    def image(self) -> "Image":
        """
        image associated with the ImageStream and tag.
        """
        return self.__image
