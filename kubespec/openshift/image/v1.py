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
    def __init__(self, name: str = "", size: int = 0, media_type: str = ""):
        super().__init__()
        self.__name = name
        self.__size = size
        self.__media_type = media_type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        size = self.size()
        check_type("size", size, int)
        v["size"] = size
        media_type = self.media_type()
        check_type("media_type", media_type, str)
        v["mediaType"] = media_type
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

    def media_type(self) -> str:
        """
        MediaType of the referenced object.
        """
        return self.__media_type


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
        last_probe_time: "base.Time" = None,
        last_transition_time: "base.Time" = None,
        reason: str = None,
        message: str = None,
    ):
        super().__init__()
        self.__type = type
        self.__status = status
        self.__last_probe_time = last_probe_time
        self.__last_transition_time = last_transition_time
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
        last_probe_time = self.last_probe_time()
        check_type("last_probe_time", last_probe_time, Optional["base.Time"])
        v["lastProbeTime"] = last_probe_time
        last_transition_time = self.last_transition_time()
        check_type("last_transition_time", last_transition_time, Optional["base.Time"])
        v["lastTransitionTime"] = last_transition_time
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

    def last_probe_time(self) -> Optional["base.Time"]:
        """
        Last time the condition was checked.
        """
        return self.__last_probe_time

    def last_transition_time(self) -> Optional["base.Time"]:
        """
        Last time the condition transit from one status to another.
        """
        return self.__last_transition_time

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
    def __init__(self, organization: str = None, common_name: str = None):
        super().__init__()
        self.__organization = organization
        self.__common_name = common_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        organization = self.organization()
        check_type("organization", organization, Optional[str])
        if organization:  # omit empty
            v["organization"] = organization
        common_name = self.common_name()
        check_type("common_name", common_name, Optional[str])
        if common_name:  # omit empty
            v["commonName"] = common_name
        return v

    def organization(self) -> Optional[str]:
        """
        Organization name.
        """
        return self.__organization

    def common_name(self) -> Optional[str]:
        """
        Common name (e.g. openshift-signing-service).
        """
        return self.__common_name


class SignatureIssuer(types.Object):
    """
    SignatureIssuer holds information about an issuer of signing certificate or key.
    """

    @context.scoped
    @typechecked
    def __init__(self, signature_generic_entity: "SignatureGenericEntity" = None):
        super().__init__()
        self.__signature_generic_entity = (
            signature_generic_entity
            if signature_generic_entity is not None
            else SignatureGenericEntity()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        signature_generic_entity = self.signature_generic_entity()
        check_type(
            "signature_generic_entity",
            signature_generic_entity,
            "SignatureGenericEntity",
        )
        v.update(signature_generic_entity._root())  # inline
        return v

    def signature_generic_entity(self) -> "SignatureGenericEntity":
        return self.__signature_generic_entity


class SignatureSubject(types.Object):
    """
    SignatureSubject holds information about a person or entity who created the signature.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        signature_generic_entity: "SignatureGenericEntity" = None,
        public_key_id: str = "",
    ):
        super().__init__()
        self.__signature_generic_entity = (
            signature_generic_entity
            if signature_generic_entity is not None
            else SignatureGenericEntity()
        )
        self.__public_key_id = public_key_id

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        signature_generic_entity = self.signature_generic_entity()
        check_type(
            "signature_generic_entity",
            signature_generic_entity,
            "SignatureGenericEntity",
        )
        v.update(signature_generic_entity._root())  # inline
        public_key_id = self.public_key_id()
        check_type("public_key_id", public_key_id, str)
        v["publicKeyID"] = public_key_id
        return v

    def signature_generic_entity(self) -> "SignatureGenericEntity":
        return self.__signature_generic_entity

    def public_key_id(self) -> str:
        """
        If present, it is a human readable key id of public key belonging to the subject used to verify image
        signature. It should contain at least 64 lowest bits of public key's fingerprint (e.g.
        0x685ebe62bf278440).
        """
        return self.__public_key_id


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
        image_identity: str = None,
        signed_claims: Dict[str, str] = None,
        created: "base.Time" = None,
        issued_by: "SignatureIssuer" = None,
        issued_to: "SignatureSubject" = None,
    ):
        super().__init__(
            api_version="image.openshift.io/v1",
            kind="ImageSignature",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__type = type
        self.__content = content if content is not None else b""
        self.__conditions = conditions if conditions is not None else []
        self.__image_identity = image_identity
        self.__signed_claims = signed_claims if signed_claims is not None else {}
        self.__created = created
        self.__issued_by = issued_by
        self.__issued_to = issued_to

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
        image_identity = self.image_identity()
        check_type("image_identity", image_identity, Optional[str])
        if image_identity:  # omit empty
            v["imageIdentity"] = image_identity
        signed_claims = self.signed_claims()
        check_type("signed_claims", signed_claims, Optional[Dict[str, str]])
        if signed_claims:  # omit empty
            v["signedClaims"] = signed_claims
        created = self.created()
        check_type("created", created, Optional["base.Time"])
        if created is not None:  # omit empty
            v["created"] = created
        issued_by = self.issued_by()
        check_type("issued_by", issued_by, Optional["SignatureIssuer"])
        if issued_by is not None:  # omit empty
            v["issuedBy"] = issued_by
        issued_to = self.issued_to()
        check_type("issued_to", issued_to, Optional["SignatureSubject"])
        if issued_to is not None:  # omit empty
            v["issuedTo"] = issued_to
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

    def image_identity(self) -> Optional[str]:
        """
        A human readable string representing image's identity. It could be a product name and version, or an
        image pull spec (e.g. "registry.access.redhat.com/rhel7/rhel:7.2").
        """
        return self.__image_identity

    def signed_claims(self) -> Optional[Dict[str, str]]:
        """
        Contains claims from the signature.
        """
        return self.__signed_claims

    def created(self) -> Optional["base.Time"]:
        """
        If specified, it is the time of signature's creation.
        """
        return self.__created

    def issued_by(self) -> Optional["SignatureIssuer"]:
        """
        If specified, it holds information about an issuer of signing certificate or key (a person or entity
        who signed the signing certificate or key).
        """
        return self.__issued_by

    def issued_to(self) -> Optional["SignatureSubject"]:
        """
        If specified, it holds information about a subject of signing certificate or key (a person or entity
        who signed the image).
        """
        return self.__issued_to


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
        docker_image_reference: str = None,
        docker_image_metadata: "runtime.RawExtension" = None,
        docker_image_metadata_version: str = None,
        docker_image_manifest: str = None,
        docker_image_layers: List["ImageLayer"] = None,
        signatures: List["ImageSignature"] = None,
        docker_image_signatures: List[bytes] = None,
        docker_image_manifest_media_type: str = None,
        docker_image_config: str = None,
    ):
        super().__init__(
            api_version="image.openshift.io/v1",
            kind="Image",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__docker_image_reference = docker_image_reference
        self.__docker_image_metadata = docker_image_metadata
        self.__docker_image_metadata_version = docker_image_metadata_version
        self.__docker_image_manifest = docker_image_manifest
        self.__docker_image_layers = (
            docker_image_layers if docker_image_layers is not None else []
        )
        self.__signatures = signatures if signatures is not None else []
        self.__docker_image_signatures = (
            docker_image_signatures if docker_image_signatures is not None else []
        )
        self.__docker_image_manifest_media_type = docker_image_manifest_media_type
        self.__docker_image_config = docker_image_config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        docker_image_reference = self.docker_image_reference()
        check_type("docker_image_reference", docker_image_reference, Optional[str])
        if docker_image_reference:  # omit empty
            v["dockerImageReference"] = docker_image_reference
        docker_image_metadata = self.docker_image_metadata()
        check_type(
            "docker_image_metadata",
            docker_image_metadata,
            Optional["runtime.RawExtension"],
        )
        v["dockerImageMetadata"] = docker_image_metadata
        docker_image_metadata_version = self.docker_image_metadata_version()
        check_type(
            "docker_image_metadata_version",
            docker_image_metadata_version,
            Optional[str],
        )
        if docker_image_metadata_version:  # omit empty
            v["dockerImageMetadataVersion"] = docker_image_metadata_version
        docker_image_manifest = self.docker_image_manifest()
        check_type("docker_image_manifest", docker_image_manifest, Optional[str])
        if docker_image_manifest:  # omit empty
            v["dockerImageManifest"] = docker_image_manifest
        docker_image_layers = self.docker_image_layers()
        check_type("docker_image_layers", docker_image_layers, List["ImageLayer"])
        v["dockerImageLayers"] = docker_image_layers
        signatures = self.signatures()
        check_type("signatures", signatures, Optional[List["ImageSignature"]])
        if signatures:  # omit empty
            v["signatures"] = signatures
        docker_image_signatures = self.docker_image_signatures()
        check_type(
            "docker_image_signatures", docker_image_signatures, Optional[List[bytes]]
        )
        if docker_image_signatures:  # omit empty
            v["dockerImageSignatures"] = docker_image_signatures
        docker_image_manifest_media_type = self.docker_image_manifest_media_type()
        check_type(
            "docker_image_manifest_media_type",
            docker_image_manifest_media_type,
            Optional[str],
        )
        if docker_image_manifest_media_type:  # omit empty
            v["dockerImageManifestMediaType"] = docker_image_manifest_media_type
        docker_image_config = self.docker_image_config()
        check_type("docker_image_config", docker_image_config, Optional[str])
        if docker_image_config:  # omit empty
            v["dockerImageConfig"] = docker_image_config
        return v

    def docker_image_reference(self) -> Optional[str]:
        """
        DockerImageReference is the string that can be used to pull this image.
        """
        return self.__docker_image_reference

    def docker_image_metadata(self) -> Optional["runtime.RawExtension"]:
        """
        DockerImageMetadata contains metadata about this image
        """
        return self.__docker_image_metadata

    def docker_image_metadata_version(self) -> Optional[str]:
        """
        DockerImageMetadataVersion conveys the version of the object, which if empty defaults to "1.0"
        """
        return self.__docker_image_metadata_version

    def docker_image_manifest(self) -> Optional[str]:
        """
        DockerImageManifest is the raw JSON of the manifest
        """
        return self.__docker_image_manifest

    def docker_image_layers(self) -> List["ImageLayer"]:
        """
        DockerImageLayers represents the layers in the image. May not be set if the image does not define that data.
        """
        return self.__docker_image_layers

    def signatures(self) -> Optional[List["ImageSignature"]]:
        """
        Signatures holds all signatures of the image.
        """
        return self.__signatures

    def docker_image_signatures(self) -> Optional[List[bytes]]:
        """
        DockerImageSignatures provides the signatures as opaque blobs. This is a part of manifest schema v1.
        """
        return self.__docker_image_signatures

    def docker_image_manifest_media_type(self) -> Optional[str]:
        """
        DockerImageManifestMediaType specifies the mediaType of manifest. This is a part of manifest schema v2.
        """
        return self.__docker_image_manifest_media_type

    def docker_image_config(self) -> Optional[str]:
        """
        DockerImageConfig is a JSON blob that the runtime uses to set up the container. This is a part of manifest schema v2.
        """
        return self.__docker_image_config


class ImageBlobReferences(types.Object):
    """
    ImageBlobReferences describes the blob references within an image.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, image_missing: bool = False, layers: List[str] = None, config: str = None
    ):
        super().__init__()
        self.__image_missing = image_missing
        self.__layers = layers if layers is not None else []
        self.__config = config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        image_missing = self.image_missing()
        check_type("image_missing", image_missing, bool)
        v["imageMissing"] = image_missing
        layers = self.layers()
        check_type("layers", layers, List[str])
        v["layers"] = layers
        config = self.config()
        check_type("config", config, Optional[str])
        v["config"] = config
        return v

    def image_missing(self) -> bool:
        """
        imageMissing is true if the image is referenced by the image stream but the image
        object has been deleted from the API by an administrator. When this field is set,
        layers and config fields may be empty and callers that depend on the image metadata
        should consider the image to be unavailable for download or viewing.
        """
        return self.__image_missing

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
        import_policy: "TagImportPolicy" = None,
        reference_policy: "TagReferencePolicy" = None,
        include_manifest: bool = None,
    ):
        super().__init__()
        self.__from_ = from_ if from_ is not None else k8sv1.ObjectReference()
        self.__to = to
        self.__import_policy = (
            import_policy if import_policy is not None else TagImportPolicy()
        )
        self.__reference_policy = (
            reference_policy if reference_policy is not None else TagReferencePolicy()
        )
        self.__include_manifest = include_manifest

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
        import_policy = self.import_policy()
        check_type("import_policy", import_policy, Optional["TagImportPolicy"])
        v["importPolicy"] = import_policy
        reference_policy = self.reference_policy()
        check_type("reference_policy", reference_policy, Optional["TagReferencePolicy"])
        v["referencePolicy"] = reference_policy
        include_manifest = self.include_manifest()
        check_type("include_manifest", include_manifest, Optional[bool])
        if include_manifest:  # omit empty
            v["includeManifest"] = include_manifest
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

    def import_policy(self) -> Optional["TagImportPolicy"]:
        """
        ImportPolicy is the policy controlling how the image is imported
        """
        return self.__import_policy

    def reference_policy(self) -> Optional["TagReferencePolicy"]:
        """
        ReferencePolicy defines how other components should consume the image
        """
        return self.__reference_policy

    def include_manifest(self) -> Optional[bool]:
        """
        IncludeManifest determines if the manifest for each image is returned in the response
        """
        return self.__include_manifest


class ImageLayerData(types.Object):
    """
    ImageLayerData contains metadata about an image layer.
    """

    @context.scoped
    @typechecked
    def __init__(self, size: int = None, media_type: str = ""):
        super().__init__()
        self.__size = size
        self.__media_type = media_type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        size = self.size()
        check_type("size", size, Optional[int])
        v["size"] = size
        media_type = self.media_type()
        check_type("media_type", media_type, str)
        v["mediaType"] = media_type
        return v

    def size(self) -> Optional[int]:
        """
        Size of the layer in bytes as defined by the underlying store. This field is
        optional if the necessary information about size is not available.
        """
        return self.__size

    def media_type(self) -> str:
        """
        MediaType of the referenced object.
        """
        return self.__media_type


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
        import_policy: "TagImportPolicy" = None,
        reference_policy: "TagReferencePolicy" = None,
    ):
        super().__init__()
        self.__name = name
        self.__annotations = annotations if annotations is not None else {}
        self.__from_ = from_
        self.__reference = reference
        self.__generation = generation
        self.__import_policy = (
            import_policy if import_policy is not None else TagImportPolicy()
        )
        self.__reference_policy = (
            reference_policy if reference_policy is not None else TagReferencePolicy()
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
        import_policy = self.import_policy()
        check_type("import_policy", import_policy, Optional["TagImportPolicy"])
        v["importPolicy"] = import_policy
        reference_policy = self.reference_policy()
        check_type("reference_policy", reference_policy, Optional["TagReferencePolicy"])
        v["referencePolicy"] = reference_policy
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

    def import_policy(self) -> Optional["TagImportPolicy"]:
        """
        ImportPolicy is information that controls how images may be imported by the server.
        """
        return self.__import_policy

    def reference_policy(self) -> Optional["TagReferencePolicy"]:
        """
        ReferencePolicy defines how other components should consume the image.
        """
        return self.__reference_policy


class ImageStreamSpec(types.Object):
    """
    ImageStreamSpec represents options for ImageStreams.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        lookup_policy: "ImageLookupPolicy" = None,
        tags: List["TagReference"] = None,
    ):
        super().__init__()
        self.__lookup_policy = (
            lookup_policy if lookup_policy is not None else ImageLookupPolicy()
        )
        self.__tags = tags if tags is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        lookup_policy = self.lookup_policy()
        check_type("lookup_policy", lookup_policy, Optional["ImageLookupPolicy"])
        v["lookupPolicy"] = lookup_policy
        tags = self.tags()
        check_type("tags", tags, Optional[List["TagReference"]])
        if tags:  # omit empty
            v["tags"] = tags
        return v

    def lookup_policy(self) -> Optional["ImageLookupPolicy"]:
        """
        lookupPolicy controls how other resources reference images within this namespace.
        """
        return self.__lookup_policy

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
            api_version="image.openshift.io/v1",
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
            api_version="image.openshift.io/v1",
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
        import_policy: "TagImportPolicy" = None,
        reference_policy: "TagReferencePolicy" = None,
        include_manifest: bool = None,
    ):
        super().__init__()
        self.__from_ = from_ if from_ is not None else k8sv1.ObjectReference()
        self.__import_policy = (
            import_policy if import_policy is not None else TagImportPolicy()
        )
        self.__reference_policy = (
            reference_policy if reference_policy is not None else TagReferencePolicy()
        )
        self.__include_manifest = include_manifest

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        from_ = self.from_()
        check_type("from_", from_, "k8sv1.ObjectReference")
        v["from"] = from_
        import_policy = self.import_policy()
        check_type("import_policy", import_policy, Optional["TagImportPolicy"])
        v["importPolicy"] = import_policy
        reference_policy = self.reference_policy()
        check_type("reference_policy", reference_policy, Optional["TagReferencePolicy"])
        v["referencePolicy"] = reference_policy
        include_manifest = self.include_manifest()
        check_type("include_manifest", include_manifest, Optional[bool])
        if include_manifest:  # omit empty
            v["includeManifest"] = include_manifest
        return v

    def from_(self) -> "k8sv1.ObjectReference":
        """
        From is the source for the image repository to import; only kind DockerImage and a name of a container image repository is allowed
        """
        return self.__from_

    def import_policy(self) -> Optional["TagImportPolicy"]:
        """
        ImportPolicy is the policy controlling how the image is imported
        """
        return self.__import_policy

    def reference_policy(self) -> Optional["TagReferencePolicy"]:
        """
        ReferencePolicy defines how other components should consume the image
        """
        return self.__reference_policy

    def include_manifest(self) -> Optional[bool]:
        """
        IncludeManifest determines if the manifest for each image is returned in the response
        """
        return self.__include_manifest


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
            api_version="image.openshift.io/v1",
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
            api_version="image.openshift.io/v1",
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
            api_version="image.openshift.io/v1",
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
        last_transition_time: "base.Time" = None,
        reason: str = None,
        message: str = None,
        generation: int = 0,
    ):
        super().__init__()
        self.__type = type
        self.__status = status
        self.__last_transition_time = last_transition_time
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
        last_transition_time = self.last_transition_time()
        check_type("last_transition_time", last_transition_time, Optional["base.Time"])
        v["lastTransitionTime"] = last_transition_time
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

    def last_transition_time(self) -> Optional["base.Time"]:
        """
        LastTransitionTIme is the time the condition transitioned from one status to another.
        """
        return self.__last_transition_time

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
        lookup_policy: "ImageLookupPolicy" = None,
        conditions: List["TagEventCondition"] = None,
        image: "Image" = None,
    ):
        super().__init__(
            api_version="image.openshift.io/v1",
            kind="ImageStreamTag",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__tag = tag
        self.__generation = generation
        self.__lookup_policy = (
            lookup_policy if lookup_policy is not None else ImageLookupPolicy()
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
        lookup_policy = self.lookup_policy()
        check_type("lookup_policy", lookup_policy, "ImageLookupPolicy")
        v["lookupPolicy"] = lookup_policy
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

    def lookup_policy(self) -> "ImageLookupPolicy":
        """
        lookupPolicy indicates whether this tag will handle image references in this
        namespace.
        """
        return self.__lookup_policy

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


class ImageTag(base.TypedObject, base.NamespacedMetadataObject):
    """
    ImageTag represents a single tag within an image stream and includes the spec,
    the status history, and the currently referenced image (if any) of the provided
    tag. This type replaces the ImageStreamTag by providing a full view of the tag.
    ImageTags are returned for every spec or status tag present on the image stream.
    If no tag exists in either form a not found error will be returned by the API.
    A create operation will succeed if no spec tag has already been defined and the
    spec field is set. Delete will remove both spec and status elements from the
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
        spec: "TagReference" = None,
        image: "Image" = None,
    ):
        super().__init__(
            api_version="image.openshift.io/v1",
            kind="ImageTag",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec
        self.__image = image

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["TagReference"])
        v["spec"] = spec
        image = self.image()
        check_type("image", image, Optional["Image"])
        v["image"] = image
        return v

    def spec(self) -> Optional["TagReference"]:
        """
        spec is the spec tag associated with this image stream tag, and it may be null
        if only pushes have occurred to this image stream.
        """
        return self.__spec

    def image(self) -> Optional["Image"]:
        """
        image is the details of the most recent image stream status tag, and it may be
        null if import has not completed or an administrator has deleted the image
        object. To verify this is the most recent image, you must verify the generation
        of the most recent status.items entry matches the spec tag (if a spec tag is
        set). This field will not be set when listing image tags.
        """
        return self.__image
