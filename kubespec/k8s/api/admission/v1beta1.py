# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec.k8s.api.authentication import v1 as authenticationv1
from kubespec.k8s.apimachinery import runtime
from kubespec.k8s.apimachinery.meta import v1 as metav1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# Operation is the type of resource operation being checked for admission control
Operation = base.Enum(
    "Operation",
    {"Connect": "CONNECT", "Create": "CREATE", "Delete": "DELETE", "Update": "UPDATE"},
)


# PatchType is the type of patch being used to represent the mutated object
PatchType = base.Enum(
    "PatchType",
    {
        # PatchType constants.
        "JSONPatch": "JSONPatch"
    },
)


# AdmissionRequest describes the admission.Attributes for the admission request.
class AdmissionRequest(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        uid: str = "",
        kind: "metav1.GroupVersionKind" = None,
        resource: "metav1.GroupVersionResource" = None,
        subResource: str = None,
        requestKind: "metav1.GroupVersionKind" = None,
        requestResource: "metav1.GroupVersionResource" = None,
        requestSubResource: str = None,
        name: str = None,
        namespace: str = None,
        operation: Operation = None,
        userInfo: "authenticationv1.UserInfo" = None,
        object: "runtime.RawExtension" = None,
        oldObject: "runtime.RawExtension" = None,
        dryRun: bool = None,
        options: "runtime.RawExtension" = None,
    ):
        super().__init__()
        self.__uid = uid
        self.__kind = kind if kind is not None else metav1.GroupVersionKind()
        self.__resource = (
            resource if resource is not None else metav1.GroupVersionResource()
        )
        self.__subResource = subResource
        self.__requestKind = requestKind
        self.__requestResource = requestResource
        self.__requestSubResource = requestSubResource
        self.__name = name
        self.__namespace = namespace
        self.__operation = operation
        self.__userInfo = (
            userInfo if userInfo is not None else authenticationv1.UserInfo()
        )
        self.__object = object if object is not None else runtime.RawExtension()
        self.__oldObject = (
            oldObject if oldObject is not None else runtime.RawExtension()
        )
        self.__dryRun = dryRun
        self.__options = options if options is not None else runtime.RawExtension()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uid = self.uid()
        check_type("uid", uid, str)
        v["uid"] = uid
        kind = self.kind()
        check_type("kind", kind, "metav1.GroupVersionKind")
        v["kind"] = kind
        resource = self.resource()
        check_type("resource", resource, "metav1.GroupVersionResource")
        v["resource"] = resource
        subResource = self.subResource()
        check_type("subResource", subResource, Optional[str])
        if subResource:  # omit empty
            v["subResource"] = subResource
        requestKind = self.requestKind()
        check_type("requestKind", requestKind, Optional["metav1.GroupVersionKind"])
        if requestKind is not None:  # omit empty
            v["requestKind"] = requestKind
        requestResource = self.requestResource()
        check_type(
            "requestResource", requestResource, Optional["metav1.GroupVersionResource"]
        )
        if requestResource is not None:  # omit empty
            v["requestResource"] = requestResource
        requestSubResource = self.requestSubResource()
        check_type("requestSubResource", requestSubResource, Optional[str])
        if requestSubResource:  # omit empty
            v["requestSubResource"] = requestSubResource
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        operation = self.operation()
        check_type("operation", operation, Operation)
        v["operation"] = operation
        userInfo = self.userInfo()
        check_type("userInfo", userInfo, "authenticationv1.UserInfo")
        v["userInfo"] = userInfo
        object = self.object()
        check_type("object", object, Optional["runtime.RawExtension"])
        v["object"] = object
        oldObject = self.oldObject()
        check_type("oldObject", oldObject, Optional["runtime.RawExtension"])
        v["oldObject"] = oldObject
        dryRun = self.dryRun()
        check_type("dryRun", dryRun, Optional[bool])
        if dryRun is not None:  # omit empty
            v["dryRun"] = dryRun
        options = self.options()
        check_type("options", options, Optional["runtime.RawExtension"])
        v["options"] = options
        return v

    # UID is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
    # otherwise identical (parallel requests, requests when earlier requests did not modify etc)
    # The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
    # It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
    def uid(self) -> str:
        return self.__uid

    # Kind is the fully-qualified type of object being submitted (for example, v1.Pod or autoscaling.v1.Scale)
    def kind(self) -> "metav1.GroupVersionKind":
        return self.__kind

    # Resource is the fully-qualified resource being requested (for example, v1.pods)
    def resource(self) -> "metav1.GroupVersionResource":
        return self.__resource

    # SubResource is the subresource being requested, if any (for example, "status" or "scale")
    def subResource(self) -> Optional[str]:
        return self.__subResource

    # RequestKind is the fully-qualified type of the original API request (for example, v1.Pod or autoscaling.v1.Scale).
    # If this is specified and differs from the value in "kind", an equivalent match and conversion was performed.
    #
    # For example, if deployments can be modified via apps/v1 and apps/v1beta1, and a webhook registered a rule of
    # `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]` and `matchPolicy: Equivalent`,
    # an API request to apps/v1beta1 deployments would be converted and sent to the webhook
    # with `kind: {group:"apps", version:"v1", kind:"Deployment"}` (matching the rule the webhook registered for),
    # and `requestKind: {group:"apps", version:"v1beta1", kind:"Deployment"}` (indicating the kind of the original API request).
    #
    # See documentation for the "matchPolicy" field in the webhook configuration type for more details.
    def requestKind(self) -> Optional["metav1.GroupVersionKind"]:
        return self.__requestKind

    # RequestResource is the fully-qualified resource of the original API request (for example, v1.pods).
    # If this is specified and differs from the value in "resource", an equivalent match and conversion was performed.
    #
    # For example, if deployments can be modified via apps/v1 and apps/v1beta1, and a webhook registered a rule of
    # `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]` and `matchPolicy: Equivalent`,
    # an API request to apps/v1beta1 deployments would be converted and sent to the webhook
    # with `resource: {group:"apps", version:"v1", resource:"deployments"}` (matching the resource the webhook registered for),
    # and `requestResource: {group:"apps", version:"v1beta1", resource:"deployments"}` (indicating the resource of the original API request).
    #
    # See documentation for the "matchPolicy" field in the webhook configuration type.
    def requestResource(self) -> Optional["metav1.GroupVersionResource"]:
        return self.__requestResource

    # RequestSubResource is the name of the subresource of the original API request, if any (for example, "status" or "scale")
    # If this is specified and differs from the value in "subResource", an equivalent match and conversion was performed.
    # See documentation for the "matchPolicy" field in the webhook configuration type.
    def requestSubResource(self) -> Optional[str]:
        return self.__requestSubResource

    # Name is the name of the object as presented in the request.  On a CREATE operation, the client may omit name and
    # rely on the server to generate the name.  If that is the case, this field will contain an empty string.
    def name(self) -> Optional[str]:
        return self.__name

    # Namespace is the namespace associated with the request (if any).
    def namespace(self) -> Optional[str]:
        return self.__namespace

    # Operation is the operation being performed. This may be different than the operation
    # requested. e.g. a patch can result in either a CREATE or UPDATE Operation.
    def operation(self) -> Operation:
        return self.__operation

    # UserInfo is information about the requesting user
    def userInfo(self) -> "authenticationv1.UserInfo":
        return self.__userInfo

    # Object is the object from the incoming request.
    def object(self) -> Optional["runtime.RawExtension"]:
        return self.__object

    # OldObject is the existing object. Only populated for DELETE and UPDATE requests.
    def oldObject(self) -> Optional["runtime.RawExtension"]:
        return self.__oldObject

    # DryRun indicates that modifications will definitely not be persisted for this request.
    # Defaults to false.
    def dryRun(self) -> Optional[bool]:
        return self.__dryRun

    # Options is the operation option structure of the operation being performed.
    # e.g. `meta.k8s.io/v1.DeleteOptions` or `meta.k8s.io/v1.CreateOptions`. This may be
    # different than the options the caller provided. e.g. for a patch request the performed
    # Operation might be a CREATE, in which case the Options will a
    # `meta.k8s.io/v1.CreateOptions` even though the caller provided `meta.k8s.io/v1.PatchOptions`.
    def options(self) -> Optional["runtime.RawExtension"]:
        return self.__options


# AdmissionResponse describes an admission response.
class AdmissionResponse(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        uid: str = "",
        allowed: bool = False,
        status: "metav1.Status" = None,
        patch: bytes = None,
        patchType: PatchType = None,
        auditAnnotations: Dict[str, str] = None,
    ):
        super().__init__()
        self.__uid = uid
        self.__allowed = allowed
        self.__status = status
        self.__patch = patch if patch is not None else b""
        self.__patchType = patchType
        self.__auditAnnotations = (
            auditAnnotations if auditAnnotations is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uid = self.uid()
        check_type("uid", uid, str)
        v["uid"] = uid
        allowed = self.allowed()
        check_type("allowed", allowed, bool)
        v["allowed"] = allowed
        status = self.status()
        check_type("status", status, Optional["metav1.Status"])
        if status is not None:  # omit empty
            v["status"] = status
        patch = self.patch()
        check_type("patch", patch, Optional[bytes])
        if patch:  # omit empty
            v["patch"] = patch
        patchType = self.patchType()
        check_type("patchType", patchType, Optional[PatchType])
        if patchType is not None:  # omit empty
            v["patchType"] = patchType
        auditAnnotations = self.auditAnnotations()
        check_type("auditAnnotations", auditAnnotations, Optional[Dict[str, str]])
        if auditAnnotations:  # omit empty
            v["auditAnnotations"] = auditAnnotations
        return v

    # UID is an identifier for the individual request/response.
    # This should be copied over from the corresponding AdmissionRequest.
    def uid(self) -> str:
        return self.__uid

    # Allowed indicates whether or not the admission request was permitted.
    def allowed(self) -> bool:
        return self.__allowed

    # Result contains extra details into why an admission request was denied.
    # This field IS NOT consulted in any way if "Allowed" is "true".
    def status(self) -> Optional["metav1.Status"]:
        return self.__status

    # The patch body. Currently we only support "JSONPatch" which implements RFC 6902.
    def patch(self) -> Optional[bytes]:
        return self.__patch

    # The type of Patch. Currently we only allow "JSONPatch".
    def patchType(self) -> Optional[PatchType]:
        return self.__patchType

    # AuditAnnotations is an unstructured key value map set by remote admission controller (e.g. error=image-blacklisted).
    # MutatingAdmissionWebhook and ValidatingAdmissionWebhook admission controller will prefix the keys with
    # admission webhook name (e.g. imagepolicy.example.com/error=image-blacklisted). AuditAnnotations will be provided by
    # the admission webhook to add additional context to the audit log for this request.
    def auditAnnotations(self) -> Optional[Dict[str, str]]:
        return self.__auditAnnotations


# AdmissionReview describes an admission review request/response.
class AdmissionReview(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self, request: AdmissionRequest = None, response: AdmissionResponse = None
    ):
        super().__init__(apiVersion="admission.k8s.io/v1beta1", kind="AdmissionReview")
        self.__request = request
        self.__response = response

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        request = self.request()
        check_type("request", request, Optional[AdmissionRequest])
        if request is not None:  # omit empty
            v["request"] = request
        response = self.response()
        check_type("response", response, Optional[AdmissionResponse])
        if response is not None:  # omit empty
            v["response"] = response
        return v

    # Request describes the attributes for the admission request.
    def request(self) -> Optional[AdmissionRequest]:
        return self.__request

    # Response describes the attributes for the admission response.
    def response(self) -> Optional[AdmissionResponse]:
        return self.__response
