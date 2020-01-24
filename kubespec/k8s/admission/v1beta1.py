# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from kubespec.k8s.authentication import v1 as authenticationv1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


# Operation is the type of resource operation being checked for admission control
Operation = base.Enum(
    "Operation",
    {
        # Operation constants
        "Connect": "CONNECT",
        # Operation constants
        "Create": "CREATE",
        # Operation constants
        "Delete": "DELETE",
        # Operation constants
        "Update": "UPDATE",
    },
)


# PatchType is the type of patch being used to represent the mutated object
PatchType = base.Enum(
    "PatchType",
    {
        # PatchType constants.
        "JSONPatch": "JSONPatch"
    },
)


class AdmissionRequest(types.Object):
    """
    AdmissionRequest describes the admission.Attributes for the admission request.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        uid: str = "",
        kind: "metav1.GroupVersionKind" = None,
        resource: "metav1.GroupVersionResource" = None,
        sub_resource: str = None,
        request_kind: "metav1.GroupVersionKind" = None,
        request_resource: "metav1.GroupVersionResource" = None,
        request_sub_resource: str = None,
        name: str = None,
        namespace: str = None,
        operation: Operation = None,
        user_info: "authenticationv1.UserInfo" = None,
        object: "runtime.RawExtension" = None,
        old_object: "runtime.RawExtension" = None,
        dry_run: bool = None,
        options: "runtime.RawExtension" = None,
    ):
        super().__init__()
        self.__uid = uid
        self.__kind = kind if kind is not None else metav1.GroupVersionKind()
        self.__resource = (
            resource if resource is not None else metav1.GroupVersionResource()
        )
        self.__sub_resource = sub_resource
        self.__request_kind = request_kind
        self.__request_resource = request_resource
        self.__request_sub_resource = request_sub_resource
        self.__name = name
        self.__namespace = namespace
        self.__operation = operation
        self.__user_info = (
            user_info if user_info is not None else authenticationv1.UserInfo()
        )
        self.__object = object
        self.__old_object = old_object
        self.__dry_run = dry_run
        self.__options = options

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
        sub_resource = self.sub_resource()
        check_type("sub_resource", sub_resource, Optional[str])
        if sub_resource:  # omit empty
            v["subResource"] = sub_resource
        request_kind = self.request_kind()
        check_type("request_kind", request_kind, Optional["metav1.GroupVersionKind"])
        if request_kind is not None:  # omit empty
            v["requestKind"] = request_kind
        request_resource = self.request_resource()
        check_type(
            "request_resource",
            request_resource,
            Optional["metav1.GroupVersionResource"],
        )
        if request_resource is not None:  # omit empty
            v["requestResource"] = request_resource
        request_sub_resource = self.request_sub_resource()
        check_type("request_sub_resource", request_sub_resource, Optional[str])
        if request_sub_resource:  # omit empty
            v["requestSubResource"] = request_sub_resource
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
        user_info = self.user_info()
        check_type("user_info", user_info, "authenticationv1.UserInfo")
        v["userInfo"] = user_info
        object = self.object()
        check_type("object", object, Optional["runtime.RawExtension"])
        v["object"] = object
        old_object = self.old_object()
        check_type("old_object", old_object, Optional["runtime.RawExtension"])
        v["oldObject"] = old_object
        dry_run = self.dry_run()
        check_type("dry_run", dry_run, Optional[bool])
        if dry_run is not None:  # omit empty
            v["dryRun"] = dry_run
        options = self.options()
        check_type("options", options, Optional["runtime.RawExtension"])
        v["options"] = options
        return v

    def uid(self) -> str:
        """
        UID is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
        otherwise identical (parallel requests, requests when earlier requests did not modify etc)
        The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
        It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
        """
        return self.__uid

    def kind(self) -> "metav1.GroupVersionKind":
        """
        Kind is the fully-qualified type of object being submitted (for example, v1.Pod or autoscaling.v1.Scale)
        """
        return self.__kind

    def resource(self) -> "metav1.GroupVersionResource":
        """
        Resource is the fully-qualified resource being requested (for example, v1.pods)
        """
        return self.__resource

    def sub_resource(self) -> Optional[str]:
        """
        SubResource is the subresource being requested, if any (for example, "status" or "scale")
        """
        return self.__sub_resource

    def request_kind(self) -> Optional["metav1.GroupVersionKind"]:
        """
        RequestKind is the fully-qualified type of the original API request (for example, v1.Pod or autoscaling.v1.Scale).
        If this is specified and differs from the value in "kind", an equivalent match and conversion was performed.
        
        For example, if deployments can be modified via apps/v1 and apps/v1beta1, and a webhook registered a rule of
        `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]` and `matchPolicy: Equivalent`,
        an API request to apps/v1beta1 deployments would be converted and sent to the webhook
        with `kind: {group:"apps", version:"v1", kind:"Deployment"}` (matching the rule the webhook registered for),
        and `requestKind: {group:"apps", version:"v1beta1", kind:"Deployment"}` (indicating the kind of the original API request).
        
        See documentation for the "matchPolicy" field in the webhook configuration type for more details.
        """
        return self.__request_kind

    def request_resource(self) -> Optional["metav1.GroupVersionResource"]:
        """
        RequestResource is the fully-qualified resource of the original API request (for example, v1.pods).
        If this is specified and differs from the value in "resource", an equivalent match and conversion was performed.
        
        For example, if deployments can be modified via apps/v1 and apps/v1beta1, and a webhook registered a rule of
        `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]` and `matchPolicy: Equivalent`,
        an API request to apps/v1beta1 deployments would be converted and sent to the webhook
        with `resource: {group:"apps", version:"v1", resource:"deployments"}` (matching the resource the webhook registered for),
        and `requestResource: {group:"apps", version:"v1beta1", resource:"deployments"}` (indicating the resource of the original API request).
        
        See documentation for the "matchPolicy" field in the webhook configuration type.
        """
        return self.__request_resource

    def request_sub_resource(self) -> Optional[str]:
        """
        RequestSubResource is the name of the subresource of the original API request, if any (for example, "status" or "scale")
        If this is specified and differs from the value in "subResource", an equivalent match and conversion was performed.
        See documentation for the "matchPolicy" field in the webhook configuration type.
        """
        return self.__request_sub_resource

    def name(self) -> Optional[str]:
        """
        Name is the name of the object as presented in the request.  On a CREATE operation, the client may omit name and
        rely on the server to generate the name.  If that is the case, this field will contain an empty string.
        """
        return self.__name

    def namespace(self) -> Optional[str]:
        """
        Namespace is the namespace associated with the request (if any).
        """
        return self.__namespace

    def operation(self) -> Operation:
        """
        Operation is the operation being performed. This may be different than the operation
        requested. e.g. a patch can result in either a CREATE or UPDATE Operation.
        """
        return self.__operation

    def user_info(self) -> "authenticationv1.UserInfo":
        """
        UserInfo is information about the requesting user
        """
        return self.__user_info

    def object(self) -> Optional["runtime.RawExtension"]:
        """
        Object is the object from the incoming request.
        """
        return self.__object

    def old_object(self) -> Optional["runtime.RawExtension"]:
        """
        OldObject is the existing object. Only populated for DELETE and UPDATE requests.
        """
        return self.__old_object

    def dry_run(self) -> Optional[bool]:
        """
        DryRun indicates that modifications will definitely not be persisted for this request.
        Defaults to false.
        """
        return self.__dry_run

    def options(self) -> Optional["runtime.RawExtension"]:
        """
        Options is the operation option structure of the operation being performed.
        e.g. `meta.k8s.io/v1.DeleteOptions` or `meta.k8s.io/v1.CreateOptions`. This may be
        different than the options the caller provided. e.g. for a patch request the performed
        Operation might be a CREATE, in which case the Options will a
        `meta.k8s.io/v1.CreateOptions` even though the caller provided `meta.k8s.io/v1.PatchOptions`.
        """
        return self.__options


class AdmissionResponse(types.Object):
    """
    AdmissionResponse describes an admission response.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        uid: str = "",
        allowed: bool = False,
        status: "metav1.Status" = None,
        patch: bytes = None,
        patch_type: PatchType = None,
        audit_annotations: Dict[str, str] = None,
    ):
        super().__init__()
        self.__uid = uid
        self.__allowed = allowed
        self.__status = status
        self.__patch = patch if patch is not None else b""
        self.__patch_type = patch_type
        self.__audit_annotations = (
            audit_annotations if audit_annotations is not None else {}
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
        patch_type = self.patch_type()
        check_type("patch_type", patch_type, Optional[PatchType])
        if patch_type is not None:  # omit empty
            v["patchType"] = patch_type
        audit_annotations = self.audit_annotations()
        check_type("audit_annotations", audit_annotations, Optional[Dict[str, str]])
        if audit_annotations:  # omit empty
            v["auditAnnotations"] = audit_annotations
        return v

    def uid(self) -> str:
        """
        UID is an identifier for the individual request/response.
        This should be copied over from the corresponding AdmissionRequest.
        """
        return self.__uid

    def allowed(self) -> bool:
        """
        Allowed indicates whether or not the admission request was permitted.
        """
        return self.__allowed

    def status(self) -> Optional["metav1.Status"]:
        """
        Result contains extra details into why an admission request was denied.
        This field IS NOT consulted in any way if "Allowed" is "true".
        """
        return self.__status

    def patch(self) -> Optional[bytes]:
        """
        The patch body. Currently we only support "JSONPatch" which implements RFC 6902.
        """
        return self.__patch

    def patch_type(self) -> Optional[PatchType]:
        """
        The type of Patch. Currently we only allow "JSONPatch".
        """
        return self.__patch_type

    def audit_annotations(self) -> Optional[Dict[str, str]]:
        """
        AuditAnnotations is an unstructured key value map set by remote admission controller (e.g. error=image-blacklisted).
        MutatingAdmissionWebhook and ValidatingAdmissionWebhook admission controller will prefix the keys with
        admission webhook name (e.g. imagepolicy.example.com/error=image-blacklisted). AuditAnnotations will be provided by
        the admission webhook to add additional context to the audit log for this request.
        """
        return self.__audit_annotations


class AdmissionReview(base.TypedObject):
    """
    AdmissionReview describes an admission review request/response.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, request: "AdmissionRequest" = None, response: "AdmissionResponse" = None
    ):
        super().__init__(api_version="admission.k8s.io/v1beta1", kind="AdmissionReview")
        self.__request = request
        self.__response = response

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        request = self.request()
        check_type("request", request, Optional["AdmissionRequest"])
        if request is not None:  # omit empty
            v["request"] = request
        response = self.response()
        check_type("response", response, Optional["AdmissionResponse"])
        if response is not None:  # omit empty
            v["response"] = response
        return v

    def request(self) -> Optional["AdmissionRequest"]:
        """
        Request describes the attributes for the admission request.
        """
        return self.__request

    def response(self) -> Optional["AdmissionResponse"]:
        """
        Response describes the attributes for the admission response.
        """
        return self.__response
