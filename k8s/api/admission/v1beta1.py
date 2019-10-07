# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.api.authentication import v1 as authenticationv1
from k8s.apimachinery import runtime
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


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
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["uid"] = self.uid()
        v["kind"] = self.kind()
        v["resource"] = self.resource()
        subResource = self.subResource()
        if subResource:  # omit empty
            v["subResource"] = subResource
        requestKind = self.requestKind()
        if requestKind is not None:  # omit empty
            v["requestKind"] = requestKind
        requestResource = self.requestResource()
        if requestResource is not None:  # omit empty
            v["requestResource"] = requestResource
        requestSubResource = self.requestSubResource()
        if requestSubResource:  # omit empty
            v["requestSubResource"] = requestSubResource
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        namespace = self.namespace()
        if namespace:  # omit empty
            v["namespace"] = namespace
        v["operation"] = self.operation()
        v["userInfo"] = self.userInfo()
        v["object"] = self.object()
        v["oldObject"] = self.oldObject()
        dryRun = self.dryRun()
        if dryRun is not None:  # omit empty
            v["dryRun"] = dryRun
        v["options"] = self.options()
        return v

    # UID is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
    # otherwise identical (parallel requests, requests when earlier requests did not modify etc)
    # The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
    # It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
    @typechecked
    def uid(self) -> str:
        if "uid" in self._kwargs:
            return self._kwargs["uid"]
        if "uid" in self._context and check_return_type(self._context["uid"]):
            return self._context["uid"]
        return ""

    # Kind is the fully-qualified type of object being submitted (for example, v1.Pod or autoscaling.v1.Scale)
    @typechecked
    def kind(self) -> "metav1.GroupVersionKind":
        if "kind" in self._kwargs:
            return self._kwargs["kind"]
        if "kind" in self._context and check_return_type(self._context["kind"]):
            return self._context["kind"]
        with context.Scope(**self._context):
            return metav1.GroupVersionKind()

    # Resource is the fully-qualified resource being requested (for example, v1.pods)
    @typechecked
    def resource(self) -> "metav1.GroupVersionResource":
        if "resource" in self._kwargs:
            return self._kwargs["resource"]
        if "resource" in self._context and check_return_type(self._context["resource"]):
            return self._context["resource"]
        with context.Scope(**self._context):
            return metav1.GroupVersionResource()

    # SubResource is the subresource being requested, if any (for example, "status" or "scale")
    @typechecked
    def subResource(self) -> Optional[str]:
        if "subResource" in self._kwargs:
            return self._kwargs["subResource"]
        if "subResource" in self._context and check_return_type(
            self._context["subResource"]
        ):
            return self._context["subResource"]
        return None

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
    @typechecked
    def requestKind(self) -> Optional["metav1.GroupVersionKind"]:
        if "requestKind" in self._kwargs:
            return self._kwargs["requestKind"]
        if "requestKind" in self._context and check_return_type(
            self._context["requestKind"]
        ):
            return self._context["requestKind"]
        return None

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
    @typechecked
    def requestResource(self) -> Optional["metav1.GroupVersionResource"]:
        if "requestResource" in self._kwargs:
            return self._kwargs["requestResource"]
        if "requestResource" in self._context and check_return_type(
            self._context["requestResource"]
        ):
            return self._context["requestResource"]
        return None

    # RequestSubResource is the name of the subresource of the original API request, if any (for example, "status" or "scale")
    # If this is specified and differs from the value in "subResource", an equivalent match and conversion was performed.
    # See documentation for the "matchPolicy" field in the webhook configuration type.
    @typechecked
    def requestSubResource(self) -> Optional[str]:
        if "requestSubResource" in self._kwargs:
            return self._kwargs["requestSubResource"]
        if "requestSubResource" in self._context and check_return_type(
            self._context["requestSubResource"]
        ):
            return self._context["requestSubResource"]
        return None

    # Name is the name of the object as presented in the request.  On a CREATE operation, the client may omit name and
    # rely on the server to generate the name.  If that is the case, this field will contain an empty string.
    @typechecked
    def name(self) -> Optional[str]:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return None

    # Namespace is the namespace associated with the request (if any).
    @typechecked
    def namespace(self) -> Optional[str]:
        if "namespace" in self._kwargs:
            return self._kwargs["namespace"]
        if "namespace" in self._context and check_return_type(
            self._context["namespace"]
        ):
            return self._context["namespace"]
        return None

    # Operation is the operation being performed. This may be different than the operation
    # requested. e.g. a patch can result in either a CREATE or UPDATE Operation.
    @typechecked
    def operation(self) -> Operation:
        if "operation" in self._kwargs:
            return self._kwargs["operation"]
        if "operation" in self._context and check_return_type(
            self._context["operation"]
        ):
            return self._context["operation"]
        return None

    # UserInfo is information about the requesting user
    @typechecked
    def userInfo(self) -> "authenticationv1.UserInfo":
        if "userInfo" in self._kwargs:
            return self._kwargs["userInfo"]
        if "userInfo" in self._context and check_return_type(self._context["userInfo"]):
            return self._context["userInfo"]
        with context.Scope(**self._context):
            return authenticationv1.UserInfo()

    # Object is the object from the incoming request.
    @typechecked
    def object(self) -> "runtime.RawExtension":
        if "object" in self._kwargs:
            return self._kwargs["object"]
        if "object" in self._context and check_return_type(self._context["object"]):
            return self._context["object"]
        with context.Scope(**self._context):
            return runtime.RawExtension()

    # OldObject is the existing object. Only populated for DELETE and UPDATE requests.
    @typechecked
    def oldObject(self) -> "runtime.RawExtension":
        if "oldObject" in self._kwargs:
            return self._kwargs["oldObject"]
        if "oldObject" in self._context and check_return_type(
            self._context["oldObject"]
        ):
            return self._context["oldObject"]
        with context.Scope(**self._context):
            return runtime.RawExtension()

    # DryRun indicates that modifications will definitely not be persisted for this request.
    # Defaults to false.
    @typechecked
    def dryRun(self) -> Optional[bool]:
        if "dryRun" in self._kwargs:
            return self._kwargs["dryRun"]
        if "dryRun" in self._context and check_return_type(self._context["dryRun"]):
            return self._context["dryRun"]
        return None

    # Options is the operation option structure of the operation being performed.
    # e.g. `meta.k8s.io/v1.DeleteOptions` or `meta.k8s.io/v1.CreateOptions`. This may be
    # different than the options the caller provided. e.g. for a patch request the performed
    # Operation might be a CREATE, in which case the Options will a
    # `meta.k8s.io/v1.CreateOptions` even though the caller provided `meta.k8s.io/v1.PatchOptions`.
    @typechecked
    def options(self) -> "runtime.RawExtension":
        if "options" in self._kwargs:
            return self._kwargs["options"]
        if "options" in self._context and check_return_type(self._context["options"]):
            return self._context["options"]
        with context.Scope(**self._context):
            return runtime.RawExtension()


# AdmissionResponse describes an admission response.
class AdmissionResponse(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["uid"] = self.uid()
        v["allowed"] = self.allowed()
        status = self.status()
        if status is not None:  # omit empty
            v["status"] = status
        patch = self.patch()
        if patch:  # omit empty
            v["patch"] = patch
        patchType = self.patchType()
        if patchType is not None:  # omit empty
            v["patchType"] = patchType
        auditAnnotations = self.auditAnnotations()
        if auditAnnotations:  # omit empty
            v["auditAnnotations"] = auditAnnotations
        return v

    # UID is an identifier for the individual request/response.
    # This should be copied over from the corresponding AdmissionRequest.
    @typechecked
    def uid(self) -> str:
        if "uid" in self._kwargs:
            return self._kwargs["uid"]
        if "uid" in self._context and check_return_type(self._context["uid"]):
            return self._context["uid"]
        return ""

    # Allowed indicates whether or not the admission request was permitted.
    @typechecked
    def allowed(self) -> bool:
        if "allowed" in self._kwargs:
            return self._kwargs["allowed"]
        if "allowed" in self._context and check_return_type(self._context["allowed"]):
            return self._context["allowed"]
        return False

    # Result contains extra details into why an admission request was denied.
    # This field IS NOT consulted in any way if "Allowed" is "true".
    @typechecked
    def status(self) -> Optional["metav1.Status"]:
        if "status" in self._kwargs:
            return self._kwargs["status"]
        if "status" in self._context and check_return_type(self._context["status"]):
            return self._context["status"]
        return None

    # The patch body. Currently we only support "JSONPatch" which implements RFC 6902.
    @typechecked
    def patch(self) -> bytes:
        if "patch" in self._kwargs:
            return self._kwargs["patch"]
        if "patch" in self._context and check_return_type(self._context["patch"]):
            return self._context["patch"]
        return b""

    # The type of Patch. Currently we only allow "JSONPatch".
    @typechecked
    def patchType(self) -> Optional[PatchType]:
        if "patchType" in self._kwargs:
            return self._kwargs["patchType"]
        if "patchType" in self._context and check_return_type(
            self._context["patchType"]
        ):
            return self._context["patchType"]
        return None

    # AuditAnnotations is an unstructured key value map set by remote admission controller (e.g. error=image-blacklisted).
    # MutatingAdmissionWebhook and ValidatingAdmissionWebhook admission controller will prefix the keys with
    # admission webhook name (e.g. imagepolicy.example.com/error=image-blacklisted). AuditAnnotations will be provided by
    # the admission webhook to add additional context to the audit log for this request.
    @typechecked
    def auditAnnotations(self) -> Dict[str, str]:
        if "auditAnnotations" in self._kwargs:
            return self._kwargs["auditAnnotations"]
        if "auditAnnotations" in self._context and check_return_type(
            self._context["auditAnnotations"]
        ):
            return self._context["auditAnnotations"]
        return {}


# AdmissionReview describes an admission review request/response.
class AdmissionReview(base.TypedObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        request = self.request()
        if request is not None:  # omit empty
            v["request"] = request
        response = self.response()
        if response is not None:  # omit empty
            v["response"] = response
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "admission.k8s.io/v1beta1"

    @typechecked
    def kind(self) -> str:
        return "AdmissionReview"

    # Request describes the attributes for the admission request.
    @typechecked
    def request(self) -> Optional[AdmissionRequest]:
        if "request" in self._kwargs:
            return self._kwargs["request"]
        if "request" in self._context and check_return_type(self._context["request"]):
            return self._context["request"]
        return None

    # Response describes the attributes for the admission response.
    @typechecked
    def response(self) -> Optional[AdmissionResponse]:
        if "response" in self._kwargs:
            return self._kwargs["response"]
        if "response" in self._context and check_return_type(self._context["response"]):
            return self._context["response"]
        return None
