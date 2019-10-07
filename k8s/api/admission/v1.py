# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.api.authentication import v1 as authenticationv1
from k8s.apimachinery import runtime
from k8s.apimachinery.meta import v1 as metav1
from kargo import types
from typeguard import typechecked


# Operation is the type of resource operation being checked for admission control
Operation = base.Enum('Operation', {
    'Connect': 'CONNECT',
    'Create': 'CREATE',
    'Delete': 'DELETE',
    'Update': 'UPDATE',
})


# PatchType is the type of patch being used to represent the mutated object
PatchType = base.Enum('PatchType', {
    # PatchType constants.
    'JSONPatch': 'JSONPatch',
})


# AdmissionRequest describes the admission.Attributes for the admission request.
class AdmissionRequest(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['uid'] = self.uid()
        v['kind'] = self.kind()
        v['resource'] = self.resource()
        subResource = self.subResource()
        if subResource:  # omit empty
            v['subResource'] = subResource
        requestKind = self.requestKind()
        if requestKind is not None:  # omit empty
            v['requestKind'] = requestKind
        requestResource = self.requestResource()
        if requestResource is not None:  # omit empty
            v['requestResource'] = requestResource
        requestSubResource = self.requestSubResource()
        if requestSubResource:  # omit empty
            v['requestSubResource'] = requestSubResource
        name = self.name()
        if name:  # omit empty
            v['name'] = name
        namespace = self.namespace()
        if namespace:  # omit empty
            v['namespace'] = namespace
        v['operation'] = self.operation()
        v['userInfo'] = self.userInfo()
        v['object'] = self.object()
        v['oldObject'] = self.oldObject()
        dryRun = self.dryRun()
        if dryRun is not None:  # omit empty
            v['dryRun'] = dryRun
        v['options'] = self.options()
        return v
    
    # UID is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
    # otherwise identical (parallel requests, requests when earlier requests did not modify etc)
    # The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
    # It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
    @typechecked
    def uid(self) -> str:
        return self._get('uid', '')
    
    # Kind is the fully-qualified type of object being submitted (for example, v1.Pod or autoscaling.v1.Scale)
    @typechecked
    def kind(self) -> 'metav1.GroupVersionKind':
        return self._get('kind', metav1.GroupVersionKind())
    
    # Resource is the fully-qualified resource being requested (for example, v1.pods)
    @typechecked
    def resource(self) -> 'metav1.GroupVersionResource':
        return self._get('resource', metav1.GroupVersionResource())
    
    # SubResource is the subresource being requested, if any (for example, "status" or "scale")
    @typechecked
    def subResource(self) -> Optional[str]:
        return self._get('subResource')
    
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
    def requestKind(self) -> Optional['metav1.GroupVersionKind']:
        return self._get('requestKind')
    
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
    def requestResource(self) -> Optional['metav1.GroupVersionResource']:
        return self._get('requestResource')
    
    # RequestSubResource is the name of the subresource of the original API request, if any (for example, "status" or "scale")
    # If this is specified and differs from the value in "subResource", an equivalent match and conversion was performed.
    # See documentation for the "matchPolicy" field in the webhook configuration type.
    @typechecked
    def requestSubResource(self) -> Optional[str]:
        return self._get('requestSubResource')
    
    # Name is the name of the object as presented in the request.  On a CREATE operation, the client may omit name and
    # rely on the server to generate the name.  If that is the case, this field will contain an empty string.
    @typechecked
    def name(self) -> Optional[str]:
        return self._get('name')
    
    # Namespace is the namespace associated with the request (if any).
    @typechecked
    def namespace(self) -> Optional[str]:
        return self._get('namespace')
    
    # Operation is the operation being performed. This may be different than the operation
    # requested. e.g. a patch can result in either a CREATE or UPDATE Operation.
    @typechecked
    def operation(self) -> Operation:
        return self._get('operation')
    
    # UserInfo is information about the requesting user
    @typechecked
    def userInfo(self) -> 'authenticationv1.UserInfo':
        return self._get('userInfo', authenticationv1.UserInfo())
    
    # Object is the object from the incoming request.
    @typechecked
    def object(self) -> 'runtime.RawExtension':
        return self._get('object', runtime.RawExtension())
    
    # OldObject is the existing object. Only populated for DELETE and UPDATE requests.
    @typechecked
    def oldObject(self) -> 'runtime.RawExtension':
        return self._get('oldObject', runtime.RawExtension())
    
    # DryRun indicates that modifications will definitely not be persisted for this request.
    # Defaults to false.
    @typechecked
    def dryRun(self) -> Optional[bool]:
        return self._get('dryRun')
    
    # Options is the operation option structure of the operation being performed.
    # e.g. `meta.k8s.io/v1.DeleteOptions` or `meta.k8s.io/v1.CreateOptions`. This may be
    # different than the options the caller provided. e.g. for a patch request the performed
    # Operation might be a CREATE, in which case the Options will a
    # `meta.k8s.io/v1.CreateOptions` even though the caller provided `meta.k8s.io/v1.PatchOptions`.
    @typechecked
    def options(self) -> 'runtime.RawExtension':
        return self._get('options', runtime.RawExtension())


# AdmissionResponse describes an admission response.
class AdmissionResponse(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['uid'] = self.uid()
        v['allowed'] = self.allowed()
        status = self.status()
        if status is not None:  # omit empty
            v['status'] = status
        patch = self.patch()
        if patch:  # omit empty
            v['patch'] = patch
        patchType = self.patchType()
        if patchType is not None:  # omit empty
            v['patchType'] = patchType
        auditAnnotations = self.auditAnnotations()
        if auditAnnotations:  # omit empty
            v['auditAnnotations'] = auditAnnotations
        return v
    
    # UID is an identifier for the individual request/response.
    # This must be copied over from the corresponding AdmissionRequest.
    @typechecked
    def uid(self) -> str:
        return self._get('uid', '')
    
    # Allowed indicates whether or not the admission request was permitted.
    @typechecked
    def allowed(self) -> bool:
        return self._get('allowed', False)
    
    # Result contains extra details into why an admission request was denied.
    # This field IS NOT consulted in any way if "Allowed" is "true".
    @typechecked
    def status(self) -> Optional['metav1.Status']:
        return self._get('status')
    
    # The patch body. Currently we only support "JSONPatch" which implements RFC 6902.
    @typechecked
    def patch(self) -> bytes:
        return self._get('patch', b'')
    
    # The type of Patch. Currently we only allow "JSONPatch".
    @typechecked
    def patchType(self) -> Optional[PatchType]:
        return self._get('patchType')
    
    # AuditAnnotations is an unstructured key value map set by remote admission controller (e.g. error=image-blacklisted).
    # MutatingAdmissionWebhook and ValidatingAdmissionWebhook admission controller will prefix the keys with
    # admission webhook name (e.g. imagepolicy.example.com/error=image-blacklisted). AuditAnnotations will be provided by
    # the admission webhook to add additional context to the audit log for this request.
    @typechecked
    def auditAnnotations(self) -> Dict[str, str]:
        return self._get('auditAnnotations', {})


# AdmissionReview describes an admission review request/response.
class AdmissionReview(base.TypedObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        request = self.request()
        if request is not None:  # omit empty
            v['request'] = request
        response = self.response()
        if response is not None:  # omit empty
            v['response'] = response
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'admission.k8s.io/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'AdmissionReview'
    
    # Request describes the attributes for the admission request.
    @typechecked
    def request(self) -> Optional[AdmissionRequest]:
        return self._get('request')
    
    # Response describes the attributes for the admission response.
    @typechecked
    def response(self) -> Optional[AdmissionResponse]:
        return self._get('response')
