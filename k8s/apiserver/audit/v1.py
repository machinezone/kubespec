# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from k8s.api.authentication import v1 as authenticationv1
from k8s.apimachinery import runtime
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# Level defines the amount of information logged during auditing
Level = base.Enum(
    "Level",
    {
        # Metadata provides the basic level of auditing.
        "Metadata": "Metadata",
        # None disables auditing
        "None": "None",
        # Request provides Metadata level of auditing, and additionally
        # logs the request object (does not apply for non-resource requests).
        "Request": "Request",
        # RequestResponse provides Request level of auditing, and additionally
        # logs the response object (does not apply for non-resource requests).
        "RequestResponse": "RequestResponse",
    },
)


# Stage defines the stages in request handling that audit events may be generated.
Stage = base.Enum(
    "Stage",
    {
        # The stage for events generated when a panic occurred.
        "Panic": "Panic",
        # The stage for events generated as soon as the audit handler receives the request, and before it
        # is delegated down the handler chain.
        "RequestReceived": "RequestReceived",
        # The stage for events generated once the response body has been completed, and no more bytes
        # will be sent.
        "ResponseComplete": "ResponseComplete",
        # The stage for events generated once the response headers are sent, but before the response body
        # is sent. This stage is only generated for long-running requests (e.g. watch).
        "ResponseStarted": "ResponseStarted",
    },
)


# ObjectReference contains enough information to let you inspect or modify the referred object.
class ObjectReference(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        resource = self.resource()
        if resource:  # omit empty
            v["resource"] = resource
        namespace = self.namespace()
        if namespace:  # omit empty
            v["namespace"] = namespace
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        uid = self.uid()
        if uid:  # omit empty
            v["uid"] = uid
        apiGroup = self.apiGroup()
        if apiGroup:  # omit empty
            v["apiGroup"] = apiGroup
        apiVersion = self.apiVersion()
        if apiVersion:  # omit empty
            v["apiVersion"] = apiVersion
        resourceVersion = self.resourceVersion()
        if resourceVersion:  # omit empty
            v["resourceVersion"] = resourceVersion
        subresource = self.subresource()
        if subresource:  # omit empty
            v["subresource"] = subresource
        return v

    @typechecked
    def resource(self) -> Optional[str]:
        if "resource" in self._kwargs:
            return self._kwargs["resource"]
        if "resource" in self._context and check_return_type(self._context["resource"]):
            return self._context["resource"]
        return None

    @typechecked
    def namespace(self) -> Optional[str]:
        if "namespace" in self._kwargs:
            return self._kwargs["namespace"]
        if "namespace" in self._context and check_return_type(
            self._context["namespace"]
        ):
            return self._context["namespace"]
        return None

    @typechecked
    def name(self) -> Optional[str]:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return None

    @typechecked
    def uid(self) -> Optional[str]:
        if "uid" in self._kwargs:
            return self._kwargs["uid"]
        if "uid" in self._context and check_return_type(self._context["uid"]):
            return self._context["uid"]
        return None

    # APIGroup is the name of the API group that contains the referred object.
    # The empty string represents the core API group.
    @typechecked
    def apiGroup(self) -> Optional[str]:
        if "apiGroup" in self._kwargs:
            return self._kwargs["apiGroup"]
        if "apiGroup" in self._context and check_return_type(self._context["apiGroup"]):
            return self._context["apiGroup"]
        return None

    # APIVersion is the version of the API group that contains the referred object.
    @typechecked
    def apiVersion(self) -> Optional[str]:
        if "apiVersion" in self._kwargs:
            return self._kwargs["apiVersion"]
        if "apiVersion" in self._context and check_return_type(
            self._context["apiVersion"]
        ):
            return self._context["apiVersion"]
        return None

    @typechecked
    def resourceVersion(self) -> Optional[str]:
        if "resourceVersion" in self._kwargs:
            return self._kwargs["resourceVersion"]
        if "resourceVersion" in self._context and check_return_type(
            self._context["resourceVersion"]
        ):
            return self._context["resourceVersion"]
        return None

    @typechecked
    def subresource(self) -> Optional[str]:
        if "subresource" in self._kwargs:
            return self._kwargs["subresource"]
        if "subresource" in self._context and check_return_type(
            self._context["subresource"]
        ):
            return self._context["subresource"]
        return None


# Event captures all the information that can be included in an API audit log.
class Event(base.TypedObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["level"] = self.level()
        v["auditID"] = self.auditID()
        v["stage"] = self.stage()
        v["requestURI"] = self.requestURI()
        v["verb"] = self.verb()
        v["user"] = self.user()
        impersonatedUser = self.impersonatedUser()
        if impersonatedUser is not None:  # omit empty
            v["impersonatedUser"] = impersonatedUser
        sourceIPs = self.sourceIPs()
        if sourceIPs:  # omit empty
            v["sourceIPs"] = sourceIPs
        userAgent = self.userAgent()
        if userAgent:  # omit empty
            v["userAgent"] = userAgent
        objectRef = self.objectRef()
        if objectRef is not None:  # omit empty
            v["objectRef"] = objectRef
        responseStatus = self.responseStatus()
        if responseStatus is not None:  # omit empty
            v["responseStatus"] = responseStatus
        requestObject = self.requestObject()
        if requestObject is not None:  # omit empty
            v["requestObject"] = requestObject
        responseObject = self.responseObject()
        if responseObject is not None:  # omit empty
            v["responseObject"] = responseObject
        v["requestReceivedTimestamp"] = self.requestReceivedTimestamp()
        v["stageTimestamp"] = self.stageTimestamp()
        annotations = self.annotations()
        if annotations:  # omit empty
            v["annotations"] = annotations
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "audit.k8s.io/v1"

    @typechecked
    def kind(self) -> str:
        return "Event"

    # AuditLevel at which event was generated
    @typechecked
    def level(self) -> Level:
        if "level" in self._kwargs:
            return self._kwargs["level"]
        if "level" in self._context and check_return_type(self._context["level"]):
            return self._context["level"]
        return None

    # Unique audit ID, generated for each request.
    @typechecked
    def auditID(self) -> str:
        if "auditID" in self._kwargs:
            return self._kwargs["auditID"]
        if "auditID" in self._context and check_return_type(self._context["auditID"]):
            return self._context["auditID"]
        return ""

    # Stage of the request handling when this event instance was generated.
    @typechecked
    def stage(self) -> Stage:
        if "stage" in self._kwargs:
            return self._kwargs["stage"]
        if "stage" in self._context and check_return_type(self._context["stage"]):
            return self._context["stage"]
        return None

    # RequestURI is the request URI as sent by the client to a server.
    @typechecked
    def requestURI(self) -> str:
        if "requestURI" in self._kwargs:
            return self._kwargs["requestURI"]
        if "requestURI" in self._context and check_return_type(
            self._context["requestURI"]
        ):
            return self._context["requestURI"]
        return ""

    # Verb is the kubernetes verb associated with the request.
    # For non-resource requests, this is the lower-cased HTTP method.
    @typechecked
    def verb(self) -> str:
        if "verb" in self._kwargs:
            return self._kwargs["verb"]
        if "verb" in self._context and check_return_type(self._context["verb"]):
            return self._context["verb"]
        return ""

    # Authenticated user information.
    @typechecked
    def user(self) -> "authenticationv1.UserInfo":
        if "user" in self._kwargs:
            return self._kwargs["user"]
        if "user" in self._context and check_return_type(self._context["user"]):
            return self._context["user"]
        with context.Scope(**self._context):
            return authenticationv1.UserInfo()

    # Impersonated user information.
    @typechecked
    def impersonatedUser(self) -> Optional["authenticationv1.UserInfo"]:
        if "impersonatedUser" in self._kwargs:
            return self._kwargs["impersonatedUser"]
        if "impersonatedUser" in self._context and check_return_type(
            self._context["impersonatedUser"]
        ):
            return self._context["impersonatedUser"]
        return None

    # Source IPs, from where the request originated and intermediate proxies.
    @typechecked
    def sourceIPs(self) -> List[str]:
        if "sourceIPs" in self._kwargs:
            return self._kwargs["sourceIPs"]
        if "sourceIPs" in self._context and check_return_type(
            self._context["sourceIPs"]
        ):
            return self._context["sourceIPs"]
        return []

    # UserAgent records the user agent string reported by the client.
    # Note that the UserAgent is provided by the client, and must not be trusted.
    @typechecked
    def userAgent(self) -> Optional[str]:
        if "userAgent" in self._kwargs:
            return self._kwargs["userAgent"]
        if "userAgent" in self._context and check_return_type(
            self._context["userAgent"]
        ):
            return self._context["userAgent"]
        return None

    # Object reference this request is targeted at.
    # Does not apply for List-type requests, or non-resource requests.
    @typechecked
    def objectRef(self) -> Optional[ObjectReference]:
        if "objectRef" in self._kwargs:
            return self._kwargs["objectRef"]
        if "objectRef" in self._context and check_return_type(
            self._context["objectRef"]
        ):
            return self._context["objectRef"]
        return None

    # The response status, populated even when the ResponseObject is not a Status type.
    # For successful responses, this will only include the Code and StatusSuccess.
    # For non-status type error responses, this will be auto-populated with the error Message.
    @typechecked
    def responseStatus(self) -> Optional["metav1.Status"]:
        if "responseStatus" in self._kwargs:
            return self._kwargs["responseStatus"]
        if "responseStatus" in self._context and check_return_type(
            self._context["responseStatus"]
        ):
            return self._context["responseStatus"]
        return None

    # API object from the request, in JSON format. The RequestObject is recorded as-is in the request
    # (possibly re-encoded as JSON), prior to version conversion, defaulting, admission or
    # merging. It is an external versioned object type, and may not be a valid object on its own.
    # Omitted for non-resource requests.  Only logged at Request Level and higher.
    @typechecked
    def requestObject(self) -> Optional["runtime.Unknown"]:
        if "requestObject" in self._kwargs:
            return self._kwargs["requestObject"]
        if "requestObject" in self._context and check_return_type(
            self._context["requestObject"]
        ):
            return self._context["requestObject"]
        return None

    # API object returned in the response, in JSON. The ResponseObject is recorded after conversion
    # to the external type, and serialized as JSON.  Omitted for non-resource requests.  Only logged
    # at Response Level.
    @typechecked
    def responseObject(self) -> Optional["runtime.Unknown"]:
        if "responseObject" in self._kwargs:
            return self._kwargs["responseObject"]
        if "responseObject" in self._context and check_return_type(
            self._context["responseObject"]
        ):
            return self._context["responseObject"]
        return None

    # Time the request reached the apiserver.
    @typechecked
    def requestReceivedTimestamp(self) -> "base.MicroTime":
        if "requestReceivedTimestamp" in self._kwargs:
            return self._kwargs["requestReceivedTimestamp"]
        if "requestReceivedTimestamp" in self._context and check_return_type(
            self._context["requestReceivedTimestamp"]
        ):
            return self._context["requestReceivedTimestamp"]
        return None

    # Time the request reached current audit stage.
    @typechecked
    def stageTimestamp(self) -> "base.MicroTime":
        if "stageTimestamp" in self._kwargs:
            return self._kwargs["stageTimestamp"]
        if "stageTimestamp" in self._context and check_return_type(
            self._context["stageTimestamp"]
        ):
            return self._context["stageTimestamp"]
        return None

    # Annotations is an unstructured key value map stored with an audit event that may be set by
    # plugins invoked in the request serving chain, including authentication, authorization and
    # admission plugins. Note that these annotations are for the audit event, and do not correspond
    # to the metadata.annotations of the submitted object. Keys should uniquely identify the informing
    # component to avoid name collisions (e.g. podsecuritypolicy.admission.k8s.io/policy). Values
    # should be short. Annotations are included in the Metadata level.
    @typechecked
    def annotations(self) -> Dict[str, str]:
        if "annotations" in self._kwargs:
            return self._kwargs["annotations"]
        if "annotations" in self._context and check_return_type(
            self._context["annotations"]
        ):
            return self._context["annotations"]
        return {}


# GroupResources represents resource kinds in an API group.
class GroupResources(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        group = self.group()
        if group:  # omit empty
            v["group"] = group
        resources = self.resources()
        if resources:  # omit empty
            v["resources"] = resources
        resourceNames = self.resourceNames()
        if resourceNames:  # omit empty
            v["resourceNames"] = resourceNames
        return v

    # Group is the name of the API group that contains the resources.
    # The empty string represents the core API group.
    @typechecked
    def group(self) -> Optional[str]:
        if "group" in self._kwargs:
            return self._kwargs["group"]
        if "group" in self._context and check_return_type(self._context["group"]):
            return self._context["group"]
        return None

    # Resources is a list of resources this rule applies to.
    #
    # For example:
    # 'pods' matches pods.
    # 'pods/log' matches the log subresource of pods.
    # '*' matches all resources and their subresources.
    # 'pods/*' matches all subresources of pods.
    # '*/scale' matches all scale subresources.
    #
    # If wildcard is present, the validation rule will ensure resources do not
    # overlap with each other.
    #
    # An empty list implies all resources and subresources in this API groups apply.
    @typechecked
    def resources(self) -> List[str]:
        if "resources" in self._kwargs:
            return self._kwargs["resources"]
        if "resources" in self._context and check_return_type(
            self._context["resources"]
        ):
            return self._context["resources"]
        return []

    # ResourceNames is a list of resource instance names that the policy matches.
    # Using this field requires Resources to be specified.
    # An empty list implies that every instance of the resource is matched.
    @typechecked
    def resourceNames(self) -> List[str]:
        if "resourceNames" in self._kwargs:
            return self._kwargs["resourceNames"]
        if "resourceNames" in self._context and check_return_type(
            self._context["resourceNames"]
        ):
            return self._context["resourceNames"]
        return []


# PolicyRule maps requests based off metadata to an audit Level.
# Requests must match the rules of every field (an intersection of rules).
class PolicyRule(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["level"] = self.level()
        users = self.users()
        if users:  # omit empty
            v["users"] = users
        userGroups = self.userGroups()
        if userGroups:  # omit empty
            v["userGroups"] = userGroups
        verbs = self.verbs()
        if verbs:  # omit empty
            v["verbs"] = verbs
        resources = self.resources()
        if resources:  # omit empty
            v["resources"] = resources
        namespaces = self.namespaces()
        if namespaces:  # omit empty
            v["namespaces"] = namespaces
        nonResourceURLs = self.nonResourceURLs()
        if nonResourceURLs:  # omit empty
            v["nonResourceURLs"] = nonResourceURLs
        omitStages = self.omitStages()
        if omitStages:  # omit empty
            v["omitStages"] = omitStages
        return v

    # The Level that requests matching this rule are recorded at.
    @typechecked
    def level(self) -> Level:
        if "level" in self._kwargs:
            return self._kwargs["level"]
        if "level" in self._context and check_return_type(self._context["level"]):
            return self._context["level"]
        return None

    # The users (by authenticated user name) this rule applies to.
    # An empty list implies every user.
    @typechecked
    def users(self) -> List[str]:
        if "users" in self._kwargs:
            return self._kwargs["users"]
        if "users" in self._context and check_return_type(self._context["users"]):
            return self._context["users"]
        return []

    # The user groups this rule applies to. A user is considered matching
    # if it is a member of any of the UserGroups.
    # An empty list implies every user group.
    @typechecked
    def userGroups(self) -> List[str]:
        if "userGroups" in self._kwargs:
            return self._kwargs["userGroups"]
        if "userGroups" in self._context and check_return_type(
            self._context["userGroups"]
        ):
            return self._context["userGroups"]
        return []

    # The verbs that match this rule.
    # An empty list implies every verb.
    @typechecked
    def verbs(self) -> List[str]:
        if "verbs" in self._kwargs:
            return self._kwargs["verbs"]
        if "verbs" in self._context and check_return_type(self._context["verbs"]):
            return self._context["verbs"]
        return []

    # Resources that this rule matches. An empty list implies all kinds in all API groups.
    @typechecked
    def resources(self) -> List[GroupResources]:
        if "resources" in self._kwargs:
            return self._kwargs["resources"]
        if "resources" in self._context and check_return_type(
            self._context["resources"]
        ):
            return self._context["resources"]
        return []

    # Namespaces that this rule matches.
    # The empty string "" matches non-namespaced resources.
    # An empty list implies every namespace.
    @typechecked
    def namespaces(self) -> List[str]:
        if "namespaces" in self._kwargs:
            return self._kwargs["namespaces"]
        if "namespaces" in self._context and check_return_type(
            self._context["namespaces"]
        ):
            return self._context["namespaces"]
        return []

    # NonResourceURLs is a set of URL paths that should be audited.
    # *s are allowed, but only as the full, final step in the path.
    # Examples:
    #  "/metrics" - Log requests for apiserver metrics
    #  "/healthz*" - Log all health checks
    @typechecked
    def nonResourceURLs(self) -> List[str]:
        if "nonResourceURLs" in self._kwargs:
            return self._kwargs["nonResourceURLs"]
        if "nonResourceURLs" in self._context and check_return_type(
            self._context["nonResourceURLs"]
        ):
            return self._context["nonResourceURLs"]
        return []

    # OmitStages is a list of stages for which no events are created. Note that this can also
    # be specified policy wide in which case the union of both are omitted.
    # An empty list means no restrictions will apply.
    @typechecked
    def omitStages(self) -> List[Stage]:
        if "omitStages" in self._kwargs:
            return self._kwargs["omitStages"]
        if "omitStages" in self._context and check_return_type(
            self._context["omitStages"]
        ):
            return self._context["omitStages"]
        return []


# Policy defines the configuration of audit logging, and the rules for how different request
# categories are logged.
class Policy(base.TypedObject, base.NamespacedMetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["rules"] = self.rules()
        omitStages = self.omitStages()
        if omitStages:  # omit empty
            v["omitStages"] = omitStages
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "audit.k8s.io/v1"

    @typechecked
    def kind(self) -> str:
        return "Policy"

    # Rules specify the audit Level a request should be recorded at.
    # A request may match multiple rules, in which case the FIRST matching rule is used.
    # The default audit level is None, but can be overridden by a catch-all rule at the end of the list.
    # PolicyRules are strictly ordered.
    @typechecked
    def rules(self) -> List[PolicyRule]:
        if "rules" in self._kwargs:
            return self._kwargs["rules"]
        if "rules" in self._context and check_return_type(self._context["rules"]):
            return self._context["rules"]
        return []

    # OmitStages is a list of stages for which no events are created. Note that this can also
    # be specified per rule in which case the union of both are omitted.
    @typechecked
    def omitStages(self) -> List[Stage]:
        if "omitStages" in self._kwargs:
            return self._kwargs["omitStages"]
        if "omitStages" in self._context and check_return_type(
            self._context["omitStages"]
        ):
            return self._context["omitStages"]
        return []
