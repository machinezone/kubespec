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
    @context.scoped
    @typechecked
    def __init__(
        self,
        resource: str = None,
        namespace: str = None,
        name: str = None,
        uid: str = None,
        apiGroup: str = None,
        apiVersion: str = None,
        resourceVersion: str = None,
        subresource: str = None,
    ):
        super().__init__(**{})
        self.__resource = resource
        self.__namespace = namespace
        self.__name = name
        self.__uid = uid
        self.__apiGroup = apiGroup
        self.__apiVersion = apiVersion
        self.__resourceVersion = resourceVersion
        self.__subresource = subresource

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
        return self.__resource

    @typechecked
    def namespace(self) -> Optional[str]:
        return self.__namespace

    @typechecked
    def name(self) -> Optional[str]:
        return self.__name

    @typechecked
    def uid(self) -> Optional[str]:
        return self.__uid

    # APIGroup is the name of the API group that contains the referred object.
    # The empty string represents the core API group.
    @typechecked
    def apiGroup(self) -> Optional[str]:
        return self.__apiGroup

    # APIVersion is the version of the API group that contains the referred object.
    @typechecked
    def apiVersion(self) -> Optional[str]:
        return self.__apiVersion

    @typechecked
    def resourceVersion(self) -> Optional[str]:
        return self.__resourceVersion

    @typechecked
    def subresource(self) -> Optional[str]:
        return self.__subresource


# Event captures all the information that can be included in an API audit log.
class Event(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        level: Level = None,
        auditID: str = "",
        stage: Stage = None,
        requestURI: str = "",
        verb: str = "",
        user: "authenticationv1.UserInfo" = None,
        impersonatedUser: "authenticationv1.UserInfo" = None,
        sourceIPs: List[str] = None,
        userAgent: str = None,
        objectRef: ObjectReference = None,
        responseStatus: "metav1.Status" = None,
        requestObject: "runtime.Unknown" = None,
        responseObject: "runtime.Unknown" = None,
        requestReceivedTimestamp: "base.MicroTime" = None,
        stageTimestamp: "base.MicroTime" = None,
        annotations: Dict[str, str] = None,
    ):
        super().__init__(**{"apiVersion": "audit.k8s.io/v1beta1", "kind": "Event"})
        self.__level = level
        self.__auditID = auditID
        self.__stage = stage
        self.__requestURI = requestURI
        self.__verb = verb
        self.__user = user if user is not None else authenticationv1.UserInfo()
        self.__impersonatedUser = impersonatedUser
        self.__sourceIPs = sourceIPs if sourceIPs is not None else []
        self.__userAgent = userAgent
        self.__objectRef = objectRef
        self.__responseStatus = responseStatus
        self.__requestObject = requestObject
        self.__responseObject = responseObject
        self.__requestReceivedTimestamp = requestReceivedTimestamp
        self.__stageTimestamp = stageTimestamp
        self.__annotations = annotations if annotations is not None else {}

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

    # AuditLevel at which event was generated
    @typechecked
    def level(self) -> Level:
        return self.__level

    # Unique audit ID, generated for each request.
    @typechecked
    def auditID(self) -> str:
        return self.__auditID

    # Stage of the request handling when this event instance was generated.
    @typechecked
    def stage(self) -> Stage:
        return self.__stage

    # RequestURI is the request URI as sent by the client to a server.
    @typechecked
    def requestURI(self) -> str:
        return self.__requestURI

    # Verb is the kubernetes verb associated with the request.
    # For non-resource requests, this is the lower-cased HTTP method.
    @typechecked
    def verb(self) -> str:
        return self.__verb

    # Authenticated user information.
    @typechecked
    def user(self) -> "authenticationv1.UserInfo":
        return self.__user

    # Impersonated user information.
    @typechecked
    def impersonatedUser(self) -> Optional["authenticationv1.UserInfo"]:
        return self.__impersonatedUser

    # Source IPs, from where the request originated and intermediate proxies.
    @typechecked
    def sourceIPs(self) -> Optional[List[str]]:
        return self.__sourceIPs

    # UserAgent records the user agent string reported by the client.
    # Note that the UserAgent is provided by the client, and must not be trusted.
    @typechecked
    def userAgent(self) -> Optional[str]:
        return self.__userAgent

    # Object reference this request is targeted at.
    # Does not apply for List-type requests, or non-resource requests.
    @typechecked
    def objectRef(self) -> Optional[ObjectReference]:
        return self.__objectRef

    # The response status, populated even when the ResponseObject is not a Status type.
    # For successful responses, this will only include the Code and StatusSuccess.
    # For non-status type error responses, this will be auto-populated with the error Message.
    @typechecked
    def responseStatus(self) -> Optional["metav1.Status"]:
        return self.__responseStatus

    # API object from the request, in JSON format. The RequestObject is recorded as-is in the request
    # (possibly re-encoded as JSON), prior to version conversion, defaulting, admission or
    # merging. It is an external versioned object type, and may not be a valid object on its own.
    # Omitted for non-resource requests.  Only logged at Request Level and higher.
    @typechecked
    def requestObject(self) -> Optional["runtime.Unknown"]:
        return self.__requestObject

    # API object returned in the response, in JSON. The ResponseObject is recorded after conversion
    # to the external type, and serialized as JSON.  Omitted for non-resource requests.  Only logged
    # at Response Level.
    @typechecked
    def responseObject(self) -> Optional["runtime.Unknown"]:
        return self.__responseObject

    # Time the request reached the apiserver.
    @typechecked
    def requestReceivedTimestamp(self) -> "base.MicroTime":
        return self.__requestReceivedTimestamp

    # Time the request reached current audit stage.
    @typechecked
    def stageTimestamp(self) -> "base.MicroTime":
        return self.__stageTimestamp

    # Annotations is an unstructured key value map stored with an audit event that may be set by
    # plugins invoked in the request serving chain, including authentication, authorization and
    # admission plugins. Note that these annotations are for the audit event, and do not correspond
    # to the metadata.annotations of the submitted object. Keys should uniquely identify the informing
    # component to avoid name collisions (e.g. podsecuritypolicy.admission.k8s.io/policy). Values
    # should be short. Annotations are included in the Metadata level.
    @typechecked
    def annotations(self) -> Optional[Dict[str, str]]:
        return self.__annotations


# GroupResources represents resource kinds in an API group.
class GroupResources(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        group: str = None,
        resources: List[str] = None,
        resourceNames: List[str] = None,
    ):
        super().__init__(**{})
        self.__group = group
        self.__resources = resources if resources is not None else []
        self.__resourceNames = resourceNames if resourceNames is not None else []

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
        return self.__group

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
    def resources(self) -> Optional[List[str]]:
        return self.__resources

    # ResourceNames is a list of resource instance names that the policy matches.
    # Using this field requires Resources to be specified.
    # An empty list implies that every instance of the resource is matched.
    @typechecked
    def resourceNames(self) -> Optional[List[str]]:
        return self.__resourceNames


# PolicyRule maps requests based off metadata to an audit Level.
# Requests must match the rules of every field (an intersection of rules).
class PolicyRule(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        level: Level = None,
        users: List[str] = None,
        userGroups: List[str] = None,
        verbs: List[str] = None,
        resources: List[GroupResources] = None,
        namespaces: List[str] = None,
        nonResourceURLs: List[str] = None,
        omitStages: List[Stage] = None,
    ):
        super().__init__(**{})
        self.__level = level
        self.__users = users if users is not None else []
        self.__userGroups = userGroups if userGroups is not None else []
        self.__verbs = verbs if verbs is not None else []
        self.__resources = resources if resources is not None else []
        self.__namespaces = namespaces if namespaces is not None else []
        self.__nonResourceURLs = nonResourceURLs if nonResourceURLs is not None else []
        self.__omitStages = omitStages if omitStages is not None else []

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
        return self.__level

    # The users (by authenticated user name) this rule applies to.
    # An empty list implies every user.
    @typechecked
    def users(self) -> Optional[List[str]]:
        return self.__users

    # The user groups this rule applies to. A user is considered matching
    # if it is a member of any of the UserGroups.
    # An empty list implies every user group.
    @typechecked
    def userGroups(self) -> Optional[List[str]]:
        return self.__userGroups

    # The verbs that match this rule.
    # An empty list implies every verb.
    @typechecked
    def verbs(self) -> Optional[List[str]]:
        return self.__verbs

    # Resources that this rule matches. An empty list implies all kinds in all API groups.
    @typechecked
    def resources(self) -> Optional[List[GroupResources]]:
        return self.__resources

    # Namespaces that this rule matches.
    # The empty string "" matches non-namespaced resources.
    # An empty list implies every namespace.
    @typechecked
    def namespaces(self) -> Optional[List[str]]:
        return self.__namespaces

    # NonResourceURLs is a set of URL paths that should be audited.
    # *s are allowed, but only as the full, final step in the path.
    # Examples:
    #  "/metrics" - Log requests for apiserver metrics
    #  "/healthz*" - Log all health checks
    @typechecked
    def nonResourceURLs(self) -> Optional[List[str]]:
        return self.__nonResourceURLs

    # OmitStages is a list of stages for which no events are created. Note that this can also
    # be specified policy wide in which case the union of both are omitted.
    # An empty list means no restrictions will apply.
    @typechecked
    def omitStages(self) -> Optional[List[Stage]]:
        return self.__omitStages


# Policy defines the configuration of audit logging, and the rules for how different request
# categories are logged.
class Policy(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        rules: List[PolicyRule] = None,
        omitStages: List[Stage] = None,
    ):
        super().__init__(
            **{
                "apiVersion": "audit.k8s.io/v1beta1",
                "kind": "Policy",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__rules = rules if rules is not None else []
        self.__omitStages = omitStages if omitStages is not None else []

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["rules"] = self.rules()
        omitStages = self.omitStages()
        if omitStages:  # omit empty
            v["omitStages"] = omitStages
        return v

    # Rules specify the audit Level a request should be recorded at.
    # A request may match multiple rules, in which case the FIRST matching rule is used.
    # The default audit level is None, but can be overridden by a catch-all rule at the end of the list.
    # PolicyRules are strictly ordered.
    @typechecked
    def rules(self) -> List[PolicyRule]:
        return self.__rules

    # OmitStages is a list of stages for which no events are created. Note that this can also
    # be specified per rule in which case the union of both are omitted.
    @typechecked
    def omitStages(self) -> Optional[List[Stage]]:
        return self.__omitStages
