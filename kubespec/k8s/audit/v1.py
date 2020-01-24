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
from typing import Any, Dict, List, Optional


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


class ObjectReference(types.Object):
    """
    ObjectReference contains enough information to let you inspect or modify the referred object.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        resource: str = None,
        namespace: str = None,
        name: str = None,
        uid: str = None,
        api_group: str = None,
        api_version: str = None,
        resource_version: str = None,
        subresource: str = None,
    ):
        super().__init__()
        self.__resource = resource
        self.__namespace = namespace
        self.__name = name
        self.__uid = uid
        self.__api_group = api_group
        self.__api_version = api_version
        self.__resource_version = resource_version
        self.__subresource = subresource

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        resource = self.resource()
        check_type("resource", resource, Optional[str])
        if resource:  # omit empty
            v["resource"] = resource
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        uid = self.uid()
        check_type("uid", uid, Optional[str])
        if uid:  # omit empty
            v["uid"] = uid
        api_group = self.api_group()
        check_type("api_group", api_group, Optional[str])
        if api_group:  # omit empty
            v["apiGroup"] = api_group
        api_version = self.api_version()
        check_type("api_version", api_version, Optional[str])
        if api_version:  # omit empty
            v["apiVersion"] = api_version
        resource_version = self.resource_version()
        check_type("resource_version", resource_version, Optional[str])
        if resource_version:  # omit empty
            v["resourceVersion"] = resource_version
        subresource = self.subresource()
        check_type("subresource", subresource, Optional[str])
        if subresource:  # omit empty
            v["subresource"] = subresource
        return v

    def resource(self) -> Optional[str]:
        return self.__resource

    def namespace(self) -> Optional[str]:
        return self.__namespace

    def name(self) -> Optional[str]:
        return self.__name

    def uid(self) -> Optional[str]:
        return self.__uid

    def api_group(self) -> Optional[str]:
        """
        APIGroup is the name of the API group that contains the referred object.
        The empty string represents the core API group.
        """
        return self.__api_group

    def api_version(self) -> Optional[str]:
        """
        APIVersion is the version of the API group that contains the referred object.
        """
        return self.__api_version

    def resource_version(self) -> Optional[str]:
        return self.__resource_version

    def subresource(self) -> Optional[str]:
        return self.__subresource


class Event(base.TypedObject):
    """
    Event captures all the information that can be included in an API audit log.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        level: Level = None,
        audit_id: str = "",
        stage: Stage = None,
        request_uri: str = "",
        verb: str = "",
        user: "authenticationv1.UserInfo" = None,
        impersonated_user: "authenticationv1.UserInfo" = None,
        source_ips: List[str] = None,
        user_agent: str = None,
        object_ref: "ObjectReference" = None,
        response_status: "metav1.Status" = None,
        request_object: "runtime.Unknown" = None,
        response_object: "runtime.Unknown" = None,
        request_received_timestamp: "base.MicroTime" = None,
        stage_timestamp: "base.MicroTime" = None,
        annotations: Dict[str, str] = None,
    ):
        super().__init__(api_version="audit.k8s.io/v1", kind="Event")
        self.__level = level
        self.__audit_id = audit_id
        self.__stage = stage
        self.__request_uri = request_uri
        self.__verb = verb
        self.__user = user if user is not None else authenticationv1.UserInfo()
        self.__impersonated_user = impersonated_user
        self.__source_ips = source_ips if source_ips is not None else []
        self.__user_agent = user_agent
        self.__object_ref = object_ref
        self.__response_status = response_status
        self.__request_object = request_object
        self.__response_object = response_object
        self.__request_received_timestamp = request_received_timestamp
        self.__stage_timestamp = stage_timestamp
        self.__annotations = annotations if annotations is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        level = self.level()
        check_type("level", level, Level)
        v["level"] = level
        audit_id = self.audit_id()
        check_type("audit_id", audit_id, str)
        v["auditID"] = audit_id
        stage = self.stage()
        check_type("stage", stage, Stage)
        v["stage"] = stage
        request_uri = self.request_uri()
        check_type("request_uri", request_uri, str)
        v["requestURI"] = request_uri
        verb = self.verb()
        check_type("verb", verb, str)
        v["verb"] = verb
        user = self.user()
        check_type("user", user, "authenticationv1.UserInfo")
        v["user"] = user
        impersonated_user = self.impersonated_user()
        check_type(
            "impersonated_user",
            impersonated_user,
            Optional["authenticationv1.UserInfo"],
        )
        if impersonated_user is not None:  # omit empty
            v["impersonatedUser"] = impersonated_user
        source_ips = self.source_ips()
        check_type("source_ips", source_ips, Optional[List[str]])
        if source_ips:  # omit empty
            v["sourceIPs"] = source_ips
        user_agent = self.user_agent()
        check_type("user_agent", user_agent, Optional[str])
        if user_agent:  # omit empty
            v["userAgent"] = user_agent
        object_ref = self.object_ref()
        check_type("object_ref", object_ref, Optional["ObjectReference"])
        if object_ref is not None:  # omit empty
            v["objectRef"] = object_ref
        response_status = self.response_status()
        check_type("response_status", response_status, Optional["metav1.Status"])
        if response_status is not None:  # omit empty
            v["responseStatus"] = response_status
        request_object = self.request_object()
        check_type("request_object", request_object, Optional["runtime.Unknown"])
        if request_object is not None:  # omit empty
            v["requestObject"] = request_object
        response_object = self.response_object()
        check_type("response_object", response_object, Optional["runtime.Unknown"])
        if response_object is not None:  # omit empty
            v["responseObject"] = response_object
        request_received_timestamp = self.request_received_timestamp()
        check_type(
            "request_received_timestamp", request_received_timestamp, "base.MicroTime"
        )
        v["requestReceivedTimestamp"] = request_received_timestamp
        stage_timestamp = self.stage_timestamp()
        check_type("stage_timestamp", stage_timestamp, "base.MicroTime")
        v["stageTimestamp"] = stage_timestamp
        annotations = self.annotations()
        check_type("annotations", annotations, Optional[Dict[str, str]])
        if annotations:  # omit empty
            v["annotations"] = annotations
        return v

    def level(self) -> Level:
        """
        AuditLevel at which event was generated
        """
        return self.__level

    def audit_id(self) -> str:
        """
        Unique audit ID, generated for each request.
        """
        return self.__audit_id

    def stage(self) -> Stage:
        """
        Stage of the request handling when this event instance was generated.
        """
        return self.__stage

    def request_uri(self) -> str:
        """
        RequestURI is the request URI as sent by the client to a server.
        """
        return self.__request_uri

    def verb(self) -> str:
        """
        Verb is the kubernetes verb associated with the request.
        For non-resource requests, this is the lower-cased HTTP method.
        """
        return self.__verb

    def user(self) -> "authenticationv1.UserInfo":
        """
        Authenticated user information.
        """
        return self.__user

    def impersonated_user(self) -> Optional["authenticationv1.UserInfo"]:
        """
        Impersonated user information.
        """
        return self.__impersonated_user

    def source_ips(self) -> Optional[List[str]]:
        """
        Source IPs, from where the request originated and intermediate proxies.
        """
        return self.__source_ips

    def user_agent(self) -> Optional[str]:
        """
        UserAgent records the user agent string reported by the client.
        Note that the UserAgent is provided by the client, and must not be trusted.
        """
        return self.__user_agent

    def object_ref(self) -> Optional["ObjectReference"]:
        """
        Object reference this request is targeted at.
        Does not apply for List-type requests, or non-resource requests.
        """
        return self.__object_ref

    def response_status(self) -> Optional["metav1.Status"]:
        """
        The response status, populated even when the ResponseObject is not a Status type.
        For successful responses, this will only include the Code and StatusSuccess.
        For non-status type error responses, this will be auto-populated with the error Message.
        """
        return self.__response_status

    def request_object(self) -> Optional["runtime.Unknown"]:
        """
        API object from the request, in JSON format. The RequestObject is recorded as-is in the request
        (possibly re-encoded as JSON), prior to version conversion, defaulting, admission or
        merging. It is an external versioned object type, and may not be a valid object on its own.
        Omitted for non-resource requests.  Only logged at Request Level and higher.
        """
        return self.__request_object

    def response_object(self) -> Optional["runtime.Unknown"]:
        """
        API object returned in the response, in JSON. The ResponseObject is recorded after conversion
        to the external type, and serialized as JSON.  Omitted for non-resource requests.  Only logged
        at Response Level.
        """
        return self.__response_object

    def request_received_timestamp(self) -> "base.MicroTime":
        """
        Time the request reached the apiserver.
        """
        return self.__request_received_timestamp

    def stage_timestamp(self) -> "base.MicroTime":
        """
        Time the request reached current audit stage.
        """
        return self.__stage_timestamp

    def annotations(self) -> Optional[Dict[str, str]]:
        """
        Annotations is an unstructured key value map stored with an audit event that may be set by
        plugins invoked in the request serving chain, including authentication, authorization and
        admission plugins. Note that these annotations are for the audit event, and do not correspond
        to the metadata.annotations of the submitted object. Keys should uniquely identify the informing
        component to avoid name collisions (e.g. podsecuritypolicy.admission.k8s.io/policy). Values
        should be short. Annotations are included in the Metadata level.
        """
        return self.__annotations


class GroupResources(types.Object):
    """
    GroupResources represents resource kinds in an API group.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        group: str = None,
        resources: List[str] = None,
        resource_names: List[str] = None,
    ):
        super().__init__()
        self.__group = group
        self.__resources = resources if resources is not None else []
        self.__resource_names = resource_names if resource_names is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        group = self.group()
        check_type("group", group, Optional[str])
        if group:  # omit empty
            v["group"] = group
        resources = self.resources()
        check_type("resources", resources, Optional[List[str]])
        if resources:  # omit empty
            v["resources"] = resources
        resource_names = self.resource_names()
        check_type("resource_names", resource_names, Optional[List[str]])
        if resource_names:  # omit empty
            v["resourceNames"] = resource_names
        return v

    def group(self) -> Optional[str]:
        """
        Group is the name of the API group that contains the resources.
        The empty string represents the core API group.
        """
        return self.__group

    def resources(self) -> Optional[List[str]]:
        """
        Resources is a list of resources this rule applies to.
        
        For example:
        'pods' matches pods.
        'pods/log' matches the log subresource of pods.
        '*' matches all resources and their subresources.
        'pods/*' matches all subresources of pods.
        '*/scale' matches all scale subresources.
        
        If wildcard is present, the validation rule will ensure resources do not
        overlap with each other.
        
        An empty list implies all resources and subresources in this API groups apply.
        """
        return self.__resources

    def resource_names(self) -> Optional[List[str]]:
        """
        ResourceNames is a list of resource instance names that the policy matches.
        Using this field requires Resources to be specified.
        An empty list implies that every instance of the resource is matched.
        """
        return self.__resource_names


class PolicyRule(types.Object):
    """
    PolicyRule maps requests based off metadata to an audit Level.
    Requests must match the rules of every field (an intersection of rules).
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        level: Level = None,
        users: List[str] = None,
        user_groups: List[str] = None,
        verbs: List[str] = None,
        resources: List["GroupResources"] = None,
        namespaces: List[str] = None,
        non_resource_urls: List[str] = None,
        omit_stages: List[Stage] = None,
    ):
        super().__init__()
        self.__level = level
        self.__users = users if users is not None else []
        self.__user_groups = user_groups if user_groups is not None else []
        self.__verbs = verbs if verbs is not None else []
        self.__resources = resources if resources is not None else []
        self.__namespaces = namespaces if namespaces is not None else []
        self.__non_resource_urls = (
            non_resource_urls if non_resource_urls is not None else []
        )
        self.__omit_stages = omit_stages if omit_stages is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        level = self.level()
        check_type("level", level, Level)
        v["level"] = level
        users = self.users()
        check_type("users", users, Optional[List[str]])
        if users:  # omit empty
            v["users"] = users
        user_groups = self.user_groups()
        check_type("user_groups", user_groups, Optional[List[str]])
        if user_groups:  # omit empty
            v["userGroups"] = user_groups
        verbs = self.verbs()
        check_type("verbs", verbs, Optional[List[str]])
        if verbs:  # omit empty
            v["verbs"] = verbs
        resources = self.resources()
        check_type("resources", resources, Optional[List["GroupResources"]])
        if resources:  # omit empty
            v["resources"] = resources
        namespaces = self.namespaces()
        check_type("namespaces", namespaces, Optional[List[str]])
        if namespaces:  # omit empty
            v["namespaces"] = namespaces
        non_resource_urls = self.non_resource_urls()
        check_type("non_resource_urls", non_resource_urls, Optional[List[str]])
        if non_resource_urls:  # omit empty
            v["nonResourceURLs"] = non_resource_urls
        omit_stages = self.omit_stages()
        check_type("omit_stages", omit_stages, Optional[List[Stage]])
        if omit_stages:  # omit empty
            v["omitStages"] = omit_stages
        return v

    def level(self) -> Level:
        """
        The Level that requests matching this rule are recorded at.
        """
        return self.__level

    def users(self) -> Optional[List[str]]:
        """
        The users (by authenticated user name) this rule applies to.
        An empty list implies every user.
        """
        return self.__users

    def user_groups(self) -> Optional[List[str]]:
        """
        The user groups this rule applies to. A user is considered matching
        if it is a member of any of the UserGroups.
        An empty list implies every user group.
        """
        return self.__user_groups

    def verbs(self) -> Optional[List[str]]:
        """
        The verbs that match this rule.
        An empty list implies every verb.
        """
        return self.__verbs

    def resources(self) -> Optional[List["GroupResources"]]:
        """
        Resources that this rule matches. An empty list implies all kinds in all API groups.
        """
        return self.__resources

    def namespaces(self) -> Optional[List[str]]:
        """
        Namespaces that this rule matches.
        The empty string "" matches non-namespaced resources.
        An empty list implies every namespace.
        """
        return self.__namespaces

    def non_resource_urls(self) -> Optional[List[str]]:
        """
        NonResourceURLs is a set of URL paths that should be audited.
        *s are allowed, but only as the full, final step in the path.
        Examples:
         "/metrics" - Log requests for apiserver metrics
         "/healthz*" - Log all health checks
        """
        return self.__non_resource_urls

    def omit_stages(self) -> Optional[List[Stage]]:
        """
        OmitStages is a list of stages for which no events are created. Note that this can also
        be specified policy wide in which case the union of both are omitted.
        An empty list means no restrictions will apply.
        """
        return self.__omit_stages


class Policy(base.TypedObject, base.NamespacedMetadataObject):
    """
    Policy defines the configuration of audit logging, and the rules for how different request
    categories are logged.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        rules: List["PolicyRule"] = None,
        omit_stages: List[Stage] = None,
    ):
        super().__init__(
            api_version="audit.k8s.io/v1",
            kind="Policy",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__rules = rules if rules is not None else []
        self.__omit_stages = omit_stages if omit_stages is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rules = self.rules()
        check_type("rules", rules, List["PolicyRule"])
        v["rules"] = rules
        omit_stages = self.omit_stages()
        check_type("omit_stages", omit_stages, Optional[List[Stage]])
        if omit_stages:  # omit empty
            v["omitStages"] = omit_stages
        return v

    def rules(self) -> List["PolicyRule"]:
        """
        Rules specify the audit Level a request should be recorded at.
        A request may match multiple rules, in which case the FIRST matching rule is used.
        The default audit level is None, but can be overridden by a catch-all rule at the end of the list.
        PolicyRules are strictly ordered.
        """
        return self.__rules

    def omit_stages(self) -> Optional[List[Stage]]:
        """
        OmitStages is a list of stages for which no events are created. Note that this can also
        be specified per rule in which case the union of both are omitted.
        """
        return self.__omit_stages
