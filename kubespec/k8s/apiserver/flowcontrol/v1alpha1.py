# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


# FlowDistinguisherMethodType is the type of flow distinguisher method
FlowDistinguisherMethodType = base.Enum(
    "FlowDistinguisherMethodType",
    {
        # ByNamespace specifies that the flow distinguisher is the namespace of the
        # object that the request acts upon. If the object is not namespaced, or if the request is a non-resource
        # request, then the distinguisher will be the empty string. An example usage of this type is to provide
        # some insulation between tenants in a situation where there are multiple tenants and each namespace
        # is dedicated to a tenant.
        "ByNamespace": "ByNamespace",
        # ByUser specifies that the flow distinguisher is the username in the request.
        # This type is used to provide some insulation between users.
        "ByUser": "ByUser",
    },
)


# LimitResponseType identifies how a Limited priority level handles a request that can not be executed right now
LimitResponseType = base.Enum(
    "LimitResponseType",
    {
        # Queue means that requests that can not be executed right now are queued until they can be executed or a queuing limit is hit
        "Queue": "Queue",
        # Reject means that requests that can not be executed right now are rejected
        "Reject": "Reject",
    },
)


# PriorityLevelEnablement indicates whether limits on execution are enabled for the priority level
PriorityLevelEnablement = base.Enum(
    "PriorityLevelEnablement",
    {
        # Exempt means that requests are not subject to limits
        "Exempt": "Exempt",
        # Limited means that requests are subject to limits
        "Limited": "Limited",
    },
)


# SubjectKind is the kind of subject.
SubjectKind = base.Enum(
    "SubjectKind",
    {
        # Supported subject's kinds.
        "Group": "Group",
        # Supported subject's kinds.
        "ServiceAccount": "ServiceAccount",
        # Supported subject's kinds.
        "User": "User",
    },
)


class FlowDistinguisherMethod(types.Object):
    """
    FlowDistinguisherMethod specifies the method of a flow distinguisher.
    """

    @context.scoped
    @typechecked
    def __init__(self, type: FlowDistinguisherMethodType = None):
        super().__init__()
        self.__type = type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, FlowDistinguisherMethodType)
        v["type"] = type
        return v

    def type(self) -> FlowDistinguisherMethodType:
        """
        `type` is the type of flow distinguisher method
        The supported types are "ByUser" and "ByNamespace".
        Required.
        """
        return self.__type


class NonResourcePolicyRule(types.Object):
    """
    NonResourcePolicyRule is a predicate that matches non-resource requests according to their verb and the
    target non-resource URL. A NonResourcePolicyRule matches a request if and only if both (a) at least one member
    of verbs matches the request and (b) at least one member of nonResourceURLs matches the request.
    """

    @context.scoped
    @typechecked
    def __init__(self, verbs: List[str] = None, nonResourceURLs: List[str] = None):
        super().__init__()
        self.__verbs = verbs if verbs is not None else []
        self.__nonResourceURLs = nonResourceURLs if nonResourceURLs is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        verbs = self.verbs()
        check_type("verbs", verbs, List[str])
        v["verbs"] = verbs
        nonResourceURLs = self.nonResourceURLs()
        check_type("nonResourceURLs", nonResourceURLs, List[str])
        v["nonResourceURLs"] = nonResourceURLs
        return v

    def verbs(self) -> List[str]:
        """
        `verbs` is a list of matching verbs and may not be empty.
        "*" matches all verbs. If it is present, it must be the only entry.
        +listType=set
        Required.
        """
        return self.__verbs

    def nonResourceURLs(self) -> List[str]:
        """
        `nonResourceURLs` is a set of url prefixes that a user should have access to and may not be empty.
        For example:
          - "/healthz" is legal
          - "/hea*" is illegal
          - "/hea" is legal but matches nothing
          - "/hea/*" also matches nothing
          - "/healthz/*" matches all per-component health checks.
        "*" matches all non-resource urls. if it is present, it must be the only entry.
        +listType=set
        Required.
        """
        return self.__nonResourceURLs


class ResourcePolicyRule(types.Object):
    """
    ResourcePolicyRule is a predicate that matches some resource
    requests, testing the request's verb and the target resource. A
    ResourcePolicyRule matches a resource request if and only if: (a)
    at least one member of verbs matches the request, (b) at least one
    member of apiGroups matches the request, (c) at least one member of
    resources matches the request, and (d) least one member of
    namespaces matches the request.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        verbs: List[str] = None,
        apiGroups: List[str] = None,
        resources: List[str] = None,
        clusterScope: bool = None,
        namespaces: List[str] = None,
    ):
        super().__init__()
        self.__verbs = verbs if verbs is not None else []
        self.__apiGroups = apiGroups if apiGroups is not None else []
        self.__resources = resources if resources is not None else []
        self.__clusterScope = clusterScope
        self.__namespaces = namespaces if namespaces is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        verbs = self.verbs()
        check_type("verbs", verbs, List[str])
        v["verbs"] = verbs
        apiGroups = self.apiGroups()
        check_type("apiGroups", apiGroups, List[str])
        v["apiGroups"] = apiGroups
        resources = self.resources()
        check_type("resources", resources, List[str])
        v["resources"] = resources
        clusterScope = self.clusterScope()
        check_type("clusterScope", clusterScope, Optional[bool])
        if clusterScope:  # omit empty
            v["clusterScope"] = clusterScope
        namespaces = self.namespaces()
        check_type("namespaces", namespaces, List[str])
        v["namespaces"] = namespaces
        return v

    def verbs(self) -> List[str]:
        """
        `verbs` is a list of matching verbs and may not be empty.
        "*" matches all verbs and, if present, must be the only entry.
        +listType=set
        Required.
        """
        return self.__verbs

    def apiGroups(self) -> List[str]:
        """
        `apiGroups` is a list of matching API groups and may not be empty.
        "*" matches all API groups and, if present, must be the only entry.
        +listType=set
        Required.
        """
        return self.__apiGroups

    def resources(self) -> List[str]:
        """
        `resources` is a list of matching resources (i.e., lowercase
        and plural) with, if desired, subresource.  For example, [
        "services", "nodes/status" ].  This list may not be empty.
        "*" matches all resources and, if present, must be the only entry.
        Required.
        +listType=set
        """
        return self.__resources

    def clusterScope(self) -> Optional[bool]:
        """
        `clusterScope` indicates whether to match requests that do not
        specify a namespace (which happens either because the resource
        is not namespaced or the request targets all namespaces).
        If this field is omitted or false then the `namespaces` field
        must contain a non-empty list.
        """
        return self.__clusterScope

    def namespaces(self) -> List[str]:
        """
        `namespaces` is a list of target namespaces that restricts
        matches.  A request that specifies a target namespace matches
        only if either (a) this list contains that target namespace or
        (b) this list contains "*".  Note that "*" matches any
        specified namespace but does not match a request that _does
        not specify_ a namespace (see the `clusterScope` field for
        that).
        This list may be empty, but only if `clusterScope` is true.
        +listType=set
        """
        return self.__namespaces


class GroupSubject(types.Object):
    """
    GroupSubject holds detailed information for group-kind subject.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = ""):
        super().__init__()
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def name(self) -> str:
        """
        name is the user group that matches, or "*" to match all user groups.
        See https://github.com/kubernetes/apiserver/blob/master/pkg/authentication/user/user.go for some
        well-known group names.
        Required.
        """
        return self.__name


class ServiceAccountSubject(types.Object):
    """
    ServiceAccountSubject holds detailed information for service-account-kind subject.
    """

    @context.scoped
    @typechecked
    def __init__(self, namespace: str = "", name: str = ""):
        super().__init__()
        self.__namespace = namespace
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, str)
        v["namespace"] = namespace
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def namespace(self) -> str:
        """
        `namespace` is the namespace of matching ServiceAccount objects.
        Required.
        """
        return self.__namespace

    def name(self) -> str:
        """
        `name` is the name of matching ServiceAccount objects, or "*" to match regardless of name.
        Required.
        """
        return self.__name


class UserSubject(types.Object):
    """
    UserSubject holds detailed information for user-kind subject.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = ""):
        super().__init__()
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def name(self) -> str:
        """
        `name` is the username that matches, or "*" to match all usernames.
        Required.
        """
        return self.__name


class Subject(types.Object):
    """
    Subject matches the originator of a request, as identified by the request authentication system. There are three
    ways of matching an originator; by user, group, or service account.
    +union
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        kind: SubjectKind = None,
        user: "UserSubject" = None,
        group: "GroupSubject" = None,
        serviceAccount: "ServiceAccountSubject" = None,
    ):
        super().__init__()
        self.__kind = kind
        self.__user = user
        self.__group = group
        self.__serviceAccount = serviceAccount

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        check_type("kind", kind, SubjectKind)
        v["kind"] = kind
        user = self.user()
        check_type("user", user, Optional["UserSubject"])
        if user is not None:  # omit empty
            v["user"] = user
        group = self.group()
        check_type("group", group, Optional["GroupSubject"])
        if group is not None:  # omit empty
            v["group"] = group
        serviceAccount = self.serviceAccount()
        check_type("serviceAccount", serviceAccount, Optional["ServiceAccountSubject"])
        if serviceAccount is not None:  # omit empty
            v["serviceAccount"] = serviceAccount
        return v

    def kind(self) -> SubjectKind:
        """
        Required
        +unionDiscriminator
        """
        return self.__kind

    def user(self) -> Optional["UserSubject"]:
        return self.__user

    def group(self) -> Optional["GroupSubject"]:
        return self.__group

    def serviceAccount(self) -> Optional["ServiceAccountSubject"]:
        return self.__serviceAccount


class PolicyRulesWithSubjects(types.Object):
    """
    PolicyRulesWithSubjects prescribes a test that applies to a request to an apiserver. The test considers the subject
    making the request, the verb being requested, and the resource to be acted upon. This PolicyRulesWithSubjects matches
    a request if and only if both (a) at least one member of subjects matches the request and (b) at least one member
    of resourceRules or nonResourceRules matches the request.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        subjects: List["Subject"] = None,
        resourceRules: List["ResourcePolicyRule"] = None,
        nonResourceRules: List["NonResourcePolicyRule"] = None,
    ):
        super().__init__()
        self.__subjects = subjects if subjects is not None else []
        self.__resourceRules = resourceRules if resourceRules is not None else []
        self.__nonResourceRules = (
            nonResourceRules if nonResourceRules is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        subjects = self.subjects()
        check_type("subjects", subjects, List["Subject"])
        v["subjects"] = subjects
        resourceRules = self.resourceRules()
        check_type("resourceRules", resourceRules, Optional[List["ResourcePolicyRule"]])
        if resourceRules:  # omit empty
            v["resourceRules"] = resourceRules
        nonResourceRules = self.nonResourceRules()
        check_type(
            "nonResourceRules",
            nonResourceRules,
            Optional[List["NonResourcePolicyRule"]],
        )
        if nonResourceRules:  # omit empty
            v["nonResourceRules"] = nonResourceRules
        return v

    def subjects(self) -> List["Subject"]:
        """
        subjects is the list of normal user, serviceaccount, or group that this rule cares about.
        There must be at least one member in this slice.
        A slice that includes both the system:authenticated and system:unauthenticated user groups matches every request.
        +listType=set
        Required.
        """
        return self.__subjects

    def resourceRules(self) -> Optional[List["ResourcePolicyRule"]]:
        """
        `resourceRules` is a slice of ResourcePolicyRules that identify matching requests according to their verb and the
        target resource.
        At least one of `resourceRules` and `nonResourceRules` has to be non-empty.
        +listType=set
        """
        return self.__resourceRules

    def nonResourceRules(self) -> Optional[List["NonResourcePolicyRule"]]:
        """
        `nonResourceRules` is a list of NonResourcePolicyRules that identify matching requests according to their verb
        and the target non-resource URL.
        +listType=set
        """
        return self.__nonResourceRules


class PriorityLevelConfigurationReference(types.Object):
    """
    PriorityLevelConfigurationReference contains information that points to the "request-priority" being used.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = ""):
        super().__init__()
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def name(self) -> str:
        """
        `name` is the name of the priority level configuration being referenced
        Required.
        """
        return self.__name


class FlowSchemaSpec(types.Object):
    """
    FlowSchemaSpec describes how the FlowSchema's specification looks like.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        priorityLevelConfiguration: "PriorityLevelConfigurationReference" = None,
        matchingPrecedence: int = 1000,
        distinguisherMethod: "FlowDistinguisherMethod" = None,
        rules: List["PolicyRulesWithSubjects"] = None,
    ):
        super().__init__()
        self.__priorityLevelConfiguration = (
            priorityLevelConfiguration
            if priorityLevelConfiguration is not None
            else PriorityLevelConfigurationReference()
        )
        self.__matchingPrecedence = matchingPrecedence
        self.__distinguisherMethod = distinguisherMethod
        self.__rules = rules if rules is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        priorityLevelConfiguration = self.priorityLevelConfiguration()
        check_type(
            "priorityLevelConfiguration",
            priorityLevelConfiguration,
            "PriorityLevelConfigurationReference",
        )
        v["priorityLevelConfiguration"] = priorityLevelConfiguration
        matchingPrecedence = self.matchingPrecedence()
        check_type("matchingPrecedence", matchingPrecedence, int)
        v["matchingPrecedence"] = matchingPrecedence
        distinguisherMethod = self.distinguisherMethod()
        check_type(
            "distinguisherMethod",
            distinguisherMethod,
            Optional["FlowDistinguisherMethod"],
        )
        if distinguisherMethod is not None:  # omit empty
            v["distinguisherMethod"] = distinguisherMethod
        rules = self.rules()
        check_type("rules", rules, Optional[List["PolicyRulesWithSubjects"]])
        if rules:  # omit empty
            v["rules"] = rules
        return v

    def priorityLevelConfiguration(self) -> "PriorityLevelConfigurationReference":
        """
        `priorityLevelConfiguration` should reference a PriorityLevelConfiguration in the cluster. If the reference cannot
        be resolved, the FlowSchema will be ignored and marked as invalid in its status.
        Required.
        """
        return self.__priorityLevelConfiguration

    def matchingPrecedence(self) -> int:
        """
        `matchingPrecedence` is used to choose among the FlowSchemas that match a given request. The chosen
        FlowSchema is among those with the numerically lowest (which we take to be logically highest)
        MatchingPrecedence.  Each MatchingPrecedence value must be non-negative.
        Note that if the precedence is not specified or zero, it will be set to 1000 as default.
        """
        return self.__matchingPrecedence

    def distinguisherMethod(self) -> Optional["FlowDistinguisherMethod"]:
        """
        `distinguisherMethod` defines how to compute the flow distinguisher for requests that match this schema.
        `nil` specifies that the distinguisher is disabled and thus will always be the empty string.
        """
        return self.__distinguisherMethod

    def rules(self) -> Optional[List["PolicyRulesWithSubjects"]]:
        """
        `rules` describes which requests will match this flow schema. This FlowSchema matches a request if and only if
        at least one member of rules matches the request.
        if it is an empty slice, there will be no requests matching the FlowSchema.
        +listType=set
        """
        return self.__rules


class FlowSchema(base.TypedObject, base.MetadataObject):
    """
    FlowSchema defines the schema of a group of flows. Note that a flow is made up of a set of inbound API requests with
    similar attributes and is identified by a pair of strings: the name of the FlowSchema and a "flow distinguisher".
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "FlowSchemaSpec" = None,
    ):
        super().__init__(
            apiVersion="flowcontrol.apiserver.k8s.io/v1alpha1",
            kind="FlowSchema",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else FlowSchemaSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["FlowSchemaSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["FlowSchemaSpec"]:
        """
        `spec` is the specification of the desired behavior of a FlowSchema.
        More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#spec-and-status
        """
        return self.__spec


class QueuingConfiguration(types.Object):
    """
    QueuingConfiguration holds the configuration parameters for queuing
    """

    @context.scoped
    @typechecked
    def __init__(self, queues: int = 64, handSize: int = 8, queueLengthLimit: int = 50):
        super().__init__()
        self.__queues = queues
        self.__handSize = handSize
        self.__queueLengthLimit = queueLengthLimit

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        queues = self.queues()
        check_type("queues", queues, int)
        v["queues"] = queues
        handSize = self.handSize()
        check_type("handSize", handSize, int)
        v["handSize"] = handSize
        queueLengthLimit = self.queueLengthLimit()
        check_type("queueLengthLimit", queueLengthLimit, int)
        v["queueLengthLimit"] = queueLengthLimit
        return v

    def queues(self) -> int:
        """
        `queues` is the number of queues for this priority level. The
        queues exist independently at each apiserver. The value must be
        positive.  Setting it to 1 effectively precludes
        shufflesharding and thus makes the distinguisher method of
        associated flow schemas irrelevant.  This field has a default
        value of 64.
        """
        return self.__queues

    def handSize(self) -> int:
        """
        `handSize` is a small positive number that configures the
        shuffle sharding of requests into queues.  When enqueuing a request
        at this priority level the request's flow identifier (a string
        pair) is hashed and the hash value is used to shuffle the list
        of queues and deal a hand of the size specified here.  The
        request is put into one of the shortest queues in that hand.
        `handSize` must be no larger than `queues`, and should be
        significantly smaller (so that a few heavy flows do not
        saturate most of the queues).  See the user-facing
        documentation for more extensive guidance on setting this
        field.  This field has a default value of 8.
        """
        return self.__handSize

    def queueLengthLimit(self) -> int:
        """
        `queueLengthLimit` is the maximum number of requests allowed to
        be waiting in a given queue of this priority level at a time;
        excess requests are rejected.  This value must be positive.  If
        not specified, it will be defaulted to 50.
        """
        return self.__queueLengthLimit


class LimitResponse(types.Object):
    """
    LimitResponse defines how to handle requests that can not be executed right now.
    +union
    """

    @context.scoped
    @typechecked
    def __init__(
        self, type: LimitResponseType = None, queuing: "QueuingConfiguration" = None
    ):
        super().__init__()
        self.__type = type
        self.__queuing = queuing

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, LimitResponseType)
        v["type"] = type
        queuing = self.queuing()
        check_type("queuing", queuing, Optional["QueuingConfiguration"])
        if queuing is not None:  # omit empty
            v["queuing"] = queuing
        return v

    def type(self) -> LimitResponseType:
        """
        `type` is "Queue" or "Reject".
        "Queue" means that requests that can not be executed upon arrival
        are held in a queue until they can be executed or a queuing limit
        is reached.
        "Reject" means that requests that can not be executed upon arrival
        are rejected.
        Required.
        +unionDiscriminator
        """
        return self.__type

    def queuing(self) -> Optional["QueuingConfiguration"]:
        """
        `queuing` holds the configuration parameters for queuing.
        This field may be non-empty only if `type` is `"Queue"`.
        """
        return self.__queuing


class LimitedPriorityLevelConfiguration(types.Object):
    """
    LimitedPriorityLevelConfiguration specifies how to handle requests that are subject to limits.
    It addresses two issues:
     * How are requests for this priority level limited?
     * What should be done with requests that exceed the limit?
    """

    @context.scoped
    @typechecked
    def __init__(
        self, assuredConcurrencyShares: int = 30, limitResponse: "LimitResponse" = None
    ):
        super().__init__()
        self.__assuredConcurrencyShares = assuredConcurrencyShares
        self.__limitResponse = (
            limitResponse if limitResponse is not None else LimitResponse()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        assuredConcurrencyShares = self.assuredConcurrencyShares()
        check_type("assuredConcurrencyShares", assuredConcurrencyShares, int)
        v["assuredConcurrencyShares"] = assuredConcurrencyShares
        limitResponse = self.limitResponse()
        check_type("limitResponse", limitResponse, Optional["LimitResponse"])
        v["limitResponse"] = limitResponse
        return v

    def assuredConcurrencyShares(self) -> int:
        """
        `assuredConcurrencyShares` (ACS) configures the execution
        limit, which is a limit on the number of requests of this
        priority level that may be exeucting at a given time.  ACS must
        be a positive number. The server's concurrency limit (SCL) is
        divided among the concurrency-controlled priority levels in
        proportion to their assured concurrency shares. This produces
        the assured concurrency value (ACV) --- the number of requests
        that may be executing at a time --- for each such priority
        level:
        
                    ACV(l) = ceil( SCL * ACS(l) / ( sum[priority levels k] ACS(k) ) )
        
        bigger numbers of ACS mean more reserved concurrent requests (at the
        expense of every other PL).
        This field has a default value of 30.
        """
        return self.__assuredConcurrencyShares

    def limitResponse(self) -> Optional["LimitResponse"]:
        """
        `limitResponse` indicates what to do with requests that can not be executed right now
        """
        return self.__limitResponse


class PriorityLevelConfigurationSpec(types.Object):
    """
    PriorityLevelConfigurationSpec specifies the configuration of a priority level.
    +union
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: PriorityLevelEnablement = None,
        limited: "LimitedPriorityLevelConfiguration" = None,
    ):
        super().__init__()
        self.__type = type
        self.__limited = limited

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, PriorityLevelEnablement)
        v["type"] = type
        limited = self.limited()
        check_type("limited", limited, Optional["LimitedPriorityLevelConfiguration"])
        if limited is not None:  # omit empty
            v["limited"] = limited
        return v

    def type(self) -> PriorityLevelEnablement:
        """
        `type` indicates whether this priority level is subject to
        limitation on request execution.  A value of `"Exempt"` means
        that requests of this priority level are not subject to a limit
        (and thus are never queued) and do not detract from the
        capacity made available to other priority levels.  A value of
        `"Limited"` means that (a) requests of this priority level
        _are_ subject to limits and (b) some of the server's limited
        capacity is made available exclusively to this priority level.
        Required.
        +unionDiscriminator
        """
        return self.__type

    def limited(self) -> Optional["LimitedPriorityLevelConfiguration"]:
        """
        `limited` specifies how requests are handled for a Limited priority level.
        This field must be non-empty if and only if `type` is `"Limited"`.
        """
        return self.__limited


class PriorityLevelConfiguration(base.TypedObject, base.MetadataObject):
    """
    PriorityLevelConfiguration represents the configuration of a priority level.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PriorityLevelConfigurationSpec" = None,
    ):
        super().__init__(
            apiVersion="flowcontrol.apiserver.k8s.io/v1alpha1",
            kind="PriorityLevelConfiguration",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PriorityLevelConfigurationSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["PriorityLevelConfigurationSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["PriorityLevelConfigurationSpec"]:
        """
        `spec` is the specification of the desired behavior of a "request-priority".
        More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#spec-and-status
        """
        return self.__spec
