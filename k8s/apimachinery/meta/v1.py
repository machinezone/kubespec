# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from kargo import context
from kargo import types
from typeguard import typechecked


# CauseType is a machine readable value providing more detail about what
# occurred in a status response. An operation may have multiple causes for a
# status (whether Failure or Success).
CauseType = base.Enum(
    "CauseType",
    {
        # FieldManagerConflict is used to report when another client claims to manage this field,
        # It should only be returned for a request using server-side apply.
        "FieldManagerConflict": "FieldManagerConflict",
        # FieldValueDuplicate is used to report collisions of values that must be
        # unique (e.g. unique IDs).
        "FieldValueDuplicate": "FieldValueDuplicate",
        # FieldValueInvalid is used to report malformed values (e.g. failed regex
        # match).
        "FieldValueInvalid": "FieldValueInvalid",
        # FieldValueNotFound is used to report failure to find a requested value
        # (e.g. looking up an ID).
        "FieldValueNotFound": "FieldValueNotFound",
        # FieldValueNotSupported is used to report valid (as per formatting rules)
        # values that can not be handled (e.g. an enumerated string).
        "FieldValueNotSupported": "FieldValueNotSupported",
        # FieldValueRequired is used to report required values that are not
        # provided (e.g. empty strings, null values, or empty arrays).
        "FieldValueRequired": "FieldValueRequired",
        # UnexpectedServerResponse is used to report when the server responded to the client
        # without the expected return type. The presence of this cause indicates the error may be
        # due to an intervening proxy or the server software malfunctioning.
        "UnexpectedServerResponse": "UnexpectedServerResponse",
    },
)


# DeletionPropagation decides if a deletion will propagate to the dependents of
# the object, and how the garbage collector will handle the propagation.
DeletionPropagation = base.Enum(
    "DeletionPropagation",
    {
        # Deletes the object from the key-value store, the garbage collector will
        # delete the dependents in the background.
        "Background": "Background",
        # The object exists in the key-value store until the garbage collector
        # deletes all the dependents whose ownerReference.blockOwnerDeletion=true
        # from the key-value store.  API sever will put the "foregroundDeletion"
        # finalizer on the object, and sets its deletionTimestamp.  This policy is
        # cascading, i.e., the dependents will be deleted with Foreground.
        "Foreground": "Foreground",
        # Orphans the dependents.
        "Orphan": "Orphan",
    },
)


# A label selector operator is the set of operators that can be used in a selector requirement.
LabelSelectorOperator = base.Enum(
    "LabelSelectorOperator",
    {"DoesNotExist": "DoesNotExist", "Exists": "Exists", "In": "In", "NotIn": "NotIn"},
)


# StatusReason is an enumeration of possible failure causes.  Each StatusReason
# must map to a single HTTP status code, but multiple reasons may map
# to the same HTTP status code.
# TODO: move to apiserver
StatusReason = base.Enum(
    "StatusReason",
    {
        # AlreadyExists means the resource you are creating already exists.
        # Details (optional):
        #   "kind" string - the kind attribute of the conflicting resource
        #   "id"   string - the identifier of the conflicting resource
        # Status code 409
        "AlreadyExists": "AlreadyExists",
        # BadRequest means that the request itself was invalid, because the request
        # doesn't make any sense, for example deleting a read-only object.  This is different than
        # StatusReasonInvalid above which indicates that the API call could possibly succeed, but the
        # data was invalid.  API calls that return BadRequest can never succeed.
        # Status code 400
        "BadRequest": "BadRequest",
        # Conflict means the requested operation cannot be completed
        # due to a conflict in the operation. The client may need to alter the
        # request. Each resource may define custom details that indicate the
        # nature of the conflict.
        # Status code 409
        "Conflict": "Conflict",
        # Expired indicates that the request is invalid because the content you are requesting
        # has expired and is no longer available. It is typically associated with watches that can't be
        # serviced.
        # Status code 410 (gone)
        "Expired": "Expired",
        # Forbidden means the server can be reached and understood the request, but refuses
        # to take any further action.  It is the result of the server being configured to deny access for some reason
        # to the requested resource by the client.
        # Details (optional):
        #   "kind" string - the kind attribute of the forbidden resource
        #                   on some operations may differ from the requested
        #                   resource.
        #   "id"   string - the identifier of the forbidden resource
        # Status code 403
        "Forbidden": "Forbidden",
        # Gone means the item is no longer available at the server and no
        # forwarding address is known.
        # Status code 410
        "Gone": "Gone",
        # InternalError indicates that an internal error occurred, it is unexpected
        # and the outcome of the call is unknown.
        # Details (optional):
        #   "causes" - The original error
        # Status code 500
        "InternalError": "InternalError",
        # Invalid means the requested create or update operation cannot be
        # completed due to invalid data provided as part of the request. The client may
        # need to alter the request. When set, the client may use the StatusDetails
        # message field as a summary of the issues encountered.
        # Details (optional):
        #   "kind" string - the kind attribute of the invalid resource
        #   "id"   string - the identifier of the invalid resource
        #   "causes"      - one or more StatusCause entries indicating the data in the
        #                   provided resource that was invalid.  The code, message, and
        #                   field attributes will be set.
        # Status code 422
        "Invalid": "Invalid",
        # MethodNotAllowed means that the action the client attempted to perform on the
        # resource was not supported by the code - for instance, attempting to delete a resource that
        # can only be created. API calls that return MethodNotAllowed can never succeed.
        # Status code 405
        "MethodNotAllowed": "MethodNotAllowed",
        # NotAcceptable means that the accept types indicated by the client were not acceptable
        # to the server - for instance, attempting to receive protobuf for a resource that supports only json and yaml.
        # API calls that return NotAcceptable can never succeed.
        # Status code 406
        "NotAcceptable": "NotAcceptable",
        # NotFound means one or more resources required for this operation
        # could not be found.
        # Details (optional):
        #   "kind" string - the kind attribute of the missing resource
        #                   on some operations may differ from the requested
        #                   resource.
        #   "id"   string - the identifier of the missing resource
        # Status code 404
        "NotFound": "NotFound",
        # RequestEntityTooLarge means that the request entity is too large.
        # Status code 413
        "RequestEntityTooLarge": "RequestEntityTooLarge",
        # ServerTimeout means the server can be reached and understood the request,
        # but cannot complete the action in a reasonable time. The client should retry the request.
        # This is may be due to temporary server load or a transient communication issue with
        # another server. Status code 500 is used because the HTTP spec provides no suitable
        # server-requested client retry and the 5xx class represents actionable errors.
        # Details (optional):
        #   "kind" string - the kind attribute of the resource being acted on.
        #   "id"   string - the operation that is being attempted.
        #   "retryAfterSeconds" int32 - the number of seconds before the operation should be retried
        # Status code 500
        "ServerTimeout": "ServerTimeout",
        # ServiceUnavailable means that the request itself was valid,
        # but the requested service is unavailable at this time.
        # Retrying the request after some time might succeed.
        # Status code 503
        "ServiceUnavailable": "ServiceUnavailable",
        # Timeout means that the request could not be completed within the given time.
        # Clients can get this response only when they specified a timeout param in the request,
        # or if the server cannot complete the operation within a reasonable amount of time.
        # The request might succeed with an increased value of timeout param. The client *should*
        # wait at least the number of seconds specified by the retryAfterSeconds field.
        # Details (optional):
        #   "retryAfterSeconds" int32 - the number of seconds before the operation should be retried
        # Status code 504
        "Timeout": "Timeout",
        # TooManyRequests means the server experienced too many requests within a
        # given window and that the client must wait to perform the action again. A client may
        # always retry the request that led to this error, although the client should wait at least
        # the number of seconds specified by the retryAfterSeconds field.
        # Details (optional):
        #   "retryAfterSeconds" int32 - the number of seconds before the operation should be retried
        # Status code 429
        "TooManyRequests": "TooManyRequests",
        # Unauthorized means the server can be reached and understood the request, but requires
        # the user to present appropriate authorization credentials (identified by the WWW-Authenticate header)
        # in order for the action to be completed. If the user has specified credentials on the request, the
        # server considers them insufficient.
        # Status code 401
        "Unauthorized": "Unauthorized",
        # Unknown means the server has declined to indicate a specific reason.
        # The details field may contain other information about this error.
        # Status code 500.
        "Unknown": "",
        # UnsupportedMediaType means that the content type sent by the client is not acceptable
        # to the server - for instance, attempting to send protobuf for a resource that supports only json and yaml.
        # API calls that return UnsupportedMediaType can never succeed.
        # Status code 415
        "UnsupportedMediaType": "UnsupportedMediaType",
    },
)


# Preconditions must be fulfilled before an operation (update, delete, etc.) is carried out.
class Preconditions(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, uid: str = None, resourceVersion: str = None):
        super().__init__(**{})
        self.__uid = uid
        self.__resourceVersion = resourceVersion

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uid = self.uid()
        if uid is not None:  # omit empty
            v["uid"] = uid
        resourceVersion = self.resourceVersion()
        if resourceVersion is not None:  # omit empty
            v["resourceVersion"] = resourceVersion
        return v

    # Specifies the target UID.
    @typechecked
    def uid(self) -> Optional[str]:
        return self.__uid

    # Specifies the target ResourceVersion
    @typechecked
    def resourceVersion(self) -> Optional[str]:
        return self.__resourceVersion


# TypeMeta describes an individual object in an API response or request
# with strings representing the type of the object and its API schema version.
# Structures that are versioned or persisted should inline TypeMeta.
class TypeMeta(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, kind: str = None, apiVersion: str = None):
        super().__init__(**{})
        self.__kind = kind
        self.__apiVersion = apiVersion

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        if kind:  # omit empty
            v["kind"] = kind
        apiVersion = self.apiVersion()
        if apiVersion:  # omit empty
            v["apiVersion"] = apiVersion
        return v

    # Kind is a string value representing the REST resource this object represents.
    # Servers may infer this from the endpoint the client submits requests to.
    # Cannot be updated.
    # In CamelCase.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    @typechecked
    def kind(self) -> Optional[str]:
        return self.__kind

    # APIVersion defines the versioned schema of this representation of an object.
    # Servers should convert recognized schemas to the latest internal value, and
    # may reject unrecognized values.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources
    @typechecked
    def apiVersion(self) -> Optional[str]:
        return self.__apiVersion


# DeleteOptions may be provided when deleting an API object.
class DeleteOptions(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        gracePeriodSeconds: int = None,
        preconditions: Preconditions = None,
        propagationPolicy: DeletionPropagation = None,
        dryRun: List[str] = None,
    ):
        super().__init__(**{})
        self.__gracePeriodSeconds = gracePeriodSeconds
        self.__preconditions = preconditions
        self.__propagationPolicy = propagationPolicy
        self.__dryRun = dryRun if dryRun is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        gracePeriodSeconds = self.gracePeriodSeconds()
        if gracePeriodSeconds is not None:  # omit empty
            v["gracePeriodSeconds"] = gracePeriodSeconds
        preconditions = self.preconditions()
        if preconditions is not None:  # omit empty
            v["preconditions"] = preconditions
        propagationPolicy = self.propagationPolicy()
        if propagationPolicy is not None:  # omit empty
            v["propagationPolicy"] = propagationPolicy
        dryRun = self.dryRun()
        if dryRun:  # omit empty
            v["dryRun"] = dryRun
        return v

    # The duration in seconds before the object should be deleted. Value must be non-negative integer.
    # The value zero indicates delete immediately. If this value is nil, the default grace period for the
    # specified type will be used.
    # Defaults to a per object value if not specified. zero means delete immediately.
    @typechecked
    def gracePeriodSeconds(self) -> Optional[int]:
        return self.__gracePeriodSeconds

    # Must be fulfilled before a deletion is carried out. If not possible, a 409 Conflict status will be
    # returned.
    @typechecked
    def preconditions(self) -> Optional[Preconditions]:
        return self.__preconditions

    # Whether and how garbage collection will be performed.
    # Either this field or OrphanDependents may be set, but not both.
    # The default policy is decided by the existing finalizer set in the
    # metadata.finalizers and the resource-specific default policy.
    # Acceptable values are: 'Orphan' - orphan the dependents; 'Background' -
    # allow the garbage collector to delete the dependents in the background;
    # 'Foreground' - a cascading policy that deletes all dependents in the
    # foreground.
    @typechecked
    def propagationPolicy(self) -> Optional[DeletionPropagation]:
        return self.__propagationPolicy

    # When present, indicates that modifications should not be
    # persisted. An invalid or unrecognized dryRun directive will
    # result in an error response and no further processing of the
    # request. Valid values are:
    # - All: all dry run stages will be processed
    @typechecked
    def dryRun(self) -> Optional[List[str]]:
        return self.__dryRun


# GroupVersionKind unambiguously identifies a kind.  It doesn't anonymously include GroupVersion
# to avoid automatic coersion.  It doesn't use a GroupVersion to avoid custom marshalling
class GroupVersionKind(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, group: str = "", version: str = "", kind: str = ""):
        super().__init__(**{})
        self.__group = group
        self.__version = version
        self.__kind = kind

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["group"] = self.group()
        v["version"] = self.version()
        v["kind"] = self.kind()
        return v

    @typechecked
    def group(self) -> str:
        return self.__group

    @typechecked
    def version(self) -> str:
        return self.__version

    @typechecked
    def kind(self) -> str:
        return self.__kind


# GroupVersionResource unambiguously identifies a resource.  It doesn't anonymously include GroupVersion
# to avoid automatic coersion.  It doesn't use a GroupVersion to avoid custom marshalling
class GroupVersionResource(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, group: str = "", version: str = "", resource: str = ""):
        super().__init__(**{})
        self.__group = group
        self.__version = version
        self.__resource = resource

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["group"] = self.group()
        v["version"] = self.version()
        v["resource"] = self.resource()
        return v

    @typechecked
    def group(self) -> str:
        return self.__group

    @typechecked
    def version(self) -> str:
        return self.__version

    @typechecked
    def resource(self) -> str:
        return self.__resource


# A label selector requirement is a selector that contains values, a key, and an operator that
# relates the key and values.
class LabelSelectorRequirement(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        key: str = "",
        operator: LabelSelectorOperator = None,
        values: List[str] = None,
    ):
        super().__init__(**{})
        self.__key = key
        self.__operator = operator
        self.__values = values if values is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["key"] = self.key()
        v["operator"] = self.operator()
        values = self.values()
        if values:  # omit empty
            v["values"] = values
        return v

    # key is the label key that the selector applies to.
    @typechecked
    def key(self) -> str:
        return self.__key

    # operator represents a key's relationship to a set of values.
    # Valid operators are In, NotIn, Exists and DoesNotExist.
    @typechecked
    def operator(self) -> LabelSelectorOperator:
        return self.__operator

    # values is an array of string values. If the operator is In or NotIn,
    # the values array must be non-empty. If the operator is Exists or DoesNotExist,
    # the values array must be empty. This array is replaced during a strategic
    # merge patch.
    @typechecked
    def values(self) -> Optional[List[str]]:
        return self.__values


# A label selector is a label query over a set of resources. The result of matchLabels and
# matchExpressions are ANDed. An empty label selector matches all objects. A null
# label selector matches no objects.
class LabelSelector(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        matchLabels: Dict[str, str] = None,
        matchExpressions: List[LabelSelectorRequirement] = None,
    ):
        super().__init__(**{})
        self.__matchLabels = matchLabels if matchLabels is not None else {}
        self.__matchExpressions = (
            matchExpressions if matchExpressions is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        matchLabels = self.matchLabels()
        if matchLabels:  # omit empty
            v["matchLabels"] = matchLabels
        matchExpressions = self.matchExpressions()
        if matchExpressions:  # omit empty
            v["matchExpressions"] = matchExpressions
        return v

    # matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels
    # map is equivalent to an element of matchExpressions, whose key field is "key", the
    # operator is "In", and the values array contains only "value". The requirements are ANDed.
    @typechecked
    def matchLabels(self) -> Optional[Dict[str, str]]:
        return self.__matchLabels

    # matchExpressions is a list of label selector requirements. The requirements are ANDed.
    @typechecked
    def matchExpressions(self) -> Optional[List[LabelSelectorRequirement]]:
        return self.__matchExpressions


# ListMeta describes metadata that synthetic resources must have, including lists and
# various status objects. A resource may have only one of {ObjectMeta, ListMeta}.
class ListMeta(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, continue_: str = None, remainingItemCount: int = None):
        super().__init__(**{})
        self.__continue_ = continue_
        self.__remainingItemCount = remainingItemCount

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        continue_ = self.continue_()
        if continue_:  # omit empty
            v["continue"] = continue_
        remainingItemCount = self.remainingItemCount()
        if remainingItemCount is not None:  # omit empty
            v["remainingItemCount"] = remainingItemCount
        return v

    # continue may be set if the user set a limit on the number of items returned, and indicates that
    # the server has more data available. The value is opaque and may be used to issue another request
    # to the endpoint that served this list to retrieve the next set of available objects. Continuing a
    # consistent list may not be possible if the server configuration has changed or more than a few
    # minutes have passed. The resourceVersion field returned when using this continue value will be
    # identical to the value in the first response, unless you have received this token from an error
    # message.
    @typechecked
    def continue_(self) -> Optional[str]:
        return self.__continue_

    # remainingItemCount is the number of subsequent items in the list which are not included in this
    # list response. If the list request contained label or field selectors, then the number of
    # remaining items is unknown and the field will be left unset and omitted during serialization.
    # If the list is complete (either because it is not chunking or because this is the last chunk),
    # then there are no more remaining items and this field will be left unset and omitted during
    # serialization.
    # Servers older than v1.15 do not set this field.
    # The intended use of the remainingItemCount is *estimating* the size of a collection. Clients
    # should not rely on the remainingItemCount to be set or to be exact.
    @typechecked
    def remainingItemCount(self) -> Optional[int]:
        return self.__remainingItemCount


# ObjectMeta is metadata that all persisted resources must have, which includes all objects
# users must create.
class ObjectMeta(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        namespace: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
    ):
        super().__init__(**{})
        self.__name = name
        self.__namespace = namespace
        self.__labels = labels if labels is not None else {}
        self.__annotations = annotations if annotations is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        namespace = self.namespace()
        if namespace:  # omit empty
            v["namespace"] = namespace
        labels = self.labels()
        if labels:  # omit empty
            v["labels"] = labels
        annotations = self.annotations()
        if annotations:  # omit empty
            v["annotations"] = annotations
        return v

    # Name must be unique within a namespace. Is required when creating resources, although
    # some resources may allow a client to request the generation of an appropriate name
    # automatically. Name is primarily intended for creation idempotence and configuration
    # definition.
    # Cannot be updated.
    # More info: http://kubernetes.io/docs/user-guide/identifiers#names
    @typechecked
    def name(self) -> Optional[str]:
        return self.__name

    # Namespace defines the space within each name must be unique. An empty namespace is
    # equivalent to the "default" namespace, but "default" is the canonical representation.
    # Not all objects are required to be scoped to a namespace - the value of this field for
    # those objects will be empty.
    #
    # Must be a DNS_LABEL.
    # Cannot be updated.
    # More info: http://kubernetes.io/docs/user-guide/namespaces
    @typechecked
    def namespace(self) -> Optional[str]:
        return self.__namespace

    # Map of string keys and values that can be used to organize and categorize
    # (scope and select) objects. May match selectors of replication controllers
    # and services.
    # More info: http://kubernetes.io/docs/user-guide/labels
    @typechecked
    def labels(self) -> Optional[Dict[str, str]]:
        return self.__labels

    # Annotations is an unstructured key value map stored with a resource that may be
    # set by external tools to store and retrieve arbitrary metadata. They are not
    # queryable and should be preserved when modifying objects.
    # More info: http://kubernetes.io/docs/user-guide/annotations
    @typechecked
    def annotations(self) -> Optional[Dict[str, str]]:
        return self.__annotations


# StatusCause provides more information about an api.Status failure, including
# cases when multiple errors are encountered.
class StatusCause(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, reason: CauseType = None, message: str = None, field: str = None
    ):
        super().__init__(**{})
        self.__reason = reason
        self.__message = message
        self.__field = field

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        reason = self.reason()
        if reason:  # omit empty
            v["reason"] = reason
        message = self.message()
        if message:  # omit empty
            v["message"] = message
        field = self.field()
        if field:  # omit empty
            v["field"] = field
        return v

    # A machine-readable description of the cause of the error. If this value is
    # empty there is no information available.
    @typechecked
    def reason(self) -> Optional[CauseType]:
        return self.__reason

    # A human-readable description of the cause of the error.  This field may be
    # presented as-is to a reader.
    @typechecked
    def message(self) -> Optional[str]:
        return self.__message

    # The field of the resource that has caused this error, as named by its JSON
    # serialization. May include dot and postfix notation for nested attributes.
    # Arrays are zero-indexed.  Fields may appear more than once in an array of
    # causes due to fields having multiple errors.
    # Optional.
    #
    # Examples:
    #   "name" - the field "name" on the current resource
    #   "items[0].name" - the field "name" on the first array entry in "items"
    @typechecked
    def field(self) -> Optional[str]:
        return self.__field


# StatusDetails is a set of additional properties that MAY be set by the
# server to provide additional information about a response. The Reason
# field of a Status object defines what attributes will be set. Clients
# must ignore fields that do not match the defined type of each attribute,
# and should assume that any attribute may be empty, invalid, or under
# defined.
class StatusDetails(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        group: str = None,
        kind: str = None,
        uid: str = None,
        causes: List[StatusCause] = None,
        retryAfterSeconds: int = None,
    ):
        super().__init__(**{})
        self.__name = name
        self.__group = group
        self.__kind = kind
        self.__uid = uid
        self.__causes = causes if causes is not None else []
        self.__retryAfterSeconds = retryAfterSeconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        group = self.group()
        if group:  # omit empty
            v["group"] = group
        kind = self.kind()
        if kind:  # omit empty
            v["kind"] = kind
        uid = self.uid()
        if uid:  # omit empty
            v["uid"] = uid
        causes = self.causes()
        if causes:  # omit empty
            v["causes"] = causes
        retryAfterSeconds = self.retryAfterSeconds()
        if retryAfterSeconds:  # omit empty
            v["retryAfterSeconds"] = retryAfterSeconds
        return v

    # The name attribute of the resource associated with the status StatusReason
    # (when there is a single name which can be described).
    @typechecked
    def name(self) -> Optional[str]:
        return self.__name

    # The group attribute of the resource associated with the status StatusReason.
    @typechecked
    def group(self) -> Optional[str]:
        return self.__group

    # The kind attribute of the resource associated with the status StatusReason.
    # On some operations may differ from the requested resource Kind.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    @typechecked
    def kind(self) -> Optional[str]:
        return self.__kind

    # UID of the resource.
    # (when there is a single resource which can be described).
    # More info: http://kubernetes.io/docs/user-guide/identifiers#uids
    @typechecked
    def uid(self) -> Optional[str]:
        return self.__uid

    # The Causes array includes more details associated with the StatusReason
    # failure. Not all StatusReasons may provide detailed causes.
    @typechecked
    def causes(self) -> Optional[List[StatusCause]]:
        return self.__causes

    # If specified, the time in seconds before the operation should be retried. Some errors may indicate
    # the client must take an alternate action - for those errors this field may indicate how long to wait
    # before taking the alternate action.
    @typechecked
    def retryAfterSeconds(self) -> Optional[int]:
        return self.__retryAfterSeconds


# Status is a return value for calls that don't return other objects.
class Status(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        metadata: ListMeta = None,
        status: str = None,
        message: str = None,
        reason: StatusReason = None,
        details: StatusDetails = None,
        code: int = None,
    ):
        super().__init__(**{})
        self.__metadata = metadata if metadata is not None else ListMeta()
        self.__status = status
        self.__message = message
        self.__reason = reason
        self.__details = details
        self.__code = code

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["metadata"] = self.metadata()
        status = self.status()
        if status:  # omit empty
            v["status"] = status
        message = self.message()
        if message:  # omit empty
            v["message"] = message
        reason = self.reason()
        if reason:  # omit empty
            v["reason"] = reason
        details = self.details()
        if details is not None:  # omit empty
            v["details"] = details
        code = self.code()
        if code:  # omit empty
            v["code"] = code
        return v

    # Standard list metadata.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    @typechecked
    def metadata(self) -> Optional[ListMeta]:
        return self.__metadata

    # Status of the operation.
    # One of: "Success" or "Failure".
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def status(self) -> Optional[str]:
        return self.__status

    # A human-readable description of the status of this operation.
    @typechecked
    def message(self) -> Optional[str]:
        return self.__message

    # A machine-readable description of why this operation is in the
    # "Failure" status. If this value is empty there
    # is no information available. A Reason clarifies an HTTP status
    # code but does not override it.
    @typechecked
    def reason(self) -> Optional[StatusReason]:
        return self.__reason

    # Extended data associated with the reason.  Each reason may define its
    # own extended details. This field is optional and the data returned
    # is not guaranteed to conform to any schema except that defined by
    # the reason type.
    @typechecked
    def details(self) -> Optional[StatusDetails]:
        return self.__details

    # Suggested HTTP return code for this status, 0 if not set.
    @typechecked
    def code(self) -> Optional[int]:
        return self.__code
