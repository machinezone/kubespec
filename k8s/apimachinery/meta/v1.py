# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


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
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "uid" in self._kwargs:
            return self._kwargs["uid"]
        if "uid" in self._context and check_return_type(self._context["uid"]):
            return self._context["uid"]
        return None

    # Specifies the target ResourceVersion
    @typechecked
    def resourceVersion(self) -> Optional[str]:
        if "resourceVersion" in self._kwargs:
            return self._kwargs["resourceVersion"]
        if "resourceVersion" in self._context and check_return_type(
            self._context["resourceVersion"]
        ):
            return self._context["resourceVersion"]
        return None


# TypeMeta describes an individual object in an API response or request
# with strings representing the type of the object and its API schema version.
# Structures that are versioned or persisted should inline TypeMeta.
class TypeMeta(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "kind" in self._kwargs:
            return self._kwargs["kind"]
        if "kind" in self._context and check_return_type(self._context["kind"]):
            return self._context["kind"]
        return None

    # APIVersion defines the versioned schema of this representation of an object.
    # Servers should convert recognized schemas to the latest internal value, and
    # may reject unrecognized values.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources
    @typechecked
    def apiVersion(self) -> Optional[str]:
        if "apiVersion" in self._kwargs:
            return self._kwargs["apiVersion"]
        if "apiVersion" in self._context and check_return_type(
            self._context["apiVersion"]
        ):
            return self._context["apiVersion"]
        return None


# DeleteOptions may be provided when deleting an API object.
class DeleteOptions(base.TypedObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "gracePeriodSeconds" in self._kwargs:
            return self._kwargs["gracePeriodSeconds"]
        if "gracePeriodSeconds" in self._context and check_return_type(
            self._context["gracePeriodSeconds"]
        ):
            return self._context["gracePeriodSeconds"]
        return None

    # Must be fulfilled before a deletion is carried out. If not possible, a 409 Conflict status will be
    # returned.
    @typechecked
    def preconditions(self) -> Optional[Preconditions]:
        if "preconditions" in self._kwargs:
            return self._kwargs["preconditions"]
        if "preconditions" in self._context and check_return_type(
            self._context["preconditions"]
        ):
            return self._context["preconditions"]
        return None

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
        if "propagationPolicy" in self._kwargs:
            return self._kwargs["propagationPolicy"]
        if "propagationPolicy" in self._context and check_return_type(
            self._context["propagationPolicy"]
        ):
            return self._context["propagationPolicy"]
        return None

    # When present, indicates that modifications should not be
    # persisted. An invalid or unrecognized dryRun directive will
    # result in an error response and no further processing of the
    # request. Valid values are:
    # - All: all dry run stages will be processed
    @typechecked
    def dryRun(self) -> List[str]:
        if "dryRun" in self._kwargs:
            return self._kwargs["dryRun"]
        if "dryRun" in self._context and check_return_type(self._context["dryRun"]):
            return self._context["dryRun"]
        return []


# Duration is a wrapper around time.Duration which supports correct
# marshaling to YAML and JSON. In particular, it marshals into strings, which
# can be used as map keys in json.
class Duration(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["Duration"] = self.duration()
        return v

    @typechecked
    def duration(self) -> int:
        if "Duration" in self._kwargs:
            return self._kwargs["Duration"]
        if "Duration" in self._context and check_return_type(self._context["Duration"]):
            return self._context["Duration"]
        return 0


# GroupVersionKind unambiguously identifies a kind.  It doesn't anonymously include GroupVersion
# to avoid automatic coersion.  It doesn't use a GroupVersion to avoid custom marshalling
class GroupVersionKind(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["group"] = self.group()
        v["version"] = self.version()
        v["kind"] = self.kind()
        return v

    @typechecked
    def group(self) -> str:
        if "group" in self._kwargs:
            return self._kwargs["group"]
        if "group" in self._context and check_return_type(self._context["group"]):
            return self._context["group"]
        return ""

    @typechecked
    def version(self) -> str:
        if "version" in self._kwargs:
            return self._kwargs["version"]
        if "version" in self._context and check_return_type(self._context["version"]):
            return self._context["version"]
        return ""

    @typechecked
    def kind(self) -> str:
        if "kind" in self._kwargs:
            return self._kwargs["kind"]
        if "kind" in self._context and check_return_type(self._context["kind"]):
            return self._context["kind"]
        return ""


# GroupVersionResource unambiguously identifies a resource.  It doesn't anonymously include GroupVersion
# to avoid automatic coersion.  It doesn't use a GroupVersion to avoid custom marshalling
class GroupVersionResource(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["group"] = self.group()
        v["version"] = self.version()
        v["resource"] = self.resource()
        return v

    @typechecked
    def group(self) -> str:
        if "group" in self._kwargs:
            return self._kwargs["group"]
        if "group" in self._context and check_return_type(self._context["group"]):
            return self._context["group"]
        return ""

    @typechecked
    def version(self) -> str:
        if "version" in self._kwargs:
            return self._kwargs["version"]
        if "version" in self._context and check_return_type(self._context["version"]):
            return self._context["version"]
        return ""

    @typechecked
    def resource(self) -> str:
        if "resource" in self._kwargs:
            return self._kwargs["resource"]
        if "resource" in self._context and check_return_type(self._context["resource"]):
            return self._context["resource"]
        return ""


# A label selector requirement is a selector that contains values, a key, and an operator that
# relates the key and values.
class LabelSelectorRequirement(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["key"] = self.key()
        v["operator"] = self.operator()
        values = self.values()
        if values:  # omit empty
            v["values"] = values
        return v

    # key is the label key that the selector applies to.
    @typechecked
    def key(self) -> str:
        if "key" in self._kwargs:
            return self._kwargs["key"]
        if "key" in self._context and check_return_type(self._context["key"]):
            return self._context["key"]
        return ""

    # operator represents a key's relationship to a set of values.
    # Valid operators are In, NotIn, Exists and DoesNotExist.
    @typechecked
    def operator(self) -> LabelSelectorOperator:
        if "operator" in self._kwargs:
            return self._kwargs["operator"]
        if "operator" in self._context and check_return_type(self._context["operator"]):
            return self._context["operator"]
        return None

    # values is an array of string values. If the operator is In or NotIn,
    # the values array must be non-empty. If the operator is Exists or DoesNotExist,
    # the values array must be empty. This array is replaced during a strategic
    # merge patch.
    @typechecked
    def values(self) -> List[str]:
        if "values" in self._kwargs:
            return self._kwargs["values"]
        if "values" in self._context and check_return_type(self._context["values"]):
            return self._context["values"]
        return []


# A label selector is a label query over a set of resources. The result of matchLabels and
# matchExpressions are ANDed. An empty label selector matches all objects. A null
# label selector matches no objects.
class LabelSelector(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
    def matchLabels(self) -> Dict[str, str]:
        if "matchLabels" in self._kwargs:
            return self._kwargs["matchLabels"]
        if "matchLabels" in self._context and check_return_type(
            self._context["matchLabels"]
        ):
            return self._context["matchLabels"]
        return {}

    # matchExpressions is a list of label selector requirements. The requirements are ANDed.
    @typechecked
    def matchExpressions(self) -> List[LabelSelectorRequirement]:
        if "matchExpressions" in self._kwargs:
            return self._kwargs["matchExpressions"]
        if "matchExpressions" in self._context and check_return_type(
            self._context["matchExpressions"]
        ):
            return self._context["matchExpressions"]
        return []


# ListMeta describes metadata that synthetic resources must have, including lists and
# various status objects. A resource may have only one of {ObjectMeta, ListMeta}.
class ListMeta(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "continue" in self._kwargs:
            return self._kwargs["continue"]
        if "continue" in self._context and check_return_type(self._context["continue"]):
            return self._context["continue"]
        return None

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
        if "remainingItemCount" in self._kwargs:
            return self._kwargs["remainingItemCount"]
        if "remainingItemCount" in self._context and check_return_type(
            self._context["remainingItemCount"]
        ):
            return self._context["remainingItemCount"]
        return None


# ObjectMeta is metadata that all persisted resources must have, which includes all objects
# users must create.
class ObjectMeta(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return None

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
        if "namespace" in self._kwargs:
            return self._kwargs["namespace"]
        if "namespace" in self._context and check_return_type(
            self._context["namespace"]
        ):
            return self._context["namespace"]
        return None

    # Map of string keys and values that can be used to organize and categorize
    # (scope and select) objects. May match selectors of replication controllers
    # and services.
    # More info: http://kubernetes.io/docs/user-guide/labels
    @typechecked
    def labels(self) -> Dict[str, str]:
        if "labels" in self._kwargs:
            return self._kwargs["labels"]
        if "labels" in self._context and check_return_type(self._context["labels"]):
            return self._context["labels"]
        return {}

    # Annotations is an unstructured key value map stored with a resource that may be
    # set by external tools to store and retrieve arbitrary metadata. They are not
    # queryable and should be preserved when modifying objects.
    # More info: http://kubernetes.io/docs/user-guide/annotations
    @typechecked
    def annotations(self) -> Dict[str, str]:
        if "annotations" in self._kwargs:
            return self._kwargs["annotations"]
        if "annotations" in self._context and check_return_type(
            self._context["annotations"]
        ):
            return self._context["annotations"]
        return {}


# StatusCause provides more information about an api.Status failure, including
# cases when multiple errors are encountered.
class StatusCause(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "reason" in self._kwargs:
            return self._kwargs["reason"]
        if "reason" in self._context and check_return_type(self._context["reason"]):
            return self._context["reason"]
        return None

    # A human-readable description of the cause of the error.  This field may be
    # presented as-is to a reader.
    @typechecked
    def message(self) -> Optional[str]:
        if "message" in self._kwargs:
            return self._kwargs["message"]
        if "message" in self._context and check_return_type(self._context["message"]):
            return self._context["message"]
        return None

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
        if "field" in self._kwargs:
            return self._kwargs["field"]
        if "field" in self._context and check_return_type(self._context["field"]):
            return self._context["field"]
        return None


# StatusDetails is a set of additional properties that MAY be set by the
# server to provide additional information about a response. The Reason
# field of a Status object defines what attributes will be set. Clients
# must ignore fields that do not match the defined type of each attribute,
# and should assume that any attribute may be empty, invalid, or under
# defined.
class StatusDetails(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return None

    # The group attribute of the resource associated with the status StatusReason.
    @typechecked
    def group(self) -> Optional[str]:
        if "group" in self._kwargs:
            return self._kwargs["group"]
        if "group" in self._context and check_return_type(self._context["group"]):
            return self._context["group"]
        return None

    # The kind attribute of the resource associated with the status StatusReason.
    # On some operations may differ from the requested resource Kind.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    @typechecked
    def kind(self) -> Optional[str]:
        if "kind" in self._kwargs:
            return self._kwargs["kind"]
        if "kind" in self._context and check_return_type(self._context["kind"]):
            return self._context["kind"]
        return None

    # UID of the resource.
    # (when there is a single resource which can be described).
    # More info: http://kubernetes.io/docs/user-guide/identifiers#uids
    @typechecked
    def uid(self) -> Optional[str]:
        if "uid" in self._kwargs:
            return self._kwargs["uid"]
        if "uid" in self._context and check_return_type(self._context["uid"]):
            return self._context["uid"]
        return None

    # The Causes array includes more details associated with the StatusReason
    # failure. Not all StatusReasons may provide detailed causes.
    @typechecked
    def causes(self) -> List[StatusCause]:
        if "causes" in self._kwargs:
            return self._kwargs["causes"]
        if "causes" in self._context and check_return_type(self._context["causes"]):
            return self._context["causes"]
        return []

    # If specified, the time in seconds before the operation should be retried. Some errors may indicate
    # the client must take an alternate action - for those errors this field may indicate how long to wait
    # before taking the alternate action.
    @typechecked
    def retryAfterSeconds(self) -> Optional[int]:
        if "retryAfterSeconds" in self._kwargs:
            return self._kwargs["retryAfterSeconds"]
        if "retryAfterSeconds" in self._context and check_return_type(
            self._context["retryAfterSeconds"]
        ):
            return self._context["retryAfterSeconds"]
        return None


# Status is a return value for calls that don't return other objects.
class Status(base.TypedObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
    def metadata(self) -> ListMeta:
        if "metadata" in self._kwargs:
            return self._kwargs["metadata"]
        if "metadata" in self._context and check_return_type(self._context["metadata"]):
            return self._context["metadata"]
        with context.Scope(**self._context):
            return ListMeta()

    # Status of the operation.
    # One of: "Success" or "Failure".
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def status(self) -> Optional[str]:
        if "status" in self._kwargs:
            return self._kwargs["status"]
        if "status" in self._context and check_return_type(self._context["status"]):
            return self._context["status"]
        return None

    # A human-readable description of the status of this operation.
    @typechecked
    def message(self) -> Optional[str]:
        if "message" in self._kwargs:
            return self._kwargs["message"]
        if "message" in self._context and check_return_type(self._context["message"]):
            return self._context["message"]
        return None

    # A machine-readable description of why this operation is in the
    # "Failure" status. If this value is empty there
    # is no information available. A Reason clarifies an HTTP status
    # code but does not override it.
    @typechecked
    def reason(self) -> Optional[StatusReason]:
        if "reason" in self._kwargs:
            return self._kwargs["reason"]
        if "reason" in self._context and check_return_type(self._context["reason"]):
            return self._context["reason"]
        return None

    # Extended data associated with the reason.  Each reason may define its
    # own extended details. This field is optional and the data returned
    # is not guaranteed to conform to any schema except that defined by
    # the reason type.
    @typechecked
    def details(self) -> Optional[StatusDetails]:
        if "details" in self._kwargs:
            return self._kwargs["details"]
        if "details" in self._context and check_return_type(self._context["details"]):
            return self._context["details"]
        return None

    # Suggested HTTP return code for this status, 0 if not set.
    @typechecked
    def code(self) -> Optional[int]:
        if "code" in self._kwargs:
            return self._kwargs["code"]
        if "code" in self._context and check_return_type(self._context["code"]):
            return self._context["code"]
        return None
