# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import enum
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import pytz
from kargo import types
from typeguard import check_return_type, typechecked


@typechecked
def Enum(name: str, values: Dict[str, str]):
    class _cls(types.Renderable, str, enum.Enum):
        def render(self) -> str:
            return self.value

    return _cls(name, values)


class TypedObject(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        apiVersion = self.apiVersion()
        if apiVersion:  # omitempty
            v["apiVersion"] = apiVersion
        kind = self.kind()
        if kind:  # omitempty
            v["kind"] = kind
        return v

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


class MetadataObject(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        metadata = v.get("metadata", {})
        name = self.name()
        if name:  # omitempty
            metadata["name"] = name
        labels = self.labels()
        if labels:  # omitempty
            metadata["labels"] = labels
        annotations = self.annotations()
        if annotations:  # omitempty
            metadata["annotations"] = annotations
        v["metadata"] = metadata
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


class NamespacedMetadataObject(MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        metadata = v.get("metadata", {})
        namespace = self.namespace()
        if namespace:  # omitempty
            metadata["namespace"] = namespace
        v["metadata"] = metadata
        return v

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


class Time(types.Renderable):
    _format = "%Y-%m-%dT%H:%M:%SZ"

    def __init__(self, time: datetime):
        self.time = time

    def render(self) -> str:
        return self.time.astimezone(pytz.utc).strftime(self._format)


class MicroTime(Time):
    _format = "%Y-%m-%dT%H:%M:%S.%fZ"


class Duration(types.Renderable):
    def __init__(self, duration: timedelta):
        self.duration = duration

    def render(self) -> str:
        out = ""
        secs = self.duration.total_seconds()
        if secs < 0:
            out = "-"
            secs = -secs
        hours, secs = divmod(secs, 3600)
        if hours > 0:
            out = out + hours + "h"
        mins, secs = divmod(secs, 60)
        if hours > 0 or mins > 0:
            out = out + mins + "m"
        return out + "{0:.9f}".format(secs).rstrip("0").rstrip(".") + "s"
