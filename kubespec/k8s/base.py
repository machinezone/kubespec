# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import enum
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import pytz
from kubespec import types
from typeguard import check_type, typechecked


@typechecked
def Enum(name: str, values: Dict[str, str]):
    class _cls(types.Renderable, str, enum.Enum):
        def render(self) -> str:
            return self.value

    return _cls(name, values)


class TypedObject(types.Object):
    def __init__(
        self, apiVersion: Optional[str] = None, kind: Optional[str] = None, **kwargs
    ):
        super().__init__(**kwargs)
        self.__apiVersion = apiVersion
        self.__kind = kind

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        apiVersion = self.apiVersion()
        check_type("apiVersion", apiVersion, Optional[str])
        if apiVersion:  # omitempty
            v["apiVersion"] = apiVersion
        kind = self.kind()
        check_type("kind", kind, Optional[str])
        if kind:  # omitempty
            v["kind"] = kind
        return v

    # APIVersion defines the versioned schema of this representation of an object.
    # Servers should convert recognized schemas to the latest internal value, and
    # may reject unrecognized values.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources
    def apiVersion(self) -> Optional[str]:
        return self.__apiVersion

    # Kind is a string value representing the REST resource this object represents.
    # Servers may infer this from the endpoint the client submits requests to.
    # Cannot be updated.
    # In CamelCase.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
    def kind(self) -> Optional[str]:
        return self.__kind


class MetadataObject(types.Object):
    def __init__(
        self,
        name: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
        annotations: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.__name = name
        self.__labels = labels or {}
        self.__annotations = annotations or {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        metadata = v.get("metadata", {})
        check_type("metadata", metadata, Dict[str, Any])
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omitempty
            metadata["name"] = name
        labels = self.labels()
        check_type("labels", labels, Dict[str, str])
        if labels:  # omitempty
            metadata["labels"] = labels
        annotations = self.annotations()
        check_type("annotations", annotations, Dict[str, str])
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
    def name(self) -> Optional[str]:
        return self.__name

    # Map of string keys and values that can be used to organize and categorize
    # (scope and select) objects. May match selectors of replication controllers
    # and services.
    # More info: http://kubernetes.io/docs/user-guide/labels
    def labels(self) -> Dict[str, str]:
        return self.__labels

    # Annotations is an unstructured key value map stored with a resource that may be
    # set by external tools to store and retrieve arbitrary metadata. They are not
    # queryable and should be preserved when modifying objects.
    # More info: http://kubernetes.io/docs/user-guide/annotations
    def annotations(self) -> Dict[str, str]:
        return self.__annotations


class NamespacedMetadataObject(MetadataObject):
    def __init__(self, namespace: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.__namespace = namespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        metadata = v.get("metadata", {})
        check_type("metadata", metadata, Dict[str, Any])
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
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
    def namespace(self) -> Optional[str]:
        return self.__namespace


class Time(types.Renderable):
    _format = "%Y-%m-%dT%H:%M:%SZ"

    @typechecked
    def __init__(self, time: datetime):
        self.time = time

    def render(self) -> str:
        return self.time.astimezone(pytz.utc).strftime(self._format)


class MicroTime(Time):
    _format = "%Y-%m-%dT%H:%M:%S.%fZ"


class Duration(types.Renderable):
    @typechecked
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
