# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec import context
from kubespec import types
from typeguard import typechecked


# EventSeries contain information on series of events, i.e. thing that was/is happening
# continuously for some time.
class EventSeries(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, count: int = 0, lastObservedTime: "base.MicroTime" = None):
        super().__init__(**{})
        self.__count = count
        self.__lastObservedTime = lastObservedTime

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["count"] = self.count()
        v["lastObservedTime"] = self.lastObservedTime()
        return v

    # Number of occurrences in this series up to the last heartbeat time
    @typechecked
    def count(self) -> int:
        return self.__count

    # Time when last Event from the series was seen before last heartbeat.
    @typechecked
    def lastObservedTime(self) -> "base.MicroTime":
        return self.__lastObservedTime


# Event is a report of an event somewhere in the cluster. It generally denotes some state change in the system.
class Event(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        eventTime: "base.MicroTime" = None,
        series: EventSeries = None,
        reportingController: str = None,
        reportingInstance: str = None,
        action: str = None,
        reason: str = None,
        regarding: "corev1.ObjectReference" = None,
        related: "corev1.ObjectReference" = None,
        note: str = None,
        type: str = None,
    ):
        super().__init__(
            **{
                "apiVersion": "events.k8s.io/v1beta1",
                "kind": "Event",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__eventTime = eventTime
        self.__series = series
        self.__reportingController = reportingController
        self.__reportingInstance = reportingInstance
        self.__action = action
        self.__reason = reason
        self.__regarding = (
            regarding if regarding is not None else corev1.ObjectReference()
        )
        self.__related = related
        self.__note = note
        self.__type = type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["eventTime"] = self.eventTime()
        series = self.series()
        if series is not None:  # omit empty
            v["series"] = series
        reportingController = self.reportingController()
        if reportingController:  # omit empty
            v["reportingController"] = reportingController
        reportingInstance = self.reportingInstance()
        if reportingInstance:  # omit empty
            v["reportingInstance"] = reportingInstance
        action = self.action()
        if action:  # omit empty
            v["action"] = action
        reason = self.reason()
        if reason:  # omit empty
            v["reason"] = reason
        v["regarding"] = self.regarding()
        related = self.related()
        if related is not None:  # omit empty
            v["related"] = related
        note = self.note()
        if note:  # omit empty
            v["note"] = note
        type = self.type()
        if type:  # omit empty
            v["type"] = type
        return v

    # Required. Time when this Event was first observed.
    @typechecked
    def eventTime(self) -> "base.MicroTime":
        return self.__eventTime

    # Data about the Event series this event represents or nil if it's a singleton Event.
    @typechecked
    def series(self) -> Optional[EventSeries]:
        return self.__series

    # Name of the controller that emitted this Event, e.g. `kubernetes.io/kubelet`.
    @typechecked
    def reportingController(self) -> Optional[str]:
        return self.__reportingController

    # ID of the controller instance, e.g. `kubelet-xyzf`.
    @typechecked
    def reportingInstance(self) -> Optional[str]:
        return self.__reportingInstance

    # What action was taken/failed regarding to the regarding object.
    @typechecked
    def action(self) -> Optional[str]:
        return self.__action

    # Why the action was taken.
    @typechecked
    def reason(self) -> Optional[str]:
        return self.__reason

    # The object this Event is about. In most cases it's an Object reporting controller implements.
    # E.g. ReplicaSetController implements ReplicaSets and this event is emitted because
    # it acts on some changes in a ReplicaSet object.
    @typechecked
    def regarding(self) -> Optional["corev1.ObjectReference"]:
        return self.__regarding

    # Optional secondary object for more complex actions. E.g. when regarding object triggers
    # a creation or deletion of related object.
    @typechecked
    def related(self) -> Optional["corev1.ObjectReference"]:
        return self.__related

    # Optional. A human-readable description of the status of this operation.
    # Maximal length of the note is 1kB, but libraries should be prepared to
    # handle values up to 64kB.
    @typechecked
    def note(self) -> Optional[str]:
        return self.__note

    # Type of this event (Normal, Warning), new types could be added in the
    # future.
    @typechecked
    def type(self) -> Optional[str]:
        return self.__type
