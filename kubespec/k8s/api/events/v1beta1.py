# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# EventSeries contain information on series of events, i.e. thing that was/is happening
# continuously for some time.
class EventSeries(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, count: int = 0, lastObservedTime: "base.MicroTime" = None):
        super().__init__()
        self.__count = count
        self.__lastObservedTime = lastObservedTime

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        count = self.count()
        check_type("count", count, int)
        v["count"] = count
        lastObservedTime = self.lastObservedTime()
        check_type("lastObservedTime", lastObservedTime, "base.MicroTime")
        v["lastObservedTime"] = lastObservedTime
        return v

    def count(self) -> int:
        """
        Number of occurrences in this series up to the last heartbeat time
        """
        return self.__count

    def lastObservedTime(self) -> "base.MicroTime":
        """
        Time when last Event from the series was seen before last heartbeat.
        """
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
            apiVersion="events.k8s.io/v1beta1",
            kind="Event",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
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
        eventTime = self.eventTime()
        check_type("eventTime", eventTime, "base.MicroTime")
        v["eventTime"] = eventTime
        series = self.series()
        check_type("series", series, Optional[EventSeries])
        if series is not None:  # omit empty
            v["series"] = series
        reportingController = self.reportingController()
        check_type("reportingController", reportingController, Optional[str])
        if reportingController:  # omit empty
            v["reportingController"] = reportingController
        reportingInstance = self.reportingInstance()
        check_type("reportingInstance", reportingInstance, Optional[str])
        if reportingInstance:  # omit empty
            v["reportingInstance"] = reportingInstance
        action = self.action()
        check_type("action", action, Optional[str])
        if action:  # omit empty
            v["action"] = action
        reason = self.reason()
        check_type("reason", reason, Optional[str])
        if reason:  # omit empty
            v["reason"] = reason
        regarding = self.regarding()
        check_type("regarding", regarding, Optional["corev1.ObjectReference"])
        v["regarding"] = regarding
        related = self.related()
        check_type("related", related, Optional["corev1.ObjectReference"])
        if related is not None:  # omit empty
            v["related"] = related
        note = self.note()
        check_type("note", note, Optional[str])
        if note:  # omit empty
            v["note"] = note
        type = self.type()
        check_type("type", type, Optional[str])
        if type:  # omit empty
            v["type"] = type
        return v

    def eventTime(self) -> "base.MicroTime":
        """
        Required. Time when this Event was first observed.
        """
        return self.__eventTime

    def series(self) -> Optional[EventSeries]:
        """
        Data about the Event series this event represents or nil if it's a singleton Event.
        """
        return self.__series

    def reportingController(self) -> Optional[str]:
        """
        Name of the controller that emitted this Event, e.g. `kubernetes.io/kubelet`.
        """
        return self.__reportingController

    def reportingInstance(self) -> Optional[str]:
        """
        ID of the controller instance, e.g. `kubelet-xyzf`.
        """
        return self.__reportingInstance

    def action(self) -> Optional[str]:
        """
        What action was taken/failed regarding to the regarding object.
        """
        return self.__action

    def reason(self) -> Optional[str]:
        """
        Why the action was taken.
        """
        return self.__reason

    def regarding(self) -> Optional["corev1.ObjectReference"]:
        """
        The object this Event is about. In most cases it's an Object reporting controller implements.
        E.g. ReplicaSetController implements ReplicaSets and this event is emitted because
        it acts on some changes in a ReplicaSet object.
        """
        return self.__regarding

    def related(self) -> Optional["corev1.ObjectReference"]:
        """
        Optional secondary object for more complex actions. E.g. when regarding object triggers
        a creation or deletion of related object.
        """
        return self.__related

    def note(self) -> Optional[str]:
        """
        Optional. A human-readable description of the status of this operation.
        Maximal length of the note is 1kB, but libraries should be prepared to
        handle values up to 64kB.
        """
        return self.__note

    def type(self) -> Optional[str]:
        """
        Type of this event (Normal, Warning), new types could be added in the
        future.
        """
        return self.__type
