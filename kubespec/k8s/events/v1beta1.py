# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


class EventSeries(types.Object):
    """
    EventSeries contain information on series of events, i.e. thing that was/is happening
    continuously for some time.
    """

    @context.scoped
    @typechecked
    def __init__(self, count: int = 0, last_observed_time: "base.MicroTime" = None):
        super().__init__()
        self.__count = count
        self.__last_observed_time = last_observed_time

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        count = self.count()
        check_type("count", count, int)
        v["count"] = count
        last_observed_time = self.last_observed_time()
        check_type("last_observed_time", last_observed_time, "base.MicroTime")
        v["lastObservedTime"] = last_observed_time
        return v

    def count(self) -> int:
        """
        Number of occurrences in this series up to the last heartbeat time
        """
        return self.__count

    def last_observed_time(self) -> "base.MicroTime":
        """
        Time when last Event from the series was seen before last heartbeat.
        """
        return self.__last_observed_time


class Event(base.TypedObject, base.NamespacedMetadataObject):
    """
    Event is a report of an event somewhere in the cluster. It generally denotes some state change in the system.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        event_time: "base.MicroTime" = None,
        series: "EventSeries" = None,
        reporting_controller: str = None,
        reporting_instance: str = None,
        action: str = None,
        reason: str = None,
        regarding: "k8sv1.ObjectReference" = None,
        related: "k8sv1.ObjectReference" = None,
        note: str = None,
        type: str = None,
    ):
        super().__init__(
            api_version="events.k8s.io/v1beta1",
            kind="Event",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__event_time = event_time
        self.__series = series
        self.__reporting_controller = reporting_controller
        self.__reporting_instance = reporting_instance
        self.__action = action
        self.__reason = reason
        self.__regarding = (
            regarding if regarding is not None else k8sv1.ObjectReference()
        )
        self.__related = related
        self.__note = note
        self.__type = type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        event_time = self.event_time()
        check_type("event_time", event_time, "base.MicroTime")
        v["eventTime"] = event_time
        series = self.series()
        check_type("series", series, Optional["EventSeries"])
        if series is not None:  # omit empty
            v["series"] = series
        reporting_controller = self.reporting_controller()
        check_type("reporting_controller", reporting_controller, Optional[str])
        if reporting_controller:  # omit empty
            v["reportingController"] = reporting_controller
        reporting_instance = self.reporting_instance()
        check_type("reporting_instance", reporting_instance, Optional[str])
        if reporting_instance:  # omit empty
            v["reportingInstance"] = reporting_instance
        action = self.action()
        check_type("action", action, Optional[str])
        if action:  # omit empty
            v["action"] = action
        reason = self.reason()
        check_type("reason", reason, Optional[str])
        if reason:  # omit empty
            v["reason"] = reason
        regarding = self.regarding()
        check_type("regarding", regarding, Optional["k8sv1.ObjectReference"])
        v["regarding"] = regarding
        related = self.related()
        check_type("related", related, Optional["k8sv1.ObjectReference"])
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

    def event_time(self) -> "base.MicroTime":
        """
        Required. Time when this Event was first observed.
        """
        return self.__event_time

    def series(self) -> Optional["EventSeries"]:
        """
        Data about the Event series this event represents or nil if it's a singleton Event.
        """
        return self.__series

    def reporting_controller(self) -> Optional[str]:
        """
        Name of the controller that emitted this Event, e.g. `kubernetes.io/kubelet`.
        """
        return self.__reporting_controller

    def reporting_instance(self) -> Optional[str]:
        """
        ID of the controller instance, e.g. `kubelet-xyzf`.
        """
        return self.__reporting_instance

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

    def regarding(self) -> Optional["k8sv1.ObjectReference"]:
        """
        The object this Event is about. In most cases it's an Object reporting controller implements.
        E.g. ReplicaSetController implements ReplicaSets and this event is emitted because
        it acts on some changes in a ReplicaSet object.
        """
        return self.__regarding

    def related(self) -> Optional["k8sv1.ObjectReference"]:
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
