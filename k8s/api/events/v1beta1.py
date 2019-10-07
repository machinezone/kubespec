# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.api.core import v1 as corev1
from kargo import types
from typeguard import typechecked


# EventSeries contain information on series of events, i.e. thing that was/is happening
# continuously for some time.
class EventSeries(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['count'] = self.count()
        v['lastObservedTime'] = self.lastObservedTime()
        return v
    
    # Number of occurrences in this series up to the last heartbeat time
    @typechecked
    def count(self) -> int:
        return self._kwargs.get('count', 0)
    
    # Time when last Event from the series was seen before last heartbeat.
    @typechecked
    def lastObservedTime(self) -> 'base.MicroTime':
        return self._kwargs.get('lastObservedTime')


# Event is a report of an event somewhere in the cluster. It generally denotes some state change in the system.
class Event(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['eventTime'] = self.eventTime()
        series = self.series()
        if series is not None:  # omit empty
            v['series'] = series
        reportingController = self.reportingController()
        if reportingController:  # omit empty
            v['reportingController'] = reportingController
        reportingInstance = self.reportingInstance()
        if reportingInstance:  # omit empty
            v['reportingInstance'] = reportingInstance
        action = self.action()
        if action:  # omit empty
            v['action'] = action
        reason = self.reason()
        if reason:  # omit empty
            v['reason'] = reason
        v['regarding'] = self.regarding()
        related = self.related()
        if related is not None:  # omit empty
            v['related'] = related
        note = self.note()
        if note:  # omit empty
            v['note'] = note
        type = self.type()
        if type:  # omit empty
            v['type'] = type
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'events.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'Event'
    
    # Required. Time when this Event was first observed.
    @typechecked
    def eventTime(self) -> 'base.MicroTime':
        return self._kwargs.get('eventTime')
    
    # Data about the Event series this event represents or nil if it's a singleton Event.
    @typechecked
    def series(self) -> Optional[EventSeries]:
        return self._kwargs.get('series')
    
    # Name of the controller that emitted this Event, e.g. `kubernetes.io/kubelet`.
    @typechecked
    def reportingController(self) -> Optional[str]:
        return self._kwargs.get('reportingController')
    
    # ID of the controller instance, e.g. `kubelet-xyzf`.
    @typechecked
    def reportingInstance(self) -> Optional[str]:
        return self._kwargs.get('reportingInstance')
    
    # What action was taken/failed regarding to the regarding object.
    @typechecked
    def action(self) -> Optional[str]:
        return self._kwargs.get('action')
    
    # Why the action was taken.
    @typechecked
    def reason(self) -> Optional[str]:
        return self._kwargs.get('reason')
    
    # The object this Event is about. In most cases it's an Object reporting controller implements.
    # E.g. ReplicaSetController implements ReplicaSets and this event is emitted because
    # it acts on some changes in a ReplicaSet object.
    @typechecked
    def regarding(self) -> 'corev1.ObjectReference':
        return self._kwargs.get('regarding', corev1.ObjectReference())
    
    # Optional secondary object for more complex actions. E.g. when regarding object triggers
    # a creation or deletion of related object.
    @typechecked
    def related(self) -> Optional['corev1.ObjectReference']:
        return self._kwargs.get('related')
    
    # Optional. A human-readable description of the status of this operation.
    # Maximal length of the note is 1kB, but libraries should be prepared to
    # handle values up to 64kB.
    @typechecked
    def note(self) -> Optional[str]:
        return self._kwargs.get('note')
    
    # Type of this event (Normal, Warning), new types could be added in the
    # future.
    @typechecked
    def type(self) -> Optional[str]:
        return self._kwargs.get('type')
