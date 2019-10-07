# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.api.core import v1 as corev1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


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
        if 'count' in self._kwargs:
            return self._kwargs['count']
        if 'count' in self._context and check_return_type(self._context['count']):
            return self._context['count']
        return 0
    
    # Time when last Event from the series was seen before last heartbeat.
    @typechecked
    def lastObservedTime(self) -> 'base.MicroTime':
        if 'lastObservedTime' in self._kwargs:
            return self._kwargs['lastObservedTime']
        if 'lastObservedTime' in self._context and check_return_type(self._context['lastObservedTime']):
            return self._context['lastObservedTime']
        return None


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
        if 'eventTime' in self._kwargs:
            return self._kwargs['eventTime']
        if 'eventTime' in self._context and check_return_type(self._context['eventTime']):
            return self._context['eventTime']
        return None
    
    # Data about the Event series this event represents or nil if it's a singleton Event.
    @typechecked
    def series(self) -> Optional[EventSeries]:
        if 'series' in self._kwargs:
            return self._kwargs['series']
        if 'series' in self._context and check_return_type(self._context['series']):
            return self._context['series']
        return None
    
    # Name of the controller that emitted this Event, e.g. `kubernetes.io/kubelet`.
    @typechecked
    def reportingController(self) -> Optional[str]:
        if 'reportingController' in self._kwargs:
            return self._kwargs['reportingController']
        if 'reportingController' in self._context and check_return_type(self._context['reportingController']):
            return self._context['reportingController']
        return None
    
    # ID of the controller instance, e.g. `kubelet-xyzf`.
    @typechecked
    def reportingInstance(self) -> Optional[str]:
        if 'reportingInstance' in self._kwargs:
            return self._kwargs['reportingInstance']
        if 'reportingInstance' in self._context and check_return_type(self._context['reportingInstance']):
            return self._context['reportingInstance']
        return None
    
    # What action was taken/failed regarding to the regarding object.
    @typechecked
    def action(self) -> Optional[str]:
        if 'action' in self._kwargs:
            return self._kwargs['action']
        if 'action' in self._context and check_return_type(self._context['action']):
            return self._context['action']
        return None
    
    # Why the action was taken.
    @typechecked
    def reason(self) -> Optional[str]:
        if 'reason' in self._kwargs:
            return self._kwargs['reason']
        if 'reason' in self._context and check_return_type(self._context['reason']):
            return self._context['reason']
        return None
    
    # The object this Event is about. In most cases it's an Object reporting controller implements.
    # E.g. ReplicaSetController implements ReplicaSets and this event is emitted because
    # it acts on some changes in a ReplicaSet object.
    @typechecked
    def regarding(self) -> 'corev1.ObjectReference':
        if 'regarding' in self._kwargs:
            return self._kwargs['regarding']
        if 'regarding' in self._context and check_return_type(self._context['regarding']):
            return self._context['regarding']
        with context.Scope(**self._context):
            return corev1.ObjectReference()
    
    # Optional secondary object for more complex actions. E.g. when regarding object triggers
    # a creation or deletion of related object.
    @typechecked
    def related(self) -> Optional['corev1.ObjectReference']:
        if 'related' in self._kwargs:
            return self._kwargs['related']
        if 'related' in self._context and check_return_type(self._context['related']):
            return self._context['related']
        return None
    
    # Optional. A human-readable description of the status of this operation.
    # Maximal length of the note is 1kB, but libraries should be prepared to
    # handle values up to 64kB.
    @typechecked
    def note(self) -> Optional[str]:
        if 'note' in self._kwargs:
            return self._kwargs['note']
        if 'note' in self._context and check_return_type(self._context['note']):
            return self._context['note']
        return None
    
    # Type of this event (Normal, Warning), new types could be added in the
    # future.
    @typechecked
    def type(self) -> Optional[str]:
        if 'type' in self._kwargs:
            return self._kwargs['type']
        if 'type' in self._context and check_return_type(self._context['type']):
            return self._context['type']
        return None
