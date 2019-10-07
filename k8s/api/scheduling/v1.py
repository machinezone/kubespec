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


# PriorityClass defines mapping from a priority class name to the priority
# integer value. The value can be any valid integer.
class PriorityClass(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['value'] = self.value()
        globalDefault = self.globalDefault()
        if globalDefault:  # omit empty
            v['globalDefault'] = globalDefault
        description = self.description()
        if description:  # omit empty
            v['description'] = description
        preemptionPolicy = self.preemptionPolicy()
        if preemptionPolicy is not None:  # omit empty
            v['preemptionPolicy'] = preemptionPolicy
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'scheduling.k8s.io/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'PriorityClass'
    
    # The value of this priority class. This is the actual priority that pods
    # receive when they have the name of this class in their pod spec.
    @typechecked
    def value(self) -> int:
        if 'value' in self._kwargs:
            return self._kwargs['value']
        if 'value' in self._context and check_return_type(self._context['value']):
            return self._context['value']
        return 0
    
    # globalDefault specifies whether this PriorityClass should be considered as
    # the default priority for pods that do not have any priority class.
    # Only one PriorityClass can be marked as `globalDefault`. However, if more than
    # one PriorityClasses exists with their `globalDefault` field set to true,
    # the smallest value of such global default PriorityClasses will be used as the default priority.
    @typechecked
    def globalDefault(self) -> Optional[bool]:
        if 'globalDefault' in self._kwargs:
            return self._kwargs['globalDefault']
        if 'globalDefault' in self._context and check_return_type(self._context['globalDefault']):
            return self._context['globalDefault']
        return None
    
    # description is an arbitrary string that usually provides guidelines on
    # when this priority class should be used.
    @typechecked
    def description(self) -> Optional[str]:
        if 'description' in self._kwargs:
            return self._kwargs['description']
        if 'description' in self._context and check_return_type(self._context['description']):
            return self._context['description']
        return None
    
    # PreemptionPolicy is the Policy for preempting pods with lower priority.
    # One of Never, PreemptLowerPriority.
    # Defaults to PreemptLowerPriority if unset.
    # This field is alpha-level and is only honored by servers that enable the NonPreemptingPriority feature.
    @typechecked
    def preemptionPolicy(self) -> Optional[corev1.PreemptionPolicy]:
        if 'preemptionPolicy' in self._kwargs:
            return self._kwargs['preemptionPolicy']
        if 'preemptionPolicy' in self._context and check_return_type(self._context['preemptionPolicy']):
            return self._context['preemptionPolicy']
        return None
