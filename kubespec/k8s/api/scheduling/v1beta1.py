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


# DEPRECATED - This group version of PriorityClass is deprecated by scheduling.k8s.io/v1/PriorityClass.
# PriorityClass defines mapping from a priority class name to the priority
# integer value. The value can be any valid integer.
class PriorityClass(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        value: int = 0,
        globalDefault: bool = None,
        description: str = None,
        preemptionPolicy: corev1.PreemptionPolicy = None,
    ):
        super().__init__(
            **{
                "apiVersion": "scheduling.k8s.io/v1beta1",
                "kind": "PriorityClass",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__value = value
        self.__globalDefault = globalDefault
        self.__description = description
        self.__preemptionPolicy = preemptionPolicy

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["value"] = self.value()
        globalDefault = self.globalDefault()
        if globalDefault:  # omit empty
            v["globalDefault"] = globalDefault
        description = self.description()
        if description:  # omit empty
            v["description"] = description
        preemptionPolicy = self.preemptionPolicy()
        if preemptionPolicy is not None:  # omit empty
            v["preemptionPolicy"] = preemptionPolicy
        return v

    # The value of this priority class. This is the actual priority that pods
    # receive when they have the name of this class in their pod spec.
    @typechecked
    def value(self) -> int:
        return self.__value

    # globalDefault specifies whether this PriorityClass should be considered as
    # the default priority for pods that do not have any priority class.
    # Only one PriorityClass can be marked as `globalDefault`. However, if more than
    # one PriorityClasses exists with their `globalDefault` field set to true,
    # the smallest value of such global default PriorityClasses will be used as the default priority.
    @typechecked
    def globalDefault(self) -> Optional[bool]:
        return self.__globalDefault

    # description is an arbitrary string that usually provides guidelines on
    # when this priority class should be used.
    @typechecked
    def description(self) -> Optional[str]:
        return self.__description

    # PreemptionPolicy is the Policy for preempting pods with lower priority.
    # One of Never, PreemptLowerPriority.
    # Defaults to PreemptLowerPriority if unset.
    # This field is alpha-level and is only honored by servers that enable the NonPreemptingPriority feature.
    @typechecked
    def preemptionPolicy(self) -> Optional[corev1.PreemptionPolicy]:
        return self.__preemptionPolicy
