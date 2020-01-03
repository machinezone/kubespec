# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


class PriorityClass(base.TypedObject, base.MetadataObject):
    """
    PriorityClass defines mapping from a priority class name to the priority
    integer value. The value can be any valid integer.
    """

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
        preemptionPolicy: k8sv1.PreemptionPolicy = None,
    ):
        super().__init__(
            apiVersion="scheduling.k8s.io/v1",
            kind="PriorityClass",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__value = value
        self.__globalDefault = globalDefault
        self.__description = description
        self.__preemptionPolicy = preemptionPolicy

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        value = self.value()
        check_type("value", value, int)
        v["value"] = value
        globalDefault = self.globalDefault()
        check_type("globalDefault", globalDefault, Optional[bool])
        if globalDefault:  # omit empty
            v["globalDefault"] = globalDefault
        description = self.description()
        check_type("description", description, Optional[str])
        if description:  # omit empty
            v["description"] = description
        preemptionPolicy = self.preemptionPolicy()
        check_type(
            "preemptionPolicy", preemptionPolicy, Optional[k8sv1.PreemptionPolicy]
        )
        if preemptionPolicy is not None:  # omit empty
            v["preemptionPolicy"] = preemptionPolicy
        return v

    def value(self) -> int:
        """
        The value of this priority class. This is the actual priority that pods
        receive when they have the name of this class in their pod spec.
        """
        return self.__value

    def globalDefault(self) -> Optional[bool]:
        """
        globalDefault specifies whether this PriorityClass should be considered as
        the default priority for pods that do not have any priority class.
        Only one PriorityClass can be marked as `globalDefault`. However, if more than
        one PriorityClasses exists with their `globalDefault` field set to true,
        the smallest value of such global default PriorityClasses will be used as the default priority.
        """
        return self.__globalDefault

    def description(self) -> Optional[str]:
        """
        description is an arbitrary string that usually provides guidelines on
        when this priority class should be used.
        """
        return self.__description

    def preemptionPolicy(self) -> Optional[k8sv1.PreemptionPolicy]:
        """
        PreemptionPolicy is the Policy for preempting pods with lower priority.
        One of Never, PreemptLowerPriority.
        Defaults to PreemptLowerPriority if unset.
        This field is alpha-level and is only honored by servers that enable the NonPreemptingPriority feature.
        """
        return self.__preemptionPolicy
