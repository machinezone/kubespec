# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import typechecked


# LeaseSpec is a specification of a Lease.
class LeaseSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        holderIdentity: str = None,
        leaseDurationSeconds: int = None,
        acquireTime: "base.MicroTime" = None,
        renewTime: "base.MicroTime" = None,
        leaseTransitions: int = None,
    ):
        super().__init__(**{})
        self.__holderIdentity = holderIdentity
        self.__leaseDurationSeconds = leaseDurationSeconds
        self.__acquireTime = acquireTime
        self.__renewTime = renewTime
        self.__leaseTransitions = leaseTransitions

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        holderIdentity = self.holderIdentity()
        if holderIdentity is not None:  # omit empty
            v["holderIdentity"] = holderIdentity
        leaseDurationSeconds = self.leaseDurationSeconds()
        if leaseDurationSeconds is not None:  # omit empty
            v["leaseDurationSeconds"] = leaseDurationSeconds
        acquireTime = self.acquireTime()
        if acquireTime is not None:  # omit empty
            v["acquireTime"] = acquireTime
        renewTime = self.renewTime()
        if renewTime is not None:  # omit empty
            v["renewTime"] = renewTime
        leaseTransitions = self.leaseTransitions()
        if leaseTransitions is not None:  # omit empty
            v["leaseTransitions"] = leaseTransitions
        return v

    # holderIdentity contains the identity of the holder of a current lease.
    @typechecked
    def holderIdentity(self) -> Optional[str]:
        return self.__holderIdentity

    # leaseDurationSeconds is a duration that candidates for a lease need
    # to wait to force acquire it. This is measure against time of last
    # observed RenewTime.
    @typechecked
    def leaseDurationSeconds(self) -> Optional[int]:
        return self.__leaseDurationSeconds

    # acquireTime is a time when the current lease was acquired.
    @typechecked
    def acquireTime(self) -> Optional["base.MicroTime"]:
        return self.__acquireTime

    # renewTime is a time when the current holder of a lease has last
    # updated the lease.
    @typechecked
    def renewTime(self) -> Optional["base.MicroTime"]:
        return self.__renewTime

    # leaseTransitions is the number of transitions of a lease between
    # holders.
    @typechecked
    def leaseTransitions(self) -> Optional[int]:
        return self.__leaseTransitions


# Lease defines a lease concept.
class Lease(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: LeaseSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else LeaseSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # Specification of the Lease.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> Optional[LeaseSpec]:
        return self.__spec
