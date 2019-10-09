# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# LeaseSpec is a specification of a Lease.
class LeaseSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "holderIdentity" in self._kwargs:
            return self._kwargs["holderIdentity"]
        if "holderIdentity" in self._context and check_return_type(
            self._context["holderIdentity"]
        ):
            return self._context["holderIdentity"]
        return None

    # leaseDurationSeconds is a duration that candidates for a lease need
    # to wait to force acquire it. This is measure against time of last
    # observed RenewTime.
    @typechecked
    def leaseDurationSeconds(self) -> Optional[int]:
        if "leaseDurationSeconds" in self._kwargs:
            return self._kwargs["leaseDurationSeconds"]
        if "leaseDurationSeconds" in self._context and check_return_type(
            self._context["leaseDurationSeconds"]
        ):
            return self._context["leaseDurationSeconds"]
        return None

    # acquireTime is a time when the current lease was acquired.
    @typechecked
    def acquireTime(self) -> Optional["base.MicroTime"]:
        if "acquireTime" in self._kwargs:
            return self._kwargs["acquireTime"]
        if "acquireTime" in self._context and check_return_type(
            self._context["acquireTime"]
        ):
            return self._context["acquireTime"]
        return None

    # renewTime is a time when the current holder of a lease has last
    # updated the lease.
    @typechecked
    def renewTime(self) -> Optional["base.MicroTime"]:
        if "renewTime" in self._kwargs:
            return self._kwargs["renewTime"]
        if "renewTime" in self._context and check_return_type(
            self._context["renewTime"]
        ):
            return self._context["renewTime"]
        return None

    # leaseTransitions is the number of transitions of a lease between
    # holders.
    @typechecked
    def leaseTransitions(self) -> Optional[int]:
        if "leaseTransitions" in self._kwargs:
            return self._kwargs["leaseTransitions"]
        if "leaseTransitions" in self._context and check_return_type(
            self._context["leaseTransitions"]
        ):
            return self._context["leaseTransitions"]
        return None


# Lease defines a lease concept.
class Lease(base.TypedObject, base.NamespacedMetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "coordination.k8s.io/v1beta1"

    @typechecked
    def kind(self) -> str:
        return "Lease"

    # Specification of the Lease.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> LeaseSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return LeaseSpec()
