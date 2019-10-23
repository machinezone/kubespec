# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


class LeaseSpec(types.Object):
    """
    LeaseSpec is a specification of a Lease.
    """

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
        super().__init__()
        self.__holderIdentity = holderIdentity
        self.__leaseDurationSeconds = leaseDurationSeconds
        self.__acquireTime = acquireTime
        self.__renewTime = renewTime
        self.__leaseTransitions = leaseTransitions

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        holderIdentity = self.holderIdentity()
        check_type("holderIdentity", holderIdentity, Optional[str])
        if holderIdentity is not None:  # omit empty
            v["holderIdentity"] = holderIdentity
        leaseDurationSeconds = self.leaseDurationSeconds()
        check_type("leaseDurationSeconds", leaseDurationSeconds, Optional[int])
        if leaseDurationSeconds is not None:  # omit empty
            v["leaseDurationSeconds"] = leaseDurationSeconds
        acquireTime = self.acquireTime()
        check_type("acquireTime", acquireTime, Optional["base.MicroTime"])
        if acquireTime is not None:  # omit empty
            v["acquireTime"] = acquireTime
        renewTime = self.renewTime()
        check_type("renewTime", renewTime, Optional["base.MicroTime"])
        if renewTime is not None:  # omit empty
            v["renewTime"] = renewTime
        leaseTransitions = self.leaseTransitions()
        check_type("leaseTransitions", leaseTransitions, Optional[int])
        if leaseTransitions is not None:  # omit empty
            v["leaseTransitions"] = leaseTransitions
        return v

    def holderIdentity(self) -> Optional[str]:
        """
        holderIdentity contains the identity of the holder of a current lease.
        """
        return self.__holderIdentity

    def leaseDurationSeconds(self) -> Optional[int]:
        """
        leaseDurationSeconds is a duration that candidates for a lease need
        to wait to force acquire it. This is measure against time of last
        observed RenewTime.
        """
        return self.__leaseDurationSeconds

    def acquireTime(self) -> Optional["base.MicroTime"]:
        """
        acquireTime is a time when the current lease was acquired.
        """
        return self.__acquireTime

    def renewTime(self) -> Optional["base.MicroTime"]:
        """
        renewTime is a time when the current holder of a lease has last
        updated the lease.
        """
        return self.__renewTime

    def leaseTransitions(self) -> Optional[int]:
        """
        leaseTransitions is the number of transitions of a lease between
        holders.
        """
        return self.__leaseTransitions


class Lease(base.TypedObject, base.NamespacedMetadataObject):
    """
    Lease defines a lease concept.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "LeaseSpec" = None,
    ):
        super().__init__(
            apiVersion="coordination.k8s.io/v1beta1",
            kind="Lease",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else LeaseSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["LeaseSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["LeaseSpec"]:
        """
        Specification of the Lease.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec
