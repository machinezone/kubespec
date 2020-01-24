# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


class LeaseSpec(types.Object):
    """
    LeaseSpec is a specification of a Lease.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        holder_identity: str = None,
        lease_duration_seconds: int = None,
        acquire_time: "base.MicroTime" = None,
        renew_time: "base.MicroTime" = None,
        lease_transitions: int = None,
    ):
        super().__init__()
        self.__holder_identity = holder_identity
        self.__lease_duration_seconds = lease_duration_seconds
        self.__acquire_time = acquire_time
        self.__renew_time = renew_time
        self.__lease_transitions = lease_transitions

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        holder_identity = self.holder_identity()
        check_type("holder_identity", holder_identity, Optional[str])
        if holder_identity is not None:  # omit empty
            v["holderIdentity"] = holder_identity
        lease_duration_seconds = self.lease_duration_seconds()
        check_type("lease_duration_seconds", lease_duration_seconds, Optional[int])
        if lease_duration_seconds is not None:  # omit empty
            v["leaseDurationSeconds"] = lease_duration_seconds
        acquire_time = self.acquire_time()
        check_type("acquire_time", acquire_time, Optional["base.MicroTime"])
        if acquire_time is not None:  # omit empty
            v["acquireTime"] = acquire_time
        renew_time = self.renew_time()
        check_type("renew_time", renew_time, Optional["base.MicroTime"])
        if renew_time is not None:  # omit empty
            v["renewTime"] = renew_time
        lease_transitions = self.lease_transitions()
        check_type("lease_transitions", lease_transitions, Optional[int])
        if lease_transitions is not None:  # omit empty
            v["leaseTransitions"] = lease_transitions
        return v

    def holder_identity(self) -> Optional[str]:
        """
        holderIdentity contains the identity of the holder of a current lease.
        """
        return self.__holder_identity

    def lease_duration_seconds(self) -> Optional[int]:
        """
        leaseDurationSeconds is a duration that candidates for a lease need
        to wait to force acquire it. This is measure against time of last
        observed RenewTime.
        """
        return self.__lease_duration_seconds

    def acquire_time(self) -> Optional["base.MicroTime"]:
        """
        acquireTime is a time when the current lease was acquired.
        """
        return self.__acquire_time

    def renew_time(self) -> Optional["base.MicroTime"]:
        """
        renewTime is a time when the current holder of a lease has last
        updated the lease.
        """
        return self.__renew_time

    def lease_transitions(self) -> Optional[int]:
        """
        leaseTransitions is the number of transitions of a lease between
        holders.
        """
        return self.__lease_transitions


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
            api_version="coordination.k8s.io/v1",
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
