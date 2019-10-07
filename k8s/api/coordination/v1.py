# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from kargo import types
from typeguard import typechecked


# LeaseSpec is a specification of a Lease.
class LeaseSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        holderIdentity = self.holderIdentity()
        if holderIdentity is not None:  # omit empty
            v['holderIdentity'] = holderIdentity
        leaseDurationSeconds = self.leaseDurationSeconds()
        if leaseDurationSeconds is not None:  # omit empty
            v['leaseDurationSeconds'] = leaseDurationSeconds
        acquireTime = self.acquireTime()
        if acquireTime is not None:  # omit empty
            v['acquireTime'] = acquireTime
        renewTime = self.renewTime()
        if renewTime is not None:  # omit empty
            v['renewTime'] = renewTime
        leaseTransitions = self.leaseTransitions()
        if leaseTransitions is not None:  # omit empty
            v['leaseTransitions'] = leaseTransitions
        return v
    
    # holderIdentity contains the identity of the holder of a current lease.
    @typechecked
    def holderIdentity(self) -> Optional[str]:
        return self._kwargs.get('holderIdentity')
    
    # leaseDurationSeconds is a duration that candidates for a lease need
    # to wait to force acquire it. This is measure against time of last
    # observed RenewTime.
    @typechecked
    def leaseDurationSeconds(self) -> Optional[int]:
        return self._kwargs.get('leaseDurationSeconds')
    
    # acquireTime is a time when the current lease was acquired.
    @typechecked
    def acquireTime(self) -> Optional['base.MicroTime']:
        return self._kwargs.get('acquireTime')
    
    # renewTime is a time when the current holder of a lease has last
    # updated the lease.
    @typechecked
    def renewTime(self) -> Optional['base.MicroTime']:
        return self._kwargs.get('renewTime')
    
    # leaseTransitions is the number of transitions of a lease between
    # holders.
    @typechecked
    def leaseTransitions(self) -> Optional[int]:
        return self._kwargs.get('leaseTransitions')


# Lease defines a lease concept.
class Lease(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'coordination.k8s.io/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'Lease'
    
    # Specification of the Lease.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> LeaseSpec:
        return self._kwargs.get('spec', LeaseSpec())
