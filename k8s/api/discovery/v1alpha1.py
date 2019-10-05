# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Dict, List, Optional

import addict
from k8s import base
from k8s.api.core import v1 as corev1
from korps import types
from typeguard import typechecked


# AddressType represents the type of address referred to by an endpoint.
AddressType = base.Enum('AddressType', {
    # IP represents an IP Address.
    'IP': 'IP',
})


# EndpointConditions represents the current condition of an endpoint.
class EndpointConditions(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        ready = self.ready()
        if ready is not None:  # omit empty
            v['ready'] = ready
        return v
    
    # ready indicates that this endpoint is prepared to receive traffic,
    # according to whatever system is managing the endpoint. A nil value
    # indicates an unknown state. In most cases consumers should interpret this
    # unknown state as ready.
    @typechecked
    def ready(self) -> Optional[bool]:
        return self._kwargs.get('ready')


# Endpoint represents a single logical "backend" implementing a service.
class Endpoint(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['addresses'] = self.addresses()
        conditions = self.conditions()
        if conditions:  # omit empty
            v['conditions'] = conditions
        hostname = self.hostname()
        if hostname is not None:  # omit empty
            v['hostname'] = hostname
        targetRef = self.targetRef()
        if targetRef is not None:  # omit empty
            v['targetRef'] = targetRef
        topology = self.topology()
        if topology:  # omit empty
            v['topology'] = topology
        return v
    
    # addresses of this endpoint. The contents of this field are interpreted
    # according to the corresponding EndpointSlice addressType field. This
    # allows for cases like dual-stack (IPv4 and IPv6) networking. Consumers
    # (e.g. kube-proxy) must handle different types of addresses in the context
    # of their own capabilities. This must contain at least one address but no
    # more than 100.
    # +listType=set
    @typechecked
    def addresses(self) -> List[str]:
        return self._kwargs.get('addresses', [])
    
    # conditions contains information about the current status of the endpoint.
    @typechecked
    def conditions(self) -> Optional[EndpointConditions]:
        return self._kwargs.get('conditions')
    
    # hostname of this endpoint. This field may be used by consumers of
    # endpoints to distinguish endpoints from each other (e.g. in DNS names).
    # Multiple endpoints which use the same hostname should be considered
    # fungible (e.g. multiple A values in DNS). Must pass DNS Label (RFC 1123)
    # validation.
    @typechecked
    def hostname(self) -> Optional[str]:
        return self._kwargs.get('hostname')
    
    # targetRef is a reference to a Kubernetes object that represents this
    # endpoint.
    @typechecked
    def targetRef(self) -> Optional['corev1.ObjectReference']:
        return self._kwargs.get('targetRef')
    
    # topology contains arbitrary topology information associated with the
    # endpoint. These key/value pairs must conform with the label format.
    # https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
    # Topology may include a maximum of 16 key/value pairs. This includes, but
    # is not limited to the following well known keys:
    # * kubernetes.io/hostname: the value indicates the hostname of the node
    #   where the endpoint is located. This should match the corresponding
    #   node label.
    # * topology.kubernetes.io/zone: the value indicates the zone where the
    #   endpoint is located. This should match the corresponding node label.
    # * topology.kubernetes.io/region: the value indicates the region where the
    #   endpoint is located. This should match the corresponding node label.
    @typechecked
    def topology(self) -> Dict[str, str]:
        return self._kwargs.get('topology', addict.Dict())


# EndpointPort represents a Port used by an EndpointSlice
class EndpointPort(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        name = self.name()
        if name is not None:  # omit empty
            v['name'] = name
        protocol = self.protocol()
        if protocol is not None:  # omit empty
            v['protocol'] = protocol
        port = self.port()
        if port is not None:  # omit empty
            v['port'] = port
        return v
    
    # The name of this port. All ports in an EndpointSlice must have a unique
    # name. If the EndpointSlice is dervied from a Kubernetes service, this
    # corresponds to the Service.ports[].name.
    # Name must either be an empty string or pass IANA_SVC_NAME validation:
    # * must be no more than 15 characters long
    # * may contain only [-a-z0-9]
    # * must contain at least one letter [a-z]
    # * it must not start or end with a hyphen, nor contain adjacent hyphens
    # Default is empty string.
    @typechecked
    def name(self) -> Optional[str]:
        return self._kwargs.get('name')
    
    # The IP protocol for this port.
    # Must be UDP, TCP, or SCTP.
    # Default is TCP.
    @typechecked
    def protocol(self) -> Optional[corev1.Protocol]:
        return self._kwargs.get('protocol', corev1.Protocol['TCP'])
    
    # The port number of the endpoint.
    # If this is not specified, ports are not restricted and must be
    # interpreted in the context of the specific consumer.
    @typechecked
    def port(self) -> Optional[int]:
        return self._kwargs.get('port')


# EndpointSlice represents a subset of the endpoints that implement a service.
# For a given service there may be multiple EndpointSlice objects, selected by
# labels, which must be joined to produce the full set of endpoints.
class EndpointSlice(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['addressType'] = self.addressType()
        v['endpoints'] = self.endpoints()
        v['ports'] = self.ports()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'discovery.k8s.io/v1alpha1'
    
    @typechecked
    def kind(self) -> str:
        return 'EndpointSlice'
    
    # addressType specifies the type of address carried by this EndpointSlice.
    # All addresses in this slice must be the same type.
    # Default is IP
    @typechecked
    def addressType(self) -> Optional[AddressType]:
        return self._kwargs.get('addressType', AddressType['IP'])
    
    # endpoints is a list of unique endpoints in this slice. Each slice may
    # include a maximum of 1000 endpoints.
    # +listType=atomic
    @typechecked
    def endpoints(self) -> List[Endpoint]:
        return self._kwargs.get('endpoints', [])
    
    # ports specifies the list of network ports exposed by each endpoint in
    # this slice. Each port must have a unique name. When ports is empty, it
    # indicates that there are no defined ports. When a port is defined with a
    # nil port value, it indicates "all ports". Each slice may include a
    # maximum of 100 ports.
    # +listType=atomic
    @typechecked
    def ports(self) -> List[EndpointPort]:
        return self._kwargs.get('ports', [])
