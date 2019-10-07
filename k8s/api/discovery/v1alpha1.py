# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from k8s.api.core import v1 as corev1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# AddressType represents the type of address referred to by an endpoint.
AddressType = base.Enum(
    "AddressType",
    {
        # IP represents an IP Address.
        "IP": "IP"
    },
)


# EndpointConditions represents the current condition of an endpoint.
class EndpointConditions(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        ready = self.ready()
        if ready is not None:  # omit empty
            v["ready"] = ready
        return v

    # ready indicates that this endpoint is prepared to receive traffic,
    # according to whatever system is managing the endpoint. A nil value
    # indicates an unknown state. In most cases consumers should interpret this
    # unknown state as ready.
    @typechecked
    def ready(self) -> Optional[bool]:
        if "ready" in self._kwargs:
            return self._kwargs["ready"]
        if "ready" in self._context and check_return_type(self._context["ready"]):
            return self._context["ready"]
        return None


# Endpoint represents a single logical "backend" implementing a service.
class Endpoint(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["addresses"] = self.addresses()
        v["conditions"] = self.conditions()
        hostname = self.hostname()
        if hostname is not None:  # omit empty
            v["hostname"] = hostname
        targetRef = self.targetRef()
        if targetRef is not None:  # omit empty
            v["targetRef"] = targetRef
        topology = self.topology()
        if topology:  # omit empty
            v["topology"] = topology
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
        if "addresses" in self._kwargs:
            return self._kwargs["addresses"]
        if "addresses" in self._context and check_return_type(
            self._context["addresses"]
        ):
            return self._context["addresses"]
        return []

    # conditions contains information about the current status of the endpoint.
    @typechecked
    def conditions(self) -> EndpointConditions:
        if "conditions" in self._kwargs:
            return self._kwargs["conditions"]
        if "conditions" in self._context and check_return_type(
            self._context["conditions"]
        ):
            return self._context["conditions"]
        with context.Scope(**self._context):
            return EndpointConditions()

    # hostname of this endpoint. This field may be used by consumers of
    # endpoints to distinguish endpoints from each other (e.g. in DNS names).
    # Multiple endpoints which use the same hostname should be considered
    # fungible (e.g. multiple A values in DNS). Must pass DNS Label (RFC 1123)
    # validation.
    @typechecked
    def hostname(self) -> Optional[str]:
        if "hostname" in self._kwargs:
            return self._kwargs["hostname"]
        if "hostname" in self._context and check_return_type(self._context["hostname"]):
            return self._context["hostname"]
        return None

    # targetRef is a reference to a Kubernetes object that represents this
    # endpoint.
    @typechecked
    def targetRef(self) -> Optional["corev1.ObjectReference"]:
        if "targetRef" in self._kwargs:
            return self._kwargs["targetRef"]
        if "targetRef" in self._context and check_return_type(
            self._context["targetRef"]
        ):
            return self._context["targetRef"]
        return None

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
        if "topology" in self._kwargs:
            return self._kwargs["topology"]
        if "topology" in self._context and check_return_type(self._context["topology"]):
            return self._context["topology"]
        return {}


# EndpointPort represents a Port used by an EndpointSlice
class EndpointPort(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        name = self.name()
        if name is not None:  # omit empty
            v["name"] = name
        protocol = self.protocol()
        if protocol is not None:  # omit empty
            v["protocol"] = protocol
        port = self.port()
        if port is not None:  # omit empty
            v["port"] = port
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
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return None

    # The IP protocol for this port.
    # Must be UDP, TCP, or SCTP.
    # Default is TCP.
    @typechecked
    def protocol(self) -> Optional[corev1.Protocol]:
        if "protocol" in self._kwargs:
            return self._kwargs["protocol"]
        if "protocol" in self._context and check_return_type(self._context["protocol"]):
            return self._context["protocol"]
        return corev1.Protocol["TCP"]

    # The port number of the endpoint.
    # If this is not specified, ports are not restricted and must be
    # interpreted in the context of the specific consumer.
    @typechecked
    def port(self) -> Optional[int]:
        if "port" in self._kwargs:
            return self._kwargs["port"]
        if "port" in self._context and check_return_type(self._context["port"]):
            return self._context["port"]
        return None


# EndpointSlice represents a subset of the endpoints that implement a service.
# For a given service there may be multiple EndpointSlice objects, selected by
# labels, which must be joined to produce the full set of endpoints.
class EndpointSlice(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["addressType"] = self.addressType()
        v["endpoints"] = self.endpoints()
        v["ports"] = self.ports()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "discovery.k8s.io/v1alpha1"

    @typechecked
    def kind(self) -> str:
        return "EndpointSlice"

    # addressType specifies the type of address carried by this EndpointSlice.
    # All addresses in this slice must be the same type.
    # Default is IP
    @typechecked
    def addressType(self) -> Optional[AddressType]:
        if "addressType" in self._kwargs:
            return self._kwargs["addressType"]
        if "addressType" in self._context and check_return_type(
            self._context["addressType"]
        ):
            return self._context["addressType"]
        return AddressType["IP"]

    # endpoints is a list of unique endpoints in this slice. Each slice may
    # include a maximum of 1000 endpoints.
    # +listType=atomic
    @typechecked
    def endpoints(self) -> List[Endpoint]:
        if "endpoints" in self._kwargs:
            return self._kwargs["endpoints"]
        if "endpoints" in self._context and check_return_type(
            self._context["endpoints"]
        ):
            return self._context["endpoints"]
        return []

    # ports specifies the list of network ports exposed by each endpoint in
    # this slice. Each port must have a unique name. When ports is empty, it
    # indicates that there are no defined ports. When a port is defined with a
    # nil port value, it indicates "all ports". Each slice may include a
    # maximum of 100 ports.
    # +listType=atomic
    @typechecked
    def ports(self) -> List[EndpointPort]:
        if "ports" in self._kwargs:
            return self._kwargs["ports"]
        if "ports" in self._context and check_return_type(self._context["ports"]):
            return self._context["ports"]
        return []
