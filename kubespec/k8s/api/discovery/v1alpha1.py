# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# AddressType represents the type of address referred to by an endpoint.
AddressType = base.Enum(
    "AddressType",
    {
        # IP represents an IP Address.
        "IP": "IP"
    },
)


class EndpointConditions(types.Object):
    """
    EndpointConditions represents the current condition of an endpoint.
    """

    @context.scoped
    @typechecked
    def __init__(self, ready: bool = None):
        super().__init__()
        self.__ready = ready

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ready = self.ready()
        check_type("ready", ready, Optional[bool])
        if ready is not None:  # omit empty
            v["ready"] = ready
        return v

    def ready(self) -> Optional[bool]:
        """
        ready indicates that this endpoint is prepared to receive traffic,
        according to whatever system is managing the endpoint. A nil value
        indicates an unknown state. In most cases consumers should interpret this
        unknown state as ready.
        """
        return self.__ready


class Endpoint(types.Object):
    """
    Endpoint represents a single logical "backend" implementing a service.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        addresses: List[str] = None,
        conditions: "EndpointConditions" = None,
        hostname: str = None,
        targetRef: "corev1.ObjectReference" = None,
        topology: Dict[str, str] = None,
    ):
        super().__init__()
        self.__addresses = addresses if addresses is not None else []
        self.__conditions = (
            conditions if conditions is not None else EndpointConditions()
        )
        self.__hostname = hostname
        self.__targetRef = targetRef
        self.__topology = topology if topology is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        addresses = self.addresses()
        check_type("addresses", addresses, List[str])
        v["addresses"] = addresses
        conditions = self.conditions()
        check_type("conditions", conditions, Optional["EndpointConditions"])
        v["conditions"] = conditions
        hostname = self.hostname()
        check_type("hostname", hostname, Optional[str])
        if hostname is not None:  # omit empty
            v["hostname"] = hostname
        targetRef = self.targetRef()
        check_type("targetRef", targetRef, Optional["corev1.ObjectReference"])
        if targetRef is not None:  # omit empty
            v["targetRef"] = targetRef
        topology = self.topology()
        check_type("topology", topology, Optional[Dict[str, str]])
        if topology:  # omit empty
            v["topology"] = topology
        return v

    def addresses(self) -> List[str]:
        """
        addresses of this endpoint. The contents of this field are interpreted
        according to the corresponding EndpointSlice addressType field. This
        allows for cases like dual-stack (IPv4 and IPv6) networking. Consumers
        (e.g. kube-proxy) must handle different types of addresses in the context
        of their own capabilities. This must contain at least one address but no
        more than 100.
        +listType=set
        """
        return self.__addresses

    def conditions(self) -> Optional["EndpointConditions"]:
        """
        conditions contains information about the current status of the endpoint.
        """
        return self.__conditions

    def hostname(self) -> Optional[str]:
        """
        hostname of this endpoint. This field may be used by consumers of
        endpoints to distinguish endpoints from each other (e.g. in DNS names).
        Multiple endpoints which use the same hostname should be considered
        fungible (e.g. multiple A values in DNS). Must pass DNS Label (RFC 1123)
        validation.
        """
        return self.__hostname

    def targetRef(self) -> Optional["corev1.ObjectReference"]:
        """
        targetRef is a reference to a Kubernetes object that represents this
        endpoint.
        """
        return self.__targetRef

    def topology(self) -> Optional[Dict[str, str]]:
        """
        topology contains arbitrary topology information associated with the
        endpoint. These key/value pairs must conform with the label format.
        https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
        Topology may include a maximum of 16 key/value pairs. This includes, but
        is not limited to the following well known keys:
        * kubernetes.io/hostname: the value indicates the hostname of the node
          where the endpoint is located. This should match the corresponding
          node label.
        * topology.kubernetes.io/zone: the value indicates the zone where the
          endpoint is located. This should match the corresponding node label.
        * topology.kubernetes.io/region: the value indicates the region where the
          endpoint is located. This should match the corresponding node label.
        """
        return self.__topology


class EndpointPort(types.Object):
    """
    EndpointPort represents a Port used by an EndpointSlice
    """

    @context.scoped
    @typechecked
    def __init__(
        self, name: str = None, protocol: corev1.Protocol = None, port: int = None
    ):
        super().__init__()
        self.__name = name
        self.__protocol = protocol if protocol is not None else corev1.Protocol["TCP"]
        self.__port = port

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, Optional[str])
        if name is not None:  # omit empty
            v["name"] = name
        protocol = self.protocol()
        check_type("protocol", protocol, Optional[corev1.Protocol])
        if protocol is not None:  # omit empty
            v["protocol"] = protocol
        port = self.port()
        check_type("port", port, Optional[int])
        if port is not None:  # omit empty
            v["port"] = port
        return v

    def name(self) -> Optional[str]:
        """
        The name of this port. All ports in an EndpointSlice must have a unique
        name. If the EndpointSlice is dervied from a Kubernetes service, this
        corresponds to the Service.ports[].name.
        Name must either be an empty string or pass IANA_SVC_NAME validation:
        * must be no more than 15 characters long
        * may contain only [-a-z0-9]
        * must contain at least one letter [a-z]
        * it must not start or end with a hyphen, nor contain adjacent hyphens
        Default is empty string.
        """
        return self.__name

    def protocol(self) -> Optional[corev1.Protocol]:
        """
        The IP protocol for this port.
        Must be UDP, TCP, or SCTP.
        Default is TCP.
        """
        return self.__protocol

    def port(self) -> Optional[int]:
        """
        The port number of the endpoint.
        If this is not specified, ports are not restricted and must be
        interpreted in the context of the specific consumer.
        """
        return self.__port


class EndpointSlice(base.TypedObject, base.NamespacedMetadataObject):
    """
    EndpointSlice represents a subset of the endpoints that implement a service.
    For a given service there may be multiple EndpointSlice objects, selected by
    labels, which must be joined to produce the full set of endpoints.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        addressType: AddressType = None,
        endpoints: List["Endpoint"] = None,
        ports: List["EndpointPort"] = None,
    ):
        super().__init__(
            apiVersion="discovery.k8s.io/v1alpha1",
            kind="EndpointSlice",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__addressType = (
            addressType if addressType is not None else AddressType["IP"]
        )
        self.__endpoints = endpoints if endpoints is not None else []
        self.__ports = ports if ports is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        addressType = self.addressType()
        check_type("addressType", addressType, Optional[AddressType])
        v["addressType"] = addressType
        endpoints = self.endpoints()
        check_type("endpoints", endpoints, List["Endpoint"])
        v["endpoints"] = endpoints
        ports = self.ports()
        check_type("ports", ports, List["EndpointPort"])
        v["ports"] = ports
        return v

    def addressType(self) -> Optional[AddressType]:
        """
        addressType specifies the type of address carried by this EndpointSlice.
        All addresses in this slice must be the same type.
        Default is IP
        """
        return self.__addressType

    def endpoints(self) -> List["Endpoint"]:
        """
        endpoints is a list of unique endpoints in this slice. Each slice may
        include a maximum of 1000 endpoints.
        +listType=atomic
        """
        return self.__endpoints

    def ports(self) -> List["EndpointPort"]:
        """
        ports specifies the list of network ports exposed by each endpoint in
        this slice. Each port must have a unique name. When ports is empty, it
        indicates that there are no defined ports. When a port is defined with a
        nil port value, it indicates "all ports". Each slice may include a
        maximum of 100 ports.
        +listType=atomic
        """
        return self.__ports
