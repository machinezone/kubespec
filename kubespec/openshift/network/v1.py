# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


# EgressNetworkPolicyRuleType indicates whether an EgressNetworkPolicyRule allows or denies traffic
EgressNetworkPolicyRuleType = base.Enum(
    "EgressNetworkPolicyRuleType", {"Allow": "Allow", "Deny": "Deny"}
)


class ClusterNetworkEntry(types.Object):
    """
    ClusterNetworkEntry defines an individual cluster network. The CIDRs cannot overlap with other cluster network CIDRs, CIDRs reserved for external ips, CIDRs reserved for service networks, and CIDRs reserved for ingress ips.
    """

    @context.scoped
    @typechecked
    def __init__(self, cidr: str = "", host_subnet_length: int = 0):
        super().__init__()
        self.__cidr = cidr
        self.__host_subnet_length = host_subnet_length

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cidr = self.cidr()
        check_type("cidr", cidr, str)
        v["CIDR"] = cidr
        host_subnet_length = self.host_subnet_length()
        check_type("host_subnet_length", host_subnet_length, int)
        v["hostSubnetLength"] = host_subnet_length
        return v

    def cidr(self) -> str:
        """
        CIDR defines the total range of a cluster networks address space.
        """
        return self.__cidr

    def host_subnet_length(self) -> int:
        """
        HostSubnetLength is the number of bits of the accompanying CIDR address to allocate to each node. eg, 8 would mean that each node would have a /24 slice of the overlay network for its pods.
        """
        return self.__host_subnet_length


class ClusterNetwork(base.TypedObject, base.MetadataObject):
    """
    ClusterNetwork describes the cluster network. There is normally only one object of this type,
    named "default", which is created by the SDN network plugin based on the master configuration
    when the cluster is brought up for the first time.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        network: str = None,
        hostsubnetlength: int = None,
        service_network: str = "",
        plugin_name: str = None,
        cluster_networks: List["ClusterNetworkEntry"] = None,
        vxlan_port: int = None,
        mtu: int = None,
    ):
        super().__init__(
            api_version="network.openshift.io/v1",
            kind="ClusterNetwork",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__network = network
        self.__hostsubnetlength = hostsubnetlength
        self.__service_network = service_network
        self.__plugin_name = plugin_name
        self.__cluster_networks = (
            cluster_networks if cluster_networks is not None else []
        )
        self.__vxlan_port = vxlan_port
        self.__mtu = mtu

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        network = self.network()
        check_type("network", network, Optional[str])
        if network:  # omit empty
            v["network"] = network
        hostsubnetlength = self.hostsubnetlength()
        check_type("hostsubnetlength", hostsubnetlength, Optional[int])
        if hostsubnetlength:  # omit empty
            v["hostsubnetlength"] = hostsubnetlength
        service_network = self.service_network()
        check_type("service_network", service_network, str)
        v["serviceNetwork"] = service_network
        plugin_name = self.plugin_name()
        check_type("plugin_name", plugin_name, Optional[str])
        if plugin_name:  # omit empty
            v["pluginName"] = plugin_name
        cluster_networks = self.cluster_networks()
        check_type("cluster_networks", cluster_networks, List["ClusterNetworkEntry"])
        v["clusterNetworks"] = cluster_networks
        vxlan_port = self.vxlan_port()
        check_type("vxlan_port", vxlan_port, Optional[int])
        if vxlan_port is not None:  # omit empty
            v["vxlanPort"] = vxlan_port
        mtu = self.mtu()
        check_type("mtu", mtu, Optional[int])
        if mtu is not None:  # omit empty
            v["mtu"] = mtu
        return v

    def network(self) -> Optional[str]:
        """
        Network is a CIDR string specifying the global overlay network's L3 space
        """
        return self.__network

    def hostsubnetlength(self) -> Optional[int]:
        """
        HostSubnetLength is the number of bits of network to allocate to each node. eg, 8 would mean that each node would have a /24 slice of the overlay network for its pods
        """
        return self.__hostsubnetlength

    def service_network(self) -> str:
        """
        ServiceNetwork is the CIDR range that Service IP addresses are allocated from
        """
        return self.__service_network

    def plugin_name(self) -> Optional[str]:
        """
        PluginName is the name of the network plugin being used
        """
        return self.__plugin_name

    def cluster_networks(self) -> List["ClusterNetworkEntry"]:
        """
        ClusterNetworks is a list of ClusterNetwork objects that defines the global overlay network's L3 space by specifying a set of CIDR and netmasks that the SDN can allocate addresses from.
        """
        return self.__cluster_networks

    def vxlan_port(self) -> Optional[int]:
        """
        VXLANPort sets the VXLAN destination port used by the cluster. It is set by the master configuration file on startup and cannot be edited manually. Valid values for VXLANPort are integers 1-65535 inclusive and if unset defaults to 4789. Changing VXLANPort allows users to resolve issues between openshift SDN and other software trying to use the same VXLAN destination port.
        """
        return self.__vxlan_port

    def mtu(self) -> Optional[int]:
        """
        MTU is the MTU for the overlay network. This should be 50 less than the MTU of the network connecting the nodes. It is normally autodetected by the cluster network operator.
        """
        return self.__mtu


class EgressNetworkPolicyPeer(types.Object):
    """
    EgressNetworkPolicyPeer specifies a target to apply egress network policy to
    """

    @context.scoped
    @typechecked
    def __init__(self, cidr_selector: str = None, dns_name: str = None):
        super().__init__()
        self.__cidr_selector = cidr_selector
        self.__dns_name = dns_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cidr_selector = self.cidr_selector()
        check_type("cidr_selector", cidr_selector, Optional[str])
        if cidr_selector:  # omit empty
            v["cidrSelector"] = cidr_selector
        dns_name = self.dns_name()
        check_type("dns_name", dns_name, Optional[str])
        if dns_name:  # omit empty
            v["dnsName"] = dns_name
        return v

    def cidr_selector(self) -> Optional[str]:
        """
        cidrSelector is the CIDR range to allow/deny traffic to. If this is set, dnsName must be unset
        """
        return self.__cidr_selector

    def dns_name(self) -> Optional[str]:
        """
        dnsName is the domain name to allow/deny traffic to. If this is set, cidrSelector must be unset
        """
        return self.__dns_name


class EgressNetworkPolicyRule(types.Object):
    """
    EgressNetworkPolicyRule contains a single egress network policy rule
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: EgressNetworkPolicyRuleType = None,
        to: "EgressNetworkPolicyPeer" = None,
    ):
        super().__init__()
        self.__type = type
        self.__to = to if to is not None else EgressNetworkPolicyPeer()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, EgressNetworkPolicyRuleType)
        v["type"] = type
        to = self.to()
        check_type("to", to, "EgressNetworkPolicyPeer")
        v["to"] = to
        return v

    def type(self) -> EgressNetworkPolicyRuleType:
        """
        type marks this as an "Allow" or "Deny" rule
        """
        return self.__type

    def to(self) -> "EgressNetworkPolicyPeer":
        """
        to is the target that traffic is allowed/denied to
        """
        return self.__to


class EgressNetworkPolicySpec(types.Object):
    """
    EgressNetworkPolicySpec provides a list of policies on outgoing network traffic
    """

    @context.scoped
    @typechecked
    def __init__(self, egress: List["EgressNetworkPolicyRule"] = None):
        super().__init__()
        self.__egress = egress if egress is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        egress = self.egress()
        check_type("egress", egress, List["EgressNetworkPolicyRule"])
        v["egress"] = egress
        return v

    def egress(self) -> List["EgressNetworkPolicyRule"]:
        """
        egress contains the list of egress policy rules
        """
        return self.__egress


class EgressNetworkPolicy(base.TypedObject, base.NamespacedMetadataObject):
    """
    EgressNetworkPolicy describes the current egress network policy for a Namespace. When using
    the 'redhat/openshift-ovs-multitenant' network plugin, traffic from a pod to an IP address
    outside the cluster will be checked against each EgressNetworkPolicyRule in the pod's
    namespace's EgressNetworkPolicy, in order. If no rule matches (or no EgressNetworkPolicy
    is present) then the traffic will be allowed by default.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "EgressNetworkPolicySpec" = None,
    ):
        super().__init__(
            api_version="network.openshift.io/v1",
            kind="EgressNetworkPolicy",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else EgressNetworkPolicySpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "EgressNetworkPolicySpec")
        v["spec"] = spec
        return v

    def spec(self) -> "EgressNetworkPolicySpec":
        """
        spec is the specification of the current egress network policy
        """
        return self.__spec


class HostSubnet(base.TypedObject, base.MetadataObject):
    """
    HostSubnet describes the container subnet network on a node. The HostSubnet object must have the
    same name as the Node object it corresponds to.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        host: str = "",
        host_ip: str = "",
        subnet: str = "",
        egress_ips: List[str] = None,
        egress_cidrs: List[str] = None,
    ):
        super().__init__(
            api_version="network.openshift.io/v1",
            kind="HostSubnet",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__host = host
        self.__host_ip = host_ip
        self.__subnet = subnet
        self.__egress_ips = egress_ips if egress_ips is not None else []
        self.__egress_cidrs = egress_cidrs if egress_cidrs is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        host = self.host()
        check_type("host", host, str)
        v["host"] = host
        host_ip = self.host_ip()
        check_type("host_ip", host_ip, str)
        v["hostIP"] = host_ip
        subnet = self.subnet()
        check_type("subnet", subnet, str)
        v["subnet"] = subnet
        egress_ips = self.egress_ips()
        check_type("egress_ips", egress_ips, Optional[List[str]])
        if egress_ips:  # omit empty
            v["egressIPs"] = egress_ips
        egress_cidrs = self.egress_cidrs()
        check_type("egress_cidrs", egress_cidrs, Optional[List[str]])
        if egress_cidrs:  # omit empty
            v["egressCIDRs"] = egress_cidrs
        return v

    def host(self) -> str:
        """
        Host is the name of the node. (This is the same as the object's name, but both fields must be set.)
        """
        return self.__host

    def host_ip(self) -> str:
        """
        HostIP is the IP address to be used as a VTEP by other nodes in the overlay network
        """
        return self.__host_ip

    def subnet(self) -> str:
        """
        Subnet is the CIDR range of the overlay network assigned to the node for its pods
        """
        return self.__subnet

    def egress_ips(self) -> Optional[List[str]]:
        """
        EgressIPs is the list of automatic egress IP addresses currently hosted by this node.
        If EgressCIDRs is empty, this can be set by hand; if EgressCIDRs is set then the
        master will overwrite the value here with its own allocation of egress IPs.
        """
        return self.__egress_ips

    def egress_cidrs(self) -> Optional[List[str]]:
        """
        EgressCIDRs is the list of CIDR ranges available for automatically assigning
        egress IPs to this node from. If this field is set then EgressIPs should be
        treated as read-only.
        """
        return self.__egress_cidrs


class NetNamespace(base.TypedObject, base.MetadataObject):
    """
    NetNamespace describes a single isolated network. When using the redhat/openshift-ovs-multitenant
    plugin, every Namespace will have a corresponding NetNamespace object with the same name.
    (When using redhat/openshift-ovs-subnet, NetNamespaces are not used.)
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        netname: str = "",
        netid: int = 0,
        egress_ips: List[str] = None,
    ):
        super().__init__(
            api_version="network.openshift.io/v1",
            kind="NetNamespace",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__netname = netname
        self.__netid = netid
        self.__egress_ips = egress_ips if egress_ips is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        netname = self.netname()
        check_type("netname", netname, str)
        v["netname"] = netname
        netid = self.netid()
        check_type("netid", netid, int)
        v["netid"] = netid
        egress_ips = self.egress_ips()
        check_type("egress_ips", egress_ips, Optional[List[str]])
        if egress_ips:  # omit empty
            v["egressIPs"] = egress_ips
        return v

    def netname(self) -> str:
        """
        NetName is the name of the network namespace. (This is the same as the object's name, but both fields must be set.)
        """
        return self.__netname

    def netid(self) -> int:
        """
        NetID is the network identifier of the network namespace assigned to each overlay network packet. This can be manipulated with the "oc adm pod-network" commands.
        """
        return self.__netid

    def egress_ips(self) -> Optional[List[str]]:
        """
        EgressIPs is a list of reserved IPs that will be used as the source for external traffic coming from pods in this namespace. (If empty, external traffic will be masqueraded to Node IPs.)
        """
        return self.__egress_ips
