# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional, Union

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec.k8s.apimachinery.meta import v1 as metav1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# Policy Type string describes the NetworkPolicy type
# This type is beta-level in 1.8
PolicyType = base.Enum(
    "PolicyType",
    {
        # Egress is a NetworkPolicy that affects egress traffic on selected pods
        "Egress": "Egress",
        # Ingress is a NetworkPolicy that affects ingress traffic on selected pods
        "Ingress": "Ingress",
    },
)


class IPBlock(types.Object):
    """
    IPBlock describes a particular CIDR (Ex. "192.168.1.1/24") that is allowed to the pods
    matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs that should
    not be included within this rule.
    """

    @context.scoped
    @typechecked
    def __init__(self, cidr: str = "", except_: List[str] = None):
        super().__init__()
        self.__cidr = cidr
        self.__except_ = except_ if except_ is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cidr = self.cidr()
        check_type("cidr", cidr, str)
        v["cidr"] = cidr
        except_ = self.except_()
        check_type("except_", except_, Optional[List[str]])
        if except_:  # omit empty
            v["except"] = except_
        return v

    def cidr(self) -> str:
        """
        CIDR is a string representing the IP Block
        Valid examples are "192.168.1.1/24"
        """
        return self.__cidr

    def except_(self) -> Optional[List[str]]:
        """
        Except is a slice of CIDRs that should not be included within an IP Block
        Valid examples are "192.168.1.1/24"
        Except values will be rejected if they are outside the CIDR range
        """
        return self.__except_


class NetworkPolicyPeer(types.Object):
    """
    NetworkPolicyPeer describes a peer to allow traffic from. Only certain combinations of
    fields are allowed
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        podSelector: "metav1.LabelSelector" = None,
        namespaceSelector: "metav1.LabelSelector" = None,
        ipBlock: "IPBlock" = None,
    ):
        super().__init__()
        self.__podSelector = podSelector
        self.__namespaceSelector = namespaceSelector
        self.__ipBlock = ipBlock

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        podSelector = self.podSelector()
        check_type("podSelector", podSelector, Optional["metav1.LabelSelector"])
        if podSelector is not None:  # omit empty
            v["podSelector"] = podSelector
        namespaceSelector = self.namespaceSelector()
        check_type(
            "namespaceSelector", namespaceSelector, Optional["metav1.LabelSelector"]
        )
        if namespaceSelector is not None:  # omit empty
            v["namespaceSelector"] = namespaceSelector
        ipBlock = self.ipBlock()
        check_type("ipBlock", ipBlock, Optional["IPBlock"])
        if ipBlock is not None:  # omit empty
            v["ipBlock"] = ipBlock
        return v

    def podSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        This is a label selector which selects Pods. This field follows standard label
        selector semantics; if present but empty, it selects all pods.
        
        If NamespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
        the Pods matching PodSelector in the Namespaces selected by NamespaceSelector.
        Otherwise it selects the Pods matching PodSelector in the policy's own Namespace.
        """
        return self.__podSelector

    def namespaceSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        Selects Namespaces using cluster-scoped labels. This field follows standard label
        selector semantics; if present but empty, it selects all namespaces.
        
        If PodSelector is also set, then the NetworkPolicyPeer as a whole selects
        the Pods matching PodSelector in the Namespaces selected by NamespaceSelector.
        Otherwise it selects all Pods in the Namespaces selected by NamespaceSelector.
        """
        return self.__namespaceSelector

    def ipBlock(self) -> Optional["IPBlock"]:
        """
        IPBlock defines policy on a particular IPBlock. If this field is set then
        neither of the other fields can be.
        """
        return self.__ipBlock


class NetworkPolicyPort(types.Object):
    """
    NetworkPolicyPort describes a port to allow traffic on
    """

    @context.scoped
    @typechecked
    def __init__(self, protocol: corev1.Protocol = None, port: Union[int, str] = None):
        super().__init__()
        self.__protocol = protocol if protocol is not None else corev1.Protocol["TCP"]
        self.__port = port

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        protocol = self.protocol()
        check_type("protocol", protocol, Optional[corev1.Protocol])
        if protocol is not None:  # omit empty
            v["protocol"] = protocol
        port = self.port()
        check_type("port", port, Optional[Union[int, str]])
        if port is not None:  # omit empty
            v["port"] = port
        return v

    def protocol(self) -> Optional[corev1.Protocol]:
        """
        The protocol (TCP, UDP, or SCTP) which traffic must match. If not specified, this
        field defaults to TCP.
        """
        return self.__protocol

    def port(self) -> Optional[Union[int, str]]:
        """
        The port on the given protocol. This can either be a numerical or named port on
        a pod. If this field is not provided, this matches all port names and numbers.
        """
        return self.__port


class NetworkPolicyEgressRule(types.Object):
    """
    NetworkPolicyEgressRule describes a particular set of traffic that is allowed out of pods
    matched by a NetworkPolicySpec's podSelector. The traffic must match both ports and to.
    This type is beta-level in 1.8
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ports: List["NetworkPolicyPort"] = None,
        to: List["NetworkPolicyPeer"] = None,
    ):
        super().__init__()
        self.__ports = ports if ports is not None else []
        self.__to = to if to is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ports = self.ports()
        check_type("ports", ports, Optional[List["NetworkPolicyPort"]])
        if ports:  # omit empty
            v["ports"] = ports
        to = self.to()
        check_type("to", to, Optional[List["NetworkPolicyPeer"]])
        if to:  # omit empty
            v["to"] = to
        return v

    def ports(self) -> Optional[List["NetworkPolicyPort"]]:
        """
        List of destination ports for outgoing traffic.
        Each item in this list is combined using a logical OR. If this field is
        empty or missing, this rule matches all ports (traffic not restricted by port).
        If this field is present and contains at least one item, then this rule allows
        traffic only if the traffic matches at least one port in the list.
        """
        return self.__ports

    def to(self) -> Optional[List["NetworkPolicyPeer"]]:
        """
        List of destinations for outgoing traffic of pods selected for this rule.
        Items in this list are combined using a logical OR operation. If this field is
        empty or missing, this rule matches all destinations (traffic not restricted by
        destination). If this field is present and contains at least one item, this rule
        allows traffic only if the traffic matches at least one item in the to list.
        """
        return self.__to


class NetworkPolicyIngressRule(types.Object):
    """
    NetworkPolicyIngressRule describes a particular set of traffic that is allowed to the pods
    matched by a NetworkPolicySpec's podSelector. The traffic must match both ports and from.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ports: List["NetworkPolicyPort"] = None,
        from_: List["NetworkPolicyPeer"] = None,
    ):
        super().__init__()
        self.__ports = ports if ports is not None else []
        self.__from_ = from_ if from_ is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ports = self.ports()
        check_type("ports", ports, Optional[List["NetworkPolicyPort"]])
        if ports:  # omit empty
            v["ports"] = ports
        from_ = self.from_()
        check_type("from_", from_, Optional[List["NetworkPolicyPeer"]])
        if from_:  # omit empty
            v["from"] = from_
        return v

    def ports(self) -> Optional[List["NetworkPolicyPort"]]:
        """
        List of ports which should be made accessible on the pods selected for this
        rule. Each item in this list is combined using a logical OR. If this field is
        empty or missing, this rule matches all ports (traffic not restricted by port).
        If this field is present and contains at least one item, then this rule allows
        traffic only if the traffic matches at least one port in the list.
        """
        return self.__ports

    def from_(self) -> Optional[List["NetworkPolicyPeer"]]:
        """
        List of sources which should be able to access the pods selected for this rule.
        Items in this list are combined using a logical OR operation. If this field is
        empty or missing, this rule matches all sources (traffic not restricted by
        source). If this field is present and contains at least one item, this rule
        allows traffic only if the traffic matches at least one item in the from list.
        """
        return self.__from_


class NetworkPolicySpec(types.Object):
    """
    NetworkPolicySpec provides the specification of a NetworkPolicy
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        podSelector: "metav1.LabelSelector" = None,
        ingress: List["NetworkPolicyIngressRule"] = None,
        egress: List["NetworkPolicyEgressRule"] = None,
        policyTypes: List[PolicyType] = None,
    ):
        super().__init__()
        self.__podSelector = (
            podSelector if podSelector is not None else metav1.LabelSelector()
        )
        self.__ingress = ingress if ingress is not None else []
        self.__egress = egress if egress is not None else []
        self.__policyTypes = policyTypes if policyTypes is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        podSelector = self.podSelector()
        check_type("podSelector", podSelector, "metav1.LabelSelector")
        v["podSelector"] = podSelector
        ingress = self.ingress()
        check_type("ingress", ingress, Optional[List["NetworkPolicyIngressRule"]])
        if ingress:  # omit empty
            v["ingress"] = ingress
        egress = self.egress()
        check_type("egress", egress, Optional[List["NetworkPolicyEgressRule"]])
        if egress:  # omit empty
            v["egress"] = egress
        policyTypes = self.policyTypes()
        check_type("policyTypes", policyTypes, Optional[List[PolicyType]])
        if policyTypes:  # omit empty
            v["policyTypes"] = policyTypes
        return v

    def podSelector(self) -> "metav1.LabelSelector":
        """
        Selects the pods to which this NetworkPolicy object applies. The array of
        ingress rules is applied to any pods selected by this field. Multiple network
        policies can select the same set of pods. In this case, the ingress rules for
        each are combined additively. This field is NOT optional and follows standard
        label selector semantics. An empty podSelector matches all pods in this
        namespace.
        """
        return self.__podSelector

    def ingress(self) -> Optional[List["NetworkPolicyIngressRule"]]:
        """
        List of ingress rules to be applied to the selected pods. Traffic is allowed to
        a pod if there are no NetworkPolicies selecting the pod
        (and cluster policy otherwise allows the traffic), OR if the traffic source is
        the pod's local node, OR if the traffic matches at least one ingress rule
        across all of the NetworkPolicy objects whose podSelector matches the pod. If
        this field is empty then this NetworkPolicy does not allow any traffic (and serves
        solely to ensure that the pods it selects are isolated by default)
        """
        return self.__ingress

    def egress(self) -> Optional[List["NetworkPolicyEgressRule"]]:
        """
        List of egress rules to be applied to the selected pods. Outgoing traffic is
        allowed if there are no NetworkPolicies selecting the pod (and cluster policy
        otherwise allows the traffic), OR if the traffic matches at least one egress rule
        across all of the NetworkPolicy objects whose podSelector matches the pod. If
        this field is empty then this NetworkPolicy limits all outgoing traffic (and serves
        solely to ensure that the pods it selects are isolated by default).
        This field is beta-level in 1.8
        """
        return self.__egress

    def policyTypes(self) -> Optional[List[PolicyType]]:
        """
        List of rule types that the NetworkPolicy relates to.
        Valid options are "Ingress", "Egress", or "Ingress,Egress".
        If this field is not specified, it will default based on the existence of Ingress or Egress rules;
        policies that contain an Egress section are assumed to affect Egress, and all policies
        (whether or not they contain an Ingress section) are assumed to affect Ingress.
        If you want to write an egress-only policy, you must explicitly specify policyTypes [ "Egress" ].
        Likewise, if you want to write a policy that specifies that no egress is allowed,
        you must specify a policyTypes value that include "Egress" (since such a policy would not include
        an Egress section and would otherwise default to just [ "Ingress" ]).
        This field is beta-level in 1.8
        """
        return self.__policyTypes


class NetworkPolicy(base.TypedObject, base.NamespacedMetadataObject):
    """
    NetworkPolicy describes what network traffic is allowed for a set of Pods
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "NetworkPolicySpec" = None,
    ):
        super().__init__(
            apiVersion="networking.k8s.io/v1",
            kind="NetworkPolicy",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else NetworkPolicySpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["NetworkPolicySpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["NetworkPolicySpec"]:
        """
        Specification of the desired behavior for this NetworkPolicy.
        """
        return self.__spec
