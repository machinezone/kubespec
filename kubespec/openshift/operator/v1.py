# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.meta import v1 as metav1
from kubespec.openshift.config import v1 as configv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


# Brand is a specific supported brand within the console.
Brand = base.Enum(
    "Brand",
    {
        # Branding for Azure Red Hat OpenShift
        "Azure": "azure",
        # Branding for OpenShift Dedicated
        "Dedicated": "dedicated",
        # Branding for OpenShift Container Platform
        "OCP": "ocp",
        # Branding for The Origin Community Distribution of Kubernetes
        "OKD": "okd",
        # Branding for OpenShift Online
        "Online": "online",
        # Branding for OpenShift
        "OpenShift": "openshift",
    },
)


# EndpointPublishingStrategyType is a way to publish ingress controller endpoints.
EndpointPublishingStrategyType = base.Enum(
    "EndpointPublishingStrategyType",
    {
        # HostNetwork publishes the ingress controller on node ports where the
        # ingress controller is deployed.
        "HostNetwork": "HostNetwork",
        # LoadBalancerService publishes the ingress controller using a Kubernetes
        # LoadBalancer Service.
        "LoadBalancerService": "LoadBalancerService",
        # NodePortService publishes the ingress controller using a Kubernetes NodePort Service.
        "NodePortService": "NodePortService",
        # Private does not publish the ingress controller.
        "Private": "Private",
    },
)


# IPAMType describes the IP address management type to configure
IPAMType = base.Enum(
    "IPAMType",
    {
        # DHCP uses DHCP for IP management
        "DHCP": "DHCP",
        # Static uses static IP
        "Static": "Static",
    },
)


# LoadBalancerScope is the scope at which a load balancer is exposed.
LoadBalancerScope = base.Enum(
    "LoadBalancerScope",
    {
        # External is a load balancer that is exposed on the
        # cluster's public network (which is typically on the Internet).
        "External": "External",
        # Internal is a load balancer that is exposed only on the
        # cluster's private network.
        "Internal": "Internal",
    },
)


LogLevel = base.Enum(
    "LogLevel",
    {
        # Debug is used when something went wrong.  Even common operations may be logged, and less helpful but more quantity of notices.  In kube, this is probably glog=4.
        "Debug": "Debug",
        # Normal is the default.  Normal, working log information, everything is fine, but helpful notices for auditing or common operations.  In kube, this is probably glog=2.
        "Normal": "Normal",
        # Trace is used when something went really badly and even more verbose logs are needed.  Logging every function call as part of a common operation, to tracing execution of a query.  In kube, this is probably glog=6.
        "Trace": "Trace",
        # TraceAll is used when something is broken at the level of API content/decoding.  It will dump complete body content.  If you turn this on in a production cluster
        # prepare from serious performance issues and massive amounts of logs.  In kube, this is probably glog=8.
        "TraceAll": "TraceAll",
    },
)


# MacvlanMode is the Mode of macvlan. The value are lowercase to match the CNI plugin
# config values. See "man ip-link" for its detail.
MacvlanMode = base.Enum(
    "MacvlanMode",
    {
        # Bridge is the macvlan with thin bridge function.
        "Bridge": "Bridge",
        # Passthru
        "Passthru": "Passthru",
        # Private
        "Private": "Private",
        # VEPA is used with Virtual Ethernet Port Aggregator
        # (802.1qbg) swtich
        "VEPA": "VEPA",
    },
)


ManagementState = base.Enum(
    "ManagementState",
    {
        # Force means that the operator is actively managing its resources but will not block an upgrade
        # if unmet prereqs exist. This state puts the operator at risk for unsuccessful upgrades
        "Force": "Force",
        # Managed means that the operator is actively managing its resources and trying to keep the component active.
        # It will only upgrade the component if it is safe to do so
        "Managed": "Managed",
        # Removed means that the operator is actively managing its resources and trying to remove all traces of the component
        # Some operators (like kube-apiserver-operator) might not support this management state as removing the API server will
        # brick the cluster.
        "Removed": "Removed",
        # Unmanaged means that the operator will not take any action related to the component
        # Some operators might not support this management state as it might damage the cluster and lead to manual recovery.
        "Unmanaged": "Unmanaged",
    },
)


# NamespaceOwnershipCheck is a route admission policy component that describes
# how host name claims across namespaces should be handled.
NamespaceOwnershipCheck = base.Enum(
    "NamespaceOwnershipCheck",
    {
        # InterNamespaceAllowed allows routes to claim different paths of the same host name across namespaces.
        "InterNamespaceAllowed": "InterNamespaceAllowed",
        # Strict does not allow routes to claim the same host name across namespaces.
        "Strict": "Strict",
    },
)


# NetworkType describes the network plugin type to configure
NetworkType = base.Enum(
    "NetworkType",
    {
        # Kuryr means the kuryr-kubernetes project will be configured.
        "Kuryr": "Kuryr",
        # OVNKubernetes means the ovn-kubernetes project will be configured.
        # This is currently not implemented.
        "OVNKubernetes": "OVNKubernetes",
        # OpenShiftSDN means the openshift-sdn plugin will be configured
        "OpenShiftSDN": "OpenShiftSDN",
        # Raw
        "Raw": "Raw",
        # SimpleMacvlan
        "SimpleMacvlan": "SimpleMacvlan",
    },
)


# SDNMode is the Mode the openshift-sdn plugin is in
SDNMode = base.Enum(
    "SDNMode",
    {
        # Multitenant is a special "multitenant" mode that offers limited
        # isolation configuration between namespaces
        "Multitenant": "Multitenant",
        # NetworkPolicy is a full NetworkPolicy implementation that allows
        # for sophisticated network isolation and segmenting. This is the default.
        "NetworkPolicy": "NetworkPolicy",
        # Subnet is a simple mode that offers no isolation between pods
        "Subnet": "Subnet",
    },
)


class StaticIPAMAddresses(types.Object):
    """
    StaticIPAMAddresses provides IP address and Gateway for static IPAM addresses
    """

    @context.scoped
    @typechecked
    def __init__(self, address: str = "", gateway: str = None):
        super().__init__()
        self.__address = address
        self.__gateway = gateway

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        address = self.address()
        check_type("address", address, str)
        v["address"] = address
        gateway = self.gateway()
        check_type("gateway", gateway, Optional[str])
        if gateway:  # omit empty
            v["gateway"] = gateway
        return v

    def address(self) -> str:
        """
        Address is the IP address in CIDR format
        """
        return self.__address

    def gateway(self) -> Optional[str]:
        """
        Gateway is IP inside of subnet to designate as the gateway
        """
        return self.__gateway


class StaticIPAMDNS(types.Object):
    """
    StaticIPAMDNS provides DNS related information for static IPAM
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        nameservers: List[str] = None,
        domain: str = None,
        search: List[str] = None,
    ):
        super().__init__()
        self.__nameservers = nameservers if nameservers is not None else []
        self.__domain = domain
        self.__search = search if search is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        nameservers = self.nameservers()
        check_type("nameservers", nameservers, Optional[List[str]])
        if nameservers:  # omit empty
            v["nameservers"] = nameservers
        domain = self.domain()
        check_type("domain", domain, Optional[str])
        if domain:  # omit empty
            v["domain"] = domain
        search = self.search()
        check_type("search", search, Optional[List[str]])
        if search:  # omit empty
            v["search"] = search
        return v

    def nameservers(self) -> Optional[List[str]]:
        """
        Nameservers points DNS servers for IP lookup
        """
        return self.__nameservers

    def domain(self) -> Optional[str]:
        """
        Domain configures the domainname the local domain used for short hostname lookups
        """
        return self.__domain

    def search(self) -> Optional[List[str]]:
        """
        Search configures priority ordered search domains for short hostname lookups
        """
        return self.__search


class StaticIPAMRoutes(types.Object):
    """
    StaticIPAMRoutes provides Destination/Gateway pairs for static IPAM routes
    """

    @context.scoped
    @typechecked
    def __init__(self, destination: str = "", gateway: str = None):
        super().__init__()
        self.__destination = destination
        self.__gateway = gateway

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        destination = self.destination()
        check_type("destination", destination, str)
        v["destination"] = destination
        gateway = self.gateway()
        check_type("gateway", gateway, Optional[str])
        if gateway:  # omit empty
            v["gateway"] = gateway
        return v

    def destination(self) -> str:
        """
        Destination points the IP route destination
        """
        return self.__destination

    def gateway(self) -> Optional[str]:
        """
        Gateway is the route's next-hop IP address
        If unset, a default gateway is assumed (as determined by the CNI plugin).
        """
        return self.__gateway


class StaticIPAMConfig(types.Object):
    """
    StaticIPAMConfig contains configurations for static IPAM (IP Address Management)
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        addresses: List["StaticIPAMAddresses"] = None,
        routes: List["StaticIPAMRoutes"] = None,
        dns: "StaticIPAMDNS" = None,
    ):
        super().__init__()
        self.__addresses = addresses if addresses is not None else []
        self.__routes = routes if routes is not None else []
        self.__dns = dns

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        addresses = self.addresses()
        check_type("addresses", addresses, Optional[List["StaticIPAMAddresses"]])
        if addresses:  # omit empty
            v["addresses"] = addresses
        routes = self.routes()
        check_type("routes", routes, Optional[List["StaticIPAMRoutes"]])
        if routes:  # omit empty
            v["routes"] = routes
        dns = self.dns()
        check_type("dns", dns, Optional["StaticIPAMDNS"])
        if dns is not None:  # omit empty
            v["dns"] = dns
        return v

    def addresses(self) -> Optional[List["StaticIPAMAddresses"]]:
        """
        Addresses configures IP address for the interface
        """
        return self.__addresses

    def routes(self) -> Optional[List["StaticIPAMRoutes"]]:
        """
        Routes configures IP routes for the interface
        """
        return self.__routes

    def dns(self) -> Optional["StaticIPAMDNS"]:
        """
        DNS configures DNS for the interface
        """
        return self.__dns


class IPAMConfig(types.Object):
    """
    IPAMConfig contains configurations for IPAM (IP Address Management)
    """

    @context.scoped
    @typechecked
    def __init__(
        self, type: IPAMType = None, static_ipam_config: "StaticIPAMConfig" = None
    ):
        super().__init__()
        self.__type = type
        self.__static_ipam_config = static_ipam_config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, IPAMType)
        v["type"] = type
        static_ipam_config = self.static_ipam_config()
        check_type(
            "static_ipam_config", static_ipam_config, Optional["StaticIPAMConfig"]
        )
        if static_ipam_config is not None:  # omit empty
            v["staticIPAMConfig"] = static_ipam_config
        return v

    def type(self) -> IPAMType:
        """
        Type is the type of IPAM module will be used for IP Address Management(IPAM).
        The supported values are IPAMTypeDHCP, IPAMTypeStatic
        """
        return self.__type

    def static_ipam_config(self) -> Optional["StaticIPAMConfig"]:
        """
        StaticIPAMConfig configures the static IP address in case of type:IPAMTypeStatic
        """
        return self.__static_ipam_config


class SimpleMacvlanConfig(types.Object):
    """
    SimpleMacvlanConfig contains configurations for macvlan interface.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        master: str = None,
        ipam_config: "IPAMConfig" = None,
        mode: MacvlanMode = None,
        mtu: int = None,
    ):
        super().__init__()
        self.__master = master
        self.__ipam_config = ipam_config
        self.__mode = mode
        self.__mtu = mtu

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        master = self.master()
        check_type("master", master, Optional[str])
        if master:  # omit empty
            v["master"] = master
        ipam_config = self.ipam_config()
        check_type("ipam_config", ipam_config, Optional["IPAMConfig"])
        if ipam_config is not None:  # omit empty
            v["ipamConfig"] = ipam_config
        mode = self.mode()
        check_type("mode", mode, Optional[MacvlanMode])
        if mode:  # omit empty
            v["mode"] = mode
        mtu = self.mtu()
        check_type("mtu", mtu, Optional[int])
        if mtu:  # omit empty
            v["mtu"] = mtu
        return v

    def master(self) -> Optional[str]:
        """
        master is the host interface to create the macvlan interface from.
        If not specified, it will be default route interface
        """
        return self.__master

    def ipam_config(self) -> Optional["IPAMConfig"]:
        """
        IPAMConfig configures IPAM module will be used for IP Address Management (IPAM).
        """
        return self.__ipam_config

    def mode(self) -> Optional[MacvlanMode]:
        """
        mode is the macvlan mode: bridge, private, vepa, passthru. The default is bridge
        """
        return self.__mode

    def mtu(self) -> Optional[int]:
        """
        mtu is the mtu to use for the macvlan interface. if unset, host's
        kernel will select the value.
        """
        return self.__mtu


class AdditionalNetworkDefinition(types.Object):
    """
    AdditionalNetworkDefinition configures an extra network that is available but not
    created by default. Instead, pods must request them by name.
    type must be specified, along with exactly one "Config" that matches the type.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: NetworkType = None,
        name: str = "",
        namespace: str = None,
        raw_cni_config: str = None,
        simple_macvlan_config: "SimpleMacvlanConfig" = None,
    ):
        super().__init__()
        self.__type = type
        self.__name = name
        self.__namespace = namespace
        self.__raw_cni_config = raw_cni_config
        self.__simple_macvlan_config = simple_macvlan_config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, NetworkType)
        v["type"] = type
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        raw_cni_config = self.raw_cni_config()
        check_type("raw_cni_config", raw_cni_config, Optional[str])
        if raw_cni_config:  # omit empty
            v["rawCNIConfig"] = raw_cni_config
        simple_macvlan_config = self.simple_macvlan_config()
        check_type(
            "simple_macvlan_config",
            simple_macvlan_config,
            Optional["SimpleMacvlanConfig"],
        )
        if simple_macvlan_config is not None:  # omit empty
            v["simpleMacvlanConfig"] = simple_macvlan_config
        return v

    def type(self) -> NetworkType:
        """
        type is the type of network
        The supported values are NetworkTypeRaw, NetworkTypeSimpleMacvlan
        """
        return self.__type

    def name(self) -> str:
        """
        name is the name of the network. This will be populated in the resulting CRD
        This must be unique.
        """
        return self.__name

    def namespace(self) -> Optional[str]:
        """
        namespace is the namespace of the network. This will be populated in the resulting CRD
        If not given the network will be created in the default namespace.
        """
        return self.__namespace

    def raw_cni_config(self) -> Optional[str]:
        """
        rawCNIConfig is the raw CNI configuration json to create in the
        NetworkAttachmentDefinition CRD
        """
        return self.__raw_cni_config

    def simple_macvlan_config(self) -> Optional["SimpleMacvlanConfig"]:
        """
        SimpleMacvlanConfig configures the macvlan interface in case of type:NetworkTypeSimpleMacvlan
        """
        return self.__simple_macvlan_config


class OperatorSpec(types.Object):
    """
    OperatorSpec contains common fields operators need.  It is intended to be anonymous included
    inside of the Spec struct for your particular operator.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        management_state: ManagementState = None,
        log_level: LogLevel = None,
        operator_log_level: LogLevel = None,
        unsupported_config_overrides: "runtime.RawExtension" = None,
        observed_config: "runtime.RawExtension" = None,
    ):
        super().__init__()
        self.__management_state = management_state
        self.__log_level = log_level
        self.__operator_log_level = operator_log_level
        self.__unsupported_config_overrides = unsupported_config_overrides
        self.__observed_config = observed_config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        management_state = self.management_state()
        check_type("management_state", management_state, ManagementState)
        v["managementState"] = management_state
        log_level = self.log_level()
        check_type("log_level", log_level, LogLevel)
        v["logLevel"] = log_level
        operator_log_level = self.operator_log_level()
        check_type("operator_log_level", operator_log_level, LogLevel)
        v["operatorLogLevel"] = operator_log_level
        unsupported_config_overrides = self.unsupported_config_overrides()
        check_type(
            "unsupported_config_overrides",
            unsupported_config_overrides,
            "runtime.RawExtension",
        )
        v["unsupportedConfigOverrides"] = unsupported_config_overrides
        observed_config = self.observed_config()
        check_type("observed_config", observed_config, "runtime.RawExtension")
        v["observedConfig"] = observed_config
        return v

    def management_state(self) -> ManagementState:
        """
        managementState indicates whether and how the operator should manage the component
        """
        return self.__management_state

    def log_level(self) -> LogLevel:
        """
        logLevel is an intent based logging for an overall component.  It does not give fine grained control, but it is a
        simple way to manage coarse grained logging choices that operators have to interpret for their operands.
        """
        return self.__log_level

    def operator_log_level(self) -> LogLevel:
        """
        operatorLogLevel is an intent based logging for the operator itself.  It does not give fine grained control, but it is a
        simple way to manage coarse grained logging choices that operators have to interpret for themselves.
        """
        return self.__operator_log_level

    def unsupported_config_overrides(self) -> "runtime.RawExtension":
        """
        unsupportedConfigOverrides holds a sparse config that will override any previously set options.  It only needs to be the fields to override
        it will end up overlaying in the following order:
        1. hardcoded defaults
        2. observedConfig
        3. unsupportedConfigOverrides
        +nullable
        """
        return self.__unsupported_config_overrides

    def observed_config(self) -> "runtime.RawExtension":
        """
        observedConfig holds a sparse config that controller has observed from the cluster state.  It exists in spec because
        it is an input to the level for the operator
        +nullable
        """
        return self.__observed_config


class AuthenticationSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, operator_spec: "OperatorSpec" = None):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "OperatorSpec")
        v.update(operator_spec._root())  # inline
        return v

    def operator_spec(self) -> "OperatorSpec":
        return self.__operator_spec


class Authentication(base.TypedObject, base.MetadataObject):
    """
    Authentication provides information to configure an operator to manage authentication.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "AuthenticationSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="Authentication",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else AuthenticationSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["AuthenticationSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["AuthenticationSpec"]:
        """
        +required
        """
        return self.__spec


class CSISnapshotControllerSpec(types.Object):
    """
    CSISnapshotControllerSpec is the specification of the desired behavior of the CSISnapshotController operator.
    """

    @context.scoped
    @typechecked
    def __init__(self, operator_spec: "OperatorSpec" = None):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "OperatorSpec")
        v.update(operator_spec._root())  # inline
        return v

    def operator_spec(self) -> "OperatorSpec":
        return self.__operator_spec


class CSISnapshotController(base.TypedObject, base.MetadataObject):
    """
    CSISnapshotController provides a means to configure an operator to manage the CSI snapshots. `cluster` is the canonical name.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "CSISnapshotControllerSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="CSISnapshotController",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else CSISnapshotControllerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "CSISnapshotControllerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "CSISnapshotControllerSpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class ClusterNetworkEntry(types.Object):
    """
    ClusterNetworkEntry is a subnet from which to allocate PodIPs. A network of size
    HostPrefix (in CIDR notation) will be allocated when nodes join the cluster.
    Not all network providers support multiple ClusterNetworks
    """

    @context.scoped
    @typechecked
    def __init__(self, cidr: str = "", host_prefix: int = 0):
        super().__init__()
        self.__cidr = cidr
        self.__host_prefix = host_prefix

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cidr = self.cidr()
        check_type("cidr", cidr, str)
        v["cidr"] = cidr
        host_prefix = self.host_prefix()
        check_type("host_prefix", host_prefix, int)
        v["hostPrefix"] = host_prefix
        return v

    def cidr(self) -> str:
        return self.__cidr

    def host_prefix(self) -> int:
        return self.__host_prefix


class ConsoleCustomization(types.Object):
    """
    ConsoleCustomization defines a list of optional configuration for the console UI.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        brand: Brand = None,
        documentation_base_url: str = None,
        custom_product_name: str = None,
        custom_logo_file: "configv1.ConfigMapFileReference" = None,
    ):
        super().__init__()
        self.__brand = brand
        self.__documentation_base_url = documentation_base_url
        self.__custom_product_name = custom_product_name
        self.__custom_logo_file = (
            custom_logo_file
            if custom_logo_file is not None
            else configv1.ConfigMapFileReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        brand = self.brand()
        check_type("brand", brand, Optional[Brand])
        if brand:  # omit empty
            v["brand"] = brand
        documentation_base_url = self.documentation_base_url()
        check_type("documentation_base_url", documentation_base_url, Optional[str])
        if documentation_base_url:  # omit empty
            v["documentationBaseURL"] = documentation_base_url
        custom_product_name = self.custom_product_name()
        check_type("custom_product_name", custom_product_name, Optional[str])
        if custom_product_name:  # omit empty
            v["customProductName"] = custom_product_name
        custom_logo_file = self.custom_logo_file()
        check_type(
            "custom_logo_file",
            custom_logo_file,
            Optional["configv1.ConfigMapFileReference"],
        )
        v["customLogoFile"] = custom_logo_file
        return v

    def brand(self) -> Optional[Brand]:
        """
        brand is the default branding of the web console which can be overridden by
        providing the brand field.  There is a limited set of specific brand options.
        This field controls elements of the console such as the logo.
        Invalid value will prevent a console rollout.
        """
        return self.__brand

    def documentation_base_url(self) -> Optional[str]:
        """
        documentationBaseURL links to external documentation are shown in various sections
        of the web console.  Providing documentationBaseURL will override the default
        documentation URL.
        Invalid value will prevent a console rollout.
        """
        return self.__documentation_base_url

    def custom_product_name(self) -> Optional[str]:
        """
        customProductName is the name that will be displayed in page titles, logo alt text, and the about dialog
        instead of the normal OpenShift product name.
        """
        return self.__custom_product_name

    def custom_logo_file(self) -> Optional["configv1.ConfigMapFileReference"]:
        """
        customLogoFile replaces the default OpenShift logo in the masthead and about dialog. It is a reference to a
        ConfigMap in the openshift-config namespace. This can be created with a command like
        'oc create configmap custom-logo --from-file=/path/to/file -n openshift-config'.
        Image size must be less than 1 MB due to constraints on the ConfigMap size.
        The ConfigMap key should include a file extension so that the console serves the file
        with the correct MIME type.
        Recommended logo specifications:
        Dimensions: Max height of 68px and max width of 200px
        SVG format preferred
        """
        return self.__custom_logo_file


class StatuspageProvider(types.Object):
    """
    StatuspageProvider provides identity for statuspage account.
    """

    @context.scoped
    @typechecked
    def __init__(self, page_id: str = ""):
        super().__init__()
        self.__page_id = page_id

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        page_id = self.page_id()
        check_type("page_id", page_id, str)
        v["pageID"] = page_id
        return v

    def page_id(self) -> str:
        """
        pageID is the unique ID assigned by Statuspage for your page. This must be a public page.
        """
        return self.__page_id


class ConsoleProviders(types.Object):
    """
    ConsoleProviders defines a list of optional additional providers of
    functionality to the console.
    """

    @context.scoped
    @typechecked
    def __init__(self, statuspage: "StatuspageProvider" = None):
        super().__init__()
        self.__statuspage = statuspage

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        statuspage = self.statuspage()
        check_type("statuspage", statuspage, Optional["StatuspageProvider"])
        if statuspage is not None:  # omit empty
            v["statuspage"] = statuspage
        return v

    def statuspage(self) -> Optional["StatuspageProvider"]:
        """
        statuspage contains ID for statuspage.io page that provides status info about.
        """
        return self.__statuspage


class ConsoleSpec(types.Object):
    """
    ConsoleSpec is the specification of the desired behavior of the Console.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        operator_spec: "OperatorSpec" = None,
        customization: "ConsoleCustomization" = None,
        providers: "ConsoleProviders" = None,
    ):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else OperatorSpec()
        )
        self.__customization = (
            customization if customization is not None else ConsoleCustomization()
        )
        self.__providers = providers if providers is not None else ConsoleProviders()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "OperatorSpec")
        v.update(operator_spec._root())  # inline
        customization = self.customization()
        check_type("customization", customization, "ConsoleCustomization")
        v["customization"] = customization
        providers = self.providers()
        check_type("providers", providers, "ConsoleProviders")
        v["providers"] = providers
        return v

    def operator_spec(self) -> "OperatorSpec":
        return self.__operator_spec

    def customization(self) -> "ConsoleCustomization":
        """
        customization is used to optionally provide a small set of
        customization options to the web console.
        """
        return self.__customization

    def providers(self) -> "ConsoleProviders":
        """
        providers contains configuration for using specific service providers.
        """
        return self.__providers


class Console(base.TypedObject, base.MetadataObject):
    """
    Console provides a means to configure an operator to manage the console.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ConsoleSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="Console",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ConsoleSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["ConsoleSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["ConsoleSpec"]:
        """
        +required
        """
        return self.__spec


class ForwardPlugin(types.Object):
    """
    ForwardPlugin defines a schema for configuring the CoreDNS forward plugin.
    """

    @context.scoped
    @typechecked
    def __init__(self, upstreams: List[str] = None):
        super().__init__()
        self.__upstreams = upstreams if upstreams is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        upstreams = self.upstreams()
        check_type("upstreams", upstreams, List[str])
        v["upstreams"] = upstreams
        return v

    def upstreams(self) -> List[str]:
        """
        upstreams is a list of resolvers to forward name queries for subdomains of Zones.
        Upstreams are randomized when more than 1 upstream is specified. Each instance of
        CoreDNS performs health checking of Upstreams. When a healthy upstream returns an
        error during the exchange, another resolver is tried from Upstreams. Each upstream
        is represented by an IP address or IP:port if the upstream listens on a port other
        than 53.
        
        A maximum of 15 upstreams is allowed per ForwardPlugin.
        """
        return self.__upstreams


class Server(types.Object):
    """
    Server defines the schema for a server that runs per instance of CoreDNS.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        zones: List[str] = None,
        forward_plugin: "ForwardPlugin" = None,
    ):
        super().__init__()
        self.__name = name
        self.__zones = zones if zones is not None else []
        self.__forward_plugin = (
            forward_plugin if forward_plugin is not None else ForwardPlugin()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        zones = self.zones()
        check_type("zones", zones, List[str])
        v["zones"] = zones
        forward_plugin = self.forward_plugin()
        check_type("forward_plugin", forward_plugin, "ForwardPlugin")
        v["forwardPlugin"] = forward_plugin
        return v

    def name(self) -> str:
        """
        name is required and specifies a unique name for the server. Name must comply
        with the Service Name Syntax of rfc6335.
        """
        return self.__name

    def zones(self) -> List[str]:
        """
        zones is required and specifies the subdomains that Server is authoritative for.
        Zones must conform to the rfc1123 definition of a subdomain. Specifying the
        cluster domain (i.e., "cluster.local") is invalid.
        """
        return self.__zones

    def forward_plugin(self) -> "ForwardPlugin":
        """
        forwardPlugin defines a schema for configuring CoreDNS to proxy DNS messages
        to upstream resolvers.
        """
        return self.__forward_plugin


class DNSSpec(types.Object):
    """
    DNSSpec is the specification of the desired behavior of the DNS.
    """

    @context.scoped
    @typechecked
    def __init__(self, servers: List["Server"] = None):
        super().__init__()
        self.__servers = servers if servers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        servers = self.servers()
        check_type("servers", servers, Optional[List["Server"]])
        if servers:  # omit empty
            v["servers"] = servers
        return v

    def servers(self) -> Optional[List["Server"]]:
        """
        servers is a list of DNS resolvers that provide name query delegation for one or
        more subdomains outside the scope of the cluster domain. If servers consists of
        more than one Server, longest suffix match will be used to determine the Server.
        
        For example, if there are two Servers, one for "foo.com" and another for "a.foo.com",
        and the name query is for "www.a.foo.com", it will be routed to the Server with Zone
        "a.foo.com".
        
        If this field is nil, no servers are created.
        """
        return self.__servers


class DNS(base.TypedObject, base.MetadataObject):
    """
    DNS manages the CoreDNS component to provide a name resolution service
    for pods and services in the cluster.
    
    This supports the DNS-based service discovery specification:
    https://github.com/kubernetes/dns/blob/master/docs/specification.md
    
    More details: https://kubernetes.io/docs/tasks/administer-cluster/coredns
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "DNSSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="DNS",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else DNSSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["DNSSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["DNSSpec"]:
        """
        spec is the specification of the desired behavior of the DNS.
        """
        return self.__spec


class KuryrConfig(types.Object):
    """
    KuryrConfig configures the Kuryr-Kubernetes SDN
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        daemon_probes_port: int = None,
        controller_probes_port: int = None,
        open_stack_service_network: str = None,
        enable_port_pools_prepopulation: bool = None,
        pool_max_ports: int = None,
        pool_min_ports: int = None,
        pool_batch_ports: int = None,
    ):
        super().__init__()
        self.__daemon_probes_port = daemon_probes_port
        self.__controller_probes_port = controller_probes_port
        self.__open_stack_service_network = open_stack_service_network
        self.__enable_port_pools_prepopulation = enable_port_pools_prepopulation
        self.__pool_max_ports = pool_max_ports
        self.__pool_min_ports = pool_min_ports
        self.__pool_batch_ports = pool_batch_ports

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        daemon_probes_port = self.daemon_probes_port()
        check_type("daemon_probes_port", daemon_probes_port, Optional[int])
        if daemon_probes_port is not None:  # omit empty
            v["daemonProbesPort"] = daemon_probes_port
        controller_probes_port = self.controller_probes_port()
        check_type("controller_probes_port", controller_probes_port, Optional[int])
        if controller_probes_port is not None:  # omit empty
            v["controllerProbesPort"] = controller_probes_port
        open_stack_service_network = self.open_stack_service_network()
        check_type(
            "open_stack_service_network", open_stack_service_network, Optional[str]
        )
        if open_stack_service_network:  # omit empty
            v["openStackServiceNetwork"] = open_stack_service_network
        enable_port_pools_prepopulation = self.enable_port_pools_prepopulation()
        check_type(
            "enable_port_pools_prepopulation",
            enable_port_pools_prepopulation,
            Optional[bool],
        )
        if enable_port_pools_prepopulation:  # omit empty
            v["enablePortPoolsPrepopulation"] = enable_port_pools_prepopulation
        pool_max_ports = self.pool_max_ports()
        check_type("pool_max_ports", pool_max_ports, Optional[int])
        if pool_max_ports:  # omit empty
            v["poolMaxPorts"] = pool_max_ports
        pool_min_ports = self.pool_min_ports()
        check_type("pool_min_ports", pool_min_ports, Optional[int])
        if pool_min_ports:  # omit empty
            v["poolMinPorts"] = pool_min_ports
        pool_batch_ports = self.pool_batch_ports()
        check_type("pool_batch_ports", pool_batch_ports, Optional[int])
        if pool_batch_ports is not None:  # omit empty
            v["poolBatchPorts"] = pool_batch_ports
        return v

    def daemon_probes_port(self) -> Optional[int]:
        """
        The port kuryr-daemon will listen for readiness and liveness requests.
        """
        return self.__daemon_probes_port

    def controller_probes_port(self) -> Optional[int]:
        """
        The port kuryr-controller will listen for readiness and liveness requests.
        """
        return self.__controller_probes_port

    def open_stack_service_network(self) -> Optional[str]:
        """
        openStackServiceNetwork contains the CIDR of network from which to allocate IPs for
        OpenStack Octavia's Amphora VMs. Please note that with Amphora driver Octavia uses
        two IPs from that network for each loadbalancer - one given by OpenShift and second
        for VRRP connections. As the first one is managed by OpenShift's and second by Neutron's
        IPAMs, those need to come from different pools. Therefore `openStackServiceNetwork`
        needs to be at least twice the size of `serviceNetwork`, and whole `serviceNetwork`
        must be overlapping with `openStackServiceNetwork`. cluster-network-operator will then
        make sure VRRP IPs are taken from the ranges inside `openStackServiceNetwork` that
        are not overlapping with `serviceNetwork`, effectivly preventing conflicts. If not set
        cluster-network-operator will use `serviceNetwork` expanded by decrementing the prefix
        size by 1.
        """
        return self.__open_stack_service_network

    def enable_port_pools_prepopulation(self) -> Optional[bool]:
        """
        enablePortPoolsPrepopulation when true will make Kuryr prepopulate each newly created port
        pool with a minimum number of ports. Kuryr uses Neutron port pooling to fight the fact
        that it takes a significant amount of time to create one. Instead of creating it when
        pod is being deployed, Kuryr keeps a number of ports ready to be attached to pods. By
        default port prepopulation is disabled.
        """
        return self.__enable_port_pools_prepopulation

    def pool_max_ports(self) -> Optional[int]:
        """
        poolMaxPorts sets a maximum number of free ports that are being kept in a port pool.
        If the number of ports exceeds this setting, free ports will get deleted. Setting 0
        will disable this upper bound, effectively preventing pools from shrinking and this
        is the default value. For more information about port pools see
        enablePortPoolsPrepopulation setting.
        """
        return self.__pool_max_ports

    def pool_min_ports(self) -> Optional[int]:
        """
        poolMinPorts sets a minimum number of free ports that should be kept in a port pool.
        If the number of ports is lower than this setting, new ports will get created and
        added to pool. The default is 1. For more information about port pools see
        enablePortPoolsPrepopulation setting.
        """
        return self.__pool_min_ports

    def pool_batch_ports(self) -> Optional[int]:
        """
        poolBatchPorts sets a number of ports that should be created in a single batch request
        to extend the port pool. The default is 3. For more information about port pools see
        enablePortPoolsPrepopulation setting.
        """
        return self.__pool_batch_ports


class HybridOverlayConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, hybrid_cluster_network: List["ClusterNetworkEntry"] = None):
        super().__init__()
        self.__hybrid_cluster_network = (
            hybrid_cluster_network if hybrid_cluster_network is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        hybrid_cluster_network = self.hybrid_cluster_network()
        check_type(
            "hybrid_cluster_network",
            hybrid_cluster_network,
            List["ClusterNetworkEntry"],
        )
        v["hybridClusterNetwork"] = hybrid_cluster_network
        return v

    def hybrid_cluster_network(self) -> List["ClusterNetworkEntry"]:
        """
        HybridClusterNetwork defines a network space given to nodes on an additional overlay network.
        """
        return self.__hybrid_cluster_network


class OVNKubernetesConfig(types.Object):
    """
    ovnKubernetesConfig contains the configuration parameters for networks
    using the ovn-kubernetes network project
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        mtu: int = None,
        geneve_port: int = None,
        hybrid_overlay_config: "HybridOverlayConfig" = None,
    ):
        super().__init__()
        self.__mtu = mtu
        self.__geneve_port = geneve_port
        self.__hybrid_overlay_config = hybrid_overlay_config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        mtu = self.mtu()
        check_type("mtu", mtu, Optional[int])
        if mtu is not None:  # omit empty
            v["mtu"] = mtu
        geneve_port = self.geneve_port()
        check_type("geneve_port", geneve_port, Optional[int])
        if geneve_port is not None:  # omit empty
            v["genevePort"] = geneve_port
        hybrid_overlay_config = self.hybrid_overlay_config()
        check_type(
            "hybrid_overlay_config",
            hybrid_overlay_config,
            Optional["HybridOverlayConfig"],
        )
        if hybrid_overlay_config is not None:  # omit empty
            v["hybridOverlayConfig"] = hybrid_overlay_config
        return v

    def mtu(self) -> Optional[int]:
        """
        mtu is the MTU to use for the tunnel interface. This must be 100
        bytes smaller than the uplink mtu.
        Default is 1400
        """
        return self.__mtu

    def geneve_port(self) -> Optional[int]:
        """
        geneve port is the UDP port to be used by geneve encapulation.
        Default is 6081
        """
        return self.__geneve_port

    def hybrid_overlay_config(self) -> Optional["HybridOverlayConfig"]:
        """
        HybridOverlayConfig configures an additional overlay network for peers that are
        not using OVN.
        """
        return self.__hybrid_overlay_config


class OpenShiftSDNConfig(types.Object):
    """
    OpenShiftSDNConfig configures the three openshift-sdn plugins
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        mode: SDNMode = None,
        vxlan_port: int = None,
        mtu: int = None,
        use_external_openvswitch: bool = None,
        enable_unidling: bool = None,
    ):
        super().__init__()
        self.__mode = mode
        self.__vxlan_port = vxlan_port
        self.__mtu = mtu
        self.__use_external_openvswitch = use_external_openvswitch
        self.__enable_unidling = enable_unidling

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        mode = self.mode()
        check_type("mode", mode, SDNMode)
        v["mode"] = mode
        vxlan_port = self.vxlan_port()
        check_type("vxlan_port", vxlan_port, Optional[int])
        if vxlan_port is not None:  # omit empty
            v["vxlanPort"] = vxlan_port
        mtu = self.mtu()
        check_type("mtu", mtu, Optional[int])
        if mtu is not None:  # omit empty
            v["mtu"] = mtu
        use_external_openvswitch = self.use_external_openvswitch()
        check_type("use_external_openvswitch", use_external_openvswitch, Optional[bool])
        if use_external_openvswitch is not None:  # omit empty
            v["useExternalOpenvswitch"] = use_external_openvswitch
        enable_unidling = self.enable_unidling()
        check_type("enable_unidling", enable_unidling, Optional[bool])
        if enable_unidling is not None:  # omit empty
            v["enableUnidling"] = enable_unidling
        return v

    def mode(self) -> SDNMode:
        """
        mode is one of "Multitenant", "Subnet", or "NetworkPolicy"
        """
        return self.__mode

    def vxlan_port(self) -> Optional[int]:
        """
        vxlanPort is the port to use for all vxlan packets. The default is 4789.
        """
        return self.__vxlan_port

    def mtu(self) -> Optional[int]:
        """
        mtu is the mtu to use for the tunnel interface. Defaults to 1450 if unset.
        This must be 50 bytes smaller than the machine's uplink.
        """
        return self.__mtu

    def use_external_openvswitch(self) -> Optional[bool]:
        """
        useExternalOpenvswitch tells the operator not to install openvswitch, because
        it will be provided separately. If set, you must provide it yourself.
        """
        return self.__use_external_openvswitch

    def enable_unidling(self) -> Optional[bool]:
        """
        enableUnidling controls whether or not the service proxy will support idling
        and unidling of services. By default, unidling is enabled.
        """
        return self.__enable_unidling


class DefaultNetworkDefinition(types.Object):
    """
    DefaultNetworkDefinition represents a single network plugin's configuration.
    type must be specified, along with exactly one "Config" that matches the type.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: NetworkType = None,
        openshift_sdn_config: "OpenShiftSDNConfig" = None,
        ovn_kubernetes_config: "OVNKubernetesConfig" = None,
        kuryr_config: "KuryrConfig" = None,
    ):
        super().__init__()
        self.__type = type
        self.__openshift_sdn_config = openshift_sdn_config
        self.__ovn_kubernetes_config = ovn_kubernetes_config
        self.__kuryr_config = kuryr_config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, NetworkType)
        v["type"] = type
        openshift_sdn_config = self.openshift_sdn_config()
        check_type(
            "openshift_sdn_config", openshift_sdn_config, Optional["OpenShiftSDNConfig"]
        )
        if openshift_sdn_config is not None:  # omit empty
            v["openshiftSDNConfig"] = openshift_sdn_config
        ovn_kubernetes_config = self.ovn_kubernetes_config()
        check_type(
            "ovn_kubernetes_config",
            ovn_kubernetes_config,
            Optional["OVNKubernetesConfig"],
        )
        if ovn_kubernetes_config is not None:  # omit empty
            v["ovnKubernetesConfig"] = ovn_kubernetes_config
        kuryr_config = self.kuryr_config()
        check_type("kuryr_config", kuryr_config, Optional["KuryrConfig"])
        if kuryr_config is not None:  # omit empty
            v["kuryrConfig"] = kuryr_config
        return v

    def type(self) -> NetworkType:
        """
        type is the type of network
        All NetworkTypes are supported except for NetworkTypeRaw
        """
        return self.__type

    def openshift_sdn_config(self) -> Optional["OpenShiftSDNConfig"]:
        """
        openShiftSDNConfig configures the openshift-sdn plugin
        """
        return self.__openshift_sdn_config

    def ovn_kubernetes_config(self) -> Optional["OVNKubernetesConfig"]:
        """
        oVNKubernetesConfig configures the ovn-kubernetes plugin. This is currently
        not implemented.
        """
        return self.__ovn_kubernetes_config

    def kuryr_config(self) -> Optional["KuryrConfig"]:
        """
        KuryrConfig configures the kuryr plugin
        """
        return self.__kuryr_config


class HostNetworkStrategy(types.Object):
    """
    HostNetworkStrategy holds parameters for the HostNetwork endpoint publishing
    strategy.
    """

    pass  # FIXME


class LoadBalancerStrategy(types.Object):
    """
    LoadBalancerStrategy holds parameters for a load balancer.
    """

    @context.scoped
    @typechecked
    def __init__(self, scope: LoadBalancerScope = None):
        super().__init__()
        self.__scope = scope

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        scope = self.scope()
        check_type("scope", scope, LoadBalancerScope)
        v["scope"] = scope
        return v

    def scope(self) -> LoadBalancerScope:
        """
        scope indicates the scope at which the load balancer is exposed.
        Possible values are "External" and "Internal".
        
        +required
        """
        return self.__scope


class NodePortStrategy(types.Object):
    """
    NodePortStrategy holds parameters for the NodePortService endpoint publishing strategy.
    """

    pass  # FIXME


class PrivateStrategy(types.Object):
    """
    PrivateStrategy holds parameters for the Private endpoint publishing
    strategy.
    """

    pass  # FIXME


class EndpointPublishingStrategy(types.Object):
    """
    EndpointPublishingStrategy is a way to publish the endpoints of an
    IngressController, and represents the type and any additional configuration
    for a specific type.
    +union
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: EndpointPublishingStrategyType = None,
        load_balancer: "LoadBalancerStrategy" = None,
        host_network: "HostNetworkStrategy" = None,
        private: "PrivateStrategy" = None,
        node_port: "NodePortStrategy" = None,
    ):
        super().__init__()
        self.__type = type
        self.__load_balancer = load_balancer
        self.__host_network = host_network
        self.__private = private
        self.__node_port = node_port

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, EndpointPublishingStrategyType)
        v["type"] = type
        load_balancer = self.load_balancer()
        check_type("load_balancer", load_balancer, Optional["LoadBalancerStrategy"])
        if load_balancer is not None:  # omit empty
            v["loadBalancer"] = load_balancer
        host_network = self.host_network()
        check_type("host_network", host_network, Optional["HostNetworkStrategy"])
        if host_network is not None:  # omit empty
            v["hostNetwork"] = host_network
        private = self.private()
        check_type("private", private, Optional["PrivateStrategy"])
        if private is not None:  # omit empty
            v["private"] = private
        node_port = self.node_port()
        check_type("node_port", node_port, Optional["NodePortStrategy"])
        if node_port is not None:  # omit empty
            v["nodePort"] = node_port
        return v

    def type(self) -> EndpointPublishingStrategyType:
        """
        type is the publishing strategy to use. Valid values are:
        
        * LoadBalancerService
        
        Publishes the ingress controller using a Kubernetes LoadBalancer Service.
        
        In this configuration, the ingress controller deployment uses container
        networking. A LoadBalancer Service is created to publish the deployment.
        
        See: https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer
        
        If domain is set, a wildcard DNS record will be managed to point at the
        LoadBalancer Service's external name. DNS records are managed only in DNS
        zones defined by dns.config.openshift.io/cluster .spec.publicZone and
        .spec.privateZone.
        
        Wildcard DNS management is currently supported only on the AWS, Azure,
        and GCP platforms.
        
        * HostNetwork
        
        Publishes the ingress controller on node ports where the ingress controller
        is deployed.
        
        In this configuration, the ingress controller deployment uses host
        networking, bound to node ports 80 and 443. The user is responsible for
        configuring an external load balancer to publish the ingress controller via
        the node ports.
        
        * Private
        
        Does not publish the ingress controller.
        
        In this configuration, the ingress controller deployment uses container
        networking, and is not explicitly published. The user must manually publish
        the ingress controller.
        
        * NodePortService
        
        Publishes the ingress controller using a Kubernetes NodePort Service.
        
        In this configuration, the ingress controller deployment uses container
        networking. A NodePort Service is created to publish the deployment. The
        specific node ports are dynamically allocated by OpenShift; however, to
        support static port allocations, user changes to the node port
        field of the managed NodePort Service will preserved.
        
        +unionDiscriminator
        +required
        """
        return self.__type

    def load_balancer(self) -> Optional["LoadBalancerStrategy"]:
        """
        loadBalancer holds parameters for the load balancer. Present only if
        type is LoadBalancerService.
        """
        return self.__load_balancer

    def host_network(self) -> Optional["HostNetworkStrategy"]:
        """
        hostNetwork holds parameters for the HostNetwork endpoint publishing
        strategy. Present only if type is HostNetwork.
        """
        return self.__host_network

    def private(self) -> Optional["PrivateStrategy"]:
        """
        private holds parameters for the Private endpoint publishing
        strategy. Present only if type is Private.
        """
        return self.__private

    def node_port(self) -> Optional["NodePortStrategy"]:
        """
        nodePort holds parameters for the NodePortService endpoint publishing strategy.
        Present only if type is NodePortService.
        """
        return self.__node_port


class StaticPodOperatorSpec(types.Object):
    """
    StaticPodOperatorSpec is spec for controllers that manage static pods.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        operator_spec: "OperatorSpec" = None,
        force_redeployment_reason: str = "",
        failed_revision_limit: int = None,
        succeeded_revision_limit: int = None,
    ):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else OperatorSpec()
        )
        self.__force_redeployment_reason = force_redeployment_reason
        self.__failed_revision_limit = failed_revision_limit
        self.__succeeded_revision_limit = succeeded_revision_limit

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "OperatorSpec")
        v.update(operator_spec._root())  # inline
        force_redeployment_reason = self.force_redeployment_reason()
        check_type("force_redeployment_reason", force_redeployment_reason, str)
        v["forceRedeploymentReason"] = force_redeployment_reason
        failed_revision_limit = self.failed_revision_limit()
        check_type("failed_revision_limit", failed_revision_limit, Optional[int])
        if failed_revision_limit:  # omit empty
            v["failedRevisionLimit"] = failed_revision_limit
        succeeded_revision_limit = self.succeeded_revision_limit()
        check_type("succeeded_revision_limit", succeeded_revision_limit, Optional[int])
        if succeeded_revision_limit:  # omit empty
            v["succeededRevisionLimit"] = succeeded_revision_limit
        return v

    def operator_spec(self) -> "OperatorSpec":
        return self.__operator_spec

    def force_redeployment_reason(self) -> str:
        """
        forceRedeploymentReason can be used to force the redeployment of the operand by providing a unique string.
        This provides a mechanism to kick a previously failed deployment and provide a reason why you think it will work
        this time instead of failing again on the same config.
        """
        return self.__force_redeployment_reason

    def failed_revision_limit(self) -> Optional[int]:
        """
        failedRevisionLimit is the number of failed static pod installer revisions to keep on disk and in the api
        -1 = unlimited, 0 or unset = 5 (default)
        """
        return self.__failed_revision_limit

    def succeeded_revision_limit(self) -> Optional[int]:
        """
        succeededRevisionLimit is the number of successful static pod installer revisions to keep on disk and in the api
        -1 = unlimited, 0 or unset = 5 (default)
        """
        return self.__succeeded_revision_limit


class EtcdSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, static_pod_operator_spec: "StaticPodOperatorSpec" = None):
        super().__init__()
        self.__static_pod_operator_spec = (
            static_pod_operator_spec
            if static_pod_operator_spec is not None
            else StaticPodOperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        static_pod_operator_spec = self.static_pod_operator_spec()
        check_type(
            "static_pod_operator_spec",
            static_pod_operator_spec,
            "StaticPodOperatorSpec",
        )
        v.update(static_pod_operator_spec._root())  # inline
        return v

    def static_pod_operator_spec(self) -> "StaticPodOperatorSpec":
        return self.__static_pod_operator_spec


class Etcd(base.TypedObject, base.MetadataObject):
    """
    Etcd provides information to configure an operator to manage kube-apiserver.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "EtcdSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="Etcd",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else EtcdSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "EtcdSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "EtcdSpec":
        """
        +required
        """
        return self.__spec


class NodePlacement(types.Object):
    """
    NodePlacement describes node scheduling configuration for an ingress
    controller.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        node_selector: "metav1.LabelSelector" = None,
        tolerations: List["k8sv1.Toleration"] = None,
    ):
        super().__init__()
        self.__node_selector = node_selector
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional["metav1.LabelSelector"])
        if node_selector is not None:  # omit empty
            v["nodeSelector"] = node_selector
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    def node_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        nodeSelector is the node selector applied to ingress controller
        deployments.
        
        If unset, the default is:
        
          beta.kubernetes.io/os: linux
          node-role.kubernetes.io/worker: ''
        
        If set, the specified selector is used and replaces the default.
        """
        return self.__node_selector

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        tolerations is a list of tolerations applied to ingress controller
        deployments.
        
        The default is an empty list.
        
        See https://kubernetes.io/docs/concepts/configuration/taint-and-toleration/
        """
        return self.__tolerations


class RouteAdmissionPolicy(types.Object):
    """
    RouteAdmissionPolicy is an admission policy for allowing new route claims.
    """

    @context.scoped
    @typechecked
    def __init__(self, namespace_ownership: NamespaceOwnershipCheck = None):
        super().__init__()
        self.__namespace_ownership = namespace_ownership

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace_ownership = self.namespace_ownership()
        check_type(
            "namespace_ownership",
            namespace_ownership,
            Optional[NamespaceOwnershipCheck],
        )
        if namespace_ownership:  # omit empty
            v["namespaceOwnership"] = namespace_ownership
        return v

    def namespace_ownership(self) -> Optional[NamespaceOwnershipCheck]:
        """
        namespaceOwnership describes how host name claims across namespaces should
        be handled.
        
        Value must be one of:
        
        - Strict: Do not allow routes in different namespaces to claim the same host.
        
        - InterNamespaceAllowed: Allow routes to claim different paths of the same
          host name across namespaces.
        
        If empty, the default is Strict.
        """
        return self.__namespace_ownership


class IngressControllerSpec(types.Object):
    """
    IngressControllerSpec is the specification of the desired behavior of the
    IngressController.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        domain: str = None,
        replicas: int = None,
        endpoint_publishing_strategy: "EndpointPublishingStrategy" = None,
        default_certificate: "k8sv1.LocalObjectReference" = None,
        namespace_selector: "metav1.LabelSelector" = None,
        route_selector: "metav1.LabelSelector" = None,
        node_placement: "NodePlacement" = None,
        tls_security_profile: "configv1.TLSSecurityProfile" = None,
        route_admission: "RouteAdmissionPolicy" = None,
    ):
        super().__init__()
        self.__domain = domain
        self.__replicas = replicas
        self.__endpoint_publishing_strategy = endpoint_publishing_strategy
        self.__default_certificate = default_certificate
        self.__namespace_selector = namespace_selector
        self.__route_selector = route_selector
        self.__node_placement = node_placement
        self.__tls_security_profile = tls_security_profile
        self.__route_admission = route_admission

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        domain = self.domain()
        check_type("domain", domain, Optional[str])
        if domain:  # omit empty
            v["domain"] = domain
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas is not None:  # omit empty
            v["replicas"] = replicas
        endpoint_publishing_strategy = self.endpoint_publishing_strategy()
        check_type(
            "endpoint_publishing_strategy",
            endpoint_publishing_strategy,
            Optional["EndpointPublishingStrategy"],
        )
        if endpoint_publishing_strategy is not None:  # omit empty
            v["endpointPublishingStrategy"] = endpoint_publishing_strategy
        default_certificate = self.default_certificate()
        check_type(
            "default_certificate",
            default_certificate,
            Optional["k8sv1.LocalObjectReference"],
        )
        if default_certificate is not None:  # omit empty
            v["defaultCertificate"] = default_certificate
        namespace_selector = self.namespace_selector()
        check_type(
            "namespace_selector", namespace_selector, Optional["metav1.LabelSelector"]
        )
        if namespace_selector is not None:  # omit empty
            v["namespaceSelector"] = namespace_selector
        route_selector = self.route_selector()
        check_type("route_selector", route_selector, Optional["metav1.LabelSelector"])
        if route_selector is not None:  # omit empty
            v["routeSelector"] = route_selector
        node_placement = self.node_placement()
        check_type("node_placement", node_placement, Optional["NodePlacement"])
        if node_placement is not None:  # omit empty
            v["nodePlacement"] = node_placement
        tls_security_profile = self.tls_security_profile()
        check_type(
            "tls_security_profile",
            tls_security_profile,
            Optional["configv1.TLSSecurityProfile"],
        )
        if tls_security_profile is not None:  # omit empty
            v["tlsSecurityProfile"] = tls_security_profile
        route_admission = self.route_admission()
        check_type("route_admission", route_admission, Optional["RouteAdmissionPolicy"])
        if route_admission is not None:  # omit empty
            v["routeAdmission"] = route_admission
        return v

    def domain(self) -> Optional[str]:
        """
        domain is a DNS name serviced by the ingress controller and is used to
        configure multiple features:
        
        * For the LoadBalancerService endpoint publishing strategy, domain is
          used to configure DNS records. See endpointPublishingStrategy.
        
        * When using a generated default certificate, the certificate will be valid
          for domain and its subdomains. See defaultCertificate.
        
        * The value is published to individual Route statuses so that end-users
          know where to target external DNS records.
        
        domain must be unique among all IngressControllers, and cannot be
        updated.
        
        If empty, defaults to ingress.config.openshift.io/cluster .spec.domain.
        """
        return self.__domain

    def replicas(self) -> Optional[int]:
        """
        replicas is the desired number of ingress controller replicas. If unset,
        defaults to 2.
        """
        return self.__replicas

    def endpoint_publishing_strategy(self) -> Optional["EndpointPublishingStrategy"]:
        """
        endpointPublishingStrategy is used to publish the ingress controller
        endpoints to other networks, enable load balancer integrations, etc.
        
        If unset, the default is based on
        infrastructure.config.openshift.io/cluster .status.platform:
        
          AWS:      LoadBalancerService (with External scope)
          Azure:    LoadBalancerService (with External scope)
          GCP:      LoadBalancerService (with External scope)
          IBMCloud: LoadBalancerService (with External scope)
          Libvirt:  HostNetwork
        
        Any other platform types (including None) default to HostNetwork.
        
        endpointPublishingStrategy cannot be updated.
        """
        return self.__endpoint_publishing_strategy

    def default_certificate(self) -> Optional["k8sv1.LocalObjectReference"]:
        """
        defaultCertificate is a reference to a secret containing the default
        certificate served by the ingress controller. When Routes don't specify
        their own certificate, defaultCertificate is used.
        
        The secret must contain the following keys and data:
        
          tls.crt: certificate file contents
          tls.key: key file contents
        
        If unset, a wildcard certificate is automatically generated and used. The
        certificate is valid for the ingress controller domain (and subdomains) and
        the generated certificate's CA will be automatically integrated with the
        cluster's trust store.
        
        The in-use certificate (whether generated or user-specified) will be
        automatically integrated with OpenShift's built-in OAuth server.
        """
        return self.__default_certificate

    def namespace_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        namespaceSelector is used to filter the set of namespaces serviced by the
        ingress controller. This is useful for implementing shards.
        
        If unset, the default is no filtering.
        """
        return self.__namespace_selector

    def route_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        routeSelector is used to filter the set of Routes serviced by the ingress
        controller. This is useful for implementing shards.
        
        If unset, the default is no filtering.
        """
        return self.__route_selector

    def node_placement(self) -> Optional["NodePlacement"]:
        """
        nodePlacement enables explicit control over the scheduling of the ingress
        controller.
        
        If unset, defaults are used. See NodePlacement for more details.
        """
        return self.__node_placement

    def tls_security_profile(self) -> Optional["configv1.TLSSecurityProfile"]:
        """
        tlsSecurityProfile specifies settings for TLS connections for ingresscontrollers.
        
        If unset, the default is based on the apiservers.config.openshift.io/cluster resource.
        
        Note that when using the Old, Intermediate, and Modern profile types, the effective
        profile configuration is subject to change between releases. For example, given
        a specification to use the Intermediate profile deployed on release X.Y.Z, an upgrade
        to release X.Y.Z+1 may cause a new profile configuration to be applied to the ingress
        controller, resulting in a rollout.
        
        Note that the minimum TLS version for ingress controllers is 1.1, and
        the maximum TLS version is 1.2.  An implication of this restriction
        is that the Modern TLS profile type cannot be used because it
        requires TLS 1.3.
        """
        return self.__tls_security_profile

    def route_admission(self) -> Optional["RouteAdmissionPolicy"]:
        """
        routeAdmission defines a policy for handling new route claims (for example,
        to allow or deny claims across namespaces).
        
        If empty, defaults will be applied. See specific routeAdmission fields
        for details about their defaults.
        """
        return self.__route_admission


class IngressController(base.TypedObject, base.NamespacedMetadataObject):
    """
    IngressController describes a managed ingress controller for the cluster. The
    controller can service OpenShift Route and Kubernetes Ingress resources.
    
    When an IngressController is created, a new ingress controller deployment is
    created to allow external traffic to reach the services that expose Ingress
    or Route resources. Updating this resource may lead to disruption for public
    facing network connections as a new ingress controller revision may be rolled
    out.
    
    https://kubernetes.io/docs/concepts/services-networking/ingress-controllers
    
    Whenever possible, sensible defaults for the platform are used. See each
    field for more details.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "IngressControllerSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="IngressController",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else IngressControllerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["IngressControllerSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["IngressControllerSpec"]:
        """
        spec is the specification of the desired behavior of the IngressController.
        """
        return self.__spec


class KubeAPIServerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, static_pod_operator_spec: "StaticPodOperatorSpec" = None):
        super().__init__()
        self.__static_pod_operator_spec = (
            static_pod_operator_spec
            if static_pod_operator_spec is not None
            else StaticPodOperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        static_pod_operator_spec = self.static_pod_operator_spec()
        check_type(
            "static_pod_operator_spec",
            static_pod_operator_spec,
            "StaticPodOperatorSpec",
        )
        v.update(static_pod_operator_spec._root())  # inline
        return v

    def static_pod_operator_spec(self) -> "StaticPodOperatorSpec":
        return self.__static_pod_operator_spec


class KubeAPIServer(base.TypedObject, base.MetadataObject):
    """
    KubeAPIServer provides information to configure an operator to manage kube-apiserver.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "KubeAPIServerSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="KubeAPIServer",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else KubeAPIServerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "KubeAPIServerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "KubeAPIServerSpec":
        """
        spec is the specification of the desired behavior of the Kubernetes API Server
        +required
        """
        return self.__spec


class KubeControllerManagerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, static_pod_operator_spec: "StaticPodOperatorSpec" = None):
        super().__init__()
        self.__static_pod_operator_spec = (
            static_pod_operator_spec
            if static_pod_operator_spec is not None
            else StaticPodOperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        static_pod_operator_spec = self.static_pod_operator_spec()
        check_type(
            "static_pod_operator_spec",
            static_pod_operator_spec,
            "StaticPodOperatorSpec",
        )
        v.update(static_pod_operator_spec._root())  # inline
        return v

    def static_pod_operator_spec(self) -> "StaticPodOperatorSpec":
        return self.__static_pod_operator_spec


class KubeControllerManager(base.TypedObject, base.MetadataObject):
    """
    KubeControllerManager provides information to configure an operator to manage kube-controller-manager.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "KubeControllerManagerSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="KubeControllerManager",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else KubeControllerManagerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "KubeControllerManagerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "KubeControllerManagerSpec":
        """
        spec is the specification of the desired behavior of the Kubernetes Controller Manager
        +required
        """
        return self.__spec


class KubeSchedulerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, static_pod_operator_spec: "StaticPodOperatorSpec" = None):
        super().__init__()
        self.__static_pod_operator_spec = (
            static_pod_operator_spec
            if static_pod_operator_spec is not None
            else StaticPodOperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        static_pod_operator_spec = self.static_pod_operator_spec()
        check_type(
            "static_pod_operator_spec",
            static_pod_operator_spec,
            "StaticPodOperatorSpec",
        )
        v.update(static_pod_operator_spec._root())  # inline
        return v

    def static_pod_operator_spec(self) -> "StaticPodOperatorSpec":
        return self.__static_pod_operator_spec


class KubeScheduler(base.TypedObject, base.MetadataObject):
    """
    KubeScheduler provides information to configure an operator to manage scheduler.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "KubeSchedulerSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="KubeScheduler",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else KubeSchedulerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "KubeSchedulerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "KubeSchedulerSpec":
        """
        spec is the specification of the desired behavior of the Kubernetes Scheduler
        +required
        """
        return self.__spec


class KubeStorageVersionMigratorSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, operator_spec: "OperatorSpec" = None):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "OperatorSpec")
        v.update(operator_spec._root())  # inline
        return v

    def operator_spec(self) -> "OperatorSpec":
        return self.__operator_spec


class KubeStorageVersionMigrator(base.TypedObject, base.MetadataObject):
    """
    KubeStorageVersionMigrator provides information to configure an operator to manage kube-storage-version-migrator.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "KubeStorageVersionMigratorSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="KubeStorageVersionMigrator",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else KubeStorageVersionMigratorSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "KubeStorageVersionMigratorSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "KubeStorageVersionMigratorSpec":
        """
        +required
        """
        return self.__spec


class ProxyConfig(types.Object):
    """
    ProxyConfig defines the configuration knobs for kubeproxy
    All of these are optional and have sensible defaults
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        iptables_sync_period: str = None,
        bind_address: str = None,
        proxy_arguments: Dict[str, List[str]] = None,
    ):
        super().__init__()
        self.__iptables_sync_period = iptables_sync_period
        self.__bind_address = bind_address
        self.__proxy_arguments = proxy_arguments if proxy_arguments is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        iptables_sync_period = self.iptables_sync_period()
        check_type("iptables_sync_period", iptables_sync_period, Optional[str])
        if iptables_sync_period:  # omit empty
            v["iptablesSyncPeriod"] = iptables_sync_period
        bind_address = self.bind_address()
        check_type("bind_address", bind_address, Optional[str])
        if bind_address:  # omit empty
            v["bindAddress"] = bind_address
        proxy_arguments = self.proxy_arguments()
        check_type("proxy_arguments", proxy_arguments, Optional[Dict[str, List[str]]])
        if proxy_arguments:  # omit empty
            v["proxyArguments"] = proxy_arguments
        return v

    def iptables_sync_period(self) -> Optional[str]:
        """
        The period that iptables rules are refreshed.
        Default: 30s
        """
        return self.__iptables_sync_period

    def bind_address(self) -> Optional[str]:
        """
        The address to "bind" on
        Defaults to 0.0.0.0
        """
        return self.__bind_address

    def proxy_arguments(self) -> Optional[Dict[str, List[str]]]:
        """
        Any additional arguments to pass to the kubeproxy process
        """
        return self.__proxy_arguments


class NetworkSpec(types.Object):
    """
    NetworkSpec is the top-level network configuration object.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        cluster_network: List["ClusterNetworkEntry"] = None,
        service_network: List[str] = None,
        default_network: "DefaultNetworkDefinition" = None,
        additional_networks: List["AdditionalNetworkDefinition"] = None,
        disable_multi_network: bool = None,
        deploy_kube_proxy: bool = None,
        kube_proxy_config: "ProxyConfig" = None,
        log_level: LogLevel = None,
    ):
        super().__init__()
        self.__cluster_network = cluster_network if cluster_network is not None else []
        self.__service_network = service_network if service_network is not None else []
        self.__default_network = (
            default_network
            if default_network is not None
            else DefaultNetworkDefinition()
        )
        self.__additional_networks = (
            additional_networks if additional_networks is not None else []
        )
        self.__disable_multi_network = disable_multi_network
        self.__deploy_kube_proxy = deploy_kube_proxy
        self.__kube_proxy_config = kube_proxy_config
        self.__log_level = log_level

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cluster_network = self.cluster_network()
        check_type("cluster_network", cluster_network, List["ClusterNetworkEntry"])
        v["clusterNetwork"] = cluster_network
        service_network = self.service_network()
        check_type("service_network", service_network, List[str])
        v["serviceNetwork"] = service_network
        default_network = self.default_network()
        check_type("default_network", default_network, "DefaultNetworkDefinition")
        v["defaultNetwork"] = default_network
        additional_networks = self.additional_networks()
        check_type(
            "additional_networks",
            additional_networks,
            Optional[List["AdditionalNetworkDefinition"]],
        )
        if additional_networks:  # omit empty
            v["additionalNetworks"] = additional_networks
        disable_multi_network = self.disable_multi_network()
        check_type("disable_multi_network", disable_multi_network, Optional[bool])
        if disable_multi_network is not None:  # omit empty
            v["disableMultiNetwork"] = disable_multi_network
        deploy_kube_proxy = self.deploy_kube_proxy()
        check_type("deploy_kube_proxy", deploy_kube_proxy, Optional[bool])
        if deploy_kube_proxy is not None:  # omit empty
            v["deployKubeProxy"] = deploy_kube_proxy
        kube_proxy_config = self.kube_proxy_config()
        check_type("kube_proxy_config", kube_proxy_config, Optional["ProxyConfig"])
        if kube_proxy_config is not None:  # omit empty
            v["kubeProxyConfig"] = kube_proxy_config
        log_level = self.log_level()
        check_type("log_level", log_level, LogLevel)
        v["logLevel"] = log_level
        return v

    def cluster_network(self) -> List["ClusterNetworkEntry"]:
        """
        clusterNetwork is the IP address pool to use for pod IPs.
        Some network providers, e.g. OpenShift SDN, support multiple ClusterNetworks.
        Others only support one. This is equivalent to the cluster-cidr.
        """
        return self.__cluster_network

    def service_network(self) -> List[str]:
        """
        serviceNetwork is the ip address pool to use for Service IPs
        Currently, all existing network providers only support a single value
        here, but this is an array to allow for growth.
        """
        return self.__service_network

    def default_network(self) -> "DefaultNetworkDefinition":
        """
        defaultNetwork is the "default" network that all pods will receive
        """
        return self.__default_network

    def additional_networks(self) -> Optional[List["AdditionalNetworkDefinition"]]:
        """
        additionalNetworks is a list of extra networks to make available to pods
        when multiple networks are enabled.
        """
        return self.__additional_networks

    def disable_multi_network(self) -> Optional[bool]:
        """
        disableMultiNetwork specifies whether or not multiple pod network
        support should be disabled. If unset, this property defaults to
        'false' and multiple network support is enabled.
        """
        return self.__disable_multi_network

    def deploy_kube_proxy(self) -> Optional[bool]:
        """
        deployKubeProxy specifies whether or not a standalone kube-proxy should
        be deployed by the operator. Some network providers include kube-proxy
        or similar functionality. If unset, the plugin will attempt to select
        the correct value, which is false when OpenShift SDN and ovn-kubernetes are
        used and true otherwise.
        """
        return self.__deploy_kube_proxy

    def kube_proxy_config(self) -> Optional["ProxyConfig"]:
        """
        kubeProxyConfig lets us configure desired proxy configuration.
        If not specified, sensible defaults will be chosen by OpenShift directly.
        Not consumed by all network providers - currently only openshift-sdn.
        """
        return self.__kube_proxy_config

    def log_level(self) -> LogLevel:
        """
        logLevel allows configuring the logging level of the components deployed
        by the operator. Currently only Kuryr SDN is affected by this setting.
        Please note that turning on extensive logging may affect performance.
        The default value is "Normal".
        """
        return self.__log_level


class Network(base.TypedObject, base.MetadataObject):
    """
    Network describes the cluster's desired network configuration. It is
    consumed by the cluster-network-operator.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "NetworkSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="Network",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else NetworkSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["NetworkSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["NetworkSpec"]:
        return self.__spec


class OpenShiftAPIServerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, operator_spec: "OperatorSpec" = None):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "OperatorSpec")
        v.update(operator_spec._root())  # inline
        return v

    def operator_spec(self) -> "OperatorSpec":
        return self.__operator_spec


class OpenShiftAPIServer(base.TypedObject, base.MetadataObject):
    """
    OpenShiftAPIServer provides information to configure an operator to manage openshift-apiserver.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "OpenShiftAPIServerSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="OpenShiftAPIServer",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else OpenShiftAPIServerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "OpenShiftAPIServerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "OpenShiftAPIServerSpec":
        """
        spec is the specification of the desired behavior of the OpenShift API Server.
        +required
        """
        return self.__spec


class OpenShiftControllerManagerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, operator_spec: "OperatorSpec" = None):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "OperatorSpec")
        v.update(operator_spec._root())  # inline
        return v

    def operator_spec(self) -> "OperatorSpec":
        return self.__operator_spec


class OpenShiftControllerManager(base.TypedObject, base.MetadataObject):
    """
    OpenShiftControllerManager provides information to configure an operator to manage openshift-controller-manager.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "OpenShiftControllerManagerSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="OpenShiftControllerManager",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else OpenShiftControllerManagerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "OpenShiftControllerManagerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "OpenShiftControllerManagerSpec":
        """
        +required
        """
        return self.__spec


class ServiceCASpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, operator_spec: "OperatorSpec" = None):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "OperatorSpec")
        v.update(operator_spec._root())  # inline
        return v

    def operator_spec(self) -> "OperatorSpec":
        return self.__operator_spec


class ServiceCA(base.TypedObject, base.MetadataObject):
    """
    ServiceCA provides information to configure an operator to manage the service cert controllers
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ServiceCASpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="ServiceCA",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ServiceCASpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ServiceCASpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ServiceCASpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class ServiceCatalogAPIServerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, operator_spec: "OperatorSpec" = None):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "OperatorSpec")
        v.update(operator_spec._root())  # inline
        return v

    def operator_spec(self) -> "OperatorSpec":
        return self.__operator_spec


class ServiceCatalogAPIServer(base.TypedObject, base.MetadataObject):
    """
    ServiceCatalogAPIServer provides information to configure an operator to manage Service Catalog API Server
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ServiceCatalogAPIServerSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="ServiceCatalogAPIServer",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ServiceCatalogAPIServerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ServiceCatalogAPIServerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ServiceCatalogAPIServerSpec":
        """
        +required
        """
        return self.__spec


class ServiceCatalogControllerManagerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, operator_spec: "OperatorSpec" = None):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "OperatorSpec")
        v.update(operator_spec._root())  # inline
        return v

    def operator_spec(self) -> "OperatorSpec":
        return self.__operator_spec


class ServiceCatalogControllerManager(base.TypedObject, base.MetadataObject):
    """
    ServiceCatalogControllerManager provides information to configure an operator to manage Service Catalog Controller Manager
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ServiceCatalogControllerManagerSpec" = None,
    ):
        super().__init__(
            api_version="operator.openshift.io/v1",
            kind="ServiceCatalogControllerManager",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = (
            spec if spec is not None else ServiceCatalogControllerManagerSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ServiceCatalogControllerManagerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ServiceCatalogControllerManagerSpec":
        """
        +required
        """
        return self.__spec
