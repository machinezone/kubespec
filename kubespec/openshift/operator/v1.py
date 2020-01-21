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
        self, type: IPAMType = None, staticIPAMConfig: "StaticIPAMConfig" = None
    ):
        super().__init__()
        self.__type = type
        self.__staticIPAMConfig = staticIPAMConfig

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, IPAMType)
        v["type"] = type
        staticIPAMConfig = self.staticIPAMConfig()
        check_type("staticIPAMConfig", staticIPAMConfig, Optional["StaticIPAMConfig"])
        if staticIPAMConfig is not None:  # omit empty
            v["staticIPAMConfig"] = staticIPAMConfig
        return v

    def type(self) -> IPAMType:
        """
        Type is the type of IPAM module will be used for IP Address Management(IPAM).
        The supported values are IPAMTypeDHCP, IPAMTypeStatic
        """
        return self.__type

    def staticIPAMConfig(self) -> Optional["StaticIPAMConfig"]:
        """
        StaticIPAMConfig configures the static IP address in case of type:IPAMTypeStatic
        """
        return self.__staticIPAMConfig


class SimpleMacvlanConfig(types.Object):
    """
    SimpleMacvlanConfig contains configurations for macvlan interface.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        master: str = None,
        ipamConfig: "IPAMConfig" = None,
        mode: MacvlanMode = None,
        mtu: int = None,
    ):
        super().__init__()
        self.__master = master
        self.__ipamConfig = ipamConfig
        self.__mode = mode
        self.__mtu = mtu

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        master = self.master()
        check_type("master", master, Optional[str])
        if master:  # omit empty
            v["master"] = master
        ipamConfig = self.ipamConfig()
        check_type("ipamConfig", ipamConfig, Optional["IPAMConfig"])
        if ipamConfig is not None:  # omit empty
            v["ipamConfig"] = ipamConfig
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

    def ipamConfig(self) -> Optional["IPAMConfig"]:
        """
        IPAMConfig configures IPAM module will be used for IP Address Management (IPAM).
        """
        return self.__ipamConfig

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
        rawCNIConfig: str = None,
        simpleMacvlanConfig: "SimpleMacvlanConfig" = None,
    ):
        super().__init__()
        self.__type = type
        self.__name = name
        self.__namespace = namespace
        self.__rawCNIConfig = rawCNIConfig
        self.__simpleMacvlanConfig = simpleMacvlanConfig

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
        rawCNIConfig = self.rawCNIConfig()
        check_type("rawCNIConfig", rawCNIConfig, Optional[str])
        if rawCNIConfig:  # omit empty
            v["rawCNIConfig"] = rawCNIConfig
        simpleMacvlanConfig = self.simpleMacvlanConfig()
        check_type(
            "simpleMacvlanConfig", simpleMacvlanConfig, Optional["SimpleMacvlanConfig"]
        )
        if simpleMacvlanConfig is not None:  # omit empty
            v["simpleMacvlanConfig"] = simpleMacvlanConfig
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

    def rawCNIConfig(self) -> Optional[str]:
        """
        rawCNIConfig is the raw CNI configuration json to create in the
        NetworkAttachmentDefinition CRD
        """
        return self.__rawCNIConfig

    def simpleMacvlanConfig(self) -> Optional["SimpleMacvlanConfig"]:
        """
        SimpleMacvlanConfig configures the macvlan interface in case of type:NetworkTypeSimpleMacvlan
        """
        return self.__simpleMacvlanConfig


class OperatorSpec(types.Object):
    """
    OperatorSpec contains common fields operators need.  It is intended to be anonymous included
    inside of the Spec struct for your particular operator.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        managementState: ManagementState = None,
        logLevel: LogLevel = None,
        operatorLogLevel: LogLevel = None,
        unsupportedConfigOverrides: "runtime.RawExtension" = None,
        observedConfig: "runtime.RawExtension" = None,
    ):
        super().__init__()
        self.__managementState = managementState
        self.__logLevel = logLevel
        self.__operatorLogLevel = operatorLogLevel
        self.__unsupportedConfigOverrides = unsupportedConfigOverrides
        self.__observedConfig = observedConfig

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        managementState = self.managementState()
        check_type("managementState", managementState, ManagementState)
        v["managementState"] = managementState
        logLevel = self.logLevel()
        check_type("logLevel", logLevel, LogLevel)
        v["logLevel"] = logLevel
        operatorLogLevel = self.operatorLogLevel()
        check_type("operatorLogLevel", operatorLogLevel, LogLevel)
        v["operatorLogLevel"] = operatorLogLevel
        unsupportedConfigOverrides = self.unsupportedConfigOverrides()
        check_type(
            "unsupportedConfigOverrides",
            unsupportedConfigOverrides,
            "runtime.RawExtension",
        )
        v["unsupportedConfigOverrides"] = unsupportedConfigOverrides
        observedConfig = self.observedConfig()
        check_type("observedConfig", observedConfig, "runtime.RawExtension")
        v["observedConfig"] = observedConfig
        return v

    def managementState(self) -> ManagementState:
        """
        managementState indicates whether and how the operator should manage the component
        """
        return self.__managementState

    def logLevel(self) -> LogLevel:
        """
        logLevel is an intent based logging for an overall component.  It does not give fine grained control, but it is a
        simple way to manage coarse grained logging choices that operators have to interpret for their operands.
        """
        return self.__logLevel

    def operatorLogLevel(self) -> LogLevel:
        """
        operatorLogLevel is an intent based logging for the operator itself.  It does not give fine grained control, but it is a
        simple way to manage coarse grained logging choices that operators have to interpret for themselves.
        """
        return self.__operatorLogLevel

    def unsupportedConfigOverrides(self) -> "runtime.RawExtension":
        """
        unsupportedConfigOverrides holds a sparse config that will override any previously set options.  It only needs to be the fields to override
        it will end up overlaying in the following order:
        1. hardcoded defaults
        2. observedConfig
        3. unsupportedConfigOverrides
        +nullable
        """
        return self.__unsupportedConfigOverrides

    def observedConfig(self) -> "runtime.RawExtension":
        """
        observedConfig holds a sparse config that controller has observed from the cluster state.  It exists in spec because
        it is an input to the level for the operator
        +nullable
        """
        return self.__observedConfig


class AuthenticationSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, operatorSpec: "OperatorSpec" = None):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "OperatorSpec")
        v.update(operatorSpec._root())  # inline
        return v

    def operatorSpec(self) -> "OperatorSpec":
        return self.__operatorSpec


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
            apiVersion="operator.openshift.io/v1",
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


class ClusterNetworkEntry(types.Object):
    """
    ClusterNetworkEntry is a subnet from which to allocate PodIPs. A network of size
    HostPrefix (in CIDR notation) will be allocated when nodes join the cluster.
    Not all network providers support multiple ClusterNetworks
    """

    @context.scoped
    @typechecked
    def __init__(self, cidr: str = "", hostPrefix: int = 0):
        super().__init__()
        self.__cidr = cidr
        self.__hostPrefix = hostPrefix

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cidr = self.cidr()
        check_type("cidr", cidr, str)
        v["cidr"] = cidr
        hostPrefix = self.hostPrefix()
        check_type("hostPrefix", hostPrefix, int)
        v["hostPrefix"] = hostPrefix
        return v

    def cidr(self) -> str:
        return self.__cidr

    def hostPrefix(self) -> int:
        return self.__hostPrefix


class ConsoleCustomization(types.Object):
    """
    ConsoleCustomization defines a list of optional configuration for the console UI.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        brand: Brand = None,
        documentationBaseURL: str = None,
        customProductName: str = None,
        customLogoFile: "configv1.ConfigMapFileReference" = None,
    ):
        super().__init__()
        self.__brand = brand
        self.__documentationBaseURL = documentationBaseURL
        self.__customProductName = customProductName
        self.__customLogoFile = (
            customLogoFile
            if customLogoFile is not None
            else configv1.ConfigMapFileReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        brand = self.brand()
        check_type("brand", brand, Optional[Brand])
        if brand:  # omit empty
            v["brand"] = brand
        documentationBaseURL = self.documentationBaseURL()
        check_type("documentationBaseURL", documentationBaseURL, Optional[str])
        if documentationBaseURL:  # omit empty
            v["documentationBaseURL"] = documentationBaseURL
        customProductName = self.customProductName()
        check_type("customProductName", customProductName, Optional[str])
        if customProductName:  # omit empty
            v["customProductName"] = customProductName
        customLogoFile = self.customLogoFile()
        check_type(
            "customLogoFile",
            customLogoFile,
            Optional["configv1.ConfigMapFileReference"],
        )
        v["customLogoFile"] = customLogoFile
        return v

    def brand(self) -> Optional[Brand]:
        """
        brand is the default branding of the web console which can be overridden by
        providing the brand field.  There is a limited set of specific brand options.
        This field controls elements of the console such as the logo.
        Invalid value will prevent a console rollout.
        """
        return self.__brand

    def documentationBaseURL(self) -> Optional[str]:
        """
        documentationBaseURL links to external documentation are shown in various sections
        of the web console.  Providing documentationBaseURL will override the default
        documentation URL.
        Invalid value will prevent a console rollout.
        """
        return self.__documentationBaseURL

    def customProductName(self) -> Optional[str]:
        """
        customProductName is the name that will be displayed in page titles, logo alt text, and the about dialog
        instead of the normal OpenShift product name.
        """
        return self.__customProductName

    def customLogoFile(self) -> Optional["configv1.ConfigMapFileReference"]:
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
        return self.__customLogoFile


class StatuspageProvider(types.Object):
    """
    StatuspageProvider provides identity for statuspage account.
    """

    @context.scoped
    @typechecked
    def __init__(self, pageID: str = ""):
        super().__init__()
        self.__pageID = pageID

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pageID = self.pageID()
        check_type("pageID", pageID, str)
        v["pageID"] = pageID
        return v

    def pageID(self) -> str:
        """
        pageID is the unique ID assigned by Statuspage for your page. This must be a public page.
        """
        return self.__pageID


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
        operatorSpec: "OperatorSpec" = None,
        customization: "ConsoleCustomization" = None,
        providers: "ConsoleProviders" = None,
    ):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else OperatorSpec()
        )
        self.__customization = (
            customization if customization is not None else ConsoleCustomization()
        )
        self.__providers = providers if providers is not None else ConsoleProviders()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "OperatorSpec")
        v.update(operatorSpec._root())  # inline
        customization = self.customization()
        check_type("customization", customization, "ConsoleCustomization")
        v["customization"] = customization
        providers = self.providers()
        check_type("providers", providers, "ConsoleProviders")
        v["providers"] = providers
        return v

    def operatorSpec(self) -> "OperatorSpec":
        return self.__operatorSpec

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
            apiVersion="operator.openshift.io/v1",
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
        forwardPlugin: "ForwardPlugin" = None,
    ):
        super().__init__()
        self.__name = name
        self.__zones = zones if zones is not None else []
        self.__forwardPlugin = (
            forwardPlugin if forwardPlugin is not None else ForwardPlugin()
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
        forwardPlugin = self.forwardPlugin()
        check_type("forwardPlugin", forwardPlugin, "ForwardPlugin")
        v["forwardPlugin"] = forwardPlugin
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

    def forwardPlugin(self) -> "ForwardPlugin":
        """
        forwardPlugin defines a schema for configuring CoreDNS to proxy DNS messages
        to upstream resolvers.
        """
        return self.__forwardPlugin


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
            apiVersion="operator.openshift.io/v1",
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
        daemonProbesPort: int = None,
        controllerProbesPort: int = None,
        openStackServiceNetwork: str = None,
        enablePortPoolsPrepopulation: bool = None,
        poolMaxPorts: int = None,
        poolMinPorts: int = None,
        poolBatchPorts: int = None,
    ):
        super().__init__()
        self.__daemonProbesPort = daemonProbesPort
        self.__controllerProbesPort = controllerProbesPort
        self.__openStackServiceNetwork = openStackServiceNetwork
        self.__enablePortPoolsPrepopulation = enablePortPoolsPrepopulation
        self.__poolMaxPorts = poolMaxPorts
        self.__poolMinPorts = poolMinPorts
        self.__poolBatchPorts = poolBatchPorts

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        daemonProbesPort = self.daemonProbesPort()
        check_type("daemonProbesPort", daemonProbesPort, Optional[int])
        if daemonProbesPort is not None:  # omit empty
            v["daemonProbesPort"] = daemonProbesPort
        controllerProbesPort = self.controllerProbesPort()
        check_type("controllerProbesPort", controllerProbesPort, Optional[int])
        if controllerProbesPort is not None:  # omit empty
            v["controllerProbesPort"] = controllerProbesPort
        openStackServiceNetwork = self.openStackServiceNetwork()
        check_type("openStackServiceNetwork", openStackServiceNetwork, Optional[str])
        if openStackServiceNetwork:  # omit empty
            v["openStackServiceNetwork"] = openStackServiceNetwork
        enablePortPoolsPrepopulation = self.enablePortPoolsPrepopulation()
        check_type(
            "enablePortPoolsPrepopulation", enablePortPoolsPrepopulation, Optional[bool]
        )
        if enablePortPoolsPrepopulation:  # omit empty
            v["enablePortPoolsPrepopulation"] = enablePortPoolsPrepopulation
        poolMaxPorts = self.poolMaxPorts()
        check_type("poolMaxPorts", poolMaxPorts, Optional[int])
        if poolMaxPorts:  # omit empty
            v["poolMaxPorts"] = poolMaxPorts
        poolMinPorts = self.poolMinPorts()
        check_type("poolMinPorts", poolMinPorts, Optional[int])
        if poolMinPorts:  # omit empty
            v["poolMinPorts"] = poolMinPorts
        poolBatchPorts = self.poolBatchPorts()
        check_type("poolBatchPorts", poolBatchPorts, Optional[int])
        if poolBatchPorts is not None:  # omit empty
            v["poolBatchPorts"] = poolBatchPorts
        return v

    def daemonProbesPort(self) -> Optional[int]:
        """
        The port kuryr-daemon will listen for readiness and liveness requests.
        """
        return self.__daemonProbesPort

    def controllerProbesPort(self) -> Optional[int]:
        """
        The port kuryr-controller will listen for readiness and liveness requests.
        """
        return self.__controllerProbesPort

    def openStackServiceNetwork(self) -> Optional[str]:
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
        return self.__openStackServiceNetwork

    def enablePortPoolsPrepopulation(self) -> Optional[bool]:
        """
        enablePortPoolsPrepopulation when true will make Kuryr prepopulate each newly created port
        pool with a minimum number of ports. Kuryr uses Neutron port pooling to fight the fact
        that it takes a significant amount of time to create one. Instead of creating it when
        pod is being deployed, Kuryr keeps a number of ports ready to be attached to pods. By
        default port prepopulation is disabled.
        """
        return self.__enablePortPoolsPrepopulation

    def poolMaxPorts(self) -> Optional[int]:
        """
        poolMaxPorts sets a maximum number of free ports that are being kept in a port pool.
        If the number of ports exceeds this setting, free ports will get deleted. Setting 0
        will disable this upper bound, effectively preventing pools from shrinking and this
        is the default value. For more information about port pools see
        enablePortPoolsPrepopulation setting.
        """
        return self.__poolMaxPorts

    def poolMinPorts(self) -> Optional[int]:
        """
        poolMinPorts sets a minimum number of free ports that should be kept in a port pool.
        If the number of ports is lower than this setting, new ports will get created and
        added to pool. The default is 1. For more information about port pools see
        enablePortPoolsPrepopulation setting.
        """
        return self.__poolMinPorts

    def poolBatchPorts(self) -> Optional[int]:
        """
        poolBatchPorts sets a number of ports that should be created in a single batch request
        to extend the port pool. The default is 3. For more information about port pools see
        enablePortPoolsPrepopulation setting.
        """
        return self.__poolBatchPorts


class HybridOverlayConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, hybridClusterNetwork: List["ClusterNetworkEntry"] = None):
        super().__init__()
        self.__hybridClusterNetwork = (
            hybridClusterNetwork if hybridClusterNetwork is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        hybridClusterNetwork = self.hybridClusterNetwork()
        check_type(
            "hybridClusterNetwork", hybridClusterNetwork, List["ClusterNetworkEntry"]
        )
        v["hybridClusterNetwork"] = hybridClusterNetwork
        return v

    def hybridClusterNetwork(self) -> List["ClusterNetworkEntry"]:
        """
        HybridClusterNetwork defines a network space given to nodes on an additional overlay network.
        """
        return self.__hybridClusterNetwork


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
        genevePort: int = None,
        hybridOverlayConfig: "HybridOverlayConfig" = None,
    ):
        super().__init__()
        self.__mtu = mtu
        self.__genevePort = genevePort
        self.__hybridOverlayConfig = hybridOverlayConfig

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        mtu = self.mtu()
        check_type("mtu", mtu, Optional[int])
        if mtu is not None:  # omit empty
            v["mtu"] = mtu
        genevePort = self.genevePort()
        check_type("genevePort", genevePort, Optional[int])
        if genevePort is not None:  # omit empty
            v["genevePort"] = genevePort
        hybridOverlayConfig = self.hybridOverlayConfig()
        check_type(
            "hybridOverlayConfig", hybridOverlayConfig, Optional["HybridOverlayConfig"]
        )
        if hybridOverlayConfig is not None:  # omit empty
            v["hybridOverlayConfig"] = hybridOverlayConfig
        return v

    def mtu(self) -> Optional[int]:
        """
        mtu is the MTU to use for the tunnel interface. This must be 100
        bytes smaller than the uplink mtu.
        Default is 1400
        """
        return self.__mtu

    def genevePort(self) -> Optional[int]:
        """
        geneve port is the UDP port to be used by geneve encapulation.
        Default is 6081
        """
        return self.__genevePort

    def hybridOverlayConfig(self) -> Optional["HybridOverlayConfig"]:
        """
        HybridOverlayConfig configures an additional overlay network for peers that are
        not using OVN.
        """
        return self.__hybridOverlayConfig


class OpenShiftSDNConfig(types.Object):
    """
    OpenShiftSDNConfig configures the three openshift-sdn plugins
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        mode: SDNMode = None,
        vxlanPort: int = None,
        mtu: int = None,
        useExternalOpenvswitch: bool = None,
        enableUnidling: bool = None,
    ):
        super().__init__()
        self.__mode = mode
        self.__vxlanPort = vxlanPort
        self.__mtu = mtu
        self.__useExternalOpenvswitch = useExternalOpenvswitch
        self.__enableUnidling = enableUnidling

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        mode = self.mode()
        check_type("mode", mode, SDNMode)
        v["mode"] = mode
        vxlanPort = self.vxlanPort()
        check_type("vxlanPort", vxlanPort, Optional[int])
        if vxlanPort is not None:  # omit empty
            v["vxlanPort"] = vxlanPort
        mtu = self.mtu()
        check_type("mtu", mtu, Optional[int])
        if mtu is not None:  # omit empty
            v["mtu"] = mtu
        useExternalOpenvswitch = self.useExternalOpenvswitch()
        check_type("useExternalOpenvswitch", useExternalOpenvswitch, Optional[bool])
        if useExternalOpenvswitch is not None:  # omit empty
            v["useExternalOpenvswitch"] = useExternalOpenvswitch
        enableUnidling = self.enableUnidling()
        check_type("enableUnidling", enableUnidling, Optional[bool])
        if enableUnidling is not None:  # omit empty
            v["enableUnidling"] = enableUnidling
        return v

    def mode(self) -> SDNMode:
        """
        mode is one of "Multitenant", "Subnet", or "NetworkPolicy"
        """
        return self.__mode

    def vxlanPort(self) -> Optional[int]:
        """
        vxlanPort is the port to use for all vxlan packets. The default is 4789.
        """
        return self.__vxlanPort

    def mtu(self) -> Optional[int]:
        """
        mtu is the mtu to use for the tunnel interface. Defaults to 1450 if unset.
        This must be 50 bytes smaller than the machine's uplink.
        """
        return self.__mtu

    def useExternalOpenvswitch(self) -> Optional[bool]:
        """
        useExternalOpenvswitch tells the operator not to install openvswitch, because
        it will be provided separately. If set, you must provide it yourself.
        """
        return self.__useExternalOpenvswitch

    def enableUnidling(self) -> Optional[bool]:
        """
        enableUnidling controls whether or not the service proxy will support idling
        and unidling of services. By default, unidling is enabled.
        """
        return self.__enableUnidling


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
        openshiftSDNConfig: "OpenShiftSDNConfig" = None,
        ovnKubernetesConfig: "OVNKubernetesConfig" = None,
        kuryrConfig: "KuryrConfig" = None,
    ):
        super().__init__()
        self.__type = type
        self.__openshiftSDNConfig = openshiftSDNConfig
        self.__ovnKubernetesConfig = ovnKubernetesConfig
        self.__kuryrConfig = kuryrConfig

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, NetworkType)
        v["type"] = type
        openshiftSDNConfig = self.openshiftSDNConfig()
        check_type(
            "openshiftSDNConfig", openshiftSDNConfig, Optional["OpenShiftSDNConfig"]
        )
        if openshiftSDNConfig is not None:  # omit empty
            v["openshiftSDNConfig"] = openshiftSDNConfig
        ovnKubernetesConfig = self.ovnKubernetesConfig()
        check_type(
            "ovnKubernetesConfig", ovnKubernetesConfig, Optional["OVNKubernetesConfig"]
        )
        if ovnKubernetesConfig is not None:  # omit empty
            v["ovnKubernetesConfig"] = ovnKubernetesConfig
        kuryrConfig = self.kuryrConfig()
        check_type("kuryrConfig", kuryrConfig, Optional["KuryrConfig"])
        if kuryrConfig is not None:  # omit empty
            v["kuryrConfig"] = kuryrConfig
        return v

    def type(self) -> NetworkType:
        """
        type is the type of network
        All NetworkTypes are supported except for NetworkTypeRaw
        """
        return self.__type

    def openshiftSDNConfig(self) -> Optional["OpenShiftSDNConfig"]:
        """
        openShiftSDNConfig configures the openshift-sdn plugin
        """
        return self.__openshiftSDNConfig

    def ovnKubernetesConfig(self) -> Optional["OVNKubernetesConfig"]:
        """
        oVNKubernetesConfig configures the ovn-kubernetes plugin. This is currently
        not implemented.
        """
        return self.__ovnKubernetesConfig

    def kuryrConfig(self) -> Optional["KuryrConfig"]:
        """
        KuryrConfig configures the kuryr plugin
        """
        return self.__kuryrConfig


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
        loadBalancer: "LoadBalancerStrategy" = None,
        hostNetwork: "HostNetworkStrategy" = None,
        private: "PrivateStrategy" = None,
    ):
        super().__init__()
        self.__type = type
        self.__loadBalancer = loadBalancer
        self.__hostNetwork = hostNetwork
        self.__private = private

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, EndpointPublishingStrategyType)
        v["type"] = type
        loadBalancer = self.loadBalancer()
        check_type("loadBalancer", loadBalancer, Optional["LoadBalancerStrategy"])
        if loadBalancer is not None:  # omit empty
            v["loadBalancer"] = loadBalancer
        hostNetwork = self.hostNetwork()
        check_type("hostNetwork", hostNetwork, Optional["HostNetworkStrategy"])
        if hostNetwork is not None:  # omit empty
            v["hostNetwork"] = hostNetwork
        private = self.private()
        check_type("private", private, Optional["PrivateStrategy"])
        if private is not None:  # omit empty
            v["private"] = private
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
        +unionDiscriminator
        +required
        """
        return self.__type

    def loadBalancer(self) -> Optional["LoadBalancerStrategy"]:
        """
        loadBalancer holds parameters for the load balancer. Present only if
        type is LoadBalancerService.
        """
        return self.__loadBalancer

    def hostNetwork(self) -> Optional["HostNetworkStrategy"]:
        """
        hostNetwork holds parameters for the HostNetwork endpoint publishing
        strategy. Present only if type is HostNetwork.
        """
        return self.__hostNetwork

    def private(self) -> Optional["PrivateStrategy"]:
        """
        private holds parameters for the Private endpoint publishing
        strategy. Present only if type is Private.
        """
        return self.__private


class StaticPodOperatorSpec(types.Object):
    """
    StaticPodOperatorSpec is spec for controllers that manage static pods.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        operatorSpec: "OperatorSpec" = None,
        forceRedeploymentReason: str = "",
        failedRevisionLimit: int = None,
        succeededRevisionLimit: int = None,
    ):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else OperatorSpec()
        )
        self.__forceRedeploymentReason = forceRedeploymentReason
        self.__failedRevisionLimit = failedRevisionLimit
        self.__succeededRevisionLimit = succeededRevisionLimit

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "OperatorSpec")
        v.update(operatorSpec._root())  # inline
        forceRedeploymentReason = self.forceRedeploymentReason()
        check_type("forceRedeploymentReason", forceRedeploymentReason, str)
        v["forceRedeploymentReason"] = forceRedeploymentReason
        failedRevisionLimit = self.failedRevisionLimit()
        check_type("failedRevisionLimit", failedRevisionLimit, Optional[int])
        if failedRevisionLimit:  # omit empty
            v["failedRevisionLimit"] = failedRevisionLimit
        succeededRevisionLimit = self.succeededRevisionLimit()
        check_type("succeededRevisionLimit", succeededRevisionLimit, Optional[int])
        if succeededRevisionLimit:  # omit empty
            v["succeededRevisionLimit"] = succeededRevisionLimit
        return v

    def operatorSpec(self) -> "OperatorSpec":
        return self.__operatorSpec

    def forceRedeploymentReason(self) -> str:
        """
        forceRedeploymentReason can be used to force the redeployment of the operand by providing a unique string.
        This provides a mechanism to kick a previously failed deployment and provide a reason why you think it will work
        this time instead of failing again on the same config.
        """
        return self.__forceRedeploymentReason

    def failedRevisionLimit(self) -> Optional[int]:
        """
        failedRevisionLimit is the number of failed static pod installer revisions to keep on disk and in the api
        -1 = unlimited, 0 or unset = 5 (default)
        """
        return self.__failedRevisionLimit

    def succeededRevisionLimit(self) -> Optional[int]:
        """
        succeededRevisionLimit is the number of successful static pod installer revisions to keep on disk and in the api
        -1 = unlimited, 0 or unset = 5 (default)
        """
        return self.__succeededRevisionLimit


class EtcdSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, staticPodOperatorSpec: "StaticPodOperatorSpec" = None):
        super().__init__()
        self.__staticPodOperatorSpec = (
            staticPodOperatorSpec
            if staticPodOperatorSpec is not None
            else StaticPodOperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        staticPodOperatorSpec = self.staticPodOperatorSpec()
        check_type(
            "staticPodOperatorSpec", staticPodOperatorSpec, "StaticPodOperatorSpec"
        )
        v.update(staticPodOperatorSpec._root())  # inline
        return v

    def staticPodOperatorSpec(self) -> "StaticPodOperatorSpec":
        return self.__staticPodOperatorSpec


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
            apiVersion="operator.openshift.io/v1",
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
        nodeSelector: "metav1.LabelSelector" = None,
        tolerations: List["k8sv1.Toleration"] = None,
    ):
        super().__init__()
        self.__nodeSelector = nodeSelector
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        nodeSelector = self.nodeSelector()
        check_type("nodeSelector", nodeSelector, Optional["metav1.LabelSelector"])
        if nodeSelector is not None:  # omit empty
            v["nodeSelector"] = nodeSelector
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    def nodeSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        nodeSelector is the node selector applied to ingress controller
        deployments.
        
        If unset, the default is:
        
          beta.kubernetes.io/os: linux
          node-role.kubernetes.io/worker: ''
        
        If set, the specified selector is used and replaces the default.
        """
        return self.__nodeSelector

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        tolerations is a list of tolerations applied to ingress controller
        deployments.
        
        The default is an empty list.
        
        See https://kubernetes.io/docs/concepts/configuration/taint-and-toleration/
        """
        return self.__tolerations


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
        endpointPublishingStrategy: "EndpointPublishingStrategy" = None,
        defaultCertificate: "k8sv1.LocalObjectReference" = None,
        namespaceSelector: "metav1.LabelSelector" = None,
        routeSelector: "metav1.LabelSelector" = None,
        nodePlacement: "NodePlacement" = None,
        tlsSecurityProfile: "configv1.TLSSecurityProfile" = None,
    ):
        super().__init__()
        self.__domain = domain
        self.__replicas = replicas
        self.__endpointPublishingStrategy = endpointPublishingStrategy
        self.__defaultCertificate = defaultCertificate
        self.__namespaceSelector = namespaceSelector
        self.__routeSelector = routeSelector
        self.__nodePlacement = nodePlacement
        self.__tlsSecurityProfile = tlsSecurityProfile

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
        endpointPublishingStrategy = self.endpointPublishingStrategy()
        check_type(
            "endpointPublishingStrategy",
            endpointPublishingStrategy,
            Optional["EndpointPublishingStrategy"],
        )
        if endpointPublishingStrategy is not None:  # omit empty
            v["endpointPublishingStrategy"] = endpointPublishingStrategy
        defaultCertificate = self.defaultCertificate()
        check_type(
            "defaultCertificate",
            defaultCertificate,
            Optional["k8sv1.LocalObjectReference"],
        )
        if defaultCertificate is not None:  # omit empty
            v["defaultCertificate"] = defaultCertificate
        namespaceSelector = self.namespaceSelector()
        check_type(
            "namespaceSelector", namespaceSelector, Optional["metav1.LabelSelector"]
        )
        if namespaceSelector is not None:  # omit empty
            v["namespaceSelector"] = namespaceSelector
        routeSelector = self.routeSelector()
        check_type("routeSelector", routeSelector, Optional["metav1.LabelSelector"])
        if routeSelector is not None:  # omit empty
            v["routeSelector"] = routeSelector
        nodePlacement = self.nodePlacement()
        check_type("nodePlacement", nodePlacement, Optional["NodePlacement"])
        if nodePlacement is not None:  # omit empty
            v["nodePlacement"] = nodePlacement
        tlsSecurityProfile = self.tlsSecurityProfile()
        check_type(
            "tlsSecurityProfile",
            tlsSecurityProfile,
            Optional["configv1.TLSSecurityProfile"],
        )
        if tlsSecurityProfile is not None:  # omit empty
            v["tlsSecurityProfile"] = tlsSecurityProfile
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

    def endpointPublishingStrategy(self) -> Optional["EndpointPublishingStrategy"]:
        """
        endpointPublishingStrategy is used to publish the ingress controller
        endpoints to other networks, enable load balancer integrations, etc.
        
        If unset, the default is based on
        infrastructure.config.openshift.io/cluster .status.platform:
        
          AWS:      LoadBalancerService (with External scope)
          Azure:    LoadBalancerService (with External scope)
          GCP:      LoadBalancerService (with External scope)
          Libvirt:  HostNetwork
        
        Any other platform types (including None) default to HostNetwork.
        
        endpointPublishingStrategy cannot be updated.
        """
        return self.__endpointPublishingStrategy

    def defaultCertificate(self) -> Optional["k8sv1.LocalObjectReference"]:
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
        return self.__defaultCertificate

    def namespaceSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        namespaceSelector is used to filter the set of namespaces serviced by the
        ingress controller. This is useful for implementing shards.
        
        If unset, the default is no filtering.
        """
        return self.__namespaceSelector

    def routeSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        routeSelector is used to filter the set of Routes serviced by the ingress
        controller. This is useful for implementing shards.
        
        If unset, the default is no filtering.
        """
        return self.__routeSelector

    def nodePlacement(self) -> Optional["NodePlacement"]:
        """
        nodePlacement enables explicit control over the scheduling of the ingress
        controller.
        
        If unset, defaults are used. See NodePlacement for more details.
        """
        return self.__nodePlacement

    def tlsSecurityProfile(self) -> Optional["configv1.TLSSecurityProfile"]:
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
        return self.__tlsSecurityProfile


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
            apiVersion="operator.openshift.io/v1",
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
    def __init__(self, staticPodOperatorSpec: "StaticPodOperatorSpec" = None):
        super().__init__()
        self.__staticPodOperatorSpec = (
            staticPodOperatorSpec
            if staticPodOperatorSpec is not None
            else StaticPodOperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        staticPodOperatorSpec = self.staticPodOperatorSpec()
        check_type(
            "staticPodOperatorSpec", staticPodOperatorSpec, "StaticPodOperatorSpec"
        )
        v.update(staticPodOperatorSpec._root())  # inline
        return v

    def staticPodOperatorSpec(self) -> "StaticPodOperatorSpec":
        return self.__staticPodOperatorSpec


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
            apiVersion="operator.openshift.io/v1",
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
    def __init__(self, staticPodOperatorSpec: "StaticPodOperatorSpec" = None):
        super().__init__()
        self.__staticPodOperatorSpec = (
            staticPodOperatorSpec
            if staticPodOperatorSpec is not None
            else StaticPodOperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        staticPodOperatorSpec = self.staticPodOperatorSpec()
        check_type(
            "staticPodOperatorSpec", staticPodOperatorSpec, "StaticPodOperatorSpec"
        )
        v.update(staticPodOperatorSpec._root())  # inline
        return v

    def staticPodOperatorSpec(self) -> "StaticPodOperatorSpec":
        return self.__staticPodOperatorSpec


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
            apiVersion="operator.openshift.io/v1",
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
    def __init__(self, staticPodOperatorSpec: "StaticPodOperatorSpec" = None):
        super().__init__()
        self.__staticPodOperatorSpec = (
            staticPodOperatorSpec
            if staticPodOperatorSpec is not None
            else StaticPodOperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        staticPodOperatorSpec = self.staticPodOperatorSpec()
        check_type(
            "staticPodOperatorSpec", staticPodOperatorSpec, "StaticPodOperatorSpec"
        )
        v.update(staticPodOperatorSpec._root())  # inline
        return v

    def staticPodOperatorSpec(self) -> "StaticPodOperatorSpec":
        return self.__staticPodOperatorSpec


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
            apiVersion="operator.openshift.io/v1",
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
    def __init__(self, operatorSpec: "OperatorSpec" = None):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "OperatorSpec")
        v.update(operatorSpec._root())  # inline
        return v

    def operatorSpec(self) -> "OperatorSpec":
        return self.__operatorSpec


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
            apiVersion="operator.openshift.io/v1",
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
        iptablesSyncPeriod: str = None,
        bindAddress: str = None,
        proxyArguments: Dict[str, List[str]] = None,
    ):
        super().__init__()
        self.__iptablesSyncPeriod = iptablesSyncPeriod
        self.__bindAddress = bindAddress
        self.__proxyArguments = proxyArguments if proxyArguments is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        iptablesSyncPeriod = self.iptablesSyncPeriod()
        check_type("iptablesSyncPeriod", iptablesSyncPeriod, Optional[str])
        if iptablesSyncPeriod:  # omit empty
            v["iptablesSyncPeriod"] = iptablesSyncPeriod
        bindAddress = self.bindAddress()
        check_type("bindAddress", bindAddress, Optional[str])
        if bindAddress:  # omit empty
            v["bindAddress"] = bindAddress
        proxyArguments = self.proxyArguments()
        check_type("proxyArguments", proxyArguments, Optional[Dict[str, List[str]]])
        if proxyArguments:  # omit empty
            v["proxyArguments"] = proxyArguments
        return v

    def iptablesSyncPeriod(self) -> Optional[str]:
        """
        The period that iptables rules are refreshed.
        Default: 30s
        """
        return self.__iptablesSyncPeriod

    def bindAddress(self) -> Optional[str]:
        """
        The address to "bind" on
        Defaults to 0.0.0.0
        """
        return self.__bindAddress

    def proxyArguments(self) -> Optional[Dict[str, List[str]]]:
        """
        Any additional arguments to pass to the kubeproxy process
        """
        return self.__proxyArguments


class NetworkSpec(types.Object):
    """
    NetworkSpec is the top-level network configuration object.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        clusterNetwork: List["ClusterNetworkEntry"] = None,
        serviceNetwork: List[str] = None,
        defaultNetwork: "DefaultNetworkDefinition" = None,
        additionalNetworks: List["AdditionalNetworkDefinition"] = None,
        disableMultiNetwork: bool = None,
        deployKubeProxy: bool = None,
        kubeProxyConfig: "ProxyConfig" = None,
        logLevel: LogLevel = None,
    ):
        super().__init__()
        self.__clusterNetwork = clusterNetwork if clusterNetwork is not None else []
        self.__serviceNetwork = serviceNetwork if serviceNetwork is not None else []
        self.__defaultNetwork = (
            defaultNetwork if defaultNetwork is not None else DefaultNetworkDefinition()
        )
        self.__additionalNetworks = (
            additionalNetworks if additionalNetworks is not None else []
        )
        self.__disableMultiNetwork = disableMultiNetwork
        self.__deployKubeProxy = deployKubeProxy
        self.__kubeProxyConfig = kubeProxyConfig
        self.__logLevel = logLevel

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clusterNetwork = self.clusterNetwork()
        check_type("clusterNetwork", clusterNetwork, List["ClusterNetworkEntry"])
        v["clusterNetwork"] = clusterNetwork
        serviceNetwork = self.serviceNetwork()
        check_type("serviceNetwork", serviceNetwork, List[str])
        v["serviceNetwork"] = serviceNetwork
        defaultNetwork = self.defaultNetwork()
        check_type("defaultNetwork", defaultNetwork, "DefaultNetworkDefinition")
        v["defaultNetwork"] = defaultNetwork
        additionalNetworks = self.additionalNetworks()
        check_type(
            "additionalNetworks",
            additionalNetworks,
            Optional[List["AdditionalNetworkDefinition"]],
        )
        if additionalNetworks:  # omit empty
            v["additionalNetworks"] = additionalNetworks
        disableMultiNetwork = self.disableMultiNetwork()
        check_type("disableMultiNetwork", disableMultiNetwork, Optional[bool])
        if disableMultiNetwork is not None:  # omit empty
            v["disableMultiNetwork"] = disableMultiNetwork
        deployKubeProxy = self.deployKubeProxy()
        check_type("deployKubeProxy", deployKubeProxy, Optional[bool])
        if deployKubeProxy is not None:  # omit empty
            v["deployKubeProxy"] = deployKubeProxy
        kubeProxyConfig = self.kubeProxyConfig()
        check_type("kubeProxyConfig", kubeProxyConfig, Optional["ProxyConfig"])
        if kubeProxyConfig is not None:  # omit empty
            v["kubeProxyConfig"] = kubeProxyConfig
        logLevel = self.logLevel()
        check_type("logLevel", logLevel, LogLevel)
        v["logLevel"] = logLevel
        return v

    def clusterNetwork(self) -> List["ClusterNetworkEntry"]:
        """
        clusterNetwork is the IP address pool to use for pod IPs.
        Some network providers, e.g. OpenShift SDN, support multiple ClusterNetworks.
        Others only support one. This is equivalent to the cluster-cidr.
        """
        return self.__clusterNetwork

    def serviceNetwork(self) -> List[str]:
        """
        serviceNetwork is the ip address pool to use for Service IPs
        Currently, all existing network providers only support a single value
        here, but this is an array to allow for growth.
        """
        return self.__serviceNetwork

    def defaultNetwork(self) -> "DefaultNetworkDefinition":
        """
        defaultNetwork is the "default" network that all pods will receive
        """
        return self.__defaultNetwork

    def additionalNetworks(self) -> Optional[List["AdditionalNetworkDefinition"]]:
        """
        additionalNetworks is a list of extra networks to make available to pods
        when multiple networks are enabled.
        """
        return self.__additionalNetworks

    def disableMultiNetwork(self) -> Optional[bool]:
        """
        disableMultiNetwork specifies whether or not multiple pod network
        support should be disabled. If unset, this property defaults to
        'false' and multiple network support is enabled.
        """
        return self.__disableMultiNetwork

    def deployKubeProxy(self) -> Optional[bool]:
        """
        deployKubeProxy specifies whether or not a standalone kube-proxy should
        be deployed by the operator. Some network providers include kube-proxy
        or similar functionality. If unset, the plugin will attempt to select
        the correct value, which is false when OpenShift SDN and ovn-kubernetes are
        used and true otherwise.
        """
        return self.__deployKubeProxy

    def kubeProxyConfig(self) -> Optional["ProxyConfig"]:
        """
        kubeProxyConfig lets us configure desired proxy configuration.
        If not specified, sensible defaults will be chosen by OpenShift directly.
        Not consumed by all network providers - currently only openshift-sdn.
        """
        return self.__kubeProxyConfig

    def logLevel(self) -> LogLevel:
        """
        logLevel allows configuring the logging level of the components deployed
        by the operator. Currently only Kuryr SDN is affected by this setting.
        Please note that turning on extensive logging may affect performance.
        The default value is "Normal".
        """
        return self.__logLevel


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
            apiVersion="operator.openshift.io/v1",
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
    def __init__(self, operatorSpec: "OperatorSpec" = None):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "OperatorSpec")
        v.update(operatorSpec._root())  # inline
        return v

    def operatorSpec(self) -> "OperatorSpec":
        return self.__operatorSpec


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
            apiVersion="operator.openshift.io/v1",
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
    def __init__(self, operatorSpec: "OperatorSpec" = None):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "OperatorSpec")
        v.update(operatorSpec._root())  # inline
        return v

    def operatorSpec(self) -> "OperatorSpec":
        return self.__operatorSpec


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
            apiVersion="operator.openshift.io/v1",
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
    def __init__(self, operatorSpec: "OperatorSpec" = None):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "OperatorSpec")
        v.update(operatorSpec._root())  # inline
        return v

    def operatorSpec(self) -> "OperatorSpec":
        return self.__operatorSpec


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
            apiVersion="operator.openshift.io/v1",
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
    def __init__(self, operatorSpec: "OperatorSpec" = None):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "OperatorSpec")
        v.update(operatorSpec._root())  # inline
        return v

    def operatorSpec(self) -> "OperatorSpec":
        return self.__operatorSpec


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
            apiVersion="operator.openshift.io/v1",
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
    def __init__(self, operatorSpec: "OperatorSpec" = None):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "OperatorSpec")
        v.update(operatorSpec._root())  # inline
        return v

    def operatorSpec(self) -> "OperatorSpec":
        return self.__operatorSpec


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
            apiVersion="operator.openshift.io/v1",
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
