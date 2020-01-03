# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.openshift.config import v1 as configv1
from kubespec.openshift.config.osin import v1 as osinv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


class AggregatorConfig(types.Object):
    """
    AggregatorConfig holds information required to make the aggregator function.
    """

    @context.scoped
    @typechecked
    def __init__(self, proxyClientInfo: "configv1.CertInfo" = None):
        super().__init__()
        self.__proxyClientInfo = (
            proxyClientInfo if proxyClientInfo is not None else configv1.CertInfo()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        proxyClientInfo = self.proxyClientInfo()
        check_type("proxyClientInfo", proxyClientInfo, "configv1.CertInfo")
        v["proxyClientInfo"] = proxyClientInfo
        return v

    def proxyClientInfo(self) -> "configv1.CertInfo":
        """
        proxyClientInfo specifies the client cert/key to use when proxying to aggregated API servers
        """
        return self.__proxyClientInfo


class KubeAPIServerImagePolicyConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        internalRegistryHostname: str = "",
        externalRegistryHostnames: List[str] = None,
    ):
        super().__init__()
        self.__internalRegistryHostname = internalRegistryHostname
        self.__externalRegistryHostnames = (
            externalRegistryHostnames if externalRegistryHostnames is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        internalRegistryHostname = self.internalRegistryHostname()
        check_type("internalRegistryHostname", internalRegistryHostname, str)
        v["internalRegistryHostname"] = internalRegistryHostname
        externalRegistryHostnames = self.externalRegistryHostnames()
        check_type("externalRegistryHostnames", externalRegistryHostnames, List[str])
        v["externalRegistryHostnames"] = externalRegistryHostnames
        return v

    def internalRegistryHostname(self) -> str:
        """
        internalRegistryHostname sets the hostname for the default internal image
        registry. The value must be in "hostname[:port]" format.
        For backward compatibility, users can still use OPENSHIFT_DEFAULT_REGISTRY
        environment variable but this setting overrides the environment variable.
        """
        return self.__internalRegistryHostname

    def externalRegistryHostnames(self) -> List[str]:
        """
        externalRegistryHostnames provides the hostnames for the default external image
        registry. The external hostname should be set only when the image registry
        is exposed externally. The first value is used in 'publicDockerImageRepository'
        field in ImageStreams. The value must be in "hostname[:port]" format.
        """
        return self.__externalRegistryHostnames


class KubeAPIServerProjectConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, defaultNodeSelector: str = ""):
        super().__init__()
        self.__defaultNodeSelector = defaultNodeSelector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        defaultNodeSelector = self.defaultNodeSelector()
        check_type("defaultNodeSelector", defaultNodeSelector, str)
        v["defaultNodeSelector"] = defaultNodeSelector
        return v

    def defaultNodeSelector(self) -> str:
        """
        defaultNodeSelector holds default project node label selector
        """
        return self.__defaultNodeSelector


class KubeletConnectionInfo(types.Object):
    """
    KubeletConnectionInfo holds information necessary for connecting to a kubelet
    """

    @context.scoped
    @typechecked
    def __init__(
        self, port: int = 0, ca: str = "", certInfo: "configv1.CertInfo" = None
    ):
        super().__init__()
        self.__port = port
        self.__ca = ca
        self.__certInfo = certInfo if certInfo is not None else configv1.CertInfo()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        port = self.port()
        check_type("port", port, int)
        v["port"] = port
        ca = self.ca()
        check_type("ca", ca, str)
        v["ca"] = ca
        certInfo = self.certInfo()
        check_type("certInfo", certInfo, "configv1.CertInfo")
        v.update(certInfo._root())  # inline
        return v

    def port(self) -> int:
        """
        port is the port to connect to kubelets on
        """
        return self.__port

    def ca(self) -> str:
        """
        ca is the CA for verifying TLS connections to kubelets
        """
        return self.__ca

    def certInfo(self) -> "configv1.CertInfo":
        """
        CertInfo is the TLS client cert information for securing communication to kubelets
        this is anonymous so that we can inline it for serialization
        """
        return self.__certInfo


class RequestHeaderAuthenticationOptions(types.Object):
    """
    RequestHeaderAuthenticationOptions provides options for setting up a front proxy against the entire
    API instead of against the /oauth endpoint.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        clientCA: str = "",
        clientCommonNames: List[str] = None,
        usernameHeaders: List[str] = None,
        groupHeaders: List[str] = None,
        extraHeaderPrefixes: List[str] = None,
    ):
        super().__init__()
        self.__clientCA = clientCA
        self.__clientCommonNames = (
            clientCommonNames if clientCommonNames is not None else []
        )
        self.__usernameHeaders = usernameHeaders if usernameHeaders is not None else []
        self.__groupHeaders = groupHeaders if groupHeaders is not None else []
        self.__extraHeaderPrefixes = (
            extraHeaderPrefixes if extraHeaderPrefixes is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientCA = self.clientCA()
        check_type("clientCA", clientCA, str)
        v["clientCA"] = clientCA
        clientCommonNames = self.clientCommonNames()
        check_type("clientCommonNames", clientCommonNames, List[str])
        v["clientCommonNames"] = clientCommonNames
        usernameHeaders = self.usernameHeaders()
        check_type("usernameHeaders", usernameHeaders, List[str])
        v["usernameHeaders"] = usernameHeaders
        groupHeaders = self.groupHeaders()
        check_type("groupHeaders", groupHeaders, List[str])
        v["groupHeaders"] = groupHeaders
        extraHeaderPrefixes = self.extraHeaderPrefixes()
        check_type("extraHeaderPrefixes", extraHeaderPrefixes, List[str])
        v["extraHeaderPrefixes"] = extraHeaderPrefixes
        return v

    def clientCA(self) -> str:
        """
        clientCA is a file with the trusted signer certs.  It is required.
        """
        return self.__clientCA

    def clientCommonNames(self) -> List[str]:
        """
        clientCommonNames is a required list of common names to require a match from.
        """
        return self.__clientCommonNames

    def usernameHeaders(self) -> List[str]:
        """
        usernameHeaders is the list of headers to check for user information.  First hit wins.
        """
        return self.__usernameHeaders

    def groupHeaders(self) -> List[str]:
        """
        groupHeaders is the set of headers to check for group information.  All are unioned.
        """
        return self.__groupHeaders

    def extraHeaderPrefixes(self) -> List[str]:
        """
        extraHeaderPrefixes is the set of request header prefixes to inspect for user extra. X-Remote-Extra- is suggested.
        """
        return self.__extraHeaderPrefixes


class WebhookTokenAuthenticator(types.Object):
    """
    WebhookTokenAuthenticators holds the necessary configuation options for
    external token authenticators
    """

    @context.scoped
    @typechecked
    def __init__(self, configFile: str = "", cacheTTL: str = ""):
        super().__init__()
        self.__configFile = configFile
        self.__cacheTTL = cacheTTL

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        configFile = self.configFile()
        check_type("configFile", configFile, str)
        v["configFile"] = configFile
        cacheTTL = self.cacheTTL()
        check_type("cacheTTL", cacheTTL, str)
        v["cacheTTL"] = cacheTTL
        return v

    def configFile(self) -> str:
        """
        configFile is a path to a Kubeconfig file with the webhook configuration
        """
        return self.__configFile

    def cacheTTL(self) -> str:
        """
        cacheTTL indicates how long an authentication result should be cached.
        It takes a valid time duration string (e.g. "5m").
        If empty, you get a default timeout of 2 minutes.
        If zero (e.g. "0m"), caching is disabled
        """
        return self.__cacheTTL


class MasterAuthConfig(types.Object):
    """
    MasterAuthConfig configures authentication options in addition to the standard
    oauth token and client certificate authenticators
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        requestHeader: "RequestHeaderAuthenticationOptions" = None,
        webhookTokenAuthenticators: List["WebhookTokenAuthenticator"] = None,
        oauthMetadataFile: str = "",
    ):
        super().__init__()
        self.__requestHeader = requestHeader
        self.__webhookTokenAuthenticators = (
            webhookTokenAuthenticators if webhookTokenAuthenticators is not None else []
        )
        self.__oauthMetadataFile = oauthMetadataFile

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        requestHeader = self.requestHeader()
        check_type(
            "requestHeader",
            requestHeader,
            Optional["RequestHeaderAuthenticationOptions"],
        )
        v["requestHeader"] = requestHeader
        webhookTokenAuthenticators = self.webhookTokenAuthenticators()
        check_type(
            "webhookTokenAuthenticators",
            webhookTokenAuthenticators,
            List["WebhookTokenAuthenticator"],
        )
        v["webhookTokenAuthenticators"] = webhookTokenAuthenticators
        oauthMetadataFile = self.oauthMetadataFile()
        check_type("oauthMetadataFile", oauthMetadataFile, str)
        v["oauthMetadataFile"] = oauthMetadataFile
        return v

    def requestHeader(self) -> Optional["RequestHeaderAuthenticationOptions"]:
        """
        requestHeader holds options for setting up a front proxy against the the API.  It is optional.
        """
        return self.__requestHeader

    def webhookTokenAuthenticators(self) -> List["WebhookTokenAuthenticator"]:
        """
        webhookTokenAuthenticators, if present configures remote token reviewers
        """
        return self.__webhookTokenAuthenticators

    def oauthMetadataFile(self) -> str:
        """
        oauthMetadataFile is a path to a file containing the discovery endpoint for OAuth 2.0 Authorization
        Server Metadata for an external OAuth server.
        See IETF Draft: // https://tools.ietf.org/html/draft-ietf-oauth-discovery-04#section-2
        This option is mutually exclusive with OAuthConfig
        """
        return self.__oauthMetadataFile


class UserAgentMatchRule(types.Object):
    """
    UserAgentMatchRule describes how to match a given request based on User-Agent and HTTPVerb
    """

    @context.scoped
    @typechecked
    def __init__(self, regex: str = "", httpVerbs: List[str] = None):
        super().__init__()
        self.__regex = regex
        self.__httpVerbs = httpVerbs if httpVerbs is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        regex = self.regex()
        check_type("regex", regex, str)
        v["regex"] = regex
        httpVerbs = self.httpVerbs()
        check_type("httpVerbs", httpVerbs, List[str])
        v["httpVerbs"] = httpVerbs
        return v

    def regex(self) -> str:
        """
        regex is a regex that is checked against the User-Agent.
        Known variants of oc clients
        1. oc accessing kube resources: oc/v1.2.0 (linux/amd64) kubernetes/bc4550d
        2. oc accessing openshift resources: oc/v1.1.3 (linux/amd64) openshift/b348c2f
        3. openshift kubectl accessing kube resources:  openshift/v1.2.0 (linux/amd64) kubernetes/bc4550d
        4. openshift kubectl accessing openshift resources: openshift/v1.1.3 (linux/amd64) openshift/b348c2f
        5. oadm accessing kube resources: oadm/v1.2.0 (linux/amd64) kubernetes/bc4550d
        6. oadm accessing openshift resources: oadm/v1.1.3 (linux/amd64) openshift/b348c2f
        7. openshift cli accessing kube resources: openshift/v1.2.0 (linux/amd64) kubernetes/bc4550d
        8. openshift cli accessing openshift resources: openshift/v1.1.3 (linux/amd64) openshift/b348c2f
        """
        return self.__regex

    def httpVerbs(self) -> List[str]:
        """
        httpVerbs specifies which HTTP verbs should be matched.  An empty list means "match all verbs".
        """
        return self.__httpVerbs


class UserAgentDenyRule(types.Object):
    """
    UserAgentDenyRule adds a rejection message that can be used to help a user figure out how to get an approved client
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        userAgentMatchRule: "UserAgentMatchRule" = None,
        rejectionMessage: str = "",
    ):
        super().__init__()
        self.__userAgentMatchRule = (
            userAgentMatchRule
            if userAgentMatchRule is not None
            else UserAgentMatchRule()
        )
        self.__rejectionMessage = rejectionMessage

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        userAgentMatchRule = self.userAgentMatchRule()
        check_type("userAgentMatchRule", userAgentMatchRule, "UserAgentMatchRule")
        v.update(userAgentMatchRule._root())  # inline
        rejectionMessage = self.rejectionMessage()
        check_type("rejectionMessage", rejectionMessage, str)
        v["rejectionMessage"] = rejectionMessage
        return v

    def userAgentMatchRule(self) -> "UserAgentMatchRule":
        return self.__userAgentMatchRule

    def rejectionMessage(self) -> str:
        """
        RejectionMessage is the message shown when rejecting a client.  If it is not a set, the default message is used.
        """
        return self.__rejectionMessage


class UserAgentMatchingConfig(types.Object):
    """
    UserAgentMatchingConfig controls how API calls from *voluntarily* identifying clients will be handled.  THIS DOES NOT DEFEND AGAINST MALICIOUS CLIENTS!
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        requiredClients: List["UserAgentMatchRule"] = None,
        deniedClients: List["UserAgentDenyRule"] = None,
        defaultRejectionMessage: str = "",
    ):
        super().__init__()
        self.__requiredClients = requiredClients if requiredClients is not None else []
        self.__deniedClients = deniedClients if deniedClients is not None else []
        self.__defaultRejectionMessage = defaultRejectionMessage

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        requiredClients = self.requiredClients()
        check_type("requiredClients", requiredClients, List["UserAgentMatchRule"])
        v["requiredClients"] = requiredClients
        deniedClients = self.deniedClients()
        check_type("deniedClients", deniedClients, List["UserAgentDenyRule"])
        v["deniedClients"] = deniedClients
        defaultRejectionMessage = self.defaultRejectionMessage()
        check_type("defaultRejectionMessage", defaultRejectionMessage, str)
        v["defaultRejectionMessage"] = defaultRejectionMessage
        return v

    def requiredClients(self) -> List["UserAgentMatchRule"]:
        """
        requiredClients if this list is non-empty, then a User-Agent must match one of the UserAgentRegexes to be allowed
        """
        return self.__requiredClients

    def deniedClients(self) -> List["UserAgentDenyRule"]:
        """
        deniedClients if this list is non-empty, then a User-Agent must not match any of the UserAgentRegexes
        """
        return self.__deniedClients

    def defaultRejectionMessage(self) -> str:
        """
        defaultRejectionMessage is the message shown when rejecting a client.  If it is not a set, a generic message is given.
        """
        return self.__defaultRejectionMessage


class KubeAPIServerConfig(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        genericAPIServerConfig: "configv1.GenericAPIServerConfig" = None,
        authConfig: "MasterAuthConfig" = None,
        aggregatorConfig: "AggregatorConfig" = None,
        kubeletClientInfo: "KubeletConnectionInfo" = None,
        servicesSubnet: str = "",
        servicesNodePortRange: str = "",
        consolePublicURL: str = "",
        userAgentMatchingConfig: "UserAgentMatchingConfig" = None,
        imagePolicyConfig: "KubeAPIServerImagePolicyConfig" = None,
        projectConfig: "KubeAPIServerProjectConfig" = None,
        serviceAccountPublicKeyFiles: List[str] = None,
        oauthConfig: "osinv1.OAuthConfig" = None,
        apiServerArguments: Dict[str, List[str]] = None,
    ):
        super().__init__(
            apiVersion="kubecontrolplane.config.openshift.io/v1",
            kind="KubeAPIServerConfig",
        )
        self.__genericAPIServerConfig = (
            genericAPIServerConfig
            if genericAPIServerConfig is not None
            else configv1.GenericAPIServerConfig()
        )
        self.__authConfig = authConfig if authConfig is not None else MasterAuthConfig()
        self.__aggregatorConfig = (
            aggregatorConfig if aggregatorConfig is not None else AggregatorConfig()
        )
        self.__kubeletClientInfo = (
            kubeletClientInfo
            if kubeletClientInfo is not None
            else KubeletConnectionInfo()
        )
        self.__servicesSubnet = servicesSubnet
        self.__servicesNodePortRange = servicesNodePortRange
        self.__consolePublicURL = consolePublicURL
        self.__userAgentMatchingConfig = (
            userAgentMatchingConfig
            if userAgentMatchingConfig is not None
            else UserAgentMatchingConfig()
        )
        self.__imagePolicyConfig = (
            imagePolicyConfig
            if imagePolicyConfig is not None
            else KubeAPIServerImagePolicyConfig()
        )
        self.__projectConfig = (
            projectConfig if projectConfig is not None else KubeAPIServerProjectConfig()
        )
        self.__serviceAccountPublicKeyFiles = (
            serviceAccountPublicKeyFiles
            if serviceAccountPublicKeyFiles is not None
            else []
        )
        self.__oauthConfig = oauthConfig
        self.__apiServerArguments = (
            apiServerArguments if apiServerArguments is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        genericAPIServerConfig = self.genericAPIServerConfig()
        check_type(
            "genericAPIServerConfig",
            genericAPIServerConfig,
            "configv1.GenericAPIServerConfig",
        )
        v.update(genericAPIServerConfig._root())  # inline
        authConfig = self.authConfig()
        check_type("authConfig", authConfig, "MasterAuthConfig")
        v["authConfig"] = authConfig
        aggregatorConfig = self.aggregatorConfig()
        check_type("aggregatorConfig", aggregatorConfig, "AggregatorConfig")
        v["aggregatorConfig"] = aggregatorConfig
        kubeletClientInfo = self.kubeletClientInfo()
        check_type("kubeletClientInfo", kubeletClientInfo, "KubeletConnectionInfo")
        v["kubeletClientInfo"] = kubeletClientInfo
        servicesSubnet = self.servicesSubnet()
        check_type("servicesSubnet", servicesSubnet, str)
        v["servicesSubnet"] = servicesSubnet
        servicesNodePortRange = self.servicesNodePortRange()
        check_type("servicesNodePortRange", servicesNodePortRange, str)
        v["servicesNodePortRange"] = servicesNodePortRange
        consolePublicURL = self.consolePublicURL()
        check_type("consolePublicURL", consolePublicURL, str)
        v["consolePublicURL"] = consolePublicURL
        userAgentMatchingConfig = self.userAgentMatchingConfig()
        check_type(
            "userAgentMatchingConfig",
            userAgentMatchingConfig,
            "UserAgentMatchingConfig",
        )
        v["userAgentMatchingConfig"] = userAgentMatchingConfig
        imagePolicyConfig = self.imagePolicyConfig()
        check_type(
            "imagePolicyConfig", imagePolicyConfig, "KubeAPIServerImagePolicyConfig"
        )
        v["imagePolicyConfig"] = imagePolicyConfig
        projectConfig = self.projectConfig()
        check_type("projectConfig", projectConfig, "KubeAPIServerProjectConfig")
        v["projectConfig"] = projectConfig
        serviceAccountPublicKeyFiles = self.serviceAccountPublicKeyFiles()
        check_type(
            "serviceAccountPublicKeyFiles", serviceAccountPublicKeyFiles, List[str]
        )
        v["serviceAccountPublicKeyFiles"] = serviceAccountPublicKeyFiles
        oauthConfig = self.oauthConfig()
        check_type("oauthConfig", oauthConfig, Optional["osinv1.OAuthConfig"])
        v["oauthConfig"] = oauthConfig
        apiServerArguments = self.apiServerArguments()
        check_type("apiServerArguments", apiServerArguments, Dict[str, List[str]])
        v["apiServerArguments"] = apiServerArguments
        return v

    def genericAPIServerConfig(self) -> "configv1.GenericAPIServerConfig":
        """
        provides the standard apiserver configuration
        """
        return self.__genericAPIServerConfig

    def authConfig(self) -> "MasterAuthConfig":
        """
        authConfig configures authentication options in addition to the standard
        oauth token and client certificate authenticators
        """
        return self.__authConfig

    def aggregatorConfig(self) -> "AggregatorConfig":
        """
        aggregatorConfig has options for configuring the aggregator component of the API server.
        """
        return self.__aggregatorConfig

    def kubeletClientInfo(self) -> "KubeletConnectionInfo":
        """
        kubeletClientInfo contains information about how to connect to kubelets
        """
        return self.__kubeletClientInfo

    def servicesSubnet(self) -> str:
        """
        servicesSubnet is the subnet to use for assigning service IPs
        """
        return self.__servicesSubnet

    def servicesNodePortRange(self) -> str:
        """
        servicesNodePortRange is the range to use for assigning service public ports on a host.
        """
        return self.__servicesNodePortRange

    def consolePublicURL(self) -> str:
        """
        consolePublicURL is an optional URL to provide a redirect from the kube-apiserver to the webconsole
        """
        return self.__consolePublicURL

    def userAgentMatchingConfig(self) -> "UserAgentMatchingConfig":
        """
        UserAgentMatchingConfig controls how API calls from *voluntarily* identifying clients will be handled.  THIS DOES NOT DEFEND AGAINST MALICIOUS CLIENTS!
        TODO I think we should just drop this feature.
        """
        return self.__userAgentMatchingConfig

    def imagePolicyConfig(self) -> "KubeAPIServerImagePolicyConfig":
        """
        imagePolicyConfig feeds the image policy admission plugin
        TODO make it an admission plugin config
        """
        return self.__imagePolicyConfig

    def projectConfig(self) -> "KubeAPIServerProjectConfig":
        """
        projectConfig feeds an admission plugin
        TODO make it an admission plugin config
        """
        return self.__projectConfig

    def serviceAccountPublicKeyFiles(self) -> List[str]:
        """
        serviceAccountPublicKeyFiles is a list of files, each containing a PEM-encoded public RSA key.
        (If any file contains a private key, the public portion of the key is used)
        The list of public keys is used to verify presented service account tokens.
        Each key is tried in order until the list is exhausted or verification succeeds.
        If no keys are specified, no service account authentication will be available.
        """
        return self.__serviceAccountPublicKeyFiles

    def oauthConfig(self) -> Optional["osinv1.OAuthConfig"]:
        """
        oauthConfig, if present start the /oauth endpoint in this process
        """
        return self.__oauthConfig

    def apiServerArguments(self) -> Dict[str, List[str]]:
        """
        TODO this needs to be removed.
        """
        return self.__apiServerArguments


class KubeControllerManagerProjectConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, defaultNodeSelector: str = ""):
        super().__init__()
        self.__defaultNodeSelector = defaultNodeSelector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        defaultNodeSelector = self.defaultNodeSelector()
        check_type("defaultNodeSelector", defaultNodeSelector, str)
        v["defaultNodeSelector"] = defaultNodeSelector
        return v

    def defaultNodeSelector(self) -> str:
        """
        defaultNodeSelector holds default project node label selector
        """
        return self.__defaultNodeSelector


class ServiceServingCert(types.Object):
    """
    ServiceServingCert holds configuration for service serving cert signer which creates cert/key pairs for
    pods fulfilling a service to serve with.
    """

    @context.scoped
    @typechecked
    def __init__(self, certFile: str = ""):
        super().__init__()
        self.__certFile = certFile

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        certFile = self.certFile()
        check_type("certFile", certFile, str)
        v["certFile"] = certFile
        return v

    def certFile(self) -> str:
        """
        CertFile is a file containing a PEM-encoded certificate
        """
        return self.__certFile


class KubeControllerManagerConfig(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        serviceServingCert: "ServiceServingCert" = None,
        projectConfig: "KubeControllerManagerProjectConfig" = None,
        extendedArguments: Dict[str, List[str]] = None,
    ):
        super().__init__(
            apiVersion="kubecontrolplane.config.openshift.io/v1",
            kind="KubeControllerManagerConfig",
        )
        self.__serviceServingCert = (
            serviceServingCert
            if serviceServingCert is not None
            else ServiceServingCert()
        )
        self.__projectConfig = (
            projectConfig
            if projectConfig is not None
            else KubeControllerManagerProjectConfig()
        )
        self.__extendedArguments = (
            extendedArguments if extendedArguments is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        serviceServingCert = self.serviceServingCert()
        check_type("serviceServingCert", serviceServingCert, "ServiceServingCert")
        v["serviceServingCert"] = serviceServingCert
        projectConfig = self.projectConfig()
        check_type("projectConfig", projectConfig, "KubeControllerManagerProjectConfig")
        v["projectConfig"] = projectConfig
        extendedArguments = self.extendedArguments()
        check_type("extendedArguments", extendedArguments, Dict[str, List[str]])
        v["extendedArguments"] = extendedArguments
        return v

    def serviceServingCert(self) -> "ServiceServingCert":
        """
        serviceServingCert provides support for the old alpha service serving cert signer CA bundle
        """
        return self.__serviceServingCert

    def projectConfig(self) -> "KubeControllerManagerProjectConfig":
        """
        projectConfig is an optimization for the daemonset controller
        """
        return self.__projectConfig

    def extendedArguments(self) -> Dict[str, List[str]]:
        """
        extendedArguments is used to configure the kube-controller-manager
        """
        return self.__extendedArguments
