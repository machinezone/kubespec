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
    def __init__(self, proxy_client_info: "configv1.CertInfo" = None):
        super().__init__()
        self.__proxy_client_info = (
            proxy_client_info if proxy_client_info is not None else configv1.CertInfo()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        proxy_client_info = self.proxy_client_info()
        check_type("proxy_client_info", proxy_client_info, "configv1.CertInfo")
        v["proxyClientInfo"] = proxy_client_info
        return v

    def proxy_client_info(self) -> "configv1.CertInfo":
        """
        proxyClientInfo specifies the client cert/key to use when proxying to aggregated API servers
        """
        return self.__proxy_client_info


class KubeAPIServerImagePolicyConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        internal_registry_hostname: str = "",
        external_registry_hostnames: List[str] = None,
    ):
        super().__init__()
        self.__internal_registry_hostname = internal_registry_hostname
        self.__external_registry_hostnames = (
            external_registry_hostnames
            if external_registry_hostnames is not None
            else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        internal_registry_hostname = self.internal_registry_hostname()
        check_type("internal_registry_hostname", internal_registry_hostname, str)
        v["internalRegistryHostname"] = internal_registry_hostname
        external_registry_hostnames = self.external_registry_hostnames()
        check_type(
            "external_registry_hostnames", external_registry_hostnames, List[str]
        )
        v["externalRegistryHostnames"] = external_registry_hostnames
        return v

    def internal_registry_hostname(self) -> str:
        """
        internalRegistryHostname sets the hostname for the default internal image
        registry. The value must be in "hostname[:port]" format.
        For backward compatibility, users can still use OPENSHIFT_DEFAULT_REGISTRY
        environment variable but this setting overrides the environment variable.
        """
        return self.__internal_registry_hostname

    def external_registry_hostnames(self) -> List[str]:
        """
        externalRegistryHostnames provides the hostnames for the default external image
        registry. The external hostname should be set only when the image registry
        is exposed externally. The first value is used in 'publicDockerImageRepository'
        field in ImageStreams. The value must be in "hostname[:port]" format.
        """
        return self.__external_registry_hostnames


class KubeAPIServerProjectConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, default_node_selector: str = ""):
        super().__init__()
        self.__default_node_selector = default_node_selector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        default_node_selector = self.default_node_selector()
        check_type("default_node_selector", default_node_selector, str)
        v["defaultNodeSelector"] = default_node_selector
        return v

    def default_node_selector(self) -> str:
        """
        defaultNodeSelector holds default project node label selector
        """
        return self.__default_node_selector


class KubeletConnectionInfo(types.Object):
    """
    KubeletConnectionInfo holds information necessary for connecting to a kubelet
    """

    @context.scoped
    @typechecked
    def __init__(
        self, port: int = 0, ca: str = "", cert_info: "configv1.CertInfo" = None
    ):
        super().__init__()
        self.__port = port
        self.__ca = ca
        self.__cert_info = cert_info if cert_info is not None else configv1.CertInfo()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        port = self.port()
        check_type("port", port, int)
        v["port"] = port
        ca = self.ca()
        check_type("ca", ca, str)
        v["ca"] = ca
        cert_info = self.cert_info()
        check_type("cert_info", cert_info, "configv1.CertInfo")
        v.update(cert_info._root())  # inline
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

    def cert_info(self) -> "configv1.CertInfo":
        """
        CertInfo is the TLS client cert information for securing communication to kubelets
        this is anonymous so that we can inline it for serialization
        """
        return self.__cert_info


class RequestHeaderAuthenticationOptions(types.Object):
    """
    RequestHeaderAuthenticationOptions provides options for setting up a front proxy against the entire
    API instead of against the /oauth endpoint.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        client_ca: str = "",
        client_common_names: List[str] = None,
        username_headers: List[str] = None,
        group_headers: List[str] = None,
        extra_header_prefixes: List[str] = None,
    ):
        super().__init__()
        self.__client_ca = client_ca
        self.__client_common_names = (
            client_common_names if client_common_names is not None else []
        )
        self.__username_headers = (
            username_headers if username_headers is not None else []
        )
        self.__group_headers = group_headers if group_headers is not None else []
        self.__extra_header_prefixes = (
            extra_header_prefixes if extra_header_prefixes is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_ca = self.client_ca()
        check_type("client_ca", client_ca, str)
        v["clientCA"] = client_ca
        client_common_names = self.client_common_names()
        check_type("client_common_names", client_common_names, List[str])
        v["clientCommonNames"] = client_common_names
        username_headers = self.username_headers()
        check_type("username_headers", username_headers, List[str])
        v["usernameHeaders"] = username_headers
        group_headers = self.group_headers()
        check_type("group_headers", group_headers, List[str])
        v["groupHeaders"] = group_headers
        extra_header_prefixes = self.extra_header_prefixes()
        check_type("extra_header_prefixes", extra_header_prefixes, List[str])
        v["extraHeaderPrefixes"] = extra_header_prefixes
        return v

    def client_ca(self) -> str:
        """
        clientCA is a file with the trusted signer certs.  It is required.
        """
        return self.__client_ca

    def client_common_names(self) -> List[str]:
        """
        clientCommonNames is a required list of common names to require a match from.
        """
        return self.__client_common_names

    def username_headers(self) -> List[str]:
        """
        usernameHeaders is the list of headers to check for user information.  First hit wins.
        """
        return self.__username_headers

    def group_headers(self) -> List[str]:
        """
        groupHeaders is the set of headers to check for group information.  All are unioned.
        """
        return self.__group_headers

    def extra_header_prefixes(self) -> List[str]:
        """
        extraHeaderPrefixes is the set of request header prefixes to inspect for user extra. X-Remote-Extra- is suggested.
        """
        return self.__extra_header_prefixes


class WebhookTokenAuthenticator(types.Object):
    """
    WebhookTokenAuthenticators holds the necessary configuation options for
    external token authenticators
    """

    @context.scoped
    @typechecked
    def __init__(self, config_file: str = "", cache_ttl: str = ""):
        super().__init__()
        self.__config_file = config_file
        self.__cache_ttl = cache_ttl

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        config_file = self.config_file()
        check_type("config_file", config_file, str)
        v["configFile"] = config_file
        cache_ttl = self.cache_ttl()
        check_type("cache_ttl", cache_ttl, str)
        v["cacheTTL"] = cache_ttl
        return v

    def config_file(self) -> str:
        """
        configFile is a path to a Kubeconfig file with the webhook configuration
        """
        return self.__config_file

    def cache_ttl(self) -> str:
        """
        cacheTTL indicates how long an authentication result should be cached.
        It takes a valid time duration string (e.g. "5m").
        If empty, you get a default timeout of 2 minutes.
        If zero (e.g. "0m"), caching is disabled
        """
        return self.__cache_ttl


class MasterAuthConfig(types.Object):
    """
    MasterAuthConfig configures authentication options in addition to the standard
    oauth token and client certificate authenticators
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        request_header: "RequestHeaderAuthenticationOptions" = None,
        webhook_token_authenticators: List["WebhookTokenAuthenticator"] = None,
        oauth_metadata_file: str = "",
    ):
        super().__init__()
        self.__request_header = request_header
        self.__webhook_token_authenticators = (
            webhook_token_authenticators
            if webhook_token_authenticators is not None
            else []
        )
        self.__oauth_metadata_file = oauth_metadata_file

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        request_header = self.request_header()
        check_type(
            "request_header",
            request_header,
            Optional["RequestHeaderAuthenticationOptions"],
        )
        v["requestHeader"] = request_header
        webhook_token_authenticators = self.webhook_token_authenticators()
        check_type(
            "webhook_token_authenticators",
            webhook_token_authenticators,
            List["WebhookTokenAuthenticator"],
        )
        v["webhookTokenAuthenticators"] = webhook_token_authenticators
        oauth_metadata_file = self.oauth_metadata_file()
        check_type("oauth_metadata_file", oauth_metadata_file, str)
        v["oauthMetadataFile"] = oauth_metadata_file
        return v

    def request_header(self) -> Optional["RequestHeaderAuthenticationOptions"]:
        """
        requestHeader holds options for setting up a front proxy against the the API.  It is optional.
        """
        return self.__request_header

    def webhook_token_authenticators(self) -> List["WebhookTokenAuthenticator"]:
        """
        webhookTokenAuthenticators, if present configures remote token reviewers
        """
        return self.__webhook_token_authenticators

    def oauth_metadata_file(self) -> str:
        """
        oauthMetadataFile is a path to a file containing the discovery endpoint for OAuth 2.0 Authorization
        Server Metadata for an external OAuth server.
        See IETF Draft: // https://tools.ietf.org/html/draft-ietf-oauth-discovery-04#section-2
        This option is mutually exclusive with OAuthConfig
        """
        return self.__oauth_metadata_file


class UserAgentMatchRule(types.Object):
    """
    UserAgentMatchRule describes how to match a given request based on User-Agent and HTTPVerb
    """

    @context.scoped
    @typechecked
    def __init__(self, regex: str = "", http_verbs: List[str] = None):
        super().__init__()
        self.__regex = regex
        self.__http_verbs = http_verbs if http_verbs is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        regex = self.regex()
        check_type("regex", regex, str)
        v["regex"] = regex
        http_verbs = self.http_verbs()
        check_type("http_verbs", http_verbs, List[str])
        v["httpVerbs"] = http_verbs
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

    def http_verbs(self) -> List[str]:
        """
        httpVerbs specifies which HTTP verbs should be matched.  An empty list means "match all verbs".
        """
        return self.__http_verbs


class UserAgentDenyRule(types.Object):
    """
    UserAgentDenyRule adds a rejection message that can be used to help a user figure out how to get an approved client
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        user_agent_match_rule: "UserAgentMatchRule" = None,
        rejection_message: str = "",
    ):
        super().__init__()
        self.__user_agent_match_rule = (
            user_agent_match_rule
            if user_agent_match_rule is not None
            else UserAgentMatchRule()
        )
        self.__rejection_message = rejection_message

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        user_agent_match_rule = self.user_agent_match_rule()
        check_type("user_agent_match_rule", user_agent_match_rule, "UserAgentMatchRule")
        v.update(user_agent_match_rule._root())  # inline
        rejection_message = self.rejection_message()
        check_type("rejection_message", rejection_message, str)
        v["rejectionMessage"] = rejection_message
        return v

    def user_agent_match_rule(self) -> "UserAgentMatchRule":
        return self.__user_agent_match_rule

    def rejection_message(self) -> str:
        """
        RejectionMessage is the message shown when rejecting a client.  If it is not a set, the default message is used.
        """
        return self.__rejection_message


class UserAgentMatchingConfig(types.Object):
    """
    UserAgentMatchingConfig controls how API calls from *voluntarily* identifying clients will be handled.  THIS DOES NOT DEFEND AGAINST MALICIOUS CLIENTS!
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        required_clients: List["UserAgentMatchRule"] = None,
        denied_clients: List["UserAgentDenyRule"] = None,
        default_rejection_message: str = "",
    ):
        super().__init__()
        self.__required_clients = (
            required_clients if required_clients is not None else []
        )
        self.__denied_clients = denied_clients if denied_clients is not None else []
        self.__default_rejection_message = default_rejection_message

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        required_clients = self.required_clients()
        check_type("required_clients", required_clients, List["UserAgentMatchRule"])
        v["requiredClients"] = required_clients
        denied_clients = self.denied_clients()
        check_type("denied_clients", denied_clients, List["UserAgentDenyRule"])
        v["deniedClients"] = denied_clients
        default_rejection_message = self.default_rejection_message()
        check_type("default_rejection_message", default_rejection_message, str)
        v["defaultRejectionMessage"] = default_rejection_message
        return v

    def required_clients(self) -> List["UserAgentMatchRule"]:
        """
        requiredClients if this list is non-empty, then a User-Agent must match one of the UserAgentRegexes to be allowed
        """
        return self.__required_clients

    def denied_clients(self) -> List["UserAgentDenyRule"]:
        """
        deniedClients if this list is non-empty, then a User-Agent must not match any of the UserAgentRegexes
        """
        return self.__denied_clients

    def default_rejection_message(self) -> str:
        """
        defaultRejectionMessage is the message shown when rejecting a client.  If it is not a set, a generic message is given.
        """
        return self.__default_rejection_message


class KubeAPIServerConfig(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        generic_api_server_config: "configv1.GenericAPIServerConfig" = None,
        auth_config: "MasterAuthConfig" = None,
        aggregator_config: "AggregatorConfig" = None,
        kubelet_client_info: "KubeletConnectionInfo" = None,
        services_subnet: str = "",
        services_node_port_range: str = "",
        console_public_url: str = "",
        user_agent_matching_config: "UserAgentMatchingConfig" = None,
        image_policy_config: "KubeAPIServerImagePolicyConfig" = None,
        project_config: "KubeAPIServerProjectConfig" = None,
        service_account_public_key_files: List[str] = None,
        oauth_config: "osinv1.OAuthConfig" = None,
        api_server_arguments: Dict[str, List[str]] = None,
    ):
        super().__init__(
            api_version="kubecontrolplane.config.openshift.io/v1",
            kind="KubeAPIServerConfig",
        )
        self.__generic_api_server_config = (
            generic_api_server_config
            if generic_api_server_config is not None
            else configv1.GenericAPIServerConfig()
        )
        self.__auth_config = (
            auth_config if auth_config is not None else MasterAuthConfig()
        )
        self.__aggregator_config = (
            aggregator_config if aggregator_config is not None else AggregatorConfig()
        )
        self.__kubelet_client_info = (
            kubelet_client_info
            if kubelet_client_info is not None
            else KubeletConnectionInfo()
        )
        self.__services_subnet = services_subnet
        self.__services_node_port_range = services_node_port_range
        self.__console_public_url = console_public_url
        self.__user_agent_matching_config = (
            user_agent_matching_config
            if user_agent_matching_config is not None
            else UserAgentMatchingConfig()
        )
        self.__image_policy_config = (
            image_policy_config
            if image_policy_config is not None
            else KubeAPIServerImagePolicyConfig()
        )
        self.__project_config = (
            project_config
            if project_config is not None
            else KubeAPIServerProjectConfig()
        )
        self.__service_account_public_key_files = (
            service_account_public_key_files
            if service_account_public_key_files is not None
            else []
        )
        self.__oauth_config = oauth_config
        self.__api_server_arguments = (
            api_server_arguments if api_server_arguments is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        generic_api_server_config = self.generic_api_server_config()
        check_type(
            "generic_api_server_config",
            generic_api_server_config,
            "configv1.GenericAPIServerConfig",
        )
        v.update(generic_api_server_config._root())  # inline
        auth_config = self.auth_config()
        check_type("auth_config", auth_config, "MasterAuthConfig")
        v["authConfig"] = auth_config
        aggregator_config = self.aggregator_config()
        check_type("aggregator_config", aggregator_config, "AggregatorConfig")
        v["aggregatorConfig"] = aggregator_config
        kubelet_client_info = self.kubelet_client_info()
        check_type("kubelet_client_info", kubelet_client_info, "KubeletConnectionInfo")
        v["kubeletClientInfo"] = kubelet_client_info
        services_subnet = self.services_subnet()
        check_type("services_subnet", services_subnet, str)
        v["servicesSubnet"] = services_subnet
        services_node_port_range = self.services_node_port_range()
        check_type("services_node_port_range", services_node_port_range, str)
        v["servicesNodePortRange"] = services_node_port_range
        console_public_url = self.console_public_url()
        check_type("console_public_url", console_public_url, str)
        v["consolePublicURL"] = console_public_url
        user_agent_matching_config = self.user_agent_matching_config()
        check_type(
            "user_agent_matching_config",
            user_agent_matching_config,
            "UserAgentMatchingConfig",
        )
        v["userAgentMatchingConfig"] = user_agent_matching_config
        image_policy_config = self.image_policy_config()
        check_type(
            "image_policy_config", image_policy_config, "KubeAPIServerImagePolicyConfig"
        )
        v["imagePolicyConfig"] = image_policy_config
        project_config = self.project_config()
        check_type("project_config", project_config, "KubeAPIServerProjectConfig")
        v["projectConfig"] = project_config
        service_account_public_key_files = self.service_account_public_key_files()
        check_type(
            "service_account_public_key_files",
            service_account_public_key_files,
            List[str],
        )
        v["serviceAccountPublicKeyFiles"] = service_account_public_key_files
        oauth_config = self.oauth_config()
        check_type("oauth_config", oauth_config, Optional["osinv1.OAuthConfig"])
        v["oauthConfig"] = oauth_config
        api_server_arguments = self.api_server_arguments()
        check_type("api_server_arguments", api_server_arguments, Dict[str, List[str]])
        v["apiServerArguments"] = api_server_arguments
        return v

    def generic_api_server_config(self) -> "configv1.GenericAPIServerConfig":
        """
        provides the standard apiserver configuration
        """
        return self.__generic_api_server_config

    def auth_config(self) -> "MasterAuthConfig":
        """
        authConfig configures authentication options in addition to the standard
        oauth token and client certificate authenticators
        """
        return self.__auth_config

    def aggregator_config(self) -> "AggregatorConfig":
        """
        aggregatorConfig has options for configuring the aggregator component of the API server.
        """
        return self.__aggregator_config

    def kubelet_client_info(self) -> "KubeletConnectionInfo":
        """
        kubeletClientInfo contains information about how to connect to kubelets
        """
        return self.__kubelet_client_info

    def services_subnet(self) -> str:
        """
        servicesSubnet is the subnet to use for assigning service IPs
        """
        return self.__services_subnet

    def services_node_port_range(self) -> str:
        """
        servicesNodePortRange is the range to use for assigning service public ports on a host.
        """
        return self.__services_node_port_range

    def console_public_url(self) -> str:
        """
        consolePublicURL is an optional URL to provide a redirect from the kube-apiserver to the webconsole
        """
        return self.__console_public_url

    def user_agent_matching_config(self) -> "UserAgentMatchingConfig":
        """
        UserAgentMatchingConfig controls how API calls from *voluntarily* identifying clients will be handled.  THIS DOES NOT DEFEND AGAINST MALICIOUS CLIENTS!
        TODO I think we should just drop this feature.
        """
        return self.__user_agent_matching_config

    def image_policy_config(self) -> "KubeAPIServerImagePolicyConfig":
        """
        imagePolicyConfig feeds the image policy admission plugin
        TODO make it an admission plugin config
        """
        return self.__image_policy_config

    def project_config(self) -> "KubeAPIServerProjectConfig":
        """
        projectConfig feeds an admission plugin
        TODO make it an admission plugin config
        """
        return self.__project_config

    def service_account_public_key_files(self) -> List[str]:
        """
        serviceAccountPublicKeyFiles is a list of files, each containing a PEM-encoded public RSA key.
        (If any file contains a private key, the public portion of the key is used)
        The list of public keys is used to verify presented service account tokens.
        Each key is tried in order until the list is exhausted or verification succeeds.
        If no keys are specified, no service account authentication will be available.
        """
        return self.__service_account_public_key_files

    def oauth_config(self) -> Optional["osinv1.OAuthConfig"]:
        """
        oauthConfig, if present start the /oauth endpoint in this process
        """
        return self.__oauth_config

    def api_server_arguments(self) -> Dict[str, List[str]]:
        """
        TODO this needs to be removed.
        """
        return self.__api_server_arguments


class KubeControllerManagerProjectConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, default_node_selector: str = ""):
        super().__init__()
        self.__default_node_selector = default_node_selector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        default_node_selector = self.default_node_selector()
        check_type("default_node_selector", default_node_selector, str)
        v["defaultNodeSelector"] = default_node_selector
        return v

    def default_node_selector(self) -> str:
        """
        defaultNodeSelector holds default project node label selector
        """
        return self.__default_node_selector


class ServiceServingCert(types.Object):
    """
    ServiceServingCert holds configuration for service serving cert signer which creates cert/key pairs for
    pods fulfilling a service to serve with.
    """

    @context.scoped
    @typechecked
    def __init__(self, cert_file: str = ""):
        super().__init__()
        self.__cert_file = cert_file

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cert_file = self.cert_file()
        check_type("cert_file", cert_file, str)
        v["certFile"] = cert_file
        return v

    def cert_file(self) -> str:
        """
        CertFile is a file containing a PEM-encoded certificate
        """
        return self.__cert_file


class KubeControllerManagerConfig(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        service_serving_cert: "ServiceServingCert" = None,
        project_config: "KubeControllerManagerProjectConfig" = None,
        extended_arguments: Dict[str, List[str]] = None,
    ):
        super().__init__(
            api_version="kubecontrolplane.config.openshift.io/v1",
            kind="KubeControllerManagerConfig",
        )
        self.__service_serving_cert = (
            service_serving_cert
            if service_serving_cert is not None
            else ServiceServingCert()
        )
        self.__project_config = (
            project_config
            if project_config is not None
            else KubeControllerManagerProjectConfig()
        )
        self.__extended_arguments = (
            extended_arguments if extended_arguments is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        service_serving_cert = self.service_serving_cert()
        check_type("service_serving_cert", service_serving_cert, "ServiceServingCert")
        v["serviceServingCert"] = service_serving_cert
        project_config = self.project_config()
        check_type(
            "project_config", project_config, "KubeControllerManagerProjectConfig"
        )
        v["projectConfig"] = project_config
        extended_arguments = self.extended_arguments()
        check_type("extended_arguments", extended_arguments, Dict[str, List[str]])
        v["extendedArguments"] = extended_arguments
        return v

    def service_serving_cert(self) -> "ServiceServingCert":
        """
        serviceServingCert provides support for the old alpha service serving cert signer CA bundle
        """
        return self.__service_serving_cert

    def project_config(self) -> "KubeControllerManagerProjectConfig":
        """
        projectConfig is an optimization for the daemonset controller
        """
        return self.__project_config

    def extended_arguments(self) -> Dict[str, List[str]]:
        """
        extendedArguments is used to configure the kube-controller-manager
        """
        return self.__extended_arguments
