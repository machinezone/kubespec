# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from kubespec.openshift.config import v1 as configv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


GrantHandlerType = base.Enum(
    "GrantHandlerType",
    {
        # auto auto-approves client authorization grant requests
        "Auto": "auto",
        # deny auto-denies client authorization grant requests
        "Deny": "deny",
        # prompt prompts the user to approve new client authorization grant requests
        "Prompt": "prompt",
    },
)


class AllowAllPasswordIdentityProvider(base.TypedObject):
    """
    AllowAllPasswordIdentityProvider provides identities for users authenticating using non-empty passwords
    """

    @context.scoped
    @typechecked
    def __init__(self):
        super().__init__(
            api_version="osin.config.openshift.io/v1",
            kind="AllowAllPasswordIdentityProvider",
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        return v


class BasicAuthPasswordIdentityProvider(base.TypedObject):
    """
    BasicAuthPasswordIdentityProvider provides identities for users authenticating using HTTP basic auth credentials
    """

    @context.scoped
    @typechecked
    def __init__(self, remote_connection_info: "configv1.RemoteConnectionInfo" = None):
        super().__init__(
            api_version="osin.config.openshift.io/v1",
            kind="BasicAuthPasswordIdentityProvider",
        )
        self.__remote_connection_info = (
            remote_connection_info
            if remote_connection_info is not None
            else configv1.RemoteConnectionInfo()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        remote_connection_info = self.remote_connection_info()
        check_type(
            "remote_connection_info",
            remote_connection_info,
            "configv1.RemoteConnectionInfo",
        )
        v.update(remote_connection_info._root())  # inline
        return v

    def remote_connection_info(self) -> "configv1.RemoteConnectionInfo":
        """
        RemoteConnectionInfo contains information about how to connect to the external basic auth server
        """
        return self.__remote_connection_info


class DenyAllPasswordIdentityProvider(base.TypedObject):
    """
    DenyAllPasswordIdentityProvider provides no identities for users
    """

    @context.scoped
    @typechecked
    def __init__(self):
        super().__init__(
            api_version="osin.config.openshift.io/v1",
            kind="DenyAllPasswordIdentityProvider",
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        return v


class GitHubIdentityProvider(base.TypedObject):
    """
    GitHubIdentityProvider provides identities for users authenticating using GitHub credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        client_id: str = "",
        client_secret: "configv1.StringSource" = None,
        organizations: List[str] = None,
        teams: List[str] = None,
        hostname: str = "",
        ca: str = "",
    ):
        super().__init__(
            api_version="osin.config.openshift.io/v1", kind="GitHubIdentityProvider"
        )
        self.__client_id = client_id
        self.__client_secret = (
            client_secret if client_secret is not None else configv1.StringSource()
        )
        self.__organizations = organizations if organizations is not None else []
        self.__teams = teams if teams is not None else []
        self.__hostname = hostname
        self.__ca = ca

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_id = self.client_id()
        check_type("client_id", client_id, str)
        v["clientID"] = client_id
        client_secret = self.client_secret()
        check_type("client_secret", client_secret, "configv1.StringSource")
        v["clientSecret"] = client_secret
        organizations = self.organizations()
        check_type("organizations", organizations, List[str])
        v["organizations"] = organizations
        teams = self.teams()
        check_type("teams", teams, List[str])
        v["teams"] = teams
        hostname = self.hostname()
        check_type("hostname", hostname, str)
        v["hostname"] = hostname
        ca = self.ca()
        check_type("ca", ca, str)
        v["ca"] = ca
        return v

    def client_id(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__client_id

    def client_secret(self) -> "configv1.StringSource":
        """
        clientSecret is the oauth client secret
        """
        return self.__client_secret

    def organizations(self) -> List[str]:
        """
        organizations optionally restricts which organizations are allowed to log in
        """
        return self.__organizations

    def teams(self) -> List[str]:
        """
        teams optionally restricts which teams are allowed to log in. Format is <org>/<team>.
        """
        return self.__teams

    def hostname(self) -> str:
        """
        hostname is the optional domain (e.g. "mycompany.com") for use with a hosted instance of GitHub Enterprise.
        It must match the GitHub Enterprise settings value that is configured at /setup/settings#hostname.
        """
        return self.__hostname

    def ca(self) -> str:
        """
        ca is the optional trusted certificate authority bundle to use when making requests to the server.
        If empty, the default system roots are used.  This can only be configured when hostname is set to a non-empty value.
        """
        return self.__ca


class GitLabIdentityProvider(base.TypedObject):
    """
    GitLabIdentityProvider provides identities for users authenticating using GitLab credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ca: str = "",
        url: str = "",
        client_id: str = "",
        client_secret: "configv1.StringSource" = None,
        legacy: bool = None,
    ):
        super().__init__(
            api_version="osin.config.openshift.io/v1", kind="GitLabIdentityProvider"
        )
        self.__ca = ca
        self.__url = url
        self.__client_id = client_id
        self.__client_secret = (
            client_secret if client_secret is not None else configv1.StringSource()
        )
        self.__legacy = legacy

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ca = self.ca()
        check_type("ca", ca, str)
        v["ca"] = ca
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        client_id = self.client_id()
        check_type("client_id", client_id, str)
        v["clientID"] = client_id
        client_secret = self.client_secret()
        check_type("client_secret", client_secret, "configv1.StringSource")
        v["clientSecret"] = client_secret
        legacy = self.legacy()
        check_type("legacy", legacy, Optional[bool])
        if legacy is not None:  # omit empty
            v["legacy"] = legacy
        return v

    def ca(self) -> str:
        """
        ca is the optional trusted certificate authority bundle to use when making requests to the server
        If empty, the default system roots are used
        """
        return self.__ca

    def url(self) -> str:
        """
        url is the oauth server base URL
        """
        return self.__url

    def client_id(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__client_id

    def client_secret(self) -> "configv1.StringSource":
        """
        clientSecret is the oauth client secret
        """
        return self.__client_secret

    def legacy(self) -> Optional[bool]:
        """
        legacy determines if OAuth2 or OIDC should be used
        If true, OAuth2 is used
        If false, OIDC is used
        If nil and the URL's host is gitlab.com, OIDC is used
        Otherwise, OAuth2 is used
        In a future release, nil will default to using OIDC
        Eventually this flag will be removed and only OIDC will be used
        """
        return self.__legacy


class GoogleIdentityProvider(base.TypedObject):
    """
    GoogleIdentityProvider provides identities for users authenticating using Google credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        client_id: str = "",
        client_secret: "configv1.StringSource" = None,
        hosted_domain: str = "",
    ):
        super().__init__(
            api_version="osin.config.openshift.io/v1", kind="GoogleIdentityProvider"
        )
        self.__client_id = client_id
        self.__client_secret = (
            client_secret if client_secret is not None else configv1.StringSource()
        )
        self.__hosted_domain = hosted_domain

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_id = self.client_id()
        check_type("client_id", client_id, str)
        v["clientID"] = client_id
        client_secret = self.client_secret()
        check_type("client_secret", client_secret, "configv1.StringSource")
        v["clientSecret"] = client_secret
        hosted_domain = self.hosted_domain()
        check_type("hosted_domain", hosted_domain, str)
        v["hostedDomain"] = hosted_domain
        return v

    def client_id(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__client_id

    def client_secret(self) -> "configv1.StringSource":
        """
        clientSecret is the oauth client secret
        """
        return self.__client_secret

    def hosted_domain(self) -> str:
        """
        hostedDomain is the optional Google App domain (e.g. "mycompany.com") to restrict logins to
        """
        return self.__hosted_domain


class GrantConfig(types.Object):
    """
    GrantConfig holds the necessary configuration options for grant handlers
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        method: GrantHandlerType = None,
        service_account_method: GrantHandlerType = None,
    ):
        super().__init__()
        self.__method = method
        self.__service_account_method = service_account_method

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        method = self.method()
        check_type("method", method, GrantHandlerType)
        v["method"] = method
        service_account_method = self.service_account_method()
        check_type("service_account_method", service_account_method, GrantHandlerType)
        v["serviceAccountMethod"] = service_account_method
        return v

    def method(self) -> GrantHandlerType:
        """
        method determines the default strategy to use when an OAuth client requests a grant.
        This method will be used only if the specific OAuth client doesn't provide a strategy
        of their own. Valid grant handling methods are:
         - auto:   always approves grant requests, useful for trusted clients
         - prompt: prompts the end user for approval of grant requests, useful for third-party clients
         - deny:   always denies grant requests, useful for black-listed clients
        """
        return self.__method

    def service_account_method(self) -> GrantHandlerType:
        """
        serviceAccountMethod is used for determining client authorization for service account oauth client.
        It must be either: deny, prompt
        """
        return self.__service_account_method


class HTPasswdPasswordIdentityProvider(base.TypedObject):
    """
    HTPasswdPasswordIdentityProvider provides identities for users authenticating using htpasswd credentials
    """

    @context.scoped
    @typechecked
    def __init__(self, file: str = ""):
        super().__init__(
            api_version="osin.config.openshift.io/v1",
            kind="HTPasswdPasswordIdentityProvider",
        )
        self.__file = file

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        file = self.file()
        check_type("file", file, str)
        v["file"] = file
        return v

    def file(self) -> str:
        """
        file is a reference to your htpasswd file
        """
        return self.__file


class IdentityProvider(types.Object):
    """
    IdentityProvider provides identities for users authenticating using credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        challenge: bool = False,
        login: bool = False,
        mapping_method: str = "",
        provider: "runtime.RawExtension" = None,
    ):
        super().__init__()
        self.__name = name
        self.__challenge = challenge
        self.__login = login
        self.__mapping_method = mapping_method
        self.__provider = provider

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        challenge = self.challenge()
        check_type("challenge", challenge, bool)
        v["challenge"] = challenge
        login = self.login()
        check_type("login", login, bool)
        v["login"] = login
        mapping_method = self.mapping_method()
        check_type("mapping_method", mapping_method, str)
        v["mappingMethod"] = mapping_method
        provider = self.provider()
        check_type("provider", provider, "runtime.RawExtension")
        v["provider"] = provider
        return v

    def name(self) -> str:
        """
        name is used to qualify the identities returned by this provider
        """
        return self.__name

    def challenge(self) -> bool:
        """
        challenge indicates whether to issue WWW-Authenticate challenges for this provider
        """
        return self.__challenge

    def login(self) -> bool:
        """
        login indicates whether to use this identity provider for unauthenticated browsers to login against
        """
        return self.__login

    def mapping_method(self) -> str:
        """
        mappingMethod determines how identities from this provider are mapped to users
        """
        return self.__mapping_method

    def provider(self) -> "runtime.RawExtension":
        """
        provider contains the information about how to set up a specific identity provider
        """
        return self.__provider


class KeystonePasswordIdentityProvider(base.TypedObject):
    """
    KeystonePasswordIdentityProvider provides identities for users authenticating using keystone password credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        remote_connection_info: "configv1.RemoteConnectionInfo" = None,
        domain_name: str = "",
        use_keystone_identity: bool = False,
    ):
        super().__init__(
            api_version="osin.config.openshift.io/v1",
            kind="KeystonePasswordIdentityProvider",
        )
        self.__remote_connection_info = (
            remote_connection_info
            if remote_connection_info is not None
            else configv1.RemoteConnectionInfo()
        )
        self.__domain_name = domain_name
        self.__use_keystone_identity = use_keystone_identity

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        remote_connection_info = self.remote_connection_info()
        check_type(
            "remote_connection_info",
            remote_connection_info,
            "configv1.RemoteConnectionInfo",
        )
        v.update(remote_connection_info._root())  # inline
        domain_name = self.domain_name()
        check_type("domain_name", domain_name, str)
        v["domainName"] = domain_name
        use_keystone_identity = self.use_keystone_identity()
        check_type("use_keystone_identity", use_keystone_identity, bool)
        v["useKeystoneIdentity"] = use_keystone_identity
        return v

    def remote_connection_info(self) -> "configv1.RemoteConnectionInfo":
        """
        RemoteConnectionInfo contains information about how to connect to the keystone server
        """
        return self.__remote_connection_info

    def domain_name(self) -> str:
        """
        domainName is required for keystone v3
        """
        return self.__domain_name

    def use_keystone_identity(self) -> bool:
        """
        useKeystoneIdentity flag indicates that user should be authenticated by keystone ID, not by username
        """
        return self.__use_keystone_identity


class LDAPAttributeMapping(types.Object):
    """
    LDAPAttributeMapping maps LDAP attributes to OpenShift identity fields
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        id: List[str] = None,
        preferred_username: List[str] = None,
        name: List[str] = None,
        email: List[str] = None,
    ):
        super().__init__()
        self.__id = id if id is not None else []
        self.__preferred_username = (
            preferred_username if preferred_username is not None else []
        )
        self.__name = name if name is not None else []
        self.__email = email if email is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        id = self.id()
        check_type("id", id, List[str])
        v["id"] = id
        preferred_username = self.preferred_username()
        check_type("preferred_username", preferred_username, List[str])
        v["preferredUsername"] = preferred_username
        name = self.name()
        check_type("name", name, List[str])
        v["name"] = name
        email = self.email()
        check_type("email", email, List[str])
        v["email"] = email
        return v

    def id(self) -> List[str]:
        """
        id is the list of attributes whose values should be used as the user ID. Required.
        LDAP standard identity attribute is "dn"
        """
        return self.__id

    def preferred_username(self) -> List[str]:
        """
        preferredUsername is the list of attributes whose values should be used as the preferred username.
        LDAP standard login attribute is "uid"
        """
        return self.__preferred_username

    def name(self) -> List[str]:
        """
        name is the list of attributes whose values should be used as the display name. Optional.
        If unspecified, no display name is set for the identity
        LDAP standard display name attribute is "cn"
        """
        return self.__name

    def email(self) -> List[str]:
        """
        email is the list of attributes whose values should be used as the email address. Optional.
        If unspecified, no email is set for the identity
        """
        return self.__email


class LDAPPasswordIdentityProvider(base.TypedObject):
    """
    LDAPPasswordIdentityProvider provides identities for users authenticating using LDAP credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = "",
        bind_dn: str = "",
        bind_password: "configv1.StringSource" = None,
        insecure: bool = False,
        ca: str = "",
        attributes: "LDAPAttributeMapping" = None,
    ):
        super().__init__(
            api_version="osin.config.openshift.io/v1",
            kind="LDAPPasswordIdentityProvider",
        )
        self.__url = url
        self.__bind_dn = bind_dn
        self.__bind_password = (
            bind_password if bind_password is not None else configv1.StringSource()
        )
        self.__insecure = insecure
        self.__ca = ca
        self.__attributes = (
            attributes if attributes is not None else LDAPAttributeMapping()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        bind_dn = self.bind_dn()
        check_type("bind_dn", bind_dn, str)
        v["bindDN"] = bind_dn
        bind_password = self.bind_password()
        check_type("bind_password", bind_password, "configv1.StringSource")
        v["bindPassword"] = bind_password
        insecure = self.insecure()
        check_type("insecure", insecure, bool)
        v["insecure"] = insecure
        ca = self.ca()
        check_type("ca", ca, str)
        v["ca"] = ca
        attributes = self.attributes()
        check_type("attributes", attributes, "LDAPAttributeMapping")
        v["attributes"] = attributes
        return v

    def url(self) -> str:
        """
        url is an RFC 2255 URL which specifies the LDAP search parameters to use. The syntax of the URL is
           ldap://host:port/basedn?attribute?scope?filter
        """
        return self.__url

    def bind_dn(self) -> str:
        """
        bindDN is an optional DN to bind with during the search phase.
        """
        return self.__bind_dn

    def bind_password(self) -> "configv1.StringSource":
        """
        bindPassword is an optional password to bind with during the search phase.
        """
        return self.__bind_password

    def insecure(self) -> bool:
        """
        insecure, if true, indicates the connection should not use TLS.
        Cannot be set to true with a URL scheme of "ldaps://"
        If false, "ldaps://" URLs connect using TLS, and "ldap://" URLs are upgraded to a TLS connection using StartTLS as specified in https://tools.ietf.org/html/rfc2830
        """
        return self.__insecure

    def ca(self) -> str:
        """
        ca is the optional trusted certificate authority bundle to use when making requests to the server
        If empty, the default system roots are used
        """
        return self.__ca

    def attributes(self) -> "LDAPAttributeMapping":
        """
        attributes maps LDAP attributes to identities
        """
        return self.__attributes


class OAuthTemplates(types.Object):
    """
    OAuthTemplates allow for customization of pages like the login page
    """

    @context.scoped
    @typechecked
    def __init__(self, login: str = "", provider_selection: str = "", error: str = ""):
        super().__init__()
        self.__login = login
        self.__provider_selection = provider_selection
        self.__error = error

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        login = self.login()
        check_type("login", login, str)
        v["login"] = login
        provider_selection = self.provider_selection()
        check_type("provider_selection", provider_selection, str)
        v["providerSelection"] = provider_selection
        error = self.error()
        check_type("error", error, str)
        v["error"] = error
        return v

    def login(self) -> str:
        """
        login is a path to a file containing a go template used to render the login page.
        If unspecified, the default login page is used.
        """
        return self.__login

    def provider_selection(self) -> str:
        """
        providerSelection is a path to a file containing a go template used to render the provider selection page.
        If unspecified, the default provider selection page is used.
        """
        return self.__provider_selection

    def error(self) -> str:
        """
        error is a path to a file containing a go template used to render error pages during the authentication or grant flow
        If unspecified, the default error page is used.
        """
        return self.__error


class SessionConfig(types.Object):
    """
    SessionConfig specifies options for cookie-based sessions. Used by AuthRequestHandlerSession
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        session_secrets_file: str = "",
        session_max_age_seconds: int = 0,
        session_name: str = "",
    ):
        super().__init__()
        self.__session_secrets_file = session_secrets_file
        self.__session_max_age_seconds = session_max_age_seconds
        self.__session_name = session_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        session_secrets_file = self.session_secrets_file()
        check_type("session_secrets_file", session_secrets_file, str)
        v["sessionSecretsFile"] = session_secrets_file
        session_max_age_seconds = self.session_max_age_seconds()
        check_type("session_max_age_seconds", session_max_age_seconds, int)
        v["sessionMaxAgeSeconds"] = session_max_age_seconds
        session_name = self.session_name()
        check_type("session_name", session_name, str)
        v["sessionName"] = session_name
        return v

    def session_secrets_file(self) -> str:
        """
        sessionSecretsFile is a reference to a file containing a serialized SessionSecrets object
        If no file is specified, a random signing and encryption key are generated at each server start
        """
        return self.__session_secrets_file

    def session_max_age_seconds(self) -> int:
        """
        sessionMaxAgeSeconds specifies how long created sessions last. Used by AuthRequestHandlerSession
        """
        return self.__session_max_age_seconds

    def session_name(self) -> str:
        """
        sessionName is the cookie name used to store the session
        """
        return self.__session_name


class TokenConfig(types.Object):
    """
    TokenConfig holds the necessary configuration options for authorization and access tokens
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        authorize_token_max_age_seconds: int = 0,
        access_token_max_age_seconds: int = 0,
        access_token_inactivity_timeout_seconds: int = None,
    ):
        super().__init__()
        self.__authorize_token_max_age_seconds = authorize_token_max_age_seconds
        self.__access_token_max_age_seconds = access_token_max_age_seconds
        self.__access_token_inactivity_timeout_seconds = (
            access_token_inactivity_timeout_seconds
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        authorize_token_max_age_seconds = self.authorize_token_max_age_seconds()
        check_type(
            "authorize_token_max_age_seconds", authorize_token_max_age_seconds, int
        )
        v["authorizeTokenMaxAgeSeconds"] = authorize_token_max_age_seconds
        access_token_max_age_seconds = self.access_token_max_age_seconds()
        check_type("access_token_max_age_seconds", access_token_max_age_seconds, int)
        v["accessTokenMaxAgeSeconds"] = access_token_max_age_seconds
        access_token_inactivity_timeout_seconds = (
            self.access_token_inactivity_timeout_seconds()
        )
        check_type(
            "access_token_inactivity_timeout_seconds",
            access_token_inactivity_timeout_seconds,
            Optional[int],
        )
        if access_token_inactivity_timeout_seconds is not None:  # omit empty
            v[
                "accessTokenInactivityTimeoutSeconds"
            ] = access_token_inactivity_timeout_seconds
        return v

    def authorize_token_max_age_seconds(self) -> int:
        """
        authorizeTokenMaxAgeSeconds defines the maximum age of authorize tokens
        """
        return self.__authorize_token_max_age_seconds

    def access_token_max_age_seconds(self) -> int:
        """
        accessTokenMaxAgeSeconds defines the maximum age of access tokens
        """
        return self.__access_token_max_age_seconds

    def access_token_inactivity_timeout_seconds(self) -> Optional[int]:
        """
        accessTokenInactivityTimeoutSeconds defined the default token
        inactivity timeout for tokens granted by any client.
        Setting it to nil means the feature is completely disabled (default)
        The default setting can be overriden on OAuthClient basis.
        The value represents the maximum amount of time that can occur between
        consecutive uses of the token. Tokens become invalid if they are not
        used within this temporal window. The user will need to acquire a new
        token to regain access once a token times out.
        Valid values are:
        - 0: Tokens never time out
        - X: Tokens time out if there is no activity for X seconds
        The current minimum allowed value for X is 300 (5 minutes)
        """
        return self.__access_token_inactivity_timeout_seconds


class OAuthConfig(types.Object):
    """
    OAuthConfig holds the necessary configuration options for OAuth authentication
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        login_url: str = "",
        asset_public_url: str = "",
        always_show_provider_selection: bool = False,
        identity_providers: List["IdentityProvider"] = None,
        grant_config: "GrantConfig" = None,
        session_config: "SessionConfig" = None,
        token_config: "TokenConfig" = None,
        templates: "OAuthTemplates" = None,
    ):
        super().__init__()
        self.__login_url = login_url
        self.__asset_public_url = asset_public_url
        self.__always_show_provider_selection = always_show_provider_selection
        self.__identity_providers = (
            identity_providers if identity_providers is not None else []
        )
        self.__grant_config = (
            grant_config if grant_config is not None else GrantConfig()
        )
        self.__session_config = session_config
        self.__token_config = (
            token_config if token_config is not None else TokenConfig()
        )
        self.__templates = templates

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        login_url = self.login_url()
        check_type("login_url", login_url, str)
        v["loginURL"] = login_url
        asset_public_url = self.asset_public_url()
        check_type("asset_public_url", asset_public_url, str)
        v["assetPublicURL"] = asset_public_url
        always_show_provider_selection = self.always_show_provider_selection()
        check_type(
            "always_show_provider_selection", always_show_provider_selection, bool
        )
        v["alwaysShowProviderSelection"] = always_show_provider_selection
        identity_providers = self.identity_providers()
        check_type("identity_providers", identity_providers, List["IdentityProvider"])
        v["identityProviders"] = identity_providers
        grant_config = self.grant_config()
        check_type("grant_config", grant_config, "GrantConfig")
        v["grantConfig"] = grant_config
        session_config = self.session_config()
        check_type("session_config", session_config, Optional["SessionConfig"])
        v["sessionConfig"] = session_config
        token_config = self.token_config()
        check_type("token_config", token_config, "TokenConfig")
        v["tokenConfig"] = token_config
        templates = self.templates()
        check_type("templates", templates, Optional["OAuthTemplates"])
        v["templates"] = templates
        return v

    def login_url(self) -> str:
        """
        loginURL, along with masterCA, masterURL and masterPublicURL have distinct
        meanings depending on how the OAuth server is run.  The two states are:
        1. embedded in the kube api server (all 3.x releases)
        2. as a standalone external process (all 4.x releases)
        in the embedded configuration, loginURL is equivalent to masterPublicURL
        and the other fields have functionality that matches their docs.
        in the standalone configuration, the fields are used as:
        loginURL is the URL required to login to the cluster:
        oc login --server=<loginURL>
        masterPublicURL is the issuer URL
        it is accessible from inside (service network) and outside (ingress) of the cluster
        masterURL is the loopback variation of the token_endpoint URL with no path component
        it is only accessible from inside (service network) of the cluster
        masterCA is used to perform TLS verification for connections made to masterURL
        For further details, see the IETF Draft:
        https://tools.ietf.org/html/draft-ietf-oauth-discovery-04#section-2
        """
        return self.__login_url

    def asset_public_url(self) -> str:
        """
        assetPublicURL is used for building valid client redirect URLs for external access
        """
        return self.__asset_public_url

    def always_show_provider_selection(self) -> bool:
        """
        alwaysShowProviderSelection will force the provider selection page to render even when there is only a single provider.
        """
        return self.__always_show_provider_selection

    def identity_providers(self) -> List["IdentityProvider"]:
        """
        identityProviders is an ordered list of ways for a user to identify themselves
        """
        return self.__identity_providers

    def grant_config(self) -> "GrantConfig":
        """
        grantConfig describes how to handle grants
        """
        return self.__grant_config

    def session_config(self) -> Optional["SessionConfig"]:
        """
        sessionConfig hold information about configuring sessions.
        """
        return self.__session_config

    def token_config(self) -> "TokenConfig":
        """
        tokenConfig contains options for authorization and access tokens
        """
        return self.__token_config

    def templates(self) -> Optional["OAuthTemplates"]:
        """
        templates allow you to customize pages like the login page.
        """
        return self.__templates


class OpenIDClaims(types.Object):
    """
    OpenIDClaims contains a list of OpenID claims to use when authenticating with an OpenID identity provider
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        id: List[str] = None,
        preferred_username: List[str] = None,
        name: List[str] = None,
        email: List[str] = None,
    ):
        super().__init__()
        self.__id = id if id is not None else []
        self.__preferred_username = (
            preferred_username if preferred_username is not None else []
        )
        self.__name = name if name is not None else []
        self.__email = email if email is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        id = self.id()
        check_type("id", id, List[str])
        v["id"] = id
        preferred_username = self.preferred_username()
        check_type("preferred_username", preferred_username, List[str])
        v["preferredUsername"] = preferred_username
        name = self.name()
        check_type("name", name, List[str])
        v["name"] = name
        email = self.email()
        check_type("email", email, List[str])
        v["email"] = email
        return v

    def id(self) -> List[str]:
        """
        id is the list of claims whose values should be used as the user ID. Required.
        OpenID standard identity claim is "sub"
        """
        return self.__id

    def preferred_username(self) -> List[str]:
        """
        preferredUsername is the list of claims whose values should be used as the preferred username.
        If unspecified, the preferred username is determined from the value of the id claim
        """
        return self.__preferred_username

    def name(self) -> List[str]:
        """
        name is the list of claims whose values should be used as the display name. Optional.
        If unspecified, no display name is set for the identity
        """
        return self.__name

    def email(self) -> List[str]:
        """
        email is the list of claims whose values should be used as the email address. Optional.
        If unspecified, no email is set for the identity
        """
        return self.__email


class OpenIDURLs(types.Object):
    """
    OpenIDURLs are URLs to use when authenticating with an OpenID identity provider
    """

    @context.scoped
    @typechecked
    def __init__(self, authorize: str = "", token: str = "", user_info: str = ""):
        super().__init__()
        self.__authorize = authorize
        self.__token = token
        self.__user_info = user_info

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        authorize = self.authorize()
        check_type("authorize", authorize, str)
        v["authorize"] = authorize
        token = self.token()
        check_type("token", token, str)
        v["token"] = token
        user_info = self.user_info()
        check_type("user_info", user_info, str)
        v["userInfo"] = user_info
        return v

    def authorize(self) -> str:
        """
        authorize is the oauth authorization URL
        """
        return self.__authorize

    def token(self) -> str:
        """
        token is the oauth token granting URL
        """
        return self.__token

    def user_info(self) -> str:
        """
        userInfo is the optional userinfo URL.
        If present, a granted access_token is used to request claims
        If empty, a granted id_token is parsed for claims
        """
        return self.__user_info


class OpenIDIdentityProvider(base.TypedObject):
    """
    OpenIDIdentityProvider provides identities for users authenticating using OpenID credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ca: str = "",
        client_id: str = "",
        client_secret: "configv1.StringSource" = None,
        extra_scopes: List[str] = None,
        extra_authorize_parameters: Dict[str, str] = None,
        urls: "OpenIDURLs" = None,
        claims: "OpenIDClaims" = None,
    ):
        super().__init__(
            api_version="osin.config.openshift.io/v1", kind="OpenIDIdentityProvider"
        )
        self.__ca = ca
        self.__client_id = client_id
        self.__client_secret = (
            client_secret if client_secret is not None else configv1.StringSource()
        )
        self.__extra_scopes = extra_scopes if extra_scopes is not None else []
        self.__extra_authorize_parameters = (
            extra_authorize_parameters if extra_authorize_parameters is not None else {}
        )
        self.__urls = urls if urls is not None else OpenIDURLs()
        self.__claims = claims if claims is not None else OpenIDClaims()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ca = self.ca()
        check_type("ca", ca, str)
        v["ca"] = ca
        client_id = self.client_id()
        check_type("client_id", client_id, str)
        v["clientID"] = client_id
        client_secret = self.client_secret()
        check_type("client_secret", client_secret, "configv1.StringSource")
        v["clientSecret"] = client_secret
        extra_scopes = self.extra_scopes()
        check_type("extra_scopes", extra_scopes, List[str])
        v["extraScopes"] = extra_scopes
        extra_authorize_parameters = self.extra_authorize_parameters()
        check_type(
            "extra_authorize_parameters", extra_authorize_parameters, Dict[str, str]
        )
        v["extraAuthorizeParameters"] = extra_authorize_parameters
        urls = self.urls()
        check_type("urls", urls, "OpenIDURLs")
        v["urls"] = urls
        claims = self.claims()
        check_type("claims", claims, "OpenIDClaims")
        v["claims"] = claims
        return v

    def ca(self) -> str:
        """
        ca is the optional trusted certificate authority bundle to use when making requests to the server
        If empty, the default system roots are used
        """
        return self.__ca

    def client_id(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__client_id

    def client_secret(self) -> "configv1.StringSource":
        """
        clientSecret is the oauth client secret
        """
        return self.__client_secret

    def extra_scopes(self) -> List[str]:
        """
        extraScopes are any scopes to request in addition to the standard "openid" scope.
        """
        return self.__extra_scopes

    def extra_authorize_parameters(self) -> Dict[str, str]:
        """
        extraAuthorizeParameters are any custom parameters to add to the authorize request.
        """
        return self.__extra_authorize_parameters

    def urls(self) -> "OpenIDURLs":
        """
        urls to use to authenticate
        """
        return self.__urls

    def claims(self) -> "OpenIDClaims":
        """
        claims mappings
        """
        return self.__claims


class OsinServerConfig(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        generic_api_server_config: "configv1.GenericAPIServerConfig" = None,
        oauth_config: "OAuthConfig" = None,
    ):
        super().__init__(
            api_version="osin.config.openshift.io/v1", kind="OsinServerConfig"
        )
        self.__generic_api_server_config = (
            generic_api_server_config
            if generic_api_server_config is not None
            else configv1.GenericAPIServerConfig()
        )
        self.__oauth_config = (
            oauth_config if oauth_config is not None else OAuthConfig()
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
        oauth_config = self.oauth_config()
        check_type("oauth_config", oauth_config, "OAuthConfig")
        v["oauthConfig"] = oauth_config
        return v

    def generic_api_server_config(self) -> "configv1.GenericAPIServerConfig":
        """
        provides the standard apiserver configuration
        """
        return self.__generic_api_server_config

    def oauth_config(self) -> "OAuthConfig":
        """
        oauthConfig holds the necessary configuration options for OAuth authentication
        """
        return self.__oauth_config


class RequestHeaderIdentityProvider(base.TypedObject):
    """
    RequestHeaderIdentityProvider provides identities for users authenticating using request header credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        login_url: str = "",
        challenge_url: str = "",
        client_ca: str = "",
        client_common_names: List[str] = None,
        headers: List[str] = None,
        preferred_username_headers: List[str] = None,
        name_headers: List[str] = None,
        email_headers: List[str] = None,
    ):
        super().__init__(
            api_version="osin.config.openshift.io/v1",
            kind="RequestHeaderIdentityProvider",
        )
        self.__login_url = login_url
        self.__challenge_url = challenge_url
        self.__client_ca = client_ca
        self.__client_common_names = (
            client_common_names if client_common_names is not None else []
        )
        self.__headers = headers if headers is not None else []
        self.__preferred_username_headers = (
            preferred_username_headers if preferred_username_headers is not None else []
        )
        self.__name_headers = name_headers if name_headers is not None else []
        self.__email_headers = email_headers if email_headers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        login_url = self.login_url()
        check_type("login_url", login_url, str)
        v["loginURL"] = login_url
        challenge_url = self.challenge_url()
        check_type("challenge_url", challenge_url, str)
        v["challengeURL"] = challenge_url
        client_ca = self.client_ca()
        check_type("client_ca", client_ca, str)
        v["clientCA"] = client_ca
        client_common_names = self.client_common_names()
        check_type("client_common_names", client_common_names, List[str])
        v["clientCommonNames"] = client_common_names
        headers = self.headers()
        check_type("headers", headers, List[str])
        v["headers"] = headers
        preferred_username_headers = self.preferred_username_headers()
        check_type("preferred_username_headers", preferred_username_headers, List[str])
        v["preferredUsernameHeaders"] = preferred_username_headers
        name_headers = self.name_headers()
        check_type("name_headers", name_headers, List[str])
        v["nameHeaders"] = name_headers
        email_headers = self.email_headers()
        check_type("email_headers", email_headers, List[str])
        v["emailHeaders"] = email_headers
        return v

    def login_url(self) -> str:
        """
        loginURL is a URL to redirect unauthenticated /authorize requests to
        Unauthenticated requests from OAuth clients which expect interactive logins will be redirected here
        ${url} is replaced with the current URL, escaped to be safe in a query parameter
          https://www.example.com/sso-login?then=${url}
        ${query} is replaced with the current query string
          https://www.example.com/auth-proxy/oauth/authorize?${query}
        """
        return self.__login_url

    def challenge_url(self) -> str:
        """
        challengeURL is a URL to redirect unauthenticated /authorize requests to
        Unauthenticated requests from OAuth clients which expect WWW-Authenticate challenges will be redirected here
        ${url} is replaced with the current URL, escaped to be safe in a query parameter
          https://www.example.com/sso-login?then=${url}
        ${query} is replaced with the current query string
          https://www.example.com/auth-proxy/oauth/authorize?${query}
        """
        return self.__challenge_url

    def client_ca(self) -> str:
        """
        clientCA is a file with the trusted signer certs.  If empty, no request verification is done, and any direct request to the OAuth server can impersonate any identity from this provider, merely by setting a request header.
        """
        return self.__client_ca

    def client_common_names(self) -> List[str]:
        """
        clientCommonNames is an optional list of common names to require a match from. If empty, any client certificate validated against the clientCA bundle is considered authoritative.
        """
        return self.__client_common_names

    def headers(self) -> List[str]:
        """
        headers is the set of headers to check for identity information
        """
        return self.__headers

    def preferred_username_headers(self) -> List[str]:
        """
        preferredUsernameHeaders is the set of headers to check for the preferred username
        """
        return self.__preferred_username_headers

    def name_headers(self) -> List[str]:
        """
        nameHeaders is the set of headers to check for the display name
        """
        return self.__name_headers

    def email_headers(self) -> List[str]:
        """
        emailHeaders is the set of headers to check for the email address
        """
        return self.__email_headers


class SessionSecret(types.Object):
    """
    SessionSecret is a secret used to authenticate/decrypt cookie-based sessions
    """

    @context.scoped
    @typechecked
    def __init__(self, authentication: str = "", encryption: str = ""):
        super().__init__()
        self.__authentication = authentication
        self.__encryption = encryption

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        authentication = self.authentication()
        check_type("authentication", authentication, str)
        v["authentication"] = authentication
        encryption = self.encryption()
        check_type("encryption", encryption, str)
        v["encryption"] = encryption
        return v

    def authentication(self) -> str:
        """
        Authentication is used to authenticate sessions using HMAC. Recommended to use a secret with 32 or 64 bytes.
        """
        return self.__authentication

    def encryption(self) -> str:
        """
        Encryption is used to encrypt sessions. Must be 16, 24, or 32 characters long, to select AES-128, AES-
        """
        return self.__encryption


class SessionSecrets(base.TypedObject):
    """
    SessionSecrets list the secrets to use to sign/encrypt and authenticate/decrypt created sessions.
    """

    @context.scoped
    @typechecked
    def __init__(self, secrets: List["SessionSecret"] = None):
        super().__init__(
            api_version="osin.config.openshift.io/v1", kind="SessionSecrets"
        )
        self.__secrets = secrets if secrets is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secrets = self.secrets()
        check_type("secrets", secrets, List["SessionSecret"])
        v["secrets"] = secrets
        return v

    def secrets(self) -> List["SessionSecret"]:
        """
        Secrets is a list of secrets
        New sessions are signed and encrypted using the first secret.
        Existing sessions are decrypted/authenticated by each secret until one succeeds. This allows rotating secrets.
        """
        return self.__secrets
