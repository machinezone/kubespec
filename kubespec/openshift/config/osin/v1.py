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
            apiVersion="osin.config.openshift.io/v1",
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
    def __init__(self, remoteConnectionInfo: "configv1.RemoteConnectionInfo" = None):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1",
            kind="BasicAuthPasswordIdentityProvider",
        )
        self.__remoteConnectionInfo = (
            remoteConnectionInfo
            if remoteConnectionInfo is not None
            else configv1.RemoteConnectionInfo()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        remoteConnectionInfo = self.remoteConnectionInfo()
        check_type(
            "remoteConnectionInfo",
            remoteConnectionInfo,
            "configv1.RemoteConnectionInfo",
        )
        v.update(remoteConnectionInfo._root())  # inline
        return v

    def remoteConnectionInfo(self) -> "configv1.RemoteConnectionInfo":
        """
        RemoteConnectionInfo contains information about how to connect to the external basic auth server
        """
        return self.__remoteConnectionInfo


class DenyAllPasswordIdentityProvider(base.TypedObject):
    """
    DenyAllPasswordIdentityProvider provides no identities for users
    """

    @context.scoped
    @typechecked
    def __init__(self):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1",
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
        clientID: str = "",
        clientSecret: "configv1.StringSource" = None,
        organizations: List[str] = None,
        teams: List[str] = None,
        hostname: str = "",
        ca: str = "",
    ):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1", kind="GitHubIdentityProvider"
        )
        self.__clientID = clientID
        self.__clientSecret = (
            clientSecret if clientSecret is not None else configv1.StringSource()
        )
        self.__organizations = organizations if organizations is not None else []
        self.__teams = teams if teams is not None else []
        self.__hostname = hostname
        self.__ca = ca

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientID = self.clientID()
        check_type("clientID", clientID, str)
        v["clientID"] = clientID
        clientSecret = self.clientSecret()
        check_type("clientSecret", clientSecret, "configv1.StringSource")
        v["clientSecret"] = clientSecret
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

    def clientID(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__clientID

    def clientSecret(self) -> "configv1.StringSource":
        """
        clientSecret is the oauth client secret
        """
        return self.__clientSecret

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
        clientID: str = "",
        clientSecret: "configv1.StringSource" = None,
        legacy: bool = None,
    ):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1", kind="GitLabIdentityProvider"
        )
        self.__ca = ca
        self.__url = url
        self.__clientID = clientID
        self.__clientSecret = (
            clientSecret if clientSecret is not None else configv1.StringSource()
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
        clientID = self.clientID()
        check_type("clientID", clientID, str)
        v["clientID"] = clientID
        clientSecret = self.clientSecret()
        check_type("clientSecret", clientSecret, "configv1.StringSource")
        v["clientSecret"] = clientSecret
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

    def clientID(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__clientID

    def clientSecret(self) -> "configv1.StringSource":
        """
        clientSecret is the oauth client secret
        """
        return self.__clientSecret

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
        clientID: str = "",
        clientSecret: "configv1.StringSource" = None,
        hostedDomain: str = "",
    ):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1", kind="GoogleIdentityProvider"
        )
        self.__clientID = clientID
        self.__clientSecret = (
            clientSecret if clientSecret is not None else configv1.StringSource()
        )
        self.__hostedDomain = hostedDomain

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientID = self.clientID()
        check_type("clientID", clientID, str)
        v["clientID"] = clientID
        clientSecret = self.clientSecret()
        check_type("clientSecret", clientSecret, "configv1.StringSource")
        v["clientSecret"] = clientSecret
        hostedDomain = self.hostedDomain()
        check_type("hostedDomain", hostedDomain, str)
        v["hostedDomain"] = hostedDomain
        return v

    def clientID(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__clientID

    def clientSecret(self) -> "configv1.StringSource":
        """
        clientSecret is the oauth client secret
        """
        return self.__clientSecret

    def hostedDomain(self) -> str:
        """
        hostedDomain is the optional Google App domain (e.g. "mycompany.com") to restrict logins to
        """
        return self.__hostedDomain


class GrantConfig(types.Object):
    """
    GrantConfig holds the necessary configuration options for grant handlers
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        method: GrantHandlerType = None,
        serviceAccountMethod: GrantHandlerType = None,
    ):
        super().__init__()
        self.__method = method
        self.__serviceAccountMethod = serviceAccountMethod

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        method = self.method()
        check_type("method", method, GrantHandlerType)
        v["method"] = method
        serviceAccountMethod = self.serviceAccountMethod()
        check_type("serviceAccountMethod", serviceAccountMethod, GrantHandlerType)
        v["serviceAccountMethod"] = serviceAccountMethod
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

    def serviceAccountMethod(self) -> GrantHandlerType:
        """
        serviceAccountMethod is used for determining client authorization for service account oauth client.
        It must be either: deny, prompt
        """
        return self.__serviceAccountMethod


class HTPasswdPasswordIdentityProvider(base.TypedObject):
    """
    HTPasswdPasswordIdentityProvider provides identities for users authenticating using htpasswd credentials
    """

    @context.scoped
    @typechecked
    def __init__(self, file: str = ""):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1",
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
        mappingMethod: str = "",
        provider: "runtime.RawExtension" = None,
    ):
        super().__init__()
        self.__name = name
        self.__challenge = challenge
        self.__login = login
        self.__mappingMethod = mappingMethod
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
        mappingMethod = self.mappingMethod()
        check_type("mappingMethod", mappingMethod, str)
        v["mappingMethod"] = mappingMethod
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

    def mappingMethod(self) -> str:
        """
        mappingMethod determines how identities from this provider are mapped to users
        """
        return self.__mappingMethod

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
        remoteConnectionInfo: "configv1.RemoteConnectionInfo" = None,
        domainName: str = "",
        useKeystoneIdentity: bool = False,
    ):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1",
            kind="KeystonePasswordIdentityProvider",
        )
        self.__remoteConnectionInfo = (
            remoteConnectionInfo
            if remoteConnectionInfo is not None
            else configv1.RemoteConnectionInfo()
        )
        self.__domainName = domainName
        self.__useKeystoneIdentity = useKeystoneIdentity

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        remoteConnectionInfo = self.remoteConnectionInfo()
        check_type(
            "remoteConnectionInfo",
            remoteConnectionInfo,
            "configv1.RemoteConnectionInfo",
        )
        v.update(remoteConnectionInfo._root())  # inline
        domainName = self.domainName()
        check_type("domainName", domainName, str)
        v["domainName"] = domainName
        useKeystoneIdentity = self.useKeystoneIdentity()
        check_type("useKeystoneIdentity", useKeystoneIdentity, bool)
        v["useKeystoneIdentity"] = useKeystoneIdentity
        return v

    def remoteConnectionInfo(self) -> "configv1.RemoteConnectionInfo":
        """
        RemoteConnectionInfo contains information about how to connect to the keystone server
        """
        return self.__remoteConnectionInfo

    def domainName(self) -> str:
        """
        domainName is required for keystone v3
        """
        return self.__domainName

    def useKeystoneIdentity(self) -> bool:
        """
        useKeystoneIdentity flag indicates that user should be authenticated by keystone ID, not by username
        """
        return self.__useKeystoneIdentity


class LDAPAttributeMapping(types.Object):
    """
    LDAPAttributeMapping maps LDAP attributes to OpenShift identity fields
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        id: List[str] = None,
        preferredUsername: List[str] = None,
        name: List[str] = None,
        email: List[str] = None,
    ):
        super().__init__()
        self.__id = id if id is not None else []
        self.__preferredUsername = (
            preferredUsername if preferredUsername is not None else []
        )
        self.__name = name if name is not None else []
        self.__email = email if email is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        id = self.id()
        check_type("id", id, List[str])
        v["id"] = id
        preferredUsername = self.preferredUsername()
        check_type("preferredUsername", preferredUsername, List[str])
        v["preferredUsername"] = preferredUsername
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

    def preferredUsername(self) -> List[str]:
        """
        preferredUsername is the list of attributes whose values should be used as the preferred username.
        LDAP standard login attribute is "uid"
        """
        return self.__preferredUsername

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
        bindDN: str = "",
        bindPassword: "configv1.StringSource" = None,
        insecure: bool = False,
        ca: str = "",
        attributes: "LDAPAttributeMapping" = None,
    ):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1",
            kind="LDAPPasswordIdentityProvider",
        )
        self.__url = url
        self.__bindDN = bindDN
        self.__bindPassword = (
            bindPassword if bindPassword is not None else configv1.StringSource()
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
        bindDN = self.bindDN()
        check_type("bindDN", bindDN, str)
        v["bindDN"] = bindDN
        bindPassword = self.bindPassword()
        check_type("bindPassword", bindPassword, "configv1.StringSource")
        v["bindPassword"] = bindPassword
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

    def bindDN(self) -> str:
        """
        bindDN is an optional DN to bind with during the search phase.
        """
        return self.__bindDN

    def bindPassword(self) -> "configv1.StringSource":
        """
        bindPassword is an optional password to bind with during the search phase.
        """
        return self.__bindPassword

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
    def __init__(self, login: str = "", providerSelection: str = "", error: str = ""):
        super().__init__()
        self.__login = login
        self.__providerSelection = providerSelection
        self.__error = error

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        login = self.login()
        check_type("login", login, str)
        v["login"] = login
        providerSelection = self.providerSelection()
        check_type("providerSelection", providerSelection, str)
        v["providerSelection"] = providerSelection
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

    def providerSelection(self) -> str:
        """
        providerSelection is a path to a file containing a go template used to render the provider selection page.
        If unspecified, the default provider selection page is used.
        """
        return self.__providerSelection

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
        sessionSecretsFile: str = "",
        sessionMaxAgeSeconds: int = 0,
        sessionName: str = "",
    ):
        super().__init__()
        self.__sessionSecretsFile = sessionSecretsFile
        self.__sessionMaxAgeSeconds = sessionMaxAgeSeconds
        self.__sessionName = sessionName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        sessionSecretsFile = self.sessionSecretsFile()
        check_type("sessionSecretsFile", sessionSecretsFile, str)
        v["sessionSecretsFile"] = sessionSecretsFile
        sessionMaxAgeSeconds = self.sessionMaxAgeSeconds()
        check_type("sessionMaxAgeSeconds", sessionMaxAgeSeconds, int)
        v["sessionMaxAgeSeconds"] = sessionMaxAgeSeconds
        sessionName = self.sessionName()
        check_type("sessionName", sessionName, str)
        v["sessionName"] = sessionName
        return v

    def sessionSecretsFile(self) -> str:
        """
        sessionSecretsFile is a reference to a file containing a serialized SessionSecrets object
        If no file is specified, a random signing and encryption key are generated at each server start
        """
        return self.__sessionSecretsFile

    def sessionMaxAgeSeconds(self) -> int:
        """
        sessionMaxAgeSeconds specifies how long created sessions last. Used by AuthRequestHandlerSession
        """
        return self.__sessionMaxAgeSeconds

    def sessionName(self) -> str:
        """
        sessionName is the cookie name used to store the session
        """
        return self.__sessionName


class TokenConfig(types.Object):
    """
    TokenConfig holds the necessary configuration options for authorization and access tokens
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        authorizeTokenMaxAgeSeconds: int = 0,
        accessTokenMaxAgeSeconds: int = 0,
        accessTokenInactivityTimeoutSeconds: int = None,
    ):
        super().__init__()
        self.__authorizeTokenMaxAgeSeconds = authorizeTokenMaxAgeSeconds
        self.__accessTokenMaxAgeSeconds = accessTokenMaxAgeSeconds
        self.__accessTokenInactivityTimeoutSeconds = accessTokenInactivityTimeoutSeconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        authorizeTokenMaxAgeSeconds = self.authorizeTokenMaxAgeSeconds()
        check_type("authorizeTokenMaxAgeSeconds", authorizeTokenMaxAgeSeconds, int)
        v["authorizeTokenMaxAgeSeconds"] = authorizeTokenMaxAgeSeconds
        accessTokenMaxAgeSeconds = self.accessTokenMaxAgeSeconds()
        check_type("accessTokenMaxAgeSeconds", accessTokenMaxAgeSeconds, int)
        v["accessTokenMaxAgeSeconds"] = accessTokenMaxAgeSeconds
        accessTokenInactivityTimeoutSeconds = self.accessTokenInactivityTimeoutSeconds()
        check_type(
            "accessTokenInactivityTimeoutSeconds",
            accessTokenInactivityTimeoutSeconds,
            Optional[int],
        )
        if accessTokenInactivityTimeoutSeconds is not None:  # omit empty
            v[
                "accessTokenInactivityTimeoutSeconds"
            ] = accessTokenInactivityTimeoutSeconds
        return v

    def authorizeTokenMaxAgeSeconds(self) -> int:
        """
        authorizeTokenMaxAgeSeconds defines the maximum age of authorize tokens
        """
        return self.__authorizeTokenMaxAgeSeconds

    def accessTokenMaxAgeSeconds(self) -> int:
        """
        accessTokenMaxAgeSeconds defines the maximum age of access tokens
        """
        return self.__accessTokenMaxAgeSeconds

    def accessTokenInactivityTimeoutSeconds(self) -> Optional[int]:
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
        return self.__accessTokenInactivityTimeoutSeconds


class OAuthConfig(types.Object):
    """
    OAuthConfig holds the necessary configuration options for OAuth authentication
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        loginURL: str = "",
        assetPublicURL: str = "",
        alwaysShowProviderSelection: bool = False,
        identityProviders: List["IdentityProvider"] = None,
        grantConfig: "GrantConfig" = None,
        sessionConfig: "SessionConfig" = None,
        tokenConfig: "TokenConfig" = None,
        templates: "OAuthTemplates" = None,
    ):
        super().__init__()
        self.__loginURL = loginURL
        self.__assetPublicURL = assetPublicURL
        self.__alwaysShowProviderSelection = alwaysShowProviderSelection
        self.__identityProviders = (
            identityProviders if identityProviders is not None else []
        )
        self.__grantConfig = grantConfig if grantConfig is not None else GrantConfig()
        self.__sessionConfig = sessionConfig
        self.__tokenConfig = tokenConfig if tokenConfig is not None else TokenConfig()
        self.__templates = templates

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        loginURL = self.loginURL()
        check_type("loginURL", loginURL, str)
        v["loginURL"] = loginURL
        assetPublicURL = self.assetPublicURL()
        check_type("assetPublicURL", assetPublicURL, str)
        v["assetPublicURL"] = assetPublicURL
        alwaysShowProviderSelection = self.alwaysShowProviderSelection()
        check_type("alwaysShowProviderSelection", alwaysShowProviderSelection, bool)
        v["alwaysShowProviderSelection"] = alwaysShowProviderSelection
        identityProviders = self.identityProviders()
        check_type("identityProviders", identityProviders, List["IdentityProvider"])
        v["identityProviders"] = identityProviders
        grantConfig = self.grantConfig()
        check_type("grantConfig", grantConfig, "GrantConfig")
        v["grantConfig"] = grantConfig
        sessionConfig = self.sessionConfig()
        check_type("sessionConfig", sessionConfig, Optional["SessionConfig"])
        v["sessionConfig"] = sessionConfig
        tokenConfig = self.tokenConfig()
        check_type("tokenConfig", tokenConfig, "TokenConfig")
        v["tokenConfig"] = tokenConfig
        templates = self.templates()
        check_type("templates", templates, Optional["OAuthTemplates"])
        v["templates"] = templates
        return v

    def loginURL(self) -> str:
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
        return self.__loginURL

    def assetPublicURL(self) -> str:
        """
        assetPublicURL is used for building valid client redirect URLs for external access
        """
        return self.__assetPublicURL

    def alwaysShowProviderSelection(self) -> bool:
        """
        alwaysShowProviderSelection will force the provider selection page to render even when there is only a single provider.
        """
        return self.__alwaysShowProviderSelection

    def identityProviders(self) -> List["IdentityProvider"]:
        """
        identityProviders is an ordered list of ways for a user to identify themselves
        """
        return self.__identityProviders

    def grantConfig(self) -> "GrantConfig":
        """
        grantConfig describes how to handle grants
        """
        return self.__grantConfig

    def sessionConfig(self) -> Optional["SessionConfig"]:
        """
        sessionConfig hold information about configuring sessions.
        """
        return self.__sessionConfig

    def tokenConfig(self) -> "TokenConfig":
        """
        tokenConfig contains options for authorization and access tokens
        """
        return self.__tokenConfig

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
        preferredUsername: List[str] = None,
        name: List[str] = None,
        email: List[str] = None,
    ):
        super().__init__()
        self.__id = id if id is not None else []
        self.__preferredUsername = (
            preferredUsername if preferredUsername is not None else []
        )
        self.__name = name if name is not None else []
        self.__email = email if email is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        id = self.id()
        check_type("id", id, List[str])
        v["id"] = id
        preferredUsername = self.preferredUsername()
        check_type("preferredUsername", preferredUsername, List[str])
        v["preferredUsername"] = preferredUsername
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

    def preferredUsername(self) -> List[str]:
        """
        preferredUsername is the list of claims whose values should be used as the preferred username.
        If unspecified, the preferred username is determined from the value of the id claim
        """
        return self.__preferredUsername

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
    def __init__(self, authorize: str = "", token: str = "", userInfo: str = ""):
        super().__init__()
        self.__authorize = authorize
        self.__token = token
        self.__userInfo = userInfo

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        authorize = self.authorize()
        check_type("authorize", authorize, str)
        v["authorize"] = authorize
        token = self.token()
        check_type("token", token, str)
        v["token"] = token
        userInfo = self.userInfo()
        check_type("userInfo", userInfo, str)
        v["userInfo"] = userInfo
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

    def userInfo(self) -> str:
        """
        userInfo is the optional userinfo URL.
        If present, a granted access_token is used to request claims
        If empty, a granted id_token is parsed for claims
        """
        return self.__userInfo


class OpenIDIdentityProvider(base.TypedObject):
    """
    OpenIDIdentityProvider provides identities for users authenticating using OpenID credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ca: str = "",
        clientID: str = "",
        clientSecret: "configv1.StringSource" = None,
        extraScopes: List[str] = None,
        extraAuthorizeParameters: Dict[str, str] = None,
        urls: "OpenIDURLs" = None,
        claims: "OpenIDClaims" = None,
    ):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1", kind="OpenIDIdentityProvider"
        )
        self.__ca = ca
        self.__clientID = clientID
        self.__clientSecret = (
            clientSecret if clientSecret is not None else configv1.StringSource()
        )
        self.__extraScopes = extraScopes if extraScopes is not None else []
        self.__extraAuthorizeParameters = (
            extraAuthorizeParameters if extraAuthorizeParameters is not None else {}
        )
        self.__urls = urls if urls is not None else OpenIDURLs()
        self.__claims = claims if claims is not None else OpenIDClaims()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ca = self.ca()
        check_type("ca", ca, str)
        v["ca"] = ca
        clientID = self.clientID()
        check_type("clientID", clientID, str)
        v["clientID"] = clientID
        clientSecret = self.clientSecret()
        check_type("clientSecret", clientSecret, "configv1.StringSource")
        v["clientSecret"] = clientSecret
        extraScopes = self.extraScopes()
        check_type("extraScopes", extraScopes, List[str])
        v["extraScopes"] = extraScopes
        extraAuthorizeParameters = self.extraAuthorizeParameters()
        check_type("extraAuthorizeParameters", extraAuthorizeParameters, Dict[str, str])
        v["extraAuthorizeParameters"] = extraAuthorizeParameters
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

    def clientID(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__clientID

    def clientSecret(self) -> "configv1.StringSource":
        """
        clientSecret is the oauth client secret
        """
        return self.__clientSecret

    def extraScopes(self) -> List[str]:
        """
        extraScopes are any scopes to request in addition to the standard "openid" scope.
        """
        return self.__extraScopes

    def extraAuthorizeParameters(self) -> Dict[str, str]:
        """
        extraAuthorizeParameters are any custom parameters to add to the authorize request.
        """
        return self.__extraAuthorizeParameters

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
        genericAPIServerConfig: "configv1.GenericAPIServerConfig" = None,
        oauthConfig: "OAuthConfig" = None,
    ):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1", kind="OsinServerConfig"
        )
        self.__genericAPIServerConfig = (
            genericAPIServerConfig
            if genericAPIServerConfig is not None
            else configv1.GenericAPIServerConfig()
        )
        self.__oauthConfig = oauthConfig if oauthConfig is not None else OAuthConfig()

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
        oauthConfig = self.oauthConfig()
        check_type("oauthConfig", oauthConfig, "OAuthConfig")
        v["oauthConfig"] = oauthConfig
        return v

    def genericAPIServerConfig(self) -> "configv1.GenericAPIServerConfig":
        """
        provides the standard apiserver configuration
        """
        return self.__genericAPIServerConfig

    def oauthConfig(self) -> "OAuthConfig":
        """
        oauthConfig holds the necessary configuration options for OAuth authentication
        """
        return self.__oauthConfig


class RequestHeaderIdentityProvider(base.TypedObject):
    """
    RequestHeaderIdentityProvider provides identities for users authenticating using request header credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        loginURL: str = "",
        challengeURL: str = "",
        clientCA: str = "",
        clientCommonNames: List[str] = None,
        headers: List[str] = None,
        preferredUsernameHeaders: List[str] = None,
        nameHeaders: List[str] = None,
        emailHeaders: List[str] = None,
    ):
        super().__init__(
            apiVersion="osin.config.openshift.io/v1",
            kind="RequestHeaderIdentityProvider",
        )
        self.__loginURL = loginURL
        self.__challengeURL = challengeURL
        self.__clientCA = clientCA
        self.__clientCommonNames = (
            clientCommonNames if clientCommonNames is not None else []
        )
        self.__headers = headers if headers is not None else []
        self.__preferredUsernameHeaders = (
            preferredUsernameHeaders if preferredUsernameHeaders is not None else []
        )
        self.__nameHeaders = nameHeaders if nameHeaders is not None else []
        self.__emailHeaders = emailHeaders if emailHeaders is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        loginURL = self.loginURL()
        check_type("loginURL", loginURL, str)
        v["loginURL"] = loginURL
        challengeURL = self.challengeURL()
        check_type("challengeURL", challengeURL, str)
        v["challengeURL"] = challengeURL
        clientCA = self.clientCA()
        check_type("clientCA", clientCA, str)
        v["clientCA"] = clientCA
        clientCommonNames = self.clientCommonNames()
        check_type("clientCommonNames", clientCommonNames, List[str])
        v["clientCommonNames"] = clientCommonNames
        headers = self.headers()
        check_type("headers", headers, List[str])
        v["headers"] = headers
        preferredUsernameHeaders = self.preferredUsernameHeaders()
        check_type("preferredUsernameHeaders", preferredUsernameHeaders, List[str])
        v["preferredUsernameHeaders"] = preferredUsernameHeaders
        nameHeaders = self.nameHeaders()
        check_type("nameHeaders", nameHeaders, List[str])
        v["nameHeaders"] = nameHeaders
        emailHeaders = self.emailHeaders()
        check_type("emailHeaders", emailHeaders, List[str])
        v["emailHeaders"] = emailHeaders
        return v

    def loginURL(self) -> str:
        """
        loginURL is a URL to redirect unauthenticated /authorize requests to
        Unauthenticated requests from OAuth clients which expect interactive logins will be redirected here
        ${url} is replaced with the current URL, escaped to be safe in a query parameter
          https://www.example.com/sso-login?then=${url}
        ${query} is replaced with the current query string
          https://www.example.com/auth-proxy/oauth/authorize?${query}
        """
        return self.__loginURL

    def challengeURL(self) -> str:
        """
        challengeURL is a URL to redirect unauthenticated /authorize requests to
        Unauthenticated requests from OAuth clients which expect WWW-Authenticate challenges will be redirected here
        ${url} is replaced with the current URL, escaped to be safe in a query parameter
          https://www.example.com/sso-login?then=${url}
        ${query} is replaced with the current query string
          https://www.example.com/auth-proxy/oauth/authorize?${query}
        """
        return self.__challengeURL

    def clientCA(self) -> str:
        """
        clientCA is a file with the trusted signer certs.  If empty, no request verification is done, and any direct request to the OAuth server can impersonate any identity from this provider, merely by setting a request header.
        """
        return self.__clientCA

    def clientCommonNames(self) -> List[str]:
        """
        clientCommonNames is an optional list of common names to require a match from. If empty, any client certificate validated against the clientCA bundle is considered authoritative.
        """
        return self.__clientCommonNames

    def headers(self) -> List[str]:
        """
        headers is the set of headers to check for identity information
        """
        return self.__headers

    def preferredUsernameHeaders(self) -> List[str]:
        """
        preferredUsernameHeaders is the set of headers to check for the preferred username
        """
        return self.__preferredUsernameHeaders

    def nameHeaders(self) -> List[str]:
        """
        nameHeaders is the set of headers to check for the display name
        """
        return self.__nameHeaders

    def emailHeaders(self) -> List[str]:
        """
        emailHeaders is the set of headers to check for the email address
        """
        return self.__emailHeaders


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
            apiVersion="osin.config.openshift.io/v1", kind="SessionSecrets"
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
