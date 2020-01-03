# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


GrantHandlerType = base.Enum(
    "GrantHandlerType",
    {
        # Auto auto-approves client authorization grant requests
        "Auto": "auto",
        # Deny auto-denies client authorization grant requests
        "Deny": "deny",
        # Prompt prompts the user to approve new client authorization grant requests
        "Prompt": "prompt",
    },
)


class ClusterRoleScopeRestriction(types.Object):
    """
    ClusterRoleScopeRestriction describes restrictions on cluster role scopes
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        roleNames: List[str] = None,
        namespaces: List[str] = None,
        allowEscalation: bool = False,
    ):
        super().__init__()
        self.__roleNames = roleNames if roleNames is not None else []
        self.__namespaces = namespaces if namespaces is not None else []
        self.__allowEscalation = allowEscalation

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        roleNames = self.roleNames()
        check_type("roleNames", roleNames, List[str])
        v["roleNames"] = roleNames
        namespaces = self.namespaces()
        check_type("namespaces", namespaces, List[str])
        v["namespaces"] = namespaces
        allowEscalation = self.allowEscalation()
        check_type("allowEscalation", allowEscalation, bool)
        v["allowEscalation"] = allowEscalation
        return v

    def roleNames(self) -> List[str]:
        """
        RoleNames is the list of cluster roles that can referenced.  * means anything
        """
        return self.__roleNames

    def namespaces(self) -> List[str]:
        """
        Namespaces is the list of namespaces that can be referenced.  * means any of them (including *)
        """
        return self.__namespaces

    def allowEscalation(self) -> bool:
        """
        AllowEscalation indicates whether you can request roles and their escalating resources
        """
        return self.__allowEscalation


class OAuthAccessToken(base.TypedObject, base.MetadataObject):
    """
    OAuthAccessToken describes an OAuth access token
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        clientName: str = None,
        expiresIn: int = None,
        scopes: List[str] = None,
        redirectURI: str = None,
        userName: str = None,
        userUID: str = None,
        authorizeToken: str = None,
        refreshToken: str = None,
        inactivityTimeoutSeconds: int = None,
    ):
        super().__init__(
            apiVersion="oauth.openshift.io/v1",
            kind="OAuthAccessToken",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__clientName = clientName
        self.__expiresIn = expiresIn
        self.__scopes = scopes if scopes is not None else []
        self.__redirectURI = redirectURI
        self.__userName = userName
        self.__userUID = userUID
        self.__authorizeToken = authorizeToken
        self.__refreshToken = refreshToken
        self.__inactivityTimeoutSeconds = inactivityTimeoutSeconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientName = self.clientName()
        check_type("clientName", clientName, Optional[str])
        if clientName:  # omit empty
            v["clientName"] = clientName
        expiresIn = self.expiresIn()
        check_type("expiresIn", expiresIn, Optional[int])
        if expiresIn:  # omit empty
            v["expiresIn"] = expiresIn
        scopes = self.scopes()
        check_type("scopes", scopes, Optional[List[str]])
        if scopes:  # omit empty
            v["scopes"] = scopes
        redirectURI = self.redirectURI()
        check_type("redirectURI", redirectURI, Optional[str])
        if redirectURI:  # omit empty
            v["redirectURI"] = redirectURI
        userName = self.userName()
        check_type("userName", userName, Optional[str])
        if userName:  # omit empty
            v["userName"] = userName
        userUID = self.userUID()
        check_type("userUID", userUID, Optional[str])
        if userUID:  # omit empty
            v["userUID"] = userUID
        authorizeToken = self.authorizeToken()
        check_type("authorizeToken", authorizeToken, Optional[str])
        if authorizeToken:  # omit empty
            v["authorizeToken"] = authorizeToken
        refreshToken = self.refreshToken()
        check_type("refreshToken", refreshToken, Optional[str])
        if refreshToken:  # omit empty
            v["refreshToken"] = refreshToken
        inactivityTimeoutSeconds = self.inactivityTimeoutSeconds()
        check_type("inactivityTimeoutSeconds", inactivityTimeoutSeconds, Optional[int])
        if inactivityTimeoutSeconds:  # omit empty
            v["inactivityTimeoutSeconds"] = inactivityTimeoutSeconds
        return v

    def clientName(self) -> Optional[str]:
        """
        ClientName references the client that created this token.
        """
        return self.__clientName

    def expiresIn(self) -> Optional[int]:
        """
        ExpiresIn is the seconds from CreationTime before this token expires.
        """
        return self.__expiresIn

    def scopes(self) -> Optional[List[str]]:
        """
        Scopes is an array of the requested scopes.
        """
        return self.__scopes

    def redirectURI(self) -> Optional[str]:
        """
        RedirectURI is the redirection associated with the token.
        """
        return self.__redirectURI

    def userName(self) -> Optional[str]:
        """
        UserName is the user name associated with this token
        """
        return self.__userName

    def userUID(self) -> Optional[str]:
        """
        UserUID is the unique UID associated with this token
        """
        return self.__userUID

    def authorizeToken(self) -> Optional[str]:
        """
        AuthorizeToken contains the token that authorized this token
        """
        return self.__authorizeToken

    def refreshToken(self) -> Optional[str]:
        """
        RefreshToken is the value by which this token can be renewed. Can be blank.
        """
        return self.__refreshToken

    def inactivityTimeoutSeconds(self) -> Optional[int]:
        """
        InactivityTimeoutSeconds is the value in seconds, from the
        CreationTimestamp, after which this token can no longer be used.
        The value is automatically incremented when the token is used.
        """
        return self.__inactivityTimeoutSeconds


class OAuthAuthorizeToken(base.TypedObject, base.MetadataObject):
    """
    OAuthAuthorizeToken describes an OAuth authorization token
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        clientName: str = None,
        expiresIn: int = None,
        scopes: List[str] = None,
        redirectURI: str = None,
        state: str = None,
        userName: str = None,
        userUID: str = None,
        codeChallenge: str = None,
        codeChallengeMethod: str = None,
    ):
        super().__init__(
            apiVersion="oauth.openshift.io/v1",
            kind="OAuthAuthorizeToken",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__clientName = clientName
        self.__expiresIn = expiresIn
        self.__scopes = scopes if scopes is not None else []
        self.__redirectURI = redirectURI
        self.__state = state
        self.__userName = userName
        self.__userUID = userUID
        self.__codeChallenge = codeChallenge
        self.__codeChallengeMethod = codeChallengeMethod

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientName = self.clientName()
        check_type("clientName", clientName, Optional[str])
        if clientName:  # omit empty
            v["clientName"] = clientName
        expiresIn = self.expiresIn()
        check_type("expiresIn", expiresIn, Optional[int])
        if expiresIn:  # omit empty
            v["expiresIn"] = expiresIn
        scopes = self.scopes()
        check_type("scopes", scopes, Optional[List[str]])
        if scopes:  # omit empty
            v["scopes"] = scopes
        redirectURI = self.redirectURI()
        check_type("redirectURI", redirectURI, Optional[str])
        if redirectURI:  # omit empty
            v["redirectURI"] = redirectURI
        state = self.state()
        check_type("state", state, Optional[str])
        if state:  # omit empty
            v["state"] = state
        userName = self.userName()
        check_type("userName", userName, Optional[str])
        if userName:  # omit empty
            v["userName"] = userName
        userUID = self.userUID()
        check_type("userUID", userUID, Optional[str])
        if userUID:  # omit empty
            v["userUID"] = userUID
        codeChallenge = self.codeChallenge()
        check_type("codeChallenge", codeChallenge, Optional[str])
        if codeChallenge:  # omit empty
            v["codeChallenge"] = codeChallenge
        codeChallengeMethod = self.codeChallengeMethod()
        check_type("codeChallengeMethod", codeChallengeMethod, Optional[str])
        if codeChallengeMethod:  # omit empty
            v["codeChallengeMethod"] = codeChallengeMethod
        return v

    def clientName(self) -> Optional[str]:
        """
        ClientName references the client that created this token.
        """
        return self.__clientName

    def expiresIn(self) -> Optional[int]:
        """
        ExpiresIn is the seconds from CreationTime before this token expires.
        """
        return self.__expiresIn

    def scopes(self) -> Optional[List[str]]:
        """
        Scopes is an array of the requested scopes.
        """
        return self.__scopes

    def redirectURI(self) -> Optional[str]:
        """
        RedirectURI is the redirection associated with the token.
        """
        return self.__redirectURI

    def state(self) -> Optional[str]:
        """
        State data from request
        """
        return self.__state

    def userName(self) -> Optional[str]:
        """
        UserName is the user name associated with this token
        """
        return self.__userName

    def userUID(self) -> Optional[str]:
        """
        UserUID is the unique UID associated with this token. UserUID and UserName must both match
        for this token to be valid.
        """
        return self.__userUID

    def codeChallenge(self) -> Optional[str]:
        """
        CodeChallenge is the optional code_challenge associated with this authorization code, as described in rfc7636
        """
        return self.__codeChallenge

    def codeChallengeMethod(self) -> Optional[str]:
        """
        CodeChallengeMethod is the optional code_challenge_method associated with this authorization code, as described in rfc7636
        """
        return self.__codeChallengeMethod


class ScopeRestriction(types.Object):
    """
    ScopeRestriction describe one restriction on scopes.  Exactly one option must be non-nil.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        literals: List[str] = None,
        clusterRole: "ClusterRoleScopeRestriction" = None,
    ):
        super().__init__()
        self.__literals = literals if literals is not None else []
        self.__clusterRole = clusterRole

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        literals = self.literals()
        check_type("literals", literals, Optional[List[str]])
        if literals:  # omit empty
            v["literals"] = literals
        clusterRole = self.clusterRole()
        check_type("clusterRole", clusterRole, Optional["ClusterRoleScopeRestriction"])
        if clusterRole is not None:  # omit empty
            v["clusterRole"] = clusterRole
        return v

    def literals(self) -> Optional[List[str]]:
        """
        ExactValues means the scope has to match a particular set of strings exactly
        """
        return self.__literals

    def clusterRole(self) -> Optional["ClusterRoleScopeRestriction"]:
        """
        ClusterRole describes a set of restrictions for cluster role scoping.
        """
        return self.__clusterRole


class OAuthClient(base.TypedObject, base.MetadataObject):
    """
    OAuthClient describes an OAuth client
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        secret: str = None,
        additionalSecrets: List[str] = None,
        respondWithChallenges: bool = None,
        redirectURIs: List[str] = None,
        grantMethod: GrantHandlerType = None,
        scopeRestrictions: List["ScopeRestriction"] = None,
        accessTokenMaxAgeSeconds: int = None,
        accessTokenInactivityTimeoutSeconds: int = None,
    ):
        super().__init__(
            apiVersion="oauth.openshift.io/v1",
            kind="OAuthClient",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__secret = secret
        self.__additionalSecrets = (
            additionalSecrets if additionalSecrets is not None else []
        )
        self.__respondWithChallenges = respondWithChallenges
        self.__redirectURIs = redirectURIs if redirectURIs is not None else []
        self.__grantMethod = grantMethod
        self.__scopeRestrictions = (
            scopeRestrictions if scopeRestrictions is not None else []
        )
        self.__accessTokenMaxAgeSeconds = accessTokenMaxAgeSeconds
        self.__accessTokenInactivityTimeoutSeconds = accessTokenInactivityTimeoutSeconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secret = self.secret()
        check_type("secret", secret, Optional[str])
        if secret:  # omit empty
            v["secret"] = secret
        additionalSecrets = self.additionalSecrets()
        check_type("additionalSecrets", additionalSecrets, Optional[List[str]])
        if additionalSecrets:  # omit empty
            v["additionalSecrets"] = additionalSecrets
        respondWithChallenges = self.respondWithChallenges()
        check_type("respondWithChallenges", respondWithChallenges, Optional[bool])
        if respondWithChallenges:  # omit empty
            v["respondWithChallenges"] = respondWithChallenges
        redirectURIs = self.redirectURIs()
        check_type("redirectURIs", redirectURIs, Optional[List[str]])
        if redirectURIs:  # omit empty
            v["redirectURIs"] = redirectURIs
        grantMethod = self.grantMethod()
        check_type("grantMethod", grantMethod, Optional[GrantHandlerType])
        if grantMethod:  # omit empty
            v["grantMethod"] = grantMethod
        scopeRestrictions = self.scopeRestrictions()
        check_type(
            "scopeRestrictions", scopeRestrictions, Optional[List["ScopeRestriction"]]
        )
        if scopeRestrictions:  # omit empty
            v["scopeRestrictions"] = scopeRestrictions
        accessTokenMaxAgeSeconds = self.accessTokenMaxAgeSeconds()
        check_type("accessTokenMaxAgeSeconds", accessTokenMaxAgeSeconds, Optional[int])
        if accessTokenMaxAgeSeconds is not None:  # omit empty
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

    def secret(self) -> Optional[str]:
        """
        Secret is the unique secret associated with a client
        """
        return self.__secret

    def additionalSecrets(self) -> Optional[List[str]]:
        """
        AdditionalSecrets holds other secrets that may be used to identify the client.  This is useful for rotation
        and for service account token validation
        """
        return self.__additionalSecrets

    def respondWithChallenges(self) -> Optional[bool]:
        """
        RespondWithChallenges indicates whether the client wants authentication needed responses made in the form of challenges instead of redirects
        """
        return self.__respondWithChallenges

    def redirectURIs(self) -> Optional[List[str]]:
        """
        RedirectURIs is the valid redirection URIs associated with a client
        """
        return self.__redirectURIs

    def grantMethod(self) -> Optional[GrantHandlerType]:
        """
        GrantMethod is a required field which determines how to handle grants for this client.
        Valid grant handling methods are:
         - auto:   always approves grant requests, useful for trusted clients
         - prompt: prompts the end user for approval of grant requests, useful for third-party clients
        """
        return self.__grantMethod

    def scopeRestrictions(self) -> Optional[List["ScopeRestriction"]]:
        """
        ScopeRestrictions describes which scopes this client can request.  Each requested scope
        is checked against each restriction.  If any restriction matches, then the scope is allowed.
        If no restriction matches, then the scope is denied.
        """
        return self.__scopeRestrictions

    def accessTokenMaxAgeSeconds(self) -> Optional[int]:
        """
        AccessTokenMaxAgeSeconds overrides the default access token max age for tokens granted to this client.
        0 means no expiration.
        """
        return self.__accessTokenMaxAgeSeconds

    def accessTokenInactivityTimeoutSeconds(self) -> Optional[int]:
        """
        AccessTokenInactivityTimeoutSeconds overrides the default token
        inactivity timeout for tokens granted to this client.
        The value represents the maximum amount of time that can occur between
        consecutive uses of the token. Tokens become invalid if they are not
        used within this temporal window. The user will need to acquire a new
        token to regain access once a token times out.
        This value needs to be set only if the default set in configuration is
        not appropriate for this client. Valid values are:
        - 0: Tokens for this client never time out
        - X: Tokens time out if there is no activity for X seconds
        The current minimum allowed value for X is 300 (5 minutes)
        """
        return self.__accessTokenInactivityTimeoutSeconds


class OAuthClientAuthorization(base.TypedObject, base.MetadataObject):
    """
    OAuthClientAuthorization describes an authorization created by an OAuth client
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        clientName: str = None,
        userName: str = None,
        userUID: str = None,
        scopes: List[str] = None,
    ):
        super().__init__(
            apiVersion="oauth.openshift.io/v1",
            kind="OAuthClientAuthorization",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__clientName = clientName
        self.__userName = userName
        self.__userUID = userUID
        self.__scopes = scopes if scopes is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientName = self.clientName()
        check_type("clientName", clientName, Optional[str])
        if clientName:  # omit empty
            v["clientName"] = clientName
        userName = self.userName()
        check_type("userName", userName, Optional[str])
        if userName:  # omit empty
            v["userName"] = userName
        userUID = self.userUID()
        check_type("userUID", userUID, Optional[str])
        if userUID:  # omit empty
            v["userUID"] = userUID
        scopes = self.scopes()
        check_type("scopes", scopes, Optional[List[str]])
        if scopes:  # omit empty
            v["scopes"] = scopes
        return v

    def clientName(self) -> Optional[str]:
        """
        ClientName references the client that created this authorization
        """
        return self.__clientName

    def userName(self) -> Optional[str]:
        """
        UserName is the user name that authorized this client
        """
        return self.__userName

    def userUID(self) -> Optional[str]:
        """
        UserUID is the unique UID associated with this authorization. UserUID and UserName
        must both match for this authorization to be valid.
        """
        return self.__userUID

    def scopes(self) -> Optional[List[str]]:
        """
        Scopes is an array of the granted scopes.
        """
        return self.__scopes


class RedirectReference(types.Object):
    """
    RedirectReference specifies the target in the current namespace that resolves into redirect URIs.  Only the 'Route' kind is currently allowed.
    """

    @context.scoped
    @typechecked
    def __init__(self, group: str = "", kind: str = "", name: str = ""):
        super().__init__()
        self.__group = group
        self.__kind = kind
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        group = self.group()
        check_type("group", group, str)
        v["group"] = group
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def group(self) -> str:
        """
        The group of the target that is being referred to.
        """
        return self.__group

    def kind(self) -> str:
        """
        The kind of the target that is being referred to.  Currently, only 'Route' is allowed.
        """
        return self.__kind

    def name(self) -> str:
        """
        The name of the target that is being referred to. e.g. name of the Route.
        """
        return self.__name


class OAuthRedirectReference(base.TypedObject, base.NamespacedMetadataObject):
    """
    OAuthRedirectReference is a reference to an OAuth redirect object.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        reference: "RedirectReference" = None,
    ):
        super().__init__(
            apiVersion="oauth.openshift.io/v1",
            kind="OAuthRedirectReference",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__reference = reference if reference is not None else RedirectReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        reference = self.reference()
        check_type("reference", reference, Optional["RedirectReference"])
        v["reference"] = reference
        return v

    def reference(self) -> Optional["RedirectReference"]:
        """
        The reference to an redirect object in the current namespace.
        """
        return self.__reference
