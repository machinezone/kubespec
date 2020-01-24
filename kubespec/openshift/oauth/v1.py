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
        role_names: List[str] = None,
        namespaces: List[str] = None,
        allow_escalation: bool = False,
    ):
        super().__init__()
        self.__role_names = role_names if role_names is not None else []
        self.__namespaces = namespaces if namespaces is not None else []
        self.__allow_escalation = allow_escalation

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        role_names = self.role_names()
        check_type("role_names", role_names, List[str])
        v["roleNames"] = role_names
        namespaces = self.namespaces()
        check_type("namespaces", namespaces, List[str])
        v["namespaces"] = namespaces
        allow_escalation = self.allow_escalation()
        check_type("allow_escalation", allow_escalation, bool)
        v["allowEscalation"] = allow_escalation
        return v

    def role_names(self) -> List[str]:
        """
        RoleNames is the list of cluster roles that can referenced.  * means anything
        """
        return self.__role_names

    def namespaces(self) -> List[str]:
        """
        Namespaces is the list of namespaces that can be referenced.  * means any of them (including *)
        """
        return self.__namespaces

    def allow_escalation(self) -> bool:
        """
        AllowEscalation indicates whether you can request roles and their escalating resources
        """
        return self.__allow_escalation


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
        client_name: str = None,
        expires_in: int = None,
        scopes: List[str] = None,
        redirect_uri: str = None,
        user_name: str = None,
        user_uid: str = None,
        authorize_token: str = None,
        refresh_token: str = None,
        inactivity_timeout_seconds: int = None,
    ):
        super().__init__(
            api_version="oauth.openshift.io/v1",
            kind="OAuthAccessToken",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__client_name = client_name
        self.__expires_in = expires_in
        self.__scopes = scopes if scopes is not None else []
        self.__redirect_uri = redirect_uri
        self.__user_name = user_name
        self.__user_uid = user_uid
        self.__authorize_token = authorize_token
        self.__refresh_token = refresh_token
        self.__inactivity_timeout_seconds = inactivity_timeout_seconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_name = self.client_name()
        check_type("client_name", client_name, Optional[str])
        if client_name:  # omit empty
            v["clientName"] = client_name
        expires_in = self.expires_in()
        check_type("expires_in", expires_in, Optional[int])
        if expires_in:  # omit empty
            v["expiresIn"] = expires_in
        scopes = self.scopes()
        check_type("scopes", scopes, Optional[List[str]])
        if scopes:  # omit empty
            v["scopes"] = scopes
        redirect_uri = self.redirect_uri()
        check_type("redirect_uri", redirect_uri, Optional[str])
        if redirect_uri:  # omit empty
            v["redirectURI"] = redirect_uri
        user_name = self.user_name()
        check_type("user_name", user_name, Optional[str])
        if user_name:  # omit empty
            v["userName"] = user_name
        user_uid = self.user_uid()
        check_type("user_uid", user_uid, Optional[str])
        if user_uid:  # omit empty
            v["userUID"] = user_uid
        authorize_token = self.authorize_token()
        check_type("authorize_token", authorize_token, Optional[str])
        if authorize_token:  # omit empty
            v["authorizeToken"] = authorize_token
        refresh_token = self.refresh_token()
        check_type("refresh_token", refresh_token, Optional[str])
        if refresh_token:  # omit empty
            v["refreshToken"] = refresh_token
        inactivity_timeout_seconds = self.inactivity_timeout_seconds()
        check_type(
            "inactivity_timeout_seconds", inactivity_timeout_seconds, Optional[int]
        )
        if inactivity_timeout_seconds:  # omit empty
            v["inactivityTimeoutSeconds"] = inactivity_timeout_seconds
        return v

    def client_name(self) -> Optional[str]:
        """
        ClientName references the client that created this token.
        """
        return self.__client_name

    def expires_in(self) -> Optional[int]:
        """
        ExpiresIn is the seconds from CreationTime before this token expires.
        """
        return self.__expires_in

    def scopes(self) -> Optional[List[str]]:
        """
        Scopes is an array of the requested scopes.
        """
        return self.__scopes

    def redirect_uri(self) -> Optional[str]:
        """
        RedirectURI is the redirection associated with the token.
        """
        return self.__redirect_uri

    def user_name(self) -> Optional[str]:
        """
        UserName is the user name associated with this token
        """
        return self.__user_name

    def user_uid(self) -> Optional[str]:
        """
        UserUID is the unique UID associated with this token
        """
        return self.__user_uid

    def authorize_token(self) -> Optional[str]:
        """
        AuthorizeToken contains the token that authorized this token
        """
        return self.__authorize_token

    def refresh_token(self) -> Optional[str]:
        """
        RefreshToken is the value by which this token can be renewed. Can be blank.
        """
        return self.__refresh_token

    def inactivity_timeout_seconds(self) -> Optional[int]:
        """
        InactivityTimeoutSeconds is the value in seconds, from the
        CreationTimestamp, after which this token can no longer be used.
        The value is automatically incremented when the token is used.
        """
        return self.__inactivity_timeout_seconds


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
        client_name: str = None,
        expires_in: int = None,
        scopes: List[str] = None,
        redirect_uri: str = None,
        state: str = None,
        user_name: str = None,
        user_uid: str = None,
        code_challenge: str = None,
        code_challenge_method: str = None,
    ):
        super().__init__(
            api_version="oauth.openshift.io/v1",
            kind="OAuthAuthorizeToken",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__client_name = client_name
        self.__expires_in = expires_in
        self.__scopes = scopes if scopes is not None else []
        self.__redirect_uri = redirect_uri
        self.__state = state
        self.__user_name = user_name
        self.__user_uid = user_uid
        self.__code_challenge = code_challenge
        self.__code_challenge_method = code_challenge_method

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_name = self.client_name()
        check_type("client_name", client_name, Optional[str])
        if client_name:  # omit empty
            v["clientName"] = client_name
        expires_in = self.expires_in()
        check_type("expires_in", expires_in, Optional[int])
        if expires_in:  # omit empty
            v["expiresIn"] = expires_in
        scopes = self.scopes()
        check_type("scopes", scopes, Optional[List[str]])
        if scopes:  # omit empty
            v["scopes"] = scopes
        redirect_uri = self.redirect_uri()
        check_type("redirect_uri", redirect_uri, Optional[str])
        if redirect_uri:  # omit empty
            v["redirectURI"] = redirect_uri
        state = self.state()
        check_type("state", state, Optional[str])
        if state:  # omit empty
            v["state"] = state
        user_name = self.user_name()
        check_type("user_name", user_name, Optional[str])
        if user_name:  # omit empty
            v["userName"] = user_name
        user_uid = self.user_uid()
        check_type("user_uid", user_uid, Optional[str])
        if user_uid:  # omit empty
            v["userUID"] = user_uid
        code_challenge = self.code_challenge()
        check_type("code_challenge", code_challenge, Optional[str])
        if code_challenge:  # omit empty
            v["codeChallenge"] = code_challenge
        code_challenge_method = self.code_challenge_method()
        check_type("code_challenge_method", code_challenge_method, Optional[str])
        if code_challenge_method:  # omit empty
            v["codeChallengeMethod"] = code_challenge_method
        return v

    def client_name(self) -> Optional[str]:
        """
        ClientName references the client that created this token.
        """
        return self.__client_name

    def expires_in(self) -> Optional[int]:
        """
        ExpiresIn is the seconds from CreationTime before this token expires.
        """
        return self.__expires_in

    def scopes(self) -> Optional[List[str]]:
        """
        Scopes is an array of the requested scopes.
        """
        return self.__scopes

    def redirect_uri(self) -> Optional[str]:
        """
        RedirectURI is the redirection associated with the token.
        """
        return self.__redirect_uri

    def state(self) -> Optional[str]:
        """
        State data from request
        """
        return self.__state

    def user_name(self) -> Optional[str]:
        """
        UserName is the user name associated with this token
        """
        return self.__user_name

    def user_uid(self) -> Optional[str]:
        """
        UserUID is the unique UID associated with this token. UserUID and UserName must both match
        for this token to be valid.
        """
        return self.__user_uid

    def code_challenge(self) -> Optional[str]:
        """
        CodeChallenge is the optional code_challenge associated with this authorization code, as described in rfc7636
        """
        return self.__code_challenge

    def code_challenge_method(self) -> Optional[str]:
        """
        CodeChallengeMethod is the optional code_challenge_method associated with this authorization code, as described in rfc7636
        """
        return self.__code_challenge_method


class ScopeRestriction(types.Object):
    """
    ScopeRestriction describe one restriction on scopes.  Exactly one option must be non-nil.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        literals: List[str] = None,
        cluster_role: "ClusterRoleScopeRestriction" = None,
    ):
        super().__init__()
        self.__literals = literals if literals is not None else []
        self.__cluster_role = cluster_role

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        literals = self.literals()
        check_type("literals", literals, Optional[List[str]])
        if literals:  # omit empty
            v["literals"] = literals
        cluster_role = self.cluster_role()
        check_type(
            "cluster_role", cluster_role, Optional["ClusterRoleScopeRestriction"]
        )
        if cluster_role is not None:  # omit empty
            v["clusterRole"] = cluster_role
        return v

    def literals(self) -> Optional[List[str]]:
        """
        ExactValues means the scope has to match a particular set of strings exactly
        """
        return self.__literals

    def cluster_role(self) -> Optional["ClusterRoleScopeRestriction"]:
        """
        ClusterRole describes a set of restrictions for cluster role scoping.
        """
        return self.__cluster_role


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
        additional_secrets: List[str] = None,
        respond_with_challenges: bool = None,
        redirect_uris: List[str] = None,
        grant_method: GrantHandlerType = None,
        scope_restrictions: List["ScopeRestriction"] = None,
        access_token_max_age_seconds: int = None,
        access_token_inactivity_timeout_seconds: int = None,
    ):
        super().__init__(
            api_version="oauth.openshift.io/v1",
            kind="OAuthClient",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__secret = secret
        self.__additional_secrets = (
            additional_secrets if additional_secrets is not None else []
        )
        self.__respond_with_challenges = respond_with_challenges
        self.__redirect_uris = redirect_uris if redirect_uris is not None else []
        self.__grant_method = grant_method
        self.__scope_restrictions = (
            scope_restrictions if scope_restrictions is not None else []
        )
        self.__access_token_max_age_seconds = access_token_max_age_seconds
        self.__access_token_inactivity_timeout_seconds = (
            access_token_inactivity_timeout_seconds
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secret = self.secret()
        check_type("secret", secret, Optional[str])
        if secret:  # omit empty
            v["secret"] = secret
        additional_secrets = self.additional_secrets()
        check_type("additional_secrets", additional_secrets, Optional[List[str]])
        if additional_secrets:  # omit empty
            v["additionalSecrets"] = additional_secrets
        respond_with_challenges = self.respond_with_challenges()
        check_type("respond_with_challenges", respond_with_challenges, Optional[bool])
        if respond_with_challenges:  # omit empty
            v["respondWithChallenges"] = respond_with_challenges
        redirect_uris = self.redirect_uris()
        check_type("redirect_uris", redirect_uris, Optional[List[str]])
        if redirect_uris:  # omit empty
            v["redirectURIs"] = redirect_uris
        grant_method = self.grant_method()
        check_type("grant_method", grant_method, Optional[GrantHandlerType])
        if grant_method:  # omit empty
            v["grantMethod"] = grant_method
        scope_restrictions = self.scope_restrictions()
        check_type(
            "scope_restrictions", scope_restrictions, Optional[List["ScopeRestriction"]]
        )
        if scope_restrictions:  # omit empty
            v["scopeRestrictions"] = scope_restrictions
        access_token_max_age_seconds = self.access_token_max_age_seconds()
        check_type(
            "access_token_max_age_seconds", access_token_max_age_seconds, Optional[int]
        )
        if access_token_max_age_seconds is not None:  # omit empty
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

    def secret(self) -> Optional[str]:
        """
        Secret is the unique secret associated with a client
        """
        return self.__secret

    def additional_secrets(self) -> Optional[List[str]]:
        """
        AdditionalSecrets holds other secrets that may be used to identify the client.  This is useful for rotation
        and for service account token validation
        """
        return self.__additional_secrets

    def respond_with_challenges(self) -> Optional[bool]:
        """
        RespondWithChallenges indicates whether the client wants authentication needed responses made in the form of challenges instead of redirects
        """
        return self.__respond_with_challenges

    def redirect_uris(self) -> Optional[List[str]]:
        """
        RedirectURIs is the valid redirection URIs associated with a client
        """
        return self.__redirect_uris

    def grant_method(self) -> Optional[GrantHandlerType]:
        """
        GrantMethod is a required field which determines how to handle grants for this client.
        Valid grant handling methods are:
         - auto:   always approves grant requests, useful for trusted clients
         - prompt: prompts the end user for approval of grant requests, useful for third-party clients
        """
        return self.__grant_method

    def scope_restrictions(self) -> Optional[List["ScopeRestriction"]]:
        """
        ScopeRestrictions describes which scopes this client can request.  Each requested scope
        is checked against each restriction.  If any restriction matches, then the scope is allowed.
        If no restriction matches, then the scope is denied.
        """
        return self.__scope_restrictions

    def access_token_max_age_seconds(self) -> Optional[int]:
        """
        AccessTokenMaxAgeSeconds overrides the default access token max age for tokens granted to this client.
        0 means no expiration.
        """
        return self.__access_token_max_age_seconds

    def access_token_inactivity_timeout_seconds(self) -> Optional[int]:
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
        return self.__access_token_inactivity_timeout_seconds


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
        client_name: str = None,
        user_name: str = None,
        user_uid: str = None,
        scopes: List[str] = None,
    ):
        super().__init__(
            api_version="oauth.openshift.io/v1",
            kind="OAuthClientAuthorization",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__client_name = client_name
        self.__user_name = user_name
        self.__user_uid = user_uid
        self.__scopes = scopes if scopes is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_name = self.client_name()
        check_type("client_name", client_name, Optional[str])
        if client_name:  # omit empty
            v["clientName"] = client_name
        user_name = self.user_name()
        check_type("user_name", user_name, Optional[str])
        if user_name:  # omit empty
            v["userName"] = user_name
        user_uid = self.user_uid()
        check_type("user_uid", user_uid, Optional[str])
        if user_uid:  # omit empty
            v["userUID"] = user_uid
        scopes = self.scopes()
        check_type("scopes", scopes, Optional[List[str]])
        if scopes:  # omit empty
            v["scopes"] = scopes
        return v

    def client_name(self) -> Optional[str]:
        """
        ClientName references the client that created this authorization
        """
        return self.__client_name

    def user_name(self) -> Optional[str]:
        """
        UserName is the user name that authorized this client
        """
        return self.__user_name

    def user_uid(self) -> Optional[str]:
        """
        UserUID is the unique UID associated with this authorization. UserUID and UserName
        must both match for this authorization to be valid.
        """
        return self.__user_uid

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
            api_version="oauth.openshift.io/v1",
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
