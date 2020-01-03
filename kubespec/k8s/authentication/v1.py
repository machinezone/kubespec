# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


class BoundObjectReference(types.Object):
    """
    BoundObjectReference is a reference to an object that a token is bound to.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        kind: str = None,
        apiVersion: str = None,
        name: str = None,
        uid: str = None,
    ):
        super().__init__()
        self.__kind = kind
        self.__apiVersion = apiVersion
        self.__name = name
        self.__uid = uid

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        check_type("kind", kind, Optional[str])
        if kind:  # omit empty
            v["kind"] = kind
        apiVersion = self.apiVersion()
        check_type("apiVersion", apiVersion, Optional[str])
        if apiVersion:  # omit empty
            v["apiVersion"] = apiVersion
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        uid = self.uid()
        check_type("uid", uid, Optional[str])
        if uid:  # omit empty
            v["uid"] = uid
        return v

    def kind(self) -> Optional[str]:
        """
        Kind of the referent. Valid kinds are 'Pod' and 'Secret'.
        """
        return self.__kind

    def apiVersion(self) -> Optional[str]:
        """
        API version of the referent.
        """
        return self.__apiVersion

    def name(self) -> Optional[str]:
        """
        Name of the referent.
        """
        return self.__name

    def uid(self) -> Optional[str]:
        """
        UID of the referent.
        """
        return self.__uid


class TokenRequestSpec(types.Object):
    """
    TokenRequestSpec contains client provided parameters of a token request.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        audiences: List[str] = None,
        expirationSeconds: int = None,
        boundObjectRef: "BoundObjectReference" = None,
    ):
        super().__init__()
        self.__audiences = audiences if audiences is not None else []
        self.__expirationSeconds = (
            expirationSeconds if expirationSeconds is not None else 3600
        )
        self.__boundObjectRef = boundObjectRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        audiences = self.audiences()
        check_type("audiences", audiences, List[str])
        v["audiences"] = audiences
        expirationSeconds = self.expirationSeconds()
        check_type("expirationSeconds", expirationSeconds, Optional[int])
        v["expirationSeconds"] = expirationSeconds
        boundObjectRef = self.boundObjectRef()
        check_type("boundObjectRef", boundObjectRef, Optional["BoundObjectReference"])
        v["boundObjectRef"] = boundObjectRef
        return v

    def audiences(self) -> List[str]:
        """
        Audiences are the intendend audiences of the token. A recipient of a
        token must identitfy themself with an identifier in the list of
        audiences of the token, and otherwise should reject the token. A
        token issued for multiple audiences may be used to authenticate
        against any of the audiences listed but implies a high degree of
        trust between the target audiences.
        """
        return self.__audiences

    def expirationSeconds(self) -> Optional[int]:
        """
        ExpirationSeconds is the requested duration of validity of the request. The
        token issuer may return a token with a different validity duration so a
        client needs to check the 'expiration' field in a response.
        """
        return self.__expirationSeconds

    def boundObjectRef(self) -> Optional["BoundObjectReference"]:
        """
        BoundObjectRef is a reference to an object that the token will be bound to.
        The token will only be valid for as long as the bound object exists.
        NOTE: The API server's TokenReview endpoint will validate the
        BoundObjectRef, but other audiences may not. Keep ExpirationSeconds
        small if you want prompt revocation.
        """
        return self.__boundObjectRef


class TokenRequest(base.TypedObject, base.NamespacedMetadataObject):
    """
    TokenRequest requests a token for a given service account.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "TokenRequestSpec" = None,
    ):
        super().__init__(
            apiVersion="authentication.k8s.io/v1",
            kind="TokenRequest",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else TokenRequestSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "TokenRequestSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "TokenRequestSpec":
        return self.__spec


class TokenReviewSpec(types.Object):
    """
    TokenReviewSpec is a description of the token authentication request.
    """

    @context.scoped
    @typechecked
    def __init__(self, token: str = None, audiences: List[str] = None):
        super().__init__()
        self.__token = token
        self.__audiences = audiences if audiences is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        token = self.token()
        check_type("token", token, Optional[str])
        if token:  # omit empty
            v["token"] = token
        audiences = self.audiences()
        check_type("audiences", audiences, Optional[List[str]])
        if audiences:  # omit empty
            v["audiences"] = audiences
        return v

    def token(self) -> Optional[str]:
        """
        Token is the opaque bearer token.
        """
        return self.__token

    def audiences(self) -> Optional[List[str]]:
        """
        Audiences is a list of the identifiers that the resource server presented
        with the token identifies as. Audience-aware token authenticators will
        verify that the token was intended for at least one of the audiences in
        this list. If no audiences are provided, the audience will default to the
        audience of the Kubernetes apiserver.
        """
        return self.__audiences


class TokenReview(base.TypedObject, base.MetadataObject):
    """
    TokenReview attempts to authenticate a token to a known user.
    Note: TokenReview requests may be cached by the webhook token authenticator
    plugin in the kube-apiserver.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "TokenReviewSpec" = None,
    ):
        super().__init__(
            apiVersion="authentication.k8s.io/v1",
            kind="TokenReview",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else TokenReviewSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "TokenReviewSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "TokenReviewSpec":
        """
        Spec holds information about the request being evaluated
        """
        return self.__spec


class UserInfo(types.Object):
    """
    UserInfo holds the information about the user needed to implement the
    user.Info interface.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        username: str = None,
        uid: str = None,
        groups: List[str] = None,
        extra: Dict[str, List[str]] = None,
    ):
        super().__init__()
        self.__username = username
        self.__uid = uid
        self.__groups = groups if groups is not None else []
        self.__extra = extra if extra is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        username = self.username()
        check_type("username", username, Optional[str])
        if username:  # omit empty
            v["username"] = username
        uid = self.uid()
        check_type("uid", uid, Optional[str])
        if uid:  # omit empty
            v["uid"] = uid
        groups = self.groups()
        check_type("groups", groups, Optional[List[str]])
        if groups:  # omit empty
            v["groups"] = groups
        extra = self.extra()
        check_type("extra", extra, Optional[Dict[str, List[str]]])
        if extra:  # omit empty
            v["extra"] = extra
        return v

    def username(self) -> Optional[str]:
        """
        The name that uniquely identifies this user among all active users.
        """
        return self.__username

    def uid(self) -> Optional[str]:
        """
        A unique value that identifies this user across time. If this user is
        deleted and another user by the same name is added, they will have
        different UIDs.
        """
        return self.__uid

    def groups(self) -> Optional[List[str]]:
        """
        The names of groups this user is a part of.
        """
        return self.__groups

    def extra(self) -> Optional[Dict[str, List[str]]]:
        """
        Any additional information provided by the authenticator.
        """
        return self.__extra
