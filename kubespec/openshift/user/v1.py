# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec.k8s import base
from kubespec.k8s.core import v1 as corev1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


class Group(base.TypedObject, base.MetadataObject):
    """
    Group represents a referenceable set of Users
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        users: List[str] = None,
    ):
        super().__init__(
            apiVersion="user.openshift.io/v1",
            kind="Group",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__users = users if users is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        users = self.users()
        check_type("users", users, List[str])
        v["users"] = users
        return v

    def users(self) -> List[str]:
        """
        Users is the list of users in this group.
        """
        return self.__users


class Identity(base.TypedObject, base.MetadataObject):
    """
    Identity records a successful authentication of a user with an identity provider. The
    information about the source of authentication is stored on the identity, and the identity
    is then associated with a single user object. Multiple identities can reference a single
    user. Information retrieved from the authentication provider is stored in the extra field
    using a schema determined by the provider.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        providerName: str = "",
        providerUserName: str = "",
        user: "corev1.ObjectReference" = None,
        extra: Dict[str, str] = None,
    ):
        super().__init__(
            apiVersion="user.openshift.io/v1",
            kind="Identity",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__providerName = providerName
        self.__providerUserName = providerUserName
        self.__user = user if user is not None else corev1.ObjectReference()
        self.__extra = extra if extra is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        providerName = self.providerName()
        check_type("providerName", providerName, str)
        v["providerName"] = providerName
        providerUserName = self.providerUserName()
        check_type("providerUserName", providerUserName, str)
        v["providerUserName"] = providerUserName
        user = self.user()
        check_type("user", user, "corev1.ObjectReference")
        v["user"] = user
        extra = self.extra()
        check_type("extra", extra, Optional[Dict[str, str]])
        if extra:  # omit empty
            v["extra"] = extra
        return v

    def providerName(self) -> str:
        """
        ProviderName is the source of identity information
        """
        return self.__providerName

    def providerUserName(self) -> str:
        """
        ProviderUserName uniquely represents this identity in the scope of the provider
        """
        return self.__providerUserName

    def user(self) -> "corev1.ObjectReference":
        """
        User is a reference to the user this identity is associated with
        Both Name and UID must be set
        """
        return self.__user

    def extra(self) -> Optional[Dict[str, str]]:
        """
        Extra holds extra information about this identity
        """
        return self.__extra


class User(base.TypedObject, base.MetadataObject):
    """
    Upon log in, every user of the system receives a User and Identity resource. Administrators
    may directly manipulate the attributes of the users for their own tracking, or set groups
    via the API. The user name is unique and is chosen based on the value provided by the
    identity provider - if a user already exists with the incoming name, the user name may have
    a number appended to it depending on the configuration of the system.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        fullName: str = None,
        identities: List[str] = None,
        groups: List[str] = None,
    ):
        super().__init__(
            apiVersion="user.openshift.io/v1",
            kind="User",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__fullName = fullName
        self.__identities = identities if identities is not None else []
        self.__groups = groups if groups is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        fullName = self.fullName()
        check_type("fullName", fullName, Optional[str])
        if fullName:  # omit empty
            v["fullName"] = fullName
        identities = self.identities()
        check_type("identities", identities, List[str])
        v["identities"] = identities
        groups = self.groups()
        check_type("groups", groups, List[str])
        v["groups"] = groups
        return v

    def fullName(self) -> Optional[str]:
        """
        FullName is the full name of user
        """
        return self.__fullName

    def identities(self) -> List[str]:
        """
        Identities are the identities associated with this user
        """
        return self.__identities

    def groups(self) -> List[str]:
        """
        Groups specifies group names this user is a member of.
        This field is deprecated and will be removed in a future release.
        Instead, create a Group object containing the name of this User.
        """
        return self.__groups


class UserIdentityMapping(base.TypedObject, base.MetadataObject):
    """
    UserIdentityMapping maps a user to an identity
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        identity: "corev1.ObjectReference" = None,
        user: "corev1.ObjectReference" = None,
    ):
        super().__init__(
            apiVersion="user.openshift.io/v1",
            kind="UserIdentityMapping",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__identity = identity if identity is not None else corev1.ObjectReference()
        self.__user = user if user is not None else corev1.ObjectReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        identity = self.identity()
        check_type("identity", identity, Optional["corev1.ObjectReference"])
        v["identity"] = identity
        user = self.user()
        check_type("user", user, Optional["corev1.ObjectReference"])
        v["user"] = user
        return v

    def identity(self) -> Optional["corev1.ObjectReference"]:
        """
        Identity is a reference to an identity
        """
        return self.__identity

    def user(self) -> Optional["corev1.ObjectReference"]:
        """
        User is a reference to a user
        """
        return self.__user
