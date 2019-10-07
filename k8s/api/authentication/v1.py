# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# BoundObjectReference is a reference to an object that a token is bound to.
class BoundObjectReference(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        kind = self.kind()
        if kind:  # omit empty
            v['kind'] = kind
        apiVersion = self.apiVersion()
        if apiVersion:  # omit empty
            v['apiVersion'] = apiVersion
        name = self.name()
        if name:  # omit empty
            v['name'] = name
        uid = self.uid()
        if uid:  # omit empty
            v['uid'] = uid
        return v
    
    # Kind of the referent. Valid kinds are 'Pod' and 'Secret'.
    @typechecked
    def kind(self) -> Optional[str]:
        if 'kind' in self._kwargs:
            return self._kwargs['kind']
        if 'kind' in self._context and check_return_type(self._context['kind']):
            return self._context['kind']
        return None
    
    # API version of the referent.
    @typechecked
    def apiVersion(self) -> Optional[str]:
        if 'apiVersion' in self._kwargs:
            return self._kwargs['apiVersion']
        if 'apiVersion' in self._context and check_return_type(self._context['apiVersion']):
            return self._context['apiVersion']
        return None
    
    # Name of the referent.
    @typechecked
    def name(self) -> Optional[str]:
        if 'name' in self._kwargs:
            return self._kwargs['name']
        if 'name' in self._context and check_return_type(self._context['name']):
            return self._context['name']
        return None
    
    # UID of the referent.
    @typechecked
    def uid(self) -> Optional[str]:
        if 'uid' in self._kwargs:
            return self._kwargs['uid']
        if 'uid' in self._context and check_return_type(self._context['uid']):
            return self._context['uid']
        return None


# TokenRequestSpec contains client provided parameters of a token request.
class TokenRequestSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['audiences'] = self.audiences()
        v['expirationSeconds'] = self.expirationSeconds()
        v['boundObjectRef'] = self.boundObjectRef()
        return v
    
    # Audiences are the intendend audiences of the token. A recipient of a
    # token must identitfy themself with an identifier in the list of
    # audiences of the token, and otherwise should reject the token. A
    # token issued for multiple audiences may be used to authenticate
    # against any of the audiences listed but implies a high degree of
    # trust between the target audiences.
    @typechecked
    def audiences(self) -> List[str]:
        if 'audiences' in self._kwargs:
            return self._kwargs['audiences']
        if 'audiences' in self._context and check_return_type(self._context['audiences']):
            return self._context['audiences']
        return []
    
    # ExpirationSeconds is the requested duration of validity of the request. The
    # token issuer may return a token with a different validity duration so a
    # client needs to check the 'expiration' field in a response.
    @typechecked
    def expirationSeconds(self) -> Optional[int]:
        if 'expirationSeconds' in self._kwargs:
            return self._kwargs['expirationSeconds']
        if 'expirationSeconds' in self._context and check_return_type(self._context['expirationSeconds']):
            return self._context['expirationSeconds']
        return 3600
    
    # BoundObjectRef is a reference to an object that the token will be bound to.
    # The token will only be valid for as long as the bound object exists.
    # NOTE: The API server's TokenReview endpoint will validate the
    # BoundObjectRef, but other audiences may not. Keep ExpirationSeconds
    # small if you want prompt revocation.
    @typechecked
    def boundObjectRef(self) -> Optional[BoundObjectReference]:
        if 'boundObjectRef' in self._kwargs:
            return self._kwargs['boundObjectRef']
        if 'boundObjectRef' in self._context and check_return_type(self._context['boundObjectRef']):
            return self._context['boundObjectRef']
        return None


# TokenRequest requests a token for a given service account.
class TokenRequest(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'authentication.k8s.io/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'TokenRequest'
    
    @typechecked
    def spec(self) -> TokenRequestSpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return TokenRequestSpec()


# TokenReviewSpec is a description of the token authentication request.
class TokenReviewSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        token = self.token()
        if token:  # omit empty
            v['token'] = token
        audiences = self.audiences()
        if audiences:  # omit empty
            v['audiences'] = audiences
        return v
    
    # Token is the opaque bearer token.
    @typechecked
    def token(self) -> Optional[str]:
        if 'token' in self._kwargs:
            return self._kwargs['token']
        if 'token' in self._context and check_return_type(self._context['token']):
            return self._context['token']
        return None
    
    # Audiences is a list of the identifiers that the resource server presented
    # with the token identifies as. Audience-aware token authenticators will
    # verify that the token was intended for at least one of the audiences in
    # this list. If no audiences are provided, the audience will default to the
    # audience of the Kubernetes apiserver.
    @typechecked
    def audiences(self) -> List[str]:
        if 'audiences' in self._kwargs:
            return self._kwargs['audiences']
        if 'audiences' in self._context and check_return_type(self._context['audiences']):
            return self._context['audiences']
        return []


# TokenReview attempts to authenticate a token to a known user.
# Note: TokenReview requests may be cached by the webhook token authenticator
# plugin in the kube-apiserver.
class TokenReview(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'authentication.k8s.io/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'TokenReview'
    
    # Spec holds information about the request being evaluated
    @typechecked
    def spec(self) -> TokenReviewSpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return TokenReviewSpec()


# UserInfo holds the information about the user needed to implement the
# user.Info interface.
class UserInfo(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        username = self.username()
        if username:  # omit empty
            v['username'] = username
        uid = self.uid()
        if uid:  # omit empty
            v['uid'] = uid
        groups = self.groups()
        if groups:  # omit empty
            v['groups'] = groups
        extra = self.extra()
        if extra:  # omit empty
            v['extra'] = extra
        return v
    
    # The name that uniquely identifies this user among all active users.
    @typechecked
    def username(self) -> Optional[str]:
        if 'username' in self._kwargs:
            return self._kwargs['username']
        if 'username' in self._context and check_return_type(self._context['username']):
            return self._context['username']
        return None
    
    # A unique value that identifies this user across time. If this user is
    # deleted and another user by the same name is added, they will have
    # different UIDs.
    @typechecked
    def uid(self) -> Optional[str]:
        if 'uid' in self._kwargs:
            return self._kwargs['uid']
        if 'uid' in self._context and check_return_type(self._context['uid']):
            return self._context['uid']
        return None
    
    # The names of groups this user is a part of.
    @typechecked
    def groups(self) -> List[str]:
        if 'groups' in self._kwargs:
            return self._kwargs['groups']
        if 'groups' in self._context and check_return_type(self._context['groups']):
            return self._context['groups']
        return []
    
    # Any additional information provided by the authenticator.
    @typechecked
    def extra(self) -> Dict[str, List[str]]:
        if 'extra' in self._kwargs:
            return self._kwargs['extra']
        if 'extra' in self._context and check_return_type(self._context['extra']):
            return self._context['extra']
        return {}
