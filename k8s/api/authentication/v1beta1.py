# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import List, Optional

import addict
from k8s import base
from korps import types
from typeguard import typechecked


# TokenReviewSpec is a description of the token authentication request.
class TokenReviewSpec(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
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
        return self._kwargs.get('token')
    
    # Audiences is a list of the identifiers that the resource server presented
    # with the token identifies as. Audience-aware token authenticators will
    # verify that the token was intended for at least one of the audiences in
    # this list. If no audiences are provided, the audience will default to the
    # audience of the Kubernetes apiserver.
    @typechecked
    def audiences(self) -> List[str]:
        return self._kwargs.get('audiences', [])


# TokenReview attempts to authenticate a token to a known user.
# Note: TokenReview requests may be cached by the webhook token authenticator
# plugin in the kube-apiserver.
class TokenReview(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'authentication.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'TokenReview'
    
    # Spec holds information about the request being evaluated
    @typechecked
    def spec(self) -> TokenReviewSpec:
        return self._kwargs.get('spec', TokenReviewSpec())
