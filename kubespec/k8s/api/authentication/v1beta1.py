# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# TokenReviewSpec is a description of the token authentication request.
class TokenReviewSpec(types.Object):
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

    # Token is the opaque bearer token.
    def token(self) -> Optional[str]:
        return self.__token

    # Audiences is a list of the identifiers that the resource server presented
    # with the token identifies as. Audience-aware token authenticators will
    # verify that the token was intended for at least one of the audiences in
    # this list. If no audiences are provided, the audience will default to the
    # audience of the Kubernetes apiserver.
    def audiences(self) -> Optional[List[str]]:
        return self.__audiences


# TokenReview attempts to authenticate a token to a known user.
# Note: TokenReview requests may be cached by the webhook token authenticator
# plugin in the kube-apiserver.
class TokenReview(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: TokenReviewSpec = None,
    ):
        super().__init__(
            apiVersion="authentication.k8s.io/v1beta1",
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
        check_type("spec", spec, TokenReviewSpec)
        v["spec"] = spec
        return v

    # Spec holds information about the request being evaluated
    def spec(self) -> TokenReviewSpec:
        return self.__spec
