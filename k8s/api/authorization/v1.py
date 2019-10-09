# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# NonResourceAttributes includes the authorization attributes available for non-resource requests to the Authorizer interface
class NonResourceAttributes(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        path = self.path()
        if path:  # omit empty
            v["path"] = path
        verb = self.verb()
        if verb:  # omit empty
            v["verb"] = verb
        return v

    # Path is the URL path of the request
    @typechecked
    def path(self) -> Optional[str]:
        if "path" in self._kwargs:
            return self._kwargs["path"]
        if "path" in self._context and check_return_type(self._context["path"]):
            return self._context["path"]
        return None

    # Verb is the standard HTTP verb
    @typechecked
    def verb(self) -> Optional[str]:
        if "verb" in self._kwargs:
            return self._kwargs["verb"]
        if "verb" in self._context and check_return_type(self._context["verb"]):
            return self._context["verb"]
        return None


# ResourceAttributes includes the authorization attributes available for resource requests to the Authorizer interface
class ResourceAttributes(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        namespace = self.namespace()
        if namespace:  # omit empty
            v["namespace"] = namespace
        verb = self.verb()
        if verb:  # omit empty
            v["verb"] = verb
        group = self.group()
        if group:  # omit empty
            v["group"] = group
        version = self.version()
        if version:  # omit empty
            v["version"] = version
        resource = self.resource()
        if resource:  # omit empty
            v["resource"] = resource
        subresource = self.subresource()
        if subresource:  # omit empty
            v["subresource"] = subresource
        name = self.name()
        if name:  # omit empty
            v["name"] = name
        return v

    # Namespace is the namespace of the action being requested.  Currently, there is no distinction between no namespace and all namespaces
    # "" (empty) is defaulted for LocalSubjectAccessReviews
    # "" (empty) is empty for cluster-scoped resources
    # "" (empty) means "all" for namespace scoped resources from a SubjectAccessReview or SelfSubjectAccessReview
    @typechecked
    def namespace(self) -> Optional[str]:
        if "namespace" in self._kwargs:
            return self._kwargs["namespace"]
        if "namespace" in self._context and check_return_type(
            self._context["namespace"]
        ):
            return self._context["namespace"]
        return None

    # Verb is a kubernetes resource API verb, like: get, list, watch, create, update, delete, proxy.  "*" means all.
    @typechecked
    def verb(self) -> Optional[str]:
        if "verb" in self._kwargs:
            return self._kwargs["verb"]
        if "verb" in self._context and check_return_type(self._context["verb"]):
            return self._context["verb"]
        return None

    # Group is the API Group of the Resource.  "*" means all.
    @typechecked
    def group(self) -> Optional[str]:
        if "group" in self._kwargs:
            return self._kwargs["group"]
        if "group" in self._context and check_return_type(self._context["group"]):
            return self._context["group"]
        return None

    # Version is the API Version of the Resource.  "*" means all.
    @typechecked
    def version(self) -> Optional[str]:
        if "version" in self._kwargs:
            return self._kwargs["version"]
        if "version" in self._context and check_return_type(self._context["version"]):
            return self._context["version"]
        return None

    # Resource is one of the existing resource types.  "*" means all.
    @typechecked
    def resource(self) -> Optional[str]:
        if "resource" in self._kwargs:
            return self._kwargs["resource"]
        if "resource" in self._context and check_return_type(self._context["resource"]):
            return self._context["resource"]
        return None

    # Subresource is one of the existing resource types.  "" means none.
    @typechecked
    def subresource(self) -> Optional[str]:
        if "subresource" in self._kwargs:
            return self._kwargs["subresource"]
        if "subresource" in self._context and check_return_type(
            self._context["subresource"]
        ):
            return self._context["subresource"]
        return None

    # Name is the name of the resource being requested for a "get" or deleted for a "delete". "" (empty) means all.
    @typechecked
    def name(self) -> Optional[str]:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return None


# SubjectAccessReviewSpec is a description of the access request.  Exactly one of ResourceAuthorizationAttributes
# and NonResourceAuthorizationAttributes must be set
class SubjectAccessReviewSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        resourceAttributes = self.resourceAttributes()
        if resourceAttributes is not None:  # omit empty
            v["resourceAttributes"] = resourceAttributes
        nonResourceAttributes = self.nonResourceAttributes()
        if nonResourceAttributes is not None:  # omit empty
            v["nonResourceAttributes"] = nonResourceAttributes
        user = self.user()
        if user:  # omit empty
            v["user"] = user
        groups = self.groups()
        if groups:  # omit empty
            v["groups"] = groups
        extra = self.extra()
        if extra:  # omit empty
            v["extra"] = extra
        uid = self.uid()
        if uid:  # omit empty
            v["uid"] = uid
        return v

    # ResourceAuthorizationAttributes describes information for a resource access request
    @typechecked
    def resourceAttributes(self) -> Optional[ResourceAttributes]:
        if "resourceAttributes" in self._kwargs:
            return self._kwargs["resourceAttributes"]
        if "resourceAttributes" in self._context and check_return_type(
            self._context["resourceAttributes"]
        ):
            return self._context["resourceAttributes"]
        return None

    # NonResourceAttributes describes information for a non-resource access request
    @typechecked
    def nonResourceAttributes(self) -> Optional[NonResourceAttributes]:
        if "nonResourceAttributes" in self._kwargs:
            return self._kwargs["nonResourceAttributes"]
        if "nonResourceAttributes" in self._context and check_return_type(
            self._context["nonResourceAttributes"]
        ):
            return self._context["nonResourceAttributes"]
        return None

    # User is the user you're testing for.
    # If you specify "User" but not "Groups", then is it interpreted as "What if User were not a member of any groups
    @typechecked
    def user(self) -> Optional[str]:
        if "user" in self._kwargs:
            return self._kwargs["user"]
        if "user" in self._context and check_return_type(self._context["user"]):
            return self._context["user"]
        return None

    # Groups is the groups you're testing for.
    @typechecked
    def groups(self) -> List[str]:
        if "groups" in self._kwargs:
            return self._kwargs["groups"]
        if "groups" in self._context and check_return_type(self._context["groups"]):
            return self._context["groups"]
        return []

    # Extra corresponds to the user.Info.GetExtra() method from the authenticator.  Since that is input to the authorizer
    # it needs a reflection here.
    @typechecked
    def extra(self) -> Dict[str, List[str]]:
        if "extra" in self._kwargs:
            return self._kwargs["extra"]
        if "extra" in self._context and check_return_type(self._context["extra"]):
            return self._context["extra"]
        return {}

    # UID information about the requesting user.
    @typechecked
    def uid(self) -> Optional[str]:
        if "uid" in self._kwargs:
            return self._kwargs["uid"]
        if "uid" in self._context and check_return_type(self._context["uid"]):
            return self._context["uid"]
        return None


# LocalSubjectAccessReview checks whether or not a user or group can perform an action in a given namespace.
# Having a namespace scoped resource makes it much easier to grant namespace scoped policy that includes permissions
# checking.
class LocalSubjectAccessReview(base.TypedObject, base.NamespacedMetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "authorization.k8s.io/v1"

    @typechecked
    def kind(self) -> str:
        return "LocalSubjectAccessReview"

    # Spec holds information about the request being evaluated.  spec.namespace must be equal to the namespace
    # you made the request against.  If empty, it is defaulted.
    @typechecked
    def spec(self) -> SubjectAccessReviewSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return SubjectAccessReviewSpec()


# SelfSubjectAccessReviewSpec is a description of the access request.  Exactly one of ResourceAuthorizationAttributes
# and NonResourceAuthorizationAttributes must be set
class SelfSubjectAccessReviewSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        resourceAttributes = self.resourceAttributes()
        if resourceAttributes is not None:  # omit empty
            v["resourceAttributes"] = resourceAttributes
        nonResourceAttributes = self.nonResourceAttributes()
        if nonResourceAttributes is not None:  # omit empty
            v["nonResourceAttributes"] = nonResourceAttributes
        return v

    # ResourceAuthorizationAttributes describes information for a resource access request
    @typechecked
    def resourceAttributes(self) -> Optional[ResourceAttributes]:
        if "resourceAttributes" in self._kwargs:
            return self._kwargs["resourceAttributes"]
        if "resourceAttributes" in self._context and check_return_type(
            self._context["resourceAttributes"]
        ):
            return self._context["resourceAttributes"]
        return None

    # NonResourceAttributes describes information for a non-resource access request
    @typechecked
    def nonResourceAttributes(self) -> Optional[NonResourceAttributes]:
        if "nonResourceAttributes" in self._kwargs:
            return self._kwargs["nonResourceAttributes"]
        if "nonResourceAttributes" in self._context and check_return_type(
            self._context["nonResourceAttributes"]
        ):
            return self._context["nonResourceAttributes"]
        return None


# SelfSubjectAccessReview checks whether or the current user can perform an action.  Not filling in a
# spec.namespace means "in all namespaces".  Self is a special case, because users should always be able
# to check whether they can perform an action
class SelfSubjectAccessReview(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "authorization.k8s.io/v1"

    @typechecked
    def kind(self) -> str:
        return "SelfSubjectAccessReview"

    # Spec holds information about the request being evaluated.  user and groups must be empty
    @typechecked
    def spec(self) -> SelfSubjectAccessReviewSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return SelfSubjectAccessReviewSpec()


class SelfSubjectRulesReviewSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        namespace = self.namespace()
        if namespace:  # omit empty
            v["namespace"] = namespace
        return v

    # Namespace to evaluate rules for. Required.
    @typechecked
    def namespace(self) -> Optional[str]:
        if "namespace" in self._kwargs:
            return self._kwargs["namespace"]
        if "namespace" in self._context and check_return_type(
            self._context["namespace"]
        ):
            return self._context["namespace"]
        return None


# SelfSubjectRulesReview enumerates the set of actions the current user can perform within a namespace.
# The returned list of actions may be incomplete depending on the server's authorization mode,
# and any errors experienced during the evaluation. SelfSubjectRulesReview should be used by UIs to show/hide actions,
# or to quickly let an end user reason about their permissions. It should NOT Be used by external systems to
# drive authorization decisions as this raises confused deputy, cache lifetime/revocation, and correctness concerns.
# SubjectAccessReview, and LocalAccessReview are the correct way to defer authorization decisions to the API server.
class SelfSubjectRulesReview(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "authorization.k8s.io/v1"

    @typechecked
    def kind(self) -> str:
        return "SelfSubjectRulesReview"

    # Spec holds information about the request being evaluated.
    @typechecked
    def spec(self) -> SelfSubjectRulesReviewSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return SelfSubjectRulesReviewSpec()


# SubjectAccessReview checks whether or not a user or group can perform an action.
class SubjectAccessReview(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "authorization.k8s.io/v1"

    @typechecked
    def kind(self) -> str:
        return "SubjectAccessReview"

    # Spec holds information about the request being evaluated
    @typechecked
    def spec(self) -> SubjectAccessReviewSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return SubjectAccessReviewSpec()
