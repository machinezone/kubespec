# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# NonResourceAttributes includes the authorization attributes available for non-resource requests to the Authorizer interface
class NonResourceAttributes(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, path: str = None, verb: str = None):
        super().__init__(**{})
        self.__path = path
        self.__verb = verb

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        verb = self.verb()
        check_type("verb", verb, Optional[str])
        if verb:  # omit empty
            v["verb"] = verb
        return v

    # Path is the URL path of the request
    def path(self) -> Optional[str]:
        return self.__path

    # Verb is the standard HTTP verb
    def verb(self) -> Optional[str]:
        return self.__verb


# ResourceAttributes includes the authorization attributes available for resource requests to the Authorizer interface
class ResourceAttributes(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        verb: str = None,
        group: str = None,
        version: str = None,
        resource: str = None,
        subresource: str = None,
        name: str = None,
    ):
        super().__init__(**{})
        self.__namespace = namespace
        self.__verb = verb
        self.__group = group
        self.__version = version
        self.__resource = resource
        self.__subresource = subresource
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        verb = self.verb()
        check_type("verb", verb, Optional[str])
        if verb:  # omit empty
            v["verb"] = verb
        group = self.group()
        check_type("group", group, Optional[str])
        if group:  # omit empty
            v["group"] = group
        version = self.version()
        check_type("version", version, Optional[str])
        if version:  # omit empty
            v["version"] = version
        resource = self.resource()
        check_type("resource", resource, Optional[str])
        if resource:  # omit empty
            v["resource"] = resource
        subresource = self.subresource()
        check_type("subresource", subresource, Optional[str])
        if subresource:  # omit empty
            v["subresource"] = subresource
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        return v

    # Namespace is the namespace of the action being requested.  Currently, there is no distinction between no namespace and all namespaces
    # "" (empty) is defaulted for LocalSubjectAccessReviews
    # "" (empty) is empty for cluster-scoped resources
    # "" (empty) means "all" for namespace scoped resources from a SubjectAccessReview or SelfSubjectAccessReview
    def namespace(self) -> Optional[str]:
        return self.__namespace

    # Verb is a kubernetes resource API verb, like: get, list, watch, create, update, delete, proxy.  "*" means all.
    def verb(self) -> Optional[str]:
        return self.__verb

    # Group is the API Group of the Resource.  "*" means all.
    def group(self) -> Optional[str]:
        return self.__group

    # Version is the API Version of the Resource.  "*" means all.
    def version(self) -> Optional[str]:
        return self.__version

    # Resource is one of the existing resource types.  "*" means all.
    def resource(self) -> Optional[str]:
        return self.__resource

    # Subresource is one of the existing resource types.  "" means none.
    def subresource(self) -> Optional[str]:
        return self.__subresource

    # Name is the name of the resource being requested for a "get" or deleted for a "delete". "" (empty) means all.
    def name(self) -> Optional[str]:
        return self.__name


# SubjectAccessReviewSpec is a description of the access request.  Exactly one of ResourceAuthorizationAttributes
# and NonResourceAuthorizationAttributes must be set
class SubjectAccessReviewSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        resourceAttributes: ResourceAttributes = None,
        nonResourceAttributes: NonResourceAttributes = None,
        user: str = None,
        group: List[str] = None,
        extra: Dict[str, List[str]] = None,
        uid: str = None,
    ):
        super().__init__(**{})
        self.__resourceAttributes = resourceAttributes
        self.__nonResourceAttributes = nonResourceAttributes
        self.__user = user
        self.__group = group if group is not None else []
        self.__extra = extra if extra is not None else {}
        self.__uid = uid

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        resourceAttributes = self.resourceAttributes()
        check_type(
            "resourceAttributes", resourceAttributes, Optional[ResourceAttributes]
        )
        if resourceAttributes is not None:  # omit empty
            v["resourceAttributes"] = resourceAttributes
        nonResourceAttributes = self.nonResourceAttributes()
        check_type(
            "nonResourceAttributes",
            nonResourceAttributes,
            Optional[NonResourceAttributes],
        )
        if nonResourceAttributes is not None:  # omit empty
            v["nonResourceAttributes"] = nonResourceAttributes
        user = self.user()
        check_type("user", user, Optional[str])
        if user:  # omit empty
            v["user"] = user
        group = self.group()
        check_type("group", group, Optional[List[str]])
        if group:  # omit empty
            v["group"] = group
        extra = self.extra()
        check_type("extra", extra, Optional[Dict[str, List[str]]])
        if extra:  # omit empty
            v["extra"] = extra
        uid = self.uid()
        check_type("uid", uid, Optional[str])
        if uid:  # omit empty
            v["uid"] = uid
        return v

    # ResourceAuthorizationAttributes describes information for a resource access request
    def resourceAttributes(self) -> Optional[ResourceAttributes]:
        return self.__resourceAttributes

    # NonResourceAttributes describes information for a non-resource access request
    def nonResourceAttributes(self) -> Optional[NonResourceAttributes]:
        return self.__nonResourceAttributes

    # User is the user you're testing for.
    # If you specify "User" but not "Group", then is it interpreted as "What if User were not a member of any groups
    def user(self) -> Optional[str]:
        return self.__user

    # Groups is the groups you're testing for.
    def group(self) -> Optional[List[str]]:
        return self.__group

    # Extra corresponds to the user.Info.GetExtra() method from the authenticator.  Since that is input to the authorizer
    # it needs a reflection here.
    def extra(self) -> Optional[Dict[str, List[str]]]:
        return self.__extra

    # UID information about the requesting user.
    def uid(self) -> Optional[str]:
        return self.__uid


# LocalSubjectAccessReview checks whether or not a user or group can perform an action in a given namespace.
# Having a namespace scoped resource makes it much easier to grant namespace scoped policy that includes permissions
# checking.
class LocalSubjectAccessReview(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: SubjectAccessReviewSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "authorization.k8s.io/v1beta1",
                "kind": "LocalSubjectAccessReview",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else SubjectAccessReviewSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, SubjectAccessReviewSpec)
        v["spec"] = spec
        return v

    # Spec holds information about the request being evaluated.  spec.namespace must be equal to the namespace
    # you made the request against.  If empty, it is defaulted.
    def spec(self) -> SubjectAccessReviewSpec:
        return self.__spec


# SelfSubjectAccessReviewSpec is a description of the access request.  Exactly one of ResourceAuthorizationAttributes
# and NonResourceAuthorizationAttributes must be set
class SelfSubjectAccessReviewSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        resourceAttributes: ResourceAttributes = None,
        nonResourceAttributes: NonResourceAttributes = None,
    ):
        super().__init__(**{})
        self.__resourceAttributes = resourceAttributes
        self.__nonResourceAttributes = nonResourceAttributes

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        resourceAttributes = self.resourceAttributes()
        check_type(
            "resourceAttributes", resourceAttributes, Optional[ResourceAttributes]
        )
        if resourceAttributes is not None:  # omit empty
            v["resourceAttributes"] = resourceAttributes
        nonResourceAttributes = self.nonResourceAttributes()
        check_type(
            "nonResourceAttributes",
            nonResourceAttributes,
            Optional[NonResourceAttributes],
        )
        if nonResourceAttributes is not None:  # omit empty
            v["nonResourceAttributes"] = nonResourceAttributes
        return v

    # ResourceAuthorizationAttributes describes information for a resource access request
    def resourceAttributes(self) -> Optional[ResourceAttributes]:
        return self.__resourceAttributes

    # NonResourceAttributes describes information for a non-resource access request
    def nonResourceAttributes(self) -> Optional[NonResourceAttributes]:
        return self.__nonResourceAttributes


# SelfSubjectAccessReview checks whether or the current user can perform an action.  Not filling in a
# spec.namespace means "in all namespaces".  Self is a special case, because users should always be able
# to check whether they can perform an action
class SelfSubjectAccessReview(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: SelfSubjectAccessReviewSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "authorization.k8s.io/v1beta1",
                "kind": "SelfSubjectAccessReview",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else SelfSubjectAccessReviewSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, SelfSubjectAccessReviewSpec)
        v["spec"] = spec
        return v

    # Spec holds information about the request being evaluated.  user and groups must be empty
    def spec(self) -> SelfSubjectAccessReviewSpec:
        return self.__spec


class SelfSubjectRulesReviewSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, namespace: str = None):
        super().__init__(**{})
        self.__namespace = namespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        return v

    # Namespace to evaluate rules for. Required.
    def namespace(self) -> Optional[str]:
        return self.__namespace


# SelfSubjectRulesReview enumerates the set of actions the current user can perform within a namespace.
# The returned list of actions may be incomplete depending on the server's authorization mode,
# and any errors experienced during the evaluation. SelfSubjectRulesReview should be used by UIs to show/hide actions,
# or to quickly let an end user reason about their permissions. It should NOT Be used by external systems to
# drive authorization decisions as this raises confused deputy, cache lifetime/revocation, and correctness concerns.
# SubjectAccessReview, and LocalAccessReview are the correct way to defer authorization decisions to the API server.
class SelfSubjectRulesReview(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: SelfSubjectRulesReviewSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "authorization.k8s.io/v1beta1",
                "kind": "SelfSubjectRulesReview",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else SelfSubjectRulesReviewSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, SelfSubjectRulesReviewSpec)
        v["spec"] = spec
        return v

    # Spec holds information about the request being evaluated.
    def spec(self) -> SelfSubjectRulesReviewSpec:
        return self.__spec


# SubjectAccessReview checks whether or not a user or group can perform an action.
class SubjectAccessReview(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: SubjectAccessReviewSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "authorization.k8s.io/v1beta1",
                "kind": "SubjectAccessReview",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else SubjectAccessReviewSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, SubjectAccessReviewSpec)
        v["spec"] = spec
        return v

    # Spec holds information about the request being evaluated
    def spec(self) -> SubjectAccessReviewSpec:
        return self.__spec
