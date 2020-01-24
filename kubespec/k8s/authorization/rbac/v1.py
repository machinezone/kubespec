# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


class AggregationRule(types.Object):
    """
    AggregationRule describes how to locate ClusterRoles to aggregate into the ClusterRole
    """

    @context.scoped
    @typechecked
    def __init__(self, cluster_role_selectors: List["metav1.LabelSelector"] = None):
        super().__init__()
        self.__cluster_role_selectors = (
            cluster_role_selectors if cluster_role_selectors is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cluster_role_selectors = self.cluster_role_selectors()
        check_type(
            "cluster_role_selectors",
            cluster_role_selectors,
            Optional[List["metav1.LabelSelector"]],
        )
        if cluster_role_selectors:  # omit empty
            v["clusterRoleSelectors"] = cluster_role_selectors
        return v

    def cluster_role_selectors(self) -> Optional[List["metav1.LabelSelector"]]:
        """
        ClusterRoleSelectors holds a list of selectors which will be used to find ClusterRoles and create the rules.
        If any of the selectors match, then the ClusterRole's permissions will be added
        """
        return self.__cluster_role_selectors


class PolicyRule(types.Object):
    """
    PolicyRule holds information that describes a policy rule, but does not contain information
    about who the rule applies to or which namespace the rule applies to.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        verbs: List[str] = None,
        api_groups: List[str] = None,
        resources: List[str] = None,
        resource_names: List[str] = None,
        non_resource_urls: List[str] = None,
    ):
        super().__init__()
        self.__verbs = verbs if verbs is not None else []
        self.__api_groups = api_groups if api_groups is not None else []
        self.__resources = resources if resources is not None else []
        self.__resource_names = resource_names if resource_names is not None else []
        self.__non_resource_urls = (
            non_resource_urls if non_resource_urls is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        verbs = self.verbs()
        check_type("verbs", verbs, List[str])
        v["verbs"] = verbs
        api_groups = self.api_groups()
        check_type("api_groups", api_groups, Optional[List[str]])
        if api_groups:  # omit empty
            v["apiGroups"] = api_groups
        resources = self.resources()
        check_type("resources", resources, Optional[List[str]])
        if resources:  # omit empty
            v["resources"] = resources
        resource_names = self.resource_names()
        check_type("resource_names", resource_names, Optional[List[str]])
        if resource_names:  # omit empty
            v["resourceNames"] = resource_names
        non_resource_urls = self.non_resource_urls()
        check_type("non_resource_urls", non_resource_urls, Optional[List[str]])
        if non_resource_urls:  # omit empty
            v["nonResourceURLs"] = non_resource_urls
        return v

    def verbs(self) -> List[str]:
        """
        Verbs is a list of Verbs that apply to ALL the ResourceKinds and AttributeRestrictions contained in this rule.  VerbAll represents all kinds.
        """
        return self.__verbs

    def api_groups(self) -> Optional[List[str]]:
        """
        APIGroups is the name of the APIGroup that contains the resources.  If multiple API groups are specified, any action requested against one of
        the enumerated resources in any API group will be allowed.
        """
        return self.__api_groups

    def resources(self) -> Optional[List[str]]:
        """
        Resources is a list of resources this rule applies to.  ResourceAll represents all resources.
        """
        return self.__resources

    def resource_names(self) -> Optional[List[str]]:
        """
        ResourceNames is an optional white list of names that the rule applies to.  An empty set means that everything is allowed.
        """
        return self.__resource_names

    def non_resource_urls(self) -> Optional[List[str]]:
        """
        NonResourceURLs is a set of partial urls that a user should have access to.  *s are allowed, but only as the full, final step in the path
        Since non-resource URLs are not namespaced, this field is only applicable for ClusterRoles referenced from a ClusterRoleBinding.
        Rules can either apply to API resources (such as "pods" or "secrets") or non-resource URL paths (such as "/api"),  but not both.
        """
        return self.__non_resource_urls


class ClusterRole(base.TypedObject, base.MetadataObject):
    """
    ClusterRole is a cluster level, logical grouping of PolicyRules that can be referenced as a unit by a RoleBinding or ClusterRoleBinding.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        rules: List["PolicyRule"] = None,
        aggregation_rule: "AggregationRule" = None,
    ):
        super().__init__(
            api_version="rbac.authorization.k8s.io/v1",
            kind="ClusterRole",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__rules = rules if rules is not None else []
        self.__aggregation_rule = aggregation_rule

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rules = self.rules()
        check_type("rules", rules, List["PolicyRule"])
        v["rules"] = rules
        aggregation_rule = self.aggregation_rule()
        check_type("aggregation_rule", aggregation_rule, Optional["AggregationRule"])
        if aggregation_rule is not None:  # omit empty
            v["aggregationRule"] = aggregation_rule
        return v

    def rules(self) -> List["PolicyRule"]:
        """
        Rules holds all the PolicyRules for this ClusterRole
        """
        return self.__rules

    def aggregation_rule(self) -> Optional["AggregationRule"]:
        """
        AggregationRule is an optional field that describes how to build the Rules for this ClusterRole.
        If AggregationRule is set, then the Rules are controller managed and direct changes to Rules will be
        stomped by the controller.
        """
        return self.__aggregation_rule


class RoleRef(types.Object):
    """
    RoleRef contains information that points to the role being used
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        api_group: str = "rbac.authorization.k8s.io",
        kind: str = "",
        name: str = "",
    ):
        super().__init__()
        self.__api_group = api_group
        self.__kind = kind
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        api_group = self.api_group()
        check_type("api_group", api_group, str)
        v["apiGroup"] = api_group
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def api_group(self) -> str:
        """
        APIGroup is the group for the resource being referenced
        """
        return self.__api_group

    def kind(self) -> str:
        """
        Kind is the type of resource being referenced
        """
        return self.__kind

    def name(self) -> str:
        """
        Name is the name of resource being referenced
        """
        return self.__name


class Subject(types.Object):
    """
    Subject contains a reference to the object or user identities a role binding applies to.  This can either hold a direct API object reference,
    or a value for non-objects such as user and group names.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        kind: str = "",
        api_group: str = None,
        name: str = "",
        namespace: str = None,
    ):
        super().__init__()
        self.__kind = kind
        self.__api_group = api_group
        self.__name = name
        self.__namespace = namespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        api_group = self.api_group()
        check_type("api_group", api_group, Optional[str])
        if api_group:  # omit empty
            v["apiGroup"] = api_group
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        return v

    def kind(self) -> str:
        """
        Kind of object being referenced. Values defined by this API group are "User", "Group", and "ServiceAccount".
        If the Authorizer does not recognized the kind value, the Authorizer should report an error.
        """
        return self.__kind

    def api_group(self) -> Optional[str]:
        """
        APIGroup holds the API group of the referenced subject.
        Defaults to "" for ServiceAccount subjects.
        Defaults to "rbac.authorization.k8s.io" for User and Group subjects.
        """
        return self.__api_group

    def name(self) -> str:
        """
        Name of the object being referenced.
        """
        return self.__name

    def namespace(self) -> Optional[str]:
        """
        Namespace of the referenced object.  If the object kind is non-namespace, such as "User" or "Group", and this value is not empty
        the Authorizer should report an error.
        """
        return self.__namespace


class ClusterRoleBinding(base.TypedObject, base.MetadataObject):
    """
    ClusterRoleBinding references a ClusterRole, but not contain it.  It can reference a ClusterRole in the global namespace,
    and adds who information via Subject.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        subjects: List["Subject"] = None,
        role_ref: "RoleRef" = None,
    ):
        super().__init__(
            api_version="rbac.authorization.k8s.io/v1",
            kind="ClusterRoleBinding",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__subjects = subjects if subjects is not None else []
        self.__role_ref = role_ref if role_ref is not None else RoleRef()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        subjects = self.subjects()
        check_type("subjects", subjects, Optional[List["Subject"]])
        if subjects:  # omit empty
            v["subjects"] = subjects
        role_ref = self.role_ref()
        check_type("role_ref", role_ref, "RoleRef")
        v["roleRef"] = role_ref
        return v

    def subjects(self) -> Optional[List["Subject"]]:
        """
        Subjects holds references to the objects the role applies to.
        """
        return self.__subjects

    def role_ref(self) -> "RoleRef":
        """
        RoleRef can only reference a ClusterRole in the global namespace.
        If the RoleRef cannot be resolved, the Authorizer must return an error.
        """
        return self.__role_ref


class Role(base.TypedObject, base.NamespacedMetadataObject):
    """
    Role is a namespaced, logical grouping of PolicyRules that can be referenced as a unit by a RoleBinding.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        rules: List["PolicyRule"] = None,
    ):
        super().__init__(
            api_version="rbac.authorization.k8s.io/v1",
            kind="Role",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__rules = rules if rules is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rules = self.rules()
        check_type("rules", rules, List["PolicyRule"])
        v["rules"] = rules
        return v

    def rules(self) -> List["PolicyRule"]:
        """
        Rules holds all the PolicyRules for this Role
        """
        return self.__rules


class RoleBinding(base.TypedObject, base.NamespacedMetadataObject):
    """
    RoleBinding references a role, but does not contain it.  It can reference a Role in the same namespace or a ClusterRole in the global namespace.
    It adds who information via Subjects and namespace information by which namespace it exists in.  RoleBindings in a given
    namespace only have effect in that namespace.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        subjects: List["Subject"] = None,
        role_ref: "RoleRef" = None,
    ):
        super().__init__(
            api_version="rbac.authorization.k8s.io/v1",
            kind="RoleBinding",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__subjects = subjects if subjects is not None else []
        self.__role_ref = role_ref if role_ref is not None else RoleRef()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        subjects = self.subjects()
        check_type("subjects", subjects, Optional[List["Subject"]])
        if subjects:  # omit empty
            v["subjects"] = subjects
        role_ref = self.role_ref()
        check_type("role_ref", role_ref, "RoleRef")
        v["roleRef"] = role_ref
        return v

    def subjects(self) -> Optional[List["Subject"]]:
        """
        Subjects holds references to the objects the role applies to.
        """
        return self.__subjects

    def role_ref(self) -> "RoleRef":
        """
        RoleRef can reference a Role in the current namespace or a ClusterRole in the global namespace.
        If the RoleRef cannot be resolved, the Authorizer must return an error.
        """
        return self.__role_ref
