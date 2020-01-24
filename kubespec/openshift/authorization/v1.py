# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.authorization.rbac import v1 as rbacv1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


class Action(types.Object):
    """
    Action describes a request to the API server
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = "",
        verb: str = "",
        resource_api_group: str = "",
        resource_api_version: str = "",
        resource: str = "",
        resource_name: str = "",
        path: str = "",
        is_non_resource_url: bool = False,
        content: "runtime.RawExtension" = None,
    ):
        super().__init__()
        self.__namespace = namespace
        self.__verb = verb
        self.__resource_api_group = resource_api_group
        self.__resource_api_version = resource_api_version
        self.__resource = resource
        self.__resource_name = resource_name
        self.__path = path
        self.__is_non_resource_url = is_non_resource_url
        self.__content = content

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, str)
        v["namespace"] = namespace
        verb = self.verb()
        check_type("verb", verb, str)
        v["verb"] = verb
        resource_api_group = self.resource_api_group()
        check_type("resource_api_group", resource_api_group, str)
        v["resourceAPIGroup"] = resource_api_group
        resource_api_version = self.resource_api_version()
        check_type("resource_api_version", resource_api_version, str)
        v["resourceAPIVersion"] = resource_api_version
        resource = self.resource()
        check_type("resource", resource, str)
        v["resource"] = resource
        resource_name = self.resource_name()
        check_type("resource_name", resource_name, str)
        v["resourceName"] = resource_name
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        is_non_resource_url = self.is_non_resource_url()
        check_type("is_non_resource_url", is_non_resource_url, bool)
        v["isNonResourceURL"] = is_non_resource_url
        content = self.content()
        check_type("content", content, Optional["runtime.RawExtension"])
        v["content"] = content
        return v

    def namespace(self) -> str:
        """
        Namespace is the namespace of the action being requested.  Currently, there is no distinction between no namespace and all namespaces
        """
        return self.__namespace

    def verb(self) -> str:
        """
        Verb is one of: get, list, watch, create, update, delete
        """
        return self.__verb

    def resource_api_group(self) -> str:
        """
        Group is the API group of the resource
        Serialized as resourceAPIGroup to avoid confusion with the 'groups' field when inlined
        """
        return self.__resource_api_group

    def resource_api_version(self) -> str:
        """
        Version is the API version of the resource
        Serialized as resourceAPIVersion to avoid confusion with TypeMeta.apiVersion and ObjectMeta.resourceVersion when inlined
        """
        return self.__resource_api_version

    def resource(self) -> str:
        """
        Resource is one of the existing resource types
        """
        return self.__resource

    def resource_name(self) -> str:
        """
        ResourceName is the name of the resource being requested for a "get" or deleted for a "delete"
        """
        return self.__resource_name

    def path(self) -> str:
        """
        Path is the path of a non resource URL
        """
        return self.__path

    def is_non_resource_url(self) -> bool:
        """
        IsNonResourceURL is true if this is a request for a non-resource URL (outside of the resource hierarchy)
        """
        return self.__is_non_resource_url

    def content(self) -> Optional["runtime.RawExtension"]:
        """
        Content is the actual content of the request for create and update
        """
        return self.__content


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
        attribute_restrictions: "runtime.RawExtension" = None,
        api_groups: List[str] = None,
        resources: List[str] = None,
        resource_names: List[str] = None,
        non_resource_urls: List[str] = None,
    ):
        super().__init__()
        self.__verbs = verbs if verbs is not None else []
        self.__attribute_restrictions = attribute_restrictions
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
        attribute_restrictions = self.attribute_restrictions()
        check_type(
            "attribute_restrictions",
            attribute_restrictions,
            Optional["runtime.RawExtension"],
        )
        v["attributeRestrictions"] = attribute_restrictions
        api_groups = self.api_groups()
        check_type("api_groups", api_groups, List[str])
        v["apiGroups"] = api_groups
        resources = self.resources()
        check_type("resources", resources, List[str])
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

    def attribute_restrictions(self) -> Optional["runtime.RawExtension"]:
        """
        AttributeRestrictions will vary depending on what the Authorizer/AuthorizationAttributeBuilder pair supports.
        If the Authorizer does not recognize how to handle the AttributeRestrictions, the Authorizer should report an error.
        """
        return self.__attribute_restrictions

    def api_groups(self) -> List[str]:
        """
        APIGroups is the name of the APIGroup that contains the resources.  If this field is empty, then both kubernetes and origin API groups are assumed.
        That means that if an action is requested against one of the enumerated resources in either the kubernetes or the origin API group, the request
        will be allowed
        """
        return self.__api_groups

    def resources(self) -> List[str]:
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
        NonResourceURLsSlice is a set of partial urls that a user should have access to.  *s are allowed, but only as the full, final step in the path
        This name is intentionally different than the internal type so that the DefaultConvert works nicely and because the ordering may be different.
        """
        return self.__non_resource_urls


class ClusterRole(base.TypedObject, base.MetadataObject):
    """
    ClusterRole is a logical grouping of PolicyRules that can be referenced as a unit by ClusterRoleBindings.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        rules: List["PolicyRule"] = None,
        aggregation_rule: "rbacv1.AggregationRule" = None,
    ):
        super().__init__(
            api_version="authorization.openshift.io/v1",
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
        check_type(
            "aggregation_rule", aggregation_rule, Optional["rbacv1.AggregationRule"]
        )
        if aggregation_rule is not None:  # omit empty
            v["aggregationRule"] = aggregation_rule
        return v

    def rules(self) -> List["PolicyRule"]:
        """
        Rules holds all the PolicyRules for this ClusterRole
        """
        return self.__rules

    def aggregation_rule(self) -> Optional["rbacv1.AggregationRule"]:
        """
        AggregationRule is an optional field that describes how to build the Rules for this ClusterRole.
        If AggregationRule is set, then the Rules are controller managed and direct changes to Rules will be
        stomped by the controller.
        """
        return self.__aggregation_rule


class ClusterRoleBinding(base.TypedObject, base.MetadataObject):
    """
    ClusterRoleBinding references a ClusterRole, but not contain it.  It can reference any ClusterRole in the same namespace or in the global namespace.
    It adds who information via (Users and Groups) OR Subjects and namespace information by which namespace it exists in.
    ClusterRoleBindings in a given namespace only have effect in that namespace (excepting the master namespace which has power in all namespaces).
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        user_names: List[str] = None,
        group_names: List[str] = None,
        subjects: List["k8sv1.ObjectReference"] = None,
        role_ref: "k8sv1.ObjectReference" = None,
    ):
        super().__init__(
            api_version="authorization.openshift.io/v1",
            kind="ClusterRoleBinding",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__user_names = user_names if user_names is not None else []
        self.__group_names = group_names if group_names is not None else []
        self.__subjects = subjects if subjects is not None else []
        self.__role_ref = role_ref if role_ref is not None else k8sv1.ObjectReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        user_names = self.user_names()
        check_type("user_names", user_names, List[str])
        v["userNames"] = user_names
        group_names = self.group_names()
        check_type("group_names", group_names, List[str])
        v["groupNames"] = group_names
        subjects = self.subjects()
        check_type("subjects", subjects, List["k8sv1.ObjectReference"])
        v["subjects"] = subjects
        role_ref = self.role_ref()
        check_type("role_ref", role_ref, "k8sv1.ObjectReference")
        v["roleRef"] = role_ref
        return v

    def user_names(self) -> List[str]:
        """
        UserNames holds all the usernames directly bound to the role.
        This field should only be specified when supporting legacy clients and servers.
        See Subjects for further details.
        """
        return self.__user_names

    def group_names(self) -> List[str]:
        """
        GroupNames holds all the groups directly bound to the role.
        This field should only be specified when supporting legacy clients and servers.
        See Subjects for further details.
        """
        return self.__group_names

    def subjects(self) -> List["k8sv1.ObjectReference"]:
        """
        Subjects hold object references to authorize with this rule.
        This field is ignored if UserNames or GroupNames are specified to support legacy clients and servers.
        Thus newer clients that do not need to support backwards compatibility should send
        only fully qualified Subjects and should omit the UserNames and GroupNames fields.
        Clients that need to support backwards compatibility can use this field to build the UserNames and GroupNames.
        """
        return self.__subjects

    def role_ref(self) -> "k8sv1.ObjectReference":
        """
        RoleRef can only reference the current namespace and the global namespace.
        If the ClusterRoleRef cannot be resolved, the Authorizer must return an error.
        Since Policy is a singleton, this is sufficient knowledge to locate a role.
        """
        return self.__role_ref


class GroupRestriction(types.Object):
    """
    GroupRestriction matches a group either by a string match on the group name
    or a label selector applied to group labels.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, groups: List[str] = None, labels: List["metav1.LabelSelector"] = None
    ):
        super().__init__()
        self.__groups = groups if groups is not None else []
        self.__labels = labels if labels is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        groups = self.groups()
        check_type("groups", groups, List[str])
        v["groups"] = groups
        labels = self.labels()
        check_type("labels", labels, List["metav1.LabelSelector"])
        v["labels"] = labels
        return v

    def groups(self) -> List[str]:
        """
        Groups is a list of groups used to match against an individual user's
        groups. If the user is a member of one of the whitelisted groups, the user
        is allowed to be bound to a role.
        +nullable
        """
        return self.__groups

    def labels(self) -> List["metav1.LabelSelector"]:
        """
        Selectors specifies a list of label selectors over group labels.
        +nullable
        """
        return self.__labels


class IsPersonalSubjectAccessReview(base.TypedObject):
    """
    IsPersonalSubjectAccessReview is a marker for PolicyRule.AttributeRestrictions that denotes that subjectaccessreviews on self should be allowed
    """

    @context.scoped
    @typechecked
    def __init__(self):
        super().__init__(
            api_version="authorization.openshift.io/v1",
            kind="IsPersonalSubjectAccessReview",
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        return v


class LocalResourceAccessReview(base.TypedObject):
    """
    LocalResourceAccessReview is a means to request a list of which users and groups are authorized to perform the action specified by spec in a particular namespace
    """

    @context.scoped
    @typechecked
    def __init__(self, action: "Action" = None):
        super().__init__(
            api_version="authorization.openshift.io/v1",
            kind="LocalResourceAccessReview",
        )
        self.__action = action if action is not None else Action()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        action = self.action()
        check_type("action", action, "Action")
        v.update(action._root())  # inline
        return v

    def action(self) -> "Action":
        """
        Action describes the action being tested.  The Namespace element is FORCED to the current namespace.
        """
        return self.__action


class LocalSubjectAccessReview(base.TypedObject):
    """
    LocalSubjectAccessReview is an object for requesting information about whether a user or group can perform an action in a particular namespace
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        action: "Action" = None,
        user: str = "",
        groups: List[str] = None,
        scopes: List[str] = None,
    ):
        super().__init__(
            api_version="authorization.openshift.io/v1", kind="LocalSubjectAccessReview"
        )
        self.__action = action if action is not None else Action()
        self.__user = user
        self.__groups = groups if groups is not None else []
        self.__scopes = scopes if scopes is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        action = self.action()
        check_type("action", action, "Action")
        v.update(action._root())  # inline
        user = self.user()
        check_type("user", user, str)
        v["user"] = user
        groups = self.groups()
        check_type("groups", groups, List[str])
        v["groups"] = groups
        scopes = self.scopes()
        check_type("scopes", scopes, List[str])
        v["scopes"] = scopes
        return v

    def action(self) -> "Action":
        """
        Action describes the action being tested.  The Namespace element is FORCED to the current namespace.
        """
        return self.__action

    def user(self) -> str:
        """
        User is optional.  If both User and Groups are empty, the current authenticated user is used.
        """
        return self.__user

    def groups(self) -> List[str]:
        """
        Groups is optional.  Groups is the list of groups to which the User belongs.
        """
        return self.__groups

    def scopes(self) -> List[str]:
        """
        Scopes to use for the evaluation.  Empty means "use the unscoped (full) permissions of the user/groups".
        Nil for a self-SAR, means "use the scopes on this request".
        Nil for a regular SAR, means the same as empty.
        """
        return self.__scopes


class ResourceAccessReview(base.TypedObject):
    """
    ResourceAccessReview is a means to request a list of which users and groups are authorized to perform the
    action specified by spec
    """

    @context.scoped
    @typechecked
    def __init__(self, action: "Action" = None):
        super().__init__(
            api_version="authorization.openshift.io/v1", kind="ResourceAccessReview"
        )
        self.__action = action if action is not None else Action()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        action = self.action()
        check_type("action", action, "Action")
        v.update(action._root())  # inline
        return v

    def action(self) -> "Action":
        """
        Action describes the action being tested.
        """
        return self.__action


class ResourceAccessReviewResponse(base.TypedObject):
    """
    ResourceAccessReviewResponse describes who can perform the action
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        users: List[str] = None,
        groups: List[str] = None,
        evalution_error: str = "",
    ):
        super().__init__(
            api_version="authorization.openshift.io/v1",
            kind="ResourceAccessReviewResponse",
        )
        self.__namespace = namespace
        self.__users = users if users is not None else []
        self.__groups = groups if groups is not None else []
        self.__evalution_error = evalution_error

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        users = self.users()
        check_type("users", users, List[str])
        v["users"] = users
        groups = self.groups()
        check_type("groups", groups, List[str])
        v["groups"] = groups
        evalution_error = self.evalution_error()
        check_type("evalution_error", evalution_error, str)
        v["evalutionError"] = evalution_error
        return v

    def namespace(self) -> Optional[str]:
        """
        Namespace is the namespace used for the access review
        """
        return self.__namespace

    def users(self) -> List[str]:
        """
        UsersSlice is the list of users who can perform the action
        """
        return self.__users

    def groups(self) -> List[str]:
        """
        GroupsSlice is the list of groups who can perform the action
        """
        return self.__groups

    def evalution_error(self) -> str:
        """
        EvaluationError is an indication that some error occurred during resolution, but partial results can still be returned.
        It is entirely possible to get an error and be able to continue determine authorization status in spite of it.  This is
        most common when a bound role is missing, but enough roles are still present and bound to reason about the request.
        """
        return self.__evalution_error


class Role(base.TypedObject, base.NamespacedMetadataObject):
    """
    Role is a logical grouping of PolicyRules that can be referenced as a unit by RoleBindings.
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
            api_version="authorization.openshift.io/v1",
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
    RoleBinding references a Role, but not contain it.  It can reference any Role in the same namespace or in the global namespace.
    It adds who information via (Users and Groups) OR Subjects and namespace information by which namespace it exists in.
    RoleBindings in a given namespace only have effect in that namespace (excepting the master namespace which has power in all namespaces).
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        user_names: List[str] = None,
        group_names: List[str] = None,
        subjects: List["k8sv1.ObjectReference"] = None,
        role_ref: "k8sv1.ObjectReference" = None,
    ):
        super().__init__(
            api_version="authorization.openshift.io/v1",
            kind="RoleBinding",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__user_names = user_names if user_names is not None else []
        self.__group_names = group_names if group_names is not None else []
        self.__subjects = subjects if subjects is not None else []
        self.__role_ref = role_ref if role_ref is not None else k8sv1.ObjectReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        user_names = self.user_names()
        check_type("user_names", user_names, List[str])
        v["userNames"] = user_names
        group_names = self.group_names()
        check_type("group_names", group_names, List[str])
        v["groupNames"] = group_names
        subjects = self.subjects()
        check_type("subjects", subjects, List["k8sv1.ObjectReference"])
        v["subjects"] = subjects
        role_ref = self.role_ref()
        check_type("role_ref", role_ref, "k8sv1.ObjectReference")
        v["roleRef"] = role_ref
        return v

    def user_names(self) -> List[str]:
        """
        UserNames holds all the usernames directly bound to the role.
        This field should only be specified when supporting legacy clients and servers.
        See Subjects for further details.
        """
        return self.__user_names

    def group_names(self) -> List[str]:
        """
        GroupNames holds all the groups directly bound to the role.
        This field should only be specified when supporting legacy clients and servers.
        See Subjects for further details.
        """
        return self.__group_names

    def subjects(self) -> List["k8sv1.ObjectReference"]:
        """
        Subjects hold object references to authorize with this rule.
        This field is ignored if UserNames or GroupNames are specified to support legacy clients and servers.
        Thus newer clients that do not need to support backwards compatibility should send
        only fully qualified Subjects and should omit the UserNames and GroupNames fields.
        Clients that need to support backwards compatibility can use this field to build the UserNames and GroupNames.
        """
        return self.__subjects

    def role_ref(self) -> "k8sv1.ObjectReference":
        """
        RoleRef can only reference the current namespace and the global namespace.
        If the RoleRef cannot be resolved, the Authorizer must return an error.
        Since Policy is a singleton, this is sufficient knowledge to locate a role.
        """
        return self.__role_ref


class ServiceAccountReference(types.Object):
    """
    ServiceAccountReference specifies a service account and namespace by their
    names.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", namespace: str = ""):
        super().__init__()
        self.__name = name
        self.__namespace = namespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        namespace = self.namespace()
        check_type("namespace", namespace, str)
        v["namespace"] = namespace
        return v

    def name(self) -> str:
        """
        Name is the name of the service account.
        """
        return self.__name

    def namespace(self) -> str:
        """
        Namespace is the namespace of the service account.  Service accounts from
        inside the whitelisted namespaces are allowed to be bound to roles.  If
        Namespace is empty, then the namespace of the RoleBindingRestriction in
        which the ServiceAccountReference is embedded is used.
        """
        return self.__namespace


class ServiceAccountRestriction(types.Object):
    """
    ServiceAccountRestriction matches a service account by a string match on
    either the service-account name or the name of the service account's
    namespace.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        serviceaccounts: List["ServiceAccountReference"] = None,
        namespaces: List[str] = None,
    ):
        super().__init__()
        self.__serviceaccounts = serviceaccounts if serviceaccounts is not None else []
        self.__namespaces = namespaces if namespaces is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        serviceaccounts = self.serviceaccounts()
        check_type("serviceaccounts", serviceaccounts, List["ServiceAccountReference"])
        v["serviceaccounts"] = serviceaccounts
        namespaces = self.namespaces()
        check_type("namespaces", namespaces, List[str])
        v["namespaces"] = namespaces
        return v

    def serviceaccounts(self) -> List["ServiceAccountReference"]:
        """
        ServiceAccounts specifies a list of literal service-account names.
        """
        return self.__serviceaccounts

    def namespaces(self) -> List[str]:
        """
        Namespaces specifies a list of literal namespace names.
        """
        return self.__namespaces


class UserRestriction(types.Object):
    """
    UserRestriction matches a user either by a string match on the user name,
    a string match on the name of a group to which the user belongs, or a label
    selector applied to the user labels.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        users: List[str] = None,
        groups: List[str] = None,
        labels: List["metav1.LabelSelector"] = None,
    ):
        super().__init__()
        self.__users = users if users is not None else []
        self.__groups = groups if groups is not None else []
        self.__labels = labels if labels is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        users = self.users()
        check_type("users", users, List[str])
        v["users"] = users
        groups = self.groups()
        check_type("groups", groups, List[str])
        v["groups"] = groups
        labels = self.labels()
        check_type("labels", labels, List["metav1.LabelSelector"])
        v["labels"] = labels
        return v

    def users(self) -> List[str]:
        """
        Users specifies a list of literal user names.
        """
        return self.__users

    def groups(self) -> List[str]:
        """
        Groups specifies a list of literal group names.
        +nullable
        """
        return self.__groups

    def labels(self) -> List["metav1.LabelSelector"]:
        """
        Selectors specifies a list of label selectors over user labels.
        +nullable
        """
        return self.__labels


class RoleBindingRestrictionSpec(types.Object):
    """
    RoleBindingRestrictionSpec defines a rolebinding restriction.  Exactly one
    field must be non-nil.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        userrestriction: "UserRestriction" = None,
        grouprestriction: "GroupRestriction" = None,
        serviceaccountrestriction: "ServiceAccountRestriction" = None,
    ):
        super().__init__()
        self.__userrestriction = userrestriction
        self.__grouprestriction = grouprestriction
        self.__serviceaccountrestriction = serviceaccountrestriction

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        userrestriction = self.userrestriction()
        check_type("userrestriction", userrestriction, Optional["UserRestriction"])
        v["userrestriction"] = userrestriction
        grouprestriction = self.grouprestriction()
        check_type("grouprestriction", grouprestriction, Optional["GroupRestriction"])
        v["grouprestriction"] = grouprestriction
        serviceaccountrestriction = self.serviceaccountrestriction()
        check_type(
            "serviceaccountrestriction",
            serviceaccountrestriction,
            Optional["ServiceAccountRestriction"],
        )
        v["serviceaccountrestriction"] = serviceaccountrestriction
        return v

    def userrestriction(self) -> Optional["UserRestriction"]:
        """
        UserRestriction matches against user subjects.
        +nullable
        """
        return self.__userrestriction

    def grouprestriction(self) -> Optional["GroupRestriction"]:
        """
        GroupRestriction matches against group subjects.
        +nullable
        """
        return self.__grouprestriction

    def serviceaccountrestriction(self) -> Optional["ServiceAccountRestriction"]:
        """
        ServiceAccountRestriction matches against service-account subjects.
        +nullable
        """
        return self.__serviceaccountrestriction


class RoleBindingRestriction(base.TypedObject, base.NamespacedMetadataObject):
    """
    RoleBindingRestriction is an object that can be matched against a subject
    (user, group, or service account) to determine whether rolebindings on that
    subject are allowed in the namespace to which the RoleBindingRestriction
    belongs.  If any one of those RoleBindingRestriction objects matches
    a subject, rolebindings on that subject in the namespace are allowed.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "RoleBindingRestrictionSpec" = None,
    ):
        super().__init__(
            api_version="authorization.openshift.io/v1",
            kind="RoleBindingRestriction",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else RoleBindingRestrictionSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "RoleBindingRestrictionSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "RoleBindingRestrictionSpec":
        """
        Spec defines the matcher.
        """
        return self.__spec


class SelfSubjectRulesReviewSpec(types.Object):
    """
    SelfSubjectRulesReviewSpec adds information about how to conduct the check
    """

    @context.scoped
    @typechecked
    def __init__(self, scopes: List[str] = None):
        super().__init__()
        self.__scopes = scopes if scopes is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        scopes = self.scopes()
        check_type("scopes", scopes, List[str])
        v["scopes"] = scopes
        return v

    def scopes(self) -> List[str]:
        """
        Scopes to use for the evaluation.  Empty means "use the unscoped (full) permissions of the user/groups".
        Nil means "use the scopes on this request".
        """
        return self.__scopes


class SelfSubjectRulesReview(base.TypedObject):
    """
    SelfSubjectRulesReview is a resource you can create to determine which actions you can perform in a namespace
    """

    @context.scoped
    @typechecked
    def __init__(self, spec: "SelfSubjectRulesReviewSpec" = None):
        super().__init__(
            api_version="authorization.openshift.io/v1", kind="SelfSubjectRulesReview"
        )
        self.__spec = spec if spec is not None else SelfSubjectRulesReviewSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "SelfSubjectRulesReviewSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "SelfSubjectRulesReviewSpec":
        """
        Spec adds information about how to conduct the check
        """
        return self.__spec


class SubjectAccessReview(base.TypedObject):
    """
    SubjectAccessReview is an object for requesting information about whether a user or group can perform an action
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        action: "Action" = None,
        user: str = "",
        groups: List[str] = None,
        scopes: List[str] = None,
    ):
        super().__init__(
            api_version="authorization.openshift.io/v1", kind="SubjectAccessReview"
        )
        self.__action = action if action is not None else Action()
        self.__user = user
        self.__groups = groups if groups is not None else []
        self.__scopes = scopes if scopes is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        action = self.action()
        check_type("action", action, "Action")
        v.update(action._root())  # inline
        user = self.user()
        check_type("user", user, str)
        v["user"] = user
        groups = self.groups()
        check_type("groups", groups, List[str])
        v["groups"] = groups
        scopes = self.scopes()
        check_type("scopes", scopes, List[str])
        v["scopes"] = scopes
        return v

    def action(self) -> "Action":
        """
        Action describes the action being tested.
        """
        return self.__action

    def user(self) -> str:
        """
        User is optional. If both User and Groups are empty, the current authenticated user is used.
        """
        return self.__user

    def groups(self) -> List[str]:
        """
        GroupsSlice is optional. Groups is the list of groups to which the User belongs.
        """
        return self.__groups

    def scopes(self) -> List[str]:
        """
        Scopes to use for the evaluation.  Empty means "use the unscoped (full) permissions of the user/groups".
        Nil for a self-SAR, means "use the scopes on this request".
        Nil for a regular SAR, means the same as empty.
        """
        return self.__scopes


class SubjectAccessReviewResponse(base.TypedObject):
    """
    SubjectAccessReviewResponse describes whether or not a user or group can perform an action
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        allowed: bool = False,
        reason: str = None,
        evaluation_error: str = None,
    ):
        super().__init__(
            api_version="authorization.openshift.io/v1",
            kind="SubjectAccessReviewResponse",
        )
        self.__namespace = namespace
        self.__allowed = allowed
        self.__reason = reason
        self.__evaluation_error = evaluation_error

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        allowed = self.allowed()
        check_type("allowed", allowed, bool)
        v["allowed"] = allowed
        reason = self.reason()
        check_type("reason", reason, Optional[str])
        if reason:  # omit empty
            v["reason"] = reason
        evaluation_error = self.evaluation_error()
        check_type("evaluation_error", evaluation_error, Optional[str])
        if evaluation_error:  # omit empty
            v["evaluationError"] = evaluation_error
        return v

    def namespace(self) -> Optional[str]:
        """
        Namespace is the namespace used for the access review
        """
        return self.__namespace

    def allowed(self) -> bool:
        """
        Allowed is required.  True if the action would be allowed, false otherwise.
        """
        return self.__allowed

    def reason(self) -> Optional[str]:
        """
        Reason is optional.  It indicates why a request was allowed or denied.
        """
        return self.__reason

    def evaluation_error(self) -> Optional[str]:
        """
        EvaluationError is an indication that some error occurred during the authorization check.
        It is entirely possible to get an error and be able to continue determine authorization status in spite of it.  This is
        most common when a bound role is missing, but enough roles are still present and bound to reason about the request.
        """
        return self.__evaluation_error


class SubjectRulesReviewSpec(types.Object):
    """
    SubjectRulesReviewSpec adds information about how to conduct the check
    """

    @context.scoped
    @typechecked
    def __init__(
        self, user: str = "", groups: List[str] = None, scopes: List[str] = None
    ):
        super().__init__()
        self.__user = user
        self.__groups = groups if groups is not None else []
        self.__scopes = scopes if scopes is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        user = self.user()
        check_type("user", user, str)
        v["user"] = user
        groups = self.groups()
        check_type("groups", groups, List[str])
        v["groups"] = groups
        scopes = self.scopes()
        check_type("scopes", scopes, List[str])
        v["scopes"] = scopes
        return v

    def user(self) -> str:
        """
        User is optional.  At least one of User and Groups must be specified.
        """
        return self.__user

    def groups(self) -> List[str]:
        """
        Groups is optional.  Groups is the list of groups to which the User belongs.  At least one of User and Groups must be specified.
        """
        return self.__groups

    def scopes(self) -> List[str]:
        """
        Scopes to use for the evaluation.  Empty means "use the unscoped (full) permissions of the user/groups".
        """
        return self.__scopes


class SubjectRulesReview(base.TypedObject):
    """
    SubjectRulesReview is a resource you can create to determine which actions another user can perform in a namespace
    """

    @context.scoped
    @typechecked
    def __init__(self, spec: "SubjectRulesReviewSpec" = None):
        super().__init__(
            api_version="authorization.openshift.io/v1", kind="SubjectRulesReview"
        )
        self.__spec = spec if spec is not None else SubjectRulesReviewSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "SubjectRulesReviewSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "SubjectRulesReviewSpec":
        """
        Spec adds information about how to conduct the check
        """
        return self.__spec
