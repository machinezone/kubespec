# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# AggregationRule describes how to locate ClusterRoles to aggregate into the ClusterRole
class AggregationRule(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        clusterRoleSelectors = self.clusterRoleSelectors()
        if clusterRoleSelectors:  # omit empty
            v['clusterRoleSelectors'] = clusterRoleSelectors
        return v
    
    # ClusterRoleSelectors holds a list of selectors which will be used to find ClusterRoles and create the rules.
    # If any of the selectors match, then the ClusterRole's permissions will be added
    @typechecked
    def clusterRoleSelectors(self) -> List['metav1.LabelSelector']:
        if 'clusterRoleSelectors' in self._kwargs:
            return self._kwargs['clusterRoleSelectors']
        if 'clusterRoleSelectors' in self._context and check_return_type(self._context['clusterRoleSelectors']):
            return self._context['clusterRoleSelectors']
        return []


# PolicyRule holds information that describes a policy rule, but does not contain information
# about who the rule applies to or which namespace the rule applies to.
class PolicyRule(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['verbs'] = self.verbs()
        apiGroups = self.apiGroups()
        if apiGroups:  # omit empty
            v['apiGroups'] = apiGroups
        resources = self.resources()
        if resources:  # omit empty
            v['resources'] = resources
        resourceNames = self.resourceNames()
        if resourceNames:  # omit empty
            v['resourceNames'] = resourceNames
        nonResourceURLs = self.nonResourceURLs()
        if nonResourceURLs:  # omit empty
            v['nonResourceURLs'] = nonResourceURLs
        return v
    
    # Verbs is a list of Verbs that apply to ALL the ResourceKinds and AttributeRestrictions contained in this rule.  VerbAll represents all kinds.
    @typechecked
    def verbs(self) -> List[str]:
        if 'verbs' in self._kwargs:
            return self._kwargs['verbs']
        if 'verbs' in self._context and check_return_type(self._context['verbs']):
            return self._context['verbs']
        return []
    
    # APIGroups is the name of the APIGroup that contains the resources.  If multiple API groups are specified, any action requested against one of
    # the enumerated resources in any API group will be allowed.
    @typechecked
    def apiGroups(self) -> List[str]:
        if 'apiGroups' in self._kwargs:
            return self._kwargs['apiGroups']
        if 'apiGroups' in self._context and check_return_type(self._context['apiGroups']):
            return self._context['apiGroups']
        return []
    
    # Resources is a list of resources this rule applies to.  ResourceAll represents all resources.
    @typechecked
    def resources(self) -> List[str]:
        if 'resources' in self._kwargs:
            return self._kwargs['resources']
        if 'resources' in self._context and check_return_type(self._context['resources']):
            return self._context['resources']
        return []
    
    # ResourceNames is an optional white list of names that the rule applies to.  An empty set means that everything is allowed.
    @typechecked
    def resourceNames(self) -> List[str]:
        if 'resourceNames' in self._kwargs:
            return self._kwargs['resourceNames']
        if 'resourceNames' in self._context and check_return_type(self._context['resourceNames']):
            return self._context['resourceNames']
        return []
    
    # NonResourceURLs is a set of partial urls that a user should have access to.  *s are allowed, but only as the full, final step in the path
    # Since non-resource URLs are not namespaced, this field is only applicable for ClusterRoles referenced from a ClusterRoleBinding.
    # Rules can either apply to API resources (such as "pods" or "secrets") or non-resource URL paths (such as "/api"),  but not both.
    @typechecked
    def nonResourceURLs(self) -> List[str]:
        if 'nonResourceURLs' in self._kwargs:
            return self._kwargs['nonResourceURLs']
        if 'nonResourceURLs' in self._context and check_return_type(self._context['nonResourceURLs']):
            return self._context['nonResourceURLs']
        return []


# ClusterRole is a cluster level, logical grouping of PolicyRules that can be referenced as a unit by a RoleBinding or ClusterRoleBinding.
class ClusterRole(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['rules'] = self.rules()
        aggregationRule = self.aggregationRule()
        if aggregationRule is not None:  # omit empty
            v['aggregationRule'] = aggregationRule
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'rbac.authorization.k8s.io/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'ClusterRole'
    
    # Rules holds all the PolicyRules for this ClusterRole
    @typechecked
    def rules(self) -> List[PolicyRule]:
        if 'rules' in self._kwargs:
            return self._kwargs['rules']
        if 'rules' in self._context and check_return_type(self._context['rules']):
            return self._context['rules']
        return []
    
    # AggregationRule is an optional field that describes how to build the Rules for this ClusterRole.
    # If AggregationRule is set, then the Rules are controller managed and direct changes to Rules will be
    # stomped by the controller.
    @typechecked
    def aggregationRule(self) -> Optional[AggregationRule]:
        if 'aggregationRule' in self._kwargs:
            return self._kwargs['aggregationRule']
        if 'aggregationRule' in self._context and check_return_type(self._context['aggregationRule']):
            return self._context['aggregationRule']
        return None


# RoleRef contains information that points to the role being used
class RoleRef(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['apiGroup'] = self.apiGroup()
        v['kind'] = self.kind()
        v['name'] = self.name()
        return v
    
    # APIGroup is the group for the resource being referenced
    @typechecked
    def apiGroup(self) -> str:
        if 'apiGroup' in self._kwargs:
            return self._kwargs['apiGroup']
        if 'apiGroup' in self._context and check_return_type(self._context['apiGroup']):
            return self._context['apiGroup']
        return 'rbac.authorization.k8s.io'
    
    # Kind is the type of resource being referenced
    @typechecked
    def kind(self) -> str:
        if 'kind' in self._kwargs:
            return self._kwargs['kind']
        if 'kind' in self._context and check_return_type(self._context['kind']):
            return self._context['kind']
        return ''
    
    # Name is the name of resource being referenced
    @typechecked
    def name(self) -> str:
        if 'name' in self._kwargs:
            return self._kwargs['name']
        if 'name' in self._context and check_return_type(self._context['name']):
            return self._context['name']
        return ''


# Subject contains a reference to the object or user identities a role binding applies to.  This can either hold a direct API object reference,
# or a value for non-objects such as user and group names.
class Subject(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['kind'] = self.kind()
        apiGroup = self.apiGroup()
        if apiGroup:  # omit empty
            v['apiGroup'] = apiGroup
        v['name'] = self.name()
        namespace = self.namespace()
        if namespace:  # omit empty
            v['namespace'] = namespace
        return v
    
    # Kind of object being referenced. Values defined by this API group are "User", "Group", and "ServiceAccount".
    # If the Authorizer does not recognized the kind value, the Authorizer should report an error.
    @typechecked
    def kind(self) -> str:
        if 'kind' in self._kwargs:
            return self._kwargs['kind']
        if 'kind' in self._context and check_return_type(self._context['kind']):
            return self._context['kind']
        return ''
    
    # APIGroup holds the API group of the referenced subject.
    # Defaults to "" for ServiceAccount subjects.
    # Defaults to "rbac.authorization.k8s.io" for User and Group subjects.
    @typechecked
    def apiGroup(self) -> Optional[str]:
        if 'apiGroup' in self._kwargs:
            return self._kwargs['apiGroup']
        if 'apiGroup' in self._context and check_return_type(self._context['apiGroup']):
            return self._context['apiGroup']
        return None
    
    # Name of the object being referenced.
    @typechecked
    def name(self) -> str:
        if 'name' in self._kwargs:
            return self._kwargs['name']
        if 'name' in self._context and check_return_type(self._context['name']):
            return self._context['name']
        return ''
    
    # Namespace of the referenced object.  If the object kind is non-namespace, such as "User" or "Group", and this value is not empty
    # the Authorizer should report an error.
    @typechecked
    def namespace(self) -> Optional[str]:
        if 'namespace' in self._kwargs:
            return self._kwargs['namespace']
        if 'namespace' in self._context and check_return_type(self._context['namespace']):
            return self._context['namespace']
        return None


# ClusterRoleBinding references a ClusterRole, but not contain it.  It can reference a ClusterRole in the global namespace,
# and adds who information via Subject.
class ClusterRoleBinding(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        subjects = self.subjects()
        if subjects:  # omit empty
            v['subjects'] = subjects.values()  # named list
        v['roleRef'] = self.roleRef()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'rbac.authorization.k8s.io/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'ClusterRoleBinding'
    
    # Subjects holds references to the objects the role applies to.
    @typechecked
    def subjects(self) -> Dict[str, Subject]:
        if 'subjects' in self._kwargs:
            return self._kwargs['subjects']
        if 'subjects' in self._context and check_return_type(self._context['subjects']):
            return self._context['subjects']
        return {}
    
    # RoleRef can only reference a ClusterRole in the global namespace.
    # If the RoleRef cannot be resolved, the Authorizer must return an error.
    @typechecked
    def roleRef(self) -> RoleRef:
        if 'roleRef' in self._kwargs:
            return self._kwargs['roleRef']
        if 'roleRef' in self._context and check_return_type(self._context['roleRef']):
            return self._context['roleRef']
        with context.Scope(**self._context):
            return RoleRef()


# Role is a namespaced, logical grouping of PolicyRules that can be referenced as a unit by a RoleBinding.
class Role(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['rules'] = self.rules()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'rbac.authorization.k8s.io/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'Role'
    
    # Rules holds all the PolicyRules for this Role
    @typechecked
    def rules(self) -> List[PolicyRule]:
        if 'rules' in self._kwargs:
            return self._kwargs['rules']
        if 'rules' in self._context and check_return_type(self._context['rules']):
            return self._context['rules']
        return []


# RoleBinding references a role, but does not contain it.  It can reference a Role in the same namespace or a ClusterRole in the global namespace.
# It adds who information via Subjects and namespace information by which namespace it exists in.  RoleBindings in a given
# namespace only have effect in that namespace.
class RoleBinding(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        subjects = self.subjects()
        if subjects:  # omit empty
            v['subjects'] = subjects.values()  # named list
        v['roleRef'] = self.roleRef()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'rbac.authorization.k8s.io/v1'
    
    @typechecked
    def kind(self) -> str:
        return 'RoleBinding'
    
    # Subjects holds references to the objects the role applies to.
    @typechecked
    def subjects(self) -> Dict[str, Subject]:
        if 'subjects' in self._kwargs:
            return self._kwargs['subjects']
        if 'subjects' in self._context and check_return_type(self._context['subjects']):
            return self._context['subjects']
        return {}
    
    # RoleRef can reference a Role in the current namespace or a ClusterRole in the global namespace.
    # If the RoleRef cannot be resolved, the Authorizer must return an error.
    @typechecked
    def roleRef(self) -> RoleRef:
        if 'roleRef' in self._kwargs:
            return self._kwargs['roleRef']
        if 'roleRef' in self._context and check_return_type(self._context['roleRef']):
            return self._context['roleRef']
        with context.Scope(**self._context):
            return RoleRef()
