# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s.core import v1 as corev1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


class ProjectSpec(types.Object):
    """
    ProjectSpec describes the attributes on a Project
    """

    @context.scoped
    @typechecked
    def __init__(self, finalizers: List[corev1.FinalizerName] = None):
        super().__init__()
        self.__finalizers = finalizers if finalizers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        finalizers = self.finalizers()
        check_type("finalizers", finalizers, Optional[List[corev1.FinalizerName]])
        if finalizers:  # omit empty
            v["finalizers"] = finalizers
        return v

    def finalizers(self) -> Optional[List[corev1.FinalizerName]]:
        """
        Finalizers is an opaque list of values that must be empty to permanently remove object from storage
        """
        return self.__finalizers


class Project(base.TypedObject, base.MetadataObject):
    """
    Projects are the unit of isolation and collaboration in OpenShift. A project has one or more members,
    a quota on the resources that the project may consume, and the security controls on the resources in
    the project. Within a project, members may have different roles - project administrators can set
    membership, editors can create and manage the resources, and viewers can see but not access running
    containers. In a normal cluster project administrators are not able to alter their quotas - that is
    restricted to cluster administrators.
    
    Listing or watching projects will return only projects the user has the reader role on.
    
    An OpenShift project is an alternative representation of a Kubernetes namespace. Projects are exposed
    as editable to end users while namespaces are not. Direct creation of a project is typically restricted
    to administrators, while end users should use the requestproject resource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ProjectSpec" = None,
    ):
        super().__init__(
            apiVersion="project.openshift.io/v1",
            kind="Project",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ProjectSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["ProjectSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["ProjectSpec"]:
        """
        Spec defines the behavior of the Namespace.
        """
        return self.__spec


class ProjectRequest(base.TypedObject, base.MetadataObject):
    """
    ProjecRequest is the set of options necessary to fully qualify a project request
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        displayName: str = None,
        description: str = None,
    ):
        super().__init__(
            apiVersion="project.openshift.io/v1",
            kind="ProjectRequest",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__displayName = displayName
        self.__description = description

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        displayName = self.displayName()
        check_type("displayName", displayName, Optional[str])
        if displayName:  # omit empty
            v["displayName"] = displayName
        description = self.description()
        check_type("description", description, Optional[str])
        if description:  # omit empty
            v["description"] = description
        return v

    def displayName(self) -> Optional[str]:
        """
        DisplayName is the display name to apply to a project
        """
        return self.__displayName

    def description(self) -> Optional[str]:
        """
        Description is the description to apply to a project
        """
        return self.__description
