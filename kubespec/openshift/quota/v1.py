# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


class ClusterResourceQuotaSelector(types.Object):
    """
    ClusterResourceQuotaSelector is used to select projects.  At least one of LabelSelector or AnnotationSelector
    must present.  If only one is present, it is the only selection criteria.  If both are specified,
    the project must match both restrictions.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, labels: "metav1.LabelSelector" = None, annotations: Dict[str, str] = None
    ):
        super().__init__()
        self.__labels = labels
        self.__annotations = annotations if annotations is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        labels = self.labels()
        check_type("labels", labels, Optional["metav1.LabelSelector"])
        v["labels"] = labels
        annotations = self.annotations()
        check_type("annotations", annotations, Dict[str, str])
        v["annotations"] = annotations
        return v

    def labels(self) -> Optional["metav1.LabelSelector"]:
        """
        LabelSelector is used to select projects by label.
        +nullable
        """
        return self.__labels

    def annotations(self) -> Dict[str, str]:
        """
        AnnotationSelector is used to select projects by annotation.
        +nullable
        """
        return self.__annotations


class ClusterResourceQuotaSpec(types.Object):
    """
    ClusterResourceQuotaSpec defines the desired quota restrictions
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        selector: "ClusterResourceQuotaSelector" = None,
        quota: "k8sv1.ResourceQuotaSpec" = None,
    ):
        super().__init__()
        self.__selector = (
            selector if selector is not None else ClusterResourceQuotaSelector()
        )
        self.__quota = quota if quota is not None else k8sv1.ResourceQuotaSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        selector = self.selector()
        check_type("selector", selector, "ClusterResourceQuotaSelector")
        v["selector"] = selector
        quota = self.quota()
        check_type("quota", quota, "k8sv1.ResourceQuotaSpec")
        v["quota"] = quota
        return v

    def selector(self) -> "ClusterResourceQuotaSelector":
        """
        Selector is the selector used to match projects.
        It should only select active projects on the scale of dozens (though it can select
        many more less active projects).  These projects will contend on object creation through
        this resource.
        """
        return self.__selector

    def quota(self) -> "k8sv1.ResourceQuotaSpec":
        """
        Quota defines the desired quota
        """
        return self.__quota


class AppliedClusterResourceQuota(base.TypedObject, base.NamespacedMetadataObject):
    """
    AppliedClusterResourceQuota mirrors ClusterResourceQuota at a project scope, for projection
    into a project.  It allows a project-admin to know which ClusterResourceQuotas are applied to
    his project and their associated usage.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ClusterResourceQuotaSpec" = None,
    ):
        super().__init__(
            api_version="quota.openshift.io/v1",
            kind="AppliedClusterResourceQuota",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ClusterResourceQuotaSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ClusterResourceQuotaSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ClusterResourceQuotaSpec":
        """
        Spec defines the desired quota
        """
        return self.__spec


class ClusterResourceQuota(base.TypedObject, base.MetadataObject):
    """
    ClusterResourceQuota mirrors ResourceQuota at a cluster scope.  This object is easily convertible to
    synthetic ResourceQuota object to allow quota evaluation re-use.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ClusterResourceQuotaSpec" = None,
    ):
        super().__init__(
            api_version="quota.openshift.io/v1",
            kind="ClusterResourceQuota",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ClusterResourceQuotaSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ClusterResourceQuotaSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ClusterResourceQuotaSpec":
        """
        Spec defines the desired quota
        """
        return self.__spec
