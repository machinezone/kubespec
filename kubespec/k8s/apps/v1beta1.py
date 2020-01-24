# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional, Union


DeploymentStrategyType = base.Enum(
    "DeploymentStrategyType",
    {
        # Kill all existing pods before creating new ones.
        "Recreate": "Recreate",
        # Replace the old ReplicaSets by new one using rolling update i.e gradually scale down the old ReplicaSets and scale up the new one.
        "RollingUpdate": "RollingUpdate",
    },
)


# PodManagementPolicyType defines the policy for creating pods under a stateful set.
PodManagementPolicyType = base.Enum(
    "PodManagementPolicyType",
    {
        # OrderedReady will create pods in strictly increasing order on
        # scale up and strictly decreasing order on scale down, progressing only when
        # the previous pod is ready or terminated. At most one pod will be changed
        # at any time.
        "OrderedReady": "OrderedReady",
        # Parallel will create and delete pods as soon as the stateful set
        # replica count is changed, and will not wait for pods to be ready or complete
        # termination.
        "Parallel": "Parallel",
    },
)


# StatefulSetUpdateStrategyType is a string enumeration type that enumerates
# all possible update strategies for the StatefulSet controller.
StatefulSetUpdateStrategyType = base.Enum(
    "StatefulSetUpdateStrategyType",
    {
        # OnDelete triggers the legacy behavior. Version
        # tracking and ordered rolling restarts are disabled. Pods are recreated
        # from the StatefulSetSpec when they are manually deleted. When a scale
        # operation is performed with this strategy,specification version indicated
        # by the StatefulSet's currentRevision.
        "OnDelete": "OnDelete",
        # RollingUpdate indicates that update will be
        # applied to all Pods in the StatefulSet with respect to the StatefulSet
        # ordering constraints. When a scale operation is performed with this
        # strategy, new Pods will be created from the specification version indicated
        # by the StatefulSet's updateRevision.
        "RollingUpdate": "RollingUpdate",
    },
)


class ControllerRevision(base.TypedObject, base.NamespacedMetadataObject):
    """
    DEPRECATED - This group version of ControllerRevision is deprecated by apps/v1beta2/ControllerRevision. See the
    release notes for more information.
    ControllerRevision implements an immutable snapshot of state data. Clients
    are responsible for serializing and deserializing the objects that contain
    their internal state.
    Once a ControllerRevision has been successfully created, it can not be updated.
    The API Server will fail validation of all requests that attempt to mutate
    the Data field. ControllerRevisions may, however, be deleted. Note that, due to its use by both
    the DaemonSet and StatefulSet controllers for update and rollback, this object is beta. However,
    it may be subject to name and representation changes in future releases, and clients should not
    depend on its stability. It is primarily for internal use by controllers.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        data: "runtime.RawExtension" = None,
        revision: int = 0,
    ):
        super().__init__(
            api_version="apps/v1beta1",
            kind="ControllerRevision",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__data = data
        self.__revision = revision

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        data = self.data()
        check_type("data", data, Optional["runtime.RawExtension"])
        v["data"] = data
        revision = self.revision()
        check_type("revision", revision, int)
        v["revision"] = revision
        return v

    def data(self) -> Optional["runtime.RawExtension"]:
        """
        Data is the serialized representation of the state.
        """
        return self.__data

    def revision(self) -> int:
        """
        Revision indicates the revision of the state represented by Data.
        """
        return self.__revision


class RollingUpdateDeployment(types.Object):
    """
    Spec to control the desired behavior of rolling update.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, max_unavailable: Union[int, str] = None, max_surge: Union[int, str] = None
    ):
        super().__init__()
        self.__max_unavailable = (
            max_unavailable if max_unavailable is not None else "25%"
        )
        self.__max_surge = max_surge if max_surge is not None else "25%"

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        max_unavailable = self.max_unavailable()
        check_type("max_unavailable", max_unavailable, Optional[Union[int, str]])
        if max_unavailable is not None:  # omit empty
            v["maxUnavailable"] = max_unavailable
        max_surge = self.max_surge()
        check_type("max_surge", max_surge, Optional[Union[int, str]])
        if max_surge is not None:  # omit empty
            v["maxSurge"] = max_surge
        return v

    def max_unavailable(self) -> Optional[Union[int, str]]:
        """
        The maximum number of pods that can be unavailable during the update.
        Value can be an absolute number (ex: 5) or a percentage of desired pods (ex: 10%).
        Absolute number is calculated from percentage by rounding down.
        This can not be 0 if MaxSurge is 0.
        Defaults to 25%.
        Example: when this is set to 30%, the old ReplicaSet can be scaled down to 70% of desired pods
        immediately when the rolling update starts. Once new pods are ready, old ReplicaSet
        can be scaled down further, followed by scaling up the new ReplicaSet, ensuring
        that the total number of pods available at all times during the update is at
        least 70% of desired pods.
        """
        return self.__max_unavailable

    def max_surge(self) -> Optional[Union[int, str]]:
        """
        The maximum number of pods that can be scheduled above the desired number of
        pods.
        Value can be an absolute number (ex: 5) or a percentage of desired pods (ex: 10%).
        This can not be 0 if MaxUnavailable is 0.
        Absolute number is calculated from percentage by rounding up.
        Defaults to 25%.
        Example: when this is set to 30%, the new ReplicaSet can be scaled up immediately when
        the rolling update starts, such that the total number of old and new pods do not exceed
        130% of desired pods. Once old pods have been killed,
        new ReplicaSet can be scaled up further, ensuring that total number of pods running
        at any time during the update is at most 130% of desired pods.
        """
        return self.__max_surge


class DeploymentStrategy(types.Object):
    """
    DeploymentStrategy describes how to replace existing pods with new ones.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: DeploymentStrategyType = DeploymentStrategyType["RollingUpdate"],
        rolling_update: "RollingUpdateDeployment" = None,
    ):
        super().__init__()
        self.__type = type
        self.__rolling_update = (
            rolling_update if rolling_update is not None else RollingUpdateDeployment()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[DeploymentStrategyType])
        if type:  # omit empty
            v["type"] = type
        rolling_update = self.rolling_update()
        check_type(
            "rolling_update", rolling_update, Optional["RollingUpdateDeployment"]
        )
        if rolling_update is not None:  # omit empty
            v["rollingUpdate"] = rolling_update
        return v

    def type(self) -> Optional[DeploymentStrategyType]:
        """
        Type of deployment. Can be "Recreate" or "RollingUpdate". Default is RollingUpdate.
        """
        return self.__type

    def rolling_update(self) -> Optional["RollingUpdateDeployment"]:
        """
        Rolling update config params. Present only if DeploymentStrategyType =
        RollingUpdate.
        ---
        TODO: Update this to follow our convention for oneOf, whatever we decide it
        to be.
        """
        return self.__rolling_update


class DeploymentSpec(types.Object):
    """
    DeploymentSpec is the specification of the desired behavior of the Deployment.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        replicas: int = None,
        selector: "metav1.LabelSelector" = None,
        template: "k8sv1.PodTemplateSpec" = None,
        strategy: "DeploymentStrategy" = None,
        min_ready_seconds: int = None,
        revision_history_limit: int = None,
        paused: bool = None,
        progress_deadline_seconds: int = None,
    ):
        super().__init__()
        self.__replicas = replicas if replicas is not None else 1
        self.__selector = selector
        self.__template = template if template is not None else k8sv1.PodTemplateSpec()
        self.__strategy = strategy if strategy is not None else DeploymentStrategy()
        self.__min_ready_seconds = min_ready_seconds
        self.__revision_history_limit = (
            revision_history_limit if revision_history_limit is not None else 2
        )
        self.__paused = paused
        self.__progress_deadline_seconds = (
            progress_deadline_seconds if progress_deadline_seconds is not None else 600
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas is not None:  # omit empty
            v["replicas"] = replicas
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        template = self.template()
        check_type("template", template, "k8sv1.PodTemplateSpec")
        v["template"] = template
        strategy = self.strategy()
        check_type("strategy", strategy, Optional["DeploymentStrategy"])
        v["strategy"] = strategy
        min_ready_seconds = self.min_ready_seconds()
        check_type("min_ready_seconds", min_ready_seconds, Optional[int])
        if min_ready_seconds:  # omit empty
            v["minReadySeconds"] = min_ready_seconds
        revision_history_limit = self.revision_history_limit()
        check_type("revision_history_limit", revision_history_limit, Optional[int])
        if revision_history_limit is not None:  # omit empty
            v["revisionHistoryLimit"] = revision_history_limit
        paused = self.paused()
        check_type("paused", paused, Optional[bool])
        if paused:  # omit empty
            v["paused"] = paused
        progress_deadline_seconds = self.progress_deadline_seconds()
        check_type(
            "progress_deadline_seconds", progress_deadline_seconds, Optional[int]
        )
        if progress_deadline_seconds is not None:  # omit empty
            v["progressDeadlineSeconds"] = progress_deadline_seconds
        return v

    def replicas(self) -> Optional[int]:
        """
        Number of desired pods. This is a pointer to distinguish between explicit
        zero and not specified. Defaults to 1.
        """
        return self.__replicas

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        Label selector for pods. Existing ReplicaSets whose pods are
        selected by this will be the ones affected by this deployment.
        """
        return self.__selector

    def template(self) -> "k8sv1.PodTemplateSpec":
        """
        Template describes the pods that will be created.
        """
        return self.__template

    def strategy(self) -> Optional["DeploymentStrategy"]:
        """
        The deployment strategy to use to replace existing pods with new ones.
        """
        return self.__strategy

    def min_ready_seconds(self) -> Optional[int]:
        """
        Minimum number of seconds for which a newly created pod should be ready
        without any of its container crashing, for it to be considered available.
        Defaults to 0 (pod will be considered available as soon as it is ready)
        """
        return self.__min_ready_seconds

    def revision_history_limit(self) -> Optional[int]:
        """
        The number of old ReplicaSets to retain to allow rollback.
        This is a pointer to distinguish between explicit zero and not specified.
        Defaults to 2.
        """
        return self.__revision_history_limit

    def paused(self) -> Optional[bool]:
        """
        Indicates that the deployment is paused.
        """
        return self.__paused

    def progress_deadline_seconds(self) -> Optional[int]:
        """
        The maximum time in seconds for a deployment to make progress before it
        is considered to be failed. The deployment controller will continue to
        process failed deployments and a condition with a ProgressDeadlineExceeded
        reason will be surfaced in the deployment status. Note that progress will
        not be estimated during the time a deployment is paused. Defaults to 600s.
        """
        return self.__progress_deadline_seconds


class Deployment(base.TypedObject, base.NamespacedMetadataObject):
    """
    DEPRECATED - This group version of Deployment is deprecated by apps/v1beta2/Deployment. See the release notes for
    more information.
    Deployment enables declarative updates for Pods and ReplicaSets.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "DeploymentSpec" = None,
    ):
        super().__init__(
            api_version="apps/v1beta1",
            kind="Deployment",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else DeploymentSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["DeploymentSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["DeploymentSpec"]:
        """
        Specification of the desired behavior of the Deployment.
        """
        return self.__spec


class RollbackConfig(types.Object):
    """
    DEPRECATED.
    """

    @context.scoped
    @typechecked
    def __init__(self, revision: int = None):
        super().__init__()
        self.__revision = revision

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        revision = self.revision()
        check_type("revision", revision, Optional[int])
        if revision:  # omit empty
            v["revision"] = revision
        return v

    def revision(self) -> Optional[int]:
        """
        The revision to rollback to. If set to 0, rollback to the last revision.
        """
        return self.__revision


class DeploymentRollback(base.TypedObject):
    """
    DEPRECATED.
    DeploymentRollback stores the information required to rollback a deployment.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        updated_annotations: Dict[str, str] = None,
        rollback_to: "RollbackConfig" = None,
    ):
        super().__init__(api_version="apps/v1beta1", kind="DeploymentRollback")
        self.__name = name
        self.__updated_annotations = (
            updated_annotations if updated_annotations is not None else {}
        )
        self.__rollback_to = (
            rollback_to if rollback_to is not None else RollbackConfig()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        updated_annotations = self.updated_annotations()
        check_type("updated_annotations", updated_annotations, Optional[Dict[str, str]])
        if updated_annotations:  # omit empty
            v["updatedAnnotations"] = updated_annotations
        rollback_to = self.rollback_to()
        check_type("rollback_to", rollback_to, "RollbackConfig")
        v["rollbackTo"] = rollback_to
        return v

    def name(self) -> str:
        """
        Required: This must match the Name of a deployment.
        """
        return self.__name

    def updated_annotations(self) -> Optional[Dict[str, str]]:
        """
        The annotations to be updated to a deployment
        """
        return self.__updated_annotations

    def rollback_to(self) -> "RollbackConfig":
        """
        The config of this deployment rollback.
        """
        return self.__rollback_to


class RollingUpdateStatefulSetStrategy(types.Object):
    """
    RollingUpdateStatefulSetStrategy is used to communicate parameter for RollingUpdateStatefulSetStrategyType.
    """

    @context.scoped
    @typechecked
    def __init__(self, partition: int = None):
        super().__init__()
        self.__partition = partition

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        partition = self.partition()
        check_type("partition", partition, Optional[int])
        if partition is not None:  # omit empty
            v["partition"] = partition
        return v

    def partition(self) -> Optional[int]:
        """
        Partition indicates the ordinal at which the StatefulSet should be
        partitioned.
        """
        return self.__partition


class ScaleSpec(types.Object):
    """
    ScaleSpec describes the attributes of a scale subresource
    """

    @context.scoped
    @typechecked
    def __init__(self, replicas: int = None):
        super().__init__()
        self.__replicas = replicas

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas:  # omit empty
            v["replicas"] = replicas
        return v

    def replicas(self) -> Optional[int]:
        """
        desired number of instances for the scaled object.
        """
        return self.__replicas


class Scale(base.TypedObject, base.NamespacedMetadataObject):
    """
    Scale represents a scaling request for a resource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ScaleSpec" = None,
    ):
        super().__init__(
            api_version="apps/v1beta1",
            kind="Scale",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ScaleSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["ScaleSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["ScaleSpec"]:
        """
        defines the behavior of the scale. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        """
        return self.__spec


class StatefulSetUpdateStrategy(types.Object):
    """
    StatefulSetUpdateStrategy indicates the strategy that the StatefulSet
    controller will use to perform updates. It includes any additional parameters
    necessary to perform the update for the indicated strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: StatefulSetUpdateStrategyType = StatefulSetUpdateStrategyType["OnDelete"],
        rolling_update: "RollingUpdateStatefulSetStrategy" = None,
    ):
        super().__init__()
        self.__type = type
        self.__rolling_update = rolling_update

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[StatefulSetUpdateStrategyType])
        if type:  # omit empty
            v["type"] = type
        rolling_update = self.rolling_update()
        check_type(
            "rolling_update",
            rolling_update,
            Optional["RollingUpdateStatefulSetStrategy"],
        )
        if rolling_update is not None:  # omit empty
            v["rollingUpdate"] = rolling_update
        return v

    def type(self) -> Optional[StatefulSetUpdateStrategyType]:
        """
        Type indicates the type of the StatefulSetUpdateStrategy.
        """
        return self.__type

    def rolling_update(self) -> Optional["RollingUpdateStatefulSetStrategy"]:
        """
        RollingUpdate is used to communicate parameters when Type is RollingUpdateStatefulSetStrategyType.
        """
        return self.__rolling_update


class StatefulSetSpec(types.Object):
    """
    A StatefulSetSpec is the specification of a StatefulSet.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        replicas: int = None,
        selector: "metav1.LabelSelector" = None,
        template: "k8sv1.PodTemplateSpec" = None,
        volume_claim_templates: List["k8sv1.PersistentVolumeClaim"] = None,
        service_name: str = "",
        pod_management_policy: PodManagementPolicyType = PodManagementPolicyType[
            "OrderedReady"
        ],
        update_strategy: "StatefulSetUpdateStrategy" = None,
        revision_history_limit: int = None,
    ):
        super().__init__()
        self.__replicas = replicas if replicas is not None else 1
        self.__selector = selector
        self.__template = template if template is not None else k8sv1.PodTemplateSpec()
        self.__volume_claim_templates = (
            volume_claim_templates if volume_claim_templates is not None else []
        )
        self.__service_name = service_name
        self.__pod_management_policy = pod_management_policy
        self.__update_strategy = (
            update_strategy
            if update_strategy is not None
            else StatefulSetUpdateStrategy()
        )
        self.__revision_history_limit = (
            revision_history_limit if revision_history_limit is not None else 10
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas is not None:  # omit empty
            v["replicas"] = replicas
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        template = self.template()
        check_type("template", template, "k8sv1.PodTemplateSpec")
        v["template"] = template
        volume_claim_templates = self.volume_claim_templates()
        check_type(
            "volume_claim_templates",
            volume_claim_templates,
            Optional[List["k8sv1.PersistentVolumeClaim"]],
        )
        if volume_claim_templates:  # omit empty
            v["volumeClaimTemplates"] = volume_claim_templates
        service_name = self.service_name()
        check_type("service_name", service_name, str)
        v["serviceName"] = service_name
        pod_management_policy = self.pod_management_policy()
        check_type(
            "pod_management_policy",
            pod_management_policy,
            Optional[PodManagementPolicyType],
        )
        if pod_management_policy:  # omit empty
            v["podManagementPolicy"] = pod_management_policy
        update_strategy = self.update_strategy()
        check_type(
            "update_strategy", update_strategy, Optional["StatefulSetUpdateStrategy"]
        )
        v["updateStrategy"] = update_strategy
        revision_history_limit = self.revision_history_limit()
        check_type("revision_history_limit", revision_history_limit, Optional[int])
        if revision_history_limit is not None:  # omit empty
            v["revisionHistoryLimit"] = revision_history_limit
        return v

    def replicas(self) -> Optional[int]:
        """
        replicas is the desired number of replicas of the given Template.
        These are replicas in the sense that they are instantiations of the
        same Template, but individual replicas also have a consistent identity.
        If unspecified, defaults to 1.
        TODO: Consider a rename of this field.
        """
        return self.__replicas

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        selector is a label query over pods that should match the replica count.
        If empty, defaulted to labels on the pod template.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
        """
        return self.__selector

    def template(self) -> "k8sv1.PodTemplateSpec":
        """
        template is the object that describes the pod that will be created if
        insufficient replicas are detected. Each pod stamped out by the StatefulSet
        will fulfill this Template, but have a unique identity from the rest
        of the StatefulSet.
        """
        return self.__template

    def volume_claim_templates(self) -> Optional[List["k8sv1.PersistentVolumeClaim"]]:
        """
        volumeClaimTemplates is a list of claims that pods are allowed to reference.
        The StatefulSet controller is responsible for mapping network identities to
        claims in a way that maintains the identity of a pod. Every claim in
        this list must have at least one matching (by name) volumeMount in one
        container in the template. A claim in this list takes precedence over
        any volumes in the template, with the same name.
        TODO: Define the behavior if a claim already exists with the same name.
        """
        return self.__volume_claim_templates

    def service_name(self) -> str:
        """
        serviceName is the name of the service that governs this StatefulSet.
        This service must exist before the StatefulSet, and is responsible for
        the network identity of the set. Pods get DNS/hostnames that follow the
        pattern: pod-specific-string.serviceName.default.svc.cluster.local
        where "pod-specific-string" is managed by the StatefulSet controller.
        """
        return self.__service_name

    def pod_management_policy(self) -> Optional[PodManagementPolicyType]:
        """
        podManagementPolicy controls how pods are created during initial scale up,
        when replacing pods on nodes, or when scaling down. The default policy is
        `OrderedReady`, where pods are created in increasing order (pod-0, then
        pod-1, etc) and the controller will wait until each pod is ready before
        continuing. When scaling down, the pods are removed in the opposite order.
        The alternative policy is `Parallel` which will create pods in parallel
        to match the desired scale without waiting, and on scale down will delete
        all pods at once.
        """
        return self.__pod_management_policy

    def update_strategy(self) -> Optional["StatefulSetUpdateStrategy"]:
        """
        updateStrategy indicates the StatefulSetUpdateStrategy that will be
        employed to update Pods in the StatefulSet when a revision is made to
        Template.
        """
        return self.__update_strategy

    def revision_history_limit(self) -> Optional[int]:
        """
        revisionHistoryLimit is the maximum number of revisions that will
        be maintained in the StatefulSet's revision history. The revision history
        consists of all revisions not represented by a currently applied
        StatefulSetSpec version. The default value is 10.
        """
        return self.__revision_history_limit


class StatefulSet(base.TypedObject, base.NamespacedMetadataObject):
    """
    DEPRECATED - This group version of StatefulSet is deprecated by apps/v1beta2/StatefulSet. See the release notes for
    more information.
    StatefulSet represents a set of pods with consistent identities.
    Identities are defined as:
     - Network: A single stable DNS and hostname.
     - Storage: As many VolumeClaims as requested.
    The StatefulSet guarantees that a given network identity will always
    map to the same storage identity.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "StatefulSetSpec" = None,
    ):
        super().__init__(
            api_version="apps/v1beta1",
            kind="StatefulSet",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else StatefulSetSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["StatefulSetSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["StatefulSetSpec"]:
        """
        Spec defines the desired identities of pods in this set.
        """
        return self.__spec
