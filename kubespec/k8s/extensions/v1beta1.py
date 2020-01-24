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
from typing import Any, Dict, List, Optional, Union


DaemonSetUpdateStrategyType = base.Enum(
    "DaemonSetUpdateStrategyType",
    {
        # Replace the old daemons only when it's killed
        "OnDelete": "OnDelete",
        # Replace the old daemons by new ones using rolling update i.e replace them on each node one after the other.
        "RollingUpdate": "RollingUpdate",
    },
)


DeploymentStrategyType = base.Enum(
    "DeploymentStrategyType",
    {
        # Kill all existing pods before creating new ones.
        "Recreate": "Recreate",
        # Replace the old RCs by new one using rolling update i.e gradually scale down the old RCs and scale up the new one.
        "RollingUpdate": "RollingUpdate",
    },
)


# FSGroupStrategyType denotes strategy types for generating FSGroup values for a
# SecurityContext
# Deprecated: use FSGroupStrategyType from policy API Group instead.
FSGroupStrategyType = base.Enum(
    "FSGroupStrategyType",
    {
        # MustRunAs meant that container must have FSGroup of X applied.
        # Deprecated: use MustRunAs from policy API Group instead.
        "MustRunAs": "MustRunAs",
        # RunAsAny means that container may make requests for any FSGroup labels.
        # Deprecated: use RunAsAny from policy API Group instead.
        "RunAsAny": "RunAsAny",
    },
)


# FSType gives strong typing to different file systems that are used by volumes.
# Deprecated: use FSType from policy API Group instead.
FSType = base.Enum(
    "FSType",
    {
        "AWSElasticBlockStore": "awsElasticBlockStore",
        "All": "*",
        "AzureDisk": "azureDisk",
        "AzureFile": "azureFile",
        "CSI": "csi",
        "CephFS": "cephFS",
        "Cinder": "cinder",
        "ConfigMap": "configMap",
        "DownwardAPI": "downwardAPI",
        "EmptyDir": "emptyDir",
        "FC": "fc",
        "FlexVolume": "flexVolume",
        "Flocker": "flocker",
        "GCEPersistentDisk": "gcePersistentDisk",
        "GitRepo": "gitRepo",
        "Glusterfs": "glusterfs",
        "HostPath": "hostPath",
        "ISCSI": "iscsi",
        "NFS": "nfs",
        "PersistentVolumeClaim": "persistentVolumeClaim",
        "Quobyte": "quobyte",
        "RBD": "rbd",
        "Secret": "secret",
    },
)


# DEPRECATED 1.9 - This group version of PolicyType is deprecated by networking/v1/PolicyType.
# Policy Type string describes the NetworkPolicy type
# This type is beta-level in 1.8
PolicyType = base.Enum(
    "PolicyType",
    {
        # Egress is a NetworkPolicy that affects egress traffic on selected pods
        "Egress": "Egress",
        # Ingress is a NetworkPolicy that affects ingress traffic on selected pods
        "Ingress": "Ingress",
    },
)


# RunAsGroupStrategy denotes strategy types for generating RunAsGroup values for a
# Security Context.
# Deprecated: use RunAsGroupStrategy from policy API Group instead.
RunAsGroupStrategy = base.Enum(
    "RunAsGroupStrategy",
    {
        # MayRunAs means that container does not need to run with a particular gid.
        # However, when RunAsGroup are specified, they have to fall in the defined range.
        "MayRunAs": "MayRunAs",
        # MustRunAs means that container must run as a particular gid.
        # Deprecated: use MustRunAs from policy API Group instead.
        "MustRunAs": "MustRunAs",
        # RunAsAny means that container may make requests for any gid.
        # Deprecated: use RunAsAny from policy API Group instead.
        "RunAsAny": "RunAsAny",
    },
)


# RunAsUserStrategy denotes strategy types for generating RunAsUser values for a
# Security Context.
# Deprecated: use RunAsUserStrategy from policy API Group instead.
RunAsUserStrategy = base.Enum(
    "RunAsUserStrategy",
    {
        # MustRunAs means that container must run as a particular uid.
        # Deprecated: use MustRunAs from policy API Group instead.
        "MustRunAs": "MustRunAs",
        # MustRunAsNonRoot means that container must run as a non-root uid.
        # Deprecated: use MustRunAsNonRoot from policy API Group instead.
        "MustRunAsNonRoot": "MustRunAsNonRoot",
        # RunAsAny means that container may make requests for any uid.
        # Deprecated: use RunAsAny from policy API Group instead.
        "RunAsAny": "RunAsAny",
    },
)


# SELinuxStrategy denotes strategy types for generating SELinux options for a
# Security Context.
# Deprecated: use SELinuxStrategy from policy API Group instead.
SELinuxStrategy = base.Enum(
    "SELinuxStrategy",
    {
        # MustRunAs means that container must have SELinux labels of X applied.
        # Deprecated: use MustRunAs from policy API Group instead.
        "MustRunAs": "MustRunAs",
        # RunAsAny means that container may make requests for any SELinux context labels.
        # Deprecated: use RunAsAny from policy API Group instead.
        "RunAsAny": "RunAsAny",
    },
)


# SupplementalGroupsStrategyType denotes strategy types for determining valid supplemental
# groups for a SecurityContext.
# Deprecated: use SupplementalGroupsStrategyType from policy API Group instead.
SupplementalGroupsStrategyType = base.Enum(
    "SupplementalGroupsStrategyType",
    {
        # MustRunAs means that container must run as a particular gid.
        # Deprecated: use MustRunAs from policy API Group instead.
        "MustRunAs": "MustRunAs",
        # RunAsAny means that container may make requests for any gid.
        # Deprecated: use RunAsAny from policy API Group instead.
        "RunAsAny": "RunAsAny",
    },
)


class AllowedCSIDriver(types.Object):
    """
    AllowedCSIDriver represents a single inline CSI Driver that is allowed to be used.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = ""):
        super().__init__()
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def name(self) -> str:
        """
        Name is the registered name of the CSI driver
        """
        return self.__name


class AllowedFlexVolume(types.Object):
    """
    AllowedFlexVolume represents a single Flexvolume that is allowed to be used.
    Deprecated: use AllowedFlexVolume from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(self, driver: str = ""):
        super().__init__()
        self.__driver = driver

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        driver = self.driver()
        check_type("driver", driver, str)
        v["driver"] = driver
        return v

    def driver(self) -> str:
        """
        driver is the name of the Flexvolume driver.
        """
        return self.__driver


class AllowedHostPath(types.Object):
    """
    AllowedHostPath defines the host volume conditions that will be enabled by a policy
    for pods to use. It requires the path prefix to be defined.
    Deprecated: use AllowedHostPath from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(self, path_prefix: str = None, read_only: bool = None):
        super().__init__()
        self.__path_prefix = path_prefix
        self.__read_only = read_only

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path_prefix = self.path_prefix()
        check_type("path_prefix", path_prefix, Optional[str])
        if path_prefix:  # omit empty
            v["pathPrefix"] = path_prefix
        read_only = self.read_only()
        check_type("read_only", read_only, Optional[bool])
        if read_only:  # omit empty
            v["readOnly"] = read_only
        return v

    def path_prefix(self) -> Optional[str]:
        """
        pathPrefix is the path prefix that the host volume must match.
        It does not support `*`.
        Trailing slashes are trimmed when validating the path prefix with a host path.
        
        Examples:
        `/foo` would allow `/foo`, `/foo/` and `/foo/bar`
        `/foo` would not allow `/food` or `/etc/foo`
        """
        return self.__path_prefix

    def read_only(self) -> Optional[bool]:
        """
        when set to true, will allow host volumes matching the pathPrefix only if all volume mounts are readOnly.
        """
        return self.__read_only


class RollingUpdateDaemonSet(types.Object):
    """
    Spec to control the desired behavior of daemon set rolling update.
    """

    @context.scoped
    @typechecked
    def __init__(self, max_unavailable: Union[int, str] = None):
        super().__init__()
        self.__max_unavailable = max_unavailable

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        max_unavailable = self.max_unavailable()
        check_type("max_unavailable", max_unavailable, Optional[Union[int, str]])
        if max_unavailable is not None:  # omit empty
            v["maxUnavailable"] = max_unavailable
        return v

    def max_unavailable(self) -> Optional[Union[int, str]]:
        """
        The maximum number of DaemonSet pods that can be unavailable during the
        update. Value can be an absolute number (ex: 5) or a percentage of total
        number of DaemonSet pods at the start of the update (ex: 10%). Absolute
        number is calculated from percentage by rounding up.
        This cannot be 0.
        Default value is 1.
        Example: when this is set to 30%, at most 30% of the total number of nodes
        that should be running the daemon pod (i.e. status.desiredNumberScheduled)
        can have their pods stopped for an update at any given
        time. The update starts by stopping at most 30% of those DaemonSet pods
        and then brings up new DaemonSet pods in their place. Once the new pods
        are available, it then proceeds onto other DaemonSet pods, thus ensuring
        that at least 70% of original number of DaemonSet pods are available at
        all times during the update.
        """
        return self.__max_unavailable


class DaemonSetUpdateStrategy(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        type: DaemonSetUpdateStrategyType = DaemonSetUpdateStrategyType["OnDelete"],
        rolling_update: "RollingUpdateDaemonSet" = None,
    ):
        super().__init__()
        self.__type = type
        self.__rolling_update = rolling_update

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[DaemonSetUpdateStrategyType])
        if type:  # omit empty
            v["type"] = type
        rolling_update = self.rolling_update()
        check_type("rolling_update", rolling_update, Optional["RollingUpdateDaemonSet"])
        if rolling_update is not None:  # omit empty
            v["rollingUpdate"] = rolling_update
        return v

    def type(self) -> Optional[DaemonSetUpdateStrategyType]:
        """
        Type of daemon set update. Can be "RollingUpdate" or "OnDelete".
        Default is OnDelete.
        """
        return self.__type

    def rolling_update(self) -> Optional["RollingUpdateDaemonSet"]:
        """
        Rolling update config params. Present only if type = "RollingUpdate".
        ---
        TODO: Update this to follow our convention for oneOf, whatever we decide it
        to be. Same as Deployment `strategy.rollingUpdate`.
        See https://github.com/kubernetes/kubernetes/issues/35345
        """
        return self.__rolling_update


class DaemonSetSpec(types.Object):
    """
    DaemonSetSpec is the specification of a daemon set.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        selector: "metav1.LabelSelector" = None,
        template: "k8sv1.PodTemplateSpec" = None,
        update_strategy: "DaemonSetUpdateStrategy" = None,
        min_ready_seconds: int = None,
        revision_history_limit: int = None,
    ):
        super().__init__()
        self.__selector = selector
        self.__template = template if template is not None else k8sv1.PodTemplateSpec()
        self.__update_strategy = (
            update_strategy
            if update_strategy is not None
            else DaemonSetUpdateStrategy()
        )
        self.__min_ready_seconds = min_ready_seconds
        self.__revision_history_limit = (
            revision_history_limit if revision_history_limit is not None else 10
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        template = self.template()
        check_type("template", template, "k8sv1.PodTemplateSpec")
        v["template"] = template
        update_strategy = self.update_strategy()
        check_type(
            "update_strategy", update_strategy, Optional["DaemonSetUpdateStrategy"]
        )
        v["updateStrategy"] = update_strategy
        min_ready_seconds = self.min_ready_seconds()
        check_type("min_ready_seconds", min_ready_seconds, Optional[int])
        if min_ready_seconds:  # omit empty
            v["minReadySeconds"] = min_ready_seconds
        revision_history_limit = self.revision_history_limit()
        check_type("revision_history_limit", revision_history_limit, Optional[int])
        if revision_history_limit is not None:  # omit empty
            v["revisionHistoryLimit"] = revision_history_limit
        return v

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        A label query over pods that are managed by the daemon set.
        Must match in order to be controlled.
        If empty, defaulted to labels on Pod template.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
        """
        return self.__selector

    def template(self) -> "k8sv1.PodTemplateSpec":
        """
        An object that describes the pod that will be created.
        The DaemonSet will create exactly one copy of this pod on every node
        that matches the template's node selector (or on every node if no node
        selector is specified).
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#pod-template
        """
        return self.__template

    def update_strategy(self) -> Optional["DaemonSetUpdateStrategy"]:
        """
        An update strategy to replace existing DaemonSet pods with new pods.
        """
        return self.__update_strategy

    def min_ready_seconds(self) -> Optional[int]:
        """
        The minimum number of seconds for which a newly created DaemonSet pod should
        be ready without any of its container crashing, for it to be considered
        available. Defaults to 0 (pod will be considered available as soon as it
        is ready).
        """
        return self.__min_ready_seconds

    def revision_history_limit(self) -> Optional[int]:
        """
        The number of old history to retain to allow rollback.
        This is a pointer to distinguish between explicit zero and not specified.
        Defaults to 10.
        """
        return self.__revision_history_limit


class DaemonSet(base.TypedObject, base.NamespacedMetadataObject):
    """
    DEPRECATED - This group version of DaemonSet is deprecated by apps/v1beta2/DaemonSet. See the release notes for
    more information.
    DaemonSet represents the configuration of a daemon set.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "DaemonSetSpec" = None,
    ):
        super().__init__(
            api_version="extensions/v1beta1",
            kind="DaemonSet",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else DaemonSetSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["DaemonSetSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["DaemonSetSpec"]:
        """
        The desired behavior of this daemon set.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


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
        self.__max_unavailable = max_unavailable if max_unavailable is not None else 1
        self.__max_surge = max_surge if max_surge is not None else 1

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
        By default, a fixed value of 1 is used.
        Example: when this is set to 30%, the old RC can be scaled down to 70% of desired pods
        immediately when the rolling update starts. Once new pods are ready, old RC
        can be scaled down further, followed by scaling up the new RC, ensuring
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
        By default, a value of 1 is used.
        Example: when this is set to 30%, the new RC can be scaled up immediately when
        the rolling update starts, such that the total number of old and new pods do not exceed
        130% of desired pods. Once old pods have been killed,
        new RC can be scaled up further, ensuring that total number of pods running
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
            revision_history_limit if revision_history_limit is not None else 2147483647
        )
        self.__paused = paused
        self.__progress_deadline_seconds = (
            progress_deadline_seconds
            if progress_deadline_seconds is not None
            else 2147483647
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
        This is set to the max value of int32 (i.e. 2147483647) by default, which
        means "retaining all old RelicaSets".
        """
        return self.__revision_history_limit

    def paused(self) -> Optional[bool]:
        """
        Indicates that the deployment is paused and will not be processed by the
        deployment controller.
        """
        return self.__paused

    def progress_deadline_seconds(self) -> Optional[int]:
        """
        The maximum time in seconds for a deployment to make progress before it
        is considered to be failed. The deployment controller will continue to
        process failed deployments and a condition with a ProgressDeadlineExceeded
        reason will be surfaced in the deployment status. Note that progress will
        not be estimated during the time a deployment is paused. This is set to
        the max value of int32 (i.e. 2147483647) by default, which means "no deadline".
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
            api_version="extensions/v1beta1",
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
        super().__init__(api_version="extensions/v1beta1", kind="DeploymentRollback")
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


class IDRange(types.Object):
    """
    IDRange provides a min/max of an allowed range of IDs.
    Deprecated: use IDRange from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(self, min: int = 0, max: int = 0):
        super().__init__()
        self.__min = min
        self.__max = max

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        min = self.min()
        check_type("min", min, int)
        v["min"] = min
        max = self.max()
        check_type("max", max, int)
        v["max"] = max
        return v

    def min(self) -> int:
        """
        min is the start of the range, inclusive.
        """
        return self.__min

    def max(self) -> int:
        """
        max is the end of the range, inclusive.
        """
        return self.__max


class FSGroupStrategyOptions(types.Object):
    """
    FSGroupStrategyOptions defines the strategy type and options used to create the strategy.
    Deprecated: use FSGroupStrategyOptions from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, rule: FSGroupStrategyType = None, ranges: List["IDRange"] = None
    ):
        super().__init__()
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, Optional[FSGroupStrategyType])
        if rule:  # omit empty
            v["rule"] = rule
        ranges = self.ranges()
        check_type("ranges", ranges, Optional[List["IDRange"]])
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    def rule(self) -> Optional[FSGroupStrategyType]:
        """
        rule is the strategy that will dictate what FSGroup is used in the SecurityContext.
        """
        return self.__rule

    def ranges(self) -> Optional[List["IDRange"]]:
        """
        ranges are the allowed ranges of fs groups.  If you would like to force a single
        fs group then supply a single range with the same start and end. Required for MustRunAs.
        """
        return self.__ranges


class IngressBackend(types.Object):
    """
    IngressBackend describes all endpoints for a given service and port.
    """

    @context.scoped
    @typechecked
    def __init__(self, service_name: str = "", service_port: Union[int, str] = None):
        super().__init__()
        self.__service_name = service_name
        self.__service_port = service_port if service_port is not None else 0

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        service_name = self.service_name()
        check_type("service_name", service_name, str)
        v["serviceName"] = service_name
        service_port = self.service_port()
        check_type("service_port", service_port, Union[int, str])
        v["servicePort"] = service_port
        return v

    def service_name(self) -> str:
        """
        Specifies the name of the referenced service.
        """
        return self.__service_name

    def service_port(self) -> Union[int, str]:
        """
        Specifies the port of the referenced service.
        """
        return self.__service_port


class HTTPIngressPath(types.Object):
    """
    HTTPIngressPath associates a path regex with a backend. Incoming urls matching
    the path are forwarded to the backend.
    """

    @context.scoped
    @typechecked
    def __init__(self, path: str = None, backend: "IngressBackend" = None):
        super().__init__()
        self.__path = path
        self.__backend = backend if backend is not None else IngressBackend()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        backend = self.backend()
        check_type("backend", backend, "IngressBackend")
        v["backend"] = backend
        return v

    def path(self) -> Optional[str]:
        """
        Path is an extended POSIX regex as defined by IEEE Std 1003.1,
        (i.e this follows the egrep/unix syntax, not the perl syntax)
        matched against the path of an incoming request. Currently it can
        contain characters disallowed from the conventional "path"
        part of a URL as defined by RFC 3986. Paths must begin with
        a '/'. If unspecified, the path defaults to a catch all sending
        traffic to the backend.
        """
        return self.__path

    def backend(self) -> "IngressBackend":
        """
        Backend defines the referenced service endpoint to which the traffic
        will be forwarded to.
        """
        return self.__backend


class HTTPIngressRuleValue(types.Object):
    """
    HTTPIngressRuleValue is a list of http selectors pointing to backends.
    In the example: http://<host>/<path>?<searchpart> -> backend where
    where parts of the url correspond to RFC 3986, this resource will be used
    to match against everything after the last '/' and before the first '?'
    or '#'.
    """

    @context.scoped
    @typechecked
    def __init__(self, paths: List["HTTPIngressPath"] = None):
        super().__init__()
        self.__paths = paths if paths is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        paths = self.paths()
        check_type("paths", paths, List["HTTPIngressPath"])
        v["paths"] = paths
        return v

    def paths(self) -> List["HTTPIngressPath"]:
        """
        A collection of paths that map requests to backends.
        """
        return self.__paths


class HostPortRange(types.Object):
    """
    HostPortRange defines a range of host ports that will be enabled by a policy
    for pods to use.  It requires both the start and end to be defined.
    Deprecated: use HostPortRange from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(self, min: int = 0, max: int = 0):
        super().__init__()
        self.__min = min
        self.__max = max

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        min = self.min()
        check_type("min", min, int)
        v["min"] = min
        max = self.max()
        check_type("max", max, int)
        v["max"] = max
        return v

    def min(self) -> int:
        """
        min is the start of the range, inclusive.
        """
        return self.__min

    def max(self) -> int:
        """
        max is the end of the range, inclusive.
        """
        return self.__max


class IPBlock(types.Object):
    """
    DEPRECATED 1.9 - This group version of IPBlock is deprecated by networking/v1/IPBlock.
    IPBlock describes a particular CIDR (Ex. "192.168.1.1/24") that is allowed to the pods
    matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs that should
    not be included within this rule.
    """

    @context.scoped
    @typechecked
    def __init__(self, cidr: str = "", except_: List[str] = None):
        super().__init__()
        self.__cidr = cidr
        self.__except_ = except_ if except_ is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cidr = self.cidr()
        check_type("cidr", cidr, str)
        v["cidr"] = cidr
        except_ = self.except_()
        check_type("except_", except_, Optional[List[str]])
        if except_:  # omit empty
            v["except"] = except_
        return v

    def cidr(self) -> str:
        """
        CIDR is a string representing the IP Block
        Valid examples are "192.168.1.1/24"
        """
        return self.__cidr

    def except_(self) -> Optional[List[str]]:
        """
        Except is a slice of CIDRs that should not be included within an IP Block
        Valid examples are "192.168.1.1/24"
        Except values will be rejected if they are outside the CIDR range
        """
        return self.__except_


class IngressRuleValue(types.Object):
    """
    IngressRuleValue represents a rule to apply against incoming requests. If the
    rule is satisfied, the request is routed to the specified backend. Currently
    mixing different types of rules in a single Ingress is disallowed, so exactly
    one of the following must be set.
    """

    @context.scoped
    @typechecked
    def __init__(self, http: "HTTPIngressRuleValue" = None):
        super().__init__()
        self.__http = http

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        http = self.http()
        check_type("http", http, Optional["HTTPIngressRuleValue"])
        if http is not None:  # omit empty
            v["http"] = http
        return v

    def http(self) -> Optional["HTTPIngressRuleValue"]:
        return self.__http


class IngressRule(types.Object):
    """
    IngressRule represents the rules mapping the paths under a specified host to
    the related backend services. Incoming requests are first evaluated for a host
    match, then routed to the backend associated with the matching IngressRuleValue.
    """

    @context.scoped
    @typechecked
    def __init__(self, host: str = None, ingress_rule_value: "IngressRuleValue" = None):
        super().__init__()
        self.__host = host
        self.__ingress_rule_value = (
            ingress_rule_value if ingress_rule_value is not None else IngressRuleValue()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        host = self.host()
        check_type("host", host, Optional[str])
        if host:  # omit empty
            v["host"] = host
        ingress_rule_value = self.ingress_rule_value()
        check_type(
            "ingress_rule_value", ingress_rule_value, Optional["IngressRuleValue"]
        )
        v.update(ingress_rule_value._root())  # inline
        return v

    def host(self) -> Optional[str]:
        """
        Host is the fully qualified domain name of a network host, as defined
        by RFC 3986. Note the following deviations from the "host" part of the
        URI as defined in the RFC:
        1. IPs are not allowed. Currently an IngressRuleValue can only apply to the
        	  IP in the Spec of the parent Ingress.
        2. The `:` delimiter is not respected because ports are not allowed.
        	  Currently the port of an Ingress is implicitly :80 for http and
        	  :443 for https.
        Both these may change in the future.
        Incoming requests are matched against the host before the IngressRuleValue.
        If the host is unspecified, the Ingress routes all traffic based on the
        specified IngressRuleValue.
        """
        return self.__host

    def ingress_rule_value(self) -> Optional["IngressRuleValue"]:
        """
        IngressRuleValue represents a rule to route requests for this IngressRule.
        If unspecified, the rule defaults to a http catch-all. Whether that sends
        just traffic matching the host to the default backend or all traffic to the
        default backend, is left to the controller fulfilling the Ingress. Http is
        currently the only supported IngressRuleValue.
        """
        return self.__ingress_rule_value


class IngressTLS(types.Object):
    """
    IngressTLS describes the transport layer security associated with an Ingress.
    """

    @context.scoped
    @typechecked
    def __init__(self, hosts: List[str] = None, secret_name: str = None):
        super().__init__()
        self.__hosts = hosts if hosts is not None else []
        self.__secret_name = secret_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        hosts = self.hosts()
        check_type("hosts", hosts, Optional[List[str]])
        if hosts:  # omit empty
            v["hosts"] = hosts
        secret_name = self.secret_name()
        check_type("secret_name", secret_name, Optional[str])
        if secret_name:  # omit empty
            v["secretName"] = secret_name
        return v

    def hosts(self) -> Optional[List[str]]:
        """
        Hosts are a list of hosts included in the TLS certificate. The values in
        this list must match the name/s used in the tlsSecret. Defaults to the
        wildcard host setting for the loadbalancer controller fulfilling this
        Ingress, if left unspecified.
        """
        return self.__hosts

    def secret_name(self) -> Optional[str]:
        """
        SecretName is the name of the secret used to terminate SSL traffic on 443.
        Field is left optional to allow SSL routing based on SNI hostname alone.
        If the SNI host in a listener conflicts with the "Host" header field used
        by an IngressRule, the SNI host is used for termination and value of the
        Host header is used for routing.
        """
        return self.__secret_name


class IngressSpec(types.Object):
    """
    IngressSpec describes the Ingress the user wishes to exist.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        backend: "IngressBackend" = None,
        tls: List["IngressTLS"] = None,
        rules: List["IngressRule"] = None,
    ):
        super().__init__()
        self.__backend = backend
        self.__tls = tls if tls is not None else []
        self.__rules = rules if rules is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        backend = self.backend()
        check_type("backend", backend, Optional["IngressBackend"])
        if backend is not None:  # omit empty
            v["backend"] = backend
        tls = self.tls()
        check_type("tls", tls, Optional[List["IngressTLS"]])
        if tls:  # omit empty
            v["tls"] = tls
        rules = self.rules()
        check_type("rules", rules, Optional[List["IngressRule"]])
        if rules:  # omit empty
            v["rules"] = rules
        return v

    def backend(self) -> Optional["IngressBackend"]:
        """
        A default backend capable of servicing requests that don't match any
        rule. At least one of 'backend' or 'rules' must be specified. This field
        is optional to allow the loadbalancer controller or defaulting logic to
        specify a global default.
        """
        return self.__backend

    def tls(self) -> Optional[List["IngressTLS"]]:
        """
        TLS configuration. Currently the Ingress only supports a single TLS
        port, 443. If multiple members of this list specify different hosts, they
        will be multiplexed on the same port according to the hostname specified
        through the SNI TLS extension, if the ingress controller fulfilling the
        ingress supports SNI.
        """
        return self.__tls

    def rules(self) -> Optional[List["IngressRule"]]:
        """
        A list of host rules used to configure the Ingress. If unspecified, or
        no rule matches, all traffic is sent to the default backend.
        """
        return self.__rules


class Ingress(base.TypedObject, base.NamespacedMetadataObject):
    """
    Ingress is a collection of rules that allow inbound connections to reach the
    endpoints defined by a backend. An Ingress can be configured to give services
    externally-reachable urls, load balance traffic, terminate SSL, offer name
    based virtual hosting etc.
    DEPRECATED - This group version of Ingress is deprecated by networking.k8s.io/v1beta1 Ingress. See the release notes for more information.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "IngressSpec" = None,
    ):
        super().__init__(
            api_version="extensions/v1beta1",
            kind="Ingress",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else IngressSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["IngressSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["IngressSpec"]:
        """
        Spec is the desired state of the Ingress.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class NetworkPolicyPeer(types.Object):
    """
    DEPRECATED 1.9 - This group version of NetworkPolicyPeer is deprecated by networking/v1/NetworkPolicyPeer.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        pod_selector: "metav1.LabelSelector" = None,
        namespace_selector: "metav1.LabelSelector" = None,
        ip_block: "IPBlock" = None,
    ):
        super().__init__()
        self.__pod_selector = pod_selector
        self.__namespace_selector = namespace_selector
        self.__ip_block = ip_block

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pod_selector = self.pod_selector()
        check_type("pod_selector", pod_selector, Optional["metav1.LabelSelector"])
        if pod_selector is not None:  # omit empty
            v["podSelector"] = pod_selector
        namespace_selector = self.namespace_selector()
        check_type(
            "namespace_selector", namespace_selector, Optional["metav1.LabelSelector"]
        )
        if namespace_selector is not None:  # omit empty
            v["namespaceSelector"] = namespace_selector
        ip_block = self.ip_block()
        check_type("ip_block", ip_block, Optional["IPBlock"])
        if ip_block is not None:  # omit empty
            v["ipBlock"] = ip_block
        return v

    def pod_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        This is a label selector which selects Pods. This field follows standard label
        selector semantics; if present but empty, it selects all pods.
        
        If NamespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
        the Pods matching PodSelector in the Namespaces selected by NamespaceSelector.
        Otherwise it selects the Pods matching PodSelector in the policy's own Namespace.
        """
        return self.__pod_selector

    def namespace_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        Selects Namespaces using cluster-scoped labels. This field follows standard label
        selector semantics; if present but empty, it selects all namespaces.
        
        If PodSelector is also set, then the NetworkPolicyPeer as a whole selects
        the Pods matching PodSelector in the Namespaces selected by NamespaceSelector.
        Otherwise it selects all Pods in the Namespaces selected by NamespaceSelector.
        """
        return self.__namespace_selector

    def ip_block(self) -> Optional["IPBlock"]:
        """
        IPBlock defines policy on a particular IPBlock. If this field is set then
        neither of the other fields can be.
        """
        return self.__ip_block


class NetworkPolicyPort(types.Object):
    """
    DEPRECATED 1.9 - This group version of NetworkPolicyPort is deprecated by networking/v1/NetworkPolicyPort.
    """

    @context.scoped
    @typechecked
    def __init__(self, protocol: k8sv1.Protocol = None, port: Union[int, str] = None):
        super().__init__()
        self.__protocol = protocol
        self.__port = port

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        protocol = self.protocol()
        check_type("protocol", protocol, Optional[k8sv1.Protocol])
        if protocol is not None:  # omit empty
            v["protocol"] = protocol
        port = self.port()
        check_type("port", port, Optional[Union[int, str]])
        if port is not None:  # omit empty
            v["port"] = port
        return v

    def protocol(self) -> Optional[k8sv1.Protocol]:
        """
        Optional.  The protocol (TCP, UDP, or SCTP) which traffic must match.
        If not specified, this field defaults to TCP.
        """
        return self.__protocol

    def port(self) -> Optional[Union[int, str]]:
        """
        If specified, the port on the given protocol.  This can
        either be a numerical or named port on a pod.  If this field is not provided,
        this matches all port names and numbers.
        If present, only traffic on the specified protocol AND port
        will be matched.
        """
        return self.__port


class NetworkPolicyEgressRule(types.Object):
    """
    DEPRECATED 1.9 - This group version of NetworkPolicyEgressRule is deprecated by networking/v1/NetworkPolicyEgressRule.
    NetworkPolicyEgressRule describes a particular set of traffic that is allowed out of pods
    matched by a NetworkPolicySpec's podSelector. The traffic must match both ports and to.
    This type is beta-level in 1.8
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ports: List["NetworkPolicyPort"] = None,
        to: List["NetworkPolicyPeer"] = None,
    ):
        super().__init__()
        self.__ports = ports if ports is not None else []
        self.__to = to if to is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ports = self.ports()
        check_type("ports", ports, Optional[List["NetworkPolicyPort"]])
        if ports:  # omit empty
            v["ports"] = ports
        to = self.to()
        check_type("to", to, Optional[List["NetworkPolicyPeer"]])
        if to:  # omit empty
            v["to"] = to
        return v

    def ports(self) -> Optional[List["NetworkPolicyPort"]]:
        """
        List of destination ports for outgoing traffic.
        Each item in this list is combined using a logical OR. If this field is
        empty or missing, this rule matches all ports (traffic not restricted by port).
        If this field is present and contains at least one item, then this rule allows
        traffic only if the traffic matches at least one port in the list.
        """
        return self.__ports

    def to(self) -> Optional[List["NetworkPolicyPeer"]]:
        """
        List of destinations for outgoing traffic of pods selected for this rule.
        Items in this list are combined using a logical OR operation. If this field is
        empty or missing, this rule matches all destinations (traffic not restricted by
        destination). If this field is present and contains at least one item, this rule
        allows traffic only if the traffic matches at least one item in the to list.
        """
        return self.__to


class NetworkPolicyIngressRule(types.Object):
    """
    DEPRECATED 1.9 - This group version of NetworkPolicyIngressRule is deprecated by networking/v1/NetworkPolicyIngressRule.
    This NetworkPolicyIngressRule matches traffic if and only if the traffic matches both ports AND from.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ports: List["NetworkPolicyPort"] = None,
        from_: List["NetworkPolicyPeer"] = None,
    ):
        super().__init__()
        self.__ports = ports if ports is not None else []
        self.__from_ = from_ if from_ is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ports = self.ports()
        check_type("ports", ports, Optional[List["NetworkPolicyPort"]])
        if ports:  # omit empty
            v["ports"] = ports
        from_ = self.from_()
        check_type("from_", from_, Optional[List["NetworkPolicyPeer"]])
        if from_:  # omit empty
            v["from"] = from_
        return v

    def ports(self) -> Optional[List["NetworkPolicyPort"]]:
        """
        List of ports which should be made accessible on the pods selected for this rule.
        Each item in this list is combined using a logical OR.
        If this field is empty or missing, this rule matches all ports (traffic not restricted by port).
        If this field is present and contains at least one item, then this rule allows traffic
        only if the traffic matches at least one port in the list.
        """
        return self.__ports

    def from_(self) -> Optional[List["NetworkPolicyPeer"]]:
        """
        List of sources which should be able to access the pods selected for this rule.
        Items in this list are combined using a logical OR operation.
        If this field is empty or missing, this rule matches all sources (traffic not restricted by source).
        If this field is present and contains at least one item, this rule allows traffic only if the
        traffic matches at least one item in the from list.
        """
        return self.__from_


class NetworkPolicySpec(types.Object):
    """
    DEPRECATED 1.9 - This group version of NetworkPolicySpec is deprecated by networking/v1/NetworkPolicySpec.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        pod_selector: "metav1.LabelSelector" = None,
        ingress: List["NetworkPolicyIngressRule"] = None,
        egress: List["NetworkPolicyEgressRule"] = None,
        policy_types: List[PolicyType] = None,
    ):
        super().__init__()
        self.__pod_selector = (
            pod_selector if pod_selector is not None else metav1.LabelSelector()
        )
        self.__ingress = ingress if ingress is not None else []
        self.__egress = egress if egress is not None else []
        self.__policy_types = policy_types if policy_types is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pod_selector = self.pod_selector()
        check_type("pod_selector", pod_selector, "metav1.LabelSelector")
        v["podSelector"] = pod_selector
        ingress = self.ingress()
        check_type("ingress", ingress, Optional[List["NetworkPolicyIngressRule"]])
        if ingress:  # omit empty
            v["ingress"] = ingress
        egress = self.egress()
        check_type("egress", egress, Optional[List["NetworkPolicyEgressRule"]])
        if egress:  # omit empty
            v["egress"] = egress
        policy_types = self.policy_types()
        check_type("policy_types", policy_types, Optional[List[PolicyType]])
        if policy_types:  # omit empty
            v["policyTypes"] = policy_types
        return v

    def pod_selector(self) -> "metav1.LabelSelector":
        """
        Selects the pods to which this NetworkPolicy object applies.  The array of ingress rules
        is applied to any pods selected by this field. Multiple network policies can select the
        same set of pods.  In this case, the ingress rules for each are combined additively.
        This field is NOT optional and follows standard label selector semantics.
        An empty podSelector matches all pods in this namespace.
        """
        return self.__pod_selector

    def ingress(self) -> Optional[List["NetworkPolicyIngressRule"]]:
        """
        List of ingress rules to be applied to the selected pods.
        Traffic is allowed to a pod if there are no NetworkPolicies selecting the pod
        OR if the traffic source is the pod's local node,
        OR if the traffic matches at least one ingress rule across all of the NetworkPolicy
        objects whose podSelector matches the pod.
        If this field is empty then this NetworkPolicy does not allow any traffic
        (and serves solely to ensure that the pods it selects are isolated by default).
        """
        return self.__ingress

    def egress(self) -> Optional[List["NetworkPolicyEgressRule"]]:
        """
        List of egress rules to be applied to the selected pods. Outgoing traffic is
        allowed if there are no NetworkPolicies selecting the pod (and cluster policy
        otherwise allows the traffic), OR if the traffic matches at least one egress rule
        across all of the NetworkPolicy objects whose podSelector matches the pod. If
        this field is empty then this NetworkPolicy limits all outgoing traffic (and serves
        solely to ensure that the pods it selects are isolated by default).
        This field is beta-level in 1.8
        """
        return self.__egress

    def policy_types(self) -> Optional[List[PolicyType]]:
        """
        List of rule types that the NetworkPolicy relates to.
        Valid options are "Ingress", "Egress", or "Ingress,Egress".
        If this field is not specified, it will default based on the existence of Ingress or Egress rules;
        policies that contain an Egress section are assumed to affect Egress, and all policies
        (whether or not they contain an Ingress section) are assumed to affect Ingress.
        If you want to write an egress-only policy, you must explicitly specify policyTypes [ "Egress" ].
        Likewise, if you want to write a policy that specifies that no egress is allowed,
        you must specify a policyTypes value that include "Egress" (since such a policy would not include
        an Egress section and would otherwise default to just [ "Ingress" ]).
        This field is beta-level in 1.8
        """
        return self.__policy_types


class NetworkPolicy(base.TypedObject, base.NamespacedMetadataObject):
    """
    DEPRECATED 1.9 - This group version of NetworkPolicy is deprecated by networking/v1/NetworkPolicy.
    NetworkPolicy describes what network traffic is allowed for a set of Pods
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "NetworkPolicySpec" = None,
    ):
        super().__init__(
            api_version="extensions/v1beta1",
            kind="NetworkPolicy",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else NetworkPolicySpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["NetworkPolicySpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["NetworkPolicySpec"]:
        """
        Specification of the desired behavior for this NetworkPolicy.
        """
        return self.__spec


class RunAsGroupStrategyOptions(types.Object):
    """
    RunAsGroupStrategyOptions defines the strategy type and any options used to create the strategy.
    Deprecated: use RunAsGroupStrategyOptions from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(self, rule: RunAsGroupStrategy = None, ranges: List["IDRange"] = None):
        super().__init__()
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, RunAsGroupStrategy)
        v["rule"] = rule
        ranges = self.ranges()
        check_type("ranges", ranges, Optional[List["IDRange"]])
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    def rule(self) -> RunAsGroupStrategy:
        """
        rule is the strategy that will dictate the allowable RunAsGroup values that may be set.
        """
        return self.__rule

    def ranges(self) -> Optional[List["IDRange"]]:
        """
        ranges are the allowed ranges of gids that may be used. If you would like to force a single gid
        then supply a single range with the same start and end. Required for MustRunAs.
        """
        return self.__ranges


class RunAsUserStrategyOptions(types.Object):
    """
    RunAsUserStrategyOptions defines the strategy type and any options used to create the strategy.
    Deprecated: use RunAsUserStrategyOptions from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(self, rule: RunAsUserStrategy = None, ranges: List["IDRange"] = None):
        super().__init__()
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, RunAsUserStrategy)
        v["rule"] = rule
        ranges = self.ranges()
        check_type("ranges", ranges, Optional[List["IDRange"]])
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    def rule(self) -> RunAsUserStrategy:
        """
        rule is the strategy that will dictate the allowable RunAsUser values that may be set.
        """
        return self.__rule

    def ranges(self) -> Optional[List["IDRange"]]:
        """
        ranges are the allowed ranges of uids that may be used. If you would like to force a single uid
        then supply a single range with the same start and end. Required for MustRunAs.
        """
        return self.__ranges


class RuntimeClassStrategyOptions(types.Object):
    """
    RuntimeClassStrategyOptions define the strategy that will dictate the allowable RuntimeClasses
    for a pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        allowed_runtime_class_names: List[str] = None,
        default_runtime_class_name: str = None,
    ):
        super().__init__()
        self.__allowed_runtime_class_names = (
            allowed_runtime_class_names
            if allowed_runtime_class_names is not None
            else []
        )
        self.__default_runtime_class_name = default_runtime_class_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        allowed_runtime_class_names = self.allowed_runtime_class_names()
        check_type(
            "allowed_runtime_class_names", allowed_runtime_class_names, List[str]
        )
        v["allowedRuntimeClassNames"] = allowed_runtime_class_names
        default_runtime_class_name = self.default_runtime_class_name()
        check_type(
            "default_runtime_class_name", default_runtime_class_name, Optional[str]
        )
        if default_runtime_class_name is not None:  # omit empty
            v["defaultRuntimeClassName"] = default_runtime_class_name
        return v

    def allowed_runtime_class_names(self) -> List[str]:
        """
        allowedRuntimeClassNames is a whitelist of RuntimeClass names that may be specified on a pod.
        A value of "*" means that any RuntimeClass name is allowed, and must be the only item in the
        list. An empty list requires the RuntimeClassName field to be unset.
        """
        return self.__allowed_runtime_class_names

    def default_runtime_class_name(self) -> Optional[str]:
        """
        defaultRuntimeClassName is the default RuntimeClassName to set on the pod.
        The default MUST be allowed by the allowedRuntimeClassNames list.
        A value of nil does not mutate the Pod.
        """
        return self.__default_runtime_class_name


class SELinuxStrategyOptions(types.Object):
    """
    SELinuxStrategyOptions defines the strategy type and any options used to create the strategy.
    Deprecated: use SELinuxStrategyOptions from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        rule: SELinuxStrategy = None,
        se_linux_options: "k8sv1.SELinuxOptions" = None,
    ):
        super().__init__()
        self.__rule = rule
        self.__se_linux_options = se_linux_options

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, SELinuxStrategy)
        v["rule"] = rule
        se_linux_options = self.se_linux_options()
        check_type(
            "se_linux_options", se_linux_options, Optional["k8sv1.SELinuxOptions"]
        )
        if se_linux_options is not None:  # omit empty
            v["seLinuxOptions"] = se_linux_options
        return v

    def rule(self) -> SELinuxStrategy:
        """
        rule is the strategy that will dictate the allowable labels that may be set.
        """
        return self.__rule

    def se_linux_options(self) -> Optional["k8sv1.SELinuxOptions"]:
        """
        seLinuxOptions required to run as; required for MustRunAs
        More info: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
        """
        return self.__se_linux_options


class SupplementalGroupsStrategyOptions(types.Object):
    """
    SupplementalGroupsStrategyOptions defines the strategy type and options used to create the strategy.
    Deprecated: use SupplementalGroupsStrategyOptions from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        rule: SupplementalGroupsStrategyType = None,
        ranges: List["IDRange"] = None,
    ):
        super().__init__()
        self.__rule = rule
        self.__ranges = ranges if ranges is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, Optional[SupplementalGroupsStrategyType])
        if rule:  # omit empty
            v["rule"] = rule
        ranges = self.ranges()
        check_type("ranges", ranges, Optional[List["IDRange"]])
        if ranges:  # omit empty
            v["ranges"] = ranges
        return v

    def rule(self) -> Optional[SupplementalGroupsStrategyType]:
        """
        rule is the strategy that will dictate what supplemental groups is used in the SecurityContext.
        """
        return self.__rule

    def ranges(self) -> Optional[List["IDRange"]]:
        """
        ranges are the allowed ranges of supplemental groups.  If you would like to force a single
        supplemental group then supply a single range with the same start and end. Required for MustRunAs.
        """
        return self.__ranges


class PodSecurityPolicySpec(types.Object):
    """
    PodSecurityPolicySpec defines the policy enforced.
    Deprecated: use PodSecurityPolicySpec from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        privileged: bool = None,
        default_add_capabilities: List[k8sv1.Capability] = None,
        required_drop_capabilities: List[k8sv1.Capability] = None,
        allowed_capabilities: List[k8sv1.Capability] = None,
        volumes: List[FSType] = None,
        host_network: bool = None,
        host_ports: List["HostPortRange"] = None,
        host_pid: bool = None,
        host_ipc: bool = None,
        se_linux: "SELinuxStrategyOptions" = None,
        run_as_user: "RunAsUserStrategyOptions" = None,
        run_as_group: "RunAsGroupStrategyOptions" = None,
        supplemental_groups: "SupplementalGroupsStrategyOptions" = None,
        fs_group: "FSGroupStrategyOptions" = None,
        read_only_root_filesystem: bool = None,
        default_allow_privilege_escalation: bool = None,
        allow_privilege_escalation: bool = None,
        allowed_host_paths: List["AllowedHostPath"] = None,
        allowed_flex_volumes: List["AllowedFlexVolume"] = None,
        allowed_csi_drivers: List["AllowedCSIDriver"] = None,
        allowed_unsafe_sysctls: List[str] = None,
        forbidden_sysctls: List[str] = None,
        allowed_proc_mount_types: List[k8sv1.ProcMountType] = None,
        runtime_class: "RuntimeClassStrategyOptions" = None,
    ):
        super().__init__()
        self.__privileged = privileged
        self.__default_add_capabilities = (
            default_add_capabilities if default_add_capabilities is not None else []
        )
        self.__required_drop_capabilities = (
            required_drop_capabilities if required_drop_capabilities is not None else []
        )
        self.__allowed_capabilities = (
            allowed_capabilities if allowed_capabilities is not None else []
        )
        self.__volumes = volumes if volumes is not None else []
        self.__host_network = host_network
        self.__host_ports = host_ports if host_ports is not None else []
        self.__host_pid = host_pid
        self.__host_ipc = host_ipc
        self.__se_linux = se_linux if se_linux is not None else SELinuxStrategyOptions()
        self.__run_as_user = (
            run_as_user if run_as_user is not None else RunAsUserStrategyOptions()
        )
        self.__run_as_group = run_as_group
        self.__supplemental_groups = (
            supplemental_groups
            if supplemental_groups is not None
            else SupplementalGroupsStrategyOptions()
        )
        self.__fs_group = fs_group if fs_group is not None else FSGroupStrategyOptions()
        self.__read_only_root_filesystem = read_only_root_filesystem
        self.__default_allow_privilege_escalation = default_allow_privilege_escalation
        self.__allow_privilege_escalation = (
            allow_privilege_escalation
            if allow_privilege_escalation is not None
            else True
        )
        self.__allowed_host_paths = (
            allowed_host_paths if allowed_host_paths is not None else []
        )
        self.__allowed_flex_volumes = (
            allowed_flex_volumes if allowed_flex_volumes is not None else []
        )
        self.__allowed_csi_drivers = (
            allowed_csi_drivers if allowed_csi_drivers is not None else []
        )
        self.__allowed_unsafe_sysctls = (
            allowed_unsafe_sysctls if allowed_unsafe_sysctls is not None else []
        )
        self.__forbidden_sysctls = (
            forbidden_sysctls if forbidden_sysctls is not None else []
        )
        self.__allowed_proc_mount_types = (
            allowed_proc_mount_types if allowed_proc_mount_types is not None else []
        )
        self.__runtime_class = runtime_class

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        privileged = self.privileged()
        check_type("privileged", privileged, Optional[bool])
        if privileged:  # omit empty
            v["privileged"] = privileged
        default_add_capabilities = self.default_add_capabilities()
        check_type(
            "default_add_capabilities",
            default_add_capabilities,
            Optional[List[k8sv1.Capability]],
        )
        if default_add_capabilities:  # omit empty
            v["defaultAddCapabilities"] = default_add_capabilities
        required_drop_capabilities = self.required_drop_capabilities()
        check_type(
            "required_drop_capabilities",
            required_drop_capabilities,
            Optional[List[k8sv1.Capability]],
        )
        if required_drop_capabilities:  # omit empty
            v["requiredDropCapabilities"] = required_drop_capabilities
        allowed_capabilities = self.allowed_capabilities()
        check_type(
            "allowed_capabilities",
            allowed_capabilities,
            Optional[List[k8sv1.Capability]],
        )
        if allowed_capabilities:  # omit empty
            v["allowedCapabilities"] = allowed_capabilities
        volumes = self.volumes()
        check_type("volumes", volumes, Optional[List[FSType]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        host_network = self.host_network()
        check_type("host_network", host_network, Optional[bool])
        if host_network:  # omit empty
            v["hostNetwork"] = host_network
        host_ports = self.host_ports()
        check_type("host_ports", host_ports, Optional[List["HostPortRange"]])
        if host_ports:  # omit empty
            v["hostPorts"] = host_ports
        host_pid = self.host_pid()
        check_type("host_pid", host_pid, Optional[bool])
        if host_pid:  # omit empty
            v["hostPID"] = host_pid
        host_ipc = self.host_ipc()
        check_type("host_ipc", host_ipc, Optional[bool])
        if host_ipc:  # omit empty
            v["hostIPC"] = host_ipc
        se_linux = self.se_linux()
        check_type("se_linux", se_linux, "SELinuxStrategyOptions")
        v["seLinux"] = se_linux
        run_as_user = self.run_as_user()
        check_type("run_as_user", run_as_user, "RunAsUserStrategyOptions")
        v["runAsUser"] = run_as_user
        run_as_group = self.run_as_group()
        check_type("run_as_group", run_as_group, Optional["RunAsGroupStrategyOptions"])
        if run_as_group is not None:  # omit empty
            v["runAsGroup"] = run_as_group
        supplemental_groups = self.supplemental_groups()
        check_type(
            "supplemental_groups",
            supplemental_groups,
            "SupplementalGroupsStrategyOptions",
        )
        v["supplementalGroups"] = supplemental_groups
        fs_group = self.fs_group()
        check_type("fs_group", fs_group, "FSGroupStrategyOptions")
        v["fsGroup"] = fs_group
        read_only_root_filesystem = self.read_only_root_filesystem()
        check_type(
            "read_only_root_filesystem", read_only_root_filesystem, Optional[bool]
        )
        if read_only_root_filesystem:  # omit empty
            v["readOnlyRootFilesystem"] = read_only_root_filesystem
        default_allow_privilege_escalation = self.default_allow_privilege_escalation()
        check_type(
            "default_allow_privilege_escalation",
            default_allow_privilege_escalation,
            Optional[bool],
        )
        if default_allow_privilege_escalation is not None:  # omit empty
            v["defaultAllowPrivilegeEscalation"] = default_allow_privilege_escalation
        allow_privilege_escalation = self.allow_privilege_escalation()
        check_type(
            "allow_privilege_escalation", allow_privilege_escalation, Optional[bool]
        )
        if allow_privilege_escalation is not None:  # omit empty
            v["allowPrivilegeEscalation"] = allow_privilege_escalation
        allowed_host_paths = self.allowed_host_paths()
        check_type(
            "allowed_host_paths", allowed_host_paths, Optional[List["AllowedHostPath"]]
        )
        if allowed_host_paths:  # omit empty
            v["allowedHostPaths"] = allowed_host_paths
        allowed_flex_volumes = self.allowed_flex_volumes()
        check_type(
            "allowed_flex_volumes",
            allowed_flex_volumes,
            Optional[List["AllowedFlexVolume"]],
        )
        if allowed_flex_volumes:  # omit empty
            v["allowedFlexVolumes"] = allowed_flex_volumes
        allowed_csi_drivers = self.allowed_csi_drivers()
        check_type(
            "allowed_csi_drivers",
            allowed_csi_drivers,
            Optional[List["AllowedCSIDriver"]],
        )
        if allowed_csi_drivers:  # omit empty
            v["allowedCSIDrivers"] = allowed_csi_drivers
        allowed_unsafe_sysctls = self.allowed_unsafe_sysctls()
        check_type(
            "allowed_unsafe_sysctls", allowed_unsafe_sysctls, Optional[List[str]]
        )
        if allowed_unsafe_sysctls:  # omit empty
            v["allowedUnsafeSysctls"] = allowed_unsafe_sysctls
        forbidden_sysctls = self.forbidden_sysctls()
        check_type("forbidden_sysctls", forbidden_sysctls, Optional[List[str]])
        if forbidden_sysctls:  # omit empty
            v["forbiddenSysctls"] = forbidden_sysctls
        allowed_proc_mount_types = self.allowed_proc_mount_types()
        check_type(
            "allowed_proc_mount_types",
            allowed_proc_mount_types,
            Optional[List[k8sv1.ProcMountType]],
        )
        if allowed_proc_mount_types:  # omit empty
            v["allowedProcMountTypes"] = allowed_proc_mount_types
        runtime_class = self.runtime_class()
        check_type(
            "runtime_class", runtime_class, Optional["RuntimeClassStrategyOptions"]
        )
        if runtime_class is not None:  # omit empty
            v["runtimeClass"] = runtime_class
        return v

    def privileged(self) -> Optional[bool]:
        """
        privileged determines if a pod can request to be run as privileged.
        """
        return self.__privileged

    def default_add_capabilities(self) -> Optional[List[k8sv1.Capability]]:
        """
        defaultAddCapabilities is the default set of capabilities that will be added to the container
        unless the pod spec specifically drops the capability.  You may not list a capability in both
        defaultAddCapabilities and requiredDropCapabilities. Capabilities added here are implicitly
        allowed, and need not be included in the allowedCapabilities list.
        """
        return self.__default_add_capabilities

    def required_drop_capabilities(self) -> Optional[List[k8sv1.Capability]]:
        """
        requiredDropCapabilities are the capabilities that will be dropped from the container.  These
        are required to be dropped and cannot be added.
        """
        return self.__required_drop_capabilities

    def allowed_capabilities(self) -> Optional[List[k8sv1.Capability]]:
        """
        allowedCapabilities is a list of capabilities that can be requested to add to the container.
        Capabilities in this field may be added at the pod author's discretion.
        You must not list a capability in both allowedCapabilities and requiredDropCapabilities.
        """
        return self.__allowed_capabilities

    def volumes(self) -> Optional[List[FSType]]:
        """
        volumes is a white list of allowed volume plugins. Empty indicates that
        no volumes may be used. To allow all volumes you may use '*'.
        """
        return self.__volumes

    def host_network(self) -> Optional[bool]:
        """
        hostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
        """
        return self.__host_network

    def host_ports(self) -> Optional[List["HostPortRange"]]:
        """
        hostPorts determines which host port ranges are allowed to be exposed.
        """
        return self.__host_ports

    def host_pid(self) -> Optional[bool]:
        """
        hostPID determines if the policy allows the use of HostPID in the pod spec.
        """
        return self.__host_pid

    def host_ipc(self) -> Optional[bool]:
        """
        hostIPC determines if the policy allows the use of HostIPC in the pod spec.
        """
        return self.__host_ipc

    def se_linux(self) -> "SELinuxStrategyOptions":
        """
        seLinux is the strategy that will dictate the allowable labels that may be set.
        """
        return self.__se_linux

    def run_as_user(self) -> "RunAsUserStrategyOptions":
        """
        runAsUser is the strategy that will dictate the allowable RunAsUser values that may be set.
        """
        return self.__run_as_user

    def run_as_group(self) -> Optional["RunAsGroupStrategyOptions"]:
        """
        RunAsGroup is the strategy that will dictate the allowable RunAsGroup values that may be set.
        If this field is omitted, the pod's RunAsGroup can take any value. This field requires the
        RunAsGroup feature gate to be enabled.
        """
        return self.__run_as_group

    def supplemental_groups(self) -> "SupplementalGroupsStrategyOptions":
        """
        supplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
        """
        return self.__supplemental_groups

    def fs_group(self) -> "FSGroupStrategyOptions":
        """
        fsGroup is the strategy that will dictate what fs group is used by the SecurityContext.
        """
        return self.__fs_group

    def read_only_root_filesystem(self) -> Optional[bool]:
        """
        readOnlyRootFilesystem when set to true will force containers to run with a read only root file
        system.  If the container specifically requests to run with a non-read only root file system
        the PSP should deny the pod.
        If set to false the container may run with a read only root file system if it wishes but it
        will not be forced to.
        """
        return self.__read_only_root_filesystem

    def default_allow_privilege_escalation(self) -> Optional[bool]:
        """
        defaultAllowPrivilegeEscalation controls the default setting for whether a
        process can gain more privileges than its parent process.
        """
        return self.__default_allow_privilege_escalation

    def allow_privilege_escalation(self) -> Optional[bool]:
        """
        allowPrivilegeEscalation determines if a pod can request to allow
        privilege escalation. If unspecified, defaults to true.
        """
        return self.__allow_privilege_escalation

    def allowed_host_paths(self) -> Optional[List["AllowedHostPath"]]:
        """
        allowedHostPaths is a white list of allowed host paths. Empty indicates
        that all host paths may be used.
        """
        return self.__allowed_host_paths

    def allowed_flex_volumes(self) -> Optional[List["AllowedFlexVolume"]]:
        """
        allowedFlexVolumes is a whitelist of allowed Flexvolumes.  Empty or nil indicates that all
        Flexvolumes may be used.  This parameter is effective only when the usage of the Flexvolumes
        is allowed in the "volumes" field.
        """
        return self.__allowed_flex_volumes

    def allowed_csi_drivers(self) -> Optional[List["AllowedCSIDriver"]]:
        """
        AllowedCSIDrivers is a whitelist of inline CSI drivers that must be explicitly set to be embedded within a pod spec.
        An empty value indicates that any CSI driver can be used for inline ephemeral volumes.
        """
        return self.__allowed_csi_drivers

    def allowed_unsafe_sysctls(self) -> Optional[List[str]]:
        """
        allowedUnsafeSysctls is a list of explicitly allowed unsafe sysctls, defaults to none.
        Each entry is either a plain sysctl name or ends in "*" in which case it is considered
        as a prefix of allowed sysctls. Single * means all unsafe sysctls are allowed.
        Kubelet has to whitelist all allowed unsafe sysctls explicitly to avoid rejection.
        
        Examples:
        e.g. "foo/*" allows "foo/bar", "foo/baz", etc.
        e.g. "foo.*" allows "foo.bar", "foo.baz", etc.
        """
        return self.__allowed_unsafe_sysctls

    def forbidden_sysctls(self) -> Optional[List[str]]:
        """
        forbiddenSysctls is a list of explicitly forbidden sysctls, defaults to none.
        Each entry is either a plain sysctl name or ends in "*" in which case it is considered
        as a prefix of forbidden sysctls. Single * means all sysctls are forbidden.
        
        Examples:
        e.g. "foo/*" forbids "foo/bar", "foo/baz", etc.
        e.g. "foo.*" forbids "foo.bar", "foo.baz", etc.
        """
        return self.__forbidden_sysctls

    def allowed_proc_mount_types(self) -> Optional[List[k8sv1.ProcMountType]]:
        """
        AllowedProcMountTypes is a whitelist of allowed ProcMountTypes.
        Empty or nil indicates that only the DefaultProcMountType may be used.
        This requires the ProcMountType feature flag to be enabled.
        """
        return self.__allowed_proc_mount_types

    def runtime_class(self) -> Optional["RuntimeClassStrategyOptions"]:
        """
        runtimeClass is the strategy that will dictate the allowable RuntimeClasses for a pod.
        If this field is omitted, the pod's runtimeClassName field is unrestricted.
        Enforcement of this field depends on the RuntimeClass feature gate being enabled.
        """
        return self.__runtime_class


class PodSecurityPolicy(base.TypedObject, base.MetadataObject):
    """
    PodSecurityPolicy governs the ability to make requests that affect the Security Context
    that will be applied to a pod and container.
    Deprecated: use PodSecurityPolicy from policy API Group instead.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PodSecurityPolicySpec" = None,
    ):
        super().__init__(
            api_version="extensions/v1beta1",
            kind="PodSecurityPolicy",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PodSecurityPolicySpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["PodSecurityPolicySpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["PodSecurityPolicySpec"]:
        """
        spec defines the policy enforced.
        """
        return self.__spec


class ReplicaSetSpec(types.Object):
    """
    ReplicaSetSpec is the specification of a ReplicaSet.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        replicas: int = None,
        min_ready_seconds: int = None,
        selector: "metav1.LabelSelector" = None,
        template: "k8sv1.PodTemplateSpec" = None,
    ):
        super().__init__()
        self.__replicas = replicas if replicas is not None else 1
        self.__min_ready_seconds = min_ready_seconds
        self.__selector = selector
        self.__template = template if template is not None else k8sv1.PodTemplateSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas is not None:  # omit empty
            v["replicas"] = replicas
        min_ready_seconds = self.min_ready_seconds()
        check_type("min_ready_seconds", min_ready_seconds, Optional[int])
        if min_ready_seconds:  # omit empty
            v["minReadySeconds"] = min_ready_seconds
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        template = self.template()
        check_type("template", template, Optional["k8sv1.PodTemplateSpec"])
        v["template"] = template
        return v

    def replicas(self) -> Optional[int]:
        """
        Replicas is the number of desired replicas.
        This is a pointer to distinguish between explicit zero and unspecified.
        Defaults to 1.
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller/#what-is-a-replicationcontroller
        """
        return self.__replicas

    def min_ready_seconds(self) -> Optional[int]:
        """
        Minimum number of seconds for which a newly created pod should be ready
        without any of its container crashing, for it to be considered available.
        Defaults to 0 (pod will be considered available as soon as it is ready)
        """
        return self.__min_ready_seconds

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        Selector is a label query over pods that should match the replica count.
        If the selector is empty, it is defaulted to the labels present on the pod template.
        Label keys and values that must match in order to be controlled by this replica set.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
        """
        return self.__selector

    def template(self) -> Optional["k8sv1.PodTemplateSpec"]:
        """
        Template is the object that describes the pod that will be created if
        insufficient replicas are detected.
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#pod-template
        """
        return self.__template


class ReplicaSet(base.TypedObject, base.NamespacedMetadataObject):
    """
    DEPRECATED - This group version of ReplicaSet is deprecated by apps/v1beta2/ReplicaSet. See the release notes for
    more information.
    ReplicaSet ensures that a specified number of pod replicas are running at any given time.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ReplicaSetSpec" = None,
    ):
        super().__init__(
            api_version="extensions/v1beta1",
            kind="ReplicaSet",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ReplicaSetSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["ReplicaSetSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["ReplicaSetSpec"]:
        """
        Spec defines the specification of the desired behavior of the ReplicaSet.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class ReplicationControllerDummy(base.TypedObject):
    """
    Dummy definition
    """

    @context.scoped
    @typechecked
    def __init__(self):
        super().__init__(
            api_version="extensions/v1beta1", kind="ReplicationControllerDummy"
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        return v


class ScaleSpec(types.Object):
    """
    describes the attributes of a scale subresource
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
    represents a scaling request for a resource.
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
            api_version="extensions/v1beta1",
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
