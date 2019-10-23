# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional, Union

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec.k8s.apimachinery.meta import v1 as metav1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


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
    def __init__(self, pathPrefix: str = None, readOnly: bool = None):
        super().__init__()
        self.__pathPrefix = pathPrefix
        self.__readOnly = readOnly

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pathPrefix = self.pathPrefix()
        check_type("pathPrefix", pathPrefix, Optional[str])
        if pathPrefix:  # omit empty
            v["pathPrefix"] = pathPrefix
        readOnly = self.readOnly()
        check_type("readOnly", readOnly, Optional[bool])
        if readOnly:  # omit empty
            v["readOnly"] = readOnly
        return v

    def pathPrefix(self) -> Optional[str]:
        """
        pathPrefix is the path prefix that the host volume must match.
        It does not support `*`.
        Trailing slashes are trimmed when validating the path prefix with a host path.
        
        Examples:
        `/foo` would allow `/foo`, `/foo/` and `/foo/bar`
        `/foo` would not allow `/food` or `/etc/foo`
        """
        return self.__pathPrefix

    def readOnly(self) -> Optional[bool]:
        """
        when set to true, will allow host volumes matching the pathPrefix only if all volume mounts are readOnly.
        """
        return self.__readOnly


class RollingUpdateDaemonSet(types.Object):
    """
    Spec to control the desired behavior of daemon set rolling update.
    """

    @context.scoped
    @typechecked
    def __init__(self, maxUnavailable: Union[int, str] = None):
        super().__init__()
        self.__maxUnavailable = maxUnavailable

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        maxUnavailable = self.maxUnavailable()
        check_type("maxUnavailable", maxUnavailable, Optional[Union[int, str]])
        if maxUnavailable is not None:  # omit empty
            v["maxUnavailable"] = maxUnavailable
        return v

    def maxUnavailable(self) -> Optional[Union[int, str]]:
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
        return self.__maxUnavailable


class DaemonSetUpdateStrategy(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        type: DaemonSetUpdateStrategyType = DaemonSetUpdateStrategyType["OnDelete"],
        rollingUpdate: "RollingUpdateDaemonSet" = None,
    ):
        super().__init__()
        self.__type = type
        self.__rollingUpdate = rollingUpdate

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[DaemonSetUpdateStrategyType])
        if type:  # omit empty
            v["type"] = type
        rollingUpdate = self.rollingUpdate()
        check_type("rollingUpdate", rollingUpdate, Optional["RollingUpdateDaemonSet"])
        if rollingUpdate is not None:  # omit empty
            v["rollingUpdate"] = rollingUpdate
        return v

    def type(self) -> Optional[DaemonSetUpdateStrategyType]:
        """
        Type of daemon set update. Can be "RollingUpdate" or "OnDelete".
        Default is OnDelete.
        """
        return self.__type

    def rollingUpdate(self) -> Optional["RollingUpdateDaemonSet"]:
        """
        Rolling update config params. Present only if type = "RollingUpdate".
        ---
        TODO: Update this to follow our convention for oneOf, whatever we decide it
        to be. Same as Deployment `strategy.rollingUpdate`.
        See https://github.com/kubernetes/kubernetes/issues/35345
        """
        return self.__rollingUpdate


class DaemonSetSpec(types.Object):
    """
    DaemonSetSpec is the specification of a daemon set.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        selector: "metav1.LabelSelector" = None,
        template: "corev1.PodTemplateSpec" = None,
        updateStrategy: "DaemonSetUpdateStrategy" = None,
        minReadySeconds: int = None,
        revisionHistoryLimit: int = None,
    ):
        super().__init__()
        self.__selector = selector
        self.__template = template if template is not None else corev1.PodTemplateSpec()
        self.__updateStrategy = (
            updateStrategy if updateStrategy is not None else DaemonSetUpdateStrategy()
        )
        self.__minReadySeconds = minReadySeconds
        self.__revisionHistoryLimit = (
            revisionHistoryLimit if revisionHistoryLimit is not None else 10
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        template = self.template()
        check_type("template", template, "corev1.PodTemplateSpec")
        v["template"] = template
        updateStrategy = self.updateStrategy()
        check_type(
            "updateStrategy", updateStrategy, Optional["DaemonSetUpdateStrategy"]
        )
        v["updateStrategy"] = updateStrategy
        minReadySeconds = self.minReadySeconds()
        check_type("minReadySeconds", minReadySeconds, Optional[int])
        if minReadySeconds:  # omit empty
            v["minReadySeconds"] = minReadySeconds
        revisionHistoryLimit = self.revisionHistoryLimit()
        check_type("revisionHistoryLimit", revisionHistoryLimit, Optional[int])
        if revisionHistoryLimit is not None:  # omit empty
            v["revisionHistoryLimit"] = revisionHistoryLimit
        return v

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        A label query over pods that are managed by the daemon set.
        Must match in order to be controlled.
        If empty, defaulted to labels on Pod template.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
        """
        return self.__selector

    def template(self) -> "corev1.PodTemplateSpec":
        """
        An object that describes the pod that will be created.
        The DaemonSet will create exactly one copy of this pod on every node
        that matches the template's node selector (or on every node if no node
        selector is specified).
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/replicationcontroller#pod-template
        """
        return self.__template

    def updateStrategy(self) -> Optional["DaemonSetUpdateStrategy"]:
        """
        An update strategy to replace existing DaemonSet pods with new pods.
        """
        return self.__updateStrategy

    def minReadySeconds(self) -> Optional[int]:
        """
        The minimum number of seconds for which a newly created DaemonSet pod should
        be ready without any of its container crashing, for it to be considered
        available. Defaults to 0 (pod will be considered available as soon as it
        is ready).
        """
        return self.__minReadySeconds

    def revisionHistoryLimit(self) -> Optional[int]:
        """
        The number of old history to retain to allow rollback.
        This is a pointer to distinguish between explicit zero and not specified.
        Defaults to 10.
        """
        return self.__revisionHistoryLimit


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
            apiVersion="extensions/v1beta1",
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
        self, maxUnavailable: Union[int, str] = None, maxSurge: Union[int, str] = None
    ):
        super().__init__()
        self.__maxUnavailable = maxUnavailable if maxUnavailable is not None else 1
        self.__maxSurge = maxSurge if maxSurge is not None else 1

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        maxUnavailable = self.maxUnavailable()
        check_type("maxUnavailable", maxUnavailable, Optional[Union[int, str]])
        if maxUnavailable is not None:  # omit empty
            v["maxUnavailable"] = maxUnavailable
        maxSurge = self.maxSurge()
        check_type("maxSurge", maxSurge, Optional[Union[int, str]])
        if maxSurge is not None:  # omit empty
            v["maxSurge"] = maxSurge
        return v

    def maxUnavailable(self) -> Optional[Union[int, str]]:
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
        return self.__maxUnavailable

    def maxSurge(self) -> Optional[Union[int, str]]:
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
        return self.__maxSurge


class DeploymentStrategy(types.Object):
    """
    DeploymentStrategy describes how to replace existing pods with new ones.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: DeploymentStrategyType = DeploymentStrategyType["RollingUpdate"],
        rollingUpdate: "RollingUpdateDeployment" = None,
    ):
        super().__init__()
        self.__type = type
        self.__rollingUpdate = (
            rollingUpdate if rollingUpdate is not None else RollingUpdateDeployment()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[DeploymentStrategyType])
        if type:  # omit empty
            v["type"] = type
        rollingUpdate = self.rollingUpdate()
        check_type("rollingUpdate", rollingUpdate, Optional["RollingUpdateDeployment"])
        if rollingUpdate is not None:  # omit empty
            v["rollingUpdate"] = rollingUpdate
        return v

    def type(self) -> Optional[DeploymentStrategyType]:
        """
        Type of deployment. Can be "Recreate" or "RollingUpdate". Default is RollingUpdate.
        """
        return self.__type

    def rollingUpdate(self) -> Optional["RollingUpdateDeployment"]:
        """
        Rolling update config params. Present only if DeploymentStrategyType =
        RollingUpdate.
        ---
        TODO: Update this to follow our convention for oneOf, whatever we decide it
        to be.
        """
        return self.__rollingUpdate


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
        template: "corev1.PodTemplateSpec" = None,
        strategy: "DeploymentStrategy" = None,
        minReadySeconds: int = None,
        revisionHistoryLimit: int = None,
        paused: bool = None,
        progressDeadlineSeconds: int = None,
    ):
        super().__init__()
        self.__replicas = replicas if replicas is not None else 1
        self.__selector = selector
        self.__template = template if template is not None else corev1.PodTemplateSpec()
        self.__strategy = strategy if strategy is not None else DeploymentStrategy()
        self.__minReadySeconds = minReadySeconds
        self.__revisionHistoryLimit = (
            revisionHistoryLimit if revisionHistoryLimit is not None else 2147483647
        )
        self.__paused = paused
        self.__progressDeadlineSeconds = (
            progressDeadlineSeconds
            if progressDeadlineSeconds is not None
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
        check_type("template", template, "corev1.PodTemplateSpec")
        v["template"] = template
        strategy = self.strategy()
        check_type("strategy", strategy, Optional["DeploymentStrategy"])
        v["strategy"] = strategy
        minReadySeconds = self.minReadySeconds()
        check_type("minReadySeconds", minReadySeconds, Optional[int])
        if minReadySeconds:  # omit empty
            v["minReadySeconds"] = minReadySeconds
        revisionHistoryLimit = self.revisionHistoryLimit()
        check_type("revisionHistoryLimit", revisionHistoryLimit, Optional[int])
        if revisionHistoryLimit is not None:  # omit empty
            v["revisionHistoryLimit"] = revisionHistoryLimit
        paused = self.paused()
        check_type("paused", paused, Optional[bool])
        if paused:  # omit empty
            v["paused"] = paused
        progressDeadlineSeconds = self.progressDeadlineSeconds()
        check_type("progressDeadlineSeconds", progressDeadlineSeconds, Optional[int])
        if progressDeadlineSeconds is not None:  # omit empty
            v["progressDeadlineSeconds"] = progressDeadlineSeconds
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

    def template(self) -> "corev1.PodTemplateSpec":
        """
        Template describes the pods that will be created.
        """
        return self.__template

    def strategy(self) -> Optional["DeploymentStrategy"]:
        """
        The deployment strategy to use to replace existing pods with new ones.
        """
        return self.__strategy

    def minReadySeconds(self) -> Optional[int]:
        """
        Minimum number of seconds for which a newly created pod should be ready
        without any of its container crashing, for it to be considered available.
        Defaults to 0 (pod will be considered available as soon as it is ready)
        """
        return self.__minReadySeconds

    def revisionHistoryLimit(self) -> Optional[int]:
        """
        The number of old ReplicaSets to retain to allow rollback.
        This is a pointer to distinguish between explicit zero and not specified.
        This is set to the max value of int32 (i.e. 2147483647) by default, which
        means "retaining all old RelicaSets".
        """
        return self.__revisionHistoryLimit

    def paused(self) -> Optional[bool]:
        """
        Indicates that the deployment is paused and will not be processed by the
        deployment controller.
        """
        return self.__paused

    def progressDeadlineSeconds(self) -> Optional[int]:
        """
        The maximum time in seconds for a deployment to make progress before it
        is considered to be failed. The deployment controller will continue to
        process failed deployments and a condition with a ProgressDeadlineExceeded
        reason will be surfaced in the deployment status. Note that progress will
        not be estimated during the time a deployment is paused. This is set to
        the max value of int32 (i.e. 2147483647) by default, which means "no deadline".
        """
        return self.__progressDeadlineSeconds


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
            apiVersion="extensions/v1beta1",
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
        updatedAnnotations: Dict[str, str] = None,
        rollbackTo: "RollbackConfig" = None,
    ):
        super().__init__(apiVersion="extensions/v1beta1", kind="DeploymentRollback")
        self.__name = name
        self.__updatedAnnotations = (
            updatedAnnotations if updatedAnnotations is not None else {}
        )
        self.__rollbackTo = rollbackTo if rollbackTo is not None else RollbackConfig()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        updatedAnnotations = self.updatedAnnotations()
        check_type("updatedAnnotations", updatedAnnotations, Optional[Dict[str, str]])
        if updatedAnnotations:  # omit empty
            v["updatedAnnotations"] = updatedAnnotations
        rollbackTo = self.rollbackTo()
        check_type("rollbackTo", rollbackTo, "RollbackConfig")
        v["rollbackTo"] = rollbackTo
        return v

    def name(self) -> str:
        """
        Required: This must match the Name of a deployment.
        """
        return self.__name

    def updatedAnnotations(self) -> Optional[Dict[str, str]]:
        """
        The annotations to be updated to a deployment
        """
        return self.__updatedAnnotations

    def rollbackTo(self) -> "RollbackConfig":
        """
        The config of this deployment rollback.
        """
        return self.__rollbackTo


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
    def __init__(self, serviceName: str = "", servicePort: Union[int, str] = None):
        super().__init__()
        self.__serviceName = serviceName
        self.__servicePort = servicePort if servicePort is not None else 0

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        serviceName = self.serviceName()
        check_type("serviceName", serviceName, str)
        v["serviceName"] = serviceName
        servicePort = self.servicePort()
        check_type("servicePort", servicePort, Union[int, str])
        v["servicePort"] = servicePort
        return v

    def serviceName(self) -> str:
        """
        Specifies the name of the referenced service.
        """
        return self.__serviceName

    def servicePort(self) -> Union[int, str]:
        """
        Specifies the port of the referenced service.
        """
        return self.__servicePort


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
    def __init__(self, host: str = None, ingressRuleValue: "IngressRuleValue" = None):
        super().__init__()
        self.__host = host
        self.__ingressRuleValue = (
            ingressRuleValue if ingressRuleValue is not None else IngressRuleValue()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        host = self.host()
        check_type("host", host, Optional[str])
        if host:  # omit empty
            v["host"] = host
        ingressRuleValue = self.ingressRuleValue()
        check_type("ingressRuleValue", ingressRuleValue, Optional["IngressRuleValue"])
        v.update(ingressRuleValue._root())  # inline
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

    def ingressRuleValue(self) -> Optional["IngressRuleValue"]:
        """
        IngressRuleValue represents a rule to route requests for this IngressRule.
        If unspecified, the rule defaults to a http catch-all. Whether that sends
        just traffic matching the host to the default backend or all traffic to the
        default backend, is left to the controller fulfilling the Ingress. Http is
        currently the only supported IngressRuleValue.
        """
        return self.__ingressRuleValue


class IngressTLS(types.Object):
    """
    IngressTLS describes the transport layer security associated with an Ingress.
    """

    @context.scoped
    @typechecked
    def __init__(self, hosts: List[str] = None, secretName: str = None):
        super().__init__()
        self.__hosts = hosts if hosts is not None else []
        self.__secretName = secretName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        hosts = self.hosts()
        check_type("hosts", hosts, Optional[List[str]])
        if hosts:  # omit empty
            v["hosts"] = hosts
        secretName = self.secretName()
        check_type("secretName", secretName, Optional[str])
        if secretName:  # omit empty
            v["secretName"] = secretName
        return v

    def hosts(self) -> Optional[List[str]]:
        """
        Hosts are a list of hosts included in the TLS certificate. The values in
        this list must match the name/s used in the tlsSecret. Defaults to the
        wildcard host setting for the loadbalancer controller fulfilling this
        Ingress, if left unspecified.
        """
        return self.__hosts

    def secretName(self) -> Optional[str]:
        """
        SecretName is the name of the secret used to terminate SSL traffic on 443.
        Field is left optional to allow SSL routing based on SNI hostname alone.
        If the SNI host in a listener conflicts with the "Host" header field used
        by an IngressRule, the SNI host is used for termination and value of the
        Host header is used for routing.
        """
        return self.__secretName


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
            apiVersion="extensions/v1beta1",
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
        podSelector: "metav1.LabelSelector" = None,
        namespaceSelector: "metav1.LabelSelector" = None,
        ipBlock: "IPBlock" = None,
    ):
        super().__init__()
        self.__podSelector = podSelector
        self.__namespaceSelector = namespaceSelector
        self.__ipBlock = ipBlock

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        podSelector = self.podSelector()
        check_type("podSelector", podSelector, Optional["metav1.LabelSelector"])
        if podSelector is not None:  # omit empty
            v["podSelector"] = podSelector
        namespaceSelector = self.namespaceSelector()
        check_type(
            "namespaceSelector", namespaceSelector, Optional["metav1.LabelSelector"]
        )
        if namespaceSelector is not None:  # omit empty
            v["namespaceSelector"] = namespaceSelector
        ipBlock = self.ipBlock()
        check_type("ipBlock", ipBlock, Optional["IPBlock"])
        if ipBlock is not None:  # omit empty
            v["ipBlock"] = ipBlock
        return v

    def podSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        This is a label selector which selects Pods. This field follows standard label
        selector semantics; if present but empty, it selects all pods.
        
        If NamespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
        the Pods matching PodSelector in the Namespaces selected by NamespaceSelector.
        Otherwise it selects the Pods matching PodSelector in the policy's own Namespace.
        """
        return self.__podSelector

    def namespaceSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        Selects Namespaces using cluster-scoped labels. This field follows standard label
        selector semantics; if present but empty, it selects all namespaces.
        
        If PodSelector is also set, then the NetworkPolicyPeer as a whole selects
        the Pods matching PodSelector in the Namespaces selected by NamespaceSelector.
        Otherwise it selects all Pods in the Namespaces selected by NamespaceSelector.
        """
        return self.__namespaceSelector

    def ipBlock(self) -> Optional["IPBlock"]:
        """
        IPBlock defines policy on a particular IPBlock. If this field is set then
        neither of the other fields can be.
        """
        return self.__ipBlock


class NetworkPolicyPort(types.Object):
    """
    DEPRECATED 1.9 - This group version of NetworkPolicyPort is deprecated by networking/v1/NetworkPolicyPort.
    """

    @context.scoped
    @typechecked
    def __init__(self, protocol: corev1.Protocol = None, port: Union[int, str] = None):
        super().__init__()
        self.__protocol = protocol
        self.__port = port

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        protocol = self.protocol()
        check_type("protocol", protocol, Optional[corev1.Protocol])
        if protocol is not None:  # omit empty
            v["protocol"] = protocol
        port = self.port()
        check_type("port", port, Optional[Union[int, str]])
        if port is not None:  # omit empty
            v["port"] = port
        return v

    def protocol(self) -> Optional[corev1.Protocol]:
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
        podSelector: "metav1.LabelSelector" = None,
        ingress: List["NetworkPolicyIngressRule"] = None,
        egress: List["NetworkPolicyEgressRule"] = None,
        policyTypes: List[PolicyType] = None,
    ):
        super().__init__()
        self.__podSelector = (
            podSelector if podSelector is not None else metav1.LabelSelector()
        )
        self.__ingress = ingress if ingress is not None else []
        self.__egress = egress if egress is not None else []
        self.__policyTypes = policyTypes if policyTypes is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        podSelector = self.podSelector()
        check_type("podSelector", podSelector, "metav1.LabelSelector")
        v["podSelector"] = podSelector
        ingress = self.ingress()
        check_type("ingress", ingress, Optional[List["NetworkPolicyIngressRule"]])
        if ingress:  # omit empty
            v["ingress"] = ingress
        egress = self.egress()
        check_type("egress", egress, Optional[List["NetworkPolicyEgressRule"]])
        if egress:  # omit empty
            v["egress"] = egress
        policyTypes = self.policyTypes()
        check_type("policyTypes", policyTypes, Optional[List[PolicyType]])
        if policyTypes:  # omit empty
            v["policyTypes"] = policyTypes
        return v

    def podSelector(self) -> "metav1.LabelSelector":
        """
        Selects the pods to which this NetworkPolicy object applies.  The array of ingress rules
        is applied to any pods selected by this field. Multiple network policies can select the
        same set of pods.  In this case, the ingress rules for each are combined additively.
        This field is NOT optional and follows standard label selector semantics.
        An empty podSelector matches all pods in this namespace.
        """
        return self.__podSelector

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

    def policyTypes(self) -> Optional[List[PolicyType]]:
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
        return self.__policyTypes


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
            apiVersion="extensions/v1beta1",
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
        allowedRuntimeClassNames: List[str] = None,
        defaultRuntimeClassName: str = None,
    ):
        super().__init__()
        self.__allowedRuntimeClassNames = (
            allowedRuntimeClassNames if allowedRuntimeClassNames is not None else []
        )
        self.__defaultRuntimeClassName = defaultRuntimeClassName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        allowedRuntimeClassNames = self.allowedRuntimeClassNames()
        check_type("allowedRuntimeClassNames", allowedRuntimeClassNames, List[str])
        v["allowedRuntimeClassNames"] = allowedRuntimeClassNames
        defaultRuntimeClassName = self.defaultRuntimeClassName()
        check_type("defaultRuntimeClassName", defaultRuntimeClassName, Optional[str])
        if defaultRuntimeClassName is not None:  # omit empty
            v["defaultRuntimeClassName"] = defaultRuntimeClassName
        return v

    def allowedRuntimeClassNames(self) -> List[str]:
        """
        allowedRuntimeClassNames is a whitelist of RuntimeClass names that may be specified on a pod.
        A value of "*" means that any RuntimeClass name is allowed, and must be the only item in the
        list. An empty list requires the RuntimeClassName field to be unset.
        """
        return self.__allowedRuntimeClassNames

    def defaultRuntimeClassName(self) -> Optional[str]:
        """
        defaultRuntimeClassName is the default RuntimeClassName to set on the pod.
        The default MUST be allowed by the allowedRuntimeClassNames list.
        A value of nil does not mutate the Pod.
        """
        return self.__defaultRuntimeClassName


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
        seLinuxOptions: "corev1.SELinuxOptions" = None,
    ):
        super().__init__()
        self.__rule = rule
        self.__seLinuxOptions = seLinuxOptions

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        rule = self.rule()
        check_type("rule", rule, SELinuxStrategy)
        v["rule"] = rule
        seLinuxOptions = self.seLinuxOptions()
        check_type("seLinuxOptions", seLinuxOptions, Optional["corev1.SELinuxOptions"])
        if seLinuxOptions is not None:  # omit empty
            v["seLinuxOptions"] = seLinuxOptions
        return v

    def rule(self) -> SELinuxStrategy:
        """
        rule is the strategy that will dictate the allowable labels that may be set.
        """
        return self.__rule

    def seLinuxOptions(self) -> Optional["corev1.SELinuxOptions"]:
        """
        seLinuxOptions required to run as; required for MustRunAs
        More info: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
        """
        return self.__seLinuxOptions


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
        defaultAddCapabilities: List[corev1.Capability] = None,
        requiredDropCapabilities: List[corev1.Capability] = None,
        allowedCapabilities: List[corev1.Capability] = None,
        volumes: List[FSType] = None,
        hostNetwork: bool = None,
        hostPorts: List["HostPortRange"] = None,
        hostPID: bool = None,
        hostIPC: bool = None,
        seLinux: "SELinuxStrategyOptions" = None,
        runAsUser: "RunAsUserStrategyOptions" = None,
        runAsGroup: "RunAsGroupStrategyOptions" = None,
        supplementalGroups: "SupplementalGroupsStrategyOptions" = None,
        fsGroup: "FSGroupStrategyOptions" = None,
        readOnlyRootFilesystem: bool = None,
        defaultAllowPrivilegeEscalation: bool = None,
        allowPrivilegeEscalation: bool = None,
        allowedHostPaths: List["AllowedHostPath"] = None,
        allowedFlexVolumes: List["AllowedFlexVolume"] = None,
        allowedCSIDrivers: Dict[str, "AllowedCSIDriver"] = None,
        allowedUnsafeSysctls: List[str] = None,
        forbiddenSysctls: List[str] = None,
        allowedProcMountTypes: List[corev1.ProcMountType] = None,
        runtimeClass: "RuntimeClassStrategyOptions" = None,
    ):
        super().__init__()
        self.__privileged = privileged
        self.__defaultAddCapabilities = (
            defaultAddCapabilities if defaultAddCapabilities is not None else []
        )
        self.__requiredDropCapabilities = (
            requiredDropCapabilities if requiredDropCapabilities is not None else []
        )
        self.__allowedCapabilities = (
            allowedCapabilities if allowedCapabilities is not None else []
        )
        self.__volumes = volumes if volumes is not None else []
        self.__hostNetwork = hostNetwork
        self.__hostPorts = hostPorts if hostPorts is not None else []
        self.__hostPID = hostPID
        self.__hostIPC = hostIPC
        self.__seLinux = seLinux if seLinux is not None else SELinuxStrategyOptions()
        self.__runAsUser = (
            runAsUser if runAsUser is not None else RunAsUserStrategyOptions()
        )
        self.__runAsGroup = runAsGroup
        self.__supplementalGroups = (
            supplementalGroups
            if supplementalGroups is not None
            else SupplementalGroupsStrategyOptions()
        )
        self.__fsGroup = fsGroup if fsGroup is not None else FSGroupStrategyOptions()
        self.__readOnlyRootFilesystem = readOnlyRootFilesystem
        self.__defaultAllowPrivilegeEscalation = defaultAllowPrivilegeEscalation
        self.__allowPrivilegeEscalation = (
            allowPrivilegeEscalation if allowPrivilegeEscalation is not None else True
        )
        self.__allowedHostPaths = (
            allowedHostPaths if allowedHostPaths is not None else []
        )
        self.__allowedFlexVolumes = (
            allowedFlexVolumes if allowedFlexVolumes is not None else []
        )
        self.__allowedCSIDrivers = (
            allowedCSIDrivers if allowedCSIDrivers is not None else {}
        )
        self.__allowedUnsafeSysctls = (
            allowedUnsafeSysctls if allowedUnsafeSysctls is not None else []
        )
        self.__forbiddenSysctls = (
            forbiddenSysctls if forbiddenSysctls is not None else []
        )
        self.__allowedProcMountTypes = (
            allowedProcMountTypes if allowedProcMountTypes is not None else []
        )
        self.__runtimeClass = runtimeClass

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        privileged = self.privileged()
        check_type("privileged", privileged, Optional[bool])
        if privileged:  # omit empty
            v["privileged"] = privileged
        defaultAddCapabilities = self.defaultAddCapabilities()
        check_type(
            "defaultAddCapabilities",
            defaultAddCapabilities,
            Optional[List[corev1.Capability]],
        )
        if defaultAddCapabilities:  # omit empty
            v["defaultAddCapabilities"] = defaultAddCapabilities
        requiredDropCapabilities = self.requiredDropCapabilities()
        check_type(
            "requiredDropCapabilities",
            requiredDropCapabilities,
            Optional[List[corev1.Capability]],
        )
        if requiredDropCapabilities:  # omit empty
            v["requiredDropCapabilities"] = requiredDropCapabilities
        allowedCapabilities = self.allowedCapabilities()
        check_type(
            "allowedCapabilities",
            allowedCapabilities,
            Optional[List[corev1.Capability]],
        )
        if allowedCapabilities:  # omit empty
            v["allowedCapabilities"] = allowedCapabilities
        volumes = self.volumes()
        check_type("volumes", volumes, Optional[List[FSType]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        hostNetwork = self.hostNetwork()
        check_type("hostNetwork", hostNetwork, Optional[bool])
        if hostNetwork:  # omit empty
            v["hostNetwork"] = hostNetwork
        hostPorts = self.hostPorts()
        check_type("hostPorts", hostPorts, Optional[List["HostPortRange"]])
        if hostPorts:  # omit empty
            v["hostPorts"] = hostPorts
        hostPID = self.hostPID()
        check_type("hostPID", hostPID, Optional[bool])
        if hostPID:  # omit empty
            v["hostPID"] = hostPID
        hostIPC = self.hostIPC()
        check_type("hostIPC", hostIPC, Optional[bool])
        if hostIPC:  # omit empty
            v["hostIPC"] = hostIPC
        seLinux = self.seLinux()
        check_type("seLinux", seLinux, "SELinuxStrategyOptions")
        v["seLinux"] = seLinux
        runAsUser = self.runAsUser()
        check_type("runAsUser", runAsUser, "RunAsUserStrategyOptions")
        v["runAsUser"] = runAsUser
        runAsGroup = self.runAsGroup()
        check_type("runAsGroup", runAsGroup, Optional["RunAsGroupStrategyOptions"])
        if runAsGroup is not None:  # omit empty
            v["runAsGroup"] = runAsGroup
        supplementalGroups = self.supplementalGroups()
        check_type(
            "supplementalGroups",
            supplementalGroups,
            "SupplementalGroupsStrategyOptions",
        )
        v["supplementalGroups"] = supplementalGroups
        fsGroup = self.fsGroup()
        check_type("fsGroup", fsGroup, "FSGroupStrategyOptions")
        v["fsGroup"] = fsGroup
        readOnlyRootFilesystem = self.readOnlyRootFilesystem()
        check_type("readOnlyRootFilesystem", readOnlyRootFilesystem, Optional[bool])
        if readOnlyRootFilesystem:  # omit empty
            v["readOnlyRootFilesystem"] = readOnlyRootFilesystem
        defaultAllowPrivilegeEscalation = self.defaultAllowPrivilegeEscalation()
        check_type(
            "defaultAllowPrivilegeEscalation",
            defaultAllowPrivilegeEscalation,
            Optional[bool],
        )
        if defaultAllowPrivilegeEscalation is not None:  # omit empty
            v["defaultAllowPrivilegeEscalation"] = defaultAllowPrivilegeEscalation
        allowPrivilegeEscalation = self.allowPrivilegeEscalation()
        check_type("allowPrivilegeEscalation", allowPrivilegeEscalation, Optional[bool])
        if allowPrivilegeEscalation is not None:  # omit empty
            v["allowPrivilegeEscalation"] = allowPrivilegeEscalation
        allowedHostPaths = self.allowedHostPaths()
        check_type(
            "allowedHostPaths", allowedHostPaths, Optional[List["AllowedHostPath"]]
        )
        if allowedHostPaths:  # omit empty
            v["allowedHostPaths"] = allowedHostPaths
        allowedFlexVolumes = self.allowedFlexVolumes()
        check_type(
            "allowedFlexVolumes",
            allowedFlexVolumes,
            Optional[List["AllowedFlexVolume"]],
        )
        if allowedFlexVolumes:  # omit empty
            v["allowedFlexVolumes"] = allowedFlexVolumes
        allowedCSIDrivers = self.allowedCSIDrivers()
        check_type(
            "allowedCSIDrivers",
            allowedCSIDrivers,
            Optional[Dict[str, "AllowedCSIDriver"]],
        )
        if allowedCSIDrivers:  # omit empty
            v["allowedCSIDrivers"] = allowedCSIDrivers.values()  # named list
        allowedUnsafeSysctls = self.allowedUnsafeSysctls()
        check_type("allowedUnsafeSysctls", allowedUnsafeSysctls, Optional[List[str]])
        if allowedUnsafeSysctls:  # omit empty
            v["allowedUnsafeSysctls"] = allowedUnsafeSysctls
        forbiddenSysctls = self.forbiddenSysctls()
        check_type("forbiddenSysctls", forbiddenSysctls, Optional[List[str]])
        if forbiddenSysctls:  # omit empty
            v["forbiddenSysctls"] = forbiddenSysctls
        allowedProcMountTypes = self.allowedProcMountTypes()
        check_type(
            "allowedProcMountTypes",
            allowedProcMountTypes,
            Optional[List[corev1.ProcMountType]],
        )
        if allowedProcMountTypes:  # omit empty
            v["allowedProcMountTypes"] = allowedProcMountTypes
        runtimeClass = self.runtimeClass()
        check_type(
            "runtimeClass", runtimeClass, Optional["RuntimeClassStrategyOptions"]
        )
        if runtimeClass is not None:  # omit empty
            v["runtimeClass"] = runtimeClass
        return v

    def privileged(self) -> Optional[bool]:
        """
        privileged determines if a pod can request to be run as privileged.
        """
        return self.__privileged

    def defaultAddCapabilities(self) -> Optional[List[corev1.Capability]]:
        """
        defaultAddCapabilities is the default set of capabilities that will be added to the container
        unless the pod spec specifically drops the capability.  You may not list a capability in both
        defaultAddCapabilities and requiredDropCapabilities. Capabilities added here are implicitly
        allowed, and need not be included in the allowedCapabilities list.
        """
        return self.__defaultAddCapabilities

    def requiredDropCapabilities(self) -> Optional[List[corev1.Capability]]:
        """
        requiredDropCapabilities are the capabilities that will be dropped from the container.  These
        are required to be dropped and cannot be added.
        """
        return self.__requiredDropCapabilities

    def allowedCapabilities(self) -> Optional[List[corev1.Capability]]:
        """
        allowedCapabilities is a list of capabilities that can be requested to add to the container.
        Capabilities in this field may be added at the pod author's discretion.
        You must not list a capability in both allowedCapabilities and requiredDropCapabilities.
        """
        return self.__allowedCapabilities

    def volumes(self) -> Optional[List[FSType]]:
        """
        volumes is a white list of allowed volume plugins. Empty indicates that
        no volumes may be used. To allow all volumes you may use '*'.
        """
        return self.__volumes

    def hostNetwork(self) -> Optional[bool]:
        """
        hostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
        """
        return self.__hostNetwork

    def hostPorts(self) -> Optional[List["HostPortRange"]]:
        """
        hostPorts determines which host port ranges are allowed to be exposed.
        """
        return self.__hostPorts

    def hostPID(self) -> Optional[bool]:
        """
        hostPID determines if the policy allows the use of HostPID in the pod spec.
        """
        return self.__hostPID

    def hostIPC(self) -> Optional[bool]:
        """
        hostIPC determines if the policy allows the use of HostIPC in the pod spec.
        """
        return self.__hostIPC

    def seLinux(self) -> "SELinuxStrategyOptions":
        """
        seLinux is the strategy that will dictate the allowable labels that may be set.
        """
        return self.__seLinux

    def runAsUser(self) -> "RunAsUserStrategyOptions":
        """
        runAsUser is the strategy that will dictate the allowable RunAsUser values that may be set.
        """
        return self.__runAsUser

    def runAsGroup(self) -> Optional["RunAsGroupStrategyOptions"]:
        """
        RunAsGroup is the strategy that will dictate the allowable RunAsGroup values that may be set.
        If this field is omitted, the pod's RunAsGroup can take any value. This field requires the
        RunAsGroup feature gate to be enabled.
        """
        return self.__runAsGroup

    def supplementalGroups(self) -> "SupplementalGroupsStrategyOptions":
        """
        supplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
        """
        return self.__supplementalGroups

    def fsGroup(self) -> "FSGroupStrategyOptions":
        """
        fsGroup is the strategy that will dictate what fs group is used by the SecurityContext.
        """
        return self.__fsGroup

    def readOnlyRootFilesystem(self) -> Optional[bool]:
        """
        readOnlyRootFilesystem when set to true will force containers to run with a read only root file
        system.  If the container specifically requests to run with a non-read only root file system
        the PSP should deny the pod.
        If set to false the container may run with a read only root file system if it wishes but it
        will not be forced to.
        """
        return self.__readOnlyRootFilesystem

    def defaultAllowPrivilegeEscalation(self) -> Optional[bool]:
        """
        defaultAllowPrivilegeEscalation controls the default setting for whether a
        process can gain more privileges than its parent process.
        """
        return self.__defaultAllowPrivilegeEscalation

    def allowPrivilegeEscalation(self) -> Optional[bool]:
        """
        allowPrivilegeEscalation determines if a pod can request to allow
        privilege escalation. If unspecified, defaults to true.
        """
        return self.__allowPrivilegeEscalation

    def allowedHostPaths(self) -> Optional[List["AllowedHostPath"]]:
        """
        allowedHostPaths is a white list of allowed host paths. Empty indicates
        that all host paths may be used.
        """
        return self.__allowedHostPaths

    def allowedFlexVolumes(self) -> Optional[List["AllowedFlexVolume"]]:
        """
        allowedFlexVolumes is a whitelist of allowed Flexvolumes.  Empty or nil indicates that all
        Flexvolumes may be used.  This parameter is effective only when the usage of the Flexvolumes
        is allowed in the "volumes" field.
        """
        return self.__allowedFlexVolumes

    def allowedCSIDrivers(self) -> Optional[Dict[str, "AllowedCSIDriver"]]:
        """
        AllowedCSIDrivers is a whitelist of inline CSI drivers that must be explicitly set to be embedded within a pod spec.
        An empty value indicates that any CSI driver can be used for inline ephemeral volumes.
        """
        return self.__allowedCSIDrivers

    def allowedUnsafeSysctls(self) -> Optional[List[str]]:
        """
        allowedUnsafeSysctls is a list of explicitly allowed unsafe sysctls, defaults to none.
        Each entry is either a plain sysctl name or ends in "*" in which case it is considered
        as a prefix of allowed sysctls. Single * means all unsafe sysctls are allowed.
        Kubelet has to whitelist all allowed unsafe sysctls explicitly to avoid rejection.
        
        Examples:
        e.g. "foo/*" allows "foo/bar", "foo/baz", etc.
        e.g. "foo.*" allows "foo.bar", "foo.baz", etc.
        """
        return self.__allowedUnsafeSysctls

    def forbiddenSysctls(self) -> Optional[List[str]]:
        """
        forbiddenSysctls is a list of explicitly forbidden sysctls, defaults to none.
        Each entry is either a plain sysctl name or ends in "*" in which case it is considered
        as a prefix of forbidden sysctls. Single * means all sysctls are forbidden.
        
        Examples:
        e.g. "foo/*" forbids "foo/bar", "foo/baz", etc.
        e.g. "foo.*" forbids "foo.bar", "foo.baz", etc.
        """
        return self.__forbiddenSysctls

    def allowedProcMountTypes(self) -> Optional[List[corev1.ProcMountType]]:
        """
        AllowedProcMountTypes is a whitelist of allowed ProcMountTypes.
        Empty or nil indicates that only the DefaultProcMountType may be used.
        This requires the ProcMountType feature flag to be enabled.
        """
        return self.__allowedProcMountTypes

    def runtimeClass(self) -> Optional["RuntimeClassStrategyOptions"]:
        """
        runtimeClass is the strategy that will dictate the allowable RuntimeClasses for a pod.
        If this field is omitted, the pod's runtimeClassName field is unrestricted.
        Enforcement of this field depends on the RuntimeClass feature gate being enabled.
        """
        return self.__runtimeClass


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
            apiVersion="extensions/v1beta1",
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
        minReadySeconds: int = None,
        selector: "metav1.LabelSelector" = None,
        template: "corev1.PodTemplateSpec" = None,
    ):
        super().__init__()
        self.__replicas = replicas if replicas is not None else 1
        self.__minReadySeconds = minReadySeconds
        self.__selector = selector
        self.__template = template if template is not None else corev1.PodTemplateSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas is not None:  # omit empty
            v["replicas"] = replicas
        minReadySeconds = self.minReadySeconds()
        check_type("minReadySeconds", minReadySeconds, Optional[int])
        if minReadySeconds:  # omit empty
            v["minReadySeconds"] = minReadySeconds
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        template = self.template()
        check_type("template", template, Optional["corev1.PodTemplateSpec"])
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

    def minReadySeconds(self) -> Optional[int]:
        """
        Minimum number of seconds for which a newly created pod should be ready
        without any of its container crashing, for it to be considered available.
        Defaults to 0 (pod will be considered available as soon as it is ready)
        """
        return self.__minReadySeconds

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        Selector is a label query over pods that should match the replica count.
        If the selector is empty, it is defaulted to the labels present on the pod template.
        Label keys and values that must match in order to be controlled by this replica set.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
        """
        return self.__selector

    def template(self) -> Optional["corev1.PodTemplateSpec"]:
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
            apiVersion="extensions/v1beta1",
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
            apiVersion="extensions/v1beta1", kind="ReplicationControllerDummy"
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
            apiVersion="extensions/v1beta1",
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
