# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional, Union


# DeploymentStrategyType refers to a specific DeploymentStrategy implementation.
DeploymentStrategyType = base.Enum(
    "DeploymentStrategyType",
    {
        # Custom is a user defined strategy.
        "Custom": "Custom",
        # Recreate is a simple strategy suitable as a default.
        "Recreate": "Recreate",
        # Rolling uses the Kubernetes RollingUpdater.
        "Rolling": "Rolling",
    },
)


# DeploymentTriggerType refers to a specific DeploymentTriggerPolicy implementation.
DeploymentTriggerType = base.Enum(
    "DeploymentTriggerType",
    {
        # ConfigChange will create new deployments in response to changes to
        # the ControllerTemplate of a DeploymentConfig.
        "ConfigChange": "ConfigChange",
        # ImageChange will create new deployments in response to updated tags from
        # a container image repository.
        "ImageChange": "ImageChange",
    },
)


# LifecycleHookFailurePolicy describes possibles actions to take if a hook fails.
LifecycleHookFailurePolicy = base.Enum(
    "LifecycleHookFailurePolicy",
    {
        # Abort means abort the deployment.
        "Abort": "Abort",
        # Ignore means ignore failure and continue the deployment.
        "Ignore": "Ignore",
        # Retry means retry the hook until it succeeds.
        "Retry": "Retry",
    },
)


class CustomDeploymentStrategyParams(types.Object):
    """
    CustomDeploymentStrategyParams are the input to the Custom deployment strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        image: str = None,
        environment: List["k8sv1.EnvVar"] = None,
        command: List[str] = None,
    ):
        super().__init__()
        self.__image = image
        self.__environment = environment if environment is not None else []
        self.__command = command if command is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        image = self.image()
        check_type("image", image, Optional[str])
        if image:  # omit empty
            v["image"] = image
        environment = self.environment()
        check_type("environment", environment, Optional[List["k8sv1.EnvVar"]])
        if environment:  # omit empty
            v["environment"] = environment
        command = self.command()
        check_type("command", command, Optional[List[str]])
        if command:  # omit empty
            v["command"] = command
        return v

    def image(self) -> Optional[str]:
        """
        Image specifies a container image which can carry out a deployment.
        """
        return self.__image

    def environment(self) -> Optional[List["k8sv1.EnvVar"]]:
        """
        Environment holds the environment which will be given to the container for Image.
        """
        return self.__environment

    def command(self) -> Optional[List[str]]:
        """
        Command is optional and overrides CMD in the container Image.
        """
        return self.__command


class ExecNewPodHook(types.Object):
    """
    ExecNewPodHook is a hook implementation which runs a command in a new pod
    based on the specified container which is assumed to be part of the
    deployment template.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        command: List[str] = None,
        env: List["k8sv1.EnvVar"] = None,
        container_name: str = "",
        volumes: List[str] = None,
    ):
        super().__init__()
        self.__command = command if command is not None else []
        self.__env = env if env is not None else []
        self.__container_name = container_name
        self.__volumes = volumes if volumes is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        command = self.command()
        check_type("command", command, List[str])
        v["command"] = command
        env = self.env()
        check_type("env", env, Optional[List["k8sv1.EnvVar"]])
        if env:  # omit empty
            v["env"] = env
        container_name = self.container_name()
        check_type("container_name", container_name, str)
        v["containerName"] = container_name
        volumes = self.volumes()
        check_type("volumes", volumes, Optional[List[str]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        return v

    def command(self) -> List[str]:
        """
        Command is the action command and its arguments.
        """
        return self.__command

    def env(self) -> Optional[List["k8sv1.EnvVar"]]:
        """
        Env is a set of environment variables to supply to the hook pod's container.
        """
        return self.__env

    def container_name(self) -> str:
        """
        ContainerName is the name of a container in the deployment pod template
        whose container image will be used for the hook pod's container.
        """
        return self.__container_name

    def volumes(self) -> Optional[List[str]]:
        """
        Volumes is a list of named volumes from the pod template which should be
        copied to the hook pod. Volumes names not found in pod spec are ignored.
        An empty list means no volumes will be copied.
        """
        return self.__volumes


class TagImageHook(types.Object):
    """
    TagImageHook is a request to tag the image in a particular container onto an ImageStreamTag.
    """

    @context.scoped
    @typechecked
    def __init__(self, container_name: str = "", to: "k8sv1.ObjectReference" = None):
        super().__init__()
        self.__container_name = container_name
        self.__to = to if to is not None else k8sv1.ObjectReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        container_name = self.container_name()
        check_type("container_name", container_name, str)
        v["containerName"] = container_name
        to = self.to()
        check_type("to", to, "k8sv1.ObjectReference")
        v["to"] = to
        return v

    def container_name(self) -> str:
        """
        ContainerName is the name of a container in the deployment config whose image value will be used as the source of the tag. If there is only a single
        container this value will be defaulted to the name of that container.
        """
        return self.__container_name

    def to(self) -> "k8sv1.ObjectReference":
        """
        To is the target ImageStreamTag to set the container's image onto.
        """
        return self.__to


class LifecycleHook(types.Object):
    """
    LifecycleHook defines a specific deployment lifecycle action. Only one type of action may be specified at any time.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        failure_policy: LifecycleHookFailurePolicy = None,
        exec_new_pod: "ExecNewPodHook" = None,
        tag_images: List["TagImageHook"] = None,
    ):
        super().__init__()
        self.__failure_policy = failure_policy
        self.__exec_new_pod = exec_new_pod
        self.__tag_images = tag_images if tag_images is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        failure_policy = self.failure_policy()
        check_type("failure_policy", failure_policy, LifecycleHookFailurePolicy)
        v["failurePolicy"] = failure_policy
        exec_new_pod = self.exec_new_pod()
        check_type("exec_new_pod", exec_new_pod, Optional["ExecNewPodHook"])
        if exec_new_pod is not None:  # omit empty
            v["execNewPod"] = exec_new_pod
        tag_images = self.tag_images()
        check_type("tag_images", tag_images, Optional[List["TagImageHook"]])
        if tag_images:  # omit empty
            v["tagImages"] = tag_images
        return v

    def failure_policy(self) -> LifecycleHookFailurePolicy:
        """
        FailurePolicy specifies what action to take if the hook fails.
        """
        return self.__failure_policy

    def exec_new_pod(self) -> Optional["ExecNewPodHook"]:
        """
        ExecNewPod specifies the options for a lifecycle hook backed by a pod.
        """
        return self.__exec_new_pod

    def tag_images(self) -> Optional[List["TagImageHook"]]:
        """
        TagImages instructs the deployer to tag the current image referenced under a container onto an image stream tag.
        """
        return self.__tag_images


class RecreateDeploymentStrategyParams(types.Object):
    """
    RecreateDeploymentStrategyParams are the input to the Recreate deployment
    strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        timeout_seconds: int = None,
        pre: "LifecycleHook" = None,
        mid: "LifecycleHook" = None,
        post: "LifecycleHook" = None,
    ):
        super().__init__()
        self.__timeout_seconds = timeout_seconds if timeout_seconds is not None else 600
        self.__pre = pre
        self.__mid = mid
        self.__post = post

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        timeout_seconds = self.timeout_seconds()
        check_type("timeout_seconds", timeout_seconds, Optional[int])
        if timeout_seconds is not None:  # omit empty
            v["timeoutSeconds"] = timeout_seconds
        pre = self.pre()
        check_type("pre", pre, Optional["LifecycleHook"])
        if pre is not None:  # omit empty
            v["pre"] = pre
        mid = self.mid()
        check_type("mid", mid, Optional["LifecycleHook"])
        if mid is not None:  # omit empty
            v["mid"] = mid
        post = self.post()
        check_type("post", post, Optional["LifecycleHook"])
        if post is not None:  # omit empty
            v["post"] = post
        return v

    def timeout_seconds(self) -> Optional[int]:
        """
        TimeoutSeconds is the time to wait for updates before giving up. If the
        value is nil, a default will be used.
        """
        return self.__timeout_seconds

    def pre(self) -> Optional["LifecycleHook"]:
        """
        Pre is a lifecycle hook which is executed before the strategy manipulates
        the deployment. All LifecycleHookFailurePolicy values are supported.
        """
        return self.__pre

    def mid(self) -> Optional["LifecycleHook"]:
        """
        Mid is a lifecycle hook which is executed while the deployment is scaled down to zero before the first new
        pod is created. All LifecycleHookFailurePolicy values are supported.
        """
        return self.__mid

    def post(self) -> Optional["LifecycleHook"]:
        """
        Post is a lifecycle hook which is executed after the strategy has
        finished all deployment logic. All LifecycleHookFailurePolicy values are supported.
        """
        return self.__post


class RollingDeploymentStrategyParams(types.Object):
    """
    RollingDeploymentStrategyParams are the input to the Rolling deployment
    strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        update_period_seconds: int = None,
        interval_seconds: int = None,
        timeout_seconds: int = None,
        max_unavailable: Union[int, str] = None,
        max_surge: Union[int, str] = None,
        pre: "LifecycleHook" = None,
        post: "LifecycleHook" = None,
    ):
        super().__init__()
        self.__update_period_seconds = (
            update_period_seconds if update_period_seconds is not None else 1
        )
        self.__interval_seconds = (
            interval_seconds if interval_seconds is not None else 1
        )
        self.__timeout_seconds = timeout_seconds if timeout_seconds is not None else 600
        self.__max_unavailable = (
            max_unavailable if max_unavailable is not None else "25%"
        )
        self.__max_surge = max_surge if max_surge is not None else "25%"
        self.__pre = pre
        self.__post = post

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        update_period_seconds = self.update_period_seconds()
        check_type("update_period_seconds", update_period_seconds, Optional[int])
        if update_period_seconds is not None:  # omit empty
            v["updatePeriodSeconds"] = update_period_seconds
        interval_seconds = self.interval_seconds()
        check_type("interval_seconds", interval_seconds, Optional[int])
        if interval_seconds is not None:  # omit empty
            v["intervalSeconds"] = interval_seconds
        timeout_seconds = self.timeout_seconds()
        check_type("timeout_seconds", timeout_seconds, Optional[int])
        if timeout_seconds is not None:  # omit empty
            v["timeoutSeconds"] = timeout_seconds
        max_unavailable = self.max_unavailable()
        check_type("max_unavailable", max_unavailable, Optional[Union[int, str]])
        if max_unavailable is not None:  # omit empty
            v["maxUnavailable"] = max_unavailable
        max_surge = self.max_surge()
        check_type("max_surge", max_surge, Optional[Union[int, str]])
        if max_surge is not None:  # omit empty
            v["maxSurge"] = max_surge
        pre = self.pre()
        check_type("pre", pre, Optional["LifecycleHook"])
        if pre is not None:  # omit empty
            v["pre"] = pre
        post = self.post()
        check_type("post", post, Optional["LifecycleHook"])
        if post is not None:  # omit empty
            v["post"] = post
        return v

    def update_period_seconds(self) -> Optional[int]:
        """
        UpdatePeriodSeconds is the time to wait between individual pod updates.
        If the value is nil, a default will be used.
        """
        return self.__update_period_seconds

    def interval_seconds(self) -> Optional[int]:
        """
        IntervalSeconds is the time to wait between polling deployment status
        after update. If the value is nil, a default will be used.
        """
        return self.__interval_seconds

    def timeout_seconds(self) -> Optional[int]:
        """
        TimeoutSeconds is the time to wait for updates before giving up. If the
        value is nil, a default will be used.
        """
        return self.__timeout_seconds

    def max_unavailable(self) -> Optional[Union[int, str]]:
        """
        MaxUnavailable is the maximum number of pods that can be unavailable
        during the update. Value can be an absolute number (ex: 5) or a
        percentage of total pods at the start of update (ex: 10%). Absolute
        number is calculated from percentage by rounding down.
        
        This cannot be 0 if MaxSurge is 0. By default, 25% is used.
        
        Example: when this is set to 30%, the old RC can be scaled down by 30%
        immediately when the rolling update starts. Once new pods are ready, old
        RC can be scaled down further, followed by scaling up the new RC,
        ensuring that at least 70% of original number of pods are available at
        all times during the update.
        """
        return self.__max_unavailable

    def max_surge(self) -> Optional[Union[int, str]]:
        """
        MaxSurge is the maximum number of pods that can be scheduled above the
        original number of pods. Value can be an absolute number (ex: 5) or a
        percentage of total pods at the start of the update (ex: 10%). Absolute
        number is calculated from percentage by rounding up.
        
        This cannot be 0 if MaxUnavailable is 0. By default, 25% is used.
        
        Example: when this is set to 30%, the new RC can be scaled up by 30%
        immediately when the rolling update starts. Once old pods have been
        killed, new RC can be scaled up further, ensuring that total number of
        pods running at any time during the update is atmost 130% of original
        pods.
        """
        return self.__max_surge

    def pre(self) -> Optional["LifecycleHook"]:
        """
        Pre is a lifecycle hook which is executed before the deployment process
        begins. All LifecycleHookFailurePolicy values are supported.
        """
        return self.__pre

    def post(self) -> Optional["LifecycleHook"]:
        """
        Post is a lifecycle hook which is executed after the strategy has
        finished all deployment logic. All LifecycleHookFailurePolicy values
        are supported.
        """
        return self.__post


class DeploymentStrategy(types.Object):
    """
    DeploymentStrategy describes how to perform a deployment.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: DeploymentStrategyType = DeploymentStrategyType["Rolling"],
        custom_params: "CustomDeploymentStrategyParams" = None,
        recreate_params: "RecreateDeploymentStrategyParams" = None,
        rolling_params: "RollingDeploymentStrategyParams" = None,
        resources: "k8sv1.ResourceRequirements" = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        active_deadline_seconds: int = None,
    ):
        super().__init__()
        self.__type = type
        self.__custom_params = custom_params
        self.__recreate_params = recreate_params
        self.__rolling_params = (
            rolling_params
            if rolling_params is not None
            else RollingDeploymentStrategyParams()
        )
        self.__resources = (
            resources if resources is not None else k8sv1.ResourceRequirements()
        )
        self.__labels = labels if labels is not None else {}
        self.__annotations = annotations if annotations is not None else {}
        self.__active_deadline_seconds = (
            active_deadline_seconds if active_deadline_seconds is not None else 21600
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[DeploymentStrategyType])
        if type:  # omit empty
            v["type"] = type
        custom_params = self.custom_params()
        check_type(
            "custom_params", custom_params, Optional["CustomDeploymentStrategyParams"]
        )
        if custom_params is not None:  # omit empty
            v["customParams"] = custom_params
        recreate_params = self.recreate_params()
        check_type(
            "recreate_params",
            recreate_params,
            Optional["RecreateDeploymentStrategyParams"],
        )
        if recreate_params is not None:  # omit empty
            v["recreateParams"] = recreate_params
        rolling_params = self.rolling_params()
        check_type(
            "rolling_params",
            rolling_params,
            Optional["RollingDeploymentStrategyParams"],
        )
        if rolling_params is not None:  # omit empty
            v["rollingParams"] = rolling_params
        resources = self.resources()
        check_type("resources", resources, Optional["k8sv1.ResourceRequirements"])
        v["resources"] = resources
        labels = self.labels()
        check_type("labels", labels, Optional[Dict[str, str]])
        if labels:  # omit empty
            v["labels"] = labels
        annotations = self.annotations()
        check_type("annotations", annotations, Optional[Dict[str, str]])
        if annotations:  # omit empty
            v["annotations"] = annotations
        active_deadline_seconds = self.active_deadline_seconds()
        check_type("active_deadline_seconds", active_deadline_seconds, Optional[int])
        if active_deadline_seconds is not None:  # omit empty
            v["activeDeadlineSeconds"] = active_deadline_seconds
        return v

    def type(self) -> Optional[DeploymentStrategyType]:
        """
        Type is the name of a deployment strategy.
        """
        return self.__type

    def custom_params(self) -> Optional["CustomDeploymentStrategyParams"]:
        """
        CustomParams are the input to the Custom deployment strategy, and may also
        be specified for the Recreate and Rolling strategies to customize the execution
        process that runs the deployment.
        """
        return self.__custom_params

    def recreate_params(self) -> Optional["RecreateDeploymentStrategyParams"]:
        """
        RecreateParams are the input to the Recreate deployment strategy.
        """
        return self.__recreate_params

    def rolling_params(self) -> Optional["RollingDeploymentStrategyParams"]:
        """
        RollingParams are the input to the Rolling deployment strategy.
        """
        return self.__rolling_params

    def resources(self) -> Optional["k8sv1.ResourceRequirements"]:
        """
        Resources contains resource requirements to execute the deployment and any hooks.
        """
        return self.__resources

    def labels(self) -> Optional[Dict[str, str]]:
        """
        Labels is a set of key, value pairs added to custom deployer and lifecycle pre/post hook pods.
        """
        return self.__labels

    def annotations(self) -> Optional[Dict[str, str]]:
        """
        Annotations is a set of key, value pairs added to custom deployer and lifecycle pre/post hook pods.
        """
        return self.__annotations

    def active_deadline_seconds(self) -> Optional[int]:
        """
        ActiveDeadlineSeconds is the duration in seconds that the deployer pods for this deployment
        config may be active on a node before the system actively tries to terminate them.
        """
        return self.__active_deadline_seconds


class DeploymentTriggerImageChangeParams(types.Object):
    """
    DeploymentTriggerImageChangeParams represents the parameters to the ImageChange trigger.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        automatic: bool = None,
        container_names: List[str] = None,
        from_: "k8sv1.ObjectReference" = None,
        last_triggered_image: str = None,
    ):
        super().__init__()
        self.__automatic = automatic
        self.__container_names = container_names if container_names is not None else []
        self.__from_ = from_ if from_ is not None else k8sv1.ObjectReference()
        self.__last_triggered_image = last_triggered_image

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        automatic = self.automatic()
        check_type("automatic", automatic, Optional[bool])
        if automatic:  # omit empty
            v["automatic"] = automatic
        container_names = self.container_names()
        check_type("container_names", container_names, Optional[List[str]])
        if container_names:  # omit empty
            v["containerNames"] = container_names
        from_ = self.from_()
        check_type("from_", from_, "k8sv1.ObjectReference")
        v["from"] = from_
        last_triggered_image = self.last_triggered_image()
        check_type("last_triggered_image", last_triggered_image, Optional[str])
        if last_triggered_image:  # omit empty
            v["lastTriggeredImage"] = last_triggered_image
        return v

    def automatic(self) -> Optional[bool]:
        """
        Automatic means that the detection of a new tag value should result in an image update
        inside the pod template.
        """
        return self.__automatic

    def container_names(self) -> Optional[List[str]]:
        """
        ContainerNames is used to restrict tag updates to the specified set of container names in a pod.
        If multiple triggers point to the same containers, the resulting behavior is undefined. Future
        API versions will make this a validation error. If ContainerNames does not point to a valid container,
        the trigger will be ignored. Future API versions will make this a validation error.
        """
        return self.__container_names

    def from_(self) -> "k8sv1.ObjectReference":
        """
        From is a reference to an image stream tag to watch for changes. From.Name is the only
        required subfield - if From.Namespace is blank, the namespace of the current deployment
        trigger will be used.
        """
        return self.__from_

    def last_triggered_image(self) -> Optional[str]:
        """
        LastTriggeredImage is the last image to be triggered.
        """
        return self.__last_triggered_image


class DeploymentTriggerPolicy(types.Object):
    """
    DeploymentTriggerPolicy describes a policy for a single trigger that results in a new deployment.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: DeploymentTriggerType = None,
        image_change_params: "DeploymentTriggerImageChangeParams" = None,
    ):
        super().__init__()
        self.__type = type
        self.__image_change_params = image_change_params

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[DeploymentTriggerType])
        if type:  # omit empty
            v["type"] = type
        image_change_params = self.image_change_params()
        check_type(
            "image_change_params",
            image_change_params,
            Optional["DeploymentTriggerImageChangeParams"],
        )
        if image_change_params is not None:  # omit empty
            v["imageChangeParams"] = image_change_params
        return v

    def type(self) -> Optional[DeploymentTriggerType]:
        """
        Type of the trigger
        """
        return self.__type

    def image_change_params(self) -> Optional["DeploymentTriggerImageChangeParams"]:
        """
        ImageChangeParams represents the parameters for the ImageChange trigger.
        """
        return self.__image_change_params


class DeploymentConfigSpec(types.Object):
    """
    DeploymentConfigSpec represents the desired state of the deployment.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        strategy: "DeploymentStrategy" = None,
        min_ready_seconds: int = None,
        triggers: List["DeploymentTriggerPolicy"] = None,
        replicas: int = 0,
        revision_history_limit: int = None,
        test: bool = False,
        paused: bool = None,
        selector: Dict[str, str] = None,
        template: "k8sv1.PodTemplateSpec" = None,
    ):
        super().__init__()
        self.__strategy = strategy if strategy is not None else DeploymentStrategy()
        self.__min_ready_seconds = min_ready_seconds
        self.__triggers = triggers if triggers is not None else []
        self.__replicas = replicas
        self.__revision_history_limit = revision_history_limit
        self.__test = test
        self.__paused = paused
        self.__selector = selector if selector is not None else {}
        self.__template = template

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        strategy = self.strategy()
        check_type("strategy", strategy, "DeploymentStrategy")
        v["strategy"] = strategy
        min_ready_seconds = self.min_ready_seconds()
        check_type("min_ready_seconds", min_ready_seconds, Optional[int])
        if min_ready_seconds:  # omit empty
            v["minReadySeconds"] = min_ready_seconds
        triggers = self.triggers()
        check_type("triggers", triggers, List["DeploymentTriggerPolicy"])
        v["triggers"] = triggers
        replicas = self.replicas()
        check_type("replicas", replicas, int)
        v["replicas"] = replicas
        revision_history_limit = self.revision_history_limit()
        check_type("revision_history_limit", revision_history_limit, Optional[int])
        if revision_history_limit is not None:  # omit empty
            v["revisionHistoryLimit"] = revision_history_limit
        test = self.test()
        check_type("test", test, bool)
        v["test"] = test
        paused = self.paused()
        check_type("paused", paused, Optional[bool])
        if paused:  # omit empty
            v["paused"] = paused
        selector = self.selector()
        check_type("selector", selector, Optional[Dict[str, str]])
        if selector:  # omit empty
            v["selector"] = selector
        template = self.template()
        check_type("template", template, Optional["k8sv1.PodTemplateSpec"])
        if template is not None:  # omit empty
            v["template"] = template
        return v

    def strategy(self) -> "DeploymentStrategy":
        """
        Strategy describes how a deployment is executed.
        """
        return self.__strategy

    def min_ready_seconds(self) -> Optional[int]:
        """
        MinReadySeconds is the minimum number of seconds for which a newly created pod should
        be ready without any of its container crashing, for it to be considered available.
        Defaults to 0 (pod will be considered available as soon as it is ready)
        """
        return self.__min_ready_seconds

    def triggers(self) -> List["DeploymentTriggerPolicy"]:
        """
        Triggers determine how updates to a DeploymentConfig result in new deployments. If no triggers
        are defined, a new deployment can only occur as a result of an explicit client update to the
        DeploymentConfig with a new LatestVersion. If null, defaults to having a config change trigger.
        """
        return self.__triggers

    def replicas(self) -> int:
        """
        Replicas is the number of desired replicas.
        """
        return self.__replicas

    def revision_history_limit(self) -> Optional[int]:
        """
        RevisionHistoryLimit is the number of old ReplicationControllers to retain to allow for rollbacks.
        This field is a pointer to allow for differentiation between an explicit zero and not specified.
        Defaults to 10. (This only applies to DeploymentConfigs created via the new group API resource, not the legacy resource.)
        """
        return self.__revision_history_limit

    def test(self) -> bool:
        """
        Test ensures that this deployment config will have zero replicas except while a deployment is running. This allows the
        deployment config to be used as a continuous deployment test - triggering on images, running the deployment, and then succeeding
        or failing. Post strategy hooks and After actions can be used to integrate successful deployment with an action.
        """
        return self.__test

    def paused(self) -> Optional[bool]:
        """
        Paused indicates that the deployment config is paused resulting in no new deployments on template
        changes or changes in the template caused by other triggers.
        """
        return self.__paused

    def selector(self) -> Optional[Dict[str, str]]:
        """
        Selector is a label query over pods that should match the Replicas count.
        """
        return self.__selector

    def template(self) -> Optional["k8sv1.PodTemplateSpec"]:
        """
        Template is the object that describes the pod that will be created if
        insufficient replicas are detected.
        """
        return self.__template


class DeploymentConfig(base.TypedObject, base.NamespacedMetadataObject):
    """
    Deployment Configs define the template for a pod and manages deploying new images or configuration changes.
    A single deployment configuration is usually analogous to a single micro-service. Can support many different
    deployment patterns, including full restart, customizable rolling updates, and  fully custom behaviors, as
    well as pre- and post- deployment hooks. Each individual deployment is represented as a replication controller.
    
    A deployment is "triggered" when its configuration is changed or a tag in an Image Stream is changed.
    Triggers can be disabled to allow manual control over a deployment. The "strategy" determines how the deployment
    is carried out and may be changed at any time. The `latestVersion` field is updated when a new deployment
    is triggered by any means.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "DeploymentConfigSpec" = None,
    ):
        super().__init__(
            api_version="apps.openshift.io/v1",
            kind="DeploymentConfig",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else DeploymentConfigSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "DeploymentConfigSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "DeploymentConfigSpec":
        """
        Spec represents a desired deployment state and how to deploy to it.
        """
        return self.__spec


class DeploymentConfigRollbackSpec(types.Object):
    """
    DeploymentConfigRollbackSpec represents the options for rollback generation.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        from_: "k8sv1.ObjectReference" = None,
        revision: int = None,
        include_triggers: bool = False,
        include_template: bool = False,
        include_replication_meta: bool = False,
        include_strategy: bool = False,
    ):
        super().__init__()
        self.__from_ = from_ if from_ is not None else k8sv1.ObjectReference()
        self.__revision = revision
        self.__include_triggers = include_triggers
        self.__include_template = include_template
        self.__include_replication_meta = include_replication_meta
        self.__include_strategy = include_strategy

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        from_ = self.from_()
        check_type("from_", from_, "k8sv1.ObjectReference")
        v["from"] = from_
        revision = self.revision()
        check_type("revision", revision, Optional[int])
        if revision:  # omit empty
            v["revision"] = revision
        include_triggers = self.include_triggers()
        check_type("include_triggers", include_triggers, bool)
        v["includeTriggers"] = include_triggers
        include_template = self.include_template()
        check_type("include_template", include_template, bool)
        v["includeTemplate"] = include_template
        include_replication_meta = self.include_replication_meta()
        check_type("include_replication_meta", include_replication_meta, bool)
        v["includeReplicationMeta"] = include_replication_meta
        include_strategy = self.include_strategy()
        check_type("include_strategy", include_strategy, bool)
        v["includeStrategy"] = include_strategy
        return v

    def from_(self) -> "k8sv1.ObjectReference":
        """
        From points to a ReplicationController which is a deployment.
        """
        return self.__from_

    def revision(self) -> Optional[int]:
        """
        Revision to rollback to. If set to 0, rollback to the last revision.
        """
        return self.__revision

    def include_triggers(self) -> bool:
        """
        IncludeTriggers specifies whether to include config Triggers.
        """
        return self.__include_triggers

    def include_template(self) -> bool:
        """
        IncludeTemplate specifies whether to include the PodTemplateSpec.
        """
        return self.__include_template

    def include_replication_meta(self) -> bool:
        """
        IncludeReplicationMeta specifies whether to include the replica count and selector.
        """
        return self.__include_replication_meta

    def include_strategy(self) -> bool:
        """
        IncludeStrategy specifies whether to include the deployment Strategy.
        """
        return self.__include_strategy


class DeploymentConfigRollback(base.TypedObject):
    """
    DeploymentConfigRollback provides the input to rollback generation.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        updated_annotations: Dict[str, str] = None,
        spec: "DeploymentConfigRollbackSpec" = None,
    ):
        super().__init__(
            api_version="apps.openshift.io/v1", kind="DeploymentConfigRollback"
        )
        self.__name = name
        self.__updated_annotations = (
            updated_annotations if updated_annotations is not None else {}
        )
        self.__spec = spec if spec is not None else DeploymentConfigRollbackSpec()

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
        spec = self.spec()
        check_type("spec", spec, "DeploymentConfigRollbackSpec")
        v["spec"] = spec
        return v

    def name(self) -> str:
        """
        Name of the deployment config that will be rolled back.
        """
        return self.__name

    def updated_annotations(self) -> Optional[Dict[str, str]]:
        """
        UpdatedAnnotations is a set of new annotations that will be added in the deployment config.
        """
        return self.__updated_annotations

    def spec(self) -> "DeploymentConfigRollbackSpec":
        """
        Spec defines the options to rollback generation.
        """
        return self.__spec


class DeploymentLog(base.TypedObject):
    """
    DeploymentLog represents the logs for a deployment
    """

    @context.scoped
    @typechecked
    def __init__(self):
        super().__init__(api_version="apps.openshift.io/v1", kind="DeploymentLog")

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        return v


class DeploymentLogOptions(base.TypedObject):
    """
    DeploymentLogOptions is the REST options for a deployment log
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        container: str = None,
        follow: bool = None,
        previous: bool = None,
        since_seconds: int = None,
        since_time: "base.Time" = None,
        timestamps: bool = None,
        tail_lines: int = None,
        limit_bytes: int = None,
        nowait: bool = None,
        version: int = None,
    ):
        super().__init__(
            api_version="apps.openshift.io/v1", kind="DeploymentLogOptions"
        )
        self.__container = container
        self.__follow = follow
        self.__previous = previous
        self.__since_seconds = since_seconds
        self.__since_time = since_time
        self.__timestamps = timestamps
        self.__tail_lines = tail_lines
        self.__limit_bytes = limit_bytes
        self.__nowait = nowait
        self.__version = version

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        container = self.container()
        check_type("container", container, Optional[str])
        if container:  # omit empty
            v["container"] = container
        follow = self.follow()
        check_type("follow", follow, Optional[bool])
        if follow:  # omit empty
            v["follow"] = follow
        previous = self.previous()
        check_type("previous", previous, Optional[bool])
        if previous:  # omit empty
            v["previous"] = previous
        since_seconds = self.since_seconds()
        check_type("since_seconds", since_seconds, Optional[int])
        if since_seconds is not None:  # omit empty
            v["sinceSeconds"] = since_seconds
        since_time = self.since_time()
        check_type("since_time", since_time, Optional["base.Time"])
        if since_time is not None:  # omit empty
            v["sinceTime"] = since_time
        timestamps = self.timestamps()
        check_type("timestamps", timestamps, Optional[bool])
        if timestamps:  # omit empty
            v["timestamps"] = timestamps
        tail_lines = self.tail_lines()
        check_type("tail_lines", tail_lines, Optional[int])
        if tail_lines is not None:  # omit empty
            v["tailLines"] = tail_lines
        limit_bytes = self.limit_bytes()
        check_type("limit_bytes", limit_bytes, Optional[int])
        if limit_bytes is not None:  # omit empty
            v["limitBytes"] = limit_bytes
        nowait = self.nowait()
        check_type("nowait", nowait, Optional[bool])
        if nowait:  # omit empty
            v["nowait"] = nowait
        version = self.version()
        check_type("version", version, Optional[int])
        if version is not None:  # omit empty
            v["version"] = version
        return v

    def container(self) -> Optional[str]:
        """
        The container for which to stream logs. Defaults to only container if there is one container in the pod.
        """
        return self.__container

    def follow(self) -> Optional[bool]:
        """
        Follow if true indicates that the build log should be streamed until
        the build terminates.
        """
        return self.__follow

    def previous(self) -> Optional[bool]:
        """
        Return previous deployment logs. Defaults to false.
        """
        return self.__previous

    def since_seconds(self) -> Optional[int]:
        """
        A relative time in seconds before the current time from which to show logs. If this value
        precedes the time a pod was started, only logs since the pod start will be returned.
        If this value is in the future, no logs will be returned.
        Only one of sinceSeconds or sinceTime may be specified.
        """
        return self.__since_seconds

    def since_time(self) -> Optional["base.Time"]:
        """
        An RFC3339 timestamp from which to show logs. If this value
        precedes the time a pod was started, only logs since the pod start will be returned.
        If this value is in the future, no logs will be returned.
        Only one of sinceSeconds or sinceTime may be specified.
        """
        return self.__since_time

    def timestamps(self) -> Optional[bool]:
        """
        If true, add an RFC3339 or RFC3339Nano timestamp at the beginning of every line
        of log output. Defaults to false.
        """
        return self.__timestamps

    def tail_lines(self) -> Optional[int]:
        """
        If set, the number of lines from the end of the logs to show. If not specified,
        logs are shown from the creation of the container or sinceSeconds or sinceTime
        """
        return self.__tail_lines

    def limit_bytes(self) -> Optional[int]:
        """
        If set, the number of bytes to read from the server before terminating the
        log output. This may not display a complete final line of logging, and may return
        slightly more or slightly less than the specified limit.
        """
        return self.__limit_bytes

    def nowait(self) -> Optional[bool]:
        """
        NoWait if true causes the call to return immediately even if the deployment
        is not available yet. Otherwise the server will wait until the deployment has started.
        TODO: Fix the tag to 'noWait' in v2
        """
        return self.__nowait

    def version(self) -> Optional[int]:
        """
        Version of the deployment for which to view logs.
        """
        return self.__version


class DeploymentRequest(base.TypedObject):
    """
    DeploymentRequest is a request to a deployment config for a new deployment.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        latest: bool = False,
        force: bool = False,
        exclude_triggers: List[DeploymentTriggerType] = None,
    ):
        super().__init__(api_version="apps.openshift.io/v1", kind="DeploymentRequest")
        self.__name = name
        self.__latest = latest
        self.__force = force
        self.__exclude_triggers = (
            exclude_triggers if exclude_triggers is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        latest = self.latest()
        check_type("latest", latest, bool)
        v["latest"] = latest
        force = self.force()
        check_type("force", force, bool)
        v["force"] = force
        exclude_triggers = self.exclude_triggers()
        check_type(
            "exclude_triggers", exclude_triggers, Optional[List[DeploymentTriggerType]]
        )
        if exclude_triggers:  # omit empty
            v["excludeTriggers"] = exclude_triggers
        return v

    def name(self) -> str:
        """
        Name of the deployment config for requesting a new deployment.
        """
        return self.__name

    def latest(self) -> bool:
        """
        Latest will update the deployment config with the latest state from all triggers.
        """
        return self.__latest

    def force(self) -> bool:
        """
        Force will try to force a new deployment to run. If the deployment config is paused,
        then setting this to true will return an Invalid error.
        """
        return self.__force

    def exclude_triggers(self) -> Optional[List[DeploymentTriggerType]]:
        """
        ExcludeTriggers instructs the instantiator to avoid processing the specified triggers.
        This field overrides the triggers from latest and allows clients to control specific
        logic. This field is ignored if not specified.
        """
        return self.__exclude_triggers
