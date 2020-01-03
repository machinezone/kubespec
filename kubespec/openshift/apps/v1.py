# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s.core import v1 as corev1
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
        environment: List["corev1.EnvVar"] = None,
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
        check_type("environment", environment, Optional[List["corev1.EnvVar"]])
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

    def environment(self) -> Optional[List["corev1.EnvVar"]]:
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
        env: List["corev1.EnvVar"] = None,
        containerName: str = "",
        volumes: List[str] = None,
    ):
        super().__init__()
        self.__command = command if command is not None else []
        self.__env = env if env is not None else []
        self.__containerName = containerName
        self.__volumes = volumes if volumes is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        command = self.command()
        check_type("command", command, List[str])
        v["command"] = command
        env = self.env()
        check_type("env", env, Optional[List["corev1.EnvVar"]])
        if env:  # omit empty
            v["env"] = env
        containerName = self.containerName()
        check_type("containerName", containerName, str)
        v["containerName"] = containerName
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

    def env(self) -> Optional[List["corev1.EnvVar"]]:
        """
        Env is a set of environment variables to supply to the hook pod's container.
        """
        return self.__env

    def containerName(self) -> str:
        """
        ContainerName is the name of a container in the deployment pod template
        whose container image will be used for the hook pod's container.
        """
        return self.__containerName

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
    def __init__(self, containerName: str = "", to: "corev1.ObjectReference" = None):
        super().__init__()
        self.__containerName = containerName
        self.__to = to if to is not None else corev1.ObjectReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        containerName = self.containerName()
        check_type("containerName", containerName, str)
        v["containerName"] = containerName
        to = self.to()
        check_type("to", to, "corev1.ObjectReference")
        v["to"] = to
        return v

    def containerName(self) -> str:
        """
        ContainerName is the name of a container in the deployment config whose image value will be used as the source of the tag. If there is only a single
        container this value will be defaulted to the name of that container.
        """
        return self.__containerName

    def to(self) -> "corev1.ObjectReference":
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
        failurePolicy: LifecycleHookFailurePolicy = None,
        execNewPod: "ExecNewPodHook" = None,
        tagImages: List["TagImageHook"] = None,
    ):
        super().__init__()
        self.__failurePolicy = failurePolicy
        self.__execNewPod = execNewPod
        self.__tagImages = tagImages if tagImages is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        failurePolicy = self.failurePolicy()
        check_type("failurePolicy", failurePolicy, LifecycleHookFailurePolicy)
        v["failurePolicy"] = failurePolicy
        execNewPod = self.execNewPod()
        check_type("execNewPod", execNewPod, Optional["ExecNewPodHook"])
        if execNewPod is not None:  # omit empty
            v["execNewPod"] = execNewPod
        tagImages = self.tagImages()
        check_type("tagImages", tagImages, Optional[List["TagImageHook"]])
        if tagImages:  # omit empty
            v["tagImages"] = tagImages
        return v

    def failurePolicy(self) -> LifecycleHookFailurePolicy:
        """
        FailurePolicy specifies what action to take if the hook fails.
        """
        return self.__failurePolicy

    def execNewPod(self) -> Optional["ExecNewPodHook"]:
        """
        ExecNewPod specifies the options for a lifecycle hook backed by a pod.
        """
        return self.__execNewPod

    def tagImages(self) -> Optional[List["TagImageHook"]]:
        """
        TagImages instructs the deployer to tag the current image referenced under a container onto an image stream tag.
        """
        return self.__tagImages


class RecreateDeploymentStrategyParams(types.Object):
    """
    RecreateDeploymentStrategyParams are the input to the Recreate deployment
    strategy.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        timeoutSeconds: int = None,
        pre: "LifecycleHook" = None,
        mid: "LifecycleHook" = None,
        post: "LifecycleHook" = None,
    ):
        super().__init__()
        self.__timeoutSeconds = timeoutSeconds if timeoutSeconds is not None else 600
        self.__pre = pre
        self.__mid = mid
        self.__post = post

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        timeoutSeconds = self.timeoutSeconds()
        check_type("timeoutSeconds", timeoutSeconds, Optional[int])
        if timeoutSeconds is not None:  # omit empty
            v["timeoutSeconds"] = timeoutSeconds
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

    def timeoutSeconds(self) -> Optional[int]:
        """
        TimeoutSeconds is the time to wait for updates before giving up. If the
        value is nil, a default will be used.
        """
        return self.__timeoutSeconds

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
        updatePeriodSeconds: int = None,
        intervalSeconds: int = None,
        timeoutSeconds: int = None,
        maxUnavailable: Union[int, str] = None,
        maxSurge: Union[int, str] = None,
        pre: "LifecycleHook" = None,
        post: "LifecycleHook" = None,
    ):
        super().__init__()
        self.__updatePeriodSeconds = (
            updatePeriodSeconds if updatePeriodSeconds is not None else 1
        )
        self.__intervalSeconds = intervalSeconds if intervalSeconds is not None else 1
        self.__timeoutSeconds = timeoutSeconds if timeoutSeconds is not None else 600
        self.__maxUnavailable = maxUnavailable if maxUnavailable is not None else "25%"
        self.__maxSurge = maxSurge if maxSurge is not None else "25%"
        self.__pre = pre
        self.__post = post

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        updatePeriodSeconds = self.updatePeriodSeconds()
        check_type("updatePeriodSeconds", updatePeriodSeconds, Optional[int])
        if updatePeriodSeconds is not None:  # omit empty
            v["updatePeriodSeconds"] = updatePeriodSeconds
        intervalSeconds = self.intervalSeconds()
        check_type("intervalSeconds", intervalSeconds, Optional[int])
        if intervalSeconds is not None:  # omit empty
            v["intervalSeconds"] = intervalSeconds
        timeoutSeconds = self.timeoutSeconds()
        check_type("timeoutSeconds", timeoutSeconds, Optional[int])
        if timeoutSeconds is not None:  # omit empty
            v["timeoutSeconds"] = timeoutSeconds
        maxUnavailable = self.maxUnavailable()
        check_type("maxUnavailable", maxUnavailable, Optional[Union[int, str]])
        if maxUnavailable is not None:  # omit empty
            v["maxUnavailable"] = maxUnavailable
        maxSurge = self.maxSurge()
        check_type("maxSurge", maxSurge, Optional[Union[int, str]])
        if maxSurge is not None:  # omit empty
            v["maxSurge"] = maxSurge
        pre = self.pre()
        check_type("pre", pre, Optional["LifecycleHook"])
        if pre is not None:  # omit empty
            v["pre"] = pre
        post = self.post()
        check_type("post", post, Optional["LifecycleHook"])
        if post is not None:  # omit empty
            v["post"] = post
        return v

    def updatePeriodSeconds(self) -> Optional[int]:
        """
        UpdatePeriodSeconds is the time to wait between individual pod updates.
        If the value is nil, a default will be used.
        """
        return self.__updatePeriodSeconds

    def intervalSeconds(self) -> Optional[int]:
        """
        IntervalSeconds is the time to wait between polling deployment status
        after update. If the value is nil, a default will be used.
        """
        return self.__intervalSeconds

    def timeoutSeconds(self) -> Optional[int]:
        """
        TimeoutSeconds is the time to wait for updates before giving up. If the
        value is nil, a default will be used.
        """
        return self.__timeoutSeconds

    def maxUnavailable(self) -> Optional[Union[int, str]]:
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
        return self.__maxUnavailable

    def maxSurge(self) -> Optional[Union[int, str]]:
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
        return self.__maxSurge

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
        customParams: "CustomDeploymentStrategyParams" = None,
        recreateParams: "RecreateDeploymentStrategyParams" = None,
        rollingParams: "RollingDeploymentStrategyParams" = None,
        resources: "corev1.ResourceRequirements" = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        activeDeadlineSeconds: int = None,
    ):
        super().__init__()
        self.__type = type
        self.__customParams = customParams
        self.__recreateParams = recreateParams
        self.__rollingParams = (
            rollingParams
            if rollingParams is not None
            else RollingDeploymentStrategyParams()
        )
        self.__resources = (
            resources if resources is not None else corev1.ResourceRequirements()
        )
        self.__labels = labels if labels is not None else {}
        self.__annotations = annotations if annotations is not None else {}
        self.__activeDeadlineSeconds = (
            activeDeadlineSeconds if activeDeadlineSeconds is not None else 21600
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[DeploymentStrategyType])
        if type:  # omit empty
            v["type"] = type
        customParams = self.customParams()
        check_type(
            "customParams", customParams, Optional["CustomDeploymentStrategyParams"]
        )
        if customParams is not None:  # omit empty
            v["customParams"] = customParams
        recreateParams = self.recreateParams()
        check_type(
            "recreateParams",
            recreateParams,
            Optional["RecreateDeploymentStrategyParams"],
        )
        if recreateParams is not None:  # omit empty
            v["recreateParams"] = recreateParams
        rollingParams = self.rollingParams()
        check_type(
            "rollingParams", rollingParams, Optional["RollingDeploymentStrategyParams"]
        )
        if rollingParams is not None:  # omit empty
            v["rollingParams"] = rollingParams
        resources = self.resources()
        check_type("resources", resources, Optional["corev1.ResourceRequirements"])
        v["resources"] = resources
        labels = self.labels()
        check_type("labels", labels, Optional[Dict[str, str]])
        if labels:  # omit empty
            v["labels"] = labels
        annotations = self.annotations()
        check_type("annotations", annotations, Optional[Dict[str, str]])
        if annotations:  # omit empty
            v["annotations"] = annotations
        activeDeadlineSeconds = self.activeDeadlineSeconds()
        check_type("activeDeadlineSeconds", activeDeadlineSeconds, Optional[int])
        if activeDeadlineSeconds is not None:  # omit empty
            v["activeDeadlineSeconds"] = activeDeadlineSeconds
        return v

    def type(self) -> Optional[DeploymentStrategyType]:
        """
        Type is the name of a deployment strategy.
        """
        return self.__type

    def customParams(self) -> Optional["CustomDeploymentStrategyParams"]:
        """
        CustomParams are the input to the Custom deployment strategy, and may also
        be specified for the Recreate and Rolling strategies to customize the execution
        process that runs the deployment.
        """
        return self.__customParams

    def recreateParams(self) -> Optional["RecreateDeploymentStrategyParams"]:
        """
        RecreateParams are the input to the Recreate deployment strategy.
        """
        return self.__recreateParams

    def rollingParams(self) -> Optional["RollingDeploymentStrategyParams"]:
        """
        RollingParams are the input to the Rolling deployment strategy.
        """
        return self.__rollingParams

    def resources(self) -> Optional["corev1.ResourceRequirements"]:
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

    def activeDeadlineSeconds(self) -> Optional[int]:
        """
        ActiveDeadlineSeconds is the duration in seconds that the deployer pods for this deployment
        config may be active on a node before the system actively tries to terminate them.
        """
        return self.__activeDeadlineSeconds


class DeploymentTriggerImageChangeParams(types.Object):
    """
    DeploymentTriggerImageChangeParams represents the parameters to the ImageChange trigger.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        automatic: bool = None,
        containerNames: List[str] = None,
        from_: "corev1.ObjectReference" = None,
        lastTriggeredImage: str = None,
    ):
        super().__init__()
        self.__automatic = automatic
        self.__containerNames = containerNames if containerNames is not None else []
        self.__from_ = from_ if from_ is not None else corev1.ObjectReference()
        self.__lastTriggeredImage = lastTriggeredImage

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        automatic = self.automatic()
        check_type("automatic", automatic, Optional[bool])
        if automatic:  # omit empty
            v["automatic"] = automatic
        containerNames = self.containerNames()
        check_type("containerNames", containerNames, Optional[List[str]])
        if containerNames:  # omit empty
            v["containerNames"] = containerNames
        from_ = self.from_()
        check_type("from_", from_, "corev1.ObjectReference")
        v["from"] = from_
        lastTriggeredImage = self.lastTriggeredImage()
        check_type("lastTriggeredImage", lastTriggeredImage, Optional[str])
        if lastTriggeredImage:  # omit empty
            v["lastTriggeredImage"] = lastTriggeredImage
        return v

    def automatic(self) -> Optional[bool]:
        """
        Automatic means that the detection of a new tag value should result in an image update
        inside the pod template.
        """
        return self.__automatic

    def containerNames(self) -> Optional[List[str]]:
        """
        ContainerNames is used to restrict tag updates to the specified set of container names in a pod.
        If multiple triggers point to the same containers, the resulting behavior is undefined. Future
        API versions will make this a validation error. If ContainerNames does not point to a valid container,
        the trigger will be ignored. Future API versions will make this a validation error.
        """
        return self.__containerNames

    def from_(self) -> "corev1.ObjectReference":
        """
        From is a reference to an image stream tag to watch for changes. From.Name is the only
        required subfield - if From.Namespace is blank, the namespace of the current deployment
        trigger will be used.
        """
        return self.__from_

    def lastTriggeredImage(self) -> Optional[str]:
        """
        LastTriggeredImage is the last image to be triggered.
        """
        return self.__lastTriggeredImage


class DeploymentTriggerPolicy(types.Object):
    """
    DeploymentTriggerPolicy describes a policy for a single trigger that results in a new deployment.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: DeploymentTriggerType = None,
        imageChangeParams: "DeploymentTriggerImageChangeParams" = None,
    ):
        super().__init__()
        self.__type = type
        self.__imageChangeParams = imageChangeParams

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[DeploymentTriggerType])
        if type:  # omit empty
            v["type"] = type
        imageChangeParams = self.imageChangeParams()
        check_type(
            "imageChangeParams",
            imageChangeParams,
            Optional["DeploymentTriggerImageChangeParams"],
        )
        if imageChangeParams is not None:  # omit empty
            v["imageChangeParams"] = imageChangeParams
        return v

    def type(self) -> Optional[DeploymentTriggerType]:
        """
        Type of the trigger
        """
        return self.__type

    def imageChangeParams(self) -> Optional["DeploymentTriggerImageChangeParams"]:
        """
        ImageChangeParams represents the parameters for the ImageChange trigger.
        """
        return self.__imageChangeParams


class DeploymentConfigSpec(types.Object):
    """
    DeploymentConfigSpec represents the desired state of the deployment.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        strategy: "DeploymentStrategy" = None,
        minReadySeconds: int = None,
        triggers: List["DeploymentTriggerPolicy"] = None,
        replicas: int = 0,
        revisionHistoryLimit: int = None,
        test: bool = False,
        paused: bool = None,
        selector: Dict[str, str] = None,
        template: "corev1.PodTemplateSpec" = None,
    ):
        super().__init__()
        self.__strategy = strategy if strategy is not None else DeploymentStrategy()
        self.__minReadySeconds = minReadySeconds
        self.__triggers = triggers if triggers is not None else []
        self.__replicas = replicas
        self.__revisionHistoryLimit = revisionHistoryLimit
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
        minReadySeconds = self.minReadySeconds()
        check_type("minReadySeconds", minReadySeconds, Optional[int])
        if minReadySeconds:  # omit empty
            v["minReadySeconds"] = minReadySeconds
        triggers = self.triggers()
        check_type("triggers", triggers, List["DeploymentTriggerPolicy"])
        v["triggers"] = triggers
        replicas = self.replicas()
        check_type("replicas", replicas, int)
        v["replicas"] = replicas
        revisionHistoryLimit = self.revisionHistoryLimit()
        check_type("revisionHistoryLimit", revisionHistoryLimit, Optional[int])
        if revisionHistoryLimit is not None:  # omit empty
            v["revisionHistoryLimit"] = revisionHistoryLimit
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
        check_type("template", template, Optional["corev1.PodTemplateSpec"])
        if template is not None:  # omit empty
            v["template"] = template
        return v

    def strategy(self) -> "DeploymentStrategy":
        """
        Strategy describes how a deployment is executed.
        """
        return self.__strategy

    def minReadySeconds(self) -> Optional[int]:
        """
        MinReadySeconds is the minimum number of seconds for which a newly created pod should
        be ready without any of its container crashing, for it to be considered available.
        Defaults to 0 (pod will be considered available as soon as it is ready)
        """
        return self.__minReadySeconds

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

    def revisionHistoryLimit(self) -> Optional[int]:
        """
        RevisionHistoryLimit is the number of old ReplicationControllers to retain to allow for rollbacks.
        This field is a pointer to allow for differentiation between an explicit zero and not specified.
        Defaults to 10. (This only applies to DeploymentConfigs created via the new group API resource, not the legacy resource.)
        """
        return self.__revisionHistoryLimit

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

    def template(self) -> Optional["corev1.PodTemplateSpec"]:
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
            apiVersion="apps.openshift.io/v1",
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
        from_: "corev1.ObjectReference" = None,
        revision: int = None,
        includeTriggers: bool = False,
        includeTemplate: bool = False,
        includeReplicationMeta: bool = False,
        includeStrategy: bool = False,
    ):
        super().__init__()
        self.__from_ = from_ if from_ is not None else corev1.ObjectReference()
        self.__revision = revision
        self.__includeTriggers = includeTriggers
        self.__includeTemplate = includeTemplate
        self.__includeReplicationMeta = includeReplicationMeta
        self.__includeStrategy = includeStrategy

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        from_ = self.from_()
        check_type("from_", from_, "corev1.ObjectReference")
        v["from"] = from_
        revision = self.revision()
        check_type("revision", revision, Optional[int])
        if revision:  # omit empty
            v["revision"] = revision
        includeTriggers = self.includeTriggers()
        check_type("includeTriggers", includeTriggers, bool)
        v["includeTriggers"] = includeTriggers
        includeTemplate = self.includeTemplate()
        check_type("includeTemplate", includeTemplate, bool)
        v["includeTemplate"] = includeTemplate
        includeReplicationMeta = self.includeReplicationMeta()
        check_type("includeReplicationMeta", includeReplicationMeta, bool)
        v["includeReplicationMeta"] = includeReplicationMeta
        includeStrategy = self.includeStrategy()
        check_type("includeStrategy", includeStrategy, bool)
        v["includeStrategy"] = includeStrategy
        return v

    def from_(self) -> "corev1.ObjectReference":
        """
        From points to a ReplicationController which is a deployment.
        """
        return self.__from_

    def revision(self) -> Optional[int]:
        """
        Revision to rollback to. If set to 0, rollback to the last revision.
        """
        return self.__revision

    def includeTriggers(self) -> bool:
        """
        IncludeTriggers specifies whether to include config Triggers.
        """
        return self.__includeTriggers

    def includeTemplate(self) -> bool:
        """
        IncludeTemplate specifies whether to include the PodTemplateSpec.
        """
        return self.__includeTemplate

    def includeReplicationMeta(self) -> bool:
        """
        IncludeReplicationMeta specifies whether to include the replica count and selector.
        """
        return self.__includeReplicationMeta

    def includeStrategy(self) -> bool:
        """
        IncludeStrategy specifies whether to include the deployment Strategy.
        """
        return self.__includeStrategy


class DeploymentConfigRollback(base.TypedObject):
    """
    DeploymentConfigRollback provides the input to rollback generation.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        updatedAnnotations: Dict[str, str] = None,
        spec: "DeploymentConfigRollbackSpec" = None,
    ):
        super().__init__(
            apiVersion="apps.openshift.io/v1", kind="DeploymentConfigRollback"
        )
        self.__name = name
        self.__updatedAnnotations = (
            updatedAnnotations if updatedAnnotations is not None else {}
        )
        self.__spec = spec if spec is not None else DeploymentConfigRollbackSpec()

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
        spec = self.spec()
        check_type("spec", spec, "DeploymentConfigRollbackSpec")
        v["spec"] = spec
        return v

    def name(self) -> str:
        """
        Name of the deployment config that will be rolled back.
        """
        return self.__name

    def updatedAnnotations(self) -> Optional[Dict[str, str]]:
        """
        UpdatedAnnotations is a set of new annotations that will be added in the deployment config.
        """
        return self.__updatedAnnotations

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
        super().__init__(apiVersion="apps.openshift.io/v1", kind="DeploymentLog")

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
        sinceSeconds: int = None,
        sinceTime: "base.Time" = None,
        timestamps: bool = None,
        tailLines: int = None,
        limitBytes: int = None,
        nowait: bool = None,
        version: int = None,
    ):
        super().__init__(apiVersion="apps.openshift.io/v1", kind="DeploymentLogOptions")
        self.__container = container
        self.__follow = follow
        self.__previous = previous
        self.__sinceSeconds = sinceSeconds
        self.__sinceTime = sinceTime
        self.__timestamps = timestamps
        self.__tailLines = tailLines
        self.__limitBytes = limitBytes
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
        sinceSeconds = self.sinceSeconds()
        check_type("sinceSeconds", sinceSeconds, Optional[int])
        if sinceSeconds is not None:  # omit empty
            v["sinceSeconds"] = sinceSeconds
        sinceTime = self.sinceTime()
        check_type("sinceTime", sinceTime, Optional["base.Time"])
        if sinceTime is not None:  # omit empty
            v["sinceTime"] = sinceTime
        timestamps = self.timestamps()
        check_type("timestamps", timestamps, Optional[bool])
        if timestamps:  # omit empty
            v["timestamps"] = timestamps
        tailLines = self.tailLines()
        check_type("tailLines", tailLines, Optional[int])
        if tailLines is not None:  # omit empty
            v["tailLines"] = tailLines
        limitBytes = self.limitBytes()
        check_type("limitBytes", limitBytes, Optional[int])
        if limitBytes is not None:  # omit empty
            v["limitBytes"] = limitBytes
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

    def sinceSeconds(self) -> Optional[int]:
        """
        A relative time in seconds before the current time from which to show logs. If this value
        precedes the time a pod was started, only logs since the pod start will be returned.
        If this value is in the future, no logs will be returned.
        Only one of sinceSeconds or sinceTime may be specified.
        """
        return self.__sinceSeconds

    def sinceTime(self) -> Optional["base.Time"]:
        """
        An RFC3339 timestamp from which to show logs. If this value
        precedes the time a pod was started, only logs since the pod start will be returned.
        If this value is in the future, no logs will be returned.
        Only one of sinceSeconds or sinceTime may be specified.
        """
        return self.__sinceTime

    def timestamps(self) -> Optional[bool]:
        """
        If true, add an RFC3339 or RFC3339Nano timestamp at the beginning of every line
        of log output. Defaults to false.
        """
        return self.__timestamps

    def tailLines(self) -> Optional[int]:
        """
        If set, the number of lines from the end of the logs to show. If not specified,
        logs are shown from the creation of the container or sinceSeconds or sinceTime
        """
        return self.__tailLines

    def limitBytes(self) -> Optional[int]:
        """
        If set, the number of bytes to read from the server before terminating the
        log output. This may not display a complete final line of logging, and may return
        slightly more or slightly less than the specified limit.
        """
        return self.__limitBytes

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
        excludeTriggers: List[DeploymentTriggerType] = None,
    ):
        super().__init__(apiVersion="apps.openshift.io/v1", kind="DeploymentRequest")
        self.__name = name
        self.__latest = latest
        self.__force = force
        self.__excludeTriggers = excludeTriggers if excludeTriggers is not None else []

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
        excludeTriggers = self.excludeTriggers()
        check_type(
            "excludeTriggers", excludeTriggers, Optional[List[DeploymentTriggerType]]
        )
        if excludeTriggers:  # omit empty
            v["excludeTriggers"] = excludeTriggers
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

    def excludeTriggers(self) -> Optional[List[DeploymentTriggerType]]:
        """
        ExcludeTriggers instructs the instantiator to avoid processing the specified triggers.
        This field overrides the triggers from latest and allows clients to control specific
        logic. This field is ignored if not specified.
        """
        return self.__excludeTriggers
