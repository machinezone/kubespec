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
from typing import Any, Dict, List, Optional


class PodPresetSpec(types.Object):
    """
    PodPresetSpec is a description of a pod preset.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        selector: "metav1.LabelSelector" = None,
        env: List["k8sv1.EnvVar"] = None,
        env_from: List["k8sv1.EnvFromSource"] = None,
        volumes: List["k8sv1.Volume"] = None,
        volume_mounts: List["k8sv1.VolumeMount"] = None,
    ):
        super().__init__()
        self.__selector = selector if selector is not None else metav1.LabelSelector()
        self.__env = env if env is not None else []
        self.__env_from = env_from if env_from is not None else []
        self.__volumes = volumes if volumes is not None else []
        self.__volume_mounts = volume_mounts if volume_mounts is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        v["selector"] = selector
        env = self.env()
        check_type("env", env, Optional[List["k8sv1.EnvVar"]])
        if env:  # omit empty
            v["env"] = env
        env_from = self.env_from()
        check_type("env_from", env_from, Optional[List["k8sv1.EnvFromSource"]])
        if env_from:  # omit empty
            v["envFrom"] = env_from
        volumes = self.volumes()
        check_type("volumes", volumes, Optional[List["k8sv1.Volume"]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        volume_mounts = self.volume_mounts()
        check_type("volume_mounts", volume_mounts, Optional[List["k8sv1.VolumeMount"]])
        if volume_mounts:  # omit empty
            v["volumeMounts"] = volume_mounts
        return v

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        Selector is a label query over a set of resources, in this case pods.
        Required.
        """
        return self.__selector

    def env(self) -> Optional[List["k8sv1.EnvVar"]]:
        """
        Env defines the collection of EnvVar to inject into containers.
        """
        return self.__env

    def env_from(self) -> Optional[List["k8sv1.EnvFromSource"]]:
        """
        EnvFrom defines the collection of EnvFromSource to inject into containers.
        """
        return self.__env_from

    def volumes(self) -> Optional[List["k8sv1.Volume"]]:
        """
        Volumes defines the collection of Volume to inject into the pod.
        """
        return self.__volumes

    def volume_mounts(self) -> Optional[List["k8sv1.VolumeMount"]]:
        """
        VolumeMounts defines the collection of VolumeMount to inject into containers.
        """
        return self.__volume_mounts


class PodPreset(base.TypedObject, base.NamespacedMetadataObject):
    """
    PodPreset is a policy resource that defines additional runtime
    requirements for a Pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PodPresetSpec" = None,
    ):
        super().__init__(
            api_version="settings.k8s.io/v1alpha1",
            kind="PodPreset",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PodPresetSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["PodPresetSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["PodPresetSpec"]:
        return self.__spec
