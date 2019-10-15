# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import typechecked


# PodPresetSpec is a description of a pod preset.
class PodPresetSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        selector: "metav1.LabelSelector" = None,
        env: Dict[str, "corev1.EnvVar"] = None,
        envFrom: List["corev1.EnvFromSource"] = None,
        volumes: Dict[str, "corev1.Volume"] = None,
        volumeMounts: Dict[str, "corev1.VolumeMount"] = None,
    ):
        super().__init__(**{})
        self.__selector = selector if selector is not None else metav1.LabelSelector()
        self.__env = env if env is not None else {}
        self.__envFrom = envFrom if envFrom is not None else []
        self.__volumes = volumes if volumes is not None else {}
        self.__volumeMounts = volumeMounts if volumeMounts is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["selector"] = self.selector()
        env = self.env()
        if env:  # omit empty
            v["env"] = env.values()  # named list
        envFrom = self.envFrom()
        if envFrom:  # omit empty
            v["envFrom"] = envFrom
        volumes = self.volumes()
        if volumes:  # omit empty
            v["volumes"] = volumes.values()  # named list
        volumeMounts = self.volumeMounts()
        if volumeMounts:  # omit empty
            v["volumeMounts"] = volumeMounts.values()  # named list
        return v

    # Selector is a label query over a set of resources, in this case pods.
    # Required.
    @typechecked
    def selector(self) -> Optional["metav1.LabelSelector"]:
        return self.__selector

    # Env defines the collection of EnvVar to inject into containers.
    @typechecked
    def env(self) -> Optional[Dict[str, "corev1.EnvVar"]]:
        return self.__env

    # EnvFrom defines the collection of EnvFromSource to inject into containers.
    @typechecked
    def envFrom(self) -> Optional[List["corev1.EnvFromSource"]]:
        return self.__envFrom

    # Volumes defines the collection of Volume to inject into the pod.
    @typechecked
    def volumes(self) -> Optional[Dict[str, "corev1.Volume"]]:
        return self.__volumes

    # VolumeMounts defines the collection of VolumeMount to inject into containers.
    @typechecked
    def volumeMounts(self) -> Optional[Dict[str, "corev1.VolumeMount"]]:
        return self.__volumeMounts


# PodPreset is a policy resource that defines additional runtime
# requirements for a Pod.
class PodPreset(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: PodPresetSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "settings.k8s.io/v1alpha1",
                "kind": "PodPreset",
                **({"namespace": namespace} if namespace is not None else {}),
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else PodPresetSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    @typechecked
    def spec(self) -> Optional[PodPresetSpec]:
        return self.__spec
