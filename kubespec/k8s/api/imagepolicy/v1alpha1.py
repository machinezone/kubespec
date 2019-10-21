# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# ImageReviewContainerSpec is a description of a container within the pod creation request.
class ImageReviewContainerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, image: str = None):
        super().__init__(**{})
        self.__image = image

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        image = self.image()
        check_type("image", image, Optional[str])
        if image:  # omit empty
            v["image"] = image
        return v

    # This can be in the form image:tag or image@SHA:012345679abcdef.
    def image(self) -> Optional[str]:
        return self.__image


# ImageReviewSpec is a description of the pod creation request.
class ImageReviewSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        containers: List[ImageReviewContainerSpec] = None,
        annotations: Dict[str, str] = None,
        namespace: str = None,
    ):
        super().__init__(**{})
        self.__containers = containers if containers is not None else []
        self.__annotations = annotations if annotations is not None else {}
        self.__namespace = namespace

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        containers = self.containers()
        check_type("containers", containers, Optional[List[ImageReviewContainerSpec]])
        if containers:  # omit empty
            v["containers"] = containers
        annotations = self.annotations()
        check_type("annotations", annotations, Optional[Dict[str, str]])
        if annotations:  # omit empty
            v["annotations"] = annotations
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        return v

    # Containers is a list of a subset of the information in each container of the Pod being created.
    def containers(self) -> Optional[List[ImageReviewContainerSpec]]:
        return self.__containers

    # Annotations is a list of key-value pairs extracted from the Pod's annotations.
    # It only includes keys which match the pattern `*.image-policy.k8s.io/*`.
    # It is up to each webhook backend to determine how to interpret these annotations, if at all.
    def annotations(self) -> Optional[Dict[str, str]]:
        return self.__annotations

    # Namespace is the namespace the pod is being created in.
    def namespace(self) -> Optional[str]:
        return self.__namespace


# ImageReview checks if the set of images in a pod are allowed.
class ImageReview(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: ImageReviewSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "imagepolicy.k8s.io/v1alpha1",
                "kind": "ImageReview",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else ImageReviewSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, ImageReviewSpec)
        v["spec"] = spec
        return v

    # Spec holds information about the pod being evaluated
    def spec(self) -> ImageReviewSpec:
        return self.__spec
