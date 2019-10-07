# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# ImageReviewContainerSpec is a description of a container within the pod creation request.
class ImageReviewContainerSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        image = self.image()
        if image:  # omit empty
            v['image'] = image
        return v
    
    # This can be in the form image:tag or image@SHA:012345679abcdef.
    @typechecked
    def image(self) -> Optional[str]:
        if 'image' in self._kwargs:
            return self._kwargs['image']
        if 'image' in self._context and check_return_type(self._context['image']):
            return self._context['image']
        return None


# ImageReviewSpec is a description of the pod creation request.
class ImageReviewSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        containers = self.containers()
        if containers:  # omit empty
            v['containers'] = containers
        annotations = self.annotations()
        if annotations:  # omit empty
            v['annotations'] = annotations
        namespace = self.namespace()
        if namespace:  # omit empty
            v['namespace'] = namespace
        return v
    
    # Containers is a list of a subset of the information in each container of the Pod being created.
    @typechecked
    def containers(self) -> List[ImageReviewContainerSpec]:
        if 'containers' in self._kwargs:
            return self._kwargs['containers']
        if 'containers' in self._context and check_return_type(self._context['containers']):
            return self._context['containers']
        return []
    
    # Annotations is a list of key-value pairs extracted from the Pod's annotations.
    # It only includes keys which match the pattern `*.image-policy.k8s.io/*`.
    # It is up to each webhook backend to determine how to interpret these annotations, if at all.
    @typechecked
    def annotations(self) -> Dict[str, str]:
        if 'annotations' in self._kwargs:
            return self._kwargs['annotations']
        if 'annotations' in self._context and check_return_type(self._context['annotations']):
            return self._context['annotations']
        return {}
    
    # Namespace is the namespace the pod is being created in.
    @typechecked
    def namespace(self) -> Optional[str]:
        if 'namespace' in self._kwargs:
            return self._kwargs['namespace']
        if 'namespace' in self._context and check_return_type(self._context['namespace']):
            return self._context['namespace']
        return None


# ImageReview checks if the set of images in a pod are allowed.
class ImageReview(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'imagepolicy.k8s.io/v1alpha1'
    
    @typechecked
    def kind(self) -> str:
        return 'ImageReview'
    
    # Spec holds information about the pod being evaluated
    @typechecked
    def spec(self) -> ImageReviewSpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return ImageReviewSpec()
