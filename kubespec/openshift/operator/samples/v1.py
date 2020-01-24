# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.openshift.operator import v1 as operatorv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


class ConfigSpec(types.Object):
    """
    ConfigSpec contains the desired configuration and state for the Samples Operator, controlling
    various behavior around the imagestreams and templates it creates/updates in the
    openshift namespace.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        management_state: operatorv1.ManagementState = None,
        samples_registry: str = None,
        architectures: List[str] = None,
        skipped_imagestreams: List[str] = None,
        skipped_templates: List[str] = None,
    ):
        super().__init__()
        self.__management_state = management_state
        self.__samples_registry = samples_registry
        self.__architectures = architectures if architectures is not None else []
        self.__skipped_imagestreams = (
            skipped_imagestreams if skipped_imagestreams is not None else []
        )
        self.__skipped_templates = (
            skipped_templates if skipped_templates is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        management_state = self.management_state()
        check_type(
            "management_state", management_state, Optional[operatorv1.ManagementState]
        )
        if management_state:  # omit empty
            v["managementState"] = management_state
        samples_registry = self.samples_registry()
        check_type("samples_registry", samples_registry, Optional[str])
        if samples_registry:  # omit empty
            v["samplesRegistry"] = samples_registry
        architectures = self.architectures()
        check_type("architectures", architectures, Optional[List[str]])
        if architectures:  # omit empty
            v["architectures"] = architectures
        skipped_imagestreams = self.skipped_imagestreams()
        check_type("skipped_imagestreams", skipped_imagestreams, Optional[List[str]])
        if skipped_imagestreams:  # omit empty
            v["skippedImagestreams"] = skipped_imagestreams
        skipped_templates = self.skipped_templates()
        check_type("skipped_templates", skipped_templates, Optional[List[str]])
        if skipped_templates:  # omit empty
            v["skippedTemplates"] = skipped_templates
        return v

    def management_state(self) -> Optional[operatorv1.ManagementState]:
        """
        managementState is top level on/off type of switch for all operators.
        When "Managed", this operator processes config and manipulates the samples accordingly.
        When "Unmanaged", this operator ignores any updates to the resources it watches.
        When "Removed", it reacts that same wasy as it does if the Config object
        is deleted, meaning any ImageStreams or Templates it manages (i.e. it honors the skipped
        lists) and the registry secret are deleted, along with the ConfigMap in the operator's
        namespace that represents the last config used to manipulate the samples,
        """
        return self.__management_state

    def samples_registry(self) -> Optional[str]:
        """
        samplesRegistry allows for the specification of which registry is accessed
        by the ImageStreams for their image content.  Defaults on the content in https://github.com/openshift/library
        that are pulled into this github repository, but based on our pulling only ocp content it typically
        defaults to registry.redhat.io.
        """
        return self.__samples_registry

    def architectures(self) -> Optional[List[str]]:
        """
        architectures determine which hardware architecture(s) to install, where x86_64, ppc64le, and s390x are the only
        supported choices currently.
        """
        return self.__architectures

    def skipped_imagestreams(self) -> Optional[List[str]]:
        """
        skippedImagestreams specifies names of image streams that should NOT be
        created/updated.  Admins can use this to allow them to delete content
        they don’t want.  They will still have to manually delete the
        content but the operator will not recreate(or update) anything
        listed here.
        """
        return self.__skipped_imagestreams

    def skipped_templates(self) -> Optional[List[str]]:
        """
        skippedTemplates specifies names of templates that should NOT be
        created/updated.  Admins can use this to allow them to delete content
        they don’t want.  They will still have to manually delete the
        content but the operator will not recreate(or update) anything
        listed here.
        """
        return self.__skipped_templates


class Config(base.TypedObject, base.MetadataObject):
    """
    Config contains the configuration and detailed condition status for the Samples Operator.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ConfigSpec" = None,
    ):
        super().__init__(
            api_version="samples.operator.openshift.io/v1",
            kind="Config",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ConfigSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ConfigSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ConfigSpec":
        """
        +required
        """
        return self.__spec
