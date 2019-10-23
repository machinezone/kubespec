# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


class ConfigMapTemplate(base.NamespacedMetadataObject):
    """
    ConfigMapTemplate is a ConfigMap template.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        data: Dict[str, str] = None,
        binaryData: Dict[str, bytes] = None,
    ):
        super().__init__(
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__data = data if data is not None else {}
        self.__binaryData = binaryData if binaryData is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        data = self.data()
        check_type("data", data, Optional[Dict[str, str]])
        if data:  # omit empty
            v["data"] = data
        binaryData = self.binaryData()
        check_type("binaryData", binaryData, Optional[Dict[str, bytes]])
        if binaryData:  # omit empty
            v["binaryData"] = binaryData
        return v

    def data(self) -> Optional[Dict[str, str]]:
        """
        Data contains the configuration data.
        Each key must consist of alphanumeric characters, '-', '_' or '.'.
        Values with non-UTF-8 byte sequences must use the BinaryData field.
        The keys stored in Data must not overlap with the keys in
        the BinaryData field.
        """
        return self.__data

    def binaryData(self) -> Optional[Dict[str, bytes]]:
        """
        BinaryData contains the binary data.
        Each key must consist of alphanumeric characters, '-', '_' or '.'.
        BinaryData can contain byte sequences that are not in the UTF-8 range.
        The keys stored in BinaryData must not overlap with the keys in
        the Data field.
        """
        return self.__binaryData


class TemplateVariable(types.Object):
    """
    TemplateVariable is a template variable.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        value: str = None,
        secretValue: "corev1.SecretKeySelector" = None,
        configMapValue: "corev1.ConfigMapKeySelector" = None,
    ):
        super().__init__()
        self.__name = name
        self.__value = value
        self.__secretValue = secretValue
        self.__configMapValue = configMapValue

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        value = self.value()
        check_type("value", value, Optional[str])
        if value:  # omit empty
            v["value"] = value
        secretValue = self.secretValue()
        check_type("secretValue", secretValue, Optional["corev1.SecretKeySelector"])
        if secretValue is not None:  # omit empty
            v["secretValue"] = secretValue
        configMapValue = self.configMapValue()
        check_type(
            "configMapValue", configMapValue, Optional["corev1.ConfigMapKeySelector"]
        )
        if configMapValue is not None:  # omit empty
            v["configMapValue"] = configMapValue
        return v

    def name(self) -> str:
        """
        Name of the template variable.
        """
        return self.__name

    def value(self) -> Optional[str]:
        """
        Variable references $(VAR_NAME) are expanded using the previous defined
        environment variables in the ConfigMapSecret. If a variable cannot be resolved,
        the reference in the input string will be unchanged. The $(VAR_NAME) syntax
        can be escaped with a double $$, ie: $$(VAR_NAME). Escaped references will
        never be expanded, regardless of whether the variable exists or not.
        Defaults to "".
        """
        return self.__value

    def secretValue(self) -> Optional["corev1.SecretKeySelector"]:
        """
        SecretValue selects a value by its key in a Secret.
        """
        return self.__secretValue

    def configMapValue(self) -> Optional["corev1.ConfigMapKeySelector"]:
        """
        ConfigMapValue selects a value by its key in a ConfigMap.
        """
        return self.__configMapValue


class ConfigMapSecretSpec(types.Object):
    """
    ConfigMapSecretSpec defines the desired state of a ConfigMapSecret.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        template: ConfigMapTemplate = None,
        vars: Dict[str, TemplateVariable] = None,
    ):
        super().__init__()
        self.__template = template if template is not None else ConfigMapTemplate()
        self.__vars = vars if vars is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        template = self.template()
        check_type("template", template, Optional[ConfigMapTemplate])
        v["template"] = template
        vars = self.vars()
        check_type("vars", vars, Optional[Dict[str, TemplateVariable]])
        if vars:  # omit empty
            v["vars"] = vars.values()  # named list
        return v

    def template(self) -> Optional[ConfigMapTemplate]:
        """
        Template that describes the config that will be rendered.
        Variable references $(VAR_NAME) in template data are expanded using the
        ConfigMapSecret's variables. If a variable cannot be resolved, the reference
        in the input data will be unchanged. The $(VAR_NAME) syntax can be escaped
        with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
        regardless of whether the variable exists or not.
        """
        return self.__template

    def vars(self) -> Optional[Dict[str, TemplateVariable]]:
        """
        List of template variables.
        """
        return self.__vars


class ConfigMapSecret(base.TypedObject, base.NamespacedMetadataObject):
    """
    ConfigMapSecret holds configuration data with embedded secrets.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: ConfigMapSecretSpec = None,
    ):
        super().__init__(
            apiVersion="secrets.k8s.mz.com/v1alpha1",
            kind="ConfigMapSecret",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ConfigMapSecretSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional[ConfigMapSecretSpec])
        v["spec"] = spec
        return v

    def spec(self) -> Optional[ConfigMapSecretSpec]:
        """
        Desired state of the ConfigMapSecret.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec
