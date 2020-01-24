# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


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
        binary_data: Dict[str, bytes] = None,
    ):
        super().__init__(
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__data = data if data is not None else {}
        self.__binary_data = binary_data if binary_data is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        data = self.data()
        check_type("data", data, Optional[Dict[str, str]])
        if data:  # omit empty
            v["data"] = data
        binary_data = self.binary_data()
        check_type("binary_data", binary_data, Optional[Dict[str, bytes]])
        if binary_data:  # omit empty
            v["binaryData"] = binary_data
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

    def binary_data(self) -> Optional[Dict[str, bytes]]:
        """
        BinaryData contains the binary data.
        Each key must consist of alphanumeric characters, '-', '_' or '.'.
        BinaryData can contain byte sequences that are not in the UTF-8 range.
        The keys stored in BinaryData must not overlap with the keys in
        the Data field.
        """
        return self.__binary_data


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
        secret_value: "k8sv1.SecretKeySelector" = None,
        config_map_value: "k8sv1.ConfigMapKeySelector" = None,
    ):
        super().__init__()
        self.__name = name
        self.__value = value
        self.__secret_value = secret_value
        self.__config_map_value = config_map_value

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
        secret_value = self.secret_value()
        check_type("secret_value", secret_value, Optional["k8sv1.SecretKeySelector"])
        if secret_value is not None:  # omit empty
            v["secretValue"] = secret_value
        config_map_value = self.config_map_value()
        check_type(
            "config_map_value", config_map_value, Optional["k8sv1.ConfigMapKeySelector"]
        )
        if config_map_value is not None:  # omit empty
            v["configMapValue"] = config_map_value
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

    def secret_value(self) -> Optional["k8sv1.SecretKeySelector"]:
        """
        SecretValue selects a value by its key in a Secret.
        """
        return self.__secret_value

    def config_map_value(self) -> Optional["k8sv1.ConfigMapKeySelector"]:
        """
        ConfigMapValue selects a value by its key in a ConfigMap.
        """
        return self.__config_map_value


class ConfigMapSecretSpec(types.Object):
    """
    ConfigMapSecretSpec defines the desired state of a ConfigMapSecret.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        template: "ConfigMapTemplate" = None,
        vars: List["TemplateVariable"] = None,
    ):
        super().__init__()
        self.__template = template if template is not None else ConfigMapTemplate()
        self.__vars = vars if vars is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        template = self.template()
        check_type("template", template, Optional["ConfigMapTemplate"])
        v["template"] = template
        vars = self.vars()
        check_type("vars", vars, Optional[List["TemplateVariable"]])
        if vars:  # omit empty
            v["vars"] = vars
        return v

    def template(self) -> Optional["ConfigMapTemplate"]:
        """
        Template that describes the config that will be rendered.
        Variable references $(VAR_NAME) in template data are expanded using the
        ConfigMapSecret's variables. If a variable cannot be resolved, the reference
        in the input data will be unchanged. The $(VAR_NAME) syntax can be escaped
        with a double $$, ie: $$(VAR_NAME). Escaped references will never be expanded,
        regardless of whether the variable exists or not.
        """
        return self.__template

    def vars(self) -> Optional[List["TemplateVariable"]]:
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
        spec: "ConfigMapSecretSpec" = None,
    ):
        super().__init__(
            api_version="secrets.mz.com/v1alpha1",
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
        check_type("spec", spec, Optional["ConfigMapSecretSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["ConfigMapSecretSpec"]:
        """
        Desired state of the ConfigMapSecret.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec
