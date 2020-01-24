# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


class SecretTemplateSpec(base.NamespacedMetadataObject):
    """
    SecretTemplateSpec describes the structure a Secret should have
    when created from a template
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        type: k8sv1.SecretType = None,
    ):
        super().__init__(
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__type = type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[k8sv1.SecretType])
        if type:  # omit empty
            v["type"] = type
        return v

    def type(self) -> Optional[k8sv1.SecretType]:
        """
        Used to facilitate programmatic handling of secret data.
        """
        return self.__type


class SealedSecretSpec(types.Object):
    """
    SealedSecretSpec is the specification of a SealedSecret
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        template: "SecretTemplateSpec" = None,
        data: bytes = None,
        encrypted_data: Dict[str, str] = None,
    ):
        super().__init__()
        self.__template = template if template is not None else SecretTemplateSpec()
        self.__data = data if data is not None else b""
        self.__encrypted_data = encrypted_data if encrypted_data is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        template = self.template()
        check_type("template", template, Optional["SecretTemplateSpec"])
        v["template"] = template
        data = self.data()
        check_type("data", data, Optional[bytes])
        if data:  # omit empty
            v["data"] = data
        encrypted_data = self.encrypted_data()
        check_type("encrypted_data", encrypted_data, Dict[str, str])
        v["encryptedData"] = encrypted_data
        return v

    def template(self) -> Optional["SecretTemplateSpec"]:
        """
        Template defines the structure of the Secret that will be
        created from this sealed secret.
        """
        return self.__template

    def data(self) -> Optional[bytes]:
        """
        Data is deprecated and will be removed eventually. Use per-value EncryptedData instead.
        """
        return self.__data

    def encrypted_data(self) -> Dict[str, str]:
        return self.__encrypted_data


class SealedSecret(base.TypedObject, base.NamespacedMetadataObject):
    """
    SealedSecret is the K8s representation of a "sealed Secret" - a
    regular k8s Secret that has been sealed (encrypted) using the
    controller's key.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "SealedSecretSpec" = None,
    ):
        super().__init__(
            api_version="bitnami.com/v1alpha1",
            kind="SealedSecret",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else SealedSecretSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "SealedSecretSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "SealedSecretSpec":
        return self.__spec
