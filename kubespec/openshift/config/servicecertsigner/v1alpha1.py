# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from kubespec.openshift.config import v1 as configv1
from kubespec.openshift.operator import v1 as operatorv1
from typeguard import check_type, typechecked
from typing import Any, Dict


class APIServiceCABundleInjectorConfig(base.TypedObject):
    """
    APIServiceCABundleInjectorConfig provides information to configure an APIService CA Bundle Injector controller
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        genericControllerConfig: "configv1.GenericControllerConfig" = None,
        caBundleFile: str = "",
    ):
        super().__init__(
            apiVersion="servicecertsigner.config.openshift.io/v1alpha1",
            kind="APIServiceCABundleInjectorConfig",
        )
        self.__genericControllerConfig = (
            genericControllerConfig
            if genericControllerConfig is not None
            else configv1.GenericControllerConfig()
        )
        self.__caBundleFile = caBundleFile

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        genericControllerConfig = self.genericControllerConfig()
        check_type(
            "genericControllerConfig",
            genericControllerConfig,
            "configv1.GenericControllerConfig",
        )
        v.update(genericControllerConfig._root())  # inline
        caBundleFile = self.caBundleFile()
        check_type("caBundleFile", caBundleFile, str)
        v["caBundleFile"] = caBundleFile
        return v

    def genericControllerConfig(self) -> "configv1.GenericControllerConfig":
        """
        This configuration is not meant to be edited by humans as
        it is normally managed by the service cert signer operator.
        ServiceCertSignerOperatorConfig's spec.apiServiceCABundleInjectorConfig
        can be used to override the defaults for this configuration.
        """
        return self.__genericControllerConfig

    def caBundleFile(self) -> str:
        """
        caBundleFile holds the ca bundle to apply to APIServices.
        """
        return self.__caBundleFile


class ConfigMapCABundleInjectorConfig(base.TypedObject):
    """
    ConfigMapCABundleInjectorConfig provides information to configure a ConfigMap CA Bundle Injector controller
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        genericControllerConfig: "configv1.GenericControllerConfig" = None,
        caBundleFile: str = "",
    ):
        super().__init__(
            apiVersion="servicecertsigner.config.openshift.io/v1alpha1",
            kind="ConfigMapCABundleInjectorConfig",
        )
        self.__genericControllerConfig = (
            genericControllerConfig
            if genericControllerConfig is not None
            else configv1.GenericControllerConfig()
        )
        self.__caBundleFile = caBundleFile

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        genericControllerConfig = self.genericControllerConfig()
        check_type(
            "genericControllerConfig",
            genericControllerConfig,
            "configv1.GenericControllerConfig",
        )
        v.update(genericControllerConfig._root())  # inline
        caBundleFile = self.caBundleFile()
        check_type("caBundleFile", caBundleFile, str)
        v["caBundleFile"] = caBundleFile
        return v

    def genericControllerConfig(self) -> "configv1.GenericControllerConfig":
        """
        This configuration is not meant to be edited by humans as
        it is normally managed by the service cert signer operator.
        ServiceCertSignerOperatorConfig's spec.configMapCABundleInjectorConfig
        can be used to override the defaults for this configuration.
        """
        return self.__genericControllerConfig

    def caBundleFile(self) -> str:
        """
        caBundleFile holds the ca bundle to apply to ConfigMaps.
        """
        return self.__caBundleFile


class ServiceCertSignerOperatorConfigSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        operatorSpec: "operatorv1.OperatorSpec" = None,
        serviceServingCertSignerConfig: "runtime.RawExtension" = None,
        apiServiceCABundleInjectorConfig: "runtime.RawExtension" = None,
        configMapCABundleInjectorConfig: "runtime.RawExtension" = None,
    ):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else operatorv1.OperatorSpec()
        )
        self.__serviceServingCertSignerConfig = serviceServingCertSignerConfig
        self.__apiServiceCABundleInjectorConfig = apiServiceCABundleInjectorConfig
        self.__configMapCABundleInjectorConfig = configMapCABundleInjectorConfig

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "operatorv1.OperatorSpec")
        v.update(operatorSpec._root())  # inline
        serviceServingCertSignerConfig = self.serviceServingCertSignerConfig()
        check_type(
            "serviceServingCertSignerConfig",
            serviceServingCertSignerConfig,
            "runtime.RawExtension",
        )
        v["serviceServingCertSignerConfig"] = serviceServingCertSignerConfig
        apiServiceCABundleInjectorConfig = self.apiServiceCABundleInjectorConfig()
        check_type(
            "apiServiceCABundleInjectorConfig",
            apiServiceCABundleInjectorConfig,
            "runtime.RawExtension",
        )
        v["apiServiceCABundleInjectorConfig"] = apiServiceCABundleInjectorConfig
        configMapCABundleInjectorConfig = self.configMapCABundleInjectorConfig()
        check_type(
            "configMapCABundleInjectorConfig",
            configMapCABundleInjectorConfig,
            "runtime.RawExtension",
        )
        v["configMapCABundleInjectorConfig"] = configMapCABundleInjectorConfig
        return v

    def operatorSpec(self) -> "operatorv1.OperatorSpec":
        return self.__operatorSpec

    def serviceServingCertSignerConfig(self) -> "runtime.RawExtension":
        """
        serviceServingCertSignerConfig holds a sparse config that the user wants for this component.  It only needs to be the overrides from the defaults
        it will end up overlaying in the following order:
        1. hardcoded default
        2. this config
        """
        return self.__serviceServingCertSignerConfig

    def apiServiceCABundleInjectorConfig(self) -> "runtime.RawExtension":
        """
        apiServiceCABundleInjectorConfig holds a sparse config that the user wants for this component.  It only needs to be the overrides from the defaults
        it will end up overlaying in the following order:
        1. hardcoded default
        2. this config
        """
        return self.__apiServiceCABundleInjectorConfig

    def configMapCABundleInjectorConfig(self) -> "runtime.RawExtension":
        """
        configMapCABundleInjectorConfig holds a sparse config that the user wants for this component.  It only needs to be the overrides from the defaults
        it will end up overlaying in the following order:
        1. hardcoded default
        2. this config
        """
        return self.__configMapCABundleInjectorConfig


class ServiceCertSignerOperatorConfig(base.TypedObject, base.MetadataObject):
    """
    ServiceCertSignerOperatorConfig provides information to configure an operator to manage the service cert signing controllers
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ServiceCertSignerOperatorConfigSpec" = None,
    ):
        super().__init__(
            apiVersion="servicecertsigner.config.openshift.io/v1alpha1",
            kind="ServiceCertSignerOperatorConfig",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = (
            spec if spec is not None else ServiceCertSignerOperatorConfigSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ServiceCertSignerOperatorConfigSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ServiceCertSignerOperatorConfigSpec":
        return self.__spec


class ServiceServingCertSignerConfig(base.TypedObject):
    """
    ServiceServingCertSignerConfig provides information to configure a serving serving cert signing controller
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        genericControllerConfig: "configv1.GenericControllerConfig" = None,
        signer: "configv1.CertInfo" = None,
        intermediateCertFile: str = "",
    ):
        super().__init__(
            apiVersion="servicecertsigner.config.openshift.io/v1alpha1",
            kind="ServiceServingCertSignerConfig",
        )
        self.__genericControllerConfig = (
            genericControllerConfig
            if genericControllerConfig is not None
            else configv1.GenericControllerConfig()
        )
        self.__signer = signer if signer is not None else configv1.CertInfo()
        self.__intermediateCertFile = intermediateCertFile

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        genericControllerConfig = self.genericControllerConfig()
        check_type(
            "genericControllerConfig",
            genericControllerConfig,
            "configv1.GenericControllerConfig",
        )
        v.update(genericControllerConfig._root())  # inline
        signer = self.signer()
        check_type("signer", signer, "configv1.CertInfo")
        v["signer"] = signer
        intermediateCertFile = self.intermediateCertFile()
        check_type("intermediateCertFile", intermediateCertFile, str)
        v["intermediateCertFile"] = intermediateCertFile
        return v

    def genericControllerConfig(self) -> "configv1.GenericControllerConfig":
        """
        This configuration is not meant to be edited by humans as
        it is normally managed by the service cert signer operator.
        ServiceCertSignerOperatorConfig's spec.serviceServingCertSignerConfig
        can be used to override the defaults for this configuration.
        """
        return self.__genericControllerConfig

    def signer(self) -> "configv1.CertInfo":
        """
        signer holds the signing information used to automatically sign serving certificates.
        """
        return self.__signer

    def intermediateCertFile(self) -> str:
        """
        IntermediateCertFile is the name of a file containing a
        PEM-encoded certificate. Only required if the initial CA has
        been rotated. The certificate should consist of the public key
        of the current CA signed by the private key of the previous
        CA. When included with a serving cert generated by the current
        CA, this certificate should allow clients with a stale CA bundle
        to trust the serving cert.
        """
        return self.__intermediateCertFile
