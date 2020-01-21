# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.openshift.operator import v1 as operatorv1
from typeguard import check_type, typechecked
from typing import Any, Dict


class ServiceCertSignerOperatorConfigSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, operatorSpec: "operatorv1.OperatorSpec" = None):
        super().__init__()
        self.__operatorSpec = (
            operatorSpec if operatorSpec is not None else operatorv1.OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operatorSpec = self.operatorSpec()
        check_type("operatorSpec", operatorSpec, "operatorv1.OperatorSpec")
        v.update(operatorSpec._root())  # inline
        return v

    def operatorSpec(self) -> "operatorv1.OperatorSpec":
        return self.__operatorSpec


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
