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
    def __init__(self, operator_spec: "operatorv1.OperatorSpec" = None):
        super().__init__()
        self.__operator_spec = (
            operator_spec if operator_spec is not None else operatorv1.OperatorSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operator_spec = self.operator_spec()
        check_type("operator_spec", operator_spec, "operatorv1.OperatorSpec")
        v.update(operator_spec._root())  # inline
        return v

    def operator_spec(self) -> "operatorv1.OperatorSpec":
        return self.__operator_spec


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
            api_version="servicecertsigner.config.openshift.io/v1alpha1",
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
