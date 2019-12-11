# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kubespec.k8s import base
from kubespec.k8s.apimachinery import runtime
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


class AdmissionPluginConfiguration(types.Object):
    """
    AdmissionPluginConfiguration provides the configuration for a single plug-in.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, name: str = "", path: str = "", configuration: "runtime.Unknown" = None
    ):
        super().__init__()
        self.__name = name
        self.__path = path
        self.__configuration = configuration

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        configuration = self.configuration()
        check_type("configuration", configuration, Optional["runtime.Unknown"])
        v["configuration"] = configuration
        return v

    def name(self) -> str:
        """
        Name is the name of the admission controller.
        It must match the registered admission plugin name.
        """
        return self.__name

    def path(self) -> str:
        """
        Path is the path to a configuration file that contains the plugin's
        configuration
        """
        return self.__path

    def configuration(self) -> Optional["runtime.Unknown"]:
        """
        Configuration is an embedded configuration object to be used as the plugin's
        configuration. If present, it will be used instead of the path to the configuration file.
        """
        return self.__configuration


class AdmissionConfiguration(base.TypedObject):
    """
    AdmissionConfiguration provides versioned configuration for admission controllers.
    """

    @context.scoped
    @typechecked
    def __init__(self, plugins: List["AdmissionPluginConfiguration"] = None):
        super().__init__(
            apiVersion="apiserver.config.k8s.io/v1", kind="AdmissionConfiguration"
        )
        self.__plugins = plugins if plugins is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        plugins = self.plugins()
        check_type("plugins", plugins, List["AdmissionPluginConfiguration"])
        v["plugins"] = plugins
        return v

    def plugins(self) -> List["AdmissionPluginConfiguration"]:
        """
        Plugins allows specifying a configuration per admission control plugin.
        """
        return self.__plugins
