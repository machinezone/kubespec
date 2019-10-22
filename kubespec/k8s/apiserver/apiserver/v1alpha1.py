# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec.k8s.apimachinery import runtime
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# AdmissionPluginConfiguration provides the configuration for a single plug-in.
class AdmissionPluginConfiguration(types.Object):
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


# AdmissionConfiguration provides versioned configuration for admission controllers.
class AdmissionConfiguration(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(self, plugins: Dict[str, AdmissionPluginConfiguration] = None):
        super().__init__(
            apiVersion="apiserver.k8s.io/v1alpha1", kind="AdmissionConfiguration"
        )
        self.__plugins = plugins if plugins is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        plugins = self.plugins()
        check_type("plugins", plugins, Dict[str, AdmissionPluginConfiguration])
        v["plugins"] = plugins.values()  # named list
        return v

    def plugins(self) -> Dict[str, AdmissionPluginConfiguration]:
        """
        Plugins allows specifying a configuration per admission control plugin.
        """
        return self.__plugins


class HTTPConnectConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = "",
        caBundle: str = None,
        clientKey: str = None,
        clientCert: str = None,
    ):
        super().__init__()
        self.__url = url
        self.__caBundle = caBundle
        self.__clientKey = clientKey
        self.__clientCert = clientCert

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        caBundle = self.caBundle()
        check_type("caBundle", caBundle, Optional[str])
        if caBundle:  # omit empty
            v["caBundle"] = caBundle
        clientKey = self.clientKey()
        check_type("clientKey", clientKey, Optional[str])
        if clientKey:  # omit empty
            v["clientKey"] = clientKey
        clientCert = self.clientCert()
        check_type("clientCert", clientCert, Optional[str])
        if clientCert:  # omit empty
            v["clientCert"] = clientCert
        return v

    def url(self) -> str:
        """
        url is the location of the proxy server to connect to.
        As an example it might be "https://127.0.0.1:8131"
        """
        return self.__url

    def caBundle(self) -> Optional[str]:
        """
        caBundle is the file location of the CA to be used to determine trust with the konnectivity server.
        Must be absent/empty http-connect using the plain http
        Must be configured for http-connect using the https protocol
        Misconfiguration will cause an error
        """
        return self.__caBundle

    def clientKey(self) -> Optional[str]:
        """
        clientKey is the file location of the client key to be used in mtls handshakes with the konnectivity server.
        Must be absent/empty http-connect using the plain http
        Must be configured for http-connect using the https protocol
        Misconfiguration will cause an error
        """
        return self.__clientKey

    def clientCert(self) -> Optional[str]:
        """
        clientCert is the file location of the client certificate to be used in mtls handshakes with the konnectivity server.
        Must be absent/empty http-connect using the plain http
        Must be configured for http-connect using the https protocol
        Misconfiguration will cause an error
        """
        return self.__clientCert


# Connection provides the configuration for a single egress selection client.
class Connection(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, type: str = "", httpConnect: HTTPConnectConfig = None):
        super().__init__()
        self.__type = type
        self.__httpConnect = httpConnect

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, str)
        v["type"] = type
        httpConnect = self.httpConnect()
        check_type("httpConnect", httpConnect, Optional[HTTPConnectConfig])
        if httpConnect is not None:  # omit empty
            v["httpConnect"] = httpConnect
        return v

    def type(self) -> str:
        """
        type is the type of connection used to connect from client to network/konnectivity server.
        Currently supported values are "http-connect" and "direct".
        """
        return self.__type

    def httpConnect(self) -> Optional[HTTPConnectConfig]:
        """
        httpConnect is the config needed to use http-connect to the konnectivity server.
        Absence when the type is "http-connect" will cause an error
        Presence when the type is "direct" will also cause an error
        """
        return self.__httpConnect


# EgressSelection provides the configuration for a single egress selection client.
class EgressSelection(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = "", connection: Connection = None):
        super().__init__()
        self.__name = name
        self.__connection = connection if connection is not None else Connection()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        connection = self.connection()
        check_type("connection", connection, Connection)
        v["connection"] = connection
        return v

    def name(self) -> str:
        """
        name is the name of the egress selection.
        Currently supported values are "Master", "Etcd" and "Cluster"
        """
        return self.__name

    def connection(self) -> Connection:
        """
        connection is the exact information used to configure the egress selection
        """
        return self.__connection


# EgressSelectorConfiguration provides versioned configuration for egress selector clients.
class EgressSelectorConfiguration(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(self, egressSelections: Dict[str, EgressSelection] = None):
        super().__init__(
            apiVersion="apiserver.k8s.io/v1alpha1", kind="EgressSelectorConfiguration"
        )
        self.__egressSelections = (
            egressSelections if egressSelections is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        egressSelections = self.egressSelections()
        check_type("egressSelections", egressSelections, Dict[str, EgressSelection])
        v["egressSelections"] = egressSelections.values()  # named list
        return v

    def egressSelections(self) -> Dict[str, EgressSelection]:
        """
        connectionServices contains a list of egress selection client configurations
        """
        return self.__egressSelections
