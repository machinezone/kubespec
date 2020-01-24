# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


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
            api_version="apiserver.k8s.io/v1alpha1", kind="AdmissionConfiguration"
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


class HTTPConnectConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = "",
        ca_bundle: str = None,
        client_key: str = None,
        client_cert: str = None,
    ):
        super().__init__()
        self.__url = url
        self.__ca_bundle = ca_bundle
        self.__client_key = client_key
        self.__client_cert = client_cert

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        ca_bundle = self.ca_bundle()
        check_type("ca_bundle", ca_bundle, Optional[str])
        if ca_bundle:  # omit empty
            v["caBundle"] = ca_bundle
        client_key = self.client_key()
        check_type("client_key", client_key, Optional[str])
        if client_key:  # omit empty
            v["clientKey"] = client_key
        client_cert = self.client_cert()
        check_type("client_cert", client_cert, Optional[str])
        if client_cert:  # omit empty
            v["clientCert"] = client_cert
        return v

    def url(self) -> str:
        """
        url is the location of the proxy server to connect to.
        As an example it might be "https://127.0.0.1:8131"
        """
        return self.__url

    def ca_bundle(self) -> Optional[str]:
        """
        caBundle is the file location of the CA to be used to determine trust with the konnectivity server.
        Must be absent/empty http-connect using the plain http
        Must be configured for http-connect using the https protocol
        Misconfiguration will cause an error
        """
        return self.__ca_bundle

    def client_key(self) -> Optional[str]:
        """
        clientKey is the file location of the client key to be used in mtls handshakes with the konnectivity server.
        Must be absent/empty http-connect using the plain http
        Must be configured for http-connect using the https protocol
        Misconfiguration will cause an error
        """
        return self.__client_key

    def client_cert(self) -> Optional[str]:
        """
        clientCert is the file location of the client certificate to be used in mtls handshakes with the konnectivity server.
        Must be absent/empty http-connect using the plain http
        Must be configured for http-connect using the https protocol
        Misconfiguration will cause an error
        """
        return self.__client_cert


class Connection(types.Object):
    """
    Connection provides the configuration for a single egress selection client.
    """

    @context.scoped
    @typechecked
    def __init__(self, type: str = "", http_connect: "HTTPConnectConfig" = None):
        super().__init__()
        self.__type = type
        self.__http_connect = http_connect

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, str)
        v["type"] = type
        http_connect = self.http_connect()
        check_type("http_connect", http_connect, Optional["HTTPConnectConfig"])
        if http_connect is not None:  # omit empty
            v["httpConnect"] = http_connect
        return v

    def type(self) -> str:
        """
        type is the type of connection used to connect from client to network/konnectivity server.
        Currently supported values are "http-connect" and "direct".
        """
        return self.__type

    def http_connect(self) -> Optional["HTTPConnectConfig"]:
        """
        httpConnect is the config needed to use http-connect to the konnectivity server.
        Absence when the type is "http-connect" will cause an error
        Presence when the type is "direct" will also cause an error
        """
        return self.__http_connect


class EgressSelection(types.Object):
    """
    EgressSelection provides the configuration for a single egress selection client.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", connection: "Connection" = None):
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
        check_type("connection", connection, "Connection")
        v["connection"] = connection
        return v

    def name(self) -> str:
        """
        name is the name of the egress selection.
        Currently supported values are "Master", "Etcd" and "Cluster"
        """
        return self.__name

    def connection(self) -> "Connection":
        """
        connection is the exact information used to configure the egress selection
        """
        return self.__connection


class EgressSelectorConfiguration(base.TypedObject):
    """
    EgressSelectorConfiguration provides versioned configuration for egress selector clients.
    """

    @context.scoped
    @typechecked
    def __init__(self, egress_selections: List["EgressSelection"] = None):
        super().__init__(
            api_version="apiserver.k8s.io/v1alpha1", kind="EgressSelectorConfiguration"
        )
        self.__egress_selections = (
            egress_selections if egress_selections is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        egress_selections = self.egress_selections()
        check_type("egress_selections", egress_selections, List["EgressSelection"])
        v["egressSelections"] = egress_selections
        return v

    def egress_selections(self) -> List["EgressSelection"]:
        """
        connectionServices contains a list of egress selection client configurations
        """
        return self.__egress_selections
