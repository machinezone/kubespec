# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.apimachinery import runtime
from kargo import types
from typeguard import typechecked


# AdmissionPluginConfiguration provides the configuration for a single plug-in.
class AdmissionPluginConfiguration(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['name'] = self.name()
        v['path'] = self.path()
        v['configuration'] = self.configuration()
        return v
    
    # Name is the name of the admission controller.
    # It must match the registered admission plugin name.
    @typechecked
    def name(self) -> str:
        return self._kwargs.get('name', '')
    
    # Path is the path to a configuration file that contains the plugin's
    # configuration
    @typechecked
    def path(self) -> str:
        return self._kwargs.get('path', '')
    
    # Configuration is an embedded configuration object to be used as the plugin's
    # configuration. If present, it will be used instead of the path to the configuration file.
    @typechecked
    def configuration(self) -> Optional['runtime.Unknown']:
        return self._kwargs.get('configuration')


# AdmissionConfiguration provides versioned configuration for admission controllers.
class AdmissionConfiguration(base.TypedObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['plugins'] = self.plugins().values()  # named list
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'apiserver.k8s.io/v1alpha1'
    
    @typechecked
    def kind(self) -> str:
        return 'AdmissionConfiguration'
    
    # Plugins allows specifying a configuration per admission control plugin.
    @typechecked
    def plugins(self) -> Dict[str, AdmissionPluginConfiguration]:
        return self._kwargs.get('plugins', {})


class HTTPConnectConfig(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['url'] = self.url()
        caBundle = self.caBundle()
        if caBundle:  # omit empty
            v['caBundle'] = caBundle
        clientKey = self.clientKey()
        if clientKey:  # omit empty
            v['clientKey'] = clientKey
        clientCert = self.clientCert()
        if clientCert:  # omit empty
            v['clientCert'] = clientCert
        return v
    
    # url is the location of the proxy server to connect to.
    # As an example it might be "https://127.0.0.1:8131"
    @typechecked
    def url(self) -> str:
        return self._kwargs.get('url', '')
    
    # caBundle is the file location of the CA to be used to determine trust with the konnectivity server.
    # Must be absent/empty http-connect using the plain http
    # Must be configured for http-connect using the https protocol
    # Misconfiguration will cause an error
    @typechecked
    def caBundle(self) -> Optional[str]:
        return self._kwargs.get('caBundle')
    
    # clientKey is the file location of the client key to be used in mtls handshakes with the konnectivity server.
    # Must be absent/empty http-connect using the plain http
    # Must be configured for http-connect using the https protocol
    # Misconfiguration will cause an error
    @typechecked
    def clientKey(self) -> Optional[str]:
        return self._kwargs.get('clientKey')
    
    # clientCert is the file location of the client certificate to be used in mtls handshakes with the konnectivity server.
    # Must be absent/empty http-connect using the plain http
    # Must be configured for http-connect using the https protocol
    # Misconfiguration will cause an error
    @typechecked
    def clientCert(self) -> Optional[str]:
        return self._kwargs.get('clientCert')


# Connection provides the configuration for a single egress selection client.
class Connection(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['type'] = self.type()
        httpConnect = self.httpConnect()
        if httpConnect is not None:  # omit empty
            v['httpConnect'] = httpConnect
        return v
    
    # type is the type of connection used to connect from client to network/konnectivity server.
    # Currently supported values are "http-connect" and "direct".
    @typechecked
    def type(self) -> str:
        return self._kwargs.get('type', '')
    
    # httpConnect is the config needed to use http-connect to the konnectivity server.
    # Absence when the type is "http-connect" will cause an error
    # Presence when the type is "direct" will also cause an error
    @typechecked
    def httpConnect(self) -> Optional[HTTPConnectConfig]:
        return self._kwargs.get('httpConnect')


# EgressSelection provides the configuration for a single egress selection client.
class EgressSelection(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['name'] = self.name()
        v['connection'] = self.connection()
        return v
    
    # name is the name of the egress selection.
    # Currently supported values are "Master", "Etcd" and "Cluster"
    @typechecked
    def name(self) -> str:
        return self._kwargs.get('name', '')
    
    # connection is the exact information used to configure the egress selection
    @typechecked
    def connection(self) -> Connection:
        return self._kwargs.get('connection', Connection())


# EgressSelectorConfiguration provides versioned configuration for egress selector clients.
class EgressSelectorConfiguration(base.TypedObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['egressSelections'] = self.egressSelections().values()  # named list
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'apiserver.k8s.io/v1alpha1'
    
    @typechecked
    def kind(self) -> str:
        return 'EgressSelectorConfiguration'
    
    # connectionServices contains a list of egress selection client configurations
    @typechecked
    def egressSelections(self) -> Dict[str, EgressSelection]:
        return self._kwargs.get('egressSelections', {})
