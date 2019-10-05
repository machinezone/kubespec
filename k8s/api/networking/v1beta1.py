# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import List, Optional, Union

import addict
from k8s import base
from korps import types
from typeguard import typechecked


# IngressBackend describes all endpoints for a given service and port.
class IngressBackend(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['serviceName'] = self.serviceName()
        v['servicePort'] = self.servicePort()
        return v
    
    # Specifies the name of the referenced service.
    @typechecked
    def serviceName(self) -> str:
        return self._kwargs.get('serviceName', '')
    
    # Specifies the port of the referenced service.
    @typechecked
    def servicePort(self) -> Union[int, str]:
        return self._kwargs.get('servicePort', 0)


# HTTPIngressPath associates a path regex with a backend. Incoming urls matching
# the path are forwarded to the backend.
class HTTPIngressPath(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        path = self.path()
        if path:  # omit empty
            v['path'] = path
        v['backend'] = self.backend()
        return v
    
    # Path is an extended POSIX regex as defined by IEEE Std 1003.1,
    # (i.e this follows the egrep/unix syntax, not the perl syntax)
    # matched against the path of an incoming request. Currently it can
    # contain characters disallowed from the conventional "path"
    # part of a URL as defined by RFC 3986. Paths must begin with
    # a '/'. If unspecified, the path defaults to a catch all sending
    # traffic to the backend.
    @typechecked
    def path(self) -> Optional[str]:
        return self._kwargs.get('path')
    
    # Backend defines the referenced service endpoint to which the traffic
    # will be forwarded to.
    @typechecked
    def backend(self) -> IngressBackend:
        return self._kwargs.get('backend', IngressBackend())


# HTTPIngressRuleValue is a list of http selectors pointing to backends.
# In the example: http://<host>/<path>?<searchpart> -> backend where
# where parts of the url correspond to RFC 3986, this resource will be used
# to match against everything after the last '/' and before the first '?'
# or '#'.
class HTTPIngressRuleValue(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['paths'] = self.paths()
        return v
    
    # A collection of paths that map requests to backends.
    @typechecked
    def paths(self) -> List[HTTPIngressPath]:
        return self._kwargs.get('paths', [])


# IngressRuleValue represents a rule to apply against incoming requests. If the
# rule is satisfied, the request is routed to the specified backend. Currently
# mixing different types of rules in a single Ingress is disallowed, so exactly
# one of the following must be set.
class IngressRuleValue(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        http = self.http()
        if http is not None:  # omit empty
            v['http'] = http
        return v
    
    @typechecked
    def http(self) -> Optional[HTTPIngressRuleValue]:
        return self._kwargs.get('http')


# IngressRule represents the rules mapping the paths under a specified host to
# the related backend services. Incoming requests are first evaluated for a host
# match, then routed to the backend associated with the matching IngressRuleValue.
class IngressRule(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        host = self.host()
        if host:  # omit empty
            v['host'] = host
        v.update(self.ingressRuleValue().render())  # inline
        return v
    
    # Host is the fully qualified domain name of a network host, as defined
    # by RFC 3986. Note the following deviations from the "host" part of the
    # URI as defined in the RFC:
    # 1. IPs are not allowed. Currently an IngressRuleValue can only apply to the
    # 	  IP in the Spec of the parent Ingress.
    # 2. The `:` delimiter is not respected because ports are not allowed.
    # 	  Currently the port of an Ingress is implicitly :80 for http and
    # 	  :443 for https.
    # Both these may change in the future.
    # Incoming requests are matched against the host before the IngressRuleValue.
    # If the host is unspecified, the Ingress routes all traffic based on the
    # specified IngressRuleValue.
    @typechecked
    def host(self) -> Optional[str]:
        return self._kwargs.get('host')
    
    # IngressRuleValue represents a rule to route requests for this IngressRule.
    # If unspecified, the rule defaults to a http catch-all. Whether that sends
    # just traffic matching the host to the default backend or all traffic to the
    # default backend, is left to the controller fulfilling the Ingress. Http is
    # currently the only supported IngressRuleValue.
    @typechecked
    def ingressRuleValue(self) -> Optional[IngressRuleValue]:
        return self._kwargs.get('ingressRuleValue')


# IngressTLS describes the transport layer security associated with an Ingress.
class IngressTLS(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        hosts = self.hosts()
        if hosts:  # omit empty
            v['hosts'] = hosts
        secretName = self.secretName()
        if secretName:  # omit empty
            v['secretName'] = secretName
        return v
    
    # Hosts are a list of hosts included in the TLS certificate. The values in
    # this list must match the name/s used in the tlsSecret. Defaults to the
    # wildcard host setting for the loadbalancer controller fulfilling this
    # Ingress, if left unspecified.
    @typechecked
    def hosts(self) -> List[str]:
        return self._kwargs.get('hosts', [])
    
    # SecretName is the name of the secret used to terminate SSL traffic on 443.
    # Field is left optional to allow SSL routing based on SNI hostname alone.
    # If the SNI host in a listener conflicts with the "Host" header field used
    # by an IngressRule, the SNI host is used for termination and value of the
    # Host header is used for routing.
    @typechecked
    def secretName(self) -> Optional[str]:
        return self._kwargs.get('secretName')


# IngressSpec describes the Ingress the user wishes to exist.
class IngressSpec(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        backend = self.backend()
        if backend is not None:  # omit empty
            v['backend'] = backend
        tls = self.tls()
        if tls:  # omit empty
            v['tls'] = tls
        rules = self.rules()
        if rules:  # omit empty
            v['rules'] = rules
        return v
    
    # A default backend capable of servicing requests that don't match any
    # rule. At least one of 'backend' or 'rules' must be specified. This field
    # is optional to allow the loadbalancer controller or defaulting logic to
    # specify a global default.
    @typechecked
    def backend(self) -> Optional[IngressBackend]:
        return self._kwargs.get('backend')
    
    # TLS configuration. Currently the Ingress only supports a single TLS
    # port, 443. If multiple members of this list specify different hosts, they
    # will be multiplexed on the same port according to the hostname specified
    # through the SNI TLS extension, if the ingress controller fulfilling the
    # ingress supports SNI.
    @typechecked
    def tls(self) -> List[IngressTLS]:
        return self._kwargs.get('tls', [])
    
    # A list of host rules used to configure the Ingress. If unspecified, or
    # no rule matches, all traffic is sent to the default backend.
    @typechecked
    def rules(self) -> List[IngressRule]:
        return self._kwargs.get('rules', [])


# Ingress is a collection of rules that allow inbound connections to reach the
# endpoints defined by a backend. An Ingress can be configured to give services
# externally-reachable urls, load balance traffic, terminate SSL, offer name
# based virtual hosting etc.
class Ingress(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        spec = self.spec()
        if spec:  # omit empty
            v['spec'] = spec
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'networking.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'Ingress'
    
    # Spec is the desired state of the Ingress.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> Optional[IngressSpec]:
        return self._kwargs.get('spec')
