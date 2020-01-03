# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional, Union


class IngressBackend(types.Object):
    """
    IngressBackend describes all endpoints for a given service and port.
    """

    @context.scoped
    @typechecked
    def __init__(self, serviceName: str = "", servicePort: Union[int, str] = None):
        super().__init__()
        self.__serviceName = serviceName
        self.__servicePort = servicePort if servicePort is not None else 0

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        serviceName = self.serviceName()
        check_type("serviceName", serviceName, str)
        v["serviceName"] = serviceName
        servicePort = self.servicePort()
        check_type("servicePort", servicePort, Union[int, str])
        v["servicePort"] = servicePort
        return v

    def serviceName(self) -> str:
        """
        Specifies the name of the referenced service.
        """
        return self.__serviceName

    def servicePort(self) -> Union[int, str]:
        """
        Specifies the port of the referenced service.
        """
        return self.__servicePort


class HTTPIngressPath(types.Object):
    """
    HTTPIngressPath associates a path regex with a backend. Incoming urls matching
    the path are forwarded to the backend.
    """

    @context.scoped
    @typechecked
    def __init__(self, path: str = None, backend: "IngressBackend" = None):
        super().__init__()
        self.__path = path
        self.__backend = backend if backend is not None else IngressBackend()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        backend = self.backend()
        check_type("backend", backend, "IngressBackend")
        v["backend"] = backend
        return v

    def path(self) -> Optional[str]:
        """
        Path is an extended POSIX regex as defined by IEEE Std 1003.1,
        (i.e this follows the egrep/unix syntax, not the perl syntax)
        matched against the path of an incoming request. Currently it can
        contain characters disallowed from the conventional "path"
        part of a URL as defined by RFC 3986. Paths must begin with
        a '/'. If unspecified, the path defaults to a catch all sending
        traffic to the backend.
        """
        return self.__path

    def backend(self) -> "IngressBackend":
        """
        Backend defines the referenced service endpoint to which the traffic
        will be forwarded to.
        """
        return self.__backend


class HTTPIngressRuleValue(types.Object):
    """
    HTTPIngressRuleValue is a list of http selectors pointing to backends.
    In the example: http://<host>/<path>?<searchpart> -> backend where
    where parts of the url correspond to RFC 3986, this resource will be used
    to match against everything after the last '/' and before the first '?'
    or '#'.
    """

    @context.scoped
    @typechecked
    def __init__(self, paths: List["HTTPIngressPath"] = None):
        super().__init__()
        self.__paths = paths if paths is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        paths = self.paths()
        check_type("paths", paths, List["HTTPIngressPath"])
        v["paths"] = paths
        return v

    def paths(self) -> List["HTTPIngressPath"]:
        """
        A collection of paths that map requests to backends.
        """
        return self.__paths


class IngressRuleValue(types.Object):
    """
    IngressRuleValue represents a rule to apply against incoming requests. If the
    rule is satisfied, the request is routed to the specified backend. Currently
    mixing different types of rules in a single Ingress is disallowed, so exactly
    one of the following must be set.
    """

    @context.scoped
    @typechecked
    def __init__(self, http: "HTTPIngressRuleValue" = None):
        super().__init__()
        self.__http = http

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        http = self.http()
        check_type("http", http, Optional["HTTPIngressRuleValue"])
        if http is not None:  # omit empty
            v["http"] = http
        return v

    def http(self) -> Optional["HTTPIngressRuleValue"]:
        return self.__http


class IngressRule(types.Object):
    """
    IngressRule represents the rules mapping the paths under a specified host to
    the related backend services. Incoming requests are first evaluated for a host
    match, then routed to the backend associated with the matching IngressRuleValue.
    """

    @context.scoped
    @typechecked
    def __init__(self, host: str = None, ingressRuleValue: "IngressRuleValue" = None):
        super().__init__()
        self.__host = host
        self.__ingressRuleValue = (
            ingressRuleValue if ingressRuleValue is not None else IngressRuleValue()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        host = self.host()
        check_type("host", host, Optional[str])
        if host:  # omit empty
            v["host"] = host
        ingressRuleValue = self.ingressRuleValue()
        check_type("ingressRuleValue", ingressRuleValue, Optional["IngressRuleValue"])
        v.update(ingressRuleValue._root())  # inline
        return v

    def host(self) -> Optional[str]:
        """
        Host is the fully qualified domain name of a network host, as defined
        by RFC 3986. Note the following deviations from the "host" part of the
        URI as defined in the RFC:
        1. IPs are not allowed. Currently an IngressRuleValue can only apply to the
        	  IP in the Spec of the parent Ingress.
        2. The `:` delimiter is not respected because ports are not allowed.
        	  Currently the port of an Ingress is implicitly :80 for http and
        	  :443 for https.
        Both these may change in the future.
        Incoming requests are matched against the host before the IngressRuleValue.
        If the host is unspecified, the Ingress routes all traffic based on the
        specified IngressRuleValue.
        """
        return self.__host

    def ingressRuleValue(self) -> Optional["IngressRuleValue"]:
        """
        IngressRuleValue represents a rule to route requests for this IngressRule.
        If unspecified, the rule defaults to a http catch-all. Whether that sends
        just traffic matching the host to the default backend or all traffic to the
        default backend, is left to the controller fulfilling the Ingress. Http is
        currently the only supported IngressRuleValue.
        """
        return self.__ingressRuleValue


class IngressTLS(types.Object):
    """
    IngressTLS describes the transport layer security associated with an Ingress.
    """

    @context.scoped
    @typechecked
    def __init__(self, hosts: List[str] = None, secretName: str = None):
        super().__init__()
        self.__hosts = hosts if hosts is not None else []
        self.__secretName = secretName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        hosts = self.hosts()
        check_type("hosts", hosts, Optional[List[str]])
        if hosts:  # omit empty
            v["hosts"] = hosts
        secretName = self.secretName()
        check_type("secretName", secretName, Optional[str])
        if secretName:  # omit empty
            v["secretName"] = secretName
        return v

    def hosts(self) -> Optional[List[str]]:
        """
        Hosts are a list of hosts included in the TLS certificate. The values in
        this list must match the name/s used in the tlsSecret. Defaults to the
        wildcard host setting for the loadbalancer controller fulfilling this
        Ingress, if left unspecified.
        """
        return self.__hosts

    def secretName(self) -> Optional[str]:
        """
        SecretName is the name of the secret used to terminate SSL traffic on 443.
        Field is left optional to allow SSL routing based on SNI hostname alone.
        If the SNI host in a listener conflicts with the "Host" header field used
        by an IngressRule, the SNI host is used for termination and value of the
        Host header is used for routing.
        """
        return self.__secretName


class IngressSpec(types.Object):
    """
    IngressSpec describes the Ingress the user wishes to exist.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        backend: "IngressBackend" = None,
        tls: List["IngressTLS"] = None,
        rules: List["IngressRule"] = None,
    ):
        super().__init__()
        self.__backend = backend
        self.__tls = tls if tls is not None else []
        self.__rules = rules if rules is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        backend = self.backend()
        check_type("backend", backend, Optional["IngressBackend"])
        if backend is not None:  # omit empty
            v["backend"] = backend
        tls = self.tls()
        check_type("tls", tls, Optional[List["IngressTLS"]])
        if tls:  # omit empty
            v["tls"] = tls
        rules = self.rules()
        check_type("rules", rules, Optional[List["IngressRule"]])
        if rules:  # omit empty
            v["rules"] = rules
        return v

    def backend(self) -> Optional["IngressBackend"]:
        """
        A default backend capable of servicing requests that don't match any
        rule. At least one of 'backend' or 'rules' must be specified. This field
        is optional to allow the loadbalancer controller or defaulting logic to
        specify a global default.
        """
        return self.__backend

    def tls(self) -> Optional[List["IngressTLS"]]:
        """
        TLS configuration. Currently the Ingress only supports a single TLS
        port, 443. If multiple members of this list specify different hosts, they
        will be multiplexed on the same port according to the hostname specified
        through the SNI TLS extension, if the ingress controller fulfilling the
        ingress supports SNI.
        """
        return self.__tls

    def rules(self) -> Optional[List["IngressRule"]]:
        """
        A list of host rules used to configure the Ingress. If unspecified, or
        no rule matches, all traffic is sent to the default backend.
        """
        return self.__rules


class Ingress(base.TypedObject, base.NamespacedMetadataObject):
    """
    Ingress is a collection of rules that allow inbound connections to reach the
    endpoints defined by a backend. An Ingress can be configured to give services
    externally-reachable urls, load balance traffic, terminate SSL, offer name
    based virtual hosting etc.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "IngressSpec" = None,
    ):
        super().__init__(
            apiVersion="networking.k8s.io/v1beta1",
            kind="Ingress",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else IngressSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["IngressSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["IngressSpec"]:
        """
        Spec is the desired state of the Ingress.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec
