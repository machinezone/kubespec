# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional, Union


# InsecureEdgeTerminationPolicyType dictates the behavior of insecure
# connections to an edge-terminated route.
InsecureEdgeTerminationPolicyType = base.Enum(
    "InsecureEdgeTerminationPolicyType",
    {
        # Allow allows insecure connections for an edge-terminated route.
        "Allow": "Allow",
        # None disables insecure connections for an edge-terminated route.
        "None": "None",
        # Redirect redirects insecure connections for an edge-terminated route.
        # As an example, for routers that support HTTP and HTTPS, the
        # insecure HTTP connections will be redirected to use HTTPS.
        "Redirect": "Redirect",
    },
)


# TLSTerminationType dictates where the secure communication will stop
# TODO: Reconsider this type in v2
TLSTerminationType = base.Enum(
    "TLSTerminationType",
    {
        # Edge terminate encryption at the edge router.
        "Edge": "edge",
        # Passthrough terminate encryption at the destination, the destination is responsible for decrypting traffic
        "Passthrough": "passthrough",
        # Reencrypt terminate encryption at the edge router and re-encrypt it with a new certificate supplied by the destination
        "Reencrypt": "reencrypt",
    },
)


# WildcardPolicyType indicates the type of wildcard support needed by routes.
WildcardPolicyType = base.Enum(
    "WildcardPolicyType",
    {
        # None indicates no wildcard support is needed.
        "None": "None",
        # Subdomain indicates the host needs wildcard support for the subdomain.
        # Example: For host = "www.acme.test", indicates that the router
        #          should support requests for *.acme.test
        #          Note that this will not match acme.test only *.acme.test
        "Subdomain": "Subdomain",
    },
)


class RoutePort(types.Object):
    """
    RoutePort defines a port mapping from a router to an endpoint in the service endpoints.
    """

    @context.scoped
    @typechecked
    def __init__(self, targetPort: Union[int, str] = None):
        super().__init__()
        self.__targetPort = targetPort if targetPort is not None else 0

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        targetPort = self.targetPort()
        check_type("targetPort", targetPort, Union[int, str])
        v["targetPort"] = targetPort
        return v

    def targetPort(self) -> Union[int, str]:
        """
        The target port on pods selected by the service this route points to.
        If this is a string, it will be looked up as a named port in the target
        endpoints port list. Required
        """
        return self.__targetPort


class RouteTargetReference(types.Object):
    """
    RouteTargetReference specifies the target that resolve into endpoints. Only the 'Service'
    kind is allowed. Use 'weight' field to emphasize one over others.
    """

    @context.scoped
    @typechecked
    def __init__(self, kind: str = "Service", name: str = "", weight: int = None):
        super().__init__()
        self.__kind = kind
        self.__name = name
        self.__weight = weight if weight is not None else 100

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        weight = self.weight()
        check_type("weight", weight, Optional[int])
        v["weight"] = weight
        return v

    def kind(self) -> str:
        """
        The kind of target that the route is referring to. Currently, only 'Service' is allowed
        """
        return self.__kind

    def name(self) -> str:
        """
        name of the service/target that is being referred to. e.g. name of the service
        """
        return self.__name

    def weight(self) -> Optional[int]:
        """
        weight as an integer between 0 and 256, default 100, that specifies the target's relative weight
        against other target reference objects. 0 suppresses requests to this backend.
        """
        return self.__weight


class TLSConfig(types.Object):
    """
    TLSConfig defines config used to secure a route and provide termination
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        termination: TLSTerminationType = TLSTerminationType["Edge"],
        certificate: str = None,
        key: str = None,
        caCertificate: str = None,
        destinationCACertificate: str = None,
        insecureEdgeTerminationPolicy: InsecureEdgeTerminationPolicyType = None,
    ):
        super().__init__()
        self.__termination = termination
        self.__certificate = certificate
        self.__key = key
        self.__caCertificate = caCertificate
        self.__destinationCACertificate = destinationCACertificate
        self.__insecureEdgeTerminationPolicy = insecureEdgeTerminationPolicy

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        termination = self.termination()
        check_type("termination", termination, TLSTerminationType)
        v["termination"] = termination
        certificate = self.certificate()
        check_type("certificate", certificate, Optional[str])
        if certificate:  # omit empty
            v["certificate"] = certificate
        key = self.key()
        check_type("key", key, Optional[str])
        if key:  # omit empty
            v["key"] = key
        caCertificate = self.caCertificate()
        check_type("caCertificate", caCertificate, Optional[str])
        if caCertificate:  # omit empty
            v["caCertificate"] = caCertificate
        destinationCACertificate = self.destinationCACertificate()
        check_type("destinationCACertificate", destinationCACertificate, Optional[str])
        if destinationCACertificate:  # omit empty
            v["destinationCACertificate"] = destinationCACertificate
        insecureEdgeTerminationPolicy = self.insecureEdgeTerminationPolicy()
        check_type(
            "insecureEdgeTerminationPolicy",
            insecureEdgeTerminationPolicy,
            Optional[InsecureEdgeTerminationPolicyType],
        )
        if insecureEdgeTerminationPolicy:  # omit empty
            v["insecureEdgeTerminationPolicy"] = insecureEdgeTerminationPolicy
        return v

    def termination(self) -> TLSTerminationType:
        """
        termination indicates termination type.
        """
        return self.__termination

    def certificate(self) -> Optional[str]:
        """
        certificate provides certificate contents
        """
        return self.__certificate

    def key(self) -> Optional[str]:
        """
        key provides key file contents
        """
        return self.__key

    def caCertificate(self) -> Optional[str]:
        """
        caCertificate provides the cert authority certificate contents
        """
        return self.__caCertificate

    def destinationCACertificate(self) -> Optional[str]:
        """
        destinationCACertificate provides the contents of the ca certificate of the final destination.  When using reencrypt
        termination this file should be provided in order to have routers use it for health checks on the secure connection.
        If this field is not specified, the router may provide its own destination CA and perform hostname validation using
        the short service name (service.namespace.svc), which allows infrastructure generated certificates to automatically
        verify.
        """
        return self.__destinationCACertificate

    def insecureEdgeTerminationPolicy(
        self
    ) -> Optional[InsecureEdgeTerminationPolicyType]:
        """
        insecureEdgeTerminationPolicy indicates the desired behavior for insecure connections to a route. While
        each router may make its own decisions on which ports to expose, this is normally port 80.
        
        * Allow - traffic is sent to the server on the insecure port (default)
        * Disable - no traffic is allowed on the insecure port.
        * Redirect - clients are redirected to the secure port.
        """
        return self.__insecureEdgeTerminationPolicy


class RouteSpec(types.Object):
    """
    RouteSpec describes the hostname or path the route exposes, any security information,
    and one to four backends (services) the route points to. Requests are distributed
    among the backends depending on the weights assigned to each backend. When using
    roundrobin scheduling the portion of requests that go to each backend is the backend
    weight divided by the sum of all of the backend weights. When the backend has more than
    one endpoint the requests that end up on the backend are roundrobin distributed among
    the endpoints. Weights are between 0 and 256 with default 100. Weight 0 causes no requests
    to the backend. If all weights are zero the route will be considered to have no backends
    and return a standard 503 response.
    
    The `tls` field is optional and allows specific certificates or behavior for the
    route. Routers typically configure a default certificate on a wildcard domain to
    terminate routes without explicit certificates, but custom hostnames usually must
    choose passthrough (send traffic directly to the backend via the TLS Server-Name-
    Indication field) or provide a certificate.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        host: str = "",
        subdomain: str = None,
        path: str = None,
        to: "RouteTargetReference" = None,
        alternateBackends: List["RouteTargetReference"] = None,
        port: "RoutePort" = None,
        tls: "TLSConfig" = None,
        wildcardPolicy: WildcardPolicyType = WildcardPolicyType["None"],
    ):
        super().__init__()
        self.__host = host
        self.__subdomain = subdomain
        self.__path = path
        self.__to = to if to is not None else RouteTargetReference()
        self.__alternateBackends = (
            alternateBackends if alternateBackends is not None else []
        )
        self.__port = port
        self.__tls = tls
        self.__wildcardPolicy = wildcardPolicy

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        host = self.host()
        check_type("host", host, str)
        v["host"] = host
        subdomain = self.subdomain()
        check_type("subdomain", subdomain, Optional[str])
        if subdomain:  # omit empty
            v["subdomain"] = subdomain
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        to = self.to()
        check_type("to", to, "RouteTargetReference")
        v["to"] = to
        alternateBackends = self.alternateBackends()
        check_type(
            "alternateBackends",
            alternateBackends,
            Optional[List["RouteTargetReference"]],
        )
        if alternateBackends:  # omit empty
            v["alternateBackends"] = alternateBackends
        port = self.port()
        check_type("port", port, Optional["RoutePort"])
        if port is not None:  # omit empty
            v["port"] = port
        tls = self.tls()
        check_type("tls", tls, Optional["TLSConfig"])
        if tls is not None:  # omit empty
            v["tls"] = tls
        wildcardPolicy = self.wildcardPolicy()
        check_type("wildcardPolicy", wildcardPolicy, Optional[WildcardPolicyType])
        if wildcardPolicy:  # omit empty
            v["wildcardPolicy"] = wildcardPolicy
        return v

    def host(self) -> str:
        """
        host is an alias/DNS that points to the service. Optional.
        If not specified a route name will typically be automatically
        chosen.
        Must follow DNS952 subdomain conventions.
        """
        return self.__host

    def subdomain(self) -> Optional[str]:
        """
        subdomain is a DNS subdomain that is requested within the ingress controller's
        domain (as a subdomain). If host is set this field is ignored. An ingress
        controller may choose to ignore this suggested name, in which case the controller
        will report the assigned name in the status.ingress array or refuse to admit the
        route. If this value is set and the server does not support this field host will
        be populated automatically. Otherwise host is left empty. The field may have
        multiple parts separated by a dot, but not all ingress controllers may honor
        the request. This field may not be changed after creation except by a user with
        the update routes/custom-host permission.
        
        Example: subdomain `frontend` automatically receives the router subdomain
        `apps.mycluster.com` to have a full hostname `frontend.apps.mycluster.com`.
        """
        return self.__subdomain

    def path(self) -> Optional[str]:
        """
        path that the router watches for, to route traffic for to the service. Optional
        """
        return self.__path

    def to(self) -> "RouteTargetReference":
        """
        to is an object the route should use as the primary backend. Only the Service kind
        is allowed, and it will be defaulted to Service. If the weight field (0-256 default 100)
        is set to zero, no traffic will be sent to this backend.
        """
        return self.__to

    def alternateBackends(self) -> Optional[List["RouteTargetReference"]]:
        """
        alternateBackends allows up to 3 additional backends to be assigned to the route.
        Only the Service kind is allowed, and it will be defaulted to Service.
        Use the weight field in RouteTargetReference object to specify relative preference.
        """
        return self.__alternateBackends

    def port(self) -> Optional["RoutePort"]:
        """
        If specified, the port to be used by the router. Most routers will use all
        endpoints exposed by the service by default - set this value to instruct routers
        which port to use.
        """
        return self.__port

    def tls(self) -> Optional["TLSConfig"]:
        """
        The tls field provides the ability to configure certificates and termination for the route.
        """
        return self.__tls

    def wildcardPolicy(self) -> Optional[WildcardPolicyType]:
        """
        Wildcard policy if any for the route.
        Currently only 'Subdomain' or 'None' is allowed.
        """
        return self.__wildcardPolicy


class Route(base.TypedObject, base.NamespacedMetadataObject):
    """
    A route allows developers to expose services through an HTTP(S) aware load balancing and proxy
    layer via a public DNS entry. The route may further specify TLS options and a certificate, or
    specify a public CNAME that the router should also accept for HTTP and HTTPS traffic. An
    administrator typically configures their router to be visible outside the cluster firewall, and
    may also add additional security, caching, or traffic controls on the service content. Routers
    usually talk directly to the service endpoints.
    
    Once a route is created, the `host` field may not be changed. Generally, routers use the oldest
    route with a given host when resolving conflicts.
    
    Routers are subject to additional customization and may support additional controls via the
    annotations field.
    
    Because administrators may configure multiple routers, the route status field is used to
    return information to clients about the names and states of the route under each router.
    If a client chooses a duplicate name, for instance, the route status conditions are used
    to indicate the route cannot be chosen.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "RouteSpec" = None,
    ):
        super().__init__(
            apiVersion="route.openshift.io/v1",
            kind="Route",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else RouteSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "RouteSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "RouteSpec":
        """
        spec is the desired state of the route
        """
        return self.__spec
