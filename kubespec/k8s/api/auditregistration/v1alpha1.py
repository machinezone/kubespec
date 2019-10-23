# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


# Level defines the amount of information logged during auditing
Level = base.Enum(
    "Level",
    {
        # Metadata provides the basic level of auditing.
        "Metadata": "Metadata",
        # None disables auditing
        "None": "None",
        # Request provides Metadata level of auditing, and additionally
        # logs the request object (does not apply for non-resource requests).
        "Request": "Request",
        # RequestResponse provides Request level of auditing, and additionally
        # logs the response object (does not apply for non-resource requests and watches).
        "RequestResponse": "RequestResponse",
    },
)


# Stage defines the stages in request handling during which audit events may be generated.
Stage = base.Enum(
    "Stage",
    {
        # The stage for events generated when a panic occurred.
        "Panic": "Panic",
        # The stage for events generated after the audit handler receives the request, but before it
        # is delegated down the handler chain.
        "RequestReceived": "RequestReceived",
        # The stage for events generated after the response body has been completed, and no more bytes
        # will be sent.
        "ResponseComplete": "ResponseComplete",
        # The stage for events generated after the response headers are sent, but before the response body
        # is sent. This stage is only generated for long-running requests (e.g. watch).
        "ResponseStarted": "ResponseStarted",
    },
)


class Policy(types.Object):
    """
    Policy defines the configuration of how audit events are logged
    """

    @context.scoped
    @typechecked
    def __init__(self, level: Level = None, stages: List[Stage] = None):
        super().__init__()
        self.__level = level
        self.__stages = stages if stages is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        level = self.level()
        check_type("level", level, Level)
        v["level"] = level
        stages = self.stages()
        check_type("stages", stages, List[Stage])
        v["stages"] = stages
        return v

    def level(self) -> Level:
        """
        The Level that all requests are recorded at.
        available options: None, Metadata, Request, RequestResponse
        required
        """
        return self.__level

    def stages(self) -> List[Stage]:
        """
        Stages is a list of stages for which events are created.
        """
        return self.__stages


class ServiceReference(types.Object):
    """
    ServiceReference holds a reference to Service.legacy.k8s.io
    """

    @context.scoped
    @typechecked
    def __init__(
        self, namespace: str = "", name: str = "", path: str = None, port: int = None
    ):
        super().__init__()
        self.__namespace = namespace
        self.__name = name
        self.__path = path
        self.__port = port if port is not None else 443

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, str)
        v["namespace"] = namespace
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        path = self.path()
        check_type("path", path, Optional[str])
        if path is not None:  # omit empty
            v["path"] = path
        port = self.port()
        check_type("port", port, Optional[int])
        if port is not None:  # omit empty
            v["port"] = port
        return v

    def namespace(self) -> str:
        """
        `namespace` is the namespace of the service.
        Required
        """
        return self.__namespace

    def name(self) -> str:
        """
        `name` is the name of the service.
        Required
        """
        return self.__name

    def path(self) -> Optional[str]:
        """
        `path` is an optional URL path which will be sent in any request to
        this service.
        """
        return self.__path

    def port(self) -> Optional[int]:
        """
        If specified, the port on the service that hosting webhook.
        Default to 443 for backward compatibility.
        `port` should be a valid port number (1-65535, inclusive).
        """
        return self.__port


class WebhookClientConfig(types.Object):
    """
    WebhookClientConfig contains the information to make a connection with the webhook
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = None,
        service: "ServiceReference" = None,
        caBundle: bytes = None,
    ):
        super().__init__()
        self.__url = url
        self.__service = service
        self.__caBundle = caBundle if caBundle is not None else b""

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, Optional[str])
        if url is not None:  # omit empty
            v["url"] = url
        service = self.service()
        check_type("service", service, Optional["ServiceReference"])
        if service is not None:  # omit empty
            v["service"] = service
        caBundle = self.caBundle()
        check_type("caBundle", caBundle, Optional[bytes])
        if caBundle:  # omit empty
            v["caBundle"] = caBundle
        return v

    def url(self) -> Optional[str]:
        """
        `url` gives the location of the webhook, in standard URL form
        (`scheme://host:port/path`). Exactly one of `url` or `service`
        must be specified.
        
        The `host` should not refer to a service running in the cluster; use
        the `service` field instead. The host might be resolved via external
        DNS in some apiservers (e.g., `kube-apiserver` cannot resolve
        in-cluster DNS as that would be a layering violation). `host` may
        also be an IP address.
        
        Please note that using `localhost` or `127.0.0.1` as a `host` is
        risky unless you take great care to run this webhook on all hosts
        which run an apiserver which might need to make calls to this
        webhook. Such installs are likely to be non-portable, i.e., not easy
        to turn up in a new cluster.
        
        The scheme must be "https"; the URL must begin with "https://".
        
        A path is optional, and if present may be any string permissible in
        a URL. You may use the path to pass an arbitrary string to the
        webhook, for example, a cluster identifier.
        
        Attempting to use a user or basic auth e.g. "user:password@" is not
        allowed. Fragments ("#...") and query parameters ("?...") are not
        allowed, either.
        """
        return self.__url

    def service(self) -> Optional["ServiceReference"]:
        """
        `service` is a reference to the service for this webhook. Either
        `service` or `url` must be specified.
        
        If the webhook is running within the cluster, then you should use `service`.
        """
        return self.__service

    def caBundle(self) -> Optional[bytes]:
        """
        `caBundle` is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
        If unspecified, system trust roots on the apiserver are used.
        """
        return self.__caBundle


class WebhookThrottleConfig(types.Object):
    """
    WebhookThrottleConfig holds the configuration for throttling events
    """

    @context.scoped
    @typechecked
    def __init__(self, qps: int = None, burst: int = None):
        super().__init__()
        self.__qps = qps if qps is not None else 10
        self.__burst = burst if burst is not None else 15

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        qps = self.qps()
        check_type("qps", qps, Optional[int])
        if qps is not None:  # omit empty
            v["qps"] = qps
        burst = self.burst()
        check_type("burst", burst, Optional[int])
        if burst is not None:  # omit empty
            v["burst"] = burst
        return v

    def qps(self) -> Optional[int]:
        """
        ThrottleQPS maximum number of batches per second
        default 10 QPS
        """
        return self.__qps

    def burst(self) -> Optional[int]:
        """
        ThrottleBurst is the maximum number of events sent at the same moment
        default 15 QPS
        """
        return self.__burst


class Webhook(types.Object):
    """
    Webhook holds the configuration of the webhook
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        throttle: "WebhookThrottleConfig" = None,
        clientConfig: "WebhookClientConfig" = None,
    ):
        super().__init__()
        self.__throttle = throttle if throttle is not None else WebhookThrottleConfig()
        self.__clientConfig = (
            clientConfig if clientConfig is not None else WebhookClientConfig()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        throttle = self.throttle()
        check_type("throttle", throttle, Optional["WebhookThrottleConfig"])
        if throttle is not None:  # omit empty
            v["throttle"] = throttle
        clientConfig = self.clientConfig()
        check_type("clientConfig", clientConfig, "WebhookClientConfig")
        v["clientConfig"] = clientConfig
        return v

    def throttle(self) -> Optional["WebhookThrottleConfig"]:
        """
        Throttle holds the options for throttling the webhook
        """
        return self.__throttle

    def clientConfig(self) -> "WebhookClientConfig":
        """
        ClientConfig holds the connection parameters for the webhook
        required
        """
        return self.__clientConfig


class AuditSinkSpec(types.Object):
    """
    AuditSinkSpec holds the spec for the audit sink
    """

    @context.scoped
    @typechecked
    def __init__(self, policy: "Policy" = None, webhook: "Webhook" = None):
        super().__init__()
        self.__policy = policy if policy is not None else Policy()
        self.__webhook = webhook if webhook is not None else Webhook()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        policy = self.policy()
        check_type("policy", policy, "Policy")
        v["policy"] = policy
        webhook = self.webhook()
        check_type("webhook", webhook, "Webhook")
        v["webhook"] = webhook
        return v

    def policy(self) -> "Policy":
        """
        Policy defines the policy for selecting which events should be sent to the webhook
        required
        """
        return self.__policy

    def webhook(self) -> "Webhook":
        """
        Webhook to send events
        required
        """
        return self.__webhook


class AuditSink(base.TypedObject, base.MetadataObject):
    """
    AuditSink represents a cluster level audit sink
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "AuditSinkSpec" = None,
    ):
        super().__init__(
            apiVersion="auditregistration.k8s.io/v1alpha1",
            kind="AuditSink",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else AuditSinkSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["AuditSinkSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["AuditSinkSpec"]:
        """
        Spec defines the audit configuration spec
        """
        return self.__spec
