# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


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


# Policy defines the configuration of how audit events are logged
class Policy(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["level"] = self.level()
        v["stages"] = self.stages()
        return v

    # The Level that all requests are recorded at.
    # available options: None, Metadata, Request, RequestResponse
    # required
    @typechecked
    def level(self) -> Level:
        if "level" in self._kwargs:
            return self._kwargs["level"]
        if "level" in self._context and check_return_type(self._context["level"]):
            return self._context["level"]
        return None

    # Stages is a list of stages for which events are created.
    @typechecked
    def stages(self) -> List[Stage]:
        if "stages" in self._kwargs:
            return self._kwargs["stages"]
        if "stages" in self._context and check_return_type(self._context["stages"]):
            return self._context["stages"]
        return []


# ServiceReference holds a reference to Service.legacy.k8s.io
class ServiceReference(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["namespace"] = self.namespace()
        v["name"] = self.name()
        path = self.path()
        if path is not None:  # omit empty
            v["path"] = path
        port = self.port()
        if port is not None:  # omit empty
            v["port"] = port
        return v

    # `namespace` is the namespace of the service.
    # Required
    @typechecked
    def namespace(self) -> str:
        if "namespace" in self._kwargs:
            return self._kwargs["namespace"]
        if "namespace" in self._context and check_return_type(
            self._context["namespace"]
        ):
            return self._context["namespace"]
        return ""

    # `name` is the name of the service.
    # Required
    @typechecked
    def name(self) -> str:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return ""

    # `path` is an optional URL path which will be sent in any request to
    # this service.
    @typechecked
    def path(self) -> Optional[str]:
        if "path" in self._kwargs:
            return self._kwargs["path"]
        if "path" in self._context and check_return_type(self._context["path"]):
            return self._context["path"]
        return None

    # If specified, the port on the service that hosting webhook.
    # Default to 443 for backward compatibility.
    # `port` should be a valid port number (1-65535, inclusive).
    @typechecked
    def port(self) -> Optional[int]:
        if "port" in self._kwargs:
            return self._kwargs["port"]
        if "port" in self._context and check_return_type(self._context["port"]):
            return self._context["port"]
        return 443


# WebhookClientConfig contains the information to make a connection with the webhook
class WebhookClientConfig(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        url = self.url()
        if url is not None:  # omit empty
            v["url"] = url
        service = self.service()
        if service is not None:  # omit empty
            v["service"] = service
        caBundle = self.caBundle()
        if caBundle:  # omit empty
            v["caBundle"] = caBundle
        return v

    # `url` gives the location of the webhook, in standard URL form
    # (`scheme://host:port/path`). Exactly one of `url` or `service`
    # must be specified.
    #
    # The `host` should not refer to a service running in the cluster; use
    # the `service` field instead. The host might be resolved via external
    # DNS in some apiservers (e.g., `kube-apiserver` cannot resolve
    # in-cluster DNS as that would be a layering violation). `host` may
    # also be an IP address.
    #
    # Please note that using `localhost` or `127.0.0.1` as a `host` is
    # risky unless you take great care to run this webhook on all hosts
    # which run an apiserver which might need to make calls to this
    # webhook. Such installs are likely to be non-portable, i.e., not easy
    # to turn up in a new cluster.
    #
    # The scheme must be "https"; the URL must begin with "https://".
    #
    # A path is optional, and if present may be any string permissible in
    # a URL. You may use the path to pass an arbitrary string to the
    # webhook, for example, a cluster identifier.
    #
    # Attempting to use a user or basic auth e.g. "user:password@" is not
    # allowed. Fragments ("#...") and query parameters ("?...") are not
    # allowed, either.
    @typechecked
    def url(self) -> Optional[str]:
        if "url" in self._kwargs:
            return self._kwargs["url"]
        if "url" in self._context and check_return_type(self._context["url"]):
            return self._context["url"]
        return None

    # `service` is a reference to the service for this webhook. Either
    # `service` or `url` must be specified.
    #
    # If the webhook is running within the cluster, then you should use `service`.
    @typechecked
    def service(self) -> Optional[ServiceReference]:
        if "service" in self._kwargs:
            return self._kwargs["service"]
        if "service" in self._context and check_return_type(self._context["service"]):
            return self._context["service"]
        return None

    # `caBundle` is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
    # If unspecified, system trust roots on the apiserver are used.
    @typechecked
    def caBundle(self) -> bytes:
        if "caBundle" in self._kwargs:
            return self._kwargs["caBundle"]
        if "caBundle" in self._context and check_return_type(self._context["caBundle"]):
            return self._context["caBundle"]
        return b""


# WebhookThrottleConfig holds the configuration for throttling events
class WebhookThrottleConfig(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        qps = self.qps()
        if qps is not None:  # omit empty
            v["qps"] = qps
        burst = self.burst()
        if burst is not None:  # omit empty
            v["burst"] = burst
        return v

    # ThrottleQPS maximum number of batches per second
    # default 10 QPS
    @typechecked
    def qps(self) -> Optional[int]:
        if "qps" in self._kwargs:
            return self._kwargs["qps"]
        if "qps" in self._context and check_return_type(self._context["qps"]):
            return self._context["qps"]
        return 10

    # ThrottleBurst is the maximum number of events sent at the same moment
    # default 15 QPS
    @typechecked
    def burst(self) -> Optional[int]:
        if "burst" in self._kwargs:
            return self._kwargs["burst"]
        if "burst" in self._context and check_return_type(self._context["burst"]):
            return self._context["burst"]
        return 15


# Webhook holds the configuration of the webhook
class Webhook(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        throttle = self.throttle()
        if throttle is not None:  # omit empty
            v["throttle"] = throttle
        v["clientConfig"] = self.clientConfig()
        return v

    # Throttle holds the options for throttling the webhook
    @typechecked
    def throttle(self) -> Optional[WebhookThrottleConfig]:
        if "throttle" in self._kwargs:
            return self._kwargs["throttle"]
        if "throttle" in self._context and check_return_type(self._context["throttle"]):
            return self._context["throttle"]
        with context.Scope(**self._context):
            return WebhookThrottleConfig()

    # ClientConfig holds the connection parameters for the webhook
    # required
    @typechecked
    def clientConfig(self) -> WebhookClientConfig:
        if "clientConfig" in self._kwargs:
            return self._kwargs["clientConfig"]
        if "clientConfig" in self._context and check_return_type(
            self._context["clientConfig"]
        ):
            return self._context["clientConfig"]
        with context.Scope(**self._context):
            return WebhookClientConfig()


# AuditSinkSpec holds the spec for the audit sink
class AuditSinkSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["policy"] = self.policy()
        v["webhook"] = self.webhook()
        return v

    # Policy defines the policy for selecting which events should be sent to the webhook
    # required
    @typechecked
    def policy(self) -> Policy:
        if "policy" in self._kwargs:
            return self._kwargs["policy"]
        if "policy" in self._context and check_return_type(self._context["policy"]):
            return self._context["policy"]
        with context.Scope(**self._context):
            return Policy()

    # Webhook to send events
    # required
    @typechecked
    def webhook(self) -> Webhook:
        if "webhook" in self._kwargs:
            return self._kwargs["webhook"]
        if "webhook" in self._context and check_return_type(self._context["webhook"]):
            return self._context["webhook"]
        with context.Scope(**self._context):
            return Webhook()


# AuditSink represents a cluster level audit sink
class AuditSink(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "auditregistration.k8s.io/v1alpha1"

    @typechecked
    def kind(self) -> str:
        return "AuditSink"

    # Spec defines the audit configuration spec
    @typechecked
    def spec(self) -> AuditSinkSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return AuditSinkSpec()
