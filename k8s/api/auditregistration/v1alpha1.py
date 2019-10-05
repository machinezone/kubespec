# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import List, Optional

import addict
from k8s import base
from kargo import types
from typeguard import typechecked


# Level defines the amount of information logged during auditing
Level = base.Enum('Level', {
    # Metadata provides the basic level of auditing.
    'Metadata': 'Metadata',
    # None disables auditing
    'None': 'None',
    # Request provides Metadata level of auditing, and additionally
    # logs the request object (does not apply for non-resource requests).
    'Request': 'Request',
    # RequestResponse provides Request level of auditing, and additionally
    # logs the response object (does not apply for non-resource requests and watches).
    'RequestResponse': 'RequestResponse',
})


# Stage defines the stages in request handling during which audit events may be generated.
Stage = base.Enum('Stage', {
    # The stage for events generated when a panic occurred.
    'Panic': 'Panic',
    # The stage for events generated after the audit handler receives the request, but before it
    # is delegated down the handler chain.
    'RequestReceived': 'RequestReceived',
    # The stage for events generated after the response body has been completed, and no more bytes
    # will be sent.
    'ResponseComplete': 'ResponseComplete',
    # The stage for events generated after the response headers are sent, but before the response body
    # is sent. This stage is only generated for long-running requests (e.g. watch).
    'ResponseStarted': 'ResponseStarted',
})


# Policy defines the configuration of how audit events are logged
class Policy(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['level'] = self.level()
        v['stages'] = self.stages()
        return v
    
    # The Level that all requests are recorded at.
    # available options: None, Metadata, Request, RequestResponse
    # required
    @typechecked
    def level(self) -> Level:
        return self._kwargs.get('level')
    
    # Stages is a list of stages for which events are created.
    @typechecked
    def stages(self) -> List[Stage]:
        return self._kwargs.get('stages', [])


# ServiceReference holds a reference to Service.legacy.k8s.io
class ServiceReference(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['namespace'] = self.namespace()
        v['name'] = self.name()
        path = self.path()
        if path is not None:  # omit empty
            v['path'] = path
        port = self.port()
        if port is not None:  # omit empty
            v['port'] = port
        return v
    
    # `namespace` is the namespace of the service.
    # Required
    @typechecked
    def namespace(self) -> str:
        return self._kwargs.get('namespace', '')
    
    # `name` is the name of the service.
    # Required
    @typechecked
    def name(self) -> str:
        return self._kwargs.get('name', '')
    
    # `path` is an optional URL path which will be sent in any request to
    # this service.
    @typechecked
    def path(self) -> Optional[str]:
        return self._kwargs.get('path')
    
    # If specified, the port on the service that hosting webhook.
    # Default to 443 for backward compatibility.
    # `port` should be a valid port number (1-65535, inclusive).
    @typechecked
    def port(self) -> Optional[int]:
        return self._kwargs.get('port', 443)


# WebhookClientConfig contains the information to make a connection with the webhook
class WebhookClientConfig(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        url = self.url()
        if url is not None:  # omit empty
            v['url'] = url
        service = self.service()
        if service is not None:  # omit empty
            v['service'] = service
        caBundle = self.caBundle()
        if caBundle:  # omit empty
            v['caBundle'] = caBundle
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
        return self._kwargs.get('url')
    
    # `service` is a reference to the service for this webhook. Either
    # `service` or `url` must be specified.
    # 
    # If the webhook is running within the cluster, then you should use `service`.
    @typechecked
    def service(self) -> Optional[ServiceReference]:
        return self._kwargs.get('service')
    
    # `caBundle` is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
    # If unspecified, system trust roots on the apiserver are used.
    @typechecked
    def caBundle(self) -> bytes:
        return self._kwargs.get('caBundle', b'')


# WebhookThrottleConfig holds the configuration for throttling events
class WebhookThrottleConfig(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        qps = self.qps()
        if qps is not None:  # omit empty
            v['qps'] = qps
        burst = self.burst()
        if burst is not None:  # omit empty
            v['burst'] = burst
        return v
    
    # ThrottleQPS maximum number of batches per second
    # default 10 QPS
    @typechecked
    def qps(self) -> Optional[int]:
        return self._kwargs.get('qps', 10)
    
    # ThrottleBurst is the maximum number of events sent at the same moment
    # default 15 QPS
    @typechecked
    def burst(self) -> Optional[int]:
        return self._kwargs.get('burst', 15)


# Webhook holds the configuration of the webhook
class Webhook(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        throttle = self.throttle()
        if throttle is not None:  # omit empty
            v['throttle'] = throttle
        v['clientConfig'] = self.clientConfig()
        return v
    
    # Throttle holds the options for throttling the webhook
    @typechecked
    def throttle(self) -> Optional[WebhookThrottleConfig]:
        return self._kwargs.get('throttle', WebhookThrottleConfig())
    
    # ClientConfig holds the connection parameters for the webhook
    # required
    @typechecked
    def clientConfig(self) -> WebhookClientConfig:
        return self._kwargs.get('clientConfig', WebhookClientConfig())


# AuditSinkSpec holds the spec for the audit sink
class AuditSinkSpec(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['policy'] = self.policy()
        v['webhook'] = self.webhook()
        return v
    
    # Policy defines the policy for selecting which events should be sent to the webhook
    # required
    @typechecked
    def policy(self) -> Policy:
        return self._kwargs.get('policy', Policy())
    
    # Webhook to send events
    # required
    @typechecked
    def webhook(self) -> Webhook:
        return self._kwargs.get('webhook', Webhook())


# AuditSink represents a cluster level audit sink
class AuditSink(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        spec = self.spec()
        if spec:  # omit empty
            v['spec'] = spec
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'auditregistration.k8s.io/v1alpha1'
    
    @typechecked
    def kind(self) -> str:
        return 'AuditSink'
    
    # Spec defines the audit configuration spec
    @typechecked
    def spec(self) -> Optional[AuditSinkSpec]:
        return self._kwargs.get('spec', AuditSinkSpec())
