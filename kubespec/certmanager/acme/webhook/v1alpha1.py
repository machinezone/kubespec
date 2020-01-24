# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s.apiextensions import v1beta1 as apiextensionsv1beta1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


ChallengeAction = base.Enum(
    "ChallengeAction", {"CleanUp": "CleanUp", "Present": "Present"}
)


class ChallengeRequest(types.Object):
    """
    ChallengeRequest is a payload that can be sent to external ACME webhook
    solvers in order to 'Present' or 'CleanUp' a challenge with an ACME server.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        uid: str = "",
        action: ChallengeAction = None,
        type: str = "",
        dns_name: str = "",
        key: str = "",
        resource_namespace: str = "",
        resolved_fqdn: str = None,
        resolved_zone: str = None,
        allow_ambient_credentials: bool = False,
        config: "apiextensionsv1beta1.JSON" = None,
    ):
        super().__init__()
        self.__uid = uid
        self.__action = action
        self.__type = type
        self.__dns_name = dns_name
        self.__key = key
        self.__resource_namespace = resource_namespace
        self.__resolved_fqdn = resolved_fqdn
        self.__resolved_zone = resolved_zone
        self.__allow_ambient_credentials = allow_ambient_credentials
        self.__config = config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uid = self.uid()
        check_type("uid", uid, str)
        v["uid"] = uid
        action = self.action()
        check_type("action", action, ChallengeAction)
        v["action"] = action
        type = self.type()
        check_type("type", type, str)
        v["type"] = type
        dns_name = self.dns_name()
        check_type("dns_name", dns_name, str)
        v["dnsName"] = dns_name
        key = self.key()
        check_type("key", key, str)
        v["key"] = key
        resource_namespace = self.resource_namespace()
        check_type("resource_namespace", resource_namespace, str)
        v["resourceNamespace"] = resource_namespace
        resolved_fqdn = self.resolved_fqdn()
        check_type("resolved_fqdn", resolved_fqdn, Optional[str])
        if resolved_fqdn:  # omit empty
            v["resolvedFQDN"] = resolved_fqdn
        resolved_zone = self.resolved_zone()
        check_type("resolved_zone", resolved_zone, Optional[str])
        if resolved_zone:  # omit empty
            v["resolvedZone"] = resolved_zone
        allow_ambient_credentials = self.allow_ambient_credentials()
        check_type("allow_ambient_credentials", allow_ambient_credentials, bool)
        v["allowAmbientCredentials"] = allow_ambient_credentials
        config = self.config()
        check_type("config", config, Optional["apiextensionsv1beta1.JSON"])
        if config is not None:  # omit empty
            v["config"] = config
        return v

    def uid(self) -> str:
        """
        UID is an identifier for the individual request/response. It allows us to distinguish instances of requests which are
        otherwise identical (parallel requests, requests when earlier requests did not modify etc)
        The UID is meant to track the round trip (request/response) between the KAS and the WebHook, not the user request.
        It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
        """
        return self.__uid

    def action(self) -> ChallengeAction:
        """
        Action is one of 'present' or 'cleanup'.
        If the action is 'present', the record will be presented with the
        solving service.
        If the action is 'cleanup', the record will be cleaned up with the
        solving service.
        """
        return self.__action

    def type(self) -> str:
        """
        Type is the type of ACME challenge.
        Only dns-01 is currently supported.
        """
        return self.__type

    def dns_name(self) -> str:
        """
        DNSName is the name of the domain that is actually being validated, as
        requested by the user on the Certificate resource.
        This will be of the form 'example.com' from normal hostnames, and
        '*.example.com' for wildcards.
        """
        return self.__dns_name

    def key(self) -> str:
        """
        Key is the key that should be presented.
        This key will already be signed by the account that owns the challenge.
        For DNS01, this is the key that should be set for the TXT record for
        ResolveFQDN.
        """
        return self.__key

    def resource_namespace(self) -> str:
        """
        ResourceNamespace is the namespace containing resources that are
        referenced in the providers config.
        If this request is solving for an Issuer resource, this will be the
        namespace of the Issuer.
        If this request is solving for a ClusterIssuer resource, this will be
        the configured 'cluster resource namespace'
        """
        return self.__resource_namespace

    def resolved_fqdn(self) -> Optional[str]:
        """
        ResolvedFQDN is the fully-qualified domain name that should be
        updated/presented after resolving all CNAMEs.
        This should be honoured when using the DNS01 solver type.
        This will be of the form '_acme-challenge.example.com.'.
        """
        return self.__resolved_fqdn

    def resolved_zone(self) -> Optional[str]:
        """
        ResolvedZone is the zone encompassing the ResolvedFQDN.
        This is included as part of the ChallengeRequest so that webhook
        implementers do not need to implement their own SOA recursion logic.
        This indicates the zone that the provided FQDN is encompassed within,
        determined by performing SOA record queries for each part of the FQDN
        until an authoritative zone is found.
        This will be of the form 'example.com.'.
        """
        return self.__resolved_zone

    def allow_ambient_credentials(self) -> bool:
        """
        AllowAmbientCredentials advises webhook implementations that they can
        use 'ambient credentials' for authenticating with their respective
        DNS provider services.
        This field SHOULD be honoured by all DNS webhook implementations, but
        in certain instances where it does not make sense to honour this option,
        an implementation may ignore it.
        """
        return self.__allow_ambient_credentials

    def config(self) -> Optional["apiextensionsv1beta1.JSON"]:
        """
        Config contains unstructured JSON configuration data that the webhook
        implementation can unmarshal in order to fetch secrets or configure
        connection details etc.
        Secret values should not be passed in this field, in favour of
        references to Kubernetes Secret resources that the webhook can fetch.
        """
        return self.__config


class ChallengeResponse(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, uid: str = "", success: bool = False, status: "metav1.Status" = None
    ):
        super().__init__()
        self.__uid = uid
        self.__success = success
        self.__status = status

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uid = self.uid()
        check_type("uid", uid, str)
        v["uid"] = uid
        success = self.success()
        check_type("success", success, bool)
        v["success"] = success
        status = self.status()
        check_type("status", status, Optional["metav1.Status"])
        if status is not None:  # omit empty
            v["status"] = status
        return v

    def uid(self) -> str:
        """
        UID is an identifier for the individual request/response.
        This should be copied over from the corresponding ChallengeRequest.
        """
        return self.__uid

    def success(self) -> bool:
        """
        Success will be set to true if the request action (i.e. presenting or
        cleaning up) was successful.
        """
        return self.__success

    def status(self) -> Optional["metav1.Status"]:
        """
        Result contains extra details into why a challenge request failed.
        This field will be completely ignored if 'success' is true.
        """
        return self.__status


class ChallengePayload(base.TypedObject):
    """
    ChallengePayload describes a request/response for presenting or cleaning up
    an ACME challenge resource
    """

    @context.scoped
    @typechecked
    def __init__(
        self, request: "ChallengeRequest" = None, response: "ChallengeResponse" = None
    ):
        super().__init__(
            api_version="webhook.acme.cert-manager.io/v1alpha1", kind="ChallengePayload"
        )
        self.__request = request
        self.__response = response

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        request = self.request()
        check_type("request", request, Optional["ChallengeRequest"])
        if request is not None:  # omit empty
            v["request"] = request
        response = self.response()
        check_type("response", response, Optional["ChallengeResponse"])
        if response is not None:  # omit empty
            v["response"] = response
        return v

    def request(self) -> Optional["ChallengeRequest"]:
        """
        Request describes the attributes for the ACME solver request
        """
        return self.__request

    def response(self) -> Optional["ChallengeResponse"]:
        """
        Response describes the attributes for the ACME solver response
        """
        return self.__response
