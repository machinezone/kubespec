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
        dnsName: str = "",
        key: str = "",
        resourceNamespace: str = "",
        resolvedFQDN: str = None,
        resolvedZone: str = None,
        allowAmbientCredentials: bool = False,
        config: "apiextensionsv1beta1.JSON" = None,
    ):
        super().__init__()
        self.__uid = uid
        self.__action = action
        self.__type = type
        self.__dnsName = dnsName
        self.__key = key
        self.__resourceNamespace = resourceNamespace
        self.__resolvedFQDN = resolvedFQDN
        self.__resolvedZone = resolvedZone
        self.__allowAmbientCredentials = allowAmbientCredentials
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
        dnsName = self.dnsName()
        check_type("dnsName", dnsName, str)
        v["dnsName"] = dnsName
        key = self.key()
        check_type("key", key, str)
        v["key"] = key
        resourceNamespace = self.resourceNamespace()
        check_type("resourceNamespace", resourceNamespace, str)
        v["resourceNamespace"] = resourceNamespace
        resolvedFQDN = self.resolvedFQDN()
        check_type("resolvedFQDN", resolvedFQDN, Optional[str])
        if resolvedFQDN:  # omit empty
            v["resolvedFQDN"] = resolvedFQDN
        resolvedZone = self.resolvedZone()
        check_type("resolvedZone", resolvedZone, Optional[str])
        if resolvedZone:  # omit empty
            v["resolvedZone"] = resolvedZone
        allowAmbientCredentials = self.allowAmbientCredentials()
        check_type("allowAmbientCredentials", allowAmbientCredentials, bool)
        v["allowAmbientCredentials"] = allowAmbientCredentials
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

    def dnsName(self) -> str:
        """
        DNSName is the name of the domain that is actually being validated, as
        requested by the user on the Certificate resource.
        This will be of the form 'example.com' from normal hostnames, and
        '*.example.com' for wildcards.
        """
        return self.__dnsName

    def key(self) -> str:
        """
        Key is the key that should be presented.
        This key will already be signed by the account that owns the challenge.
        For DNS01, this is the key that should be set for the TXT record for
        ResolveFQDN.
        """
        return self.__key

    def resourceNamespace(self) -> str:
        """
        ResourceNamespace is the namespace containing resources that are
        referenced in the providers config.
        If this request is solving for an Issuer resource, this will be the
        namespace of the Issuer.
        If this request is solving for a ClusterIssuer resource, this will be
        the configured 'cluster resource namespace'
        """
        return self.__resourceNamespace

    def resolvedFQDN(self) -> Optional[str]:
        """
        ResolvedFQDN is the fully-qualified domain name that should be
        updated/presented after resolving all CNAMEs.
        This should be honoured when using the DNS01 solver type.
        This will be of the form '_acme-challenge.example.com.'.
        """
        return self.__resolvedFQDN

    def resolvedZone(self) -> Optional[str]:
        """
        ResolvedZone is the zone encompassing the ResolvedFQDN.
        This is included as part of the ChallengeRequest so that webhook
        implementers do not need to implement their own SOA recursion logic.
        This indicates the zone that the provided FQDN is encompassed within,
        determined by performing SOA record queries for each part of the FQDN
        until an authoritative zone is found.
        This will be of the form 'example.com.'.
        """
        return self.__resolvedZone

    def allowAmbientCredentials(self) -> bool:
        """
        AllowAmbientCredentials advises webhook implementations that they can
        use 'ambient credentials' for authenticating with their respective
        DNS provider services.
        This field SHOULD be honoured by all DNS webhook implementations, but
        in certain instances where it does not make sense to honour this option,
        an implementation may ignore it.
        """
        return self.__allowAmbientCredentials

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
            apiVersion="webhook.acme.cert-manager.io/v1alpha1", kind="ChallengePayload"
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
