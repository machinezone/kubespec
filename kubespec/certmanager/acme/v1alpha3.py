# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.apiextensions import v1beta1 as apiextensionsv1beta1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


# ACMEChallengeType denotes a type of ACME challenge
ACMEChallengeType = base.Enum(
    "ACMEChallengeType",
    {
        # DNS01 denotes a Challenge is of type dns-01
        "DNS01": "dns-01",
        # HTTP01 denotes a Challenge is of type http-01
        "HTTP01": "http-01",
    },
)


AzureDNSEnvironment = base.Enum(
    "AzureDNSEnvironment",
    {
        "AzureChinaCloud": "AzureChinaCloud",
        "AzureGermanCloud": "AzureGermanCloud",
        "AzurePublicCloud": "AzurePublicCloud",
        "AzureUSGovernmentCloud": "AzureUSGovernmentCloud",
    },
)


# CNAMEStrategy configures how the DNS01 provider should handle CNAME records
# when found in DNS zones.
# By default, the None strategy will be applied (i.e. do not follow CNAMEs).
CNAMEStrategy = base.Enum("CNAMEStrategy", {})


# HMACKeyAlgorithm is the name of a key algorithm used for HMAC encryption
HMACKeyAlgorithm = base.Enum(
    "HMACKeyAlgorithm", {"HS256": "HS256", "HS384": "HS384", "HS512": "HS512"}
)


class ACMEIssuerDNS01ProviderAcmeDNS(types.Object):
    """
    ACMEIssuerDNS01ProviderAcmeDNS is a structure containing the
    configuration for ACME-DNS servers
    """

    @context.scoped
    @typechecked
    def __init__(
        self, host: str = "", accountSecretRef: "k8sv1.SecretKeySelector" = None
    ):
        super().__init__()
        self.__host = host
        self.__accountSecretRef = (
            accountSecretRef
            if accountSecretRef is not None
            else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        host = self.host()
        check_type("host", host, str)
        v["host"] = host
        accountSecretRef = self.accountSecretRef()
        check_type("accountSecretRef", accountSecretRef, "k8sv1.SecretKeySelector")
        v["accountSecretRef"] = accountSecretRef
        return v

    def host(self) -> str:
        return self.__host

    def accountSecretRef(self) -> "k8sv1.SecretKeySelector":
        return self.__accountSecretRef


class ACMEIssuerDNS01ProviderAkamai(types.Object):
    """
    ACMEIssuerDNS01ProviderAkamai is a structure containing the DNS
    configuration for Akamai DNS—Zone Record Management API
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        serviceConsumerDomain: str = "",
        clientTokenSecretRef: "k8sv1.SecretKeySelector" = None,
        clientSecretSecretRef: "k8sv1.SecretKeySelector" = None,
        accessTokenSecretRef: "k8sv1.SecretKeySelector" = None,
    ):
        super().__init__()
        self.__serviceConsumerDomain = serviceConsumerDomain
        self.__clientTokenSecretRef = (
            clientTokenSecretRef
            if clientTokenSecretRef is not None
            else k8sv1.SecretKeySelector()
        )
        self.__clientSecretSecretRef = (
            clientSecretSecretRef
            if clientSecretSecretRef is not None
            else k8sv1.SecretKeySelector()
        )
        self.__accessTokenSecretRef = (
            accessTokenSecretRef
            if accessTokenSecretRef is not None
            else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        serviceConsumerDomain = self.serviceConsumerDomain()
        check_type("serviceConsumerDomain", serviceConsumerDomain, str)
        v["serviceConsumerDomain"] = serviceConsumerDomain
        clientTokenSecretRef = self.clientTokenSecretRef()
        check_type(
            "clientTokenSecretRef", clientTokenSecretRef, "k8sv1.SecretKeySelector"
        )
        v["clientTokenSecretRef"] = clientTokenSecretRef
        clientSecretSecretRef = self.clientSecretSecretRef()
        check_type(
            "clientSecretSecretRef", clientSecretSecretRef, "k8sv1.SecretKeySelector"
        )
        v["clientSecretSecretRef"] = clientSecretSecretRef
        accessTokenSecretRef = self.accessTokenSecretRef()
        check_type(
            "accessTokenSecretRef", accessTokenSecretRef, "k8sv1.SecretKeySelector"
        )
        v["accessTokenSecretRef"] = accessTokenSecretRef
        return v

    def serviceConsumerDomain(self) -> str:
        return self.__serviceConsumerDomain

    def clientTokenSecretRef(self) -> "k8sv1.SecretKeySelector":
        return self.__clientTokenSecretRef

    def clientSecretSecretRef(self) -> "k8sv1.SecretKeySelector":
        return self.__clientSecretSecretRef

    def accessTokenSecretRef(self) -> "k8sv1.SecretKeySelector":
        return self.__accessTokenSecretRef


class ACMEIssuerDNS01ProviderAzureDNS(types.Object):
    """
    ACMEIssuerDNS01ProviderAzureDNS is a structure containing the
    configuration for Azure DNS
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        clientID: str = "",
        clientSecretSecretRef: "k8sv1.SecretKeySelector" = None,
        subscriptionID: str = "",
        tenantID: str = "",
        resourceGroupName: str = "",
        hostedZoneName: str = None,
        environment: AzureDNSEnvironment = None,
    ):
        super().__init__()
        self.__clientID = clientID
        self.__clientSecretSecretRef = (
            clientSecretSecretRef
            if clientSecretSecretRef is not None
            else k8sv1.SecretKeySelector()
        )
        self.__subscriptionID = subscriptionID
        self.__tenantID = tenantID
        self.__resourceGroupName = resourceGroupName
        self.__hostedZoneName = hostedZoneName
        self.__environment = environment

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientID = self.clientID()
        check_type("clientID", clientID, str)
        v["clientID"] = clientID
        clientSecretSecretRef = self.clientSecretSecretRef()
        check_type(
            "clientSecretSecretRef", clientSecretSecretRef, "k8sv1.SecretKeySelector"
        )
        v["clientSecretSecretRef"] = clientSecretSecretRef
        subscriptionID = self.subscriptionID()
        check_type("subscriptionID", subscriptionID, str)
        v["subscriptionID"] = subscriptionID
        tenantID = self.tenantID()
        check_type("tenantID", tenantID, str)
        v["tenantID"] = tenantID
        resourceGroupName = self.resourceGroupName()
        check_type("resourceGroupName", resourceGroupName, str)
        v["resourceGroupName"] = resourceGroupName
        hostedZoneName = self.hostedZoneName()
        check_type("hostedZoneName", hostedZoneName, Optional[str])
        if hostedZoneName:  # omit empty
            v["hostedZoneName"] = hostedZoneName
        environment = self.environment()
        check_type("environment", environment, Optional[AzureDNSEnvironment])
        if environment:  # omit empty
            v["environment"] = environment
        return v

    def clientID(self) -> str:
        return self.__clientID

    def clientSecretSecretRef(self) -> "k8sv1.SecretKeySelector":
        return self.__clientSecretSecretRef

    def subscriptionID(self) -> str:
        return self.__subscriptionID

    def tenantID(self) -> str:
        return self.__tenantID

    def resourceGroupName(self) -> str:
        return self.__resourceGroupName

    def hostedZoneName(self) -> Optional[str]:
        return self.__hostedZoneName

    def environment(self) -> Optional[AzureDNSEnvironment]:
        return self.__environment


class ACMEIssuerDNS01ProviderCloudDNS(types.Object):
    """
    ACMEIssuerDNS01ProviderCloudDNS is a structure containing the DNS
    configuration for Google Cloud DNS
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        serviceAccountSecretRef: "k8sv1.SecretKeySelector" = None,
        project: str = "",
    ):
        super().__init__()
        self.__serviceAccountSecretRef = serviceAccountSecretRef
        self.__project = project

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        serviceAccountSecretRef = self.serviceAccountSecretRef()
        check_type(
            "serviceAccountSecretRef",
            serviceAccountSecretRef,
            Optional["k8sv1.SecretKeySelector"],
        )
        if serviceAccountSecretRef is not None:  # omit empty
            v["serviceAccountSecretRef"] = serviceAccountSecretRef
        project = self.project()
        check_type("project", project, str)
        v["project"] = project
        return v

    def serviceAccountSecretRef(self) -> Optional["k8sv1.SecretKeySelector"]:
        return self.__serviceAccountSecretRef

    def project(self) -> str:
        return self.__project


class ACMEIssuerDNS01ProviderCloudflare(types.Object):
    """
    ACMEIssuerDNS01ProviderCloudflare is a structure containing the DNS
    configuration for Cloudflare
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        email: str = "",
        apiKeySecretRef: "k8sv1.SecretKeySelector" = None,
        apiTokenSecretRef: "k8sv1.SecretKeySelector" = None,
    ):
        super().__init__()
        self.__email = email
        self.__apiKeySecretRef = apiKeySecretRef
        self.__apiTokenSecretRef = apiTokenSecretRef

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        email = self.email()
        check_type("email", email, str)
        v["email"] = email
        apiKeySecretRef = self.apiKeySecretRef()
        check_type(
            "apiKeySecretRef", apiKeySecretRef, Optional["k8sv1.SecretKeySelector"]
        )
        if apiKeySecretRef is not None:  # omit empty
            v["apiKeySecretRef"] = apiKeySecretRef
        apiTokenSecretRef = self.apiTokenSecretRef()
        check_type(
            "apiTokenSecretRef", apiTokenSecretRef, Optional["k8sv1.SecretKeySelector"]
        )
        if apiTokenSecretRef is not None:  # omit empty
            v["apiTokenSecretRef"] = apiTokenSecretRef
        return v

    def email(self) -> str:
        return self.__email

    def apiKeySecretRef(self) -> Optional["k8sv1.SecretKeySelector"]:
        return self.__apiKeySecretRef

    def apiTokenSecretRef(self) -> Optional["k8sv1.SecretKeySelector"]:
        return self.__apiTokenSecretRef


class ACMEIssuerDNS01ProviderDigitalOcean(types.Object):
    """
    ACMEIssuerDNS01ProviderDigitalOcean is a structure containing the DNS
    configuration for DigitalOcean Domains
    """

    @context.scoped
    @typechecked
    def __init__(self, tokenSecretRef: "k8sv1.SecretKeySelector" = None):
        super().__init__()
        self.__tokenSecretRef = (
            tokenSecretRef if tokenSecretRef is not None else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        tokenSecretRef = self.tokenSecretRef()
        check_type("tokenSecretRef", tokenSecretRef, "k8sv1.SecretKeySelector")
        v["tokenSecretRef"] = tokenSecretRef
        return v

    def tokenSecretRef(self) -> "k8sv1.SecretKeySelector":
        return self.__tokenSecretRef


class ACMEIssuerDNS01ProviderRFC2136(types.Object):
    """
    ACMEIssuerDNS01ProviderRFC2136 is a structure containing the
    configuration for RFC2136 DNS
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        nameserver: str = "",
        tsigSecretSecretRef: "k8sv1.SecretKeySelector" = None,
        tsigKeyName: str = None,
        tsigAlgorithm: str = None,
    ):
        super().__init__()
        self.__nameserver = nameserver
        self.__tsigSecretSecretRef = (
            tsigSecretSecretRef
            if tsigSecretSecretRef is not None
            else k8sv1.SecretKeySelector()
        )
        self.__tsigKeyName = tsigKeyName
        self.__tsigAlgorithm = tsigAlgorithm

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        nameserver = self.nameserver()
        check_type("nameserver", nameserver, str)
        v["nameserver"] = nameserver
        tsigSecretSecretRef = self.tsigSecretSecretRef()
        check_type(
            "tsigSecretSecretRef",
            tsigSecretSecretRef,
            Optional["k8sv1.SecretKeySelector"],
        )
        v["tsigSecretSecretRef"] = tsigSecretSecretRef
        tsigKeyName = self.tsigKeyName()
        check_type("tsigKeyName", tsigKeyName, Optional[str])
        if tsigKeyName:  # omit empty
            v["tsigKeyName"] = tsigKeyName
        tsigAlgorithm = self.tsigAlgorithm()
        check_type("tsigAlgorithm", tsigAlgorithm, Optional[str])
        if tsigAlgorithm:  # omit empty
            v["tsigAlgorithm"] = tsigAlgorithm
        return v

    def nameserver(self) -> str:
        """
        The IP address of the DNS supporting RFC2136. Required.
        Note: FQDN is not a valid value, only IP.
        """
        return self.__nameserver

    def tsigSecretSecretRef(self) -> Optional["k8sv1.SecretKeySelector"]:
        """
        The name of the secret containing the TSIG value.
        If ``tsigKeyName`` is defined, this field is required.
        """
        return self.__tsigSecretSecretRef

    def tsigKeyName(self) -> Optional[str]:
        """
        The TSIG Key name configured in the DNS.
        If ``tsigSecretSecretRef`` is defined, this field is required.
        """
        return self.__tsigKeyName

    def tsigAlgorithm(self) -> Optional[str]:
        """
        The TSIG Algorithm configured in the DNS supporting RFC2136. Used only
        when ``tsigSecretSecretRef`` and ``tsigKeyName`` are defined.
        Supported values are (case-insensitive): ``HMACMD5`` (default),
        ``HMACSHA1``, ``HMACSHA256`` or ``HMACSHA512``.
        """
        return self.__tsigAlgorithm


class ACMEIssuerDNS01ProviderRoute53(types.Object):
    """
    ACMEIssuerDNS01ProviderRoute53 is a structure containing the Route 53
    configuration for AWS
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        accessKeyID: str = "",
        secretAccessKeySecretRef: "k8sv1.SecretKeySelector" = None,
        role: str = "",
        hostedZoneID: str = None,
        region: str = "",
    ):
        super().__init__()
        self.__accessKeyID = accessKeyID
        self.__secretAccessKeySecretRef = (
            secretAccessKeySecretRef
            if secretAccessKeySecretRef is not None
            else k8sv1.SecretKeySelector()
        )
        self.__role = role
        self.__hostedZoneID = hostedZoneID
        self.__region = region

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        accessKeyID = self.accessKeyID()
        check_type("accessKeyID", accessKeyID, str)
        v["accessKeyID"] = accessKeyID
        secretAccessKeySecretRef = self.secretAccessKeySecretRef()
        check_type(
            "secretAccessKeySecretRef",
            secretAccessKeySecretRef,
            "k8sv1.SecretKeySelector",
        )
        v["secretAccessKeySecretRef"] = secretAccessKeySecretRef
        role = self.role()
        check_type("role", role, str)
        v["role"] = role
        hostedZoneID = self.hostedZoneID()
        check_type("hostedZoneID", hostedZoneID, Optional[str])
        if hostedZoneID:  # omit empty
            v["hostedZoneID"] = hostedZoneID
        region = self.region()
        check_type("region", region, str)
        v["region"] = region
        return v

    def accessKeyID(self) -> str:
        """
        The AccessKeyID is used for authentication. If not set we fall-back to using env vars, shared credentials file or AWS Instance metadata
        see: https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
        """
        return self.__accessKeyID

    def secretAccessKeySecretRef(self) -> "k8sv1.SecretKeySelector":
        """
        The SecretAccessKey is used for authentication. If not set we fall-back to using env vars, shared credentials file or AWS Instance metadata
        https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
        """
        return self.__secretAccessKeySecretRef

    def role(self) -> str:
        """
        Role is a Role ARN which the Route53 provider will assume using either the explicit credentials AccessKeyID/SecretAccessKey
        or the inferred credentials from environment variables, shared credentials file or AWS Instance metadata
        """
        return self.__role

    def hostedZoneID(self) -> Optional[str]:
        """
        If set, the provider will manage only this zone in Route53 and will not do an lookup using the route53:ListHostedZonesByName api call.
        """
        return self.__hostedZoneID

    def region(self) -> str:
        """
        Always set the region when using AccessKeyID and SecretAccessKey
        """
        return self.__region


class ACMEIssuerDNS01ProviderWebhook(types.Object):
    """
    ACMEIssuerDNS01ProviderWebhook specifies configuration for a webhook DNS01
    provider, including where to POST ChallengePayload resources.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        groupName: str = "",
        solverName: str = "",
        config: "apiextensionsv1beta1.JSON" = None,
    ):
        super().__init__()
        self.__groupName = groupName
        self.__solverName = solverName
        self.__config = config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        groupName = self.groupName()
        check_type("groupName", groupName, str)
        v["groupName"] = groupName
        solverName = self.solverName()
        check_type("solverName", solverName, str)
        v["solverName"] = solverName
        config = self.config()
        check_type("config", config, Optional["apiextensionsv1beta1.JSON"])
        if config is not None:  # omit empty
            v["config"] = config
        return v

    def groupName(self) -> str:
        """
        The API group name that should be used when POSTing ChallengePayload
        resources to the webhook apiserver.
        This should be the same as the GroupName specified in the webhook
        provider implementation.
        """
        return self.__groupName

    def solverName(self) -> str:
        """
        The name of the solver to use, as defined in the webhook provider
        implementation.
        This will typically be the name of the provider, e.g. 'cloudflare'.
        """
        return self.__solverName

    def config(self) -> Optional["apiextensionsv1beta1.JSON"]:
        """
        Additional configuration that should be passed to the webhook apiserver
        when challenges are processed.
        This can contain arbitrary JSON data.
        Secret values should not be specified in this stanza.
        If secret values are needed (e.g. credentials for a DNS service), you
        should use a SecretKeySelector to reference a Secret resource.
        For details on the schema of this field, consult the webhook provider
        implementation's documentation.
        """
        return self.__config


class ACMEChallengeSolverDNS01(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        cnameStrategy: CNAMEStrategy = None,
        akamai: "ACMEIssuerDNS01ProviderAkamai" = None,
        clouddns: "ACMEIssuerDNS01ProviderCloudDNS" = None,
        cloudflare: "ACMEIssuerDNS01ProviderCloudflare" = None,
        route53: "ACMEIssuerDNS01ProviderRoute53" = None,
        azuredns: "ACMEIssuerDNS01ProviderAzureDNS" = None,
        digitalocean: "ACMEIssuerDNS01ProviderDigitalOcean" = None,
        acmedns: "ACMEIssuerDNS01ProviderAcmeDNS" = None,
        rfc2136: "ACMEIssuerDNS01ProviderRFC2136" = None,
        webhook: "ACMEIssuerDNS01ProviderWebhook" = None,
    ):
        super().__init__()
        self.__cnameStrategy = cnameStrategy
        self.__akamai = akamai
        self.__clouddns = clouddns
        self.__cloudflare = cloudflare
        self.__route53 = route53
        self.__azuredns = azuredns
        self.__digitalocean = digitalocean
        self.__acmedns = acmedns
        self.__rfc2136 = rfc2136
        self.__webhook = webhook

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cnameStrategy = self.cnameStrategy()
        check_type("cnameStrategy", cnameStrategy, Optional[CNAMEStrategy])
        if cnameStrategy:  # omit empty
            v["cnameStrategy"] = cnameStrategy
        akamai = self.akamai()
        check_type("akamai", akamai, Optional["ACMEIssuerDNS01ProviderAkamai"])
        if akamai is not None:  # omit empty
            v["akamai"] = akamai
        clouddns = self.clouddns()
        check_type("clouddns", clouddns, Optional["ACMEIssuerDNS01ProviderCloudDNS"])
        if clouddns is not None:  # omit empty
            v["clouddns"] = clouddns
        cloudflare = self.cloudflare()
        check_type(
            "cloudflare", cloudflare, Optional["ACMEIssuerDNS01ProviderCloudflare"]
        )
        if cloudflare is not None:  # omit empty
            v["cloudflare"] = cloudflare
        route53 = self.route53()
        check_type("route53", route53, Optional["ACMEIssuerDNS01ProviderRoute53"])
        if route53 is not None:  # omit empty
            v["route53"] = route53
        azuredns = self.azuredns()
        check_type("azuredns", azuredns, Optional["ACMEIssuerDNS01ProviderAzureDNS"])
        if azuredns is not None:  # omit empty
            v["azuredns"] = azuredns
        digitalocean = self.digitalocean()
        check_type(
            "digitalocean",
            digitalocean,
            Optional["ACMEIssuerDNS01ProviderDigitalOcean"],
        )
        if digitalocean is not None:  # omit empty
            v["digitalocean"] = digitalocean
        acmedns = self.acmedns()
        check_type("acmedns", acmedns, Optional["ACMEIssuerDNS01ProviderAcmeDNS"])
        if acmedns is not None:  # omit empty
            v["acmedns"] = acmedns
        rfc2136 = self.rfc2136()
        check_type("rfc2136", rfc2136, Optional["ACMEIssuerDNS01ProviderRFC2136"])
        if rfc2136 is not None:  # omit empty
            v["rfc2136"] = rfc2136
        webhook = self.webhook()
        check_type("webhook", webhook, Optional["ACMEIssuerDNS01ProviderWebhook"])
        if webhook is not None:  # omit empty
            v["webhook"] = webhook
        return v

    def cnameStrategy(self) -> Optional[CNAMEStrategy]:
        """
        CNAMEStrategy configures how the DNS01 provider should handle CNAME
        records when found in DNS zones.
        """
        return self.__cnameStrategy

    def akamai(self) -> Optional["ACMEIssuerDNS01ProviderAkamai"]:
        return self.__akamai

    def clouddns(self) -> Optional["ACMEIssuerDNS01ProviderCloudDNS"]:
        return self.__clouddns

    def cloudflare(self) -> Optional["ACMEIssuerDNS01ProviderCloudflare"]:
        return self.__cloudflare

    def route53(self) -> Optional["ACMEIssuerDNS01ProviderRoute53"]:
        return self.__route53

    def azuredns(self) -> Optional["ACMEIssuerDNS01ProviderAzureDNS"]:
        return self.__azuredns

    def digitalocean(self) -> Optional["ACMEIssuerDNS01ProviderDigitalOcean"]:
        return self.__digitalocean

    def acmedns(self) -> Optional["ACMEIssuerDNS01ProviderAcmeDNS"]:
        return self.__acmedns

    def rfc2136(self) -> Optional["ACMEIssuerDNS01ProviderRFC2136"]:
        return self.__rfc2136

    def webhook(self) -> Optional["ACMEIssuerDNS01ProviderWebhook"]:
        return self.__webhook


class ACMEChallengeSolverHTTP01IngressPodObjectMeta(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, annotations: Dict[str, str] = None, labels: Dict[str, str] = None
    ):
        super().__init__()
        self.__annotations = annotations if annotations is not None else {}
        self.__labels = labels if labels is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        annotations = self.annotations()
        check_type("annotations", annotations, Optional[Dict[str, str]])
        if annotations:  # omit empty
            v["annotations"] = annotations
        labels = self.labels()
        check_type("labels", labels, Optional[Dict[str, str]])
        if labels:  # omit empty
            v["labels"] = labels
        return v

    def annotations(self) -> Optional[Dict[str, str]]:
        """
        Annotations that should be added to the create ACME HTTP01 solver pods.
        """
        return self.__annotations

    def labels(self) -> Optional[Dict[str, str]]:
        """
        Labels that should be added to the created ACME HTTP01 solver pods.
        """
        return self.__labels


class ACMEChallengeSolverHTTP01IngressPodSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        nodeSelector: Dict[str, str] = None,
        affinity: "k8sv1.Affinity" = None,
        tolerations: List["k8sv1.Toleration"] = None,
    ):
        super().__init__()
        self.__nodeSelector = nodeSelector if nodeSelector is not None else {}
        self.__affinity = affinity
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        nodeSelector = self.nodeSelector()
        check_type("nodeSelector", nodeSelector, Optional[Dict[str, str]])
        if nodeSelector:  # omit empty
            v["nodeSelector"] = nodeSelector
        affinity = self.affinity()
        check_type("affinity", affinity, Optional["k8sv1.Affinity"])
        if affinity is not None:  # omit empty
            v["affinity"] = affinity
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    def nodeSelector(self) -> Optional[Dict[str, str]]:
        """
        NodeSelector is a selector which must be true for the pod to fit on a node.
        Selector which must match a node's labels for the pod to be scheduled on that node.
        More info: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
        """
        return self.__nodeSelector

    def affinity(self) -> Optional["k8sv1.Affinity"]:
        """
        If specified, the pod's scheduling constraints
        """
        return self.__affinity

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        If specified, the pod's tolerations.
        """
        return self.__tolerations


class ACMEChallengeSolverHTTP01IngressPodTemplate(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        metadata: "ACMEChallengeSolverHTTP01IngressPodObjectMeta" = None,
        spec: "ACMEChallengeSolverHTTP01IngressPodSpec" = None,
    ):
        super().__init__()
        self.__metadata = (
            metadata
            if metadata is not None
            else ACMEChallengeSolverHTTP01IngressPodObjectMeta()
        )
        self.__spec = (
            spec if spec is not None else ACMEChallengeSolverHTTP01IngressPodSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        metadata = self.metadata()
        check_type(
            "metadata",
            metadata,
            Optional["ACMEChallengeSolverHTTP01IngressPodObjectMeta"],
        )
        v["metadata"] = metadata
        spec = self.spec()
        check_type("spec", spec, Optional["ACMEChallengeSolverHTTP01IngressPodSpec"])
        v["spec"] = spec
        return v

    def metadata(self) -> Optional["ACMEChallengeSolverHTTP01IngressPodObjectMeta"]:
        """
        ObjectMeta overrides for the pod used to solve HTTP01 challenges.
        Only the 'labels' and 'annotations' fields may be set.
        If labels or annotations overlap with in-built values, the values here
        will override the in-built values.
        """
        return self.__metadata

    def spec(self) -> Optional["ACMEChallengeSolverHTTP01IngressPodSpec"]:
        """
        PodSpec defines overrides for the HTTP01 challenge solver pod.
        Only the 'nodeSelector', 'affinity' and 'tolerations' fields are
        supported currently. All other fields will be ignored.
        """
        return self.__spec


class ACMEChallengeSolverHTTP01Ingress(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        serviceType: k8sv1.ServiceType = None,
        class_: str = None,
        name: str = None,
        podTemplate: "ACMEChallengeSolverHTTP01IngressPodTemplate" = None,
    ):
        super().__init__()
        self.__serviceType = serviceType
        self.__class_ = class_
        self.__name = name
        self.__podTemplate = podTemplate

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        serviceType = self.serviceType()
        check_type("serviceType", serviceType, Optional[k8sv1.ServiceType])
        if serviceType:  # omit empty
            v["serviceType"] = serviceType
        class_ = self.class_()
        check_type("class_", class_, Optional[str])
        if class_ is not None:  # omit empty
            v["class"] = class_
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        podTemplate = self.podTemplate()
        check_type(
            "podTemplate",
            podTemplate,
            Optional["ACMEChallengeSolverHTTP01IngressPodTemplate"],
        )
        if podTemplate is not None:  # omit empty
            v["podTemplate"] = podTemplate
        return v

    def serviceType(self) -> Optional[k8sv1.ServiceType]:
        """
        Optional service type for Kubernetes solver service
        """
        return self.__serviceType

    def class_(self) -> Optional[str]:
        """
        The ingress class to use when creating Ingress resources to solve ACME
        challenges that use this challenge solver.
        Only one of 'class' or 'name' may be specified.
        """
        return self.__class_

    def name(self) -> Optional[str]:
        """
        The name of the ingress resource that should have ACME challenge solving
        routes inserted into it in order to solve HTTP01 challenges.
        This is typically used in conjunction with ingress controllers like
        ingress-gce, which maintains a 1:1 mapping between external IPs and
        ingress resources.
        """
        return self.__name

    def podTemplate(self) -> Optional["ACMEChallengeSolverHTTP01IngressPodTemplate"]:
        """
        Optional pod template used to configure the ACME challenge solver pods
        used for HTTP01 challenges
        """
        return self.__podTemplate


class ACMEChallengeSolverHTTP01(types.Object):
    """
    ACMEChallengeSolverHTTP01 contains configuration detailing how to solve
    HTTP01 challenges within a Kubernetes cluster.
    Typically this is accomplished through creating 'routes' of some description
    that configure ingress controllers to direct traffic to 'solver pods', which
    are responsible for responding to the ACME server's HTTP requests.
    """

    @context.scoped
    @typechecked
    def __init__(self, ingress: "ACMEChallengeSolverHTTP01Ingress" = None):
        super().__init__()
        self.__ingress = ingress

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ingress = self.ingress()
        check_type("ingress", ingress, Optional["ACMEChallengeSolverHTTP01Ingress"])
        v["ingress"] = ingress
        return v

    def ingress(self) -> Optional["ACMEChallengeSolverHTTP01Ingress"]:
        """
        The ingress based HTTP01 challenge solver will solve challenges by
        creating or modifying Ingress resources in order to route requests for
        '/.well-known/acme-challenge/XYZ' to 'challenge solver' pods that are
        provisioned by cert-manager for each Challenge to be completed.
        """
        return self.__ingress


class CertificateDNSNameSelector(types.Object):
    """
    CertificateDomainSelector selects certificates using a label selector, and
    can optionally select individual DNS names within those certificates.
    If both MatchLabels and DNSNames are empty, this selector will match all
    certificates and DNS names within them.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        matchLabels: Dict[str, str] = None,
        dnsNames: List[str] = None,
        dnsZones: List[str] = None,
    ):
        super().__init__()
        self.__matchLabels = matchLabels if matchLabels is not None else {}
        self.__dnsNames = dnsNames if dnsNames is not None else []
        self.__dnsZones = dnsZones if dnsZones is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        matchLabels = self.matchLabels()
        check_type("matchLabels", matchLabels, Optional[Dict[str, str]])
        if matchLabels:  # omit empty
            v["matchLabels"] = matchLabels
        dnsNames = self.dnsNames()
        check_type("dnsNames", dnsNames, Optional[List[str]])
        if dnsNames:  # omit empty
            v["dnsNames"] = dnsNames
        dnsZones = self.dnsZones()
        check_type("dnsZones", dnsZones, Optional[List[str]])
        if dnsZones:  # omit empty
            v["dnsZones"] = dnsZones
        return v

    def matchLabels(self) -> Optional[Dict[str, str]]:
        """
        A label selector that is used to refine the set of certificate's that
        this challenge solver will apply to.
        """
        return self.__matchLabels

    def dnsNames(self) -> Optional[List[str]]:
        """
        List of DNSNames that this solver will be used to solve.
        If specified and a match is found, a dnsNames selector will take
        precedence over a dnsZones selector.
        If multiple solvers match with the same dnsNames value, the solver
        with the most matching labels in matchLabels will be selected.
        If neither has more matches, the solver defined earlier in the list
        will be selected.
        """
        return self.__dnsNames

    def dnsZones(self) -> Optional[List[str]]:
        """
        List of DNSZones that this solver will be used to solve.
        The most specific DNS zone match specified here will take precedence
        over other DNS zone matches, so a solver specifying sys.example.com
        will be selected over one specifying example.com for the domain
        www.sys.example.com.
        If multiple solvers match with the same dnsZones value, the solver
        with the most matching labels in matchLabels will be selected.
        If neither has more matches, the solver defined earlier in the list
        will be selected.
        """
        return self.__dnsZones


class ACMEChallengeSolver(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        selector: "CertificateDNSNameSelector" = None,
        http01: "ACMEChallengeSolverHTTP01" = None,
        dns01: "ACMEChallengeSolverDNS01" = None,
    ):
        super().__init__()
        self.__selector = selector
        self.__http01 = http01
        self.__dns01 = dns01

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        selector = self.selector()
        check_type("selector", selector, Optional["CertificateDNSNameSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        http01 = self.http01()
        check_type("http01", http01, Optional["ACMEChallengeSolverHTTP01"])
        if http01 is not None:  # omit empty
            v["http01"] = http01
        dns01 = self.dns01()
        check_type("dns01", dns01, Optional["ACMEChallengeSolverDNS01"])
        if dns01 is not None:  # omit empty
            v["dns01"] = dns01
        return v

    def selector(self) -> Optional["CertificateDNSNameSelector"]:
        """
        Selector selects a set of DNSNames on the Certificate resource that
        should be solved using this challenge solver.
        """
        return self.__selector

    def http01(self) -> Optional["ACMEChallengeSolverHTTP01"]:
        return self.__http01

    def dns01(self) -> Optional["ACMEChallengeSolverDNS01"]:
        return self.__dns01


class ACMEExternalAccountBinding(types.Object):
    """
    ACMEExternalAcccountBinding is a reference to a CA external account of the ACME
    server.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        keyID: str = "",
        keySecretRef: "k8sv1.SecretKeySelector" = None,
        keyAlgorithm: HMACKeyAlgorithm = None,
    ):
        super().__init__()
        self.__keyID = keyID
        self.__keySecretRef = (
            keySecretRef if keySecretRef is not None else k8sv1.SecretKeySelector()
        )
        self.__keyAlgorithm = keyAlgorithm

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        keyID = self.keyID()
        check_type("keyID", keyID, str)
        v["keyID"] = keyID
        keySecretRef = self.keySecretRef()
        check_type("keySecretRef", keySecretRef, "k8sv1.SecretKeySelector")
        v["keySecretRef"] = keySecretRef
        keyAlgorithm = self.keyAlgorithm()
        check_type("keyAlgorithm", keyAlgorithm, HMACKeyAlgorithm)
        v["keyAlgorithm"] = keyAlgorithm
        return v

    def keyID(self) -> str:
        """
        keyID is the ID of the CA key that the External Account is bound to.
        """
        return self.__keyID

    def keySecretRef(self) -> "k8sv1.SecretKeySelector":
        """
        keySecretRef is a Secret Key Selector referencing a data item in a Kubernetes
        Secret which holds the symmetric MAC key of the External Account Binding.
        The `key` is the index string that is paired with the key data in the
        Secret and should not be confused with the key data itself, or indeed with
        the External Account Binding keyID above.
        The secret key stored in the Secret **must** be un-padded, base64 URL
        encoded data.
        """
        return self.__keySecretRef

    def keyAlgorithm(self) -> HMACKeyAlgorithm:
        """
        keyAlgorithm is the MAC key algorithm that the key is used for. Valid
        values are "HS256", "HS384" and "HS512".
        """
        return self.__keyAlgorithm


class ACMEIssuer(types.Object):
    """
    ACMEIssuer contains the specification for an ACME issuer
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        email: str = None,
        server: str = "",
        skipTLSVerify: bool = None,
        externalAccountBinding: "ACMEExternalAccountBinding" = None,
        privateKeySecretRef: "k8sv1.SecretKeySelector" = None,
        solvers: List["ACMEChallengeSolver"] = None,
    ):
        super().__init__()
        self.__email = email
        self.__server = server
        self.__skipTLSVerify = skipTLSVerify
        self.__externalAccountBinding = externalAccountBinding
        self.__privateKeySecretRef = (
            privateKeySecretRef
            if privateKeySecretRef is not None
            else k8sv1.SecretKeySelector()
        )
        self.__solvers = solvers if solvers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        email = self.email()
        check_type("email", email, Optional[str])
        if email:  # omit empty
            v["email"] = email
        server = self.server()
        check_type("server", server, str)
        v["server"] = server
        skipTLSVerify = self.skipTLSVerify()
        check_type("skipTLSVerify", skipTLSVerify, Optional[bool])
        if skipTLSVerify:  # omit empty
            v["skipTLSVerify"] = skipTLSVerify
        externalAccountBinding = self.externalAccountBinding()
        check_type(
            "externalAccountBinding",
            externalAccountBinding,
            Optional["ACMEExternalAccountBinding"],
        )
        if externalAccountBinding is not None:  # omit empty
            v["externalAccountBinding"] = externalAccountBinding
        privateKeySecretRef = self.privateKeySecretRef()
        check_type(
            "privateKeySecretRef", privateKeySecretRef, "k8sv1.SecretKeySelector"
        )
        v["privateKeySecretRef"] = privateKeySecretRef
        solvers = self.solvers()
        check_type("solvers", solvers, Optional[List["ACMEChallengeSolver"]])
        if solvers:  # omit empty
            v["solvers"] = solvers
        return v

    def email(self) -> Optional[str]:
        """
        Email is the email for this account
        """
        return self.__email

    def server(self) -> str:
        """
        Server is the ACME server URL
        """
        return self.__server

    def skipTLSVerify(self) -> Optional[bool]:
        """
        If true, skip verifying the ACME server TLS certificate
        """
        return self.__skipTLSVerify

    def externalAccountBinding(self) -> Optional["ACMEExternalAccountBinding"]:
        """
        ExternalAcccountBinding is a reference to a CA external account of the ACME
        server.
        """
        return self.__externalAccountBinding

    def privateKeySecretRef(self) -> "k8sv1.SecretKeySelector":
        """
        PrivateKey is the name of a secret containing the private key for this
        user account.
        """
        return self.__privateKeySecretRef

    def solvers(self) -> Optional[List["ACMEChallengeSolver"]]:
        """
        Solvers is a list of challenge solvers that will be used to solve
        ACME challenges for the matching domains.
        """
        return self.__solvers


class ChallengeSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        authzURL: str = "",
        type: ACMEChallengeType = None,
        url: str = "",
        dnsName: str = "",
        token: str = "",
        key: str = "",
        wildcard: bool = False,
        solver: "ACMEChallengeSolver" = None,
        issuerRef: "k8sv1.TypedLocalObjectReference" = None,
    ):
        super().__init__()
        self.__authzURL = authzURL
        self.__type = type
        self.__url = url
        self.__dnsName = dnsName
        self.__token = token
        self.__key = key
        self.__wildcard = wildcard
        self.__solver = solver
        self.__issuerRef = (
            issuerRef if issuerRef is not None else k8sv1.TypedLocalObjectReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        authzURL = self.authzURL()
        check_type("authzURL", authzURL, str)
        v["authzURL"] = authzURL
        type = self.type()
        check_type("type", type, ACMEChallengeType)
        v["type"] = type
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        dnsName = self.dnsName()
        check_type("dnsName", dnsName, str)
        v["dnsName"] = dnsName
        token = self.token()
        check_type("token", token, str)
        v["token"] = token
        key = self.key()
        check_type("key", key, str)
        v["key"] = key
        wildcard = self.wildcard()
        check_type("wildcard", wildcard, bool)
        v["wildcard"] = wildcard
        solver = self.solver()
        check_type("solver", solver, Optional["ACMEChallengeSolver"])
        if solver is not None:  # omit empty
            v["solver"] = solver
        issuerRef = self.issuerRef()
        check_type("issuerRef", issuerRef, "k8sv1.TypedLocalObjectReference")
        v["issuerRef"] = issuerRef
        return v

    def authzURL(self) -> str:
        """
        AuthzURL is the URL to the ACME Authorization resource that this
        challenge is a part of.
        """
        return self.__authzURL

    def type(self) -> ACMEChallengeType:
        """
        Type is the type of ACME challenge this resource represents, e.g. "dns01"
        or "http01"
        """
        return self.__type

    def url(self) -> str:
        """
        URL is the URL of the ACME Challenge resource for this challenge.
        This can be used to lookup details about the status of this challenge.
        """
        return self.__url

    def dnsName(self) -> str:
        """
        DNSName is the identifier that this challenge is for, e.g. example.com.
        """
        return self.__dnsName

    def token(self) -> str:
        """
        Token is the ACME challenge token for this challenge.
        """
        return self.__token

    def key(self) -> str:
        """
        Key is the ACME challenge key for this challenge
        """
        return self.__key

    def wildcard(self) -> bool:
        """
        Wildcard will be true if this challenge is for a wildcard identifier,
        for example '*.example.com'
        """
        return self.__wildcard

    def solver(self) -> Optional["ACMEChallengeSolver"]:
        """
        Solver contains the domain solving configuration that should be used to
        solve this challenge resource.
        """
        return self.__solver

    def issuerRef(self) -> "k8sv1.TypedLocalObjectReference":
        """
        IssuerRef references a properly configured ACME-type Issuer which should
        be used to create this Challenge.
        If the Issuer does not exist, processing will be retried.
        If the Issuer is not an 'ACME' Issuer, an error will be returned and the
        Challenge will be marked as failed.
        """
        return self.__issuerRef


class Challenge(base.TypedObject, base.NamespacedMetadataObject):
    """
    Challenge is a type to represent a Challenge request with an ACME server
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ChallengeSpec" = None,
    ):
        super().__init__(
            apiVersion="acme.cert-manager.io/v1alpha3",
            kind="Challenge",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ChallengeSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["ChallengeSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["ChallengeSpec"]:
        return self.__spec


class OrderSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        csr: bytes = None,
        issuerRef: "k8sv1.TypedLocalObjectReference" = None,
        commonName: str = None,
        dnsNames: List[str] = None,
    ):
        super().__init__()
        self.__csr = csr if csr is not None else b""
        self.__issuerRef = (
            issuerRef if issuerRef is not None else k8sv1.TypedLocalObjectReference()
        )
        self.__commonName = commonName
        self.__dnsNames = dnsNames if dnsNames is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        csr = self.csr()
        check_type("csr", csr, bytes)
        v["csr"] = csr
        issuerRef = self.issuerRef()
        check_type("issuerRef", issuerRef, "k8sv1.TypedLocalObjectReference")
        v["issuerRef"] = issuerRef
        commonName = self.commonName()
        check_type("commonName", commonName, Optional[str])
        if commonName:  # omit empty
            v["commonName"] = commonName
        dnsNames = self.dnsNames()
        check_type("dnsNames", dnsNames, Optional[List[str]])
        if dnsNames:  # omit empty
            v["dnsNames"] = dnsNames
        return v

    def csr(self) -> bytes:
        """
        Certificate signing request bytes in DER encoding.
        This will be used when finalizing the order.
        This field must be set on the order.
        """
        return self.__csr

    def issuerRef(self) -> "k8sv1.TypedLocalObjectReference":
        """
        IssuerRef references a properly configured ACME-type Issuer which should
        be used to create this Order.
        If the Issuer does not exist, processing will be retried.
        If the Issuer is not an 'ACME' Issuer, an error will be returned and the
        Order will be marked as failed.
        """
        return self.__issuerRef

    def commonName(self) -> Optional[str]:
        """
        CommonName is the common name as specified on the DER encoded CSR.
        If CommonName is not specified, the first DNSName specified will be used
        as the CommonName.
        At least one of CommonName or a DNSNames must be set.
        This field must match the corresponding field on the DER encoded CSR.
        """
        return self.__commonName

    def dnsNames(self) -> Optional[List[str]]:
        """
        DNSNames is a list of DNS names that should be included as part of the Order
        validation process.
        If CommonName is not specified, the first DNSName specified will be used
        as the CommonName.
        At least one of CommonName or a DNSNames must be set.
        This field must match the corresponding field on the DER encoded CSR.
        """
        return self.__dnsNames


class Order(base.TypedObject, base.NamespacedMetadataObject):
    """
    Order is a type to represent an Order with an ACME server
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "OrderSpec" = None,
    ):
        super().__init__(
            apiVersion="acme.cert-manager.io/v1alpha3",
            kind="Order",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else OrderSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["OrderSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["OrderSpec"]:
        return self.__spec
