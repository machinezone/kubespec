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
        self, host: str = "", account_secret_ref: "k8sv1.SecretKeySelector" = None
    ):
        super().__init__()
        self.__host = host
        self.__account_secret_ref = (
            account_secret_ref
            if account_secret_ref is not None
            else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        host = self.host()
        check_type("host", host, str)
        v["host"] = host
        account_secret_ref = self.account_secret_ref()
        check_type("account_secret_ref", account_secret_ref, "k8sv1.SecretKeySelector")
        v["accountSecretRef"] = account_secret_ref
        return v

    def host(self) -> str:
        return self.__host

    def account_secret_ref(self) -> "k8sv1.SecretKeySelector":
        return self.__account_secret_ref


class ACMEIssuerDNS01ProviderAkamai(types.Object):
    """
    ACMEIssuerDNS01ProviderAkamai is a structure containing the DNS
    configuration for Akamai DNS—Zone Record Management API
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        service_consumer_domain: str = "",
        client_token_secret_ref: "k8sv1.SecretKeySelector" = None,
        client_secret_secret_ref: "k8sv1.SecretKeySelector" = None,
        access_token_secret_ref: "k8sv1.SecretKeySelector" = None,
    ):
        super().__init__()
        self.__service_consumer_domain = service_consumer_domain
        self.__client_token_secret_ref = (
            client_token_secret_ref
            if client_token_secret_ref is not None
            else k8sv1.SecretKeySelector()
        )
        self.__client_secret_secret_ref = (
            client_secret_secret_ref
            if client_secret_secret_ref is not None
            else k8sv1.SecretKeySelector()
        )
        self.__access_token_secret_ref = (
            access_token_secret_ref
            if access_token_secret_ref is not None
            else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        service_consumer_domain = self.service_consumer_domain()
        check_type("service_consumer_domain", service_consumer_domain, str)
        v["serviceConsumerDomain"] = service_consumer_domain
        client_token_secret_ref = self.client_token_secret_ref()
        check_type(
            "client_token_secret_ref",
            client_token_secret_ref,
            "k8sv1.SecretKeySelector",
        )
        v["clientTokenSecretRef"] = client_token_secret_ref
        client_secret_secret_ref = self.client_secret_secret_ref()
        check_type(
            "client_secret_secret_ref",
            client_secret_secret_ref,
            "k8sv1.SecretKeySelector",
        )
        v["clientSecretSecretRef"] = client_secret_secret_ref
        access_token_secret_ref = self.access_token_secret_ref()
        check_type(
            "access_token_secret_ref",
            access_token_secret_ref,
            "k8sv1.SecretKeySelector",
        )
        v["accessTokenSecretRef"] = access_token_secret_ref
        return v

    def service_consumer_domain(self) -> str:
        return self.__service_consumer_domain

    def client_token_secret_ref(self) -> "k8sv1.SecretKeySelector":
        return self.__client_token_secret_ref

    def client_secret_secret_ref(self) -> "k8sv1.SecretKeySelector":
        return self.__client_secret_secret_ref

    def access_token_secret_ref(self) -> "k8sv1.SecretKeySelector":
        return self.__access_token_secret_ref


class ACMEIssuerDNS01ProviderAzureDNS(types.Object):
    """
    ACMEIssuerDNS01ProviderAzureDNS is a structure containing the
    configuration for Azure DNS
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        client_id: str = "",
        client_secret_secret_ref: "k8sv1.SecretKeySelector" = None,
        subscription_id: str = "",
        tenant_id: str = "",
        resource_group_name: str = "",
        hosted_zone_name: str = None,
        environment: AzureDNSEnvironment = None,
    ):
        super().__init__()
        self.__client_id = client_id
        self.__client_secret_secret_ref = (
            client_secret_secret_ref
            if client_secret_secret_ref is not None
            else k8sv1.SecretKeySelector()
        )
        self.__subscription_id = subscription_id
        self.__tenant_id = tenant_id
        self.__resource_group_name = resource_group_name
        self.__hosted_zone_name = hosted_zone_name
        self.__environment = environment

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_id = self.client_id()
        check_type("client_id", client_id, str)
        v["clientID"] = client_id
        client_secret_secret_ref = self.client_secret_secret_ref()
        check_type(
            "client_secret_secret_ref",
            client_secret_secret_ref,
            "k8sv1.SecretKeySelector",
        )
        v["clientSecretSecretRef"] = client_secret_secret_ref
        subscription_id = self.subscription_id()
        check_type("subscription_id", subscription_id, str)
        v["subscriptionID"] = subscription_id
        tenant_id = self.tenant_id()
        check_type("tenant_id", tenant_id, str)
        v["tenantID"] = tenant_id
        resource_group_name = self.resource_group_name()
        check_type("resource_group_name", resource_group_name, str)
        v["resourceGroupName"] = resource_group_name
        hosted_zone_name = self.hosted_zone_name()
        check_type("hosted_zone_name", hosted_zone_name, Optional[str])
        if hosted_zone_name:  # omit empty
            v["hostedZoneName"] = hosted_zone_name
        environment = self.environment()
        check_type("environment", environment, Optional[AzureDNSEnvironment])
        if environment:  # omit empty
            v["environment"] = environment
        return v

    def client_id(self) -> str:
        return self.__client_id

    def client_secret_secret_ref(self) -> "k8sv1.SecretKeySelector":
        return self.__client_secret_secret_ref

    def subscription_id(self) -> str:
        return self.__subscription_id

    def tenant_id(self) -> str:
        return self.__tenant_id

    def resource_group_name(self) -> str:
        return self.__resource_group_name

    def hosted_zone_name(self) -> Optional[str]:
        return self.__hosted_zone_name

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
        service_account_secret_ref: "k8sv1.SecretKeySelector" = None,
        project: str = "",
    ):
        super().__init__()
        self.__service_account_secret_ref = service_account_secret_ref
        self.__project = project

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        service_account_secret_ref = self.service_account_secret_ref()
        check_type(
            "service_account_secret_ref",
            service_account_secret_ref,
            Optional["k8sv1.SecretKeySelector"],
        )
        if service_account_secret_ref is not None:  # omit empty
            v["serviceAccountSecretRef"] = service_account_secret_ref
        project = self.project()
        check_type("project", project, str)
        v["project"] = project
        return v

    def service_account_secret_ref(self) -> Optional["k8sv1.SecretKeySelector"]:
        return self.__service_account_secret_ref

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
        api_key_secret_ref: "k8sv1.SecretKeySelector" = None,
        api_token_secret_ref: "k8sv1.SecretKeySelector" = None,
    ):
        super().__init__()
        self.__email = email
        self.__api_key_secret_ref = api_key_secret_ref
        self.__api_token_secret_ref = api_token_secret_ref

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        email = self.email()
        check_type("email", email, str)
        v["email"] = email
        api_key_secret_ref = self.api_key_secret_ref()
        check_type(
            "api_key_secret_ref",
            api_key_secret_ref,
            Optional["k8sv1.SecretKeySelector"],
        )
        if api_key_secret_ref is not None:  # omit empty
            v["apiKeySecretRef"] = api_key_secret_ref
        api_token_secret_ref = self.api_token_secret_ref()
        check_type(
            "api_token_secret_ref",
            api_token_secret_ref,
            Optional["k8sv1.SecretKeySelector"],
        )
        if api_token_secret_ref is not None:  # omit empty
            v["apiTokenSecretRef"] = api_token_secret_ref
        return v

    def email(self) -> str:
        return self.__email

    def api_key_secret_ref(self) -> Optional["k8sv1.SecretKeySelector"]:
        return self.__api_key_secret_ref

    def api_token_secret_ref(self) -> Optional["k8sv1.SecretKeySelector"]:
        return self.__api_token_secret_ref


class ACMEIssuerDNS01ProviderDigitalOcean(types.Object):
    """
    ACMEIssuerDNS01ProviderDigitalOcean is a structure containing the DNS
    configuration for DigitalOcean Domains
    """

    @context.scoped
    @typechecked
    def __init__(self, token_secret_ref: "k8sv1.SecretKeySelector" = None):
        super().__init__()
        self.__token_secret_ref = (
            token_secret_ref
            if token_secret_ref is not None
            else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        token_secret_ref = self.token_secret_ref()
        check_type("token_secret_ref", token_secret_ref, "k8sv1.SecretKeySelector")
        v["tokenSecretRef"] = token_secret_ref
        return v

    def token_secret_ref(self) -> "k8sv1.SecretKeySelector":
        return self.__token_secret_ref


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
        tsig_secret_secret_ref: "k8sv1.SecretKeySelector" = None,
        tsig_key_name: str = None,
        tsig_algorithm: str = None,
    ):
        super().__init__()
        self.__nameserver = nameserver
        self.__tsig_secret_secret_ref = (
            tsig_secret_secret_ref
            if tsig_secret_secret_ref is not None
            else k8sv1.SecretKeySelector()
        )
        self.__tsig_key_name = tsig_key_name
        self.__tsig_algorithm = tsig_algorithm

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        nameserver = self.nameserver()
        check_type("nameserver", nameserver, str)
        v["nameserver"] = nameserver
        tsig_secret_secret_ref = self.tsig_secret_secret_ref()
        check_type(
            "tsig_secret_secret_ref",
            tsig_secret_secret_ref,
            Optional["k8sv1.SecretKeySelector"],
        )
        v["tsigSecretSecretRef"] = tsig_secret_secret_ref
        tsig_key_name = self.tsig_key_name()
        check_type("tsig_key_name", tsig_key_name, Optional[str])
        if tsig_key_name:  # omit empty
            v["tsigKeyName"] = tsig_key_name
        tsig_algorithm = self.tsig_algorithm()
        check_type("tsig_algorithm", tsig_algorithm, Optional[str])
        if tsig_algorithm:  # omit empty
            v["tsigAlgorithm"] = tsig_algorithm
        return v

    def nameserver(self) -> str:
        """
        The IP address of the DNS supporting RFC2136. Required.
        Note: FQDN is not a valid value, only IP.
        """
        return self.__nameserver

    def tsig_secret_secret_ref(self) -> Optional["k8sv1.SecretKeySelector"]:
        """
        The name of the secret containing the TSIG value.
        If ``tsigKeyName`` is defined, this field is required.
        """
        return self.__tsig_secret_secret_ref

    def tsig_key_name(self) -> Optional[str]:
        """
        The TSIG Key name configured in the DNS.
        If ``tsigSecretSecretRef`` is defined, this field is required.
        """
        return self.__tsig_key_name

    def tsig_algorithm(self) -> Optional[str]:
        """
        The TSIG Algorithm configured in the DNS supporting RFC2136. Used only
        when ``tsigSecretSecretRef`` and ``tsigKeyName`` are defined.
        Supported values are (case-insensitive): ``HMACMD5`` (default),
        ``HMACSHA1``, ``HMACSHA256`` or ``HMACSHA512``.
        """
        return self.__tsig_algorithm


class ACMEIssuerDNS01ProviderRoute53(types.Object):
    """
    ACMEIssuerDNS01ProviderRoute53 is a structure containing the Route 53
    configuration for AWS
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        access_key_id: str = "",
        secret_access_key_secret_ref: "k8sv1.SecretKeySelector" = None,
        role: str = "",
        hosted_zone_id: str = None,
        region: str = "",
    ):
        super().__init__()
        self.__access_key_id = access_key_id
        self.__secret_access_key_secret_ref = (
            secret_access_key_secret_ref
            if secret_access_key_secret_ref is not None
            else k8sv1.SecretKeySelector()
        )
        self.__role = role
        self.__hosted_zone_id = hosted_zone_id
        self.__region = region

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        access_key_id = self.access_key_id()
        check_type("access_key_id", access_key_id, str)
        v["accessKeyID"] = access_key_id
        secret_access_key_secret_ref = self.secret_access_key_secret_ref()
        check_type(
            "secret_access_key_secret_ref",
            secret_access_key_secret_ref,
            "k8sv1.SecretKeySelector",
        )
        v["secretAccessKeySecretRef"] = secret_access_key_secret_ref
        role = self.role()
        check_type("role", role, str)
        v["role"] = role
        hosted_zone_id = self.hosted_zone_id()
        check_type("hosted_zone_id", hosted_zone_id, Optional[str])
        if hosted_zone_id:  # omit empty
            v["hostedZoneID"] = hosted_zone_id
        region = self.region()
        check_type("region", region, str)
        v["region"] = region
        return v

    def access_key_id(self) -> str:
        """
        The AccessKeyID is used for authentication. If not set we fall-back to using env vars, shared credentials file or AWS Instance metadata
        see: https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
        """
        return self.__access_key_id

    def secret_access_key_secret_ref(self) -> "k8sv1.SecretKeySelector":
        """
        The SecretAccessKey is used for authentication. If not set we fall-back to using env vars, shared credentials file or AWS Instance metadata
        https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
        """
        return self.__secret_access_key_secret_ref

    def role(self) -> str:
        """
        Role is a Role ARN which the Route53 provider will assume using either the explicit credentials AccessKeyID/SecretAccessKey
        or the inferred credentials from environment variables, shared credentials file or AWS Instance metadata
        """
        return self.__role

    def hosted_zone_id(self) -> Optional[str]:
        """
        If set, the provider will manage only this zone in Route53 and will not do an lookup using the route53:ListHostedZonesByName api call.
        """
        return self.__hosted_zone_id

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
        group_name: str = "",
        solver_name: str = "",
        config: "apiextensionsv1beta1.JSON" = None,
    ):
        super().__init__()
        self.__group_name = group_name
        self.__solver_name = solver_name
        self.__config = config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        group_name = self.group_name()
        check_type("group_name", group_name, str)
        v["groupName"] = group_name
        solver_name = self.solver_name()
        check_type("solver_name", solver_name, str)
        v["solverName"] = solver_name
        config = self.config()
        check_type("config", config, Optional["apiextensionsv1beta1.JSON"])
        if config is not None:  # omit empty
            v["config"] = config
        return v

    def group_name(self) -> str:
        """
        The API group name that should be used when POSTing ChallengePayload
        resources to the webhook apiserver.
        This should be the same as the GroupName specified in the webhook
        provider implementation.
        """
        return self.__group_name

    def solver_name(self) -> str:
        """
        The name of the solver to use, as defined in the webhook provider
        implementation.
        This will typically be the name of the provider, e.g. 'cloudflare'.
        """
        return self.__solver_name

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
        cname_strategy: CNAMEStrategy = None,
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
        self.__cname_strategy = cname_strategy
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
        cname_strategy = self.cname_strategy()
        check_type("cname_strategy", cname_strategy, Optional[CNAMEStrategy])
        if cname_strategy:  # omit empty
            v["cnameStrategy"] = cname_strategy
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

    def cname_strategy(self) -> Optional[CNAMEStrategy]:
        """
        CNAMEStrategy configures how the DNS01 provider should handle CNAME
        records when found in DNS zones.
        """
        return self.__cname_strategy

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
        node_selector: Dict[str, str] = None,
        affinity: "k8sv1.Affinity" = None,
        tolerations: List["k8sv1.Toleration"] = None,
    ):
        super().__init__()
        self.__node_selector = node_selector if node_selector is not None else {}
        self.__affinity = affinity
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional[Dict[str, str]])
        if node_selector:  # omit empty
            v["nodeSelector"] = node_selector
        affinity = self.affinity()
        check_type("affinity", affinity, Optional["k8sv1.Affinity"])
        if affinity is not None:  # omit empty
            v["affinity"] = affinity
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    def node_selector(self) -> Optional[Dict[str, str]]:
        """
        NodeSelector is a selector which must be true for the pod to fit on a node.
        Selector which must match a node's labels for the pod to be scheduled on that node.
        More info: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
        """
        return self.__node_selector

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
        service_type: k8sv1.ServiceType = None,
        class_: str = None,
        name: str = None,
        pod_template: "ACMEChallengeSolverHTTP01IngressPodTemplate" = None,
    ):
        super().__init__()
        self.__service_type = service_type
        self.__class_ = class_
        self.__name = name
        self.__pod_template = pod_template

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        service_type = self.service_type()
        check_type("service_type", service_type, Optional[k8sv1.ServiceType])
        if service_type:  # omit empty
            v["serviceType"] = service_type
        class_ = self.class_()
        check_type("class_", class_, Optional[str])
        if class_ is not None:  # omit empty
            v["class"] = class_
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        pod_template = self.pod_template()
        check_type(
            "pod_template",
            pod_template,
            Optional["ACMEChallengeSolverHTTP01IngressPodTemplate"],
        )
        if pod_template is not None:  # omit empty
            v["podTemplate"] = pod_template
        return v

    def service_type(self) -> Optional[k8sv1.ServiceType]:
        """
        Optional service type for Kubernetes solver service
        """
        return self.__service_type

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

    def pod_template(self) -> Optional["ACMEChallengeSolverHTTP01IngressPodTemplate"]:
        """
        Optional pod template used to configure the ACME challenge solver pods
        used for HTTP01 challenges
        """
        return self.__pod_template


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
        match_labels: Dict[str, str] = None,
        dns_names: List[str] = None,
        dns_zones: List[str] = None,
    ):
        super().__init__()
        self.__match_labels = match_labels if match_labels is not None else {}
        self.__dns_names = dns_names if dns_names is not None else []
        self.__dns_zones = dns_zones if dns_zones is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        match_labels = self.match_labels()
        check_type("match_labels", match_labels, Optional[Dict[str, str]])
        if match_labels:  # omit empty
            v["matchLabels"] = match_labels
        dns_names = self.dns_names()
        check_type("dns_names", dns_names, Optional[List[str]])
        if dns_names:  # omit empty
            v["dnsNames"] = dns_names
        dns_zones = self.dns_zones()
        check_type("dns_zones", dns_zones, Optional[List[str]])
        if dns_zones:  # omit empty
            v["dnsZones"] = dns_zones
        return v

    def match_labels(self) -> Optional[Dict[str, str]]:
        """
        A label selector that is used to refine the set of certificate's that
        this challenge solver will apply to.
        """
        return self.__match_labels

    def dns_names(self) -> Optional[List[str]]:
        """
        List of DNSNames that this solver will be used to solve.
        If specified and a match is found, a dnsNames selector will take
        precedence over a dnsZones selector.
        If multiple solvers match with the same dnsNames value, the solver
        with the most matching labels in matchLabels will be selected.
        If neither has more matches, the solver defined earlier in the list
        will be selected.
        """
        return self.__dns_names

    def dns_zones(self) -> Optional[List[str]]:
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
        return self.__dns_zones


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
        key_id: str = "",
        key_secret_ref: "k8sv1.SecretKeySelector" = None,
        key_algorithm: HMACKeyAlgorithm = None,
    ):
        super().__init__()
        self.__key_id = key_id
        self.__key_secret_ref = (
            key_secret_ref if key_secret_ref is not None else k8sv1.SecretKeySelector()
        )
        self.__key_algorithm = key_algorithm

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        key_id = self.key_id()
        check_type("key_id", key_id, str)
        v["keyID"] = key_id
        key_secret_ref = self.key_secret_ref()
        check_type("key_secret_ref", key_secret_ref, "k8sv1.SecretKeySelector")
        v["keySecretRef"] = key_secret_ref
        key_algorithm = self.key_algorithm()
        check_type("key_algorithm", key_algorithm, HMACKeyAlgorithm)
        v["keyAlgorithm"] = key_algorithm
        return v

    def key_id(self) -> str:
        """
        keyID is the ID of the CA key that the External Account is bound to.
        """
        return self.__key_id

    def key_secret_ref(self) -> "k8sv1.SecretKeySelector":
        """
        keySecretRef is a Secret Key Selector referencing a data item in a Kubernetes
        Secret which holds the symmetric MAC key of the External Account Binding.
        The `key` is the index string that is paired with the key data in the
        Secret and should not be confused with the key data itself, or indeed with
        the External Account Binding keyID above.
        The secret key stored in the Secret **must** be un-padded, base64 URL
        encoded data.
        """
        return self.__key_secret_ref

    def key_algorithm(self) -> HMACKeyAlgorithm:
        """
        keyAlgorithm is the MAC key algorithm that the key is used for. Valid
        values are "HS256", "HS384" and "HS512".
        """
        return self.__key_algorithm


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
        skip_tls_verify: bool = None,
        external_account_binding: "ACMEExternalAccountBinding" = None,
        private_key_secret_ref: "k8sv1.SecretKeySelector" = None,
        solvers: List["ACMEChallengeSolver"] = None,
    ):
        super().__init__()
        self.__email = email
        self.__server = server
        self.__skip_tls_verify = skip_tls_verify
        self.__external_account_binding = external_account_binding
        self.__private_key_secret_ref = (
            private_key_secret_ref
            if private_key_secret_ref is not None
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
        skip_tls_verify = self.skip_tls_verify()
        check_type("skip_tls_verify", skip_tls_verify, Optional[bool])
        if skip_tls_verify:  # omit empty
            v["skipTLSVerify"] = skip_tls_verify
        external_account_binding = self.external_account_binding()
        check_type(
            "external_account_binding",
            external_account_binding,
            Optional["ACMEExternalAccountBinding"],
        )
        if external_account_binding is not None:  # omit empty
            v["externalAccountBinding"] = external_account_binding
        private_key_secret_ref = self.private_key_secret_ref()
        check_type(
            "private_key_secret_ref", private_key_secret_ref, "k8sv1.SecretKeySelector"
        )
        v["privateKeySecretRef"] = private_key_secret_ref
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

    def skip_tls_verify(self) -> Optional[bool]:
        """
        If true, skip verifying the ACME server TLS certificate
        """
        return self.__skip_tls_verify

    def external_account_binding(self) -> Optional["ACMEExternalAccountBinding"]:
        """
        ExternalAcccountBinding is a reference to a CA external account of the ACME
        server.
        """
        return self.__external_account_binding

    def private_key_secret_ref(self) -> "k8sv1.SecretKeySelector":
        """
        PrivateKey is the name of a secret containing the private key for this
        user account.
        """
        return self.__private_key_secret_ref

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
        authz_url: str = "",
        type: ACMEChallengeType = None,
        url: str = "",
        dns_name: str = "",
        token: str = "",
        key: str = "",
        wildcard: bool = False,
        solver: "ACMEChallengeSolver" = None,
        issuer_ref: "k8sv1.TypedLocalObjectReference" = None,
    ):
        super().__init__()
        self.__authz_url = authz_url
        self.__type = type
        self.__url = url
        self.__dns_name = dns_name
        self.__token = token
        self.__key = key
        self.__wildcard = wildcard
        self.__solver = solver
        self.__issuer_ref = (
            issuer_ref if issuer_ref is not None else k8sv1.TypedLocalObjectReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        authz_url = self.authz_url()
        check_type("authz_url", authz_url, str)
        v["authzURL"] = authz_url
        type = self.type()
        check_type("type", type, ACMEChallengeType)
        v["type"] = type
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        dns_name = self.dns_name()
        check_type("dns_name", dns_name, str)
        v["dnsName"] = dns_name
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
        issuer_ref = self.issuer_ref()
        check_type("issuer_ref", issuer_ref, "k8sv1.TypedLocalObjectReference")
        v["issuerRef"] = issuer_ref
        return v

    def authz_url(self) -> str:
        """
        AuthzURL is the URL to the ACME Authorization resource that this
        challenge is a part of.
        """
        return self.__authz_url

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

    def dns_name(self) -> str:
        """
        DNSName is the identifier that this challenge is for, e.g. example.com.
        """
        return self.__dns_name

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

    def issuer_ref(self) -> "k8sv1.TypedLocalObjectReference":
        """
        IssuerRef references a properly configured ACME-type Issuer which should
        be used to create this Challenge.
        If the Issuer does not exist, processing will be retried.
        If the Issuer is not an 'ACME' Issuer, an error will be returned and the
        Challenge will be marked as failed.
        """
        return self.__issuer_ref


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
            api_version="acme.cert-manager.io/v1alpha3",
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
        issuer_ref: "k8sv1.TypedLocalObjectReference" = None,
        common_name: str = None,
        dns_names: List[str] = None,
    ):
        super().__init__()
        self.__csr = csr if csr is not None else b""
        self.__issuer_ref = (
            issuer_ref if issuer_ref is not None else k8sv1.TypedLocalObjectReference()
        )
        self.__common_name = common_name
        self.__dns_names = dns_names if dns_names is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        csr = self.csr()
        check_type("csr", csr, bytes)
        v["csr"] = csr
        issuer_ref = self.issuer_ref()
        check_type("issuer_ref", issuer_ref, "k8sv1.TypedLocalObjectReference")
        v["issuerRef"] = issuer_ref
        common_name = self.common_name()
        check_type("common_name", common_name, Optional[str])
        if common_name:  # omit empty
            v["commonName"] = common_name
        dns_names = self.dns_names()
        check_type("dns_names", dns_names, Optional[List[str]])
        if dns_names:  # omit empty
            v["dnsNames"] = dns_names
        return v

    def csr(self) -> bytes:
        """
        Certificate signing request bytes in DER encoding.
        This will be used when finalizing the order.
        This field must be set on the order.
        """
        return self.__csr

    def issuer_ref(self) -> "k8sv1.TypedLocalObjectReference":
        """
        IssuerRef references a properly configured ACME-type Issuer which should
        be used to create this Order.
        If the Issuer does not exist, processing will be retried.
        If the Issuer is not an 'ACME' Issuer, an error will be returned and the
        Order will be marked as failed.
        """
        return self.__issuer_ref

    def common_name(self) -> Optional[str]:
        """
        CommonName is the common name as specified on the DER encoded CSR.
        If CommonName is not specified, the first DNSName specified will be used
        as the CommonName.
        At least one of CommonName or a DNSNames must be set.
        This field must match the corresponding field on the DER encoded CSR.
        """
        return self.__common_name

    def dns_names(self) -> Optional[List[str]]:
        """
        DNSNames is a list of DNS names that should be included as part of the Order
        validation process.
        If CommonName is not specified, the first DNSName specified will be used
        as the CommonName.
        At least one of CommonName or a DNSNames must be set.
        This field must match the corresponding field on the DER encoded CSR.
        """
        return self.__dns_names


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
            api_version="acme.cert-manager.io/v1alpha3",
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
