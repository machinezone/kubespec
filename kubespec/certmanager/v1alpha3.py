# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.certmanager.acme import v1alpha3 as acmev1alpha3
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


KeyAlgorithm = base.Enum("KeyAlgorithm", {"ECDSA": "ecdsa", "RSA": "rsa"})


KeyEncoding = base.Enum("KeyEncoding", {"PKCS1": "pkcs1", "PKCS8": "pkcs8"})


# KeyUsage specifies valid usage contexts for keys.
# See: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
#      https://tools.ietf.org/html/rfc5280#section-4.2.1.12
# Valid KeyUsage values are as follows:
# "signing",
# "digital signature",
# "content commitment",
# "key encipherment",
# "key agreement",
# "data encipherment",
# "cert sign",
# "crl sign",
# "encipher only",
# "decipher only",
# "any",
# "server auth",
# "client auth",
# "code signing",
# "email protection",
# "s/mime",
# "ipsec end system",
# "ipsec tunnel",
# "ipsec user",
# "timestamping",
# "ocsp signing",
# "microsoft sgc",
# "netscape sgc"
KeyUsage = base.Enum(
    "KeyUsage",
    {
        "Any": "any",
        "CRLSign": "crl sign",
        "CertSign": "cert sign",
        "ClientAuth": "client auth",
        "CodeSigning": "code signing",
        "ContentCommitment": "content commitment",
        "DataEncipherment": "data encipherment",
        "DecipherOnly": "decipher only",
        "DigitalSignature": "digital signature",
        "EmailProtection": "email protection",
        "EncipherOnly": "encipher only",
        "IPsecEndSystem": "ipsec end system",
        "IPsecTunnel": "ipsec tunnel",
        "IPsecUser": "ipsec user",
        "KeyAgreement": "key agreement",
        "KeyEncipherment": "key encipherment",
        "MicrosoftSGC": "microsoft sgc",
        "NetscapeSGC": "netscape sgc",
        "OCSPSigning": "ocsp signing",
        "SMIME": "s/mime",
        "ServerAuth": "server auth",
        "Signing": "signing",
        "Timestamping": "timestamping",
    },
)


class CAIssuer(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, secret_name: str = ""):
        super().__init__()
        self.__secret_name = secret_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secret_name = self.secret_name()
        check_type("secret_name", secret_name, str)
        v["secretName"] = secret_name
        return v

    def secret_name(self) -> str:
        """
        SecretName is the name of the secret used to sign Certificates issued
        by this Issuer.
        """
        return self.__secret_name


class X509Subject(types.Object):
    """
    X509Subject Full X509 name specification
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        countries: List[str] = None,
        organizational_units: List[str] = None,
        localities: List[str] = None,
        provinces: List[str] = None,
        street_addresses: List[str] = None,
        postal_codes: List[str] = None,
        serial_number: str = None,
    ):
        super().__init__()
        self.__countries = countries if countries is not None else []
        self.__organizational_units = (
            organizational_units if organizational_units is not None else []
        )
        self.__localities = localities if localities is not None else []
        self.__provinces = provinces if provinces is not None else []
        self.__street_addresses = (
            street_addresses if street_addresses is not None else []
        )
        self.__postal_codes = postal_codes if postal_codes is not None else []
        self.__serial_number = serial_number

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        countries = self.countries()
        check_type("countries", countries, Optional[List[str]])
        if countries:  # omit empty
            v["countries"] = countries
        organizational_units = self.organizational_units()
        check_type("organizational_units", organizational_units, Optional[List[str]])
        if organizational_units:  # omit empty
            v["organizationalUnits"] = organizational_units
        localities = self.localities()
        check_type("localities", localities, Optional[List[str]])
        if localities:  # omit empty
            v["localities"] = localities
        provinces = self.provinces()
        check_type("provinces", provinces, Optional[List[str]])
        if provinces:  # omit empty
            v["provinces"] = provinces
        street_addresses = self.street_addresses()
        check_type("street_addresses", street_addresses, Optional[List[str]])
        if street_addresses:  # omit empty
            v["streetAddresses"] = street_addresses
        postal_codes = self.postal_codes()
        check_type("postal_codes", postal_codes, Optional[List[str]])
        if postal_codes:  # omit empty
            v["postalCodes"] = postal_codes
        serial_number = self.serial_number()
        check_type("serial_number", serial_number, Optional[str])
        if serial_number:  # omit empty
            v["serialNumber"] = serial_number
        return v

    def countries(self) -> Optional[List[str]]:
        """
        Countries to be used on the Certificate.
        """
        return self.__countries

    def organizational_units(self) -> Optional[List[str]]:
        """
        Organizational Units to be used on the Certificate.
        """
        return self.__organizational_units

    def localities(self) -> Optional[List[str]]:
        """
        Cities to be used on the Certificate.
        """
        return self.__localities

    def provinces(self) -> Optional[List[str]]:
        """
        State/Provinces to be used on the Certificate.
        """
        return self.__provinces

    def street_addresses(self) -> Optional[List[str]]:
        """
        Street addresses to be used on the Certificate.
        """
        return self.__street_addresses

    def postal_codes(self) -> Optional[List[str]]:
        """
        Postal codes to be used on the Certificate.
        """
        return self.__postal_codes

    def serial_number(self) -> Optional[str]:
        """
        Serial number to be used on the Certificate.
        """
        return self.__serial_number


class CertificateSpec(types.Object):
    """
    CertificateSpec defines the desired state of Certificate.
    A valid Certificate requires at least one of a CommonName, DNSName, or
    URISAN to be valid.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        subject: "X509Subject" = None,
        common_name: str = None,
        organization: List[str] = None,
        duration: "base.Duration" = None,
        renew_before: "base.Duration" = None,
        dns_names: List[str] = None,
        ip_addresses: List[str] = None,
        uri_sans: List[str] = None,
        secret_name: str = "",
        issuer_ref: "k8sv1.TypedLocalObjectReference" = None,
        is_ca: bool = None,
        usages: List[KeyUsage] = None,
        key_size: int = None,
        key_algorithm: KeyAlgorithm = None,
        key_encoding: KeyEncoding = None,
    ):
        super().__init__()
        self.__subject = subject
        self.__common_name = common_name
        self.__organization = organization if organization is not None else []
        self.__duration = duration
        self.__renew_before = renew_before
        self.__dns_names = dns_names if dns_names is not None else []
        self.__ip_addresses = ip_addresses if ip_addresses is not None else []
        self.__uri_sans = uri_sans if uri_sans is not None else []
        self.__secret_name = secret_name
        self.__issuer_ref = (
            issuer_ref if issuer_ref is not None else k8sv1.TypedLocalObjectReference()
        )
        self.__is_ca = is_ca
        self.__usages = usages if usages is not None else []
        self.__key_size = key_size
        self.__key_algorithm = key_algorithm
        self.__key_encoding = key_encoding

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        subject = self.subject()
        check_type("subject", subject, Optional["X509Subject"])
        if subject is not None:  # omit empty
            v["subject"] = subject
        common_name = self.common_name()
        check_type("common_name", common_name, Optional[str])
        if common_name:  # omit empty
            v["commonName"] = common_name
        organization = self.organization()
        check_type("organization", organization, Optional[List[str]])
        if organization:  # omit empty
            v["organization"] = organization
        duration = self.duration()
        check_type("duration", duration, Optional["base.Duration"])
        if duration is not None:  # omit empty
            v["duration"] = duration
        renew_before = self.renew_before()
        check_type("renew_before", renew_before, Optional["base.Duration"])
        if renew_before is not None:  # omit empty
            v["renewBefore"] = renew_before
        dns_names = self.dns_names()
        check_type("dns_names", dns_names, Optional[List[str]])
        if dns_names:  # omit empty
            v["dnsNames"] = dns_names
        ip_addresses = self.ip_addresses()
        check_type("ip_addresses", ip_addresses, Optional[List[str]])
        if ip_addresses:  # omit empty
            v["ipAddresses"] = ip_addresses
        uri_sans = self.uri_sans()
        check_type("uri_sans", uri_sans, Optional[List[str]])
        if uri_sans:  # omit empty
            v["uriSANs"] = uri_sans
        secret_name = self.secret_name()
        check_type("secret_name", secret_name, str)
        v["secretName"] = secret_name
        issuer_ref = self.issuer_ref()
        check_type("issuer_ref", issuer_ref, "k8sv1.TypedLocalObjectReference")
        v["issuerRef"] = issuer_ref
        is_ca = self.is_ca()
        check_type("is_ca", is_ca, Optional[bool])
        if is_ca:  # omit empty
            v["isCA"] = is_ca
        usages = self.usages()
        check_type("usages", usages, Optional[List[KeyUsage]])
        if usages:  # omit empty
            v["usages"] = usages
        key_size = self.key_size()
        check_type("key_size", key_size, Optional[int])
        if key_size:  # omit empty
            v["keySize"] = key_size
        key_algorithm = self.key_algorithm()
        check_type("key_algorithm", key_algorithm, Optional[KeyAlgorithm])
        if key_algorithm:  # omit empty
            v["keyAlgorithm"] = key_algorithm
        key_encoding = self.key_encoding()
        check_type("key_encoding", key_encoding, Optional[KeyEncoding])
        if key_encoding:  # omit empty
            v["keyEncoding"] = key_encoding
        return v

    def subject(self) -> Optional["X509Subject"]:
        """
        Full X509 name specification (https://golang.org/pkg/crypto/x509/pkix/#Name).
        """
        return self.__subject

    def common_name(self) -> Optional[str]:
        """
        CommonName is a common name to be used on the Certificate.
        The CommonName should have a length of 64 characters or fewer to avoid
        generating invalid CSRs.
        """
        return self.__common_name

    def organization(self) -> Optional[List[str]]:
        """
        Organization is the organization to be used on the Certificate
        """
        return self.__organization

    def duration(self) -> Optional["base.Duration"]:
        """
        Certificate default Duration
        """
        return self.__duration

    def renew_before(self) -> Optional["base.Duration"]:
        """
        Certificate renew before expiration duration
        """
        return self.__renew_before

    def dns_names(self) -> Optional[List[str]]:
        """
        DNSNames is a list of subject alt names to be used on the Certificate.
        """
        return self.__dns_names

    def ip_addresses(self) -> Optional[List[str]]:
        """
        IPAddresses is a list of IP addresses to be used on the Certificate
        """
        return self.__ip_addresses

    def uri_sans(self) -> Optional[List[str]]:
        """
        URISANs is a list of URI Subject Alternative Names to be set on this
        Certificate.
        """
        return self.__uri_sans

    def secret_name(self) -> str:
        """
        SecretName is the name of the secret resource to store this secret in
        """
        return self.__secret_name

    def issuer_ref(self) -> "k8sv1.TypedLocalObjectReference":
        """
        IssuerRef is a reference to the issuer for this certificate.
        If the 'kind' field is not set, or set to 'Issuer', an Issuer resource
        with the given name in the same namespace as the Certificate will be used.
        If the 'kind' field is set to 'ClusterIssuer', a ClusterIssuer with the
        provided name will be used.
        The 'name' field in this stanza is required at all times.
        """
        return self.__issuer_ref

    def is_ca(self) -> Optional[bool]:
        """
        IsCA will mark this Certificate as valid for signing.
        This implies that the 'cert sign' usage is set
        """
        return self.__is_ca

    def usages(self) -> Optional[List[KeyUsage]]:
        """
        Usages is the set of x509 actions that are enabled for a given key. Defaults are ('digital signature', 'key encipherment') if empty
        """
        return self.__usages

    def key_size(self) -> Optional[int]:
        """
        KeySize is the key bit size of the corresponding private key for this certificate.
        If provided, value must be between 2048 and 8192 inclusive when KeyAlgorithm is
        empty or is set to "rsa", and value must be one of (256, 384, 521) when
        KeyAlgorithm is set to "ecdsa".
        """
        return self.__key_size

    def key_algorithm(self) -> Optional[KeyAlgorithm]:
        """
        KeyAlgorithm is the private key algorithm of the corresponding private key
        for this certificate. If provided, allowed values are either "rsa" or "ecdsa"
        If KeyAlgorithm is specified and KeySize is not provided,
        key size of 256 will be used for "ecdsa" key algorithm and
        key size of 2048 will be used for "rsa" key algorithm.
        """
        return self.__key_algorithm

    def key_encoding(self) -> Optional[KeyEncoding]:
        """
        KeyEncoding is the private key cryptography standards (PKCS)
        for this certificate's private key to be encoded in. If provided, allowed
        values are "pkcs1" and "pkcs8" standing for PKCS#1 and PKCS#8, respectively.
        If KeyEncoding is not specified, then PKCS#1 will be used by default.
        """
        return self.__key_encoding


class Certificate(base.TypedObject, base.NamespacedMetadataObject):
    """
    Certificate is a type to represent a Certificate from ACME
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "CertificateSpec" = None,
    ):
        super().__init__(
            api_version="cert-manager.io/v1alpha3",
            kind="Certificate",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else CertificateSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["CertificateSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["CertificateSpec"]:
        return self.__spec


class CertificateRequestSpec(types.Object):
    """
    CertificateRequestSpec defines the desired state of CertificateRequest
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        duration: "base.Duration" = None,
        issuer_ref: "k8sv1.TypedLocalObjectReference" = None,
        csr: bytes = None,
        is_ca: bool = None,
        usages: List[KeyUsage] = None,
    ):
        super().__init__()
        self.__duration = duration
        self.__issuer_ref = (
            issuer_ref if issuer_ref is not None else k8sv1.TypedLocalObjectReference()
        )
        self.__csr = csr if csr is not None else b""
        self.__is_ca = is_ca
        self.__usages = usages if usages is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        duration = self.duration()
        check_type("duration", duration, Optional["base.Duration"])
        if duration is not None:  # omit empty
            v["duration"] = duration
        issuer_ref = self.issuer_ref()
        check_type("issuer_ref", issuer_ref, "k8sv1.TypedLocalObjectReference")
        v["issuerRef"] = issuer_ref
        csr = self.csr()
        check_type("csr", csr, bytes)
        v["csr"] = csr
        is_ca = self.is_ca()
        check_type("is_ca", is_ca, Optional[bool])
        if is_ca:  # omit empty
            v["isCA"] = is_ca
        usages = self.usages()
        check_type("usages", usages, Optional[List[KeyUsage]])
        if usages:  # omit empty
            v["usages"] = usages
        return v

    def duration(self) -> Optional["base.Duration"]:
        """
        Requested certificate default Duration
        """
        return self.__duration

    def issuer_ref(self) -> "k8sv1.TypedLocalObjectReference":
        """
        IssuerRef is a reference to the issuer for this CertificateRequest.  If
        the 'kind' field is not set, or set to 'Issuer', an Issuer resource with
        the given name in the same namespace as the CertificateRequest will be
        used.  If the 'kind' field is set to 'ClusterIssuer', a ClusterIssuer with
        the provided name will be used. The 'name' field in this stanza is
        required at all times. The group field refers to the API group of the
        issuer which defaults to 'cert-manager.io' if empty.
        """
        return self.__issuer_ref

    def csr(self) -> bytes:
        """
        Byte slice containing the PEM encoded CertificateSigningRequest
        """
        return self.__csr

    def is_ca(self) -> Optional[bool]:
        """
        IsCA will mark the resulting certificate as valid for signing. This
        implies that the 'cert sign' usage is set
        """
        return self.__is_ca

    def usages(self) -> Optional[List[KeyUsage]]:
        """
        Usages is the set of x509 actions that are enabled for a given key.
        Defaults are ('digital signature', 'key encipherment') if empty
        """
        return self.__usages


class CertificateRequest(base.TypedObject, base.NamespacedMetadataObject):
    """
    CertificateRequest is a type to represent a Certificate Signing Request
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "CertificateRequestSpec" = None,
    ):
        super().__init__(
            api_version="cert-manager.io/v1alpha3",
            kind="CertificateRequest",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else CertificateRequestSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["CertificateRequestSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["CertificateRequestSpec"]:
        return self.__spec


class SelfSignedIssuer(types.Object):
    pass  # FIXME


class VaultAppRole(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        path: str = "",
        role_id: str = "",
        secret_ref: "k8sv1.SecretKeySelector" = None,
    ):
        super().__init__()
        self.__path = path
        self.__role_id = role_id
        self.__secret_ref = (
            secret_ref if secret_ref is not None else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        role_id = self.role_id()
        check_type("role_id", role_id, str)
        v["roleId"] = role_id
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, "k8sv1.SecretKeySelector")
        v["secretRef"] = secret_ref
        return v

    def path(self) -> str:
        """
        Where the authentication path is mounted in Vault.
        """
        return self.__path

    def role_id(self) -> str:
        return self.__role_id

    def secret_ref(self) -> "k8sv1.SecretKeySelector":
        return self.__secret_ref


class VaultKubernetesAuth(types.Object):
    """
    Authenticate against Vault using a Kubernetes ServiceAccount token stored in
    a Secret.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        mount_path: str = None,
        secret_ref: "k8sv1.SecretKeySelector" = None,
        role: str = "",
    ):
        super().__init__()
        self.__mount_path = mount_path
        self.__secret_ref = (
            secret_ref if secret_ref is not None else k8sv1.SecretKeySelector()
        )
        self.__role = role

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        mount_path = self.mount_path()
        check_type("mount_path", mount_path, Optional[str])
        if mount_path:  # omit empty
            v["mountPath"] = mount_path
        secret_ref = self.secret_ref()
        check_type("secret_ref", secret_ref, "k8sv1.SecretKeySelector")
        v["secretRef"] = secret_ref
        role = self.role()
        check_type("role", role, str)
        v["role"] = role
        return v

    def mount_path(self) -> Optional[str]:
        """
        The Vault mountPath here is the mount path to use when authenticating with
        Vault. For example, setting a value to `/v1/auth/foo`, will use the path
        `/v1/auth/foo/login` to authenticate with Vault. If unspecified, the
        default value "/v1/auth/kubernetes" will be used.
        """
        return self.__mount_path

    def secret_ref(self) -> "k8sv1.SecretKeySelector":
        """
        The required Secret field containing a Kubernetes ServiceAccount JWT used
        for authenticating with Vault. Use of 'ambient credentials' is not
        supported.
        """
        return self.__secret_ref

    def role(self) -> str:
        """
        A required field containing the Vault Role to assume. A Role binds a
        Kubernetes ServiceAccount with a set of Vault policies.
        """
        return self.__role


class VaultAuth(types.Object):
    """
    Vault authentication  can be configured:
    - With a secret containing a token. Cert-manager is using this token as-is.
    - With a secret containing a AppRole. This AppRole is used to authenticate to
      Vault and retrieve a token.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        token_secret_ref: "k8sv1.SecretKeySelector" = None,
        app_role: "VaultAppRole" = None,
        kubernetes: "VaultKubernetesAuth" = None,
    ):
        super().__init__()
        self.__token_secret_ref = token_secret_ref
        self.__app_role = app_role
        self.__kubernetes = kubernetes

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        token_secret_ref = self.token_secret_ref()
        check_type(
            "token_secret_ref", token_secret_ref, Optional["k8sv1.SecretKeySelector"]
        )
        if token_secret_ref is not None:  # omit empty
            v["tokenSecretRef"] = token_secret_ref
        app_role = self.app_role()
        check_type("app_role", app_role, Optional["VaultAppRole"])
        if app_role is not None:  # omit empty
            v["appRole"] = app_role
        kubernetes = self.kubernetes()
        check_type("kubernetes", kubernetes, Optional["VaultKubernetesAuth"])
        if kubernetes is not None:  # omit empty
            v["kubernetes"] = kubernetes
        return v

    def token_secret_ref(self) -> Optional["k8sv1.SecretKeySelector"]:
        """
        This Secret contains the Vault token key
        """
        return self.__token_secret_ref

    def app_role(self) -> Optional["VaultAppRole"]:
        """
        This Secret contains a AppRole and Secret
        """
        return self.__app_role

    def kubernetes(self) -> Optional["VaultKubernetesAuth"]:
        """
        This contains a Role and Secret with a ServiceAccount token to
        authenticate with vault.
        """
        return self.__kubernetes


class VaultIssuer(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        auth: "VaultAuth" = None,
        server: str = "",
        path: str = "",
        ca_bundle: bytes = None,
    ):
        super().__init__()
        self.__auth = auth if auth is not None else VaultAuth()
        self.__server = server
        self.__path = path
        self.__ca_bundle = ca_bundle if ca_bundle is not None else b""

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        auth = self.auth()
        check_type("auth", auth, "VaultAuth")
        v["auth"] = auth
        server = self.server()
        check_type("server", server, str)
        v["server"] = server
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        ca_bundle = self.ca_bundle()
        check_type("ca_bundle", ca_bundle, Optional[bytes])
        if ca_bundle:  # omit empty
            v["caBundle"] = ca_bundle
        return v

    def auth(self) -> "VaultAuth":
        """
        Vault authentication
        """
        return self.__auth

    def server(self) -> str:
        """
        Server is the vault connection address
        """
        return self.__server

    def path(self) -> str:
        """
        Vault URL path to the certificate role
        """
        return self.__path

    def ca_bundle(self) -> Optional[bytes]:
        """
        Base64 encoded CA bundle to validate Vault server certificate. Only used
        if the Server URL is using HTTPS protocol. This parameter is ignored for
        plain HTTP protocol connection. If not set the system root certificates
        are used to validate the TLS connection.
        """
        return self.__ca_bundle


class VenafiCloud(types.Object):
    """
    VenafiCloud defines connection configuration details for Venafi Cloud
    """

    @context.scoped
    @typechecked
    def __init__(
        self, url: str = "", api_token_secret_ref: "k8sv1.SecretKeySelector" = None
    ):
        super().__init__()
        self.__url = url
        self.__api_token_secret_ref = (
            api_token_secret_ref
            if api_token_secret_ref is not None
            else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        api_token_secret_ref = self.api_token_secret_ref()
        check_type(
            "api_token_secret_ref", api_token_secret_ref, "k8sv1.SecretKeySelector"
        )
        v["apiTokenSecretRef"] = api_token_secret_ref
        return v

    def url(self) -> str:
        """
        URL is the base URL for Venafi Cloud
        """
        return self.__url

    def api_token_secret_ref(self) -> "k8sv1.SecretKeySelector":
        """
        APITokenSecretRef is a secret key selector for the Venafi Cloud API token.
        """
        return self.__api_token_secret_ref


class VenafiTPP(types.Object):
    """
    VenafiTPP defines connection configuration details for a Venafi TPP instance
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = "",
        credentials_ref: "k8sv1.LocalObjectReference" = None,
        ca_bundle: bytes = None,
    ):
        super().__init__()
        self.__url = url
        self.__credentials_ref = (
            credentials_ref
            if credentials_ref is not None
            else k8sv1.LocalObjectReference()
        )
        self.__ca_bundle = ca_bundle if ca_bundle is not None else b""

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        credentials_ref = self.credentials_ref()
        check_type("credentials_ref", credentials_ref, "k8sv1.LocalObjectReference")
        v["credentialsRef"] = credentials_ref
        ca_bundle = self.ca_bundle()
        check_type("ca_bundle", ca_bundle, Optional[bytes])
        if ca_bundle:  # omit empty
            v["caBundle"] = ca_bundle
        return v

    def url(self) -> str:
        """
        URL is the base URL for the Venafi TPP instance
        """
        return self.__url

    def credentials_ref(self) -> "k8sv1.LocalObjectReference":
        """
        CredentialsRef is a reference to a Secret containing the username and
        password for the TPP server.
        The secret must contain two keys, 'username' and 'password'.
        """
        return self.__credentials_ref

    def ca_bundle(self) -> Optional[bytes]:
        """
        CABundle is a PEM encoded TLS certifiate to use to verify connections to
        the TPP instance.
        If specified, system roots will not be used and the issuing CA for the
        TPP instance must be verifiable using the provided root.
        If not specified, the connection will be verified using the cert-manager
        system root certificates.
        """
        return self.__ca_bundle


class VenafiIssuer(types.Object):
    """
    VenafiIssuer describes issuer configuration details for Venafi Cloud.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, zone: str = "", tpp: "VenafiTPP" = None, cloud: "VenafiCloud" = None
    ):
        super().__init__()
        self.__zone = zone
        self.__tpp = tpp
        self.__cloud = cloud

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        zone = self.zone()
        check_type("zone", zone, str)
        v["zone"] = zone
        tpp = self.tpp()
        check_type("tpp", tpp, Optional["VenafiTPP"])
        if tpp is not None:  # omit empty
            v["tpp"] = tpp
        cloud = self.cloud()
        check_type("cloud", cloud, Optional["VenafiCloud"])
        if cloud is not None:  # omit empty
            v["cloud"] = cloud
        return v

    def zone(self) -> str:
        """
        Zone is the Venafi Policy Zone to use for this issuer.
        All requests made to the Venafi platform will be restricted by the named
        zone policy.
        This field is required.
        """
        return self.__zone

    def tpp(self) -> Optional["VenafiTPP"]:
        """
        TPP specifies Trust Protection Platform configuration settings.
        Only one of TPP or Cloud may be specified.
        """
        return self.__tpp

    def cloud(self) -> Optional["VenafiCloud"]:
        """
        Cloud specifies the Venafi cloud configuration settings.
        Only one of TPP or Cloud may be specified.
        """
        return self.__cloud


class IssuerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        acme: "acmev1alpha3.ACMEIssuer" = None,
        ca: "CAIssuer" = None,
        vault: "VaultIssuer" = None,
        self_signed: "SelfSignedIssuer" = None,
        venafi: "VenafiIssuer" = None,
    ):
        super().__init__()
        self.__acme = acme
        self.__ca = ca
        self.__vault = vault
        self.__self_signed = self_signed
        self.__venafi = venafi

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        acme = self.acme()
        check_type("acme", acme, Optional["acmev1alpha3.ACMEIssuer"])
        if acme is not None:  # omit empty
            v["acme"] = acme
        ca = self.ca()
        check_type("ca", ca, Optional["CAIssuer"])
        if ca is not None:  # omit empty
            v["ca"] = ca
        vault = self.vault()
        check_type("vault", vault, Optional["VaultIssuer"])
        if vault is not None:  # omit empty
            v["vault"] = vault
        self_signed = self.self_signed()
        check_type("self_signed", self_signed, Optional["SelfSignedIssuer"])
        if self_signed is not None:  # omit empty
            v["selfSigned"] = self_signed
        venafi = self.venafi()
        check_type("venafi", venafi, Optional["VenafiIssuer"])
        if venafi is not None:  # omit empty
            v["venafi"] = venafi
        return v

    def acme(self) -> Optional["acmev1alpha3.ACMEIssuer"]:
        return self.__acme

    def ca(self) -> Optional["CAIssuer"]:
        return self.__ca

    def vault(self) -> Optional["VaultIssuer"]:
        return self.__vault

    def self_signed(self) -> Optional["SelfSignedIssuer"]:
        return self.__self_signed

    def venafi(self) -> Optional["VenafiIssuer"]:
        return self.__venafi


class IssuerSpec(types.Object):
    """
    IssuerSpec is the specification of an Issuer. This includes any
    configuration required for the issuer.
    """

    @context.scoped
    @typechecked
    def __init__(self, issuer_config: "IssuerConfig" = None):
        super().__init__()
        self.__issuer_config = (
            issuer_config if issuer_config is not None else IssuerConfig()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        issuer_config = self.issuer_config()
        check_type("issuer_config", issuer_config, "IssuerConfig")
        v.update(issuer_config._root())  # inline
        return v

    def issuer_config(self) -> "IssuerConfig":
        return self.__issuer_config


class ClusterIssuer(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "IssuerSpec" = None,
    ):
        super().__init__(
            api_version="cert-manager.io/v1alpha3",
            kind="ClusterIssuer",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else IssuerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["IssuerSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["IssuerSpec"]:
        return self.__spec


class Issuer(base.TypedObject, base.NamespacedMetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "IssuerSpec" = None,
    ):
        super().__init__(
            api_version="cert-manager.io/v1alpha3",
            kind="Issuer",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else IssuerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["IssuerSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["IssuerSpec"]:
        return self.__spec
