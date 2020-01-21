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
    def __init__(self, secretName: str = ""):
        super().__init__()
        self.__secretName = secretName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secretName = self.secretName()
        check_type("secretName", secretName, str)
        v["secretName"] = secretName
        return v

    def secretName(self) -> str:
        """
        SecretName is the name of the secret used to sign Certificates issued
        by this Issuer.
        """
        return self.__secretName


class X509Subject(types.Object):
    """
    X509Subject Full X509 name specification
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        countries: List[str] = None,
        organizationalUnits: List[str] = None,
        localities: List[str] = None,
        provinces: List[str] = None,
        streetAddresses: List[str] = None,
        postalCodes: List[str] = None,
        serialNumber: str = None,
    ):
        super().__init__()
        self.__countries = countries if countries is not None else []
        self.__organizationalUnits = (
            organizationalUnits if organizationalUnits is not None else []
        )
        self.__localities = localities if localities is not None else []
        self.__provinces = provinces if provinces is not None else []
        self.__streetAddresses = streetAddresses if streetAddresses is not None else []
        self.__postalCodes = postalCodes if postalCodes is not None else []
        self.__serialNumber = serialNumber

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        countries = self.countries()
        check_type("countries", countries, Optional[List[str]])
        if countries:  # omit empty
            v["countries"] = countries
        organizationalUnits = self.organizationalUnits()
        check_type("organizationalUnits", organizationalUnits, Optional[List[str]])
        if organizationalUnits:  # omit empty
            v["organizationalUnits"] = organizationalUnits
        localities = self.localities()
        check_type("localities", localities, Optional[List[str]])
        if localities:  # omit empty
            v["localities"] = localities
        provinces = self.provinces()
        check_type("provinces", provinces, Optional[List[str]])
        if provinces:  # omit empty
            v["provinces"] = provinces
        streetAddresses = self.streetAddresses()
        check_type("streetAddresses", streetAddresses, Optional[List[str]])
        if streetAddresses:  # omit empty
            v["streetAddresses"] = streetAddresses
        postalCodes = self.postalCodes()
        check_type("postalCodes", postalCodes, Optional[List[str]])
        if postalCodes:  # omit empty
            v["postalCodes"] = postalCodes
        serialNumber = self.serialNumber()
        check_type("serialNumber", serialNumber, Optional[str])
        if serialNumber:  # omit empty
            v["serialNumber"] = serialNumber
        return v

    def countries(self) -> Optional[List[str]]:
        """
        Countries to be used on the Certificate.
        """
        return self.__countries

    def organizationalUnits(self) -> Optional[List[str]]:
        """
        Organizational Units to be used on the Certificate.
        """
        return self.__organizationalUnits

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

    def streetAddresses(self) -> Optional[List[str]]:
        """
        Street addresses to be used on the Certificate.
        """
        return self.__streetAddresses

    def postalCodes(self) -> Optional[List[str]]:
        """
        Postal codes to be used on the Certificate.
        """
        return self.__postalCodes

    def serialNumber(self) -> Optional[str]:
        """
        Serial number to be used on the Certificate.
        """
        return self.__serialNumber


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
        commonName: str = None,
        organization: List[str] = None,
        duration: "base.Duration" = None,
        renewBefore: "base.Duration" = None,
        dnsNames: List[str] = None,
        ipAddresses: List[str] = None,
        uriSANs: List[str] = None,
        secretName: str = "",
        issuerRef: "k8sv1.TypedLocalObjectReference" = None,
        isCA: bool = None,
        usages: List[KeyUsage] = None,
        keySize: int = None,
        keyAlgorithm: KeyAlgorithm = None,
        keyEncoding: KeyEncoding = None,
    ):
        super().__init__()
        self.__subject = subject
        self.__commonName = commonName
        self.__organization = organization if organization is not None else []
        self.__duration = duration
        self.__renewBefore = renewBefore
        self.__dnsNames = dnsNames if dnsNames is not None else []
        self.__ipAddresses = ipAddresses if ipAddresses is not None else []
        self.__uriSANs = uriSANs if uriSANs is not None else []
        self.__secretName = secretName
        self.__issuerRef = (
            issuerRef if issuerRef is not None else k8sv1.TypedLocalObjectReference()
        )
        self.__isCA = isCA
        self.__usages = usages if usages is not None else []
        self.__keySize = keySize
        self.__keyAlgorithm = keyAlgorithm
        self.__keyEncoding = keyEncoding

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        subject = self.subject()
        check_type("subject", subject, Optional["X509Subject"])
        if subject is not None:  # omit empty
            v["subject"] = subject
        commonName = self.commonName()
        check_type("commonName", commonName, Optional[str])
        if commonName:  # omit empty
            v["commonName"] = commonName
        organization = self.organization()
        check_type("organization", organization, Optional[List[str]])
        if organization:  # omit empty
            v["organization"] = organization
        duration = self.duration()
        check_type("duration", duration, Optional["base.Duration"])
        if duration is not None:  # omit empty
            v["duration"] = duration
        renewBefore = self.renewBefore()
        check_type("renewBefore", renewBefore, Optional["base.Duration"])
        if renewBefore is not None:  # omit empty
            v["renewBefore"] = renewBefore
        dnsNames = self.dnsNames()
        check_type("dnsNames", dnsNames, Optional[List[str]])
        if dnsNames:  # omit empty
            v["dnsNames"] = dnsNames
        ipAddresses = self.ipAddresses()
        check_type("ipAddresses", ipAddresses, Optional[List[str]])
        if ipAddresses:  # omit empty
            v["ipAddresses"] = ipAddresses
        uriSANs = self.uriSANs()
        check_type("uriSANs", uriSANs, Optional[List[str]])
        if uriSANs:  # omit empty
            v["uriSANs"] = uriSANs
        secretName = self.secretName()
        check_type("secretName", secretName, str)
        v["secretName"] = secretName
        issuerRef = self.issuerRef()
        check_type("issuerRef", issuerRef, "k8sv1.TypedLocalObjectReference")
        v["issuerRef"] = issuerRef
        isCA = self.isCA()
        check_type("isCA", isCA, Optional[bool])
        if isCA:  # omit empty
            v["isCA"] = isCA
        usages = self.usages()
        check_type("usages", usages, Optional[List[KeyUsage]])
        if usages:  # omit empty
            v["usages"] = usages
        keySize = self.keySize()
        check_type("keySize", keySize, Optional[int])
        if keySize:  # omit empty
            v["keySize"] = keySize
        keyAlgorithm = self.keyAlgorithm()
        check_type("keyAlgorithm", keyAlgorithm, Optional[KeyAlgorithm])
        if keyAlgorithm:  # omit empty
            v["keyAlgorithm"] = keyAlgorithm
        keyEncoding = self.keyEncoding()
        check_type("keyEncoding", keyEncoding, Optional[KeyEncoding])
        if keyEncoding:  # omit empty
            v["keyEncoding"] = keyEncoding
        return v

    def subject(self) -> Optional["X509Subject"]:
        """
        Full X509 name specification (https://golang.org/pkg/crypto/x509/pkix/#Name).
        """
        return self.__subject

    def commonName(self) -> Optional[str]:
        """
        CommonName is a common name to be used on the Certificate.
        The CommonName should have a length of 64 characters or fewer to avoid
        generating invalid CSRs.
        """
        return self.__commonName

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

    def renewBefore(self) -> Optional["base.Duration"]:
        """
        Certificate renew before expiration duration
        """
        return self.__renewBefore

    def dnsNames(self) -> Optional[List[str]]:
        """
        DNSNames is a list of subject alt names to be used on the Certificate.
        """
        return self.__dnsNames

    def ipAddresses(self) -> Optional[List[str]]:
        """
        IPAddresses is a list of IP addresses to be used on the Certificate
        """
        return self.__ipAddresses

    def uriSANs(self) -> Optional[List[str]]:
        """
        URISANs is a list of URI Subject Alternative Names to be set on this
        Certificate.
        """
        return self.__uriSANs

    def secretName(self) -> str:
        """
        SecretName is the name of the secret resource to store this secret in
        """
        return self.__secretName

    def issuerRef(self) -> "k8sv1.TypedLocalObjectReference":
        """
        IssuerRef is a reference to the issuer for this certificate.
        If the 'kind' field is not set, or set to 'Issuer', an Issuer resource
        with the given name in the same namespace as the Certificate will be used.
        If the 'kind' field is set to 'ClusterIssuer', a ClusterIssuer with the
        provided name will be used.
        The 'name' field in this stanza is required at all times.
        """
        return self.__issuerRef

    def isCA(self) -> Optional[bool]:
        """
        IsCA will mark this Certificate as valid for signing.
        This implies that the 'cert sign' usage is set
        """
        return self.__isCA

    def usages(self) -> Optional[List[KeyUsage]]:
        """
        Usages is the set of x509 actions that are enabled for a given key. Defaults are ('digital signature', 'key encipherment') if empty
        """
        return self.__usages

    def keySize(self) -> Optional[int]:
        """
        KeySize is the key bit size of the corresponding private key for this certificate.
        If provided, value must be between 2048 and 8192 inclusive when KeyAlgorithm is
        empty or is set to "rsa", and value must be one of (256, 384, 521) when
        KeyAlgorithm is set to "ecdsa".
        """
        return self.__keySize

    def keyAlgorithm(self) -> Optional[KeyAlgorithm]:
        """
        KeyAlgorithm is the private key algorithm of the corresponding private key
        for this certificate. If provided, allowed values are either "rsa" or "ecdsa"
        If KeyAlgorithm is specified and KeySize is not provided,
        key size of 256 will be used for "ecdsa" key algorithm and
        key size of 2048 will be used for "rsa" key algorithm.
        """
        return self.__keyAlgorithm

    def keyEncoding(self) -> Optional[KeyEncoding]:
        """
        KeyEncoding is the private key cryptography standards (PKCS)
        for this certificate's private key to be encoded in. If provided, allowed
        values are "pkcs1" and "pkcs8" standing for PKCS#1 and PKCS#8, respectively.
        If KeyEncoding is not specified, then PKCS#1 will be used by default.
        """
        return self.__keyEncoding


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
            apiVersion="cert-manager.io/v1alpha3",
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
        issuerRef: "k8sv1.TypedLocalObjectReference" = None,
        csr: bytes = None,
        isCA: bool = None,
        usages: List[KeyUsage] = None,
    ):
        super().__init__()
        self.__duration = duration
        self.__issuerRef = (
            issuerRef if issuerRef is not None else k8sv1.TypedLocalObjectReference()
        )
        self.__csr = csr if csr is not None else b""
        self.__isCA = isCA
        self.__usages = usages if usages is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        duration = self.duration()
        check_type("duration", duration, Optional["base.Duration"])
        if duration is not None:  # omit empty
            v["duration"] = duration
        issuerRef = self.issuerRef()
        check_type("issuerRef", issuerRef, "k8sv1.TypedLocalObjectReference")
        v["issuerRef"] = issuerRef
        csr = self.csr()
        check_type("csr", csr, bytes)
        v["csr"] = csr
        isCA = self.isCA()
        check_type("isCA", isCA, Optional[bool])
        if isCA:  # omit empty
            v["isCA"] = isCA
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

    def issuerRef(self) -> "k8sv1.TypedLocalObjectReference":
        """
        IssuerRef is a reference to the issuer for this CertificateRequest.  If
        the 'kind' field is not set, or set to 'Issuer', an Issuer resource with
        the given name in the same namespace as the CertificateRequest will be
        used.  If the 'kind' field is set to 'ClusterIssuer', a ClusterIssuer with
        the provided name will be used. The 'name' field in this stanza is
        required at all times. The group field refers to the API group of the
        issuer which defaults to 'cert-manager.io' if empty.
        """
        return self.__issuerRef

    def csr(self) -> bytes:
        """
        Byte slice containing the PEM encoded CertificateSigningRequest
        """
        return self.__csr

    def isCA(self) -> Optional[bool]:
        """
        IsCA will mark the resulting certificate as valid for signing. This
        implies that the 'cert sign' usage is set
        """
        return self.__isCA

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
            apiVersion="cert-manager.io/v1alpha3",
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
        roleId: str = "",
        secretRef: "k8sv1.SecretKeySelector" = None,
    ):
        super().__init__()
        self.__path = path
        self.__roleId = roleId
        self.__secretRef = (
            secretRef if secretRef is not None else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        path = self.path()
        check_type("path", path, str)
        v["path"] = path
        roleId = self.roleId()
        check_type("roleId", roleId, str)
        v["roleId"] = roleId
        secretRef = self.secretRef()
        check_type("secretRef", secretRef, "k8sv1.SecretKeySelector")
        v["secretRef"] = secretRef
        return v

    def path(self) -> str:
        """
        Where the authentication path is mounted in Vault.
        """
        return self.__path

    def roleId(self) -> str:
        return self.__roleId

    def secretRef(self) -> "k8sv1.SecretKeySelector":
        return self.__secretRef


class VaultKubernetesAuth(types.Object):
    """
    Authenticate against Vault using a Kubernetes ServiceAccount token stored in
    a Secret.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        mountPath: str = None,
        secretRef: "k8sv1.SecretKeySelector" = None,
        role: str = "",
    ):
        super().__init__()
        self.__mountPath = mountPath
        self.__secretRef = (
            secretRef if secretRef is not None else k8sv1.SecretKeySelector()
        )
        self.__role = role

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        mountPath = self.mountPath()
        check_type("mountPath", mountPath, Optional[str])
        if mountPath:  # omit empty
            v["mountPath"] = mountPath
        secretRef = self.secretRef()
        check_type("secretRef", secretRef, "k8sv1.SecretKeySelector")
        v["secretRef"] = secretRef
        role = self.role()
        check_type("role", role, str)
        v["role"] = role
        return v

    def mountPath(self) -> Optional[str]:
        """
        The Vault mountPath here is the mount path to use when authenticating with
        Vault. For example, setting a value to `/v1/auth/foo`, will use the path
        `/v1/auth/foo/login` to authenticate with Vault. If unspecified, the
        default value "/v1/auth/kubernetes" will be used.
        """
        return self.__mountPath

    def secretRef(self) -> "k8sv1.SecretKeySelector":
        """
        The required Secret field containing a Kubernetes ServiceAccount JWT used
        for authenticating with Vault. Use of 'ambient credentials' is not
        supported.
        """
        return self.__secretRef

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
        tokenSecretRef: "k8sv1.SecretKeySelector" = None,
        appRole: "VaultAppRole" = None,
        kubernetes: "VaultKubernetesAuth" = None,
    ):
        super().__init__()
        self.__tokenSecretRef = tokenSecretRef
        self.__appRole = appRole
        self.__kubernetes = kubernetes

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        tokenSecretRef = self.tokenSecretRef()
        check_type(
            "tokenSecretRef", tokenSecretRef, Optional["k8sv1.SecretKeySelector"]
        )
        if tokenSecretRef is not None:  # omit empty
            v["tokenSecretRef"] = tokenSecretRef
        appRole = self.appRole()
        check_type("appRole", appRole, Optional["VaultAppRole"])
        if appRole is not None:  # omit empty
            v["appRole"] = appRole
        kubernetes = self.kubernetes()
        check_type("kubernetes", kubernetes, Optional["VaultKubernetesAuth"])
        if kubernetes is not None:  # omit empty
            v["kubernetes"] = kubernetes
        return v

    def tokenSecretRef(self) -> Optional["k8sv1.SecretKeySelector"]:
        """
        This Secret contains the Vault token key
        """
        return self.__tokenSecretRef

    def appRole(self) -> Optional["VaultAppRole"]:
        """
        This Secret contains a AppRole and Secret
        """
        return self.__appRole

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
        caBundle: bytes = None,
    ):
        super().__init__()
        self.__auth = auth if auth is not None else VaultAuth()
        self.__server = server
        self.__path = path
        self.__caBundle = caBundle if caBundle is not None else b""

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
        caBundle = self.caBundle()
        check_type("caBundle", caBundle, Optional[bytes])
        if caBundle:  # omit empty
            v["caBundle"] = caBundle
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

    def caBundle(self) -> Optional[bytes]:
        """
        Base64 encoded CA bundle to validate Vault server certificate. Only used
        if the Server URL is using HTTPS protocol. This parameter is ignored for
        plain HTTP protocol connection. If not set the system root certificates
        are used to validate the TLS connection.
        """
        return self.__caBundle


class VenafiCloud(types.Object):
    """
    VenafiCloud defines connection configuration details for Venafi Cloud
    """

    @context.scoped
    @typechecked
    def __init__(
        self, url: str = "", apiTokenSecretRef: "k8sv1.SecretKeySelector" = None
    ):
        super().__init__()
        self.__url = url
        self.__apiTokenSecretRef = (
            apiTokenSecretRef
            if apiTokenSecretRef is not None
            else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        apiTokenSecretRef = self.apiTokenSecretRef()
        check_type("apiTokenSecretRef", apiTokenSecretRef, "k8sv1.SecretKeySelector")
        v["apiTokenSecretRef"] = apiTokenSecretRef
        return v

    def url(self) -> str:
        """
        URL is the base URL for Venafi Cloud
        """
        return self.__url

    def apiTokenSecretRef(self) -> "k8sv1.SecretKeySelector":
        """
        APITokenSecretRef is a secret key selector for the Venafi Cloud API token.
        """
        return self.__apiTokenSecretRef


class VenafiTPP(types.Object):
    """
    VenafiTPP defines connection configuration details for a Venafi TPP instance
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = "",
        credentialsRef: "k8sv1.LocalObjectReference" = None,
        caBundle: bytes = None,
    ):
        super().__init__()
        self.__url = url
        self.__credentialsRef = (
            credentialsRef
            if credentialsRef is not None
            else k8sv1.LocalObjectReference()
        )
        self.__caBundle = caBundle if caBundle is not None else b""

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        credentialsRef = self.credentialsRef()
        check_type("credentialsRef", credentialsRef, "k8sv1.LocalObjectReference")
        v["credentialsRef"] = credentialsRef
        caBundle = self.caBundle()
        check_type("caBundle", caBundle, Optional[bytes])
        if caBundle:  # omit empty
            v["caBundle"] = caBundle
        return v

    def url(self) -> str:
        """
        URL is the base URL for the Venafi TPP instance
        """
        return self.__url

    def credentialsRef(self) -> "k8sv1.LocalObjectReference":
        """
        CredentialsRef is a reference to a Secret containing the username and
        password for the TPP server.
        The secret must contain two keys, 'username' and 'password'.
        """
        return self.__credentialsRef

    def caBundle(self) -> Optional[bytes]:
        """
        CABundle is a PEM encoded TLS certifiate to use to verify connections to
        the TPP instance.
        If specified, system roots will not be used and the issuing CA for the
        TPP instance must be verifiable using the provided root.
        If not specified, the connection will be verified using the cert-manager
        system root certificates.
        """
        return self.__caBundle


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
        selfSigned: "SelfSignedIssuer" = None,
        venafi: "VenafiIssuer" = None,
    ):
        super().__init__()
        self.__acme = acme
        self.__ca = ca
        self.__vault = vault
        self.__selfSigned = selfSigned
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
        selfSigned = self.selfSigned()
        check_type("selfSigned", selfSigned, Optional["SelfSignedIssuer"])
        if selfSigned is not None:  # omit empty
            v["selfSigned"] = selfSigned
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

    def selfSigned(self) -> Optional["SelfSignedIssuer"]:
        return self.__selfSigned

    def venafi(self) -> Optional["VenafiIssuer"]:
        return self.__venafi


class IssuerSpec(types.Object):
    """
    IssuerSpec is the specification of an Issuer. This includes any
    configuration required for the issuer.
    """

    @context.scoped
    @typechecked
    def __init__(self, issuerConfig: "IssuerConfig" = None):
        super().__init__()
        self.__issuerConfig = (
            issuerConfig if issuerConfig is not None else IssuerConfig()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        issuerConfig = self.issuerConfig()
        check_type("issuerConfig", issuerConfig, "IssuerConfig")
        v.update(issuerConfig._root())  # inline
        return v

    def issuerConfig(self) -> "IssuerConfig":
        return self.__issuerConfig


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
            apiVersion="cert-manager.io/v1alpha3",
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
            apiVersion="cert-manager.io/v1alpha3",
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
