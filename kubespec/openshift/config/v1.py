# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


AuthenticationType = base.Enum(
    "AuthenticationType",
    {
        # IntegratedOAuth refers to the cluster managed OAuth server.
        # It is configured via the top level OAuth config.
        "IntegratedOAuth": "IntegratedOAuth",
        # None means that no cluster managed authentication system is in place.
        # Note that user login will only work if a manually configured system is in place and
        # referenced in authentication spec via oauthMetadata and webhookTokenAuthenticators.
        "None": "None",
    },
)


# ClusterID is string RFC4122 uuid.
ClusterID = base.Enum("ClusterID", {})


EncryptionType = base.Enum(
    "EncryptionType",
    {
        # aescbc refers to a type where AES-CBC with PKCS#7 padding and a 32-byte key
        # is used to perform encryption at the datastore layer.
        "AESCBC": "aescbc",
        # identity refers to a type where no encryption is performed at the datastore layer.
        # Resources are written as-is without encryption.
        "Identity": "identity",
    },
)


FeatureSet = base.Enum(
    "FeatureSet",
    {
        # CustomNoUpgrade allows the enabling or disabling of any feature. Turning this feature set on IS NOT SUPPORTED, CANNOT BE UNDONE, and PREVENTS UPGRADES.
        # Because of its nature, this setting cannot be validated.  If you have any typos or accidentally apply invalid combinations
        # your cluster may fail in an unrecoverable way.
        "CustomNoUpgrade": "CustomNoUpgrade",
        # Default feature set that allows upgrades.
        "Default": "",
        # TopologyManager enables ToplogyManager support. Upgrades are enabled with this feature.
        "LatencySensitive": "LatencySensitive",
        # TechPreviewNoUpgrade turns on tech preview features that are not part of the normal supported platform. Turning
        # this feature set on CANNOT BE UNDONE and PREVENTS UPGRADES.
        "TechPreviewNoUpgrade": "TechPreviewNoUpgrade",
    },
)


IdentityProviderType = base.Enum(
    "IdentityProviderType",
    {
        # BasicAuth provides identities for users authenticating with HTTP Basic Auth
        "BasicAuth": "BasicAuth",
        # GitHub provides identities for users authenticating using GitHub credentials
        "GitHub": "GitHub",
        # GitLab provides identities for users authenticating using GitLab credentials
        "GitLab": "GitLab",
        # Google provides identities for users authenticating using Google credentials
        "Google": "Google",
        # HTPasswd provides identities from an HTPasswd file
        "HTPasswd": "HTPasswd",
        # Keystone provides identitities for users authenticating using keystone password credentials
        "Keystone": "Keystone",
        # LDAP provides identities for users authenticating using LDAP credentials
        "LDAP": "LDAP",
        # OpenID provides identities for users authenticating using OpenID credentials
        "OpenID": "OpenID",
        # RequestHeader provides identities for users authenticating using request header credentials
        "RequestHeader": "RequestHeader",
    },
)


LogFormatType = base.Enum(
    "LogFormatType",
    {
        # Json saves event in structured json format.
        "Json": "json",
        # Legacy saves event in 1-line text format.
        "Legacy": "legacy",
    },
)


# MappingMethodType specifies how new identities should be mapped to users when they log in
MappingMethodType = base.Enum(
    "MappingMethodType",
    {
        # Add provisions a user with the identity’s preferred user name. If a user with
        # that user name already exists, the identity is mapped to the existing user, adding to any
        # existing identity mappings for the user.
        "Add": "add",
        # Claim provisions a user with the identity’s preferred user name. Fails if a user
        # with that user name is already mapped to another identity.
        # Default.
        "Claim": "claim",
        # Lookup looks up existing users already mapped to an identity but does not
        # automatically provision users or identities. Requires identities and users be set up
        # manually or using an external process.
        "Lookup": "lookup",
    },
)


# TLSProfileType defines a TLS security profile type.
TLSProfileType = base.Enum(
    "TLSProfileType",
    {
        # Custom is a TLS security profile that allows for user-defined parameters.
        "Custom": "Custom",
        # Intermediate is a TLS security profile based on:
        # https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29
        "Intermediate": "Intermediate",
        # Modern is a TLS security profile based on:
        # https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
        "Modern": "Modern",
        # Old is a TLS security profile based on:
        # https://wiki.mozilla.org/Security/Server_Side_TLS#Old_backward_compatibility
        "Old": "Old",
    },
)


# TLSProtocolVersion is a way to specify the protocol version used for TLS connections.
# Protocol versions are based on the following most common TLS configurations:
#
#   https://ssl-config.mozilla.org/
#
# Note that SSLv3.0 is not a supported protocol version due to well known
# vulnerabilities such as POODLE: https://en.wikipedia.org/wiki/POODLE
TLSProtocolVersion = base.Enum(
    "TLSProtocolVersion",
    {
        # VersionTLSv10 is version 1.0 of the TLS security protocol.
        "VersionTLS10": "VersionTLS10",
        # VersionTLSv11 is version 1.1 of the TLS security protocol.
        "VersionTLS11": "VersionTLS11",
        # VersionTLSv12 is version 1.2 of the TLS security protocol.
        "VersionTLS12": "VersionTLS12",
        # VersionTLSv13 is version 1.3 of the TLS security protocol.
        "VersionTLS13": "VersionTLS13",
    },
)


# URL is a thin wrapper around string that ensures the string is a valid URL.
URL = base.Enum("URL", {})


WebHookModeType = base.Enum(
    "WebHookModeType",
    {
        # Batch indicates that the webhook should buffer audit events
        # internally, sending batch updates either once a certain number of
        # events have been received or a certain amount of time has passed.
        "Batch": "batch",
        # Blocking causes the webhook to block on every attempt to process
        # a set of events. This causes requests to the API server to wait for a
        # round trip to the external audit service before sending a response.
        "Blocking": "blocking",
    },
)


class APIServerEncryption(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, type: EncryptionType = None):
        super().__init__()
        self.__type = type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, Optional[EncryptionType])
        if type:  # omit empty
            v["type"] = type
        return v

    def type(self) -> Optional[EncryptionType]:
        """
        type defines what encryption type should be used to encrypt resources at the datastore layer.
        When this field is unset (i.e. when it is set to the empty string), identity is implied.
        The behavior of unset can and will change over time.  Even if encryption is enabled by default,
        the meaning of unset may change to a different encryption type based on changes in best practices.
        
        When encryption is enabled, all sensitive resources shipped with the platform are encrypted.
        This list of sensitive resources can and will change over time.  The current authoritative list is:
        
          1. secrets
          2. configmaps
          3. routes.route.openshift.io
          4. oauthaccesstokens.oauth.openshift.io
          5. oauthauthorizetokens.oauth.openshift.io
        
        +unionDiscriminator
        """
        return self.__type


class SecretNameReference(types.Object):
    """
    SecretNameReference references a secret in a specific namespace.
    The namespace must be specified at the point of use.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = ""):
        super().__init__()
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def name(self) -> str:
        """
        name is the metadata.name of the referenced secret
        +required
        """
        return self.__name


class APIServerNamedServingCert(types.Object):
    """
    APIServerNamedServingCert maps a server DNS name, as understood by a client, to a certificate.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, names: List[str] = None, serving_certificate: "SecretNameReference" = None
    ):
        super().__init__()
        self.__names = names if names is not None else []
        self.__serving_certificate = (
            serving_certificate
            if serving_certificate is not None
            else SecretNameReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        names = self.names()
        check_type("names", names, Optional[List[str]])
        if names:  # omit empty
            v["names"] = names
        serving_certificate = self.serving_certificate()
        check_type("serving_certificate", serving_certificate, "SecretNameReference")
        v["servingCertificate"] = serving_certificate
        return v

    def names(self) -> Optional[List[str]]:
        """
        names is a optional list of explicit DNS names (leading wildcards allowed) that should use this certificate to
        serve secure traffic. If no names are provided, the implicit names will be extracted from the certificates.
        Exact names trump over wildcard names. Explicit names defined here trump over extracted implicit names.
        """
        return self.__names

    def serving_certificate(self) -> "SecretNameReference":
        """
        servingCertificate references a kubernetes.io/tls type secret containing the TLS cert info for serving secure traffic.
        The secret must exist in the openshift-config namespace and contain the following required fields:
        - Secret.Data["tls.key"] - TLS private key.
        - Secret.Data["tls.crt"] - TLS certificate.
        """
        return self.__serving_certificate


class APIServerServingCerts(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, named_certificates: List["APIServerNamedServingCert"] = None):
        super().__init__()
        self.__named_certificates = (
            named_certificates if named_certificates is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        named_certificates = self.named_certificates()
        check_type(
            "named_certificates",
            named_certificates,
            Optional[List["APIServerNamedServingCert"]],
        )
        if named_certificates:  # omit empty
            v["namedCertificates"] = named_certificates
        return v

    def named_certificates(self) -> Optional[List["APIServerNamedServingCert"]]:
        """
        namedCertificates references secrets containing the TLS cert info for serving secure traffic to specific hostnames.
        If no named certificates are provided, or no named certificates match the server name as understood by a client,
        the defaultServingCertificate will be used.
        """
        return self.__named_certificates


class ConfigMapNameReference(types.Object):
    """
    ConfigMapNameReference references a config map in a specific namespace.
    The namespace must be specified at the point of use.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = ""):
        super().__init__()
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def name(self) -> str:
        """
        name is the metadata.name of the referenced config map
        +required
        """
        return self.__name


class TLSProfileSpec(types.Object):
    """
    TLSProfileSpec is the desired behavior of a TLSSecurityProfile.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, ciphers: List[str] = None, min_tls_version: TLSProtocolVersion = None
    ):
        super().__init__()
        self.__ciphers = ciphers if ciphers is not None else []
        self.__min_tls_version = min_tls_version

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ciphers = self.ciphers()
        check_type("ciphers", ciphers, List[str])
        v["ciphers"] = ciphers
        min_tls_version = self.min_tls_version()
        check_type("min_tls_version", min_tls_version, TLSProtocolVersion)
        v["minTLSVersion"] = min_tls_version
        return v

    def ciphers(self) -> List[str]:
        """
        ciphers is used to specify the cipher algorithms that are negotiated
        during the TLS handshake.  Operators may remove entries their operands
        do not support.  For example, to use DES-CBC3-SHA  (yaml):
        
          ciphers:
            - DES-CBC3-SHA
        """
        return self.__ciphers

    def min_tls_version(self) -> TLSProtocolVersion:
        """
        minTLSVersion is used to specify the minimal version of the TLS protocol
        that is negotiated during the TLS handshake. For example, to use TLS
        versions 1.1, 1.2 and 1.3 (yaml):
        
          minTLSVersion: TLSv1.1
        
        NOTE: currently the highest minTLSVersion allowed is VersionTLS12
        """
        return self.__min_tls_version


class CustomTLSProfile(types.Object):
    """
    CustomTLSProfile is a user-defined TLS security profile. Be extremely careful
    using a custom TLS profile as invalid configurations can be catastrophic.
    """

    @context.scoped
    @typechecked
    def __init__(self, tls_profile_spec: "TLSProfileSpec" = None):
        super().__init__()
        self.__tls_profile_spec = (
            tls_profile_spec if tls_profile_spec is not None else TLSProfileSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        tls_profile_spec = self.tls_profile_spec()
        check_type("tls_profile_spec", tls_profile_spec, "TLSProfileSpec")
        v.update(tls_profile_spec._root())  # inline
        return v

    def tls_profile_spec(self) -> "TLSProfileSpec":
        return self.__tls_profile_spec


class IntermediateTLSProfile(types.Object):
    """
    IntermediateTLSProfile is a TLS security profile based on:
    https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29
    """

    pass  # FIXME


class ModernTLSProfile(types.Object):
    """
    ModernTLSProfile is a TLS security profile based on:
    https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
    """

    pass  # FIXME


class OldTLSProfile(types.Object):
    """
    OldTLSProfile is a TLS security profile based on:
    https://wiki.mozilla.org/Security/Server_Side_TLS#Old_backward_compatibility
    """

    pass  # FIXME


class TLSSecurityProfile(types.Object):
    """
    TLSSecurityProfile defines the schema for a TLS security profile. This object
    is used by operators to apply TLS security settings to operands.
    +union
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: TLSProfileType = None,
        old: "OldTLSProfile" = None,
        intermediate: "IntermediateTLSProfile" = None,
        modern: "ModernTLSProfile" = None,
        custom: "CustomTLSProfile" = None,
    ):
        super().__init__()
        self.__type = type
        self.__old = old
        self.__intermediate = intermediate
        self.__modern = modern
        self.__custom = custom

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, TLSProfileType)
        v["type"] = type
        old = self.old()
        check_type("old", old, Optional["OldTLSProfile"])
        if old is not None:  # omit empty
            v["old"] = old
        intermediate = self.intermediate()
        check_type("intermediate", intermediate, Optional["IntermediateTLSProfile"])
        if intermediate is not None:  # omit empty
            v["intermediate"] = intermediate
        modern = self.modern()
        check_type("modern", modern, Optional["ModernTLSProfile"])
        if modern is not None:  # omit empty
            v["modern"] = modern
        custom = self.custom()
        check_type("custom", custom, Optional["CustomTLSProfile"])
        if custom is not None:  # omit empty
            v["custom"] = custom
        return v

    def type(self) -> TLSProfileType:
        """
        type is one of Old, Intermediate, Modern or Custom. Custom provides
        the ability to specify individual TLS security profile parameters.
        Old, Intermediate and Modern are TLS security profiles based on:
        
        https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations
        
        The profiles are intent based, so they may change over time as new ciphers are developed and existing ciphers
        are found to be insecure.  Depending on precisely which ciphers are available to a process, the list may be
        reduced.
        
        Note that the Modern profile is currently not supported because it is not
        yet well adopted by common software libraries.
        
        +unionDiscriminator
        """
        return self.__type

    def old(self) -> Optional["OldTLSProfile"]:
        """
        old is a TLS security profile based on:
        
        https://wiki.mozilla.org/Security/Server_Side_TLS#Old_backward_compatibility
        
        and looks like this (yaml):
        
          ciphers:
            - TLS_AES_128_GCM_SHA256
            - TLS_AES_256_GCM_SHA384
            - TLS_CHACHA20_POLY1305_SHA256
            - ECDHE-ECDSA-AES128-GCM-SHA256
            - ECDHE-RSA-AES128-GCM-SHA256
            - ECDHE-ECDSA-AES256-GCM-SHA384
            - ECDHE-RSA-AES256-GCM-SHA384
            - ECDHE-ECDSA-CHACHA20-POLY1305
            - ECDHE-RSA-CHACHA20-POLY1305
            - DHE-RSA-AES128-GCM-SHA256
            - DHE-RSA-AES256-GCM-SHA384
            - DHE-RSA-CHACHA20-POLY1305
            - ECDHE-ECDSA-AES128-SHA256
            - ECDHE-RSA-AES128-SHA256
            - ECDHE-ECDSA-AES128-SHA
            - ECDHE-RSA-AES128-SHA
            - ECDHE-ECDSA-AES256-SHA384
            - ECDHE-RSA-AES256-SHA384
            - ECDHE-ECDSA-AES256-SHA
            - ECDHE-RSA-AES256-SHA
            - DHE-RSA-AES128-SHA256
            - DHE-RSA-AES256-SHA256
            - AES128-GCM-SHA256
            - AES256-GCM-SHA384
            - AES128-SHA256
            - AES256-SHA256
            - AES128-SHA
            - AES256-SHA
            - DES-CBC3-SHA
          minTLSVersion: TLSv1.0
        
        +nullable
        """
        return self.__old

    def intermediate(self) -> Optional["IntermediateTLSProfile"]:
        """
        intermediate is a TLS security profile based on:
        
        https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28recommended.29
        
        and looks like this (yaml):
        
          ciphers:
            - TLS_AES_128_GCM_SHA256
            - TLS_AES_256_GCM_SHA384
            - TLS_CHACHA20_POLY1305_SHA256
            - ECDHE-ECDSA-AES128-GCM-SHA256
            - ECDHE-RSA-AES128-GCM-SHA256
            - ECDHE-ECDSA-AES256-GCM-SHA384
            - ECDHE-RSA-AES256-GCM-SHA384
            - ECDHE-ECDSA-CHACHA20-POLY1305
            - ECDHE-RSA-CHACHA20-POLY1305
            - DHE-RSA-AES128-GCM-SHA256
            - DHE-RSA-AES256-GCM-SHA384
          minTLSVersion: TLSv1.2
        
        +nullable
        """
        return self.__intermediate

    def modern(self) -> Optional["ModernTLSProfile"]:
        """
        modern is a TLS security profile based on:
        
        https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
        
        and looks like this (yaml):
        
          ciphers:
            - TLS_AES_128_GCM_SHA256
            - TLS_AES_256_GCM_SHA384
            - TLS_CHACHA20_POLY1305_SHA256
          minTLSVersion: TLSv1.3
        
        NOTE: Currently unsupported.
        
        +nullable
        """
        return self.__modern

    def custom(self) -> Optional["CustomTLSProfile"]:
        """
        custom is a user-defined TLS security profile. Be extremely careful using a custom
        profile as invalid configurations can be catastrophic. An example custom profile
        looks like this:
        
          ciphers:
            - ECDHE-ECDSA-CHACHA20-POLY1305
            - ECDHE-RSA-CHACHA20-POLY1305
            - ECDHE-RSA-AES128-GCM-SHA256
            - ECDHE-ECDSA-AES128-GCM-SHA256
          minTLSVersion: TLSv1.1
        
        +nullable
        """
        return self.__custom


class APIServerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        serving_certs: "APIServerServingCerts" = None,
        client_ca: "ConfigMapNameReference" = None,
        additional_cors_allowed_origins: List[str] = None,
        encryption: "APIServerEncryption" = None,
        tls_security_profile: "TLSSecurityProfile" = None,
    ):
        super().__init__()
        self.__serving_certs = (
            serving_certs if serving_certs is not None else APIServerServingCerts()
        )
        self.__client_ca = (
            client_ca if client_ca is not None else ConfigMapNameReference()
        )
        self.__additional_cors_allowed_origins = (
            additional_cors_allowed_origins
            if additional_cors_allowed_origins is not None
            else []
        )
        self.__encryption = (
            encryption if encryption is not None else APIServerEncryption()
        )
        self.__tls_security_profile = tls_security_profile

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        serving_certs = self.serving_certs()
        check_type("serving_certs", serving_certs, "APIServerServingCerts")
        v["servingCerts"] = serving_certs
        client_ca = self.client_ca()
        check_type("client_ca", client_ca, "ConfigMapNameReference")
        v["clientCA"] = client_ca
        additional_cors_allowed_origins = self.additional_cors_allowed_origins()
        check_type(
            "additional_cors_allowed_origins",
            additional_cors_allowed_origins,
            Optional[List[str]],
        )
        if additional_cors_allowed_origins:  # omit empty
            v["additionalCORSAllowedOrigins"] = additional_cors_allowed_origins
        encryption = self.encryption()
        check_type("encryption", encryption, "APIServerEncryption")
        v["encryption"] = encryption
        tls_security_profile = self.tls_security_profile()
        check_type(
            "tls_security_profile", tls_security_profile, Optional["TLSSecurityProfile"]
        )
        if tls_security_profile is not None:  # omit empty
            v["tlsSecurityProfile"] = tls_security_profile
        return v

    def serving_certs(self) -> "APIServerServingCerts":
        """
        servingCert is the TLS cert info for serving secure traffic. If not specified, operator managed certificates
        will be used for serving secure traffic.
        """
        return self.__serving_certs

    def client_ca(self) -> "ConfigMapNameReference":
        """
        clientCA references a ConfigMap containing a certificate bundle for the signers that will be recognized for
        incoming client certificates in addition to the operator managed signers. If this is empty, then only operator managed signers are valid.
        You usually only have to set this if you have your own PKI you wish to honor client certificates from.
        The ConfigMap must exist in the openshift-config namespace and contain the following required fields:
        - ConfigMap.Data["ca-bundle.crt"] - CA bundle.
        """
        return self.__client_ca

    def additional_cors_allowed_origins(self) -> Optional[List[str]]:
        """
        additionalCORSAllowedOrigins lists additional, user-defined regular expressions describing hosts for which the
        API server allows access using the CORS headers. This may be needed to access the API and the integrated OAuth
        server from JavaScript applications.
        The values are regular expressions that correspond to the Golang regular expression language.
        """
        return self.__additional_cors_allowed_origins

    def encryption(self) -> "APIServerEncryption":
        """
        encryption allows the configuration of encryption of resources at the datastore layer.
        """
        return self.__encryption

    def tls_security_profile(self) -> Optional["TLSSecurityProfile"]:
        """
        tlsSecurityProfile specifies settings for TLS connections for externally exposed servers.
        
        If unset, a default (which may change between releases) is chosen. Note that only Old and
        Intermediate profiles are currently supported, and the maximum available MinTLSVersions
        is VersionTLS12.
        """
        return self.__tls_security_profile


class APIServer(base.TypedObject, base.MetadataObject):
    """
    APIServer holds configuration (like serving certificates, client CA and CORS domains)
    shared by all API servers in the system, among them especially kube-apiserver
    and openshift-apiserver. The canonical name of an instance is 'cluster'.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "APIServerSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="APIServer",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else APIServerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "APIServerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "APIServerSpec":
        """
        +required
        """
        return self.__spec


class AdmissionPluginConfig(types.Object):
    """
    AdmissionPluginConfig holds the necessary configuration options for admission plugins
    """

    @context.scoped
    @typechecked
    def __init__(
        self, location: str = "", configuration: "runtime.RawExtension" = None
    ):
        super().__init__()
        self.__location = location
        self.__configuration = configuration

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        location = self.location()
        check_type("location", location, str)
        v["location"] = location
        configuration = self.configuration()
        check_type("configuration", configuration, "runtime.RawExtension")
        v["configuration"] = configuration
        return v

    def location(self) -> str:
        """
        Location is the path to a configuration file that contains the plugin's
        configuration
        """
        return self.__location

    def configuration(self) -> "runtime.RawExtension":
        """
        Configuration is an embedded configuration object to be used as the plugin's
        configuration. If present, it will be used instead of the path to the configuration file.
        +nullable
        """
        return self.__configuration


class AdmissionConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        plugin_config: Dict[str, "AdmissionPluginConfig"] = None,
        enabled_plugins: List[str] = None,
        disabled_plugins: List[str] = None,
    ):
        super().__init__()
        self.__plugin_config = plugin_config if plugin_config is not None else {}
        self.__enabled_plugins = enabled_plugins if enabled_plugins is not None else []
        self.__disabled_plugins = (
            disabled_plugins if disabled_plugins is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        plugin_config = self.plugin_config()
        check_type(
            "plugin_config", plugin_config, Optional[Dict[str, "AdmissionPluginConfig"]]
        )
        if plugin_config:  # omit empty
            v["pluginConfig"] = plugin_config
        enabled_plugins = self.enabled_plugins()
        check_type("enabled_plugins", enabled_plugins, Optional[List[str]])
        if enabled_plugins:  # omit empty
            v["enabledPlugins"] = enabled_plugins
        disabled_plugins = self.disabled_plugins()
        check_type("disabled_plugins", disabled_plugins, Optional[List[str]])
        if disabled_plugins:  # omit empty
            v["disabledPlugins"] = disabled_plugins
        return v

    def plugin_config(self) -> Optional[Dict[str, "AdmissionPluginConfig"]]:
        return self.__plugin_config

    def enabled_plugins(self) -> Optional[List[str]]:
        """
        enabledPlugins is a list of admission plugins that must be on in addition to the default list.
        Some admission plugins are disabled by default, but certain configurations require them.  This is fairly uncommon
        and can result in performance penalties and unexpected behavior.
        """
        return self.__enabled_plugins

    def disabled_plugins(self) -> Optional[List[str]]:
        """
        disabledPlugins is a list of admission plugins that must be off.  Putting something in this list
        is almost always a mistake and likely to result in cluster instability.
        """
        return self.__disabled_plugins


class AuditConfig(types.Object):
    """
    AuditConfig holds configuration for the audit capabilities
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        enabled: bool = False,
        audit_file_path: str = "",
        maximum_file_retention_days: int = 0,
        maximum_retained_files: int = 0,
        maximum_file_size_megabytes: int = 0,
        policy_file: str = "",
        policy_configuration: "runtime.RawExtension" = None,
        log_format: LogFormatType = None,
        web_hook_kube_config: str = "",
        web_hook_mode: WebHookModeType = None,
    ):
        super().__init__()
        self.__enabled = enabled
        self.__audit_file_path = audit_file_path
        self.__maximum_file_retention_days = maximum_file_retention_days
        self.__maximum_retained_files = maximum_retained_files
        self.__maximum_file_size_megabytes = maximum_file_size_megabytes
        self.__policy_file = policy_file
        self.__policy_configuration = policy_configuration
        self.__log_format = log_format
        self.__web_hook_kube_config = web_hook_kube_config
        self.__web_hook_mode = web_hook_mode

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        enabled = self.enabled()
        check_type("enabled", enabled, bool)
        v["enabled"] = enabled
        audit_file_path = self.audit_file_path()
        check_type("audit_file_path", audit_file_path, str)
        v["auditFilePath"] = audit_file_path
        maximum_file_retention_days = self.maximum_file_retention_days()
        check_type("maximum_file_retention_days", maximum_file_retention_days, int)
        v["maximumFileRetentionDays"] = maximum_file_retention_days
        maximum_retained_files = self.maximum_retained_files()
        check_type("maximum_retained_files", maximum_retained_files, int)
        v["maximumRetainedFiles"] = maximum_retained_files
        maximum_file_size_megabytes = self.maximum_file_size_megabytes()
        check_type("maximum_file_size_megabytes", maximum_file_size_megabytes, int)
        v["maximumFileSizeMegabytes"] = maximum_file_size_megabytes
        policy_file = self.policy_file()
        check_type("policy_file", policy_file, str)
        v["policyFile"] = policy_file
        policy_configuration = self.policy_configuration()
        check_type("policy_configuration", policy_configuration, "runtime.RawExtension")
        v["policyConfiguration"] = policy_configuration
        log_format = self.log_format()
        check_type("log_format", log_format, LogFormatType)
        v["logFormat"] = log_format
        web_hook_kube_config = self.web_hook_kube_config()
        check_type("web_hook_kube_config", web_hook_kube_config, str)
        v["webHookKubeConfig"] = web_hook_kube_config
        web_hook_mode = self.web_hook_mode()
        check_type("web_hook_mode", web_hook_mode, WebHookModeType)
        v["webHookMode"] = web_hook_mode
        return v

    def enabled(self) -> bool:
        """
        If this flag is set, audit log will be printed in the logs.
        The logs contains, method, user and a requested URL.
        """
        return self.__enabled

    def audit_file_path(self) -> str:
        """
        All requests coming to the apiserver will be logged to this file.
        """
        return self.__audit_file_path

    def maximum_file_retention_days(self) -> int:
        """
        Maximum number of days to retain old log files based on the timestamp encoded in their filename.
        """
        return self.__maximum_file_retention_days

    def maximum_retained_files(self) -> int:
        """
        Maximum number of old log files to retain.
        """
        return self.__maximum_retained_files

    def maximum_file_size_megabytes(self) -> int:
        """
        Maximum size in megabytes of the log file before it gets rotated. Defaults to 100MB.
        """
        return self.__maximum_file_size_megabytes

    def policy_file(self) -> str:
        """
        PolicyFile is a path to the file that defines the audit policy configuration.
        """
        return self.__policy_file

    def policy_configuration(self) -> "runtime.RawExtension":
        """
        PolicyConfiguration is an embedded policy configuration object to be used
        as the audit policy configuration. If present, it will be used instead of
        the path to the policy file.
        +nullable
        """
        return self.__policy_configuration

    def log_format(self) -> LogFormatType:
        """
        Format of saved audits (legacy or json).
        """
        return self.__log_format

    def web_hook_kube_config(self) -> str:
        """
        Path to a .kubeconfig formatted file that defines the audit webhook configuration.
        """
        return self.__web_hook_kube_config

    def web_hook_mode(self) -> WebHookModeType:
        """
        Strategy for sending audit events (block or batch).
        """
        return self.__web_hook_mode


class WebhookTokenAuthenticator(types.Object):
    """
    webhookTokenAuthenticator holds the necessary configuration options for a remote token authenticator
    """

    @context.scoped
    @typechecked
    def __init__(self, kube_config: "SecretNameReference" = None):
        super().__init__()
        self.__kube_config = (
            kube_config if kube_config is not None else SecretNameReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kube_config = self.kube_config()
        check_type("kube_config", kube_config, "SecretNameReference")
        v["kubeConfig"] = kube_config
        return v

    def kube_config(self) -> "SecretNameReference":
        """
        kubeConfig contains kube config file data which describes how to access the remote webhook service.
        For further details, see:
        https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication
        The key "kubeConfig" is used to locate the data.
        If the secret or expected key is not found, the webhook is not honored.
        If the specified kube config data is not valid, the webhook is not honored.
        The namespace for this secret is determined by the point of use.
        """
        return self.__kube_config


class AuthenticationSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        type: AuthenticationType = None,
        oauth_metadata: "ConfigMapNameReference" = None,
        webhook_token_authenticators: List["WebhookTokenAuthenticator"] = None,
    ):
        super().__init__()
        self.__type = type
        self.__oauth_metadata = (
            oauth_metadata if oauth_metadata is not None else ConfigMapNameReference()
        )
        self.__webhook_token_authenticators = (
            webhook_token_authenticators
            if webhook_token_authenticators is not None
            else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, AuthenticationType)
        v["type"] = type
        oauth_metadata = self.oauth_metadata()
        check_type("oauth_metadata", oauth_metadata, "ConfigMapNameReference")
        v["oauthMetadata"] = oauth_metadata
        webhook_token_authenticators = self.webhook_token_authenticators()
        check_type(
            "webhook_token_authenticators",
            webhook_token_authenticators,
            Optional[List["WebhookTokenAuthenticator"]],
        )
        if webhook_token_authenticators:  # omit empty
            v["webhookTokenAuthenticators"] = webhook_token_authenticators
        return v

    def type(self) -> AuthenticationType:
        """
        type identifies the cluster managed, user facing authentication mode in use.
        Specifically, it manages the component that responds to login attempts.
        The default is IntegratedOAuth.
        """
        return self.__type

    def oauth_metadata(self) -> "ConfigMapNameReference":
        """
        oauthMetadata contains the discovery endpoint data for OAuth 2.0
        Authorization Server Metadata for an external OAuth server.
        This discovery document can be viewed from its served location:
        oc get --raw '/.well-known/oauth-authorization-server'
        For further details, see the IETF Draft:
        https://tools.ietf.org/html/draft-ietf-oauth-discovery-04#section-2
        If oauthMetadata.name is non-empty, this value has precedence
        over any metadata reference stored in status.
        The key "oauthMetadata" is used to locate the data.
        If specified and the config map or expected key is not found, no metadata is served.
        If the specified metadata is not valid, no metadata is served.
        The namespace for this config map is openshift-config.
        """
        return self.__oauth_metadata

    def webhook_token_authenticators(
        self
    ) -> Optional[List["WebhookTokenAuthenticator"]]:
        """
        webhookTokenAuthenticators configures remote token reviewers.
        These remote authentication webhooks can be used to verify bearer tokens
        via the tokenreviews.authentication.k8s.io REST API.  This is required to
        honor bearer tokens that are provisioned by an external authentication service.
        The namespace for these secrets is openshift-config.
        """
        return self.__webhook_token_authenticators


class Authentication(base.TypedObject, base.MetadataObject):
    """
    Authentication specifies cluster-wide settings for authentication (like OAuth and
    webhook token authenticators). The canonical name of an instance is `cluster`.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "AuthenticationSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="Authentication",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else AuthenticationSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "AuthenticationSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "AuthenticationSpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class OAuthRemoteConnectionInfo(types.Object):
    """
    OAuthRemoteConnectionInfo holds information necessary for establishing a remote connection
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = "",
        ca: "ConfigMapNameReference" = None,
        tls_client_cert: "SecretNameReference" = None,
        tls_client_key: "SecretNameReference" = None,
    ):
        super().__init__()
        self.__url = url
        self.__ca = ca if ca is not None else ConfigMapNameReference()
        self.__tls_client_cert = (
            tls_client_cert if tls_client_cert is not None else SecretNameReference()
        )
        self.__tls_client_key = (
            tls_client_key if tls_client_key is not None else SecretNameReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        ca = self.ca()
        check_type("ca", ca, "ConfigMapNameReference")
        v["ca"] = ca
        tls_client_cert = self.tls_client_cert()
        check_type("tls_client_cert", tls_client_cert, "SecretNameReference")
        v["tlsClientCert"] = tls_client_cert
        tls_client_key = self.tls_client_key()
        check_type("tls_client_key", tls_client_key, "SecretNameReference")
        v["tlsClientKey"] = tls_client_key
        return v

    def url(self) -> str:
        """
        url is the remote URL to connect to
        """
        return self.__url

    def ca(self) -> "ConfigMapNameReference":
        """
        ca is an optional reference to a config map by name containing the PEM-encoded CA bundle.
        It is used as a trust anchor to validate the TLS certificate presented by the remote server.
        The key "ca.crt" is used to locate the data.
        If specified and the config map or expected key is not found, the identity provider is not honored.
        If the specified ca data is not valid, the identity provider is not honored.
        If empty, the default system roots are used.
        The namespace for this config map is openshift-config.
        """
        return self.__ca

    def tls_client_cert(self) -> "SecretNameReference":
        """
        tlsClientCert is an optional reference to a secret by name that contains the
        PEM-encoded TLS client certificate to present when connecting to the server.
        The key "tls.crt" is used to locate the data.
        If specified and the secret or expected key is not found, the identity provider is not honored.
        If the specified certificate data is not valid, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__tls_client_cert

    def tls_client_key(self) -> "SecretNameReference":
        """
        tlsClientKey is an optional reference to a secret by name that contains the
        PEM-encoded TLS private key for the client certificate referenced in tlsClientCert.
        The key "tls.key" is used to locate the data.
        If specified and the secret or expected key is not found, the identity provider is not honored.
        If the specified certificate data is not valid, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__tls_client_key


class BasicAuthIdentityProvider(types.Object):
    """
    BasicAuthPasswordIdentityProvider provides identities for users authenticating using HTTP basic auth credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self, oauth_remote_connection_info: "OAuthRemoteConnectionInfo" = None
    ):
        super().__init__()
        self.__oauth_remote_connection_info = (
            oauth_remote_connection_info
            if oauth_remote_connection_info is not None
            else OAuthRemoteConnectionInfo()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        oauth_remote_connection_info = self.oauth_remote_connection_info()
        check_type(
            "oauth_remote_connection_info",
            oauth_remote_connection_info,
            "OAuthRemoteConnectionInfo",
        )
        v.update(oauth_remote_connection_info._root())  # inline
        return v

    def oauth_remote_connection_info(self) -> "OAuthRemoteConnectionInfo":
        """
        OAuthRemoteConnectionInfo contains information about how to connect to the external basic auth server
        """
        return self.__oauth_remote_connection_info


class ImageLabel(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, name: str = "", value: str = None):
        super().__init__()
        self.__name = name
        self.__value = value

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        value = self.value()
        check_type("value", value, Optional[str])
        if value:  # omit empty
            v["value"] = value
        return v

    def name(self) -> str:
        """
        Name defines the name of the label. It must have non-zero length.
        """
        return self.__name

    def value(self) -> Optional[str]:
        """
        Value defines the literal value of the label.
        """
        return self.__value


class ProxySpec(types.Object):
    """
    ProxySpec contains cluster proxy creation configuration.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        http_proxy: str = None,
        https_proxy: str = None,
        no_proxy: str = None,
        readiness_endpoints: List[str] = None,
        trusted_ca: "ConfigMapNameReference" = None,
    ):
        super().__init__()
        self.__http_proxy = http_proxy
        self.__https_proxy = https_proxy
        self.__no_proxy = no_proxy
        self.__readiness_endpoints = (
            readiness_endpoints if readiness_endpoints is not None else []
        )
        self.__trusted_ca = (
            trusted_ca if trusted_ca is not None else ConfigMapNameReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        http_proxy = self.http_proxy()
        check_type("http_proxy", http_proxy, Optional[str])
        if http_proxy:  # omit empty
            v["httpProxy"] = http_proxy
        https_proxy = self.https_proxy()
        check_type("https_proxy", https_proxy, Optional[str])
        if https_proxy:  # omit empty
            v["httpsProxy"] = https_proxy
        no_proxy = self.no_proxy()
        check_type("no_proxy", no_proxy, Optional[str])
        if no_proxy:  # omit empty
            v["noProxy"] = no_proxy
        readiness_endpoints = self.readiness_endpoints()
        check_type("readiness_endpoints", readiness_endpoints, Optional[List[str]])
        if readiness_endpoints:  # omit empty
            v["readinessEndpoints"] = readiness_endpoints
        trusted_ca = self.trusted_ca()
        check_type("trusted_ca", trusted_ca, Optional["ConfigMapNameReference"])
        v["trustedCA"] = trusted_ca
        return v

    def http_proxy(self) -> Optional[str]:
        """
        httpProxy is the URL of the proxy for HTTP requests.  Empty means unset and will not result in an env var.
        """
        return self.__http_proxy

    def https_proxy(self) -> Optional[str]:
        """
        httpsProxy is the URL of the proxy for HTTPS requests.  Empty means unset and will not result in an env var.
        """
        return self.__https_proxy

    def no_proxy(self) -> Optional[str]:
        """
        noProxy is a comma-separated list of hostnames and/or CIDRs for which the proxy should not be used.
        Empty means unset and will not result in an env var.
        """
        return self.__no_proxy

    def readiness_endpoints(self) -> Optional[List[str]]:
        """
        readinessEndpoints is a list of endpoints used to verify readiness of the proxy.
        """
        return self.__readiness_endpoints

    def trusted_ca(self) -> Optional["ConfigMapNameReference"]:
        """
        trustedCA is a reference to a ConfigMap containing a CA certificate bundle used
        for client egress HTTPS connections. The certificate bundle must be from the CA
        that signed the proxy's certificate and be signed for everything. The trustedCA
        field should only be consumed by a proxy validator. The validator is responsible
        for reading the certificate bundle from required key "ca-bundle.crt" and copying
        it to a ConfigMap named "trusted-ca-bundle" in the "openshift-config-managed"
        namespace. The namespace for the ConfigMap referenced by trustedCA is
        "openshift-config". Here is an example ConfigMap (in yaml):
        
        apiVersion: v1
        kind: ConfigMap
        metadata:
         name: user-ca-bundle
         namespace: openshift-config
         data:
           ca-bundle.crt: |
             -----BEGIN CERTIFICATE-----
             Custom CA certificate bundle.
             -----END CERTIFICATE-----
        """
        return self.__trusted_ca


class BuildDefaults(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        default_proxy: "ProxySpec" = None,
        git_proxy: "ProxySpec" = None,
        env: List["k8sv1.EnvVar"] = None,
        image_labels: List["ImageLabel"] = None,
        resources: "k8sv1.ResourceRequirements" = None,
    ):
        super().__init__()
        self.__default_proxy = default_proxy
        self.__git_proxy = git_proxy
        self.__env = env if env is not None else []
        self.__image_labels = image_labels if image_labels is not None else []
        self.__resources = (
            resources if resources is not None else k8sv1.ResourceRequirements()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        default_proxy = self.default_proxy()
        check_type("default_proxy", default_proxy, Optional["ProxySpec"])
        if default_proxy is not None:  # omit empty
            v["defaultProxy"] = default_proxy
        git_proxy = self.git_proxy()
        check_type("git_proxy", git_proxy, Optional["ProxySpec"])
        if git_proxy is not None:  # omit empty
            v["gitProxy"] = git_proxy
        env = self.env()
        check_type("env", env, Optional[List["k8sv1.EnvVar"]])
        if env:  # omit empty
            v["env"] = env
        image_labels = self.image_labels()
        check_type("image_labels", image_labels, Optional[List["ImageLabel"]])
        if image_labels:  # omit empty
            v["imageLabels"] = image_labels
        resources = self.resources()
        check_type("resources", resources, "k8sv1.ResourceRequirements")
        v["resources"] = resources
        return v

    def default_proxy(self) -> Optional["ProxySpec"]:
        """
        DefaultProxy contains the default proxy settings for all build operations, including image pull/push
        and source download.
        
        Values can be overrode by setting the `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables
        in the build config's strategy.
        """
        return self.__default_proxy

    def git_proxy(self) -> Optional["ProxySpec"]:
        """
        GitProxy contains the proxy settings for git operations only. If set, this will override
        any Proxy settings for all git commands, such as git clone.
        
        Values that are not set here will be inherited from DefaultProxy.
        """
        return self.__git_proxy

    def env(self) -> Optional[List["k8sv1.EnvVar"]]:
        """
        Env is a set of default environment variables that will be applied to the
        build if the specified variables do not exist on the build
        """
        return self.__env

    def image_labels(self) -> Optional[List["ImageLabel"]]:
        """
        ImageLabels is a list of docker labels that are applied to the resulting image.
        User can override a default label by providing a label with the same name in their
        Build/BuildConfig.
        """
        return self.__image_labels

    def resources(self) -> "k8sv1.ResourceRequirements":
        """
        Resources defines resource requirements to execute the build.
        """
        return self.__resources


class BuildOverrides(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        image_labels: List["ImageLabel"] = None,
        node_selector: Dict[str, str] = None,
        tolerations: List["k8sv1.Toleration"] = None,
    ):
        super().__init__()
        self.__image_labels = image_labels if image_labels is not None else []
        self.__node_selector = node_selector if node_selector is not None else {}
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        image_labels = self.image_labels()
        check_type("image_labels", image_labels, Optional[List["ImageLabel"]])
        if image_labels:  # omit empty
            v["imageLabels"] = image_labels
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional[Dict[str, str]])
        if node_selector:  # omit empty
            v["nodeSelector"] = node_selector
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    def image_labels(self) -> Optional[List["ImageLabel"]]:
        """
        ImageLabels is a list of docker labels that are applied to the resulting image.
        If user provided a label in their Build/BuildConfig with the same name as one in this
        list, the user's label will be overwritten.
        """
        return self.__image_labels

    def node_selector(self) -> Optional[Dict[str, str]]:
        """
        NodeSelector is a selector which must be true for the build pod to fit on a node
        """
        return self.__node_selector

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        Tolerations is a list of Tolerations that will override any existing
        tolerations set on a build pod.
        """
        return self.__tolerations


class BuildSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        build_defaults: "BuildDefaults" = None,
        build_overrides: "BuildOverrides" = None,
    ):
        super().__init__()
        self.__build_defaults = (
            build_defaults if build_defaults is not None else BuildDefaults()
        )
        self.__build_overrides = (
            build_overrides if build_overrides is not None else BuildOverrides()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        build_defaults = self.build_defaults()
        check_type("build_defaults", build_defaults, "BuildDefaults")
        v["buildDefaults"] = build_defaults
        build_overrides = self.build_overrides()
        check_type("build_overrides", build_overrides, "BuildOverrides")
        v["buildOverrides"] = build_overrides
        return v

    def build_defaults(self) -> "BuildDefaults":
        """
        BuildDefaults controls the default information for Builds
        """
        return self.__build_defaults

    def build_overrides(self) -> "BuildOverrides":
        """
        BuildOverrides controls override settings for builds
        """
        return self.__build_overrides


class Build(base.TypedObject, base.MetadataObject):
    """
    Build configures the behavior of OpenShift builds for the entire cluster.
    This includes default settings that can be overridden in BuildConfig objects, and overrides which are applied to all builds.
    
    The canonical name is "cluster"
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "BuildSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="Build",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else BuildSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "BuildSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "BuildSpec":
        """
        Spec holds user-settable values for the build controller configuration
        +required
        """
        return self.__spec


class CertInfo(types.Object):
    """
    CertInfo relates a certificate with a private key
    """

    @context.scoped
    @typechecked
    def __init__(self, cert_file: str = "", key_file: str = ""):
        super().__init__()
        self.__cert_file = cert_file
        self.__key_file = key_file

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cert_file = self.cert_file()
        check_type("cert_file", cert_file, str)
        v["certFile"] = cert_file
        key_file = self.key_file()
        check_type("key_file", key_file, str)
        v["keyFile"] = key_file
        return v

    def cert_file(self) -> str:
        """
        CertFile is a file containing a PEM-encoded certificate
        """
        return self.__cert_file

    def key_file(self) -> str:
        """
        KeyFile is a file containing a PEM-encoded private key for the certificate specified by CertFile
        """
        return self.__key_file


class ClientConnectionOverrides(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        accept_content_types: str = "",
        content_type: str = "",
        qps: float = float("0E+00"),
        burst: int = 0,
    ):
        super().__init__()
        self.__accept_content_types = accept_content_types
        self.__content_type = content_type
        self.__qps = qps
        self.__burst = burst

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        accept_content_types = self.accept_content_types()
        check_type("accept_content_types", accept_content_types, str)
        v["acceptContentTypes"] = accept_content_types
        content_type = self.content_type()
        check_type("content_type", content_type, str)
        v["contentType"] = content_type
        qps = self.qps()
        check_type("qps", qps, float)
        v["qps"] = qps
        burst = self.burst()
        check_type("burst", burst, int)
        v["burst"] = burst
        return v

    def accept_content_types(self) -> str:
        """
        acceptContentTypes defines the Accept header sent by clients when connecting to a server, overriding the
        default value of 'application/json'. This field will control all connections to the server used by a particular
        client.
        """
        return self.__accept_content_types

    def content_type(self) -> str:
        """
        contentType is the content type used when sending data to the server from this client.
        """
        return self.__content_type

    def qps(self) -> float:
        """
        qps controls the number of queries per second allowed for this connection.
        """
        return self.__qps

    def burst(self) -> int:
        """
        burst allows extra queries to accumulate when a client is exceeding its rate.
        """
        return self.__burst


class ClusterNetworkEntry(types.Object):
    """
    ClusterNetworkEntry is a contiguous block of IP addresses from which pod IPs
    are allocated.
    """

    @context.scoped
    @typechecked
    def __init__(self, cidr: str = "", host_prefix: int = 0):
        super().__init__()
        self.__cidr = cidr
        self.__host_prefix = host_prefix

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cidr = self.cidr()
        check_type("cidr", cidr, str)
        v["cidr"] = cidr
        host_prefix = self.host_prefix()
        check_type("host_prefix", host_prefix, int)
        v["hostPrefix"] = host_prefix
        return v

    def cidr(self) -> str:
        """
        The complete block for pod IPs.
        """
        return self.__cidr

    def host_prefix(self) -> int:
        """
        The size (prefix) of block to allocate to each node.
        """
        return self.__host_prefix


class ClusterOperatorSpec(types.Object):
    """
    ClusterOperatorSpec is empty for now, but you could imagine holding information like "pause".
    """

    pass  # FIXME


class ClusterOperator(base.TypedObject, base.MetadataObject):
    """
    ClusterOperator is the Custom Resource object which holds the current state
    of an operator. This object is used by operators to convey their state to
    the rest of the cluster.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ClusterOperatorSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="ClusterOperator",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ClusterOperatorSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ClusterOperatorSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ClusterOperatorSpec":
        """
        spec holds configuration that could apply to any operator.
        +required
        """
        return self.__spec


class ComponentOverride(types.Object):
    """
    ComponentOverride allows overriding cluster version operator's behavior
    for a component.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        kind: str = "",
        group: str = "",
        namespace: str = "",
        name: str = "",
        unmanaged: bool = False,
    ):
        super().__init__()
        self.__kind = kind
        self.__group = group
        self.__namespace = namespace
        self.__name = name
        self.__unmanaged = unmanaged

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        group = self.group()
        check_type("group", group, str)
        v["group"] = group
        namespace = self.namespace()
        check_type("namespace", namespace, str)
        v["namespace"] = namespace
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        unmanaged = self.unmanaged()
        check_type("unmanaged", unmanaged, bool)
        v["unmanaged"] = unmanaged
        return v

    def kind(self) -> str:
        """
        kind indentifies which object to override.
        +required
        """
        return self.__kind

    def group(self) -> str:
        """
        group identifies the API group that the kind is in.
        +required
        """
        return self.__group

    def namespace(self) -> str:
        """
        namespace is the component's namespace. If the resource is cluster
        scoped, the namespace should be empty.
        +required
        """
        return self.__namespace

    def name(self) -> str:
        """
        name is the component's name.
        +required
        """
        return self.__name

    def unmanaged(self) -> bool:
        """
        unmanaged controls if cluster version operator should stop managing the
        resources in this cluster.
        Default: false
        +required
        """
        return self.__unmanaged


class Update(types.Object):
    """
    Update represents a release of the ClusterVersionOperator, referenced by the
    Image member.
    """

    @context.scoped
    @typechecked
    def __init__(self, version: str = "", image: str = "", force: bool = False):
        super().__init__()
        self.__version = version
        self.__image = image
        self.__force = force

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        version = self.version()
        check_type("version", version, str)
        v["version"] = version
        image = self.image()
        check_type("image", image, str)
        v["image"] = image
        force = self.force()
        check_type("force", force, bool)
        v["force"] = force
        return v

    def version(self) -> str:
        """
        version is a semantic versioning identifying the update version. When this
        field is part of spec, version is optional if image is specified.
        """
        return self.__version

    def image(self) -> str:
        """
        image is a container image location that contains the update. When this
        field is part of spec, image is optional if version is specified and the
        availableUpdates field contains a matching version.
        """
        return self.__image

    def force(self) -> bool:
        """
        force allows an administrator to update to an image that has failed
        verification, does not appear in the availableUpdates list, or otherwise
        would be blocked by normal protections on update. This option should only
        be used when the authenticity of the provided image has been verified out
        of band because the provided image will run with full administrative access
        to the cluster. Do not use this flag with images that comes from unknown
        or potentially malicious sources.
        
        This flag does not override other forms of consistency checking that are
        required before a new update is deployed.
        """
        return self.__force


class ClusterVersionSpec(types.Object):
    """
    ClusterVersionSpec is the desired version state of the cluster. It includes
    the version the cluster should be at, how the cluster is identified, and
    where the cluster should look for version updates.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        cluster_id: ClusterID = None,
        desired_update: "Update" = None,
        upstream: URL = None,
        channel: str = None,
        overrides: List["ComponentOverride"] = None,
    ):
        super().__init__()
        self.__cluster_id = cluster_id
        self.__desired_update = desired_update
        self.__upstream = upstream
        self.__channel = channel
        self.__overrides = overrides if overrides is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cluster_id = self.cluster_id()
        check_type("cluster_id", cluster_id, ClusterID)
        v["clusterID"] = cluster_id
        desired_update = self.desired_update()
        check_type("desired_update", desired_update, Optional["Update"])
        if desired_update is not None:  # omit empty
            v["desiredUpdate"] = desired_update
        upstream = self.upstream()
        check_type("upstream", upstream, Optional[URL])
        if upstream:  # omit empty
            v["upstream"] = upstream
        channel = self.channel()
        check_type("channel", channel, Optional[str])
        if channel:  # omit empty
            v["channel"] = channel
        overrides = self.overrides()
        check_type("overrides", overrides, Optional[List["ComponentOverride"]])
        if overrides:  # omit empty
            v["overrides"] = overrides
        return v

    def cluster_id(self) -> ClusterID:
        """
        clusterID uniquely identifies this cluster. This is expected to be
        an RFC4122 UUID value (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx in
        hexadecimal values). This is a required field.
        +required
        """
        return self.__cluster_id

    def desired_update(self) -> Optional["Update"]:
        """
        desiredUpdate is an optional field that indicates the desired value of
        the cluster version. Setting this value will trigger an upgrade (if
        the current version does not match the desired version). The set of
        recommended update values is listed as part of available updates in
        status, and setting values outside that range may cause the upgrade
        to fail. You may specify the version field without setting image if
        an update exists with that version in the availableUpdates or history.
        
        If an upgrade fails the operator will halt and report status
        about the failing component. Setting the desired update value back to
        the previous version will cause a rollback to be attempted. Not all
        rollbacks will succeed.
        """
        return self.__desired_update

    def upstream(self) -> Optional[URL]:
        """
        upstream may be used to specify the preferred update server. By default
        it will use the appropriate update server for the cluster and region.
        """
        return self.__upstream

    def channel(self) -> Optional[str]:
        """
        channel is an identifier for explicitly requesting that a non-default
        set of updates be applied to this cluster. The default channel will be
        contain stable updates that are appropriate for production clusters.
        """
        return self.__channel

    def overrides(self) -> Optional[List["ComponentOverride"]]:
        """
        overrides is list of overides for components that are managed by
        cluster version operator. Marking a component unmanaged will prevent
        the operator from creating or updating the object.
        """
        return self.__overrides


class ClusterVersion(base.TypedObject, base.MetadataObject):
    """
    ClusterVersion is the configuration for the ClusterVersionOperator. This is where
    parameters related to automatic updates can be set.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ClusterVersionSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="ClusterVersion",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ClusterVersionSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ClusterVersionSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ClusterVersionSpec":
        """
        spec is the desired state of the cluster version - the operator will work
        to ensure that the desired version is applied to the cluster.
        +required
        """
        return self.__spec


class ConfigMapFileReference(types.Object):
    """
    ConfigMapFileReference references a config map in a specific namespace.
    The namespace must be specified at the point of use.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", key: str = None):
        super().__init__()
        self.__name = name
        self.__key = key

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        key = self.key()
        check_type("key", key, Optional[str])
        if key:  # omit empty
            v["key"] = key
        return v

    def name(self) -> str:
        return self.__name

    def key(self) -> Optional[str]:
        """
        Key allows pointing to a specific key/value inside of the configmap.  This is useful for logical file references.
        """
        return self.__key


class ConsoleAuthentication(types.Object):
    """
    ConsoleAuthentication defines a list of optional configuration for console authentication.
    """

    @context.scoped
    @typechecked
    def __init__(self, logout_redirect: str = None):
        super().__init__()
        self.__logout_redirect = logout_redirect

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        logout_redirect = self.logout_redirect()
        check_type("logout_redirect", logout_redirect, Optional[str])
        if logout_redirect:  # omit empty
            v["logoutRedirect"] = logout_redirect
        return v

    def logout_redirect(self) -> Optional[str]:
        """
        An optional, absolute URL to redirect web browsers to after logging out of
        the console. If not specified, it will redirect to the default login page.
        This is required when using an identity provider that supports single
        sign-on (SSO) such as:
        - OpenID (Keycloak, Azure)
        - RequestHeader (GSSAPI, SSPI, SAML)
        - OAuth (GitHub, GitLab, Google)
        Logging out of the console will destroy the user's token. The logoutRedirect
        provides the user the option to perform single logout (SLO) through the identity
        provider to destroy their single sign-on session.
        """
        return self.__logout_redirect


class ConsoleSpec(types.Object):
    """
    ConsoleSpec is the specification of the desired behavior of the Console.
    """

    @context.scoped
    @typechecked
    def __init__(self, authentication: "ConsoleAuthentication" = None):
        super().__init__()
        self.__authentication = (
            authentication if authentication is not None else ConsoleAuthentication()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        authentication = self.authentication()
        check_type("authentication", authentication, "ConsoleAuthentication")
        v["authentication"] = authentication
        return v

    def authentication(self) -> "ConsoleAuthentication":
        return self.__authentication


class Console(base.TypedObject, base.MetadataObject):
    """
    Console holds cluster-wide configuration for the web console, including the
    logout URL, and reports the public URL of the console. The canonical name is
    `cluster`.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ConsoleSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="Console",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ConsoleSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ConsoleSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ConsoleSpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class CustomFeatureGates(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, enabled: List[str] = None, disabled: List[str] = None):
        super().__init__()
        self.__enabled = enabled if enabled is not None else []
        self.__disabled = disabled if disabled is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        enabled = self.enabled()
        check_type("enabled", enabled, Optional[List[str]])
        if enabled:  # omit empty
            v["enabled"] = enabled
        disabled = self.disabled()
        check_type("disabled", disabled, Optional[List[str]])
        if disabled:  # omit empty
            v["disabled"] = disabled
        return v

    def enabled(self) -> Optional[List[str]]:
        """
        enabled is a list of all feature gates that you want to force on
        """
        return self.__enabled

    def disabled(self) -> Optional[List[str]]:
        """
        disabled is a list of all feature gates that you want to force off
        """
        return self.__disabled


class DNSZone(types.Object):
    """
    DNSZone is used to define a DNS hosted zone.
    A zone can be identified by an ID or tags.
    """

    @context.scoped
    @typechecked
    def __init__(self, id: str = None, tags: Dict[str, str] = None):
        super().__init__()
        self.__id = id
        self.__tags = tags if tags is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        id = self.id()
        check_type("id", id, Optional[str])
        if id:  # omit empty
            v["id"] = id
        tags = self.tags()
        check_type("tags", tags, Optional[Dict[str, str]])
        if tags:  # omit empty
            v["tags"] = tags
        return v

    def id(self) -> Optional[str]:
        """
        id is the identifier that can be used to find the DNS hosted zone.
        
        on AWS zone can be fetched using `ID` as id in [1]
        on Azure zone can be fetched using `ID` as a pre-determined name in [2],
        on GCP zone can be fetched using `ID` as a pre-determined name in [3].
        
        [1]: https://docs.aws.amazon.com/cli/latest/reference/route53/get-hosted-zone.html#options
        [2]: https://docs.microsoft.com/en-us/cli/azure/network/dns/zone?view=azure-cli-latest#az-network-dns-zone-show
        [3]: https://cloud.google.com/dns/docs/reference/v1/managedZones/get
        """
        return self.__id

    def tags(self) -> Optional[Dict[str, str]]:
        """
        tags can be used to query the DNS hosted zone.
        
        on AWS, resourcegroupstaggingapi [1] can be used to fetch a zone using `Tags` as tag-filters,
        
        [1]: https://docs.aws.amazon.com/cli/latest/reference/resourcegroupstaggingapi/get-resources.html#options
        """
        return self.__tags


class DNSSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        base_domain: str = "",
        public_zone: "DNSZone" = None,
        private_zone: "DNSZone" = None,
    ):
        super().__init__()
        self.__base_domain = base_domain
        self.__public_zone = public_zone
        self.__private_zone = private_zone

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        base_domain = self.base_domain()
        check_type("base_domain", base_domain, str)
        v["baseDomain"] = base_domain
        public_zone = self.public_zone()
        check_type("public_zone", public_zone, Optional["DNSZone"])
        if public_zone is not None:  # omit empty
            v["publicZone"] = public_zone
        private_zone = self.private_zone()
        check_type("private_zone", private_zone, Optional["DNSZone"])
        if private_zone is not None:  # omit empty
            v["privateZone"] = private_zone
        return v

    def base_domain(self) -> str:
        """
        baseDomain is the base domain of the cluster. All managed DNS records will
        be sub-domains of this base.
        
        For example, given the base domain `openshift.example.com`, an API server
        DNS record may be created for `cluster-api.openshift.example.com`.
        
        Once set, this field cannot be changed.
        """
        return self.__base_domain

    def public_zone(self) -> Optional["DNSZone"]:
        """
        publicZone is the location where all the DNS records that are publicly accessible to
        the internet exist.
        
        If this field is nil, no public records should be created.
        
        Once set, this field cannot be changed.
        """
        return self.__public_zone

    def private_zone(self) -> Optional["DNSZone"]:
        """
        privateZone is the location where all the DNS records that are only available internally
        to the cluster exist.
        
        If this field is nil, no private records should be created.
        
        Once set, this field cannot be changed.
        """
        return self.__private_zone


class DNS(base.TypedObject, base.MetadataObject):
    """
    DNS holds cluster-wide information about DNS. The canonical name is `cluster`
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "DNSSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="DNS",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else DNSSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "DNSSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "DNSSpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class EtcdConnectionInfo(types.Object):
    """
    EtcdConnectionInfo holds information necessary for connecting to an etcd server
    """

    @context.scoped
    @typechecked
    def __init__(
        self, urls: List[str] = None, ca: str = "", cert_info: "CertInfo" = None
    ):
        super().__init__()
        self.__urls = urls if urls is not None else []
        self.__ca = ca
        self.__cert_info = cert_info if cert_info is not None else CertInfo()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        urls = self.urls()
        check_type("urls", urls, Optional[List[str]])
        if urls:  # omit empty
            v["urls"] = urls
        ca = self.ca()
        check_type("ca", ca, str)
        v["ca"] = ca
        cert_info = self.cert_info()
        check_type("cert_info", cert_info, "CertInfo")
        v.update(cert_info._root())  # inline
        return v

    def urls(self) -> Optional[List[str]]:
        """
        URLs are the URLs for etcd
        """
        return self.__urls

    def ca(self) -> str:
        """
        CA is a file containing trusted roots for the etcd server certificates
        """
        return self.__ca

    def cert_info(self) -> "CertInfo":
        """
        CertInfo is the TLS client cert information for securing communication to etcd
        this is anonymous so that we can inline it for serialization
        """
        return self.__cert_info


class EtcdStorageConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        etcd_connection_info: "EtcdConnectionInfo" = None,
        storage_prefix: str = "",
    ):
        super().__init__()
        self.__etcd_connection_info = (
            etcd_connection_info
            if etcd_connection_info is not None
            else EtcdConnectionInfo()
        )
        self.__storage_prefix = storage_prefix

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        etcd_connection_info = self.etcd_connection_info()
        check_type("etcd_connection_info", etcd_connection_info, "EtcdConnectionInfo")
        v.update(etcd_connection_info._root())  # inline
        storage_prefix = self.storage_prefix()
        check_type("storage_prefix", storage_prefix, str)
        v["storagePrefix"] = storage_prefix
        return v

    def etcd_connection_info(self) -> "EtcdConnectionInfo":
        return self.__etcd_connection_info

    def storage_prefix(self) -> str:
        """
        StoragePrefix is the path within etcd that the OpenShift resources will
        be rooted under. This value, if changed, will mean existing objects in etcd will
        no longer be located.
        """
        return self.__storage_prefix


class ExternalIPPolicy(types.Object):
    """
    ExternalIPPolicy configures exactly which IPs are allowed for the ExternalIP
    field in a Service. If the zero struct is supplied, then none are permitted.
    The policy controller always allows automatically assigned external IPs.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, allowed_cidrs: List[str] = None, rejected_cidrs: List[str] = None
    ):
        super().__init__()
        self.__allowed_cidrs = allowed_cidrs if allowed_cidrs is not None else []
        self.__rejected_cidrs = rejected_cidrs if rejected_cidrs is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        allowed_cidrs = self.allowed_cidrs()
        check_type("allowed_cidrs", allowed_cidrs, Optional[List[str]])
        if allowed_cidrs:  # omit empty
            v["allowedCIDRs"] = allowed_cidrs
        rejected_cidrs = self.rejected_cidrs()
        check_type("rejected_cidrs", rejected_cidrs, Optional[List[str]])
        if rejected_cidrs:  # omit empty
            v["rejectedCIDRs"] = rejected_cidrs
        return v

    def allowed_cidrs(self) -> Optional[List[str]]:
        """
        allowedCIDRs is the list of allowed CIDRs.
        """
        return self.__allowed_cidrs

    def rejected_cidrs(self) -> Optional[List[str]]:
        """
        rejectedCIDRs is the list of disallowed CIDRs. These take precedence
        over allowedCIDRs.
        """
        return self.__rejected_cidrs


class ExternalIPConfig(types.Object):
    """
    ExternalIPConfig specifies some IP blocks relevant for the ExternalIP field
    of a Service resource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, policy: "ExternalIPPolicy" = None, auto_assign_cidrs: List[str] = None
    ):
        super().__init__()
        self.__policy = policy
        self.__auto_assign_cidrs = (
            auto_assign_cidrs if auto_assign_cidrs is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        policy = self.policy()
        check_type("policy", policy, Optional["ExternalIPPolicy"])
        if policy is not None:  # omit empty
            v["policy"] = policy
        auto_assign_cidrs = self.auto_assign_cidrs()
        check_type("auto_assign_cidrs", auto_assign_cidrs, Optional[List[str]])
        if auto_assign_cidrs:  # omit empty
            v["autoAssignCIDRs"] = auto_assign_cidrs
        return v

    def policy(self) -> Optional["ExternalIPPolicy"]:
        """
        policy is a set of restrictions applied to the ExternalIP field.
        If nil or empty, then ExternalIP is not allowed to be set.
        """
        return self.__policy

    def auto_assign_cidrs(self) -> Optional[List[str]]:
        """
        autoAssignCIDRs is a list of CIDRs from which to automatically assign
        Service.ExternalIP. These are assigned when the service is of type
        LoadBalancer. In general, this is only useful for bare-metal clusters.
        In Openshift 3.x, this was misleadingly called "IngressIPs".
        Automatically assigned External IPs are not affected by any
        ExternalIPPolicy rules.
        Currently, only one entry may be provided.
        """
        return self.__auto_assign_cidrs


class FeatureGateSelection(types.Object):
    """
    +union
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        feature_set: FeatureSet = None,
        custom_no_upgrade: "CustomFeatureGates" = None,
    ):
        super().__init__()
        self.__feature_set = feature_set
        self.__custom_no_upgrade = custom_no_upgrade

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        feature_set = self.feature_set()
        check_type("feature_set", feature_set, Optional[FeatureSet])
        if feature_set:  # omit empty
            v["featureSet"] = feature_set
        custom_no_upgrade = self.custom_no_upgrade()
        check_type(
            "custom_no_upgrade", custom_no_upgrade, Optional["CustomFeatureGates"]
        )
        if custom_no_upgrade is not None:  # omit empty
            v["customNoUpgrade"] = custom_no_upgrade
        return v

    def feature_set(self) -> Optional[FeatureSet]:
        """
        featureSet changes the list of features in the cluster.  The default is empty.  Be very careful adjusting this setting.
        Turning on or off features may cause irreversible changes in your cluster which cannot be undone.
        +unionDiscriminator
        """
        return self.__feature_set

    def custom_no_upgrade(self) -> Optional["CustomFeatureGates"]:
        """
        customNoUpgrade allows the enabling or disabling of any feature. Turning this feature set on IS NOT SUPPORTED, CANNOT BE UNDONE, and PREVENTS UPGRADES.
        Because of its nature, this setting cannot be validated.  If you have any typos or accidentally apply invalid combinations
        your cluster may fail in an unrecoverable way.  featureSet must equal "CustomNoUpgrade" must be set to use this field.
        +nullable
        """
        return self.__custom_no_upgrade


class FeatureGateSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, feature_gate_selection: "FeatureGateSelection" = None):
        super().__init__()
        self.__feature_gate_selection = (
            feature_gate_selection
            if feature_gate_selection is not None
            else FeatureGateSelection()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        feature_gate_selection = self.feature_gate_selection()
        check_type(
            "feature_gate_selection", feature_gate_selection, "FeatureGateSelection"
        )
        v.update(feature_gate_selection._root())  # inline
        return v

    def feature_gate_selection(self) -> "FeatureGateSelection":
        return self.__feature_gate_selection


class FeatureGate(base.TypedObject, base.MetadataObject):
    """
    Feature holds cluster-wide information about feature gates.  The canonical name is `cluster`
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "FeatureGateSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="FeatureGate",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else FeatureGateSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "FeatureGateSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "FeatureGateSpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class NamedCertificate(types.Object):
    """
    NamedCertificate specifies a certificate/key, and the names it should be served for
    """

    @context.scoped
    @typechecked
    def __init__(self, names: List[str] = None, cert_info: "CertInfo" = None):
        super().__init__()
        self.__names = names if names is not None else []
        self.__cert_info = cert_info if cert_info is not None else CertInfo()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        names = self.names()
        check_type("names", names, Optional[List[str]])
        if names:  # omit empty
            v["names"] = names
        cert_info = self.cert_info()
        check_type("cert_info", cert_info, "CertInfo")
        v.update(cert_info._root())  # inline
        return v

    def names(self) -> Optional[List[str]]:
        """
        Names is a list of DNS names this certificate should be used to secure
        A name can be a normal DNS name, or can contain leading wildcard segments.
        """
        return self.__names

    def cert_info(self) -> "CertInfo":
        """
        CertInfo is the TLS cert info for serving secure traffic
        """
        return self.__cert_info


class ServingInfo(types.Object):
    """
    ServingInfo holds information about serving web pages
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        bind_address: str = "",
        bind_network: str = "",
        cert_info: "CertInfo" = None,
        client_ca: str = None,
        named_certificates: List["NamedCertificate"] = None,
        min_tls_version: str = None,
        cipher_suites: List[str] = None,
    ):
        super().__init__()
        self.__bind_address = bind_address
        self.__bind_network = bind_network
        self.__cert_info = cert_info if cert_info is not None else CertInfo()
        self.__client_ca = client_ca
        self.__named_certificates = (
            named_certificates if named_certificates is not None else []
        )
        self.__min_tls_version = min_tls_version
        self.__cipher_suites = cipher_suites if cipher_suites is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        bind_address = self.bind_address()
        check_type("bind_address", bind_address, str)
        v["bindAddress"] = bind_address
        bind_network = self.bind_network()
        check_type("bind_network", bind_network, str)
        v["bindNetwork"] = bind_network
        cert_info = self.cert_info()
        check_type("cert_info", cert_info, "CertInfo")
        v.update(cert_info._root())  # inline
        client_ca = self.client_ca()
        check_type("client_ca", client_ca, Optional[str])
        if client_ca:  # omit empty
            v["clientCA"] = client_ca
        named_certificates = self.named_certificates()
        check_type(
            "named_certificates", named_certificates, Optional[List["NamedCertificate"]]
        )
        if named_certificates:  # omit empty
            v["namedCertificates"] = named_certificates
        min_tls_version = self.min_tls_version()
        check_type("min_tls_version", min_tls_version, Optional[str])
        if min_tls_version:  # omit empty
            v["minTLSVersion"] = min_tls_version
        cipher_suites = self.cipher_suites()
        check_type("cipher_suites", cipher_suites, Optional[List[str]])
        if cipher_suites:  # omit empty
            v["cipherSuites"] = cipher_suites
        return v

    def bind_address(self) -> str:
        """
        BindAddress is the ip:port to serve on
        """
        return self.__bind_address

    def bind_network(self) -> str:
        """
        BindNetwork is the type of network to bind to - defaults to "tcp4", accepts "tcp",
        "tcp4", and "tcp6"
        """
        return self.__bind_network

    def cert_info(self) -> "CertInfo":
        """
        CertInfo is the TLS cert info for serving secure traffic.
        this is anonymous so that we can inline it for serialization
        """
        return self.__cert_info

    def client_ca(self) -> Optional[str]:
        """
        ClientCA is the certificate bundle for all the signers that you'll recognize for incoming client certificates
        """
        return self.__client_ca

    def named_certificates(self) -> Optional[List["NamedCertificate"]]:
        """
        NamedCertificates is a list of certificates to use to secure requests to specific hostnames
        """
        return self.__named_certificates

    def min_tls_version(self) -> Optional[str]:
        """
        MinTLSVersion is the minimum TLS version supported.
        Values must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants
        """
        return self.__min_tls_version

    def cipher_suites(self) -> Optional[List[str]]:
        """
        CipherSuites contains an overridden list of ciphers for the server to support.
        Values must match cipher suite IDs from https://golang.org/pkg/crypto/tls/#pkg-constants
        """
        return self.__cipher_suites


class HTTPServingInfo(types.Object):
    """
    HTTPServingInfo holds configuration for serving HTTP
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        serving_info: "ServingInfo" = None,
        max_requests_in_flight: int = 0,
        request_timeout_seconds: int = 0,
    ):
        super().__init__()
        self.__serving_info = (
            serving_info if serving_info is not None else ServingInfo()
        )
        self.__max_requests_in_flight = max_requests_in_flight
        self.__request_timeout_seconds = request_timeout_seconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        serving_info = self.serving_info()
        check_type("serving_info", serving_info, "ServingInfo")
        v.update(serving_info._root())  # inline
        max_requests_in_flight = self.max_requests_in_flight()
        check_type("max_requests_in_flight", max_requests_in_flight, int)
        v["maxRequestsInFlight"] = max_requests_in_flight
        request_timeout_seconds = self.request_timeout_seconds()
        check_type("request_timeout_seconds", request_timeout_seconds, int)
        v["requestTimeoutSeconds"] = request_timeout_seconds
        return v

    def serving_info(self) -> "ServingInfo":
        """
        ServingInfo is the HTTP serving information
        """
        return self.__serving_info

    def max_requests_in_flight(self) -> int:
        """
        MaxRequestsInFlight is the number of concurrent requests allowed to the server. If zero, no limit.
        """
        return self.__max_requests_in_flight

    def request_timeout_seconds(self) -> int:
        """
        RequestTimeoutSeconds is the number of seconds before requests are timed out. The default is 60 minutes, if
        -1 there is no limit on requests.
        """
        return self.__request_timeout_seconds


class KubeClientConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        kube_config: str = "",
        connection_overrides: "ClientConnectionOverrides" = None,
    ):
        super().__init__()
        self.__kube_config = kube_config
        self.__connection_overrides = (
            connection_overrides
            if connection_overrides is not None
            else ClientConnectionOverrides()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kube_config = self.kube_config()
        check_type("kube_config", kube_config, str)
        v["kubeConfig"] = kube_config
        connection_overrides = self.connection_overrides()
        check_type(
            "connection_overrides", connection_overrides, "ClientConnectionOverrides"
        )
        v["connectionOverrides"] = connection_overrides
        return v

    def kube_config(self) -> str:
        """
        kubeConfig is a .kubeconfig filename for going to the owning kube-apiserver.  Empty uses an in-cluster-config
        """
        return self.__kube_config

    def connection_overrides(self) -> "ClientConnectionOverrides":
        """
        connectionOverrides specifies client overrides for system components to loop back to this master.
        """
        return self.__connection_overrides


class GenericAPIServerConfig(types.Object):
    """
    GenericAPIServerConfig is an inline-able struct for aggregated apiservers that need to store data in etcd
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        serving_info: "HTTPServingInfo" = None,
        cors_allowed_origins: List[str] = None,
        audit_config: "AuditConfig" = None,
        storage_config: "EtcdStorageConfig" = None,
        admission: "AdmissionConfig" = None,
        kube_client_config: "KubeClientConfig" = None,
    ):
        super().__init__()
        self.__serving_info = (
            serving_info if serving_info is not None else HTTPServingInfo()
        )
        self.__cors_allowed_origins = (
            cors_allowed_origins if cors_allowed_origins is not None else []
        )
        self.__audit_config = (
            audit_config if audit_config is not None else AuditConfig()
        )
        self.__storage_config = (
            storage_config if storage_config is not None else EtcdStorageConfig()
        )
        self.__admission = admission if admission is not None else AdmissionConfig()
        self.__kube_client_config = (
            kube_client_config if kube_client_config is not None else KubeClientConfig()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        serving_info = self.serving_info()
        check_type("serving_info", serving_info, "HTTPServingInfo")
        v["servingInfo"] = serving_info
        cors_allowed_origins = self.cors_allowed_origins()
        check_type("cors_allowed_origins", cors_allowed_origins, List[str])
        v["corsAllowedOrigins"] = cors_allowed_origins
        audit_config = self.audit_config()
        check_type("audit_config", audit_config, "AuditConfig")
        v["auditConfig"] = audit_config
        storage_config = self.storage_config()
        check_type("storage_config", storage_config, "EtcdStorageConfig")
        v["storageConfig"] = storage_config
        admission = self.admission()
        check_type("admission", admission, "AdmissionConfig")
        v["admission"] = admission
        kube_client_config = self.kube_client_config()
        check_type("kube_client_config", kube_client_config, "KubeClientConfig")
        v["kubeClientConfig"] = kube_client_config
        return v

    def serving_info(self) -> "HTTPServingInfo":
        """
        servingInfo describes how to start serving
        """
        return self.__serving_info

    def cors_allowed_origins(self) -> List[str]:
        """
        corsAllowedOrigins
        """
        return self.__cors_allowed_origins

    def audit_config(self) -> "AuditConfig":
        """
        auditConfig describes how to configure audit information
        """
        return self.__audit_config

    def storage_config(self) -> "EtcdStorageConfig":
        """
        storageConfig contains information about how to use
        """
        return self.__storage_config

    def admission(self) -> "AdmissionConfig":
        """
        admissionConfig holds information about how to configure admission.
        """
        return self.__admission

    def kube_client_config(self) -> "KubeClientConfig":
        return self.__kube_client_config


class GitHubIdentityProvider(types.Object):
    """
    GitHubIdentityProvider provides identities for users authenticating using GitHub credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        client_id: str = "",
        client_secret: "SecretNameReference" = None,
        organizations: List[str] = None,
        teams: List[str] = None,
        hostname: str = "",
        ca: "ConfigMapNameReference" = None,
    ):
        super().__init__()
        self.__client_id = client_id
        self.__client_secret = (
            client_secret if client_secret is not None else SecretNameReference()
        )
        self.__organizations = organizations if organizations is not None else []
        self.__teams = teams if teams is not None else []
        self.__hostname = hostname
        self.__ca = ca if ca is not None else ConfigMapNameReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_id = self.client_id()
        check_type("client_id", client_id, str)
        v["clientID"] = client_id
        client_secret = self.client_secret()
        check_type("client_secret", client_secret, "SecretNameReference")
        v["clientSecret"] = client_secret
        organizations = self.organizations()
        check_type("organizations", organizations, Optional[List[str]])
        if organizations:  # omit empty
            v["organizations"] = organizations
        teams = self.teams()
        check_type("teams", teams, Optional[List[str]])
        if teams:  # omit empty
            v["teams"] = teams
        hostname = self.hostname()
        check_type("hostname", hostname, str)
        v["hostname"] = hostname
        ca = self.ca()
        check_type("ca", ca, "ConfigMapNameReference")
        v["ca"] = ca
        return v

    def client_id(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__client_id

    def client_secret(self) -> "SecretNameReference":
        """
        clientSecret is a required reference to the secret by name containing the oauth client secret.
        The key "clientSecret" is used to locate the data.
        If the secret or expected key is not found, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__client_secret

    def organizations(self) -> Optional[List[str]]:
        """
        organizations optionally restricts which organizations are allowed to log in
        """
        return self.__organizations

    def teams(self) -> Optional[List[str]]:
        """
        teams optionally restricts which teams are allowed to log in. Format is <org>/<team>.
        """
        return self.__teams

    def hostname(self) -> str:
        """
        hostname is the optional domain (e.g. "mycompany.com") for use with a hosted instance of
        GitHub Enterprise.
        It must match the GitHub Enterprise settings value configured at /setup/settings#hostname.
        """
        return self.__hostname

    def ca(self) -> "ConfigMapNameReference":
        """
        ca is an optional reference to a config map by name containing the PEM-encoded CA bundle.
        It is used as a trust anchor to validate the TLS certificate presented by the remote server.
        The key "ca.crt" is used to locate the data.
        If specified and the config map or expected key is not found, the identity provider is not honored.
        If the specified ca data is not valid, the identity provider is not honored.
        If empty, the default system roots are used.
        This can only be configured when hostname is set to a non-empty value.
        The namespace for this config map is openshift-config.
        """
        return self.__ca


class GitLabIdentityProvider(types.Object):
    """
    GitLabIdentityProvider provides identities for users authenticating using GitLab credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        client_id: str = "",
        client_secret: "SecretNameReference" = None,
        url: str = "",
        ca: "ConfigMapNameReference" = None,
    ):
        super().__init__()
        self.__client_id = client_id
        self.__client_secret = (
            client_secret if client_secret is not None else SecretNameReference()
        )
        self.__url = url
        self.__ca = ca if ca is not None else ConfigMapNameReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_id = self.client_id()
        check_type("client_id", client_id, str)
        v["clientID"] = client_id
        client_secret = self.client_secret()
        check_type("client_secret", client_secret, "SecretNameReference")
        v["clientSecret"] = client_secret
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        ca = self.ca()
        check_type("ca", ca, "ConfigMapNameReference")
        v["ca"] = ca
        return v

    def client_id(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__client_id

    def client_secret(self) -> "SecretNameReference":
        """
        clientSecret is a required reference to the secret by name containing the oauth client secret.
        The key "clientSecret" is used to locate the data.
        If the secret or expected key is not found, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__client_secret

    def url(self) -> str:
        """
        url is the oauth server base URL
        """
        return self.__url

    def ca(self) -> "ConfigMapNameReference":
        """
        ca is an optional reference to a config map by name containing the PEM-encoded CA bundle.
        It is used as a trust anchor to validate the TLS certificate presented by the remote server.
        The key "ca.crt" is used to locate the data.
        If specified and the config map or expected key is not found, the identity provider is not honored.
        If the specified ca data is not valid, the identity provider is not honored.
        If empty, the default system roots are used.
        The namespace for this config map is openshift-config.
        """
        return self.__ca


class GoogleIdentityProvider(types.Object):
    """
    GoogleIdentityProvider provides identities for users authenticating using Google credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        client_id: str = "",
        client_secret: "SecretNameReference" = None,
        hosted_domain: str = "",
    ):
        super().__init__()
        self.__client_id = client_id
        self.__client_secret = (
            client_secret if client_secret is not None else SecretNameReference()
        )
        self.__hosted_domain = hosted_domain

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_id = self.client_id()
        check_type("client_id", client_id, str)
        v["clientID"] = client_id
        client_secret = self.client_secret()
        check_type("client_secret", client_secret, "SecretNameReference")
        v["clientSecret"] = client_secret
        hosted_domain = self.hosted_domain()
        check_type("hosted_domain", hosted_domain, str)
        v["hostedDomain"] = hosted_domain
        return v

    def client_id(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__client_id

    def client_secret(self) -> "SecretNameReference":
        """
        clientSecret is a required reference to the secret by name containing the oauth client secret.
        The key "clientSecret" is used to locate the data.
        If the secret or expected key is not found, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__client_secret

    def hosted_domain(self) -> str:
        """
        hostedDomain is the optional Google App domain (e.g. "mycompany.com") to restrict logins to
        """
        return self.__hosted_domain


class HTPasswdIdentityProvider(types.Object):
    """
    HTPasswdPasswordIdentityProvider provides identities for users authenticating using htpasswd credentials
    """

    @context.scoped
    @typechecked
    def __init__(self, file_data: "SecretNameReference" = None):
        super().__init__()
        self.__file_data = file_data if file_data is not None else SecretNameReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        file_data = self.file_data()
        check_type("file_data", file_data, "SecretNameReference")
        v["fileData"] = file_data
        return v

    def file_data(self) -> "SecretNameReference":
        """
        fileData is a required reference to a secret by name containing the data to use as the htpasswd file.
        The key "htpasswd" is used to locate the data.
        If the secret or expected key is not found, the identity provider is not honored.
        If the specified htpasswd data is not valid, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__file_data


class HubSource(types.Object):
    """
    HubSource is used to specify the hub source and its configuration
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", disabled: bool = False):
        super().__init__()
        self.__name = name
        self.__disabled = disabled

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        disabled = self.disabled()
        check_type("disabled", disabled, bool)
        v["disabled"] = disabled
        return v

    def name(self) -> str:
        """
        name is the name of one of the default hub sources
        """
        return self.__name

    def disabled(self) -> bool:
        """
        disabled is used to disable a default hub source on cluster
        """
        return self.__disabled


class KeystoneIdentityProvider(types.Object):
    """
    KeystonePasswordIdentityProvider provides identities for users authenticating using keystone password credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        oauth_remote_connection_info: "OAuthRemoteConnectionInfo" = None,
        domain_name: str = "",
    ):
        super().__init__()
        self.__oauth_remote_connection_info = (
            oauth_remote_connection_info
            if oauth_remote_connection_info is not None
            else OAuthRemoteConnectionInfo()
        )
        self.__domain_name = domain_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        oauth_remote_connection_info = self.oauth_remote_connection_info()
        check_type(
            "oauth_remote_connection_info",
            oauth_remote_connection_info,
            "OAuthRemoteConnectionInfo",
        )
        v.update(oauth_remote_connection_info._root())  # inline
        domain_name = self.domain_name()
        check_type("domain_name", domain_name, str)
        v["domainName"] = domain_name
        return v

    def oauth_remote_connection_info(self) -> "OAuthRemoteConnectionInfo":
        """
        OAuthRemoteConnectionInfo contains information about how to connect to the keystone server
        """
        return self.__oauth_remote_connection_info

    def domain_name(self) -> str:
        """
        domainName is required for keystone v3
        """
        return self.__domain_name


class LDAPAttributeMapping(types.Object):
    """
    LDAPAttributeMapping maps LDAP attributes to OpenShift identity fields
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        id: List[str] = None,
        preferred_username: List[str] = None,
        name: List[str] = None,
        email: List[str] = None,
    ):
        super().__init__()
        self.__id = id if id is not None else []
        self.__preferred_username = (
            preferred_username if preferred_username is not None else []
        )
        self.__name = name if name is not None else []
        self.__email = email if email is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        id = self.id()
        check_type("id", id, List[str])
        v["id"] = id
        preferred_username = self.preferred_username()
        check_type("preferred_username", preferred_username, Optional[List[str]])
        if preferred_username:  # omit empty
            v["preferredUsername"] = preferred_username
        name = self.name()
        check_type("name", name, Optional[List[str]])
        if name:  # omit empty
            v["name"] = name
        email = self.email()
        check_type("email", email, Optional[List[str]])
        if email:  # omit empty
            v["email"] = email
        return v

    def id(self) -> List[str]:
        """
        id is the list of attributes whose values should be used as the user ID. Required.
        First non-empty attribute is used. At least one attribute is required. If none of the listed
        attribute have a value, authentication fails.
        LDAP standard identity attribute is "dn"
        """
        return self.__id

    def preferred_username(self) -> Optional[List[str]]:
        """
        preferredUsername is the list of attributes whose values should be used as the preferred username.
        LDAP standard login attribute is "uid"
        """
        return self.__preferred_username

    def name(self) -> Optional[List[str]]:
        """
        name is the list of attributes whose values should be used as the display name. Optional.
        If unspecified, no display name is set for the identity
        LDAP standard display name attribute is "cn"
        """
        return self.__name

    def email(self) -> Optional[List[str]]:
        """
        email is the list of attributes whose values should be used as the email address. Optional.
        If unspecified, no email is set for the identity
        """
        return self.__email


class LDAPIdentityProvider(types.Object):
    """
    LDAPPasswordIdentityProvider provides identities for users authenticating using LDAP credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = "",
        bind_dn: str = "",
        bind_password: "SecretNameReference" = None,
        insecure: bool = False,
        ca: "ConfigMapNameReference" = None,
        attributes: "LDAPAttributeMapping" = None,
    ):
        super().__init__()
        self.__url = url
        self.__bind_dn = bind_dn
        self.__bind_password = (
            bind_password if bind_password is not None else SecretNameReference()
        )
        self.__insecure = insecure
        self.__ca = ca if ca is not None else ConfigMapNameReference()
        self.__attributes = (
            attributes if attributes is not None else LDAPAttributeMapping()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        bind_dn = self.bind_dn()
        check_type("bind_dn", bind_dn, str)
        v["bindDN"] = bind_dn
        bind_password = self.bind_password()
        check_type("bind_password", bind_password, "SecretNameReference")
        v["bindPassword"] = bind_password
        insecure = self.insecure()
        check_type("insecure", insecure, bool)
        v["insecure"] = insecure
        ca = self.ca()
        check_type("ca", ca, "ConfigMapNameReference")
        v["ca"] = ca
        attributes = self.attributes()
        check_type("attributes", attributes, "LDAPAttributeMapping")
        v["attributes"] = attributes
        return v

    def url(self) -> str:
        """
        url is an RFC 2255 URL which specifies the LDAP search parameters to use.
        The syntax of the URL is:
        ldap://host:port/basedn?attribute?scope?filter
        """
        return self.__url

    def bind_dn(self) -> str:
        """
        bindDN is an optional DN to bind with during the search phase.
        """
        return self.__bind_dn

    def bind_password(self) -> "SecretNameReference":
        """
        bindPassword is an optional reference to a secret by name
        containing a password to bind with during the search phase.
        The key "bindPassword" is used to locate the data.
        If specified and the secret or expected key is not found, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__bind_password

    def insecure(self) -> bool:
        """
        insecure, if true, indicates the connection should not use TLS
        WARNING: Should not be set to `true` with the URL scheme "ldaps://" as "ldaps://" URLs always
                 attempt to connect using TLS, even when `insecure` is set to `true`
        When `true`, "ldap://" URLS connect insecurely. When `false`, "ldap://" URLs are upgraded to
        a TLS connection using StartTLS as specified in https://tools.ietf.org/html/rfc2830.
        """
        return self.__insecure

    def ca(self) -> "ConfigMapNameReference":
        """
        ca is an optional reference to a config map by name containing the PEM-encoded CA bundle.
        It is used as a trust anchor to validate the TLS certificate presented by the remote server.
        The key "ca.crt" is used to locate the data.
        If specified and the config map or expected key is not found, the identity provider is not honored.
        If the specified ca data is not valid, the identity provider is not honored.
        If empty, the default system roots are used.
        The namespace for this config map is openshift-config.
        """
        return self.__ca

    def attributes(self) -> "LDAPAttributeMapping":
        """
        attributes maps LDAP attributes to identities
        """
        return self.__attributes


class OpenIDClaims(types.Object):
    """
    OpenIDClaims contains a list of OpenID claims to use when authenticating with an OpenID identity provider
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        preferred_username: List[str] = None,
        name: List[str] = None,
        email: List[str] = None,
    ):
        super().__init__()
        self.__preferred_username = (
            preferred_username if preferred_username is not None else []
        )
        self.__name = name if name is not None else []
        self.__email = email if email is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        preferred_username = self.preferred_username()
        check_type("preferred_username", preferred_username, Optional[List[str]])
        if preferred_username:  # omit empty
            v["preferredUsername"] = preferred_username
        name = self.name()
        check_type("name", name, Optional[List[str]])
        if name:  # omit empty
            v["name"] = name
        email = self.email()
        check_type("email", email, Optional[List[str]])
        if email:  # omit empty
            v["email"] = email
        return v

    def preferred_username(self) -> Optional[List[str]]:
        """
        preferredUsername is the list of claims whose values should be used as the preferred username.
        If unspecified, the preferred username is determined from the value of the sub claim
        """
        return self.__preferred_username

    def name(self) -> Optional[List[str]]:
        """
        name is the list of claims whose values should be used as the display name. Optional.
        If unspecified, no display name is set for the identity
        """
        return self.__name

    def email(self) -> Optional[List[str]]:
        """
        email is the list of claims whose values should be used as the email address. Optional.
        If unspecified, no email is set for the identity
        """
        return self.__email


class OpenIDIdentityProvider(types.Object):
    """
    OpenIDIdentityProvider provides identities for users authenticating using OpenID credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        client_id: str = "",
        client_secret: "SecretNameReference" = None,
        ca: "ConfigMapNameReference" = None,
        extra_scopes: List[str] = None,
        extra_authorize_parameters: Dict[str, str] = None,
        issuer: str = "",
        claims: "OpenIDClaims" = None,
    ):
        super().__init__()
        self.__client_id = client_id
        self.__client_secret = (
            client_secret if client_secret is not None else SecretNameReference()
        )
        self.__ca = ca if ca is not None else ConfigMapNameReference()
        self.__extra_scopes = extra_scopes if extra_scopes is not None else []
        self.__extra_authorize_parameters = (
            extra_authorize_parameters if extra_authorize_parameters is not None else {}
        )
        self.__issuer = issuer
        self.__claims = claims if claims is not None else OpenIDClaims()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_id = self.client_id()
        check_type("client_id", client_id, str)
        v["clientID"] = client_id
        client_secret = self.client_secret()
        check_type("client_secret", client_secret, "SecretNameReference")
        v["clientSecret"] = client_secret
        ca = self.ca()
        check_type("ca", ca, "ConfigMapNameReference")
        v["ca"] = ca
        extra_scopes = self.extra_scopes()
        check_type("extra_scopes", extra_scopes, Optional[List[str]])
        if extra_scopes:  # omit empty
            v["extraScopes"] = extra_scopes
        extra_authorize_parameters = self.extra_authorize_parameters()
        check_type(
            "extra_authorize_parameters",
            extra_authorize_parameters,
            Optional[Dict[str, str]],
        )
        if extra_authorize_parameters:  # omit empty
            v["extraAuthorizeParameters"] = extra_authorize_parameters
        issuer = self.issuer()
        check_type("issuer", issuer, str)
        v["issuer"] = issuer
        claims = self.claims()
        check_type("claims", claims, "OpenIDClaims")
        v["claims"] = claims
        return v

    def client_id(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__client_id

    def client_secret(self) -> "SecretNameReference":
        """
        clientSecret is a required reference to the secret by name containing the oauth client secret.
        The key "clientSecret" is used to locate the data.
        If the secret or expected key is not found, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__client_secret

    def ca(self) -> "ConfigMapNameReference":
        """
        ca is an optional reference to a config map by name containing the PEM-encoded CA bundle.
        It is used as a trust anchor to validate the TLS certificate presented by the remote server.
        The key "ca.crt" is used to locate the data.
        If specified and the config map or expected key is not found, the identity provider is not honored.
        If the specified ca data is not valid, the identity provider is not honored.
        If empty, the default system roots are used.
        The namespace for this config map is openshift-config.
        """
        return self.__ca

    def extra_scopes(self) -> Optional[List[str]]:
        """
        extraScopes are any scopes to request in addition to the standard "openid" scope.
        """
        return self.__extra_scopes

    def extra_authorize_parameters(self) -> Optional[Dict[str, str]]:
        """
        extraAuthorizeParameters are any custom parameters to add to the authorize request.
        """
        return self.__extra_authorize_parameters

    def issuer(self) -> str:
        """
        issuer is the URL that the OpenID Provider asserts as its Issuer Identifier.
        It must use the https scheme with no query or fragment component.
        """
        return self.__issuer

    def claims(self) -> "OpenIDClaims":
        """
        claims mappings
        """
        return self.__claims


class RequestHeaderIdentityProvider(types.Object):
    """
    RequestHeaderIdentityProvider provides identities for users authenticating using request header credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        login_url: str = "",
        challenge_url: str = "",
        ca: "ConfigMapNameReference" = None,
        client_common_names: List[str] = None,
        headers: List[str] = None,
        preferred_username_headers: List[str] = None,
        name_headers: List[str] = None,
        email_headers: List[str] = None,
    ):
        super().__init__()
        self.__login_url = login_url
        self.__challenge_url = challenge_url
        self.__ca = ca if ca is not None else ConfigMapNameReference()
        self.__client_common_names = (
            client_common_names if client_common_names is not None else []
        )
        self.__headers = headers if headers is not None else []
        self.__preferred_username_headers = (
            preferred_username_headers if preferred_username_headers is not None else []
        )
        self.__name_headers = name_headers if name_headers is not None else []
        self.__email_headers = email_headers if email_headers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        login_url = self.login_url()
        check_type("login_url", login_url, str)
        v["loginURL"] = login_url
        challenge_url = self.challenge_url()
        check_type("challenge_url", challenge_url, str)
        v["challengeURL"] = challenge_url
        ca = self.ca()
        check_type("ca", ca, "ConfigMapNameReference")
        v["ca"] = ca
        client_common_names = self.client_common_names()
        check_type("client_common_names", client_common_names, Optional[List[str]])
        if client_common_names:  # omit empty
            v["clientCommonNames"] = client_common_names
        headers = self.headers()
        check_type("headers", headers, List[str])
        v["headers"] = headers
        preferred_username_headers = self.preferred_username_headers()
        check_type("preferred_username_headers", preferred_username_headers, List[str])
        v["preferredUsernameHeaders"] = preferred_username_headers
        name_headers = self.name_headers()
        check_type("name_headers", name_headers, List[str])
        v["nameHeaders"] = name_headers
        email_headers = self.email_headers()
        check_type("email_headers", email_headers, List[str])
        v["emailHeaders"] = email_headers
        return v

    def login_url(self) -> str:
        """
        loginURL is a URL to redirect unauthenticated /authorize requests to
        Unauthenticated requests from OAuth clients which expect interactive logins will be redirected here
        ${url} is replaced with the current URL, escaped to be safe in a query parameter
          https://www.example.com/sso-login?then=${url}
        ${query} is replaced with the current query string
          https://www.example.com/auth-proxy/oauth/authorize?${query}
        Required when login is set to true.
        """
        return self.__login_url

    def challenge_url(self) -> str:
        """
        challengeURL is a URL to redirect unauthenticated /authorize requests to
        Unauthenticated requests from OAuth clients which expect WWW-Authenticate challenges will be
        redirected here.
        ${url} is replaced with the current URL, escaped to be safe in a query parameter
          https://www.example.com/sso-login?then=${url}
        ${query} is replaced with the current query string
          https://www.example.com/auth-proxy/oauth/authorize?${query}
        Required when challenge is set to true.
        """
        return self.__challenge_url

    def ca(self) -> "ConfigMapNameReference":
        """
        ca is a required reference to a config map by name containing the PEM-encoded CA bundle.
        It is used as a trust anchor to validate the TLS certificate presented by the remote server.
        Specifically, it allows verification of incoming requests to prevent header spoofing.
        The key "ca.crt" is used to locate the data.
        If the config map or expected key is not found, the identity provider is not honored.
        If the specified ca data is not valid, the identity provider is not honored.
        The namespace for this config map is openshift-config.
        """
        return self.__ca

    def client_common_names(self) -> Optional[List[str]]:
        """
        clientCommonNames is an optional list of common names to require a match from. If empty, any
        client certificate validated against the clientCA bundle is considered authoritative.
        """
        return self.__client_common_names

    def headers(self) -> List[str]:
        """
        headers is the set of headers to check for identity information
        """
        return self.__headers

    def preferred_username_headers(self) -> List[str]:
        """
        preferredUsernameHeaders is the set of headers to check for the preferred username
        """
        return self.__preferred_username_headers

    def name_headers(self) -> List[str]:
        """
        nameHeaders is the set of headers to check for the display name
        """
        return self.__name_headers

    def email_headers(self) -> List[str]:
        """
        emailHeaders is the set of headers to check for the email address
        """
        return self.__email_headers


class IdentityProviderConfig(types.Object):
    """
    IdentityProviderConfig contains configuration for using a specific identity provider
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: IdentityProviderType = None,
        basic_auth: "BasicAuthIdentityProvider" = None,
        github: "GitHubIdentityProvider" = None,
        gitlab: "GitLabIdentityProvider" = None,
        google: "GoogleIdentityProvider" = None,
        htpasswd: "HTPasswdIdentityProvider" = None,
        keystone: "KeystoneIdentityProvider" = None,
        ldap: "LDAPIdentityProvider" = None,
        open_id: "OpenIDIdentityProvider" = None,
        request_header: "RequestHeaderIdentityProvider" = None,
    ):
        super().__init__()
        self.__type = type
        self.__basic_auth = basic_auth
        self.__github = github
        self.__gitlab = gitlab
        self.__google = google
        self.__htpasswd = htpasswd
        self.__keystone = keystone
        self.__ldap = ldap
        self.__open_id = open_id
        self.__request_header = request_header

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, IdentityProviderType)
        v["type"] = type
        basic_auth = self.basic_auth()
        check_type("basic_auth", basic_auth, Optional["BasicAuthIdentityProvider"])
        if basic_auth is not None:  # omit empty
            v["basicAuth"] = basic_auth
        github = self.github()
        check_type("github", github, Optional["GitHubIdentityProvider"])
        if github is not None:  # omit empty
            v["github"] = github
        gitlab = self.gitlab()
        check_type("gitlab", gitlab, Optional["GitLabIdentityProvider"])
        if gitlab is not None:  # omit empty
            v["gitlab"] = gitlab
        google = self.google()
        check_type("google", google, Optional["GoogleIdentityProvider"])
        if google is not None:  # omit empty
            v["google"] = google
        htpasswd = self.htpasswd()
        check_type("htpasswd", htpasswd, Optional["HTPasswdIdentityProvider"])
        if htpasswd is not None:  # omit empty
            v["htpasswd"] = htpasswd
        keystone = self.keystone()
        check_type("keystone", keystone, Optional["KeystoneIdentityProvider"])
        if keystone is not None:  # omit empty
            v["keystone"] = keystone
        ldap = self.ldap()
        check_type("ldap", ldap, Optional["LDAPIdentityProvider"])
        if ldap is not None:  # omit empty
            v["ldap"] = ldap
        open_id = self.open_id()
        check_type("open_id", open_id, Optional["OpenIDIdentityProvider"])
        if open_id is not None:  # omit empty
            v["openID"] = open_id
        request_header = self.request_header()
        check_type(
            "request_header", request_header, Optional["RequestHeaderIdentityProvider"]
        )
        if request_header is not None:  # omit empty
            v["requestHeader"] = request_header
        return v

    def type(self) -> IdentityProviderType:
        """
        type identifies the identity provider type for this entry.
        """
        return self.__type

    def basic_auth(self) -> Optional["BasicAuthIdentityProvider"]:
        """
        basicAuth contains configuration options for the BasicAuth IdP
        """
        return self.__basic_auth

    def github(self) -> Optional["GitHubIdentityProvider"]:
        """
        github enables user authentication using GitHub credentials
        """
        return self.__github

    def gitlab(self) -> Optional["GitLabIdentityProvider"]:
        """
        gitlab enables user authentication using GitLab credentials
        """
        return self.__gitlab

    def google(self) -> Optional["GoogleIdentityProvider"]:
        """
        google enables user authentication using Google credentials
        """
        return self.__google

    def htpasswd(self) -> Optional["HTPasswdIdentityProvider"]:
        """
        htpasswd enables user authentication using an HTPasswd file to validate credentials
        """
        return self.__htpasswd

    def keystone(self) -> Optional["KeystoneIdentityProvider"]:
        """
        keystone enables user authentication using keystone password credentials
        """
        return self.__keystone

    def ldap(self) -> Optional["LDAPIdentityProvider"]:
        """
        ldap enables user authentication using LDAP credentials
        """
        return self.__ldap

    def open_id(self) -> Optional["OpenIDIdentityProvider"]:
        """
        openID enables user authentication using OpenID credentials
        """
        return self.__open_id

    def request_header(self) -> Optional["RequestHeaderIdentityProvider"]:
        """
        requestHeader enables user authentication using request header credentials
        """
        return self.__request_header


class IdentityProvider(types.Object):
    """
    IdentityProvider provides identities for users authenticating using credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        mapping_method: MappingMethodType = None,
        identity_provider_config: "IdentityProviderConfig" = None,
    ):
        super().__init__()
        self.__name = name
        self.__mapping_method = mapping_method
        self.__identity_provider_config = (
            identity_provider_config
            if identity_provider_config is not None
            else IdentityProviderConfig()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        mapping_method = self.mapping_method()
        check_type("mapping_method", mapping_method, Optional[MappingMethodType])
        if mapping_method:  # omit empty
            v["mappingMethod"] = mapping_method
        identity_provider_config = self.identity_provider_config()
        check_type(
            "identity_provider_config",
            identity_provider_config,
            "IdentityProviderConfig",
        )
        v.update(identity_provider_config._root())  # inline
        return v

    def name(self) -> str:
        """
        name is used to qualify the identities returned by this provider.
        - It MUST be unique and not shared by any other identity provider used
        - It MUST be a valid path segment: name cannot equal "." or ".." or contain "/" or "%" or ":"
          Ref: https://godoc.org/github.com/openshift/origin/pkg/user/apis/user/validation#ValidateIdentityProviderName
        """
        return self.__name

    def mapping_method(self) -> Optional[MappingMethodType]:
        """
        mappingMethod determines how identities from this provider are mapped to users
        Defaults to "claim"
        """
        return self.__mapping_method

    def identity_provider_config(self) -> "IdentityProviderConfig":
        return self.__identity_provider_config


class RegistryLocation(types.Object):
    """
    RegistryLocation contains a location of the registry specified by the registry domain
    name. The domain name might include wildcards, like '*' or '??'.
    """

    @context.scoped
    @typechecked
    def __init__(self, domain_name: str = "", insecure: bool = None):
        super().__init__()
        self.__domain_name = domain_name
        self.__insecure = insecure

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        domain_name = self.domain_name()
        check_type("domain_name", domain_name, str)
        v["domainName"] = domain_name
        insecure = self.insecure()
        check_type("insecure", insecure, Optional[bool])
        if insecure:  # omit empty
            v["insecure"] = insecure
        return v

    def domain_name(self) -> str:
        """
        domainName specifies a domain name for the registry
        In case the registry use non-standard (80 or 443) port, the port should be included
        in the domain name as well.
        """
        return self.__domain_name

    def insecure(self) -> Optional[bool]:
        """
        insecure indicates whether the registry is secure (https) or insecure (http)
        By default (if not specified) the registry is assumed as secure.
        """
        return self.__insecure


class RegistrySources(types.Object):
    """
    RegistrySources holds cluster-wide information about how to handle the registries config.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        insecure_registries: List[str] = None,
        blocked_registries: List[str] = None,
        allowed_registries: List[str] = None,
    ):
        super().__init__()
        self.__insecure_registries = (
            insecure_registries if insecure_registries is not None else []
        )
        self.__blocked_registries = (
            blocked_registries if blocked_registries is not None else []
        )
        self.__allowed_registries = (
            allowed_registries if allowed_registries is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        insecure_registries = self.insecure_registries()
        check_type("insecure_registries", insecure_registries, Optional[List[str]])
        if insecure_registries:  # omit empty
            v["insecureRegistries"] = insecure_registries
        blocked_registries = self.blocked_registries()
        check_type("blocked_registries", blocked_registries, Optional[List[str]])
        if blocked_registries:  # omit empty
            v["blockedRegistries"] = blocked_registries
        allowed_registries = self.allowed_registries()
        check_type("allowed_registries", allowed_registries, Optional[List[str]])
        if allowed_registries:  # omit empty
            v["allowedRegistries"] = allowed_registries
        return v

    def insecure_registries(self) -> Optional[List[str]]:
        """
        insecureRegistries are registries which do not have a valid TLS certificates or only support HTTP connections.
        """
        return self.__insecure_registries

    def blocked_registries(self) -> Optional[List[str]]:
        """
        blockedRegistries cannot be used for image pull and push actions. All other registries are permitted.
        
        Only one of BlockedRegistries or AllowedRegistries may be set.
        """
        return self.__blocked_registries

    def allowed_registries(self) -> Optional[List[str]]:
        """
        allowedRegistries are the only registries permitted for image pull and push actions. All other registries are denied.
        
        Only one of BlockedRegistries or AllowedRegistries may be set.
        """
        return self.__allowed_registries


class ImageSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        allowed_registries_for_import: List["RegistryLocation"] = None,
        external_registry_hostnames: List[str] = None,
        additional_trusted_ca: "ConfigMapNameReference" = None,
        registry_sources: "RegistrySources" = None,
    ):
        super().__init__()
        self.__allowed_registries_for_import = (
            allowed_registries_for_import
            if allowed_registries_for_import is not None
            else []
        )
        self.__external_registry_hostnames = (
            external_registry_hostnames
            if external_registry_hostnames is not None
            else []
        )
        self.__additional_trusted_ca = (
            additional_trusted_ca
            if additional_trusted_ca is not None
            else ConfigMapNameReference()
        )
        self.__registry_sources = (
            registry_sources if registry_sources is not None else RegistrySources()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        allowed_registries_for_import = self.allowed_registries_for_import()
        check_type(
            "allowed_registries_for_import",
            allowed_registries_for_import,
            Optional[List["RegistryLocation"]],
        )
        if allowed_registries_for_import:  # omit empty
            v["allowedRegistriesForImport"] = allowed_registries_for_import
        external_registry_hostnames = self.external_registry_hostnames()
        check_type(
            "external_registry_hostnames",
            external_registry_hostnames,
            Optional[List[str]],
        )
        if external_registry_hostnames:  # omit empty
            v["externalRegistryHostnames"] = external_registry_hostnames
        additional_trusted_ca = self.additional_trusted_ca()
        check_type(
            "additional_trusted_ca", additional_trusted_ca, "ConfigMapNameReference"
        )
        v["additionalTrustedCA"] = additional_trusted_ca
        registry_sources = self.registry_sources()
        check_type("registry_sources", registry_sources, "RegistrySources")
        v["registrySources"] = registry_sources
        return v

    def allowed_registries_for_import(self) -> Optional[List["RegistryLocation"]]:
        """
        allowedRegistriesForImport limits the container image registries that normal users may import
        images from. Set this list to the registries that you trust to contain valid Docker
        images and that you want applications to be able to import from. Users with
        permission to create Images or ImageStreamMappings via the API are not affected by
        this policy - typically only administrators or system integrations will have those
        permissions.
        """
        return self.__allowed_registries_for_import

    def external_registry_hostnames(self) -> Optional[List[str]]:
        """
        externalRegistryHostnames provides the hostnames for the default external image
        registry. The external hostname should be set only when the image registry
        is exposed externally. The first value is used in 'publicDockerImageRepository'
        field in ImageStreams. The value must be in "hostname[:port]" format.
        """
        return self.__external_registry_hostnames

    def additional_trusted_ca(self) -> "ConfigMapNameReference":
        """
        additionalTrustedCA is a reference to a ConfigMap containing additional CAs that
        should be trusted during imagestream import, pod image pull, build image pull, and
        imageregistry pullthrough.
        The namespace for this config map is openshift-config.
        """
        return self.__additional_trusted_ca

    def registry_sources(self) -> "RegistrySources":
        """
        registrySources contains configuration that determines how the container runtime
        should treat individual registries when accessing images for builds+pods. (e.g.
        whether or not to allow insecure access).  It does not contain configuration for the
        internal cluster registry.
        """
        return self.__registry_sources


class Image(base.TypedObject, base.MetadataObject):
    """
    Image governs policies related to imagestream imports and runtime configuration
    for external registries. It allows cluster admins to configure which registries
    OpenShift is allowed to import images from, extra CA trust bundles for external
    registries, and policies to block or allow registry hostnames.
    When exposing OpenShift's image registry to the public, this also lets cluster
    admins specify the external hostname.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ImageSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="Image",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ImageSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ImageSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ImageSpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class InfrastructureSpec(types.Object):
    """
    InfrastructureSpec contains settings that apply to the cluster infrastructure.
    """

    @context.scoped
    @typechecked
    def __init__(self, cloud_config: "ConfigMapFileReference" = None):
        super().__init__()
        self.__cloud_config = (
            cloud_config if cloud_config is not None else ConfigMapFileReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cloud_config = self.cloud_config()
        check_type("cloud_config", cloud_config, "ConfigMapFileReference")
        v["cloudConfig"] = cloud_config
        return v

    def cloud_config(self) -> "ConfigMapFileReference":
        """
        cloudConfig is a reference to a ConfigMap containing the cloud provider configuration file.
        This configuration file is used to configure the Kubernetes cloud provider integration
        when using the built-in cloud provider integration or the external cloud controller manager.
        The namespace for this config map is openshift-config.
        """
        return self.__cloud_config


class Infrastructure(base.TypedObject, base.MetadataObject):
    """
    Infrastructure holds cluster-wide information about Infrastructure.  The canonical name is `cluster`
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "InfrastructureSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="Infrastructure",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else InfrastructureSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "InfrastructureSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "InfrastructureSpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class IngressSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, domain: str = ""):
        super().__init__()
        self.__domain = domain

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        domain = self.domain()
        check_type("domain", domain, str)
        v["domain"] = domain
        return v

    def domain(self) -> str:
        """
        domain is used to generate a default host name for a route when the
        route's host name is empty. The generated host name will follow this
        pattern: "<route-name>.<route-namespace>.<domain>".
        
        It is also used as the default wildcard domain suffix for ingress. The
        default ingresscontroller domain will follow this pattern: "*.<domain>".
        
        Once set, changing domain is not currently supported.
        """
        return self.__domain


class Ingress(base.TypedObject, base.MetadataObject):
    """
    Ingress holds cluster-wide information about ingress, including the default ingress domain
    used for routes. The canonical name is `cluster`.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "IngressSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="Ingress",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else IngressSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "IngressSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "IngressSpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class LeaderElection(types.Object):
    """
    LeaderElection provides information to elect a leader
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        disable: bool = None,
        namespace: str = None,
        name: str = None,
        lease_duration: "base.Duration" = None,
        renew_deadline: "base.Duration" = None,
        retry_period: "base.Duration" = None,
    ):
        super().__init__()
        self.__disable = disable
        self.__namespace = namespace
        self.__name = name
        self.__lease_duration = (
            lease_duration if lease_duration is not None else metav1.Duration()
        )
        self.__renew_deadline = (
            renew_deadline if renew_deadline is not None else metav1.Duration()
        )
        self.__retry_period = (
            retry_period if retry_period is not None else metav1.Duration()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        disable = self.disable()
        check_type("disable", disable, Optional[bool])
        if disable:  # omit empty
            v["disable"] = disable
        namespace = self.namespace()
        check_type("namespace", namespace, Optional[str])
        if namespace:  # omit empty
            v["namespace"] = namespace
        name = self.name()
        check_type("name", name, Optional[str])
        if name:  # omit empty
            v["name"] = name
        lease_duration = self.lease_duration()
        check_type("lease_duration", lease_duration, "base.Duration")
        v["leaseDuration"] = lease_duration
        renew_deadline = self.renew_deadline()
        check_type("renew_deadline", renew_deadline, "base.Duration")
        v["renewDeadline"] = renew_deadline
        retry_period = self.retry_period()
        check_type("retry_period", retry_period, "base.Duration")
        v["retryPeriod"] = retry_period
        return v

    def disable(self) -> Optional[bool]:
        """
        disable allows leader election to be suspended while allowing a fully defaulted "normal" startup case.
        """
        return self.__disable

    def namespace(self) -> Optional[str]:
        """
        namespace indicates which namespace the resource is in
        """
        return self.__namespace

    def name(self) -> Optional[str]:
        """
        name indicates what name to use for the resource
        """
        return self.__name

    def lease_duration(self) -> "base.Duration":
        """
        leaseDuration is the duration that non-leader candidates will wait
        after observing a leadership renewal until attempting to acquire
        leadership of a led but unrenewed leader slot. This is effectively the
        maximum duration that a leader can be stopped before it is replaced
        by another candidate. This is only applicable if leader election is
        enabled.
        +nullable
        """
        return self.__lease_duration

    def renew_deadline(self) -> "base.Duration":
        """
        renewDeadline is the interval between attempts by the acting master to
        renew a leadership slot before it stops leading. This must be less
        than or equal to the lease duration. This is only applicable if leader
        election is enabled.
        +nullable
        """
        return self.__renew_deadline

    def retry_period(self) -> "base.Duration":
        """
        retryPeriod is the duration the clients should wait between attempting
        acquisition and renewal of a leadership. This is only applicable if
        leader election is enabled.
        +nullable
        """
        return self.__retry_period


class NetworkSpec(types.Object):
    """
    NetworkSpec is the desired network configuration.
    As a general rule, this SHOULD NOT be read directly. Instead, you should
    consume the NetworkStatus, as it indicates the currently deployed configuration.
    Currently, most spec fields are immutable after installation. Please view the individual ones for further details on each.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        cluster_network: List["ClusterNetworkEntry"] = None,
        service_network: List[str] = None,
        network_type: str = "",
        external_ip: "ExternalIPConfig" = None,
    ):
        super().__init__()
        self.__cluster_network = cluster_network if cluster_network is not None else []
        self.__service_network = service_network if service_network is not None else []
        self.__network_type = network_type
        self.__external_ip = external_ip

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cluster_network = self.cluster_network()
        check_type("cluster_network", cluster_network, List["ClusterNetworkEntry"])
        v["clusterNetwork"] = cluster_network
        service_network = self.service_network()
        check_type("service_network", service_network, List[str])
        v["serviceNetwork"] = service_network
        network_type = self.network_type()
        check_type("network_type", network_type, str)
        v["networkType"] = network_type
        external_ip = self.external_ip()
        check_type("external_ip", external_ip, Optional["ExternalIPConfig"])
        if external_ip is not None:  # omit empty
            v["externalIP"] = external_ip
        return v

    def cluster_network(self) -> List["ClusterNetworkEntry"]:
        """
        IP address pool to use for pod IPs.
        This field is immutable after installation.
        """
        return self.__cluster_network

    def service_network(self) -> List[str]:
        """
        IP address pool for services.
        Currently, we only support a single entry here.
        This field is immutable after installation.
        """
        return self.__service_network

    def network_type(self) -> str:
        """
        NetworkType is the plugin that is to be deployed (e.g. OpenShiftSDN).
        This should match a value that the cluster-network-operator understands,
        or else no networking will be installed.
        Currently supported values are:
        - OpenShiftSDN
        This field is immutable after installation.
        """
        return self.__network_type

    def external_ip(self) -> Optional["ExternalIPConfig"]:
        """
        externalIP defines configuration for controllers that
        affect Service.ExternalIP. If nil, then ExternalIP is
        not allowed to be set.
        """
        return self.__external_ip


class Network(base.TypedObject, base.MetadataObject):
    """
    Network holds cluster-wide information about Network. The canonical name is `cluster`. It is used to configure the desired network configuration, such as: IP address pools for services/pod IPs, network plugin, etc.
    Please view network.spec for an explanation on what applies when configuring this resource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "NetworkSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="Network",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else NetworkSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "NetworkSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "NetworkSpec":
        """
        spec holds user settable values for configuration.
        As a general rule, this SHOULD NOT be read directly. Instead, you should
        consume the NetworkStatus, as it indicates the currently deployed configuration.
        Currently, most spec fields are immutable after installation. Please view the individual ones for further details on each.
        +required
        """
        return self.__spec


class OAuthTemplates(types.Object):
    """
    OAuthTemplates allow for customization of pages like the login page
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        login: "SecretNameReference" = None,
        provider_selection: "SecretNameReference" = None,
        error: "SecretNameReference" = None,
    ):
        super().__init__()
        self.__login = login if login is not None else SecretNameReference()
        self.__provider_selection = (
            provider_selection
            if provider_selection is not None
            else SecretNameReference()
        )
        self.__error = error if error is not None else SecretNameReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        login = self.login()
        check_type("login", login, "SecretNameReference")
        v["login"] = login
        provider_selection = self.provider_selection()
        check_type("provider_selection", provider_selection, "SecretNameReference")
        v["providerSelection"] = provider_selection
        error = self.error()
        check_type("error", error, "SecretNameReference")
        v["error"] = error
        return v

    def login(self) -> "SecretNameReference":
        """
        login is the name of a secret that specifies a go template to use to render the login page.
        The key "login.html" is used to locate the template data.
        If specified and the secret or expected key is not found, the default login page is used.
        If the specified template is not valid, the default login page is used.
        If unspecified, the default login page is used.
        The namespace for this secret is openshift-config.
        """
        return self.__login

    def provider_selection(self) -> "SecretNameReference":
        """
        providerSelection is the name of a secret that specifies a go template to use to render
        the provider selection page.
        The key "providers.html" is used to locate the template data.
        If specified and the secret or expected key is not found, the default provider selection page is used.
        If the specified template is not valid, the default provider selection page is used.
        If unspecified, the default provider selection page is used.
        The namespace for this secret is openshift-config.
        """
        return self.__provider_selection

    def error(self) -> "SecretNameReference":
        """
        error is the name of a secret that specifies a go template to use to render error pages
        during the authentication or grant flow.
        The key "errors.html" is used to locate the template data.
        If specified and the secret or expected key is not found, the default error page is used.
        If the specified template is not valid, the default error page is used.
        If unspecified, the default error page is used.
        The namespace for this secret is openshift-config.
        """
        return self.__error


class TokenConfig(types.Object):
    """
    TokenConfig holds the necessary configuration options for authorization and access tokens
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        access_token_max_age_seconds: int = 0,
        access_token_inactivity_timeout_seconds: int = None,
    ):
        super().__init__()
        self.__access_token_max_age_seconds = access_token_max_age_seconds
        self.__access_token_inactivity_timeout_seconds = (
            access_token_inactivity_timeout_seconds
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        access_token_max_age_seconds = self.access_token_max_age_seconds()
        check_type("access_token_max_age_seconds", access_token_max_age_seconds, int)
        v["accessTokenMaxAgeSeconds"] = access_token_max_age_seconds
        access_token_inactivity_timeout_seconds = (
            self.access_token_inactivity_timeout_seconds()
        )
        check_type(
            "access_token_inactivity_timeout_seconds",
            access_token_inactivity_timeout_seconds,
            Optional[int],
        )
        if access_token_inactivity_timeout_seconds:  # omit empty
            v[
                "accessTokenInactivityTimeoutSeconds"
            ] = access_token_inactivity_timeout_seconds
        return v

    def access_token_max_age_seconds(self) -> int:
        """
        accessTokenMaxAgeSeconds defines the maximum age of access tokens
        """
        return self.__access_token_max_age_seconds

    def access_token_inactivity_timeout_seconds(self) -> Optional[int]:
        """
        accessTokenInactivityTimeoutSeconds defines the default token
        inactivity timeout for tokens granted by any client.
        The value represents the maximum amount of time that can occur between
        consecutive uses of the token. Tokens become invalid if they are not
        used within this temporal window. The user will need to acquire a new
        token to regain access once a token times out.
        Valid values are integer values:
          x < 0  Tokens time out is enabled but tokens never timeout unless configured per client (e.g. `-1`)
          x = 0  Tokens time out is disabled (default)
          x > 0  Tokens time out if there is no activity for x seconds
        The current minimum allowed value for X is 300 (5 minutes)
        """
        return self.__access_token_inactivity_timeout_seconds


class OAuthSpec(types.Object):
    """
    OAuthSpec contains desired cluster auth configuration
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        identity_providers: List["IdentityProvider"] = None,
        token_config: "TokenConfig" = None,
        templates: "OAuthTemplates" = None,
    ):
        super().__init__()
        self.__identity_providers = (
            identity_providers if identity_providers is not None else []
        )
        self.__token_config = (
            token_config if token_config is not None else TokenConfig()
        )
        self.__templates = templates if templates is not None else OAuthTemplates()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        identity_providers = self.identity_providers()
        check_type(
            "identity_providers", identity_providers, Optional[List["IdentityProvider"]]
        )
        if identity_providers:  # omit empty
            v["identityProviders"] = identity_providers
        token_config = self.token_config()
        check_type("token_config", token_config, "TokenConfig")
        v["tokenConfig"] = token_config
        templates = self.templates()
        check_type("templates", templates, "OAuthTemplates")
        v["templates"] = templates
        return v

    def identity_providers(self) -> Optional[List["IdentityProvider"]]:
        """
        identityProviders is an ordered list of ways for a user to identify themselves.
        When this list is empty, no identities are provisioned for users.
        """
        return self.__identity_providers

    def token_config(self) -> "TokenConfig":
        """
        tokenConfig contains options for authorization and access tokens
        """
        return self.__token_config

    def templates(self) -> "OAuthTemplates":
        """
        templates allow you to customize pages like the login page.
        """
        return self.__templates


class OAuth(base.TypedObject, base.MetadataObject):
    """
    OAuth holds cluster-wide information about OAuth.  The canonical name is `cluster`.
    It is used to configure the integrated OAuth server.
    This configuration is only honored when the top level Authentication config has type set to IntegratedOAuth.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "OAuthSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="OAuth",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else OAuthSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "OAuthSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "OAuthSpec":
        """
        +required
        """
        return self.__spec


class OperatorHubSpec(types.Object):
    """
    OperatorHubSpec defines the desired state of OperatorHub
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        disable_all_default_sources: bool = None,
        sources: List["HubSource"] = None,
    ):
        super().__init__()
        self.__disable_all_default_sources = disable_all_default_sources
        self.__sources = sources if sources is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        disable_all_default_sources = self.disable_all_default_sources()
        check_type(
            "disable_all_default_sources", disable_all_default_sources, Optional[bool]
        )
        if disable_all_default_sources:  # omit empty
            v["disableAllDefaultSources"] = disable_all_default_sources
        sources = self.sources()
        check_type("sources", sources, Optional[List["HubSource"]])
        if sources:  # omit empty
            v["sources"] = sources
        return v

    def disable_all_default_sources(self) -> Optional[bool]:
        """
        disableAllDefaultSources allows you to disable all the default hub
        sources. If this is true, a specific entry in sources can be used to
        enable a default source. If this is false, a specific entry in
        sources can be used to disable or enable a default source.
        """
        return self.__disable_all_default_sources

    def sources(self) -> Optional[List["HubSource"]]:
        """
        sources is the list of default hub sources and their configuration.
        If the list is empty, it implies that the default hub sources are
        enabled on the cluster unless disableAllDefaultSources is true.
        If disableAllDefaultSources is true and sources is not empty,
        the configuration present in sources will take precedence. The list of
        default hub sources and their current state will always be reflected in
        the status block.
        """
        return self.__sources


class OperatorHub(base.TypedObject, base.NamespacedMetadataObject):
    """
    OperatorHub is the Schema for the operatorhubs API. It can be used to change
    the state of the default hub sources for OperatorHub on the cluster from
    enabled to disabled and vice versa.
    +genclient:nonNamespaced
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "OperatorHubSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="OperatorHub",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else OperatorHubSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "OperatorHubSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "OperatorHubSpec":
        return self.__spec


class TemplateReference(types.Object):
    """
    TemplateReference references a template in a specific namespace.
    The namespace must be specified at the point of use.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = ""):
        super().__init__()
        self.__name = name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        return v

    def name(self) -> str:
        """
        name is the metadata.name of the referenced project request template
        """
        return self.__name


class ProjectSpec(types.Object):
    """
    ProjectSpec holds the project creation configuration.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        project_request_message: str = "",
        project_request_template: "TemplateReference" = None,
    ):
        super().__init__()
        self.__project_request_message = project_request_message
        self.__project_request_template = (
            project_request_template
            if project_request_template is not None
            else TemplateReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        project_request_message = self.project_request_message()
        check_type("project_request_message", project_request_message, str)
        v["projectRequestMessage"] = project_request_message
        project_request_template = self.project_request_template()
        check_type(
            "project_request_template", project_request_template, "TemplateReference"
        )
        v["projectRequestTemplate"] = project_request_template
        return v

    def project_request_message(self) -> str:
        """
        projectRequestMessage is the string presented to a user if they are unable to request a project via the projectrequest api endpoint
        """
        return self.__project_request_message

    def project_request_template(self) -> "TemplateReference":
        """
        projectRequestTemplate is the template to use for creating projects in response to projectrequest.
        This must point to a template in 'openshift-config' namespace. It is optional.
        If it is not specified, a default template is used.
        """
        return self.__project_request_template


class Project(base.TypedObject, base.MetadataObject):
    """
    Project holds cluster-wide information about Project.  The canonical name is `cluster`
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ProjectSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="Project",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ProjectSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ProjectSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ProjectSpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class Proxy(base.TypedObject, base.MetadataObject):
    """
    Proxy holds cluster-wide information on how to configure default proxies for the cluster. The canonical name is `cluster`
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ProxySpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="Proxy",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ProxySpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ProxySpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ProxySpec":
        """
        Spec holds user-settable values for the proxy configuration
        +required
        """
        return self.__spec


class RemoteConnectionInfo(types.Object):
    """
    RemoteConnectionInfo holds information necessary for establishing a remote connection
    """

    @context.scoped
    @typechecked
    def __init__(self, url: str = "", ca: str = "", cert_info: "CertInfo" = None):
        super().__init__()
        self.__url = url
        self.__ca = ca
        self.__cert_info = cert_info if cert_info is not None else CertInfo()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        ca = self.ca()
        check_type("ca", ca, str)
        v["ca"] = ca
        cert_info = self.cert_info()
        check_type("cert_info", cert_info, "CertInfo")
        v.update(cert_info._root())  # inline
        return v

    def url(self) -> str:
        """
        URL is the remote URL to connect to
        """
        return self.__url

    def ca(self) -> str:
        """
        CA is the CA for verifying TLS connections
        """
        return self.__ca

    def cert_info(self) -> "CertInfo":
        """
        CertInfo is the TLS client cert information to present
        this is anonymous so that we can inline it for serialization
        """
        return self.__cert_info


class SchedulerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        policy: "ConfigMapNameReference" = None,
        default_node_selector: str = None,
        masters_schedulable: bool = False,
    ):
        super().__init__()
        self.__policy = policy if policy is not None else ConfigMapNameReference()
        self.__default_node_selector = default_node_selector
        self.__masters_schedulable = masters_schedulable

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        policy = self.policy()
        check_type("policy", policy, "ConfigMapNameReference")
        v["policy"] = policy
        default_node_selector = self.default_node_selector()
        check_type("default_node_selector", default_node_selector, Optional[str])
        if default_node_selector:  # omit empty
            v["defaultNodeSelector"] = default_node_selector
        masters_schedulable = self.masters_schedulable()
        check_type("masters_schedulable", masters_schedulable, bool)
        v["mastersSchedulable"] = masters_schedulable
        return v

    def policy(self) -> "ConfigMapNameReference":
        """
        policy is a reference to a ConfigMap containing scheduler policy which has
        user specified predicates and priorities. If this ConfigMap is not available
        scheduler will default to use DefaultAlgorithmProvider.
        The namespace for this configmap is openshift-config.
        """
        return self.__policy

    def default_node_selector(self) -> Optional[str]:
        """
        defaultNodeSelector helps set the cluster-wide default node selector to
        restrict pod placement to specific nodes. This is applied to the pods
        created in all namespaces without a specified nodeSelector value.
        For example,
        defaultNodeSelector: "type=user-node,region=east" would set nodeSelector
        field in pod spec to "type=user-node,region=east" to all pods created
        in all namespaces. Namespaces having project-wide node selectors won't be
        impacted even if this field is set. This adds an annotation section to
        the namespace.
        For example, if a new namespace is created with
        node-selector='type=user-node,region=east',
        the annotation openshift.io/node-selector: type=user-node,region=east
        gets added to the project. When the openshift.io/node-selector annotation
        is set on the project the value is used in preference to the value we are setting
        for defaultNodeSelector field.
        For instance,
        openshift.io/node-selector: "type=user-node,region=west" means
        that the default of "type=user-node,region=east" set in defaultNodeSelector
        would not be applied.
        """
        return self.__default_node_selector

    def masters_schedulable(self) -> bool:
        """
        MastersSchedulable allows masters nodes to be schedulable. When this flag is
        turned on, all the master nodes in the cluster will be made schedulable,
        so that workload pods can run on them. The default value for this field is false,
        meaning none of the master nodes are schedulable.
        Important Note: Once the workload pods start running on the master nodes,
        extreme care must be taken to ensure that cluster-critical control plane components
        are not impacted.
        Please turn on this field after doing due diligence.
        """
        return self.__masters_schedulable


class Scheduler(base.TypedObject, base.MetadataObject):
    """
    Scheduler holds cluster-wide config information to run the Kubernetes Scheduler
    and influence its placement decisions. The canonical name for this config is `cluster`.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "SchedulerSpec" = None,
    ):
        super().__init__(
            api_version="config.openshift.io/v1",
            kind="Scheduler",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else SchedulerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "SchedulerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "SchedulerSpec":
        """
        spec holds user settable values for configuration
        +required
        """
        return self.__spec


class StringSourceSpec(types.Object):
    """
    StringSourceSpec specifies a string value, or external location
    """

    @context.scoped
    @typechecked
    def __init__(
        self, value: str = "", env: str = "", file: str = "", key_file: str = ""
    ):
        super().__init__()
        self.__value = value
        self.__env = env
        self.__file = file
        self.__key_file = key_file

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        value = self.value()
        check_type("value", value, str)
        v["value"] = value
        env = self.env()
        check_type("env", env, str)
        v["env"] = env
        file = self.file()
        check_type("file", file, str)
        v["file"] = file
        key_file = self.key_file()
        check_type("key_file", key_file, str)
        v["keyFile"] = key_file
        return v

    def value(self) -> str:
        """
        Value specifies the cleartext value, or an encrypted value if keyFile is specified.
        """
        return self.__value

    def env(self) -> str:
        """
        Env specifies an envvar containing the cleartext value, or an encrypted value if the keyFile is specified.
        """
        return self.__env

    def file(self) -> str:
        """
        File references a file containing the cleartext value, or an encrypted value if a keyFile is specified.
        """
        return self.__file

    def key_file(self) -> str:
        """
        KeyFile references a file containing the key to use to decrypt the value.
        """
        return self.__key_file


class StringSource(types.Object):
    """
    StringSource allows specifying a string inline, or externally via env var or file.
    When it contains only a string value, it marshals to a simple JSON string.
    """

    @context.scoped
    @typechecked
    def __init__(self, string_source_spec: "StringSourceSpec" = None):
        super().__init__()
        self.__string_source_spec = (
            string_source_spec if string_source_spec is not None else StringSourceSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        string_source_spec = self.string_source_spec()
        check_type("string_source_spec", string_source_spec, "StringSourceSpec")
        v.update(string_source_spec._root())  # inline
        return v

    def string_source_spec(self) -> "StringSourceSpec":
        """
        StringSourceSpec specifies the string value, or external location
        """
        return self.__string_source_spec
