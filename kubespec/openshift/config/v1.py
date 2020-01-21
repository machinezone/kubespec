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
        self, names: List[str] = None, servingCertificate: "SecretNameReference" = None
    ):
        super().__init__()
        self.__names = names if names is not None else []
        self.__servingCertificate = (
            servingCertificate
            if servingCertificate is not None
            else SecretNameReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        names = self.names()
        check_type("names", names, Optional[List[str]])
        if names:  # omit empty
            v["names"] = names
        servingCertificate = self.servingCertificate()
        check_type("servingCertificate", servingCertificate, "SecretNameReference")
        v["servingCertificate"] = servingCertificate
        return v

    def names(self) -> Optional[List[str]]:
        """
        names is a optional list of explicit DNS names (leading wildcards allowed) that should use this certificate to
        serve secure traffic. If no names are provided, the implicit names will be extracted from the certificates.
        Exact names trump over wildcard names. Explicit names defined here trump over extracted implicit names.
        """
        return self.__names

    def servingCertificate(self) -> "SecretNameReference":
        """
        servingCertificate references a kubernetes.io/tls type secret containing the TLS cert info for serving secure traffic.
        The secret must exist in the openshift-config namespace and contain the following required fields:
        - Secret.Data["tls.key"] - TLS private key.
        - Secret.Data["tls.crt"] - TLS certificate.
        """
        return self.__servingCertificate


class APIServerServingCerts(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, namedCertificates: List["APIServerNamedServingCert"] = None):
        super().__init__()
        self.__namedCertificates = (
            namedCertificates if namedCertificates is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namedCertificates = self.namedCertificates()
        check_type(
            "namedCertificates",
            namedCertificates,
            Optional[List["APIServerNamedServingCert"]],
        )
        if namedCertificates:  # omit empty
            v["namedCertificates"] = namedCertificates
        return v

    def namedCertificates(self) -> Optional[List["APIServerNamedServingCert"]]:
        """
        namedCertificates references secrets containing the TLS cert info for serving secure traffic to specific hostnames.
        If no named certificates are provided, or no named certificates match the server name as understood by a client,
        the defaultServingCertificate will be used.
        """
        return self.__namedCertificates


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
        self, ciphers: List[str] = None, minTLSVersion: TLSProtocolVersion = None
    ):
        super().__init__()
        self.__ciphers = ciphers if ciphers is not None else []
        self.__minTLSVersion = minTLSVersion

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ciphers = self.ciphers()
        check_type("ciphers", ciphers, List[str])
        v["ciphers"] = ciphers
        minTLSVersion = self.minTLSVersion()
        check_type("minTLSVersion", minTLSVersion, TLSProtocolVersion)
        v["minTLSVersion"] = minTLSVersion
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

    def minTLSVersion(self) -> TLSProtocolVersion:
        """
        minTLSVersion is used to specify the minimal version of the TLS protocol
        that is negotiated during the TLS handshake. For example, to use TLS
        versions 1.1, 1.2 and 1.3 (yaml):
        
          minTLSVersion: TLSv1.1
        
        NOTE: currently the highest minTLSVersion allowed is VersionTLS12
        """
        return self.__minTLSVersion


class CustomTLSProfile(types.Object):
    """
    CustomTLSProfile is a user-defined TLS security profile. Be extremely careful
    using a custom TLS profile as invalid configurations can be catastrophic.
    """

    @context.scoped
    @typechecked
    def __init__(self, tLSProfileSpec: "TLSProfileSpec" = None):
        super().__init__()
        self.__tLSProfileSpec = (
            tLSProfileSpec if tLSProfileSpec is not None else TLSProfileSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        tLSProfileSpec = self.tLSProfileSpec()
        check_type("tLSProfileSpec", tLSProfileSpec, "TLSProfileSpec")
        v.update(tLSProfileSpec._root())  # inline
        return v

    def tLSProfileSpec(self) -> "TLSProfileSpec":
        return self.__tLSProfileSpec


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
        servingCerts: "APIServerServingCerts" = None,
        clientCA: "ConfigMapNameReference" = None,
        additionalCORSAllowedOrigins: List[str] = None,
        encryption: "APIServerEncryption" = None,
        tlsSecurityProfile: "TLSSecurityProfile" = None,
    ):
        super().__init__()
        self.__servingCerts = (
            servingCerts if servingCerts is not None else APIServerServingCerts()
        )
        self.__clientCA = clientCA if clientCA is not None else ConfigMapNameReference()
        self.__additionalCORSAllowedOrigins = (
            additionalCORSAllowedOrigins
            if additionalCORSAllowedOrigins is not None
            else []
        )
        self.__encryption = (
            encryption if encryption is not None else APIServerEncryption()
        )
        self.__tlsSecurityProfile = tlsSecurityProfile

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        servingCerts = self.servingCerts()
        check_type("servingCerts", servingCerts, "APIServerServingCerts")
        v["servingCerts"] = servingCerts
        clientCA = self.clientCA()
        check_type("clientCA", clientCA, "ConfigMapNameReference")
        v["clientCA"] = clientCA
        additionalCORSAllowedOrigins = self.additionalCORSAllowedOrigins()
        check_type(
            "additionalCORSAllowedOrigins",
            additionalCORSAllowedOrigins,
            Optional[List[str]],
        )
        if additionalCORSAllowedOrigins:  # omit empty
            v["additionalCORSAllowedOrigins"] = additionalCORSAllowedOrigins
        encryption = self.encryption()
        check_type("encryption", encryption, "APIServerEncryption")
        v["encryption"] = encryption
        tlsSecurityProfile = self.tlsSecurityProfile()
        check_type(
            "tlsSecurityProfile", tlsSecurityProfile, Optional["TLSSecurityProfile"]
        )
        if tlsSecurityProfile is not None:  # omit empty
            v["tlsSecurityProfile"] = tlsSecurityProfile
        return v

    def servingCerts(self) -> "APIServerServingCerts":
        """
        servingCert is the TLS cert info for serving secure traffic. If not specified, operator managed certificates
        will be used for serving secure traffic.
        """
        return self.__servingCerts

    def clientCA(self) -> "ConfigMapNameReference":
        """
        clientCA references a ConfigMap containing a certificate bundle for the signers that will be recognized for
        incoming client certificates in addition to the operator managed signers. If this is empty, then only operator managed signers are valid.
        You usually only have to set this if you have your own PKI you wish to honor client certificates from.
        The ConfigMap must exist in the openshift-config namespace and contain the following required fields:
        - ConfigMap.Data["ca-bundle.crt"] - CA bundle.
        """
        return self.__clientCA

    def additionalCORSAllowedOrigins(self) -> Optional[List[str]]:
        """
        additionalCORSAllowedOrigins lists additional, user-defined regular expressions describing hosts for which the
        API server allows access using the CORS headers. This may be needed to access the API and the integrated OAuth
        server from JavaScript applications.
        The values are regular expressions that correspond to the Golang regular expression language.
        """
        return self.__additionalCORSAllowedOrigins

    def encryption(self) -> "APIServerEncryption":
        """
        encryption allows the configuration of encryption of resources at the datastore layer.
        """
        return self.__encryption

    def tlsSecurityProfile(self) -> Optional["TLSSecurityProfile"]:
        """
        tlsSecurityProfile specifies settings for TLS connections for externally exposed servers.
        
        If unset, a default (which may change between releases) is chosen. Note that only Old and
        Intermediate profiles are currently supported, and the maximum available MinTLSVersions
        is VersionTLS12.
        """
        return self.__tlsSecurityProfile


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
            apiVersion="config.openshift.io/v1",
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
        pluginConfig: Dict[str, "AdmissionPluginConfig"] = None,
        enabledPlugins: List[str] = None,
        disabledPlugins: List[str] = None,
    ):
        super().__init__()
        self.__pluginConfig = pluginConfig if pluginConfig is not None else {}
        self.__enabledPlugins = enabledPlugins if enabledPlugins is not None else []
        self.__disabledPlugins = disabledPlugins if disabledPlugins is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pluginConfig = self.pluginConfig()
        check_type(
            "pluginConfig", pluginConfig, Optional[Dict[str, "AdmissionPluginConfig"]]
        )
        if pluginConfig:  # omit empty
            v["pluginConfig"] = pluginConfig
        enabledPlugins = self.enabledPlugins()
        check_type("enabledPlugins", enabledPlugins, Optional[List[str]])
        if enabledPlugins:  # omit empty
            v["enabledPlugins"] = enabledPlugins
        disabledPlugins = self.disabledPlugins()
        check_type("disabledPlugins", disabledPlugins, Optional[List[str]])
        if disabledPlugins:  # omit empty
            v["disabledPlugins"] = disabledPlugins
        return v

    def pluginConfig(self) -> Optional[Dict[str, "AdmissionPluginConfig"]]:
        return self.__pluginConfig

    def enabledPlugins(self) -> Optional[List[str]]:
        """
        enabledPlugins is a list of admission plugins that must be on in addition to the default list.
        Some admission plugins are disabled by default, but certain configurations require them.  This is fairly uncommon
        and can result in performance penalties and unexpected behavior.
        """
        return self.__enabledPlugins

    def disabledPlugins(self) -> Optional[List[str]]:
        """
        disabledPlugins is a list of admission plugins that must be off.  Putting something in this list
        is almost always a mistake and likely to result in cluster instability.
        """
        return self.__disabledPlugins


class AuditConfig(types.Object):
    """
    AuditConfig holds configuration for the audit capabilities
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        enabled: bool = False,
        auditFilePath: str = "",
        maximumFileRetentionDays: int = 0,
        maximumRetainedFiles: int = 0,
        maximumFileSizeMegabytes: int = 0,
        policyFile: str = "",
        policyConfiguration: "runtime.RawExtension" = None,
        logFormat: LogFormatType = None,
        webHookKubeConfig: str = "",
        webHookMode: WebHookModeType = None,
    ):
        super().__init__()
        self.__enabled = enabled
        self.__auditFilePath = auditFilePath
        self.__maximumFileRetentionDays = maximumFileRetentionDays
        self.__maximumRetainedFiles = maximumRetainedFiles
        self.__maximumFileSizeMegabytes = maximumFileSizeMegabytes
        self.__policyFile = policyFile
        self.__policyConfiguration = policyConfiguration
        self.__logFormat = logFormat
        self.__webHookKubeConfig = webHookKubeConfig
        self.__webHookMode = webHookMode

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        enabled = self.enabled()
        check_type("enabled", enabled, bool)
        v["enabled"] = enabled
        auditFilePath = self.auditFilePath()
        check_type("auditFilePath", auditFilePath, str)
        v["auditFilePath"] = auditFilePath
        maximumFileRetentionDays = self.maximumFileRetentionDays()
        check_type("maximumFileRetentionDays", maximumFileRetentionDays, int)
        v["maximumFileRetentionDays"] = maximumFileRetentionDays
        maximumRetainedFiles = self.maximumRetainedFiles()
        check_type("maximumRetainedFiles", maximumRetainedFiles, int)
        v["maximumRetainedFiles"] = maximumRetainedFiles
        maximumFileSizeMegabytes = self.maximumFileSizeMegabytes()
        check_type("maximumFileSizeMegabytes", maximumFileSizeMegabytes, int)
        v["maximumFileSizeMegabytes"] = maximumFileSizeMegabytes
        policyFile = self.policyFile()
        check_type("policyFile", policyFile, str)
        v["policyFile"] = policyFile
        policyConfiguration = self.policyConfiguration()
        check_type("policyConfiguration", policyConfiguration, "runtime.RawExtension")
        v["policyConfiguration"] = policyConfiguration
        logFormat = self.logFormat()
        check_type("logFormat", logFormat, LogFormatType)
        v["logFormat"] = logFormat
        webHookKubeConfig = self.webHookKubeConfig()
        check_type("webHookKubeConfig", webHookKubeConfig, str)
        v["webHookKubeConfig"] = webHookKubeConfig
        webHookMode = self.webHookMode()
        check_type("webHookMode", webHookMode, WebHookModeType)
        v["webHookMode"] = webHookMode
        return v

    def enabled(self) -> bool:
        """
        If this flag is set, audit log will be printed in the logs.
        The logs contains, method, user and a requested URL.
        """
        return self.__enabled

    def auditFilePath(self) -> str:
        """
        All requests coming to the apiserver will be logged to this file.
        """
        return self.__auditFilePath

    def maximumFileRetentionDays(self) -> int:
        """
        Maximum number of days to retain old log files based on the timestamp encoded in their filename.
        """
        return self.__maximumFileRetentionDays

    def maximumRetainedFiles(self) -> int:
        """
        Maximum number of old log files to retain.
        """
        return self.__maximumRetainedFiles

    def maximumFileSizeMegabytes(self) -> int:
        """
        Maximum size in megabytes of the log file before it gets rotated. Defaults to 100MB.
        """
        return self.__maximumFileSizeMegabytes

    def policyFile(self) -> str:
        """
        PolicyFile is a path to the file that defines the audit policy configuration.
        """
        return self.__policyFile

    def policyConfiguration(self) -> "runtime.RawExtension":
        """
        PolicyConfiguration is an embedded policy configuration object to be used
        as the audit policy configuration. If present, it will be used instead of
        the path to the policy file.
        +nullable
        """
        return self.__policyConfiguration

    def logFormat(self) -> LogFormatType:
        """
        Format of saved audits (legacy or json).
        """
        return self.__logFormat

    def webHookKubeConfig(self) -> str:
        """
        Path to a .kubeconfig formatted file that defines the audit webhook configuration.
        """
        return self.__webHookKubeConfig

    def webHookMode(self) -> WebHookModeType:
        """
        Strategy for sending audit events (block or batch).
        """
        return self.__webHookMode


class WebhookTokenAuthenticator(types.Object):
    """
    webhookTokenAuthenticator holds the necessary configuration options for a remote token authenticator
    """

    @context.scoped
    @typechecked
    def __init__(self, kubeConfig: "SecretNameReference" = None):
        super().__init__()
        self.__kubeConfig = (
            kubeConfig if kubeConfig is not None else SecretNameReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kubeConfig = self.kubeConfig()
        check_type("kubeConfig", kubeConfig, "SecretNameReference")
        v["kubeConfig"] = kubeConfig
        return v

    def kubeConfig(self) -> "SecretNameReference":
        """
        kubeConfig contains kube config file data which describes how to access the remote webhook service.
        For further details, see:
        https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication
        The key "kubeConfig" is used to locate the data.
        If the secret or expected key is not found, the webhook is not honored.
        If the specified kube config data is not valid, the webhook is not honored.
        The namespace for this secret is determined by the point of use.
        """
        return self.__kubeConfig


class AuthenticationSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        type: AuthenticationType = None,
        oauthMetadata: "ConfigMapNameReference" = None,
        webhookTokenAuthenticators: List["WebhookTokenAuthenticator"] = None,
    ):
        super().__init__()
        self.__type = type
        self.__oauthMetadata = (
            oauthMetadata if oauthMetadata is not None else ConfigMapNameReference()
        )
        self.__webhookTokenAuthenticators = (
            webhookTokenAuthenticators if webhookTokenAuthenticators is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, AuthenticationType)
        v["type"] = type
        oauthMetadata = self.oauthMetadata()
        check_type("oauthMetadata", oauthMetadata, "ConfigMapNameReference")
        v["oauthMetadata"] = oauthMetadata
        webhookTokenAuthenticators = self.webhookTokenAuthenticators()
        check_type(
            "webhookTokenAuthenticators",
            webhookTokenAuthenticators,
            Optional[List["WebhookTokenAuthenticator"]],
        )
        if webhookTokenAuthenticators:  # omit empty
            v["webhookTokenAuthenticators"] = webhookTokenAuthenticators
        return v

    def type(self) -> AuthenticationType:
        """
        type identifies the cluster managed, user facing authentication mode in use.
        Specifically, it manages the component that responds to login attempts.
        The default is IntegratedOAuth.
        """
        return self.__type

    def oauthMetadata(self) -> "ConfigMapNameReference":
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
        return self.__oauthMetadata

    def webhookTokenAuthenticators(self) -> Optional[List["WebhookTokenAuthenticator"]]:
        """
        webhookTokenAuthenticators configures remote token reviewers.
        These remote authentication webhooks can be used to verify bearer tokens
        via the tokenreviews.authentication.k8s.io REST API.  This is required to
        honor bearer tokens that are provisioned by an external authentication service.
        The namespace for these secrets is openshift-config.
        """
        return self.__webhookTokenAuthenticators


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
            apiVersion="config.openshift.io/v1",
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
        tlsClientCert: "SecretNameReference" = None,
        tlsClientKey: "SecretNameReference" = None,
    ):
        super().__init__()
        self.__url = url
        self.__ca = ca if ca is not None else ConfigMapNameReference()
        self.__tlsClientCert = (
            tlsClientCert if tlsClientCert is not None else SecretNameReference()
        )
        self.__tlsClientKey = (
            tlsClientKey if tlsClientKey is not None else SecretNameReference()
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
        tlsClientCert = self.tlsClientCert()
        check_type("tlsClientCert", tlsClientCert, "SecretNameReference")
        v["tlsClientCert"] = tlsClientCert
        tlsClientKey = self.tlsClientKey()
        check_type("tlsClientKey", tlsClientKey, "SecretNameReference")
        v["tlsClientKey"] = tlsClientKey
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

    def tlsClientCert(self) -> "SecretNameReference":
        """
        tlsClientCert is an optional reference to a secret by name that contains the
        PEM-encoded TLS client certificate to present when connecting to the server.
        The key "tls.crt" is used to locate the data.
        If specified and the secret or expected key is not found, the identity provider is not honored.
        If the specified certificate data is not valid, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__tlsClientCert

    def tlsClientKey(self) -> "SecretNameReference":
        """
        tlsClientKey is an optional reference to a secret by name that contains the
        PEM-encoded TLS private key for the client certificate referenced in tlsClientCert.
        The key "tls.key" is used to locate the data.
        If specified and the secret or expected key is not found, the identity provider is not honored.
        If the specified certificate data is not valid, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__tlsClientKey


class BasicAuthIdentityProvider(types.Object):
    """
    BasicAuthPasswordIdentityProvider provides identities for users authenticating using HTTP basic auth credentials
    """

    @context.scoped
    @typechecked
    def __init__(self, oAuthRemoteConnectionInfo: "OAuthRemoteConnectionInfo" = None):
        super().__init__()
        self.__oAuthRemoteConnectionInfo = (
            oAuthRemoteConnectionInfo
            if oAuthRemoteConnectionInfo is not None
            else OAuthRemoteConnectionInfo()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        oAuthRemoteConnectionInfo = self.oAuthRemoteConnectionInfo()
        check_type(
            "oAuthRemoteConnectionInfo",
            oAuthRemoteConnectionInfo,
            "OAuthRemoteConnectionInfo",
        )
        v.update(oAuthRemoteConnectionInfo._root())  # inline
        return v

    def oAuthRemoteConnectionInfo(self) -> "OAuthRemoteConnectionInfo":
        """
        OAuthRemoteConnectionInfo contains information about how to connect to the external basic auth server
        """
        return self.__oAuthRemoteConnectionInfo


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
        httpProxy: str = None,
        httpsProxy: str = None,
        noProxy: str = None,
        readinessEndpoints: List[str] = None,
        trustedCA: "ConfigMapNameReference" = None,
    ):
        super().__init__()
        self.__httpProxy = httpProxy
        self.__httpsProxy = httpsProxy
        self.__noProxy = noProxy
        self.__readinessEndpoints = (
            readinessEndpoints if readinessEndpoints is not None else []
        )
        self.__trustedCA = (
            trustedCA if trustedCA is not None else ConfigMapNameReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        httpProxy = self.httpProxy()
        check_type("httpProxy", httpProxy, Optional[str])
        if httpProxy:  # omit empty
            v["httpProxy"] = httpProxy
        httpsProxy = self.httpsProxy()
        check_type("httpsProxy", httpsProxy, Optional[str])
        if httpsProxy:  # omit empty
            v["httpsProxy"] = httpsProxy
        noProxy = self.noProxy()
        check_type("noProxy", noProxy, Optional[str])
        if noProxy:  # omit empty
            v["noProxy"] = noProxy
        readinessEndpoints = self.readinessEndpoints()
        check_type("readinessEndpoints", readinessEndpoints, Optional[List[str]])
        if readinessEndpoints:  # omit empty
            v["readinessEndpoints"] = readinessEndpoints
        trustedCA = self.trustedCA()
        check_type("trustedCA", trustedCA, Optional["ConfigMapNameReference"])
        v["trustedCA"] = trustedCA
        return v

    def httpProxy(self) -> Optional[str]:
        """
        httpProxy is the URL of the proxy for HTTP requests.  Empty means unset and will not result in an env var.
        """
        return self.__httpProxy

    def httpsProxy(self) -> Optional[str]:
        """
        httpsProxy is the URL of the proxy for HTTPS requests.  Empty means unset and will not result in an env var.
        """
        return self.__httpsProxy

    def noProxy(self) -> Optional[str]:
        """
        noProxy is a comma-separated list of hostnames and/or CIDRs for which the proxy should not be used.
        Empty means unset and will not result in an env var.
        """
        return self.__noProxy

    def readinessEndpoints(self) -> Optional[List[str]]:
        """
        readinessEndpoints is a list of endpoints used to verify readiness of the proxy.
        """
        return self.__readinessEndpoints

    def trustedCA(self) -> Optional["ConfigMapNameReference"]:
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
        return self.__trustedCA


class BuildDefaults(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        defaultProxy: "ProxySpec" = None,
        gitProxy: "ProxySpec" = None,
        env: List["k8sv1.EnvVar"] = None,
        imageLabels: List["ImageLabel"] = None,
        resources: "k8sv1.ResourceRequirements" = None,
    ):
        super().__init__()
        self.__defaultProxy = defaultProxy
        self.__gitProxy = gitProxy
        self.__env = env if env is not None else []
        self.__imageLabels = imageLabels if imageLabels is not None else []
        self.__resources = (
            resources if resources is not None else k8sv1.ResourceRequirements()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        defaultProxy = self.defaultProxy()
        check_type("defaultProxy", defaultProxy, Optional["ProxySpec"])
        if defaultProxy is not None:  # omit empty
            v["defaultProxy"] = defaultProxy
        gitProxy = self.gitProxy()
        check_type("gitProxy", gitProxy, Optional["ProxySpec"])
        if gitProxy is not None:  # omit empty
            v["gitProxy"] = gitProxy
        env = self.env()
        check_type("env", env, Optional[List["k8sv1.EnvVar"]])
        if env:  # omit empty
            v["env"] = env
        imageLabels = self.imageLabels()
        check_type("imageLabels", imageLabels, Optional[List["ImageLabel"]])
        if imageLabels:  # omit empty
            v["imageLabels"] = imageLabels
        resources = self.resources()
        check_type("resources", resources, "k8sv1.ResourceRequirements")
        v["resources"] = resources
        return v

    def defaultProxy(self) -> Optional["ProxySpec"]:
        """
        DefaultProxy contains the default proxy settings for all build operations, including image pull/push
        and source download.
        
        Values can be overrode by setting the `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables
        in the build config's strategy.
        """
        return self.__defaultProxy

    def gitProxy(self) -> Optional["ProxySpec"]:
        """
        GitProxy contains the proxy settings for git operations only. If set, this will override
        any Proxy settings for all git commands, such as git clone.
        
        Values that are not set here will be inherited from DefaultProxy.
        """
        return self.__gitProxy

    def env(self) -> Optional[List["k8sv1.EnvVar"]]:
        """
        Env is a set of default environment variables that will be applied to the
        build if the specified variables do not exist on the build
        """
        return self.__env

    def imageLabels(self) -> Optional[List["ImageLabel"]]:
        """
        ImageLabels is a list of docker labels that are applied to the resulting image.
        User can override a default label by providing a label with the same name in their
        Build/BuildConfig.
        """
        return self.__imageLabels

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
        imageLabels: List["ImageLabel"] = None,
        nodeSelector: Dict[str, str] = None,
        tolerations: List["k8sv1.Toleration"] = None,
    ):
        super().__init__()
        self.__imageLabels = imageLabels if imageLabels is not None else []
        self.__nodeSelector = nodeSelector if nodeSelector is not None else {}
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        imageLabels = self.imageLabels()
        check_type("imageLabels", imageLabels, Optional[List["ImageLabel"]])
        if imageLabels:  # omit empty
            v["imageLabels"] = imageLabels
        nodeSelector = self.nodeSelector()
        check_type("nodeSelector", nodeSelector, Optional[Dict[str, str]])
        if nodeSelector:  # omit empty
            v["nodeSelector"] = nodeSelector
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    def imageLabels(self) -> Optional[List["ImageLabel"]]:
        """
        ImageLabels is a list of docker labels that are applied to the resulting image.
        If user provided a label in their Build/BuildConfig with the same name as one in this
        list, the user's label will be overwritten.
        """
        return self.__imageLabels

    def nodeSelector(self) -> Optional[Dict[str, str]]:
        """
        NodeSelector is a selector which must be true for the build pod to fit on a node
        """
        return self.__nodeSelector

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
        buildDefaults: "BuildDefaults" = None,
        buildOverrides: "BuildOverrides" = None,
    ):
        super().__init__()
        self.__buildDefaults = (
            buildDefaults if buildDefaults is not None else BuildDefaults()
        )
        self.__buildOverrides = (
            buildOverrides if buildOverrides is not None else BuildOverrides()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        buildDefaults = self.buildDefaults()
        check_type("buildDefaults", buildDefaults, "BuildDefaults")
        v["buildDefaults"] = buildDefaults
        buildOverrides = self.buildOverrides()
        check_type("buildOverrides", buildOverrides, "BuildOverrides")
        v["buildOverrides"] = buildOverrides
        return v

    def buildDefaults(self) -> "BuildDefaults":
        """
        BuildDefaults controls the default information for Builds
        """
        return self.__buildDefaults

    def buildOverrides(self) -> "BuildOverrides":
        """
        BuildOverrides controls override settings for builds
        """
        return self.__buildOverrides


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
            apiVersion="config.openshift.io/v1",
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
    def __init__(self, certFile: str = "", keyFile: str = ""):
        super().__init__()
        self.__certFile = certFile
        self.__keyFile = keyFile

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        certFile = self.certFile()
        check_type("certFile", certFile, str)
        v["certFile"] = certFile
        keyFile = self.keyFile()
        check_type("keyFile", keyFile, str)
        v["keyFile"] = keyFile
        return v

    def certFile(self) -> str:
        """
        CertFile is a file containing a PEM-encoded certificate
        """
        return self.__certFile

    def keyFile(self) -> str:
        """
        KeyFile is a file containing a PEM-encoded private key for the certificate specified by CertFile
        """
        return self.__keyFile


class ClientConnectionOverrides(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        acceptContentTypes: str = "",
        contentType: str = "",
        qps: float = float("0E+00"),
        burst: int = 0,
    ):
        super().__init__()
        self.__acceptContentTypes = acceptContentTypes
        self.__contentType = contentType
        self.__qps = qps
        self.__burst = burst

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        acceptContentTypes = self.acceptContentTypes()
        check_type("acceptContentTypes", acceptContentTypes, str)
        v["acceptContentTypes"] = acceptContentTypes
        contentType = self.contentType()
        check_type("contentType", contentType, str)
        v["contentType"] = contentType
        qps = self.qps()
        check_type("qps", qps, float)
        v["qps"] = qps
        burst = self.burst()
        check_type("burst", burst, int)
        v["burst"] = burst
        return v

    def acceptContentTypes(self) -> str:
        """
        acceptContentTypes defines the Accept header sent by clients when connecting to a server, overriding the
        default value of 'application/json'. This field will control all connections to the server used by a particular
        client.
        """
        return self.__acceptContentTypes

    def contentType(self) -> str:
        """
        contentType is the content type used when sending data to the server from this client.
        """
        return self.__contentType

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
    def __init__(self, cidr: str = "", hostPrefix: int = 0):
        super().__init__()
        self.__cidr = cidr
        self.__hostPrefix = hostPrefix

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cidr = self.cidr()
        check_type("cidr", cidr, str)
        v["cidr"] = cidr
        hostPrefix = self.hostPrefix()
        check_type("hostPrefix", hostPrefix, int)
        v["hostPrefix"] = hostPrefix
        return v

    def cidr(self) -> str:
        """
        The complete block for pod IPs.
        """
        return self.__cidr

    def hostPrefix(self) -> int:
        """
        The size (prefix) of block to allocate to each node.
        """
        return self.__hostPrefix


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
            apiVersion="config.openshift.io/v1",
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
        clusterID: ClusterID = None,
        desiredUpdate: "Update" = None,
        upstream: URL = None,
        channel: str = None,
        overrides: List["ComponentOverride"] = None,
    ):
        super().__init__()
        self.__clusterID = clusterID
        self.__desiredUpdate = desiredUpdate
        self.__upstream = upstream
        self.__channel = channel
        self.__overrides = overrides if overrides is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clusterID = self.clusterID()
        check_type("clusterID", clusterID, ClusterID)
        v["clusterID"] = clusterID
        desiredUpdate = self.desiredUpdate()
        check_type("desiredUpdate", desiredUpdate, Optional["Update"])
        if desiredUpdate is not None:  # omit empty
            v["desiredUpdate"] = desiredUpdate
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

    def clusterID(self) -> ClusterID:
        """
        clusterID uniquely identifies this cluster. This is expected to be
        an RFC4122 UUID value (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx in
        hexadecimal values). This is a required field.
        +required
        """
        return self.__clusterID

    def desiredUpdate(self) -> Optional["Update"]:
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
        return self.__desiredUpdate

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
            apiVersion="config.openshift.io/v1",
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
    def __init__(self, logoutRedirect: str = None):
        super().__init__()
        self.__logoutRedirect = logoutRedirect

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        logoutRedirect = self.logoutRedirect()
        check_type("logoutRedirect", logoutRedirect, Optional[str])
        if logoutRedirect:  # omit empty
            v["logoutRedirect"] = logoutRedirect
        return v

    def logoutRedirect(self) -> Optional[str]:
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
        return self.__logoutRedirect


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
            apiVersion="config.openshift.io/v1",
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
        baseDomain: str = "",
        publicZone: "DNSZone" = None,
        privateZone: "DNSZone" = None,
    ):
        super().__init__()
        self.__baseDomain = baseDomain
        self.__publicZone = publicZone
        self.__privateZone = privateZone

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        baseDomain = self.baseDomain()
        check_type("baseDomain", baseDomain, str)
        v["baseDomain"] = baseDomain
        publicZone = self.publicZone()
        check_type("publicZone", publicZone, Optional["DNSZone"])
        if publicZone is not None:  # omit empty
            v["publicZone"] = publicZone
        privateZone = self.privateZone()
        check_type("privateZone", privateZone, Optional["DNSZone"])
        if privateZone is not None:  # omit empty
            v["privateZone"] = privateZone
        return v

    def baseDomain(self) -> str:
        """
        baseDomain is the base domain of the cluster. All managed DNS records will
        be sub-domains of this base.
        
        For example, given the base domain `openshift.example.com`, an API server
        DNS record may be created for `cluster-api.openshift.example.com`.
        
        Once set, this field cannot be changed.
        """
        return self.__baseDomain

    def publicZone(self) -> Optional["DNSZone"]:
        """
        publicZone is the location where all the DNS records that are publicly accessible to
        the internet exist.
        
        If this field is nil, no public records should be created.
        
        Once set, this field cannot be changed.
        """
        return self.__publicZone

    def privateZone(self) -> Optional["DNSZone"]:
        """
        privateZone is the location where all the DNS records that are only available internally
        to the cluster exist.
        
        If this field is nil, no private records should be created.
        
        Once set, this field cannot be changed.
        """
        return self.__privateZone


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
            apiVersion="config.openshift.io/v1",
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


class DelegatedAuthentication(types.Object):
    """
    DelegatedAuthentication allows authentication to be disabled.
    """

    @context.scoped
    @typechecked
    def __init__(self, disabled: bool = None):
        super().__init__()
        self.__disabled = disabled

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        disabled = self.disabled()
        check_type("disabled", disabled, Optional[bool])
        if disabled:  # omit empty
            v["disabled"] = disabled
        return v

    def disabled(self) -> Optional[bool]:
        """
        disabled indicates that authentication should be disabled.  By default it will use delegated authentication.
        """
        return self.__disabled


class DelegatedAuthorization(types.Object):
    """
    DelegatedAuthorization allows authorization to be disabled.
    """

    @context.scoped
    @typechecked
    def __init__(self, disabled: bool = None):
        super().__init__()
        self.__disabled = disabled

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        disabled = self.disabled()
        check_type("disabled", disabled, Optional[bool])
        if disabled:  # omit empty
            v["disabled"] = disabled
        return v

    def disabled(self) -> Optional[bool]:
        """
        disabled indicates that authorization should be disabled.  By default it will use delegated authorization.
        """
        return self.__disabled


class EtcdConnectionInfo(types.Object):
    """
    EtcdConnectionInfo holds information necessary for connecting to an etcd server
    """

    @context.scoped
    @typechecked
    def __init__(
        self, urls: List[str] = None, ca: str = "", certInfo: "CertInfo" = None
    ):
        super().__init__()
        self.__urls = urls if urls is not None else []
        self.__ca = ca
        self.__certInfo = certInfo if certInfo is not None else CertInfo()

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
        certInfo = self.certInfo()
        check_type("certInfo", certInfo, "CertInfo")
        v.update(certInfo._root())  # inline
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

    def certInfo(self) -> "CertInfo":
        """
        CertInfo is the TLS client cert information for securing communication to etcd
        this is anonymous so that we can inline it for serialization
        """
        return self.__certInfo


class EtcdStorageConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, etcdConnectionInfo: "EtcdConnectionInfo" = None, storagePrefix: str = ""
    ):
        super().__init__()
        self.__etcdConnectionInfo = (
            etcdConnectionInfo
            if etcdConnectionInfo is not None
            else EtcdConnectionInfo()
        )
        self.__storagePrefix = storagePrefix

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        etcdConnectionInfo = self.etcdConnectionInfo()
        check_type("etcdConnectionInfo", etcdConnectionInfo, "EtcdConnectionInfo")
        v.update(etcdConnectionInfo._root())  # inline
        storagePrefix = self.storagePrefix()
        check_type("storagePrefix", storagePrefix, str)
        v["storagePrefix"] = storagePrefix
        return v

    def etcdConnectionInfo(self) -> "EtcdConnectionInfo":
        return self.__etcdConnectionInfo

    def storagePrefix(self) -> str:
        """
        StoragePrefix is the path within etcd that the OpenShift resources will
        be rooted under. This value, if changed, will mean existing objects in etcd will
        no longer be located.
        """
        return self.__storagePrefix


class ExternalIPPolicy(types.Object):
    """
    ExternalIPPolicy configures exactly which IPs are allowed for the ExternalIP
    field in a Service. If the zero struct is supplied, then none are permitted.
    The policy controller always allows automatically assigned external IPs.
    """

    @context.scoped
    @typechecked
    def __init__(self, allowedCIDRs: List[str] = None, rejectedCIDRs: List[str] = None):
        super().__init__()
        self.__allowedCIDRs = allowedCIDRs if allowedCIDRs is not None else []
        self.__rejectedCIDRs = rejectedCIDRs if rejectedCIDRs is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        allowedCIDRs = self.allowedCIDRs()
        check_type("allowedCIDRs", allowedCIDRs, Optional[List[str]])
        if allowedCIDRs:  # omit empty
            v["allowedCIDRs"] = allowedCIDRs
        rejectedCIDRs = self.rejectedCIDRs()
        check_type("rejectedCIDRs", rejectedCIDRs, Optional[List[str]])
        if rejectedCIDRs:  # omit empty
            v["rejectedCIDRs"] = rejectedCIDRs
        return v

    def allowedCIDRs(self) -> Optional[List[str]]:
        """
        allowedCIDRs is the list of allowed CIDRs.
        """
        return self.__allowedCIDRs

    def rejectedCIDRs(self) -> Optional[List[str]]:
        """
        rejectedCIDRs is the list of disallowed CIDRs. These take precedence
        over allowedCIDRs.
        """
        return self.__rejectedCIDRs


class ExternalIPConfig(types.Object):
    """
    ExternalIPConfig specifies some IP blocks relevant for the ExternalIP field
    of a Service resource.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, policy: "ExternalIPPolicy" = None, autoAssignCIDRs: List[str] = None
    ):
        super().__init__()
        self.__policy = policy
        self.__autoAssignCIDRs = autoAssignCIDRs if autoAssignCIDRs is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        policy = self.policy()
        check_type("policy", policy, Optional["ExternalIPPolicy"])
        if policy is not None:  # omit empty
            v["policy"] = policy
        autoAssignCIDRs = self.autoAssignCIDRs()
        check_type("autoAssignCIDRs", autoAssignCIDRs, Optional[List[str]])
        if autoAssignCIDRs:  # omit empty
            v["autoAssignCIDRs"] = autoAssignCIDRs
        return v

    def policy(self) -> Optional["ExternalIPPolicy"]:
        """
        policy is a set of restrictions applied to the ExternalIP field.
        If nil or empty, then ExternalIP is not allowed to be set.
        """
        return self.__policy

    def autoAssignCIDRs(self) -> Optional[List[str]]:
        """
        autoAssignCIDRs is a list of CIDRs from which to automatically assign
        Service.ExternalIP. These are assigned when the service is of type
        LoadBalancer. In general, this is only useful for bare-metal clusters.
        In Openshift 3.x, this was misleadingly called "IngressIPs".
        Automatically assigned External IPs are not affected by any
        ExternalIPPolicy rules.
        Currently, only one entry may be provided.
        """
        return self.__autoAssignCIDRs


class FeatureGateSelection(types.Object):
    """
    +union
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        featureSet: FeatureSet = None,
        customNoUpgrade: "CustomFeatureGates" = None,
    ):
        super().__init__()
        self.__featureSet = featureSet
        self.__customNoUpgrade = customNoUpgrade

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        featureSet = self.featureSet()
        check_type("featureSet", featureSet, Optional[FeatureSet])
        if featureSet:  # omit empty
            v["featureSet"] = featureSet
        customNoUpgrade = self.customNoUpgrade()
        check_type("customNoUpgrade", customNoUpgrade, Optional["CustomFeatureGates"])
        if customNoUpgrade is not None:  # omit empty
            v["customNoUpgrade"] = customNoUpgrade
        return v

    def featureSet(self) -> Optional[FeatureSet]:
        """
        featureSet changes the list of features in the cluster.  The default is empty.  Be very careful adjusting this setting.
        Turning on or off features may cause irreversible changes in your cluster which cannot be undone.
        +unionDiscriminator
        """
        return self.__featureSet

    def customNoUpgrade(self) -> Optional["CustomFeatureGates"]:
        """
        customNoUpgrade allows the enabling or disabling of any feature. Turning this feature set on IS NOT SUPPORTED, CANNOT BE UNDONE, and PREVENTS UPGRADES.
        Because of its nature, this setting cannot be validated.  If you have any typos or accidentally apply invalid combinations
        your cluster may fail in an unrecoverable way.  featureSet must equal "CustomNoUpgrade" must be set to use this field.
        +nullable
        """
        return self.__customNoUpgrade


class FeatureGateSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, featureGateSelection: "FeatureGateSelection" = None):
        super().__init__()
        self.__featureGateSelection = (
            featureGateSelection
            if featureGateSelection is not None
            else FeatureGateSelection()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        featureGateSelection = self.featureGateSelection()
        check_type("featureGateSelection", featureGateSelection, "FeatureGateSelection")
        v.update(featureGateSelection._root())  # inline
        return v

    def featureGateSelection(self) -> "FeatureGateSelection":
        return self.__featureGateSelection


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
            apiVersion="config.openshift.io/v1",
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
    def __init__(self, names: List[str] = None, certInfo: "CertInfo" = None):
        super().__init__()
        self.__names = names if names is not None else []
        self.__certInfo = certInfo if certInfo is not None else CertInfo()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        names = self.names()
        check_type("names", names, Optional[List[str]])
        if names:  # omit empty
            v["names"] = names
        certInfo = self.certInfo()
        check_type("certInfo", certInfo, "CertInfo")
        v.update(certInfo._root())  # inline
        return v

    def names(self) -> Optional[List[str]]:
        """
        Names is a list of DNS names this certificate should be used to secure
        A name can be a normal DNS name, or can contain leading wildcard segments.
        """
        return self.__names

    def certInfo(self) -> "CertInfo":
        """
        CertInfo is the TLS cert info for serving secure traffic
        """
        return self.__certInfo


class ServingInfo(types.Object):
    """
    ServingInfo holds information about serving web pages
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        bindAddress: str = "",
        bindNetwork: str = "",
        certInfo: "CertInfo" = None,
        clientCA: str = None,
        namedCertificates: List["NamedCertificate"] = None,
        minTLSVersion: str = None,
        cipherSuites: List[str] = None,
    ):
        super().__init__()
        self.__bindAddress = bindAddress
        self.__bindNetwork = bindNetwork
        self.__certInfo = certInfo if certInfo is not None else CertInfo()
        self.__clientCA = clientCA
        self.__namedCertificates = (
            namedCertificates if namedCertificates is not None else []
        )
        self.__minTLSVersion = minTLSVersion
        self.__cipherSuites = cipherSuites if cipherSuites is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        bindAddress = self.bindAddress()
        check_type("bindAddress", bindAddress, str)
        v["bindAddress"] = bindAddress
        bindNetwork = self.bindNetwork()
        check_type("bindNetwork", bindNetwork, str)
        v["bindNetwork"] = bindNetwork
        certInfo = self.certInfo()
        check_type("certInfo", certInfo, "CertInfo")
        v.update(certInfo._root())  # inline
        clientCA = self.clientCA()
        check_type("clientCA", clientCA, Optional[str])
        if clientCA:  # omit empty
            v["clientCA"] = clientCA
        namedCertificates = self.namedCertificates()
        check_type(
            "namedCertificates", namedCertificates, Optional[List["NamedCertificate"]]
        )
        if namedCertificates:  # omit empty
            v["namedCertificates"] = namedCertificates
        minTLSVersion = self.minTLSVersion()
        check_type("minTLSVersion", minTLSVersion, Optional[str])
        if minTLSVersion:  # omit empty
            v["minTLSVersion"] = minTLSVersion
        cipherSuites = self.cipherSuites()
        check_type("cipherSuites", cipherSuites, Optional[List[str]])
        if cipherSuites:  # omit empty
            v["cipherSuites"] = cipherSuites
        return v

    def bindAddress(self) -> str:
        """
        BindAddress is the ip:port to serve on
        """
        return self.__bindAddress

    def bindNetwork(self) -> str:
        """
        BindNetwork is the type of network to bind to - defaults to "tcp4", accepts "tcp",
        "tcp4", and "tcp6"
        """
        return self.__bindNetwork

    def certInfo(self) -> "CertInfo":
        """
        CertInfo is the TLS cert info for serving secure traffic.
        this is anonymous so that we can inline it for serialization
        """
        return self.__certInfo

    def clientCA(self) -> Optional[str]:
        """
        ClientCA is the certificate bundle for all the signers that you'll recognize for incoming client certificates
        """
        return self.__clientCA

    def namedCertificates(self) -> Optional[List["NamedCertificate"]]:
        """
        NamedCertificates is a list of certificates to use to secure requests to specific hostnames
        """
        return self.__namedCertificates

    def minTLSVersion(self) -> Optional[str]:
        """
        MinTLSVersion is the minimum TLS version supported.
        Values must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants
        """
        return self.__minTLSVersion

    def cipherSuites(self) -> Optional[List[str]]:
        """
        CipherSuites contains an overridden list of ciphers for the server to support.
        Values must match cipher suite IDs from https://golang.org/pkg/crypto/tls/#pkg-constants
        """
        return self.__cipherSuites


class HTTPServingInfo(types.Object):
    """
    HTTPServingInfo holds configuration for serving HTTP
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        servingInfo: "ServingInfo" = None,
        maxRequestsInFlight: int = 0,
        requestTimeoutSeconds: int = 0,
    ):
        super().__init__()
        self.__servingInfo = servingInfo if servingInfo is not None else ServingInfo()
        self.__maxRequestsInFlight = maxRequestsInFlight
        self.__requestTimeoutSeconds = requestTimeoutSeconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        servingInfo = self.servingInfo()
        check_type("servingInfo", servingInfo, "ServingInfo")
        v.update(servingInfo._root())  # inline
        maxRequestsInFlight = self.maxRequestsInFlight()
        check_type("maxRequestsInFlight", maxRequestsInFlight, int)
        v["maxRequestsInFlight"] = maxRequestsInFlight
        requestTimeoutSeconds = self.requestTimeoutSeconds()
        check_type("requestTimeoutSeconds", requestTimeoutSeconds, int)
        v["requestTimeoutSeconds"] = requestTimeoutSeconds
        return v

    def servingInfo(self) -> "ServingInfo":
        """
        ServingInfo is the HTTP serving information
        """
        return self.__servingInfo

    def maxRequestsInFlight(self) -> int:
        """
        MaxRequestsInFlight is the number of concurrent requests allowed to the server. If zero, no limit.
        """
        return self.__maxRequestsInFlight

    def requestTimeoutSeconds(self) -> int:
        """
        RequestTimeoutSeconds is the number of seconds before requests are timed out. The default is 60 minutes, if
        -1 there is no limit on requests.
        """
        return self.__requestTimeoutSeconds


class KubeClientConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        kubeConfig: str = "",
        connectionOverrides: "ClientConnectionOverrides" = None,
    ):
        super().__init__()
        self.__kubeConfig = kubeConfig
        self.__connectionOverrides = (
            connectionOverrides
            if connectionOverrides is not None
            else ClientConnectionOverrides()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kubeConfig = self.kubeConfig()
        check_type("kubeConfig", kubeConfig, str)
        v["kubeConfig"] = kubeConfig
        connectionOverrides = self.connectionOverrides()
        check_type(
            "connectionOverrides", connectionOverrides, "ClientConnectionOverrides"
        )
        v["connectionOverrides"] = connectionOverrides
        return v

    def kubeConfig(self) -> str:
        """
        kubeConfig is a .kubeconfig filename for going to the owning kube-apiserver.  Empty uses an in-cluster-config
        """
        return self.__kubeConfig

    def connectionOverrides(self) -> "ClientConnectionOverrides":
        """
        connectionOverrides specifies client overrides for system components to loop back to this master.
        """
        return self.__connectionOverrides


class GenericAPIServerConfig(types.Object):
    """
    GenericAPIServerConfig is an inline-able struct for aggregated apiservers that need to store data in etcd
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        servingInfo: "HTTPServingInfo" = None,
        corsAllowedOrigins: List[str] = None,
        auditConfig: "AuditConfig" = None,
        storageConfig: "EtcdStorageConfig" = None,
        admission: "AdmissionConfig" = None,
        kubeClientConfig: "KubeClientConfig" = None,
    ):
        super().__init__()
        self.__servingInfo = (
            servingInfo if servingInfo is not None else HTTPServingInfo()
        )
        self.__corsAllowedOrigins = (
            corsAllowedOrigins if corsAllowedOrigins is not None else []
        )
        self.__auditConfig = auditConfig if auditConfig is not None else AuditConfig()
        self.__storageConfig = (
            storageConfig if storageConfig is not None else EtcdStorageConfig()
        )
        self.__admission = admission if admission is not None else AdmissionConfig()
        self.__kubeClientConfig = (
            kubeClientConfig if kubeClientConfig is not None else KubeClientConfig()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        servingInfo = self.servingInfo()
        check_type("servingInfo", servingInfo, "HTTPServingInfo")
        v["servingInfo"] = servingInfo
        corsAllowedOrigins = self.corsAllowedOrigins()
        check_type("corsAllowedOrigins", corsAllowedOrigins, List[str])
        v["corsAllowedOrigins"] = corsAllowedOrigins
        auditConfig = self.auditConfig()
        check_type("auditConfig", auditConfig, "AuditConfig")
        v["auditConfig"] = auditConfig
        storageConfig = self.storageConfig()
        check_type("storageConfig", storageConfig, "EtcdStorageConfig")
        v["storageConfig"] = storageConfig
        admission = self.admission()
        check_type("admission", admission, "AdmissionConfig")
        v["admission"] = admission
        kubeClientConfig = self.kubeClientConfig()
        check_type("kubeClientConfig", kubeClientConfig, "KubeClientConfig")
        v["kubeClientConfig"] = kubeClientConfig
        return v

    def servingInfo(self) -> "HTTPServingInfo":
        """
        servingInfo describes how to start serving
        """
        return self.__servingInfo

    def corsAllowedOrigins(self) -> List[str]:
        """
        corsAllowedOrigins
        """
        return self.__corsAllowedOrigins

    def auditConfig(self) -> "AuditConfig":
        """
        auditConfig describes how to configure audit information
        """
        return self.__auditConfig

    def storageConfig(self) -> "EtcdStorageConfig":
        """
        storageConfig contains information about how to use
        """
        return self.__storageConfig

    def admission(self) -> "AdmissionConfig":
        """
        admissionConfig holds information about how to configure admission.
        """
        return self.__admission

    def kubeClientConfig(self) -> "KubeClientConfig":
        return self.__kubeClientConfig


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
        leaseDuration: "base.Duration" = None,
        renewDeadline: "base.Duration" = None,
        retryPeriod: "base.Duration" = None,
    ):
        super().__init__()
        self.__disable = disable
        self.__namespace = namespace
        self.__name = name
        self.__leaseDuration = (
            leaseDuration if leaseDuration is not None else metav1.Duration()
        )
        self.__renewDeadline = (
            renewDeadline if renewDeadline is not None else metav1.Duration()
        )
        self.__retryPeriod = (
            retryPeriod if retryPeriod is not None else metav1.Duration()
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
        leaseDuration = self.leaseDuration()
        check_type("leaseDuration", leaseDuration, "base.Duration")
        v["leaseDuration"] = leaseDuration
        renewDeadline = self.renewDeadline()
        check_type("renewDeadline", renewDeadline, "base.Duration")
        v["renewDeadline"] = renewDeadline
        retryPeriod = self.retryPeriod()
        check_type("retryPeriod", retryPeriod, "base.Duration")
        v["retryPeriod"] = retryPeriod
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

    def leaseDuration(self) -> "base.Duration":
        """
        leaseDuration is the duration that non-leader candidates will wait
        after observing a leadership renewal until attempting to acquire
        leadership of a led but unrenewed leader slot. This is effectively the
        maximum duration that a leader can be stopped before it is replaced
        by another candidate. This is only applicable if leader election is
        enabled.
        +nullable
        """
        return self.__leaseDuration

    def renewDeadline(self) -> "base.Duration":
        """
        renewDeadline is the interval between attempts by the acting master to
        renew a leadership slot before it stops leading. This must be less
        than or equal to the lease duration. This is only applicable if leader
        election is enabled.
        +nullable
        """
        return self.__renewDeadline

    def retryPeriod(self) -> "base.Duration":
        """
        retryPeriod is the duration the clients should wait between attempting
        acquisition and renewal of a leadership. This is only applicable if
        leader election is enabled.
        +nullable
        """
        return self.__retryPeriod


class GenericControllerConfig(types.Object):
    """
    GenericControllerConfig provides information to configure a controller
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        servingInfo: "HTTPServingInfo" = None,
        leaderElection: "LeaderElection" = None,
        authentication: "DelegatedAuthentication" = None,
        authorization: "DelegatedAuthorization" = None,
    ):
        super().__init__()
        self.__servingInfo = (
            servingInfo if servingInfo is not None else HTTPServingInfo()
        )
        self.__leaderElection = (
            leaderElection if leaderElection is not None else LeaderElection()
        )
        self.__authentication = (
            authentication if authentication is not None else DelegatedAuthentication()
        )
        self.__authorization = (
            authorization if authorization is not None else DelegatedAuthorization()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        servingInfo = self.servingInfo()
        check_type("servingInfo", servingInfo, "HTTPServingInfo")
        v["servingInfo"] = servingInfo
        leaderElection = self.leaderElection()
        check_type("leaderElection", leaderElection, "LeaderElection")
        v["leaderElection"] = leaderElection
        authentication = self.authentication()
        check_type("authentication", authentication, "DelegatedAuthentication")
        v["authentication"] = authentication
        authorization = self.authorization()
        check_type("authorization", authorization, "DelegatedAuthorization")
        v["authorization"] = authorization
        return v

    def servingInfo(self) -> "HTTPServingInfo":
        """
        ServingInfo is the HTTP serving information for the controller's endpoints
        """
        return self.__servingInfo

    def leaderElection(self) -> "LeaderElection":
        """
        leaderElection provides information to elect a leader. Only override this if you have a specific need
        """
        return self.__leaderElection

    def authentication(self) -> "DelegatedAuthentication":
        """
        authentication allows configuration of authentication for the endpoints
        """
        return self.__authentication

    def authorization(self) -> "DelegatedAuthorization":
        """
        authorization allows configuration of authentication for the endpoints
        """
        return self.__authorization


class GitHubIdentityProvider(types.Object):
    """
    GitHubIdentityProvider provides identities for users authenticating using GitHub credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        clientID: str = "",
        clientSecret: "SecretNameReference" = None,
        organizations: List[str] = None,
        teams: List[str] = None,
        hostname: str = "",
        ca: "ConfigMapNameReference" = None,
    ):
        super().__init__()
        self.__clientID = clientID
        self.__clientSecret = (
            clientSecret if clientSecret is not None else SecretNameReference()
        )
        self.__organizations = organizations if organizations is not None else []
        self.__teams = teams if teams is not None else []
        self.__hostname = hostname
        self.__ca = ca if ca is not None else ConfigMapNameReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientID = self.clientID()
        check_type("clientID", clientID, str)
        v["clientID"] = clientID
        clientSecret = self.clientSecret()
        check_type("clientSecret", clientSecret, "SecretNameReference")
        v["clientSecret"] = clientSecret
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

    def clientID(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__clientID

    def clientSecret(self) -> "SecretNameReference":
        """
        clientSecret is a required reference to the secret by name containing the oauth client secret.
        The key "clientSecret" is used to locate the data.
        If the secret or expected key is not found, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__clientSecret

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
        clientID: str = "",
        clientSecret: "SecretNameReference" = None,
        url: str = "",
        ca: "ConfigMapNameReference" = None,
    ):
        super().__init__()
        self.__clientID = clientID
        self.__clientSecret = (
            clientSecret if clientSecret is not None else SecretNameReference()
        )
        self.__url = url
        self.__ca = ca if ca is not None else ConfigMapNameReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientID = self.clientID()
        check_type("clientID", clientID, str)
        v["clientID"] = clientID
        clientSecret = self.clientSecret()
        check_type("clientSecret", clientSecret, "SecretNameReference")
        v["clientSecret"] = clientSecret
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        ca = self.ca()
        check_type("ca", ca, "ConfigMapNameReference")
        v["ca"] = ca
        return v

    def clientID(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__clientID

    def clientSecret(self) -> "SecretNameReference":
        """
        clientSecret is a required reference to the secret by name containing the oauth client secret.
        The key "clientSecret" is used to locate the data.
        If the secret or expected key is not found, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__clientSecret

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
        clientID: str = "",
        clientSecret: "SecretNameReference" = None,
        hostedDomain: str = "",
    ):
        super().__init__()
        self.__clientID = clientID
        self.__clientSecret = (
            clientSecret if clientSecret is not None else SecretNameReference()
        )
        self.__hostedDomain = hostedDomain

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientID = self.clientID()
        check_type("clientID", clientID, str)
        v["clientID"] = clientID
        clientSecret = self.clientSecret()
        check_type("clientSecret", clientSecret, "SecretNameReference")
        v["clientSecret"] = clientSecret
        hostedDomain = self.hostedDomain()
        check_type("hostedDomain", hostedDomain, str)
        v["hostedDomain"] = hostedDomain
        return v

    def clientID(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__clientID

    def clientSecret(self) -> "SecretNameReference":
        """
        clientSecret is a required reference to the secret by name containing the oauth client secret.
        The key "clientSecret" is used to locate the data.
        If the secret or expected key is not found, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__clientSecret

    def hostedDomain(self) -> str:
        """
        hostedDomain is the optional Google App domain (e.g. "mycompany.com") to restrict logins to
        """
        return self.__hostedDomain


class HTPasswdIdentityProvider(types.Object):
    """
    HTPasswdPasswordIdentityProvider provides identities for users authenticating using htpasswd credentials
    """

    @context.scoped
    @typechecked
    def __init__(self, fileData: "SecretNameReference" = None):
        super().__init__()
        self.__fileData = fileData if fileData is not None else SecretNameReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        fileData = self.fileData()
        check_type("fileData", fileData, "SecretNameReference")
        v["fileData"] = fileData
        return v

    def fileData(self) -> "SecretNameReference":
        """
        fileData is a required reference to a secret by name containing the data to use as the htpasswd file.
        The key "htpasswd" is used to locate the data.
        If the secret or expected key is not found, the identity provider is not honored.
        If the specified htpasswd data is not valid, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__fileData


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
        oAuthRemoteConnectionInfo: "OAuthRemoteConnectionInfo" = None,
        domainName: str = "",
    ):
        super().__init__()
        self.__oAuthRemoteConnectionInfo = (
            oAuthRemoteConnectionInfo
            if oAuthRemoteConnectionInfo is not None
            else OAuthRemoteConnectionInfo()
        )
        self.__domainName = domainName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        oAuthRemoteConnectionInfo = self.oAuthRemoteConnectionInfo()
        check_type(
            "oAuthRemoteConnectionInfo",
            oAuthRemoteConnectionInfo,
            "OAuthRemoteConnectionInfo",
        )
        v.update(oAuthRemoteConnectionInfo._root())  # inline
        domainName = self.domainName()
        check_type("domainName", domainName, str)
        v["domainName"] = domainName
        return v

    def oAuthRemoteConnectionInfo(self) -> "OAuthRemoteConnectionInfo":
        """
        OAuthRemoteConnectionInfo contains information about how to connect to the keystone server
        """
        return self.__oAuthRemoteConnectionInfo

    def domainName(self) -> str:
        """
        domainName is required for keystone v3
        """
        return self.__domainName


class LDAPAttributeMapping(types.Object):
    """
    LDAPAttributeMapping maps LDAP attributes to OpenShift identity fields
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        id: List[str] = None,
        preferredUsername: List[str] = None,
        name: List[str] = None,
        email: List[str] = None,
    ):
        super().__init__()
        self.__id = id if id is not None else []
        self.__preferredUsername = (
            preferredUsername if preferredUsername is not None else []
        )
        self.__name = name if name is not None else []
        self.__email = email if email is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        id = self.id()
        check_type("id", id, List[str])
        v["id"] = id
        preferredUsername = self.preferredUsername()
        check_type("preferredUsername", preferredUsername, Optional[List[str]])
        if preferredUsername:  # omit empty
            v["preferredUsername"] = preferredUsername
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

    def preferredUsername(self) -> Optional[List[str]]:
        """
        preferredUsername is the list of attributes whose values should be used as the preferred username.
        LDAP standard login attribute is "uid"
        """
        return self.__preferredUsername

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
        bindDN: str = "",
        bindPassword: "SecretNameReference" = None,
        insecure: bool = False,
        ca: "ConfigMapNameReference" = None,
        attributes: "LDAPAttributeMapping" = None,
    ):
        super().__init__()
        self.__url = url
        self.__bindDN = bindDN
        self.__bindPassword = (
            bindPassword if bindPassword is not None else SecretNameReference()
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
        bindDN = self.bindDN()
        check_type("bindDN", bindDN, str)
        v["bindDN"] = bindDN
        bindPassword = self.bindPassword()
        check_type("bindPassword", bindPassword, "SecretNameReference")
        v["bindPassword"] = bindPassword
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

    def bindDN(self) -> str:
        """
        bindDN is an optional DN to bind with during the search phase.
        """
        return self.__bindDN

    def bindPassword(self) -> "SecretNameReference":
        """
        bindPassword is an optional reference to a secret by name
        containing a password to bind with during the search phase.
        The key "bindPassword" is used to locate the data.
        If specified and the secret or expected key is not found, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__bindPassword

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
        preferredUsername: List[str] = None,
        name: List[str] = None,
        email: List[str] = None,
    ):
        super().__init__()
        self.__preferredUsername = (
            preferredUsername if preferredUsername is not None else []
        )
        self.__name = name if name is not None else []
        self.__email = email if email is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        preferredUsername = self.preferredUsername()
        check_type("preferredUsername", preferredUsername, Optional[List[str]])
        if preferredUsername:  # omit empty
            v["preferredUsername"] = preferredUsername
        name = self.name()
        check_type("name", name, Optional[List[str]])
        if name:  # omit empty
            v["name"] = name
        email = self.email()
        check_type("email", email, Optional[List[str]])
        if email:  # omit empty
            v["email"] = email
        return v

    def preferredUsername(self) -> Optional[List[str]]:
        """
        preferredUsername is the list of claims whose values should be used as the preferred username.
        If unspecified, the preferred username is determined from the value of the sub claim
        """
        return self.__preferredUsername

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
        clientID: str = "",
        clientSecret: "SecretNameReference" = None,
        ca: "ConfigMapNameReference" = None,
        extraScopes: List[str] = None,
        extraAuthorizeParameters: Dict[str, str] = None,
        issuer: str = "",
        claims: "OpenIDClaims" = None,
    ):
        super().__init__()
        self.__clientID = clientID
        self.__clientSecret = (
            clientSecret if clientSecret is not None else SecretNameReference()
        )
        self.__ca = ca if ca is not None else ConfigMapNameReference()
        self.__extraScopes = extraScopes if extraScopes is not None else []
        self.__extraAuthorizeParameters = (
            extraAuthorizeParameters if extraAuthorizeParameters is not None else {}
        )
        self.__issuer = issuer
        self.__claims = claims if claims is not None else OpenIDClaims()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientID = self.clientID()
        check_type("clientID", clientID, str)
        v["clientID"] = clientID
        clientSecret = self.clientSecret()
        check_type("clientSecret", clientSecret, "SecretNameReference")
        v["clientSecret"] = clientSecret
        ca = self.ca()
        check_type("ca", ca, "ConfigMapNameReference")
        v["ca"] = ca
        extraScopes = self.extraScopes()
        check_type("extraScopes", extraScopes, Optional[List[str]])
        if extraScopes:  # omit empty
            v["extraScopes"] = extraScopes
        extraAuthorizeParameters = self.extraAuthorizeParameters()
        check_type(
            "extraAuthorizeParameters",
            extraAuthorizeParameters,
            Optional[Dict[str, str]],
        )
        if extraAuthorizeParameters:  # omit empty
            v["extraAuthorizeParameters"] = extraAuthorizeParameters
        issuer = self.issuer()
        check_type("issuer", issuer, str)
        v["issuer"] = issuer
        claims = self.claims()
        check_type("claims", claims, "OpenIDClaims")
        v["claims"] = claims
        return v

    def clientID(self) -> str:
        """
        clientID is the oauth client ID
        """
        return self.__clientID

    def clientSecret(self) -> "SecretNameReference":
        """
        clientSecret is a required reference to the secret by name containing the oauth client secret.
        The key "clientSecret" is used to locate the data.
        If the secret or expected key is not found, the identity provider is not honored.
        The namespace for this secret is openshift-config.
        """
        return self.__clientSecret

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

    def extraScopes(self) -> Optional[List[str]]:
        """
        extraScopes are any scopes to request in addition to the standard "openid" scope.
        """
        return self.__extraScopes

    def extraAuthorizeParameters(self) -> Optional[Dict[str, str]]:
        """
        extraAuthorizeParameters are any custom parameters to add to the authorize request.
        """
        return self.__extraAuthorizeParameters

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
        loginURL: str = "",
        challengeURL: str = "",
        ca: "ConfigMapNameReference" = None,
        clientCommonNames: List[str] = None,
        headers: List[str] = None,
        preferredUsernameHeaders: List[str] = None,
        nameHeaders: List[str] = None,
        emailHeaders: List[str] = None,
    ):
        super().__init__()
        self.__loginURL = loginURL
        self.__challengeURL = challengeURL
        self.__ca = ca if ca is not None else ConfigMapNameReference()
        self.__clientCommonNames = (
            clientCommonNames if clientCommonNames is not None else []
        )
        self.__headers = headers if headers is not None else []
        self.__preferredUsernameHeaders = (
            preferredUsernameHeaders if preferredUsernameHeaders is not None else []
        )
        self.__nameHeaders = nameHeaders if nameHeaders is not None else []
        self.__emailHeaders = emailHeaders if emailHeaders is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        loginURL = self.loginURL()
        check_type("loginURL", loginURL, str)
        v["loginURL"] = loginURL
        challengeURL = self.challengeURL()
        check_type("challengeURL", challengeURL, str)
        v["challengeURL"] = challengeURL
        ca = self.ca()
        check_type("ca", ca, "ConfigMapNameReference")
        v["ca"] = ca
        clientCommonNames = self.clientCommonNames()
        check_type("clientCommonNames", clientCommonNames, Optional[List[str]])
        if clientCommonNames:  # omit empty
            v["clientCommonNames"] = clientCommonNames
        headers = self.headers()
        check_type("headers", headers, List[str])
        v["headers"] = headers
        preferredUsernameHeaders = self.preferredUsernameHeaders()
        check_type("preferredUsernameHeaders", preferredUsernameHeaders, List[str])
        v["preferredUsernameHeaders"] = preferredUsernameHeaders
        nameHeaders = self.nameHeaders()
        check_type("nameHeaders", nameHeaders, List[str])
        v["nameHeaders"] = nameHeaders
        emailHeaders = self.emailHeaders()
        check_type("emailHeaders", emailHeaders, List[str])
        v["emailHeaders"] = emailHeaders
        return v

    def loginURL(self) -> str:
        """
        loginURL is a URL to redirect unauthenticated /authorize requests to
        Unauthenticated requests from OAuth clients which expect interactive logins will be redirected here
        ${url} is replaced with the current URL, escaped to be safe in a query parameter
          https://www.example.com/sso-login?then=${url}
        ${query} is replaced with the current query string
          https://www.example.com/auth-proxy/oauth/authorize?${query}
        Required when login is set to true.
        """
        return self.__loginURL

    def challengeURL(self) -> str:
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
        return self.__challengeURL

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

    def clientCommonNames(self) -> Optional[List[str]]:
        """
        clientCommonNames is an optional list of common names to require a match from. If empty, any
        client certificate validated against the clientCA bundle is considered authoritative.
        """
        return self.__clientCommonNames

    def headers(self) -> List[str]:
        """
        headers is the set of headers to check for identity information
        """
        return self.__headers

    def preferredUsernameHeaders(self) -> List[str]:
        """
        preferredUsernameHeaders is the set of headers to check for the preferred username
        """
        return self.__preferredUsernameHeaders

    def nameHeaders(self) -> List[str]:
        """
        nameHeaders is the set of headers to check for the display name
        """
        return self.__nameHeaders

    def emailHeaders(self) -> List[str]:
        """
        emailHeaders is the set of headers to check for the email address
        """
        return self.__emailHeaders


class IdentityProviderConfig(types.Object):
    """
    IdentityProviderConfig contains configuration for using a specific identity provider
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        type: IdentityProviderType = None,
        basicAuth: "BasicAuthIdentityProvider" = None,
        github: "GitHubIdentityProvider" = None,
        gitlab: "GitLabIdentityProvider" = None,
        google: "GoogleIdentityProvider" = None,
        htpasswd: "HTPasswdIdentityProvider" = None,
        keystone: "KeystoneIdentityProvider" = None,
        ldap: "LDAPIdentityProvider" = None,
        openID: "OpenIDIdentityProvider" = None,
        requestHeader: "RequestHeaderIdentityProvider" = None,
    ):
        super().__init__()
        self.__type = type
        self.__basicAuth = basicAuth
        self.__github = github
        self.__gitlab = gitlab
        self.__google = google
        self.__htpasswd = htpasswd
        self.__keystone = keystone
        self.__ldap = ldap
        self.__openID = openID
        self.__requestHeader = requestHeader

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        type = self.type()
        check_type("type", type, IdentityProviderType)
        v["type"] = type
        basicAuth = self.basicAuth()
        check_type("basicAuth", basicAuth, Optional["BasicAuthIdentityProvider"])
        if basicAuth is not None:  # omit empty
            v["basicAuth"] = basicAuth
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
        openID = self.openID()
        check_type("openID", openID, Optional["OpenIDIdentityProvider"])
        if openID is not None:  # omit empty
            v["openID"] = openID
        requestHeader = self.requestHeader()
        check_type(
            "requestHeader", requestHeader, Optional["RequestHeaderIdentityProvider"]
        )
        if requestHeader is not None:  # omit empty
            v["requestHeader"] = requestHeader
        return v

    def type(self) -> IdentityProviderType:
        """
        type identifies the identity provider type for this entry.
        """
        return self.__type

    def basicAuth(self) -> Optional["BasicAuthIdentityProvider"]:
        """
        basicAuth contains configuration options for the BasicAuth IdP
        """
        return self.__basicAuth

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

    def openID(self) -> Optional["OpenIDIdentityProvider"]:
        """
        openID enables user authentication using OpenID credentials
        """
        return self.__openID

    def requestHeader(self) -> Optional["RequestHeaderIdentityProvider"]:
        """
        requestHeader enables user authentication using request header credentials
        """
        return self.__requestHeader


class IdentityProvider(types.Object):
    """
    IdentityProvider provides identities for users authenticating using credentials
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        mappingMethod: MappingMethodType = None,
        identityProviderConfig: "IdentityProviderConfig" = None,
    ):
        super().__init__()
        self.__name = name
        self.__mappingMethod = mappingMethod
        self.__identityProviderConfig = (
            identityProviderConfig
            if identityProviderConfig is not None
            else IdentityProviderConfig()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        mappingMethod = self.mappingMethod()
        check_type("mappingMethod", mappingMethod, Optional[MappingMethodType])
        if mappingMethod:  # omit empty
            v["mappingMethod"] = mappingMethod
        identityProviderConfig = self.identityProviderConfig()
        check_type(
            "identityProviderConfig", identityProviderConfig, "IdentityProviderConfig"
        )
        v.update(identityProviderConfig._root())  # inline
        return v

    def name(self) -> str:
        """
        name is used to qualify the identities returned by this provider.
        - It MUST be unique and not shared by any other identity provider used
        - It MUST be a valid path segment: name cannot equal "." or ".." or contain "/" or "%" or ":"
          Ref: https://godoc.org/github.com/openshift/origin/pkg/user/apis/user/validation#ValidateIdentityProviderName
        """
        return self.__name

    def mappingMethod(self) -> Optional[MappingMethodType]:
        """
        mappingMethod determines how identities from this provider are mapped to users
        Defaults to "claim"
        """
        return self.__mappingMethod

    def identityProviderConfig(self) -> "IdentityProviderConfig":
        return self.__identityProviderConfig


class RegistryLocation(types.Object):
    """
    RegistryLocation contains a location of the registry specified by the registry domain
    name. The domain name might include wildcards, like '*' or '??'.
    """

    @context.scoped
    @typechecked
    def __init__(self, domainName: str = "", insecure: bool = None):
        super().__init__()
        self.__domainName = domainName
        self.__insecure = insecure

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        domainName = self.domainName()
        check_type("domainName", domainName, str)
        v["domainName"] = domainName
        insecure = self.insecure()
        check_type("insecure", insecure, Optional[bool])
        if insecure:  # omit empty
            v["insecure"] = insecure
        return v

    def domainName(self) -> str:
        """
        domainName specifies a domain name for the registry
        In case the registry use non-standard (80 or 443) port, the port should be included
        in the domain name as well.
        """
        return self.__domainName

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
        insecureRegistries: List[str] = None,
        blockedRegistries: List[str] = None,
        allowedRegistries: List[str] = None,
    ):
        super().__init__()
        self.__insecureRegistries = (
            insecureRegistries if insecureRegistries is not None else []
        )
        self.__blockedRegistries = (
            blockedRegistries if blockedRegistries is not None else []
        )
        self.__allowedRegistries = (
            allowedRegistries if allowedRegistries is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        insecureRegistries = self.insecureRegistries()
        check_type("insecureRegistries", insecureRegistries, Optional[List[str]])
        if insecureRegistries:  # omit empty
            v["insecureRegistries"] = insecureRegistries
        blockedRegistries = self.blockedRegistries()
        check_type("blockedRegistries", blockedRegistries, Optional[List[str]])
        if blockedRegistries:  # omit empty
            v["blockedRegistries"] = blockedRegistries
        allowedRegistries = self.allowedRegistries()
        check_type("allowedRegistries", allowedRegistries, Optional[List[str]])
        if allowedRegistries:  # omit empty
            v["allowedRegistries"] = allowedRegistries
        return v

    def insecureRegistries(self) -> Optional[List[str]]:
        """
        insecureRegistries are registries which do not have a valid TLS certificates or only support HTTP connections.
        """
        return self.__insecureRegistries

    def blockedRegistries(self) -> Optional[List[str]]:
        """
        blockedRegistries are blacklisted from image pull/push. All other registries are allowed.
        
        Only one of BlockedRegistries or AllowedRegistries may be set.
        """
        return self.__blockedRegistries

    def allowedRegistries(self) -> Optional[List[str]]:
        """
        allowedRegistries are whitelisted for image pull/push. All other registries are blocked.
        
        Only one of BlockedRegistries or AllowedRegistries may be set.
        """
        return self.__allowedRegistries


class ImageSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        allowedRegistriesForImport: List["RegistryLocation"] = None,
        externalRegistryHostnames: List[str] = None,
        additionalTrustedCA: "ConfigMapNameReference" = None,
        registrySources: "RegistrySources" = None,
    ):
        super().__init__()
        self.__allowedRegistriesForImport = (
            allowedRegistriesForImport if allowedRegistriesForImport is not None else []
        )
        self.__externalRegistryHostnames = (
            externalRegistryHostnames if externalRegistryHostnames is not None else []
        )
        self.__additionalTrustedCA = (
            additionalTrustedCA
            if additionalTrustedCA is not None
            else ConfigMapNameReference()
        )
        self.__registrySources = (
            registrySources if registrySources is not None else RegistrySources()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        allowedRegistriesForImport = self.allowedRegistriesForImport()
        check_type(
            "allowedRegistriesForImport",
            allowedRegistriesForImport,
            Optional[List["RegistryLocation"]],
        )
        if allowedRegistriesForImport:  # omit empty
            v["allowedRegistriesForImport"] = allowedRegistriesForImport
        externalRegistryHostnames = self.externalRegistryHostnames()
        check_type(
            "externalRegistryHostnames", externalRegistryHostnames, Optional[List[str]]
        )
        if externalRegistryHostnames:  # omit empty
            v["externalRegistryHostnames"] = externalRegistryHostnames
        additionalTrustedCA = self.additionalTrustedCA()
        check_type("additionalTrustedCA", additionalTrustedCA, "ConfigMapNameReference")
        v["additionalTrustedCA"] = additionalTrustedCA
        registrySources = self.registrySources()
        check_type("registrySources", registrySources, "RegistrySources")
        v["registrySources"] = registrySources
        return v

    def allowedRegistriesForImport(self) -> Optional[List["RegistryLocation"]]:
        """
        allowedRegistriesForImport limits the container image registries that normal users may import
        images from. Set this list to the registries that you trust to contain valid Docker
        images and that you want applications to be able to import from. Users with
        permission to create Images or ImageStreamMappings via the API are not affected by
        this policy - typically only administrators or system integrations will have those
        permissions.
        """
        return self.__allowedRegistriesForImport

    def externalRegistryHostnames(self) -> Optional[List[str]]:
        """
        externalRegistryHostnames provides the hostnames for the default external image
        registry. The external hostname should be set only when the image registry
        is exposed externally. The first value is used in 'publicDockerImageRepository'
        field in ImageStreams. The value must be in "hostname[:port]" format.
        """
        return self.__externalRegistryHostnames

    def additionalTrustedCA(self) -> "ConfigMapNameReference":
        """
        additionalTrustedCA is a reference to a ConfigMap containing additional CAs that
        should be trusted during imagestream import, pod image pull, build image pull, and
        imageregistry pullthrough.
        The namespace for this config map is openshift-config.
        """
        return self.__additionalTrustedCA

    def registrySources(self) -> "RegistrySources":
        """
        registrySources contains configuration that determines how the container runtime
        should treat individual registries when accessing images for builds+pods. (e.g.
        whether or not to allow insecure access).  It does not contain configuration for the
        internal cluster registry.
        """
        return self.__registrySources


class Image(base.TypedObject, base.MetadataObject):
    """
    Image governs policies related to imagestream imports and runtime configuration
    for external registries. It allows cluster admins to configure which registries
    OpenShift is allowed to import images from, extra CA trust bundles for external
    registries, and policies to blacklist/whitelist registry hostnames.
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
            apiVersion="config.openshift.io/v1",
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
    def __init__(self, cloudConfig: "ConfigMapFileReference" = None):
        super().__init__()
        self.__cloudConfig = (
            cloudConfig if cloudConfig is not None else ConfigMapFileReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cloudConfig = self.cloudConfig()
        check_type("cloudConfig", cloudConfig, "ConfigMapFileReference")
        v["cloudConfig"] = cloudConfig
        return v

    def cloudConfig(self) -> "ConfigMapFileReference":
        """
        cloudConfig is a reference to a ConfigMap containing the cloud provider configuration file.
        This configuration file is used to configure the Kubernetes cloud provider integration
        when using the built-in cloud provider integration or the external cloud controller manager.
        The namespace for this config map is openshift-config.
        """
        return self.__cloudConfig


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
            apiVersion="config.openshift.io/v1",
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
            apiVersion="config.openshift.io/v1",
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
        clusterNetwork: List["ClusterNetworkEntry"] = None,
        serviceNetwork: List[str] = None,
        networkType: str = "",
        externalIP: "ExternalIPConfig" = None,
    ):
        super().__init__()
        self.__clusterNetwork = clusterNetwork if clusterNetwork is not None else []
        self.__serviceNetwork = serviceNetwork if serviceNetwork is not None else []
        self.__networkType = networkType
        self.__externalIP = externalIP

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clusterNetwork = self.clusterNetwork()
        check_type("clusterNetwork", clusterNetwork, List["ClusterNetworkEntry"])
        v["clusterNetwork"] = clusterNetwork
        serviceNetwork = self.serviceNetwork()
        check_type("serviceNetwork", serviceNetwork, List[str])
        v["serviceNetwork"] = serviceNetwork
        networkType = self.networkType()
        check_type("networkType", networkType, str)
        v["networkType"] = networkType
        externalIP = self.externalIP()
        check_type("externalIP", externalIP, Optional["ExternalIPConfig"])
        if externalIP is not None:  # omit empty
            v["externalIP"] = externalIP
        return v

    def clusterNetwork(self) -> List["ClusterNetworkEntry"]:
        """
        IP address pool to use for pod IPs.
        This field is immutable after installation.
        """
        return self.__clusterNetwork

    def serviceNetwork(self) -> List[str]:
        """
        IP address pool for services.
        Currently, we only support a single entry here.
        This field is immutable after installation.
        """
        return self.__serviceNetwork

    def networkType(self) -> str:
        """
        NetworkType is the plugin that is to be deployed (e.g. OpenShiftSDN).
        This should match a value that the cluster-network-operator understands,
        or else no networking will be installed.
        Currently supported values are:
        - OpenShiftSDN
        This field is immutable after installation.
        """
        return self.__networkType

    def externalIP(self) -> Optional["ExternalIPConfig"]:
        """
        externalIP defines configuration for controllers that
        affect Service.ExternalIP. If nil, then ExternalIP is
        not allowed to be set.
        """
        return self.__externalIP


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
            apiVersion="config.openshift.io/v1",
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
        providerSelection: "SecretNameReference" = None,
        error: "SecretNameReference" = None,
    ):
        super().__init__()
        self.__login = login if login is not None else SecretNameReference()
        self.__providerSelection = (
            providerSelection
            if providerSelection is not None
            else SecretNameReference()
        )
        self.__error = error if error is not None else SecretNameReference()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        login = self.login()
        check_type("login", login, "SecretNameReference")
        v["login"] = login
        providerSelection = self.providerSelection()
        check_type("providerSelection", providerSelection, "SecretNameReference")
        v["providerSelection"] = providerSelection
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

    def providerSelection(self) -> "SecretNameReference":
        """
        providerSelection is the name of a secret that specifies a go template to use to render
        the provider selection page.
        The key "providers.html" is used to locate the template data.
        If specified and the secret or expected key is not found, the default provider selection page is used.
        If the specified template is not valid, the default provider selection page is used.
        If unspecified, the default provider selection page is used.
        The namespace for this secret is openshift-config.
        """
        return self.__providerSelection

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
        accessTokenMaxAgeSeconds: int = 0,
        accessTokenInactivityTimeoutSeconds: int = None,
    ):
        super().__init__()
        self.__accessTokenMaxAgeSeconds = accessTokenMaxAgeSeconds
        self.__accessTokenInactivityTimeoutSeconds = accessTokenInactivityTimeoutSeconds

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        accessTokenMaxAgeSeconds = self.accessTokenMaxAgeSeconds()
        check_type("accessTokenMaxAgeSeconds", accessTokenMaxAgeSeconds, int)
        v["accessTokenMaxAgeSeconds"] = accessTokenMaxAgeSeconds
        accessTokenInactivityTimeoutSeconds = self.accessTokenInactivityTimeoutSeconds()
        check_type(
            "accessTokenInactivityTimeoutSeconds",
            accessTokenInactivityTimeoutSeconds,
            Optional[int],
        )
        if accessTokenInactivityTimeoutSeconds:  # omit empty
            v[
                "accessTokenInactivityTimeoutSeconds"
            ] = accessTokenInactivityTimeoutSeconds
        return v

    def accessTokenMaxAgeSeconds(self) -> int:
        """
        accessTokenMaxAgeSeconds defines the maximum age of access tokens
        """
        return self.__accessTokenMaxAgeSeconds

    def accessTokenInactivityTimeoutSeconds(self) -> Optional[int]:
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
        return self.__accessTokenInactivityTimeoutSeconds


class OAuthSpec(types.Object):
    """
    OAuthSpec contains desired cluster auth configuration
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        identityProviders: List["IdentityProvider"] = None,
        tokenConfig: "TokenConfig" = None,
        templates: "OAuthTemplates" = None,
    ):
        super().__init__()
        self.__identityProviders = (
            identityProviders if identityProviders is not None else []
        )
        self.__tokenConfig = tokenConfig if tokenConfig is not None else TokenConfig()
        self.__templates = templates if templates is not None else OAuthTemplates()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        identityProviders = self.identityProviders()
        check_type(
            "identityProviders", identityProviders, Optional[List["IdentityProvider"]]
        )
        if identityProviders:  # omit empty
            v["identityProviders"] = identityProviders
        tokenConfig = self.tokenConfig()
        check_type("tokenConfig", tokenConfig, "TokenConfig")
        v["tokenConfig"] = tokenConfig
        templates = self.templates()
        check_type("templates", templates, "OAuthTemplates")
        v["templates"] = templates
        return v

    def identityProviders(self) -> Optional[List["IdentityProvider"]]:
        """
        identityProviders is an ordered list of ways for a user to identify themselves.
        When this list is empty, no identities are provisioned for users.
        """
        return self.__identityProviders

    def tokenConfig(self) -> "TokenConfig":
        """
        tokenConfig contains options for authorization and access tokens
        """
        return self.__tokenConfig

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
            apiVersion="config.openshift.io/v1",
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
        self, disableAllDefaultSources: bool = None, sources: List["HubSource"] = None
    ):
        super().__init__()
        self.__disableAllDefaultSources = disableAllDefaultSources
        self.__sources = sources if sources is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        disableAllDefaultSources = self.disableAllDefaultSources()
        check_type("disableAllDefaultSources", disableAllDefaultSources, Optional[bool])
        if disableAllDefaultSources:  # omit empty
            v["disableAllDefaultSources"] = disableAllDefaultSources
        sources = self.sources()
        check_type("sources", sources, Optional[List["HubSource"]])
        if sources:  # omit empty
            v["sources"] = sources
        return v

    def disableAllDefaultSources(self) -> Optional[bool]:
        """
        disableAllDefaultSources allows you to disable all the default hub
        sources. If this is true, a specific entry in sources can be used to
        enable a default source. If this is false, a specific entry in
        sources can be used to disable or enable a default source.
        """
        return self.__disableAllDefaultSources

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
            apiVersion="config.openshift.io/v1",
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
        projectRequestMessage: str = "",
        projectRequestTemplate: "TemplateReference" = None,
    ):
        super().__init__()
        self.__projectRequestMessage = projectRequestMessage
        self.__projectRequestTemplate = (
            projectRequestTemplate
            if projectRequestTemplate is not None
            else TemplateReference()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        projectRequestMessage = self.projectRequestMessage()
        check_type("projectRequestMessage", projectRequestMessage, str)
        v["projectRequestMessage"] = projectRequestMessage
        projectRequestTemplate = self.projectRequestTemplate()
        check_type(
            "projectRequestTemplate", projectRequestTemplate, "TemplateReference"
        )
        v["projectRequestTemplate"] = projectRequestTemplate
        return v

    def projectRequestMessage(self) -> str:
        """
        projectRequestMessage is the string presented to a user if they are unable to request a project via the projectrequest api endpoint
        """
        return self.__projectRequestMessage

    def projectRequestTemplate(self) -> "TemplateReference":
        """
        projectRequestTemplate is the template to use for creating projects in response to projectrequest.
        This must point to a template in 'openshift-config' namespace. It is optional.
        If it is not specified, a default template is used.
        """
        return self.__projectRequestTemplate


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
            apiVersion="config.openshift.io/v1",
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
            apiVersion="config.openshift.io/v1",
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
    def __init__(self, url: str = "", ca: str = "", certInfo: "CertInfo" = None):
        super().__init__()
        self.__url = url
        self.__ca = ca
        self.__certInfo = certInfo if certInfo is not None else CertInfo()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        ca = self.ca()
        check_type("ca", ca, str)
        v["ca"] = ca
        certInfo = self.certInfo()
        check_type("certInfo", certInfo, "CertInfo")
        v.update(certInfo._root())  # inline
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

    def certInfo(self) -> "CertInfo":
        """
        CertInfo is the TLS client cert information to present
        this is anonymous so that we can inline it for serialization
        """
        return self.__certInfo


class SchedulerSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        policy: "ConfigMapNameReference" = None,
        defaultNodeSelector: str = None,
        mastersSchedulable: bool = False,
    ):
        super().__init__()
        self.__policy = policy if policy is not None else ConfigMapNameReference()
        self.__defaultNodeSelector = defaultNodeSelector
        self.__mastersSchedulable = mastersSchedulable

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        policy = self.policy()
        check_type("policy", policy, "ConfigMapNameReference")
        v["policy"] = policy
        defaultNodeSelector = self.defaultNodeSelector()
        check_type("defaultNodeSelector", defaultNodeSelector, Optional[str])
        if defaultNodeSelector:  # omit empty
            v["defaultNodeSelector"] = defaultNodeSelector
        mastersSchedulable = self.mastersSchedulable()
        check_type("mastersSchedulable", mastersSchedulable, bool)
        v["mastersSchedulable"] = mastersSchedulable
        return v

    def policy(self) -> "ConfigMapNameReference":
        """
        policy is a reference to a ConfigMap containing scheduler policy which has
        user specified predicates and priorities. If this ConfigMap is not available
        scheduler will default to use DefaultAlgorithmProvider.
        The namespace for this configmap is openshift-config.
        """
        return self.__policy

    def defaultNodeSelector(self) -> Optional[str]:
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
        return self.__defaultNodeSelector

    def mastersSchedulable(self) -> bool:
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
        return self.__mastersSchedulable


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
            apiVersion="config.openshift.io/v1",
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
        self, value: str = "", env: str = "", file: str = "", keyFile: str = ""
    ):
        super().__init__()
        self.__value = value
        self.__env = env
        self.__file = file
        self.__keyFile = keyFile

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
        keyFile = self.keyFile()
        check_type("keyFile", keyFile, str)
        v["keyFile"] = keyFile
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

    def keyFile(self) -> str:
        """
        KeyFile references a file containing the key to use to decrypt the value.
        """
        return self.__keyFile


class StringSource(types.Object):
    """
    StringSource allows specifying a string inline, or externally via env var or file.
    When it contains only a string value, it marshals to a simple JSON string.
    """

    @context.scoped
    @typechecked
    def __init__(self, stringSourceSpec: "StringSourceSpec" = None):
        super().__init__()
        self.__stringSourceSpec = (
            stringSourceSpec if stringSourceSpec is not None else StringSourceSpec()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        stringSourceSpec = self.stringSourceSpec()
        check_type("stringSourceSpec", stringSourceSpec, "StringSourceSpec")
        v.update(stringSourceSpec._root())  # inline
        return v

    def stringSourceSpec(self) -> "StringSourceSpec":
        """
        StringSourceSpec specifies the string value, or external location
        """
        return self.__stringSourceSpec
