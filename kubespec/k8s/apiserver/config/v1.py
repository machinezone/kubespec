# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from kubespec.k8s import base
from kubespec.k8s.apimachinery.meta import v1 as metav1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


class Key(types.Object):
    """
    Key contains name and secret of the provided key for a transformer.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", secret: str = ""):
        super().__init__()
        self.__name = name
        self.__secret = secret

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        secret = self.secret()
        check_type("secret", secret, str)
        v["secret"] = secret
        return v

    def name(self) -> str:
        """
        name is the name of the key to be used while storing data to disk.
        """
        return self.__name

    def secret(self) -> str:
        """
        secret is the actual key, encoded in base64.
        """
        return self.__secret


class AESConfiguration(types.Object):
    """
    AESConfiguration contains the API configuration for an AES transformer.
    """

    @context.scoped
    @typechecked
    def __init__(self, keys: Dict[str, "Key"] = None):
        super().__init__()
        self.__keys = keys if keys is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        keys = self.keys()
        check_type("keys", keys, Dict[str, "Key"])
        v["keys"] = keys.values()  # named list
        return v

    def keys(self) -> Dict[str, "Key"]:
        """
        keys is a list of keys to be used for creating the AES transformer.
        Each key has to be 32 bytes long for AES-CBC and 16, 24 or 32 bytes for AES-GCM.
        """
        return self.__keys


class IdentityConfiguration(types.Object):
    """
    IdentityConfiguration is an empty struct to allow identity transformer in provider configuration.
    """

    pass  # FIXME


class KMSConfiguration(types.Object):
    """
    KMSConfiguration contains the name, cache size and path to configuration file for a KMS based envelope transformer.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        cachesize: int = None,
        endpoint: str = "",
        timeout: "base.Duration" = None,
    ):
        super().__init__()
        self.__name = name
        self.__cachesize = cachesize
        self.__endpoint = endpoint
        self.__timeout = timeout

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        cachesize = self.cachesize()
        check_type("cachesize", cachesize, Optional[int])
        if cachesize:  # omit empty
            v["cachesize"] = cachesize
        endpoint = self.endpoint()
        check_type("endpoint", endpoint, str)
        v["endpoint"] = endpoint
        timeout = self.timeout()
        check_type("timeout", timeout, Optional["base.Duration"])
        if timeout is not None:  # omit empty
            v["timeout"] = timeout
        return v

    def name(self) -> str:
        """
        name is the name of the KMS plugin to be used.
        """
        return self.__name

    def cachesize(self) -> Optional[int]:
        """
        cacheSize is the maximum number of secrets which are cached in memory. The default value is 1000.
        """
        return self.__cachesize

    def endpoint(self) -> str:
        """
        endpoint is the gRPC server listening address, for example "unix:///var/run/kms-provider.sock".
        """
        return self.__endpoint

    def timeout(self) -> Optional["base.Duration"]:
        """
        Timeout for gRPC calls to kms-plugin (ex. 5s). The default is 3 seconds.
        """
        return self.__timeout


class SecretboxConfiguration(types.Object):
    """
    SecretboxConfiguration contains the API configuration for an Secretbox transformer.
    """

    @context.scoped
    @typechecked
    def __init__(self, keys: Dict[str, "Key"] = None):
        super().__init__()
        self.__keys = keys if keys is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        keys = self.keys()
        check_type("keys", keys, Dict[str, "Key"])
        v["keys"] = keys.values()  # named list
        return v

    def keys(self) -> Dict[str, "Key"]:
        """
        keys is a list of keys to be used for creating the Secretbox transformer.
        Each key has to be 32 bytes long.
        """
        return self.__keys


class ProviderConfiguration(types.Object):
    """
    ProviderConfiguration stores the provided configuration for an encryption provider.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        aesgcm: "AESConfiguration" = None,
        aescbc: "AESConfiguration" = None,
        secretbox: "SecretboxConfiguration" = None,
        identity: "IdentityConfiguration" = None,
        kms: "KMSConfiguration" = None,
    ):
        super().__init__()
        self.__aesgcm = aesgcm
        self.__aescbc = aescbc
        self.__secretbox = secretbox
        self.__identity = identity
        self.__kms = kms

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        aesgcm = self.aesgcm()
        check_type("aesgcm", aesgcm, Optional["AESConfiguration"])
        if aesgcm is not None:  # omit empty
            v["aesgcm"] = aesgcm
        aescbc = self.aescbc()
        check_type("aescbc", aescbc, Optional["AESConfiguration"])
        if aescbc is not None:  # omit empty
            v["aescbc"] = aescbc
        secretbox = self.secretbox()
        check_type("secretbox", secretbox, Optional["SecretboxConfiguration"])
        if secretbox is not None:  # omit empty
            v["secretbox"] = secretbox
        identity = self.identity()
        check_type("identity", identity, Optional["IdentityConfiguration"])
        if identity is not None:  # omit empty
            v["identity"] = identity
        kms = self.kms()
        check_type("kms", kms, Optional["KMSConfiguration"])
        if kms is not None:  # omit empty
            v["kms"] = kms
        return v

    def aesgcm(self) -> Optional["AESConfiguration"]:
        """
        aesgcm is the configuration for the AES-GCM transformer.
        """
        return self.__aesgcm

    def aescbc(self) -> Optional["AESConfiguration"]:
        """
        aescbc is the configuration for the AES-CBC transformer.
        """
        return self.__aescbc

    def secretbox(self) -> Optional["SecretboxConfiguration"]:
        """
        secretbox is the configuration for the Secretbox based transformer.
        """
        return self.__secretbox

    def identity(self) -> Optional["IdentityConfiguration"]:
        """
        identity is the (empty) configuration for the identity transformer.
        """
        return self.__identity

    def kms(self) -> Optional["KMSConfiguration"]:
        """
        kms contains the name, cache size and path to configuration file for a KMS based envelope transformer.
        """
        return self.__kms


class ResourceConfiguration(types.Object):
    """
    ResourceConfiguration stores per resource configuration.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        resources: List[str] = None,
        providers: List["ProviderConfiguration"] = None,
    ):
        super().__init__()
        self.__resources = resources if resources is not None else []
        self.__providers = providers if providers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        resources = self.resources()
        check_type("resources", resources, List[str])
        v["resources"] = resources
        providers = self.providers()
        check_type("providers", providers, List["ProviderConfiguration"])
        v["providers"] = providers
        return v

    def resources(self) -> List[str]:
        """
        resources is a list of kubernetes resources which have to be encrypted.
        """
        return self.__resources

    def providers(self) -> List["ProviderConfiguration"]:
        """
        providers is a list of transformers to be used for reading and writing the resources to disk.
        eg: aesgcm, aescbc, secretbox, identity.
        """
        return self.__providers


class EncryptionConfiguration(types.Object):
    """
    EncryptionConfiguration stores the complete configuration for encryption providers.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        typeMeta: "metav1.TypeMeta" = None,
        resources: List["ResourceConfiguration"] = None,
    ):
        super().__init__()
        self.__typeMeta = typeMeta if typeMeta is not None else metav1.TypeMeta()
        self.__resources = resources if resources is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        typeMeta = self.typeMeta()
        check_type("typeMeta", typeMeta, "metav1.TypeMeta")
        v["TypeMeta"] = typeMeta
        resources = self.resources()
        check_type("resources", resources, List["ResourceConfiguration"])
        v["resources"] = resources
        return v

    def typeMeta(self) -> "metav1.TypeMeta":
        return self.__typeMeta

    def resources(self) -> List["ResourceConfiguration"]:
        """
        resources is a list containing resources, and their corresponding encryption providers.
        """
        return self.__resources
