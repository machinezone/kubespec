# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


# KeyUsages specifies valid usage contexts for keys.
# See: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
#      https://tools.ietf.org/html/rfc5280#section-4.2.1.12
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


class CertificateSigningRequestSpec(types.Object):
    """
    This information is immutable after the request is created. Only the Request
    and Usages fields can be set on creation, other fields are derived by
    Kubernetes and cannot be modified by users.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        request: bytes = None,
        usages: List[KeyUsage] = None,
        username: str = None,
        uid: str = None,
        groups: List[str] = None,
        extra: Dict[str, List[str]] = None,
    ):
        super().__init__()
        self.__request = request if request is not None else b""
        self.__usages = usages if usages is not None else []
        self.__username = username
        self.__uid = uid
        self.__groups = groups if groups is not None else []
        self.__extra = extra if extra is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        request = self.request()
        check_type("request", request, bytes)
        v["request"] = request
        usages = self.usages()
        check_type("usages", usages, Optional[List[KeyUsage]])
        if usages:  # omit empty
            v["usages"] = usages
        username = self.username()
        check_type("username", username, Optional[str])
        if username:  # omit empty
            v["username"] = username
        uid = self.uid()
        check_type("uid", uid, Optional[str])
        if uid:  # omit empty
            v["uid"] = uid
        groups = self.groups()
        check_type("groups", groups, Optional[List[str]])
        if groups:  # omit empty
            v["groups"] = groups
        extra = self.extra()
        check_type("extra", extra, Optional[Dict[str, List[str]]])
        if extra:  # omit empty
            v["extra"] = extra
        return v

    def request(self) -> bytes:
        """
        Base64-encoded PKCS#10 CSR data
        """
        return self.__request

    def usages(self) -> Optional[List[KeyUsage]]:
        """
        allowedUsages specifies a set of usage contexts the key will be
        valid for.
        See: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
             https://tools.ietf.org/html/rfc5280#section-4.2.1.12
        """
        return self.__usages

    def username(self) -> Optional[str]:
        """
        Information about the requesting user.
        See user.Info interface for details.
        """
        return self.__username

    def uid(self) -> Optional[str]:
        """
        UID information about the requesting user.
        See user.Info interface for details.
        """
        return self.__uid

    def groups(self) -> Optional[List[str]]:
        """
        Group information about the requesting user.
        See user.Info interface for details.
        """
        return self.__groups

    def extra(self) -> Optional[Dict[str, List[str]]]:
        """
        Extra information about the requesting user.
        See user.Info interface for details.
        """
        return self.__extra


class CertificateSigningRequest(base.TypedObject, base.MetadataObject):
    """
    Describes a certificate signing request
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "CertificateSigningRequestSpec" = None,
    ):
        super().__init__(
            api_version="certificates.k8s.io/v1beta1",
            kind="CertificateSigningRequest",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else CertificateSigningRequestSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["CertificateSigningRequestSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["CertificateSigningRequestSpec"]:
        """
        The certificate request itself and any additional information.
        """
        return self.__spec
