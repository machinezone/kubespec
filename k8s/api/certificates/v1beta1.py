# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# KeyUsages specifies valid usage contexts for keys.
# See: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
#      https://tools.ietf.org/html/rfc5280#section-4.2.1.12
KeyUsage = base.Enum('KeyUsage', {
    'Any': 'any',
    'CRLSign': 'crl sign',
    'CertSign': 'cert sign',
    'ClientAuth': 'client auth',
    'CodeSigning': 'code signing',
    'ContentCommitment': 'content commitment',
    'DataEncipherment': 'data encipherment',
    'DecipherOnly': 'decipher only',
    'DigitalSignature': 'digital signature',
    'EmailProtection': 'email protection',
    'EncipherOnly': 'encipher only',
    'IPsecEndSystem': 'ipsec end system',
    'IPsecTunnel': 'ipsec tunnel',
    'IPsecUser': 'ipsec user',
    'KeyAgreement': 'key agreement',
    'KeyEncipherment': 'key encipherment',
    'MicrosoftSGC': 'microsoft sgc',
    'NetscapeSGC': 'netscape sgc',
    'OCSPSigning': 'ocsp signing',
    'SMIME': 's/mime',
    'ServerAuth': 'server auth',
    'Signing': 'signing',
    'Timestamping': 'timestamping',
})


# This information is immutable after the request is created. Only the Request
# and Usages fields can be set on creation, other fields are derived by
# Kubernetes and cannot be modified by users.
class CertificateSigningRequestSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['request'] = self.request()
        usages = self.usages()
        if usages:  # omit empty
            v['usages'] = usages
        username = self.username()
        if username:  # omit empty
            v['username'] = username
        uid = self.uid()
        if uid:  # omit empty
            v['uid'] = uid
        groups = self.groups()
        if groups:  # omit empty
            v['groups'] = groups
        extra = self.extra()
        if extra:  # omit empty
            v['extra'] = extra
        return v
    
    # Base64-encoded PKCS#10 CSR data
    @typechecked
    def request(self) -> bytes:
        if 'request' in self._kwargs:
            return self._kwargs['request']
        if 'request' in self._context and check_return_type(self._context['request']):
            return self._context['request']
        return b''
    
    # allowedUsages specifies a set of usage contexts the key will be
    # valid for.
    # See: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
    #      https://tools.ietf.org/html/rfc5280#section-4.2.1.12
    @typechecked
    def usages(self) -> List[KeyUsage]:
        if 'usages' in self._kwargs:
            return self._kwargs['usages']
        if 'usages' in self._context and check_return_type(self._context['usages']):
            return self._context['usages']
        return []
    
    # Information about the requesting user.
    # See user.Info interface for details.
    @typechecked
    def username(self) -> Optional[str]:
        if 'username' in self._kwargs:
            return self._kwargs['username']
        if 'username' in self._context and check_return_type(self._context['username']):
            return self._context['username']
        return None
    
    # UID information about the requesting user.
    # See user.Info interface for details.
    @typechecked
    def uid(self) -> Optional[str]:
        if 'uid' in self._kwargs:
            return self._kwargs['uid']
        if 'uid' in self._context and check_return_type(self._context['uid']):
            return self._context['uid']
        return None
    
    # Group information about the requesting user.
    # See user.Info interface for details.
    @typechecked
    def groups(self) -> List[str]:
        if 'groups' in self._kwargs:
            return self._kwargs['groups']
        if 'groups' in self._context and check_return_type(self._context['groups']):
            return self._context['groups']
        return []
    
    # Extra information about the requesting user.
    # See user.Info interface for details.
    @typechecked
    def extra(self) -> Dict[str, List[str]]:
        if 'extra' in self._kwargs:
            return self._kwargs['extra']
        if 'extra' in self._context and check_return_type(self._context['extra']):
            return self._context['extra']
        return {}


# Describes a certificate signing request
class CertificateSigningRequest(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'certificates.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'CertificateSigningRequest'
    
    # The certificate request itself and any additional information.
    @typechecked
    def spec(self) -> CertificateSigningRequestSpec:
        if 'spec' in self._kwargs:
            return self._kwargs['spec']
        if 'spec' in self._context and check_return_type(self._context['spec']):
            return self._context['spec']
        with context.Scope(**self._context):
            return CertificateSigningRequestSpec()
