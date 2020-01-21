# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.meta import v1 as metav1
from kubespec.openshift.operator import v1 as operatorv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


class ImageRegistryConfigProxy(types.Object):
    """
    ImageRegistryConfigProxy defines proxy configuration to be used by registry.
    """

    @context.scoped
    @typechecked
    def __init__(self, http: str = "", https: str = "", noProxy: str = ""):
        super().__init__()
        self.__http = http
        self.__https = https
        self.__noProxy = noProxy

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        http = self.http()
        check_type("http", http, str)
        v["http"] = http
        https = self.https()
        check_type("https", https, str)
        v["https"] = https
        noProxy = self.noProxy()
        check_type("noProxy", noProxy, str)
        v["noProxy"] = noProxy
        return v

    def http(self) -> str:
        """
        http defines the proxy to be used by the image registry when
        accessing HTTP endpoints.
        """
        return self.__http

    def https(self) -> str:
        """
        https defines the proxy to be used by the image registry when
        accessing HTTPS endpoints.
        """
        return self.__https

    def noProxy(self) -> str:
        """
        noProxy defines a comma-separated list of host names that shouldn't
        go through any proxy.
        """
        return self.__noProxy


class ImageRegistryConfigRequestsLimits(types.Object):
    """
    ImageRegistryConfigRequestsLimits holds configuration on the max, enqueued
    and waiting registry's API requests.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        maxRunning: int = 0,
        maxInQueue: int = 0,
        maxWaitInQueue: "base.Duration" = None,
    ):
        super().__init__()
        self.__maxRunning = maxRunning
        self.__maxInQueue = maxInQueue
        self.__maxWaitInQueue = (
            maxWaitInQueue if maxWaitInQueue is not None else metav1.Duration()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        maxRunning = self.maxRunning()
        check_type("maxRunning", maxRunning, int)
        v["maxRunning"] = maxRunning
        maxInQueue = self.maxInQueue()
        check_type("maxInQueue", maxInQueue, int)
        v["maxInQueue"] = maxInQueue
        maxWaitInQueue = self.maxWaitInQueue()
        check_type("maxWaitInQueue", maxWaitInQueue, "base.Duration")
        v["maxWaitInQueue"] = maxWaitInQueue
        return v

    def maxRunning(self) -> int:
        """
        maxRunning sets the maximum in flight api requests to the registry.
        """
        return self.__maxRunning

    def maxInQueue(self) -> int:
        """
        maxInQueue sets the maximum queued api requests to the registry.
        """
        return self.__maxInQueue

    def maxWaitInQueue(self) -> "base.Duration":
        """
        maxWaitInQueue sets the maximum time a request can wait in the queue
        before being rejected.
        """
        return self.__maxWaitInQueue


class ImageRegistryConfigRequests(types.Object):
    """
    ImageRegistryConfigRequests defines registry limits on requests read and write.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        read: "ImageRegistryConfigRequestsLimits" = None,
        write: "ImageRegistryConfigRequestsLimits" = None,
    ):
        super().__init__()
        self.__read = read if read is not None else ImageRegistryConfigRequestsLimits()
        self.__write = (
            write if write is not None else ImageRegistryConfigRequestsLimits()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        read = self.read()
        check_type("read", read, "ImageRegistryConfigRequestsLimits")
        v["read"] = read
        write = self.write()
        check_type("write", write, "ImageRegistryConfigRequestsLimits")
        v["write"] = write
        return v

    def read(self) -> "ImageRegistryConfigRequestsLimits":
        """
        read defines limits for image registry's reads.
        """
        return self.__read

    def write(self) -> "ImageRegistryConfigRequestsLimits":
        """
        write defines limits for image registry's writes.
        """
        return self.__write


class ImageRegistryConfigRoute(types.Object):
    """
    ImageRegistryConfigRoute holds information on external route access to image
    registry.
    """

    @context.scoped
    @typechecked
    def __init__(self, name: str = "", hostname: str = None, secretName: str = None):
        super().__init__()
        self.__name = name
        self.__hostname = hostname
        self.__secretName = secretName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        hostname = self.hostname()
        check_type("hostname", hostname, Optional[str])
        if hostname:  # omit empty
            v["hostname"] = hostname
        secretName = self.secretName()
        check_type("secretName", secretName, Optional[str])
        if secretName:  # omit empty
            v["secretName"] = secretName
        return v

    def name(self) -> str:
        """
        name of the route to be created.
        """
        return self.__name

    def hostname(self) -> Optional[str]:
        """
        hostname for the route.
        """
        return self.__hostname

    def secretName(self) -> Optional[str]:
        """
        secretName points to secret containing the certificates to be used
        by the route.
        """
        return self.__secretName


class ImageRegistryConfigStorageAzure(types.Object):
    """
    ImageRegistryConfigStorageAzure holds the information to configure
    the registry to use Azure Blob Storage for backend storage.
    """

    @context.scoped
    @typechecked
    def __init__(self, accountName: str = "", container: str = ""):
        super().__init__()
        self.__accountName = accountName
        self.__container = container

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        accountName = self.accountName()
        check_type("accountName", accountName, str)
        v["accountName"] = accountName
        container = self.container()
        check_type("container", container, str)
        v["container"] = container
        return v

    def accountName(self) -> str:
        """
        accountName defines the account to be used by the registry.
        """
        return self.__accountName

    def container(self) -> str:
        """
        container defines Azure's container to be used by registry.
        """
        return self.__container


class ImageRegistryConfigStorageEmptyDir(types.Object):
    """
    ImageRegistryConfigStorageEmptyDir is an place holder to be used when
    when registry is leveraging ephemeral storage.
    """

    pass  # FIXME


class ImageRegistryConfigStorageGCS(types.Object):
    """
    ImageRegistryConfigStorageGCS holds GCS configuration.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        bucket: str = None,
        region: str = None,
        projectID: str = None,
        keyID: str = None,
    ):
        super().__init__()
        self.__bucket = bucket
        self.__region = region
        self.__projectID = projectID
        self.__keyID = keyID

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        bucket = self.bucket()
        check_type("bucket", bucket, Optional[str])
        if bucket:  # omit empty
            v["bucket"] = bucket
        region = self.region()
        check_type("region", region, Optional[str])
        if region:  # omit empty
            v["region"] = region
        projectID = self.projectID()
        check_type("projectID", projectID, Optional[str])
        if projectID:  # omit empty
            v["projectID"] = projectID
        keyID = self.keyID()
        check_type("keyID", keyID, Optional[str])
        if keyID:  # omit empty
            v["keyID"] = keyID
        return v

    def bucket(self) -> Optional[str]:
        """
        bucket is the bucket name in which you want to store the registry's
        data.
        Optional, will be generated if not provided.
        """
        return self.__bucket

    def region(self) -> Optional[str]:
        """
        region is the GCS location in which your bucket exists.
        Optional, will be set based on the installed GCS Region.
        """
        return self.__region

    def projectID(self) -> Optional[str]:
        """
        projectID is the Project ID of the GCP project that this bucket should
        be associated with.
        """
        return self.__projectID

    def keyID(self) -> Optional[str]:
        """
        keyID is the KMS key ID to use for encryption.
        Optional, buckets are encrypted by default on GCP.
        This allows for the use of a custom encryption key.
        """
        return self.__keyID


class ImageRegistryConfigStoragePVC(types.Object):
    """
    ImageRegistryConfigStoragePVC holds Persistent Volume Claims data to
    be used by the registry.
    """

    @context.scoped
    @typechecked
    def __init__(self, claim: str = ""):
        super().__init__()
        self.__claim = claim

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        claim = self.claim()
        check_type("claim", claim, str)
        v["claim"] = claim
        return v

    def claim(self) -> str:
        """
        claim defines the Persisent Volume Claim's name to be used.
        """
        return self.__claim


class ImageRegistryConfigStorageS3CloudFront(types.Object):
    """
    ImageRegistryConfigStorageS3CloudFront holds the configuration
    to use Amazon Cloudfront as the storage middleware in a registry.
    https://docs.docker.com/registry/configuration/#cloudfront
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        baseURL: str = "",
        privateKey: "k8sv1.SecretKeySelector" = None,
        keypairID: str = "",
        duration: "base.Duration" = None,
    ):
        super().__init__()
        self.__baseURL = baseURL
        self.__privateKey = (
            privateKey if privateKey is not None else k8sv1.SecretKeySelector()
        )
        self.__keypairID = keypairID
        self.__duration = duration if duration is not None else metav1.Duration()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        baseURL = self.baseURL()
        check_type("baseURL", baseURL, str)
        v["baseURL"] = baseURL
        privateKey = self.privateKey()
        check_type("privateKey", privateKey, "k8sv1.SecretKeySelector")
        v["privateKey"] = privateKey
        keypairID = self.keypairID()
        check_type("keypairID", keypairID, str)
        v["keypairID"] = keypairID
        duration = self.duration()
        check_type("duration", duration, "base.Duration")
        v["duration"] = duration
        return v

    def baseURL(self) -> str:
        """
        baseURL contains the SCHEME://HOST[/PATH] at which Cloudfront is served.
        """
        return self.__baseURL

    def privateKey(self) -> "k8sv1.SecretKeySelector":
        """
        privateKey points to secret containing the private key, provided by AWS.
        """
        return self.__privateKey

    def keypairID(self) -> str:
        """
        keypairID is key pair ID provided by AWS.
        """
        return self.__keypairID

    def duration(self) -> "base.Duration":
        """
        duration is the duration of the Cloudfront session.
        """
        return self.__duration


class ImageRegistryConfigStorageS3(types.Object):
    """
    ImageRegistryConfigStorageS3 holds the information to configure
    the registry to use the AWS S3 service for backend storage
    https://docs.docker.com/registry/storage-drivers/s3/
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        bucket: str = "",
        region: str = "",
        regionEndpoint: str = "",
        encrypt: bool = False,
        keyID: str = "",
        cloudFront: "ImageRegistryConfigStorageS3CloudFront" = None,
    ):
        super().__init__()
        self.__bucket = bucket
        self.__region = region
        self.__regionEndpoint = regionEndpoint
        self.__encrypt = encrypt
        self.__keyID = keyID
        self.__cloudFront = cloudFront

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        bucket = self.bucket()
        check_type("bucket", bucket, str)
        v["bucket"] = bucket
        region = self.region()
        check_type("region", region, str)
        v["region"] = region
        regionEndpoint = self.regionEndpoint()
        check_type("regionEndpoint", regionEndpoint, str)
        v["regionEndpoint"] = regionEndpoint
        encrypt = self.encrypt()
        check_type("encrypt", encrypt, bool)
        v["encrypt"] = encrypt
        keyID = self.keyID()
        check_type("keyID", keyID, str)
        v["keyID"] = keyID
        cloudFront = self.cloudFront()
        check_type(
            "cloudFront", cloudFront, Optional["ImageRegistryConfigStorageS3CloudFront"]
        )
        if cloudFront is not None:  # omit empty
            v["cloudFront"] = cloudFront
        return v

    def bucket(self) -> str:
        """
        bucket is the bucket name in which you want to store the registry's
        data.
        Optional, will be generated if not provided.
        """
        return self.__bucket

    def region(self) -> str:
        """
        region is the AWS region in which your bucket exists.
        Optional, will be set based on the installed AWS Region.
        """
        return self.__region

    def regionEndpoint(self) -> str:
        """
        regionEndpoint is the endpoint for S3 compatible storage services.
        Optional, defaults based on the Region that is provided.
        """
        return self.__regionEndpoint

    def encrypt(self) -> bool:
        """
        encrypt specifies whether the registry stores the image in encrypted
        format or not.
        Optional, defaults to false.
        """
        return self.__encrypt

    def keyID(self) -> str:
        """
        keyID is the KMS key ID to use for encryption.
        Optional, Encrypt must be true, or this parameter is ignored.
        """
        return self.__keyID

    def cloudFront(self) -> Optional["ImageRegistryConfigStorageS3CloudFront"]:
        """
        cloudFront configures Amazon Cloudfront as the storage middleware in a
        registry.
        """
        return self.__cloudFront


class ImageRegistryConfigStorageSwift(types.Object):
    """
    ImageRegistryConfigStorageSwift holds the information to configure
    the registry to use the OpenStack Swift service for backend storage
    https://docs.docker.com/registry/storage-drivers/swift/
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        authURL: str = "",
        authVersion: str = "",
        container: str = "",
        domain: str = "",
        domainID: str = "",
        tenant: str = "",
        tenantID: str = "",
        regionName: str = "",
    ):
        super().__init__()
        self.__authURL = authURL
        self.__authVersion = authVersion
        self.__container = container
        self.__domain = domain
        self.__domainID = domainID
        self.__tenant = tenant
        self.__tenantID = tenantID
        self.__regionName = regionName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        authURL = self.authURL()
        check_type("authURL", authURL, str)
        v["authURL"] = authURL
        authVersion = self.authVersion()
        check_type("authVersion", authVersion, str)
        v["authVersion"] = authVersion
        container = self.container()
        check_type("container", container, str)
        v["container"] = container
        domain = self.domain()
        check_type("domain", domain, str)
        v["domain"] = domain
        domainID = self.domainID()
        check_type("domainID", domainID, str)
        v["domainID"] = domainID
        tenant = self.tenant()
        check_type("tenant", tenant, str)
        v["tenant"] = tenant
        tenantID = self.tenantID()
        check_type("tenantID", tenantID, str)
        v["tenantID"] = tenantID
        regionName = self.regionName()
        check_type("regionName", regionName, str)
        v["regionName"] = regionName
        return v

    def authURL(self) -> str:
        """
        authURL defines the URL for obtaining an authentication token.
        """
        return self.__authURL

    def authVersion(self) -> str:
        """
        authVersion specifies the OpenStack Auth's version.
        """
        return self.__authVersion

    def container(self) -> str:
        """
        container defines the name of Swift container where to store the
        registry's data.
        """
        return self.__container

    def domain(self) -> str:
        """
        domain specifies Openstack's domain name for Identity v3 API.
        """
        return self.__domain

    def domainID(self) -> str:
        """
        domainID specifies Openstack's domain id for Identity v3 API.
        """
        return self.__domainID

    def tenant(self) -> str:
        """
        tenant defines Openstack tenant name to be used by registry.
        """
        return self.__tenant

    def tenantID(self) -> str:
        """
        tenant defines Openstack tenant id to be used by registry.
        """
        return self.__tenantID

    def regionName(self) -> str:
        """
        regionName defines Openstack's region in which container exists.
        """
        return self.__regionName


class ImageRegistryConfigStorage(types.Object):
    """
    ImageRegistryConfigStorage describes how the storage should be configured
    for the image registry.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        emptyDir: "ImageRegistryConfigStorageEmptyDir" = None,
        s3: "ImageRegistryConfigStorageS3" = None,
        gcs: "ImageRegistryConfigStorageGCS" = None,
        swift: "ImageRegistryConfigStorageSwift" = None,
        pvc: "ImageRegistryConfigStoragePVC" = None,
        azure: "ImageRegistryConfigStorageAzure" = None,
    ):
        super().__init__()
        self.__emptyDir = emptyDir
        self.__s3 = s3
        self.__gcs = gcs
        self.__swift = swift
        self.__pvc = pvc
        self.__azure = azure

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        emptyDir = self.emptyDir()
        check_type("emptyDir", emptyDir, Optional["ImageRegistryConfigStorageEmptyDir"])
        if emptyDir is not None:  # omit empty
            v["emptyDir"] = emptyDir
        s3 = self.s3()
        check_type("s3", s3, Optional["ImageRegistryConfigStorageS3"])
        if s3 is not None:  # omit empty
            v["s3"] = s3
        gcs = self.gcs()
        check_type("gcs", gcs, Optional["ImageRegistryConfigStorageGCS"])
        if gcs is not None:  # omit empty
            v["gcs"] = gcs
        swift = self.swift()
        check_type("swift", swift, Optional["ImageRegistryConfigStorageSwift"])
        if swift is not None:  # omit empty
            v["swift"] = swift
        pvc = self.pvc()
        check_type("pvc", pvc, Optional["ImageRegistryConfigStoragePVC"])
        if pvc is not None:  # omit empty
            v["pvc"] = pvc
        azure = self.azure()
        check_type("azure", azure, Optional["ImageRegistryConfigStorageAzure"])
        if azure is not None:  # omit empty
            v["azure"] = azure
        return v

    def emptyDir(self) -> Optional["ImageRegistryConfigStorageEmptyDir"]:
        """
        emptyDir represents ephemeral storage on the pod's host node.
        WARNING: this storage cannot be used with more than 1 replica and
        is not suitable for production use. When the pod is removed from a
        node for any reason, the data in the emptyDir is deleted forever.
        """
        return self.__emptyDir

    def s3(self) -> Optional["ImageRegistryConfigStorageS3"]:
        """
        s3 represents configuration that uses Amazon Simple Storage Service.
        """
        return self.__s3

    def gcs(self) -> Optional["ImageRegistryConfigStorageGCS"]:
        """
        gcs represents configuration that uses Google Cloud Storage.
        """
        return self.__gcs

    def swift(self) -> Optional["ImageRegistryConfigStorageSwift"]:
        """
        swift represents configuration that uses OpenStack Object Storage.
        """
        return self.__swift

    def pvc(self) -> Optional["ImageRegistryConfigStoragePVC"]:
        """
        pvc represents configuration that uses a PersistentVolumeClaim.
        """
        return self.__pvc

    def azure(self) -> Optional["ImageRegistryConfigStorageAzure"]:
        """
        azure represents configuration that uses Azure Blob Storage.
        """
        return self.__azure


class ImageRegistrySpec(types.Object):
    """
    ImageRegistrySpec defines the specs for the running registry.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        managementState: operatorv1.ManagementState = None,
        httpSecret: str = "",
        proxy: "ImageRegistryConfigProxy" = None,
        storage: "ImageRegistryConfigStorage" = None,
        readOnly: bool = False,
        disableRedirect: bool = False,
        requests: "ImageRegistryConfigRequests" = None,
        defaultRoute: bool = False,
        routes: List["ImageRegistryConfigRoute"] = None,
        replicas: int = 0,
        logging: int = 0,
        resources: "k8sv1.ResourceRequirements" = None,
        nodeSelector: Dict[str, str] = None,
        tolerations: List["k8sv1.Toleration"] = None,
    ):
        super().__init__()
        self.__managementState = managementState
        self.__httpSecret = httpSecret
        self.__proxy = proxy if proxy is not None else ImageRegistryConfigProxy()
        self.__storage = (
            storage if storage is not None else ImageRegistryConfigStorage()
        )
        self.__readOnly = readOnly
        self.__disableRedirect = disableRedirect
        self.__requests = (
            requests if requests is not None else ImageRegistryConfigRequests()
        )
        self.__defaultRoute = defaultRoute
        self.__routes = routes if routes is not None else []
        self.__replicas = replicas
        self.__logging = logging
        self.__resources = resources
        self.__nodeSelector = nodeSelector if nodeSelector is not None else {}
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        managementState = self.managementState()
        check_type("managementState", managementState, operatorv1.ManagementState)
        v["managementState"] = managementState
        httpSecret = self.httpSecret()
        check_type("httpSecret", httpSecret, str)
        v["httpSecret"] = httpSecret
        proxy = self.proxy()
        check_type("proxy", proxy, "ImageRegistryConfigProxy")
        v["proxy"] = proxy
        storage = self.storage()
        check_type("storage", storage, "ImageRegistryConfigStorage")
        v["storage"] = storage
        readOnly = self.readOnly()
        check_type("readOnly", readOnly, bool)
        v["readOnly"] = readOnly
        disableRedirect = self.disableRedirect()
        check_type("disableRedirect", disableRedirect, bool)
        v["disableRedirect"] = disableRedirect
        requests = self.requests()
        check_type("requests", requests, "ImageRegistryConfigRequests")
        v["requests"] = requests
        defaultRoute = self.defaultRoute()
        check_type("defaultRoute", defaultRoute, bool)
        v["defaultRoute"] = defaultRoute
        routes = self.routes()
        check_type("routes", routes, Optional[List["ImageRegistryConfigRoute"]])
        if routes:  # omit empty
            v["routes"] = routes
        replicas = self.replicas()
        check_type("replicas", replicas, int)
        v["replicas"] = replicas
        logging = self.logging()
        check_type("logging", logging, int)
        v["logging"] = logging
        resources = self.resources()
        check_type("resources", resources, Optional["k8sv1.ResourceRequirements"])
        if resources is not None:  # omit empty
            v["resources"] = resources
        nodeSelector = self.nodeSelector()
        check_type("nodeSelector", nodeSelector, Optional[Dict[str, str]])
        if nodeSelector:  # omit empty
            v["nodeSelector"] = nodeSelector
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    def managementState(self) -> operatorv1.ManagementState:
        """
        managementState indicates whether the registry instance represented
        by this config instance is under operator management or not.  Valid
        values are Managed, Unmanaged, and Removed.
        """
        return self.__managementState

    def httpSecret(self) -> str:
        """
        httpSecret is the value needed by the registry to secure uploads, generated by default.
        """
        return self.__httpSecret

    def proxy(self) -> "ImageRegistryConfigProxy":
        """
        proxy defines the proxy to be used when calling master api, upstream
        registries, etc.
        """
        return self.__proxy

    def storage(self) -> "ImageRegistryConfigStorage":
        """
        storage details for configuring registry storage, e.g. S3 bucket
        coordinates.
        """
        return self.__storage

    def readOnly(self) -> bool:
        """
        readOnly indicates whether the registry instance should reject attempts
        to push new images or delete existing ones.
        """
        return self.__readOnly

    def disableRedirect(self) -> bool:
        """
        disableRedirect controls whether to route all data through the Registry,
        rather than redirecting to the backend.
        """
        return self.__disableRedirect

    def requests(self) -> "ImageRegistryConfigRequests":
        """
        requests controls how many parallel requests a given registry instance
        will handle before queuing additional requests.
        """
        return self.__requests

    def defaultRoute(self) -> bool:
        """
        defaultRoute indicates whether an external facing route for the registry
        should be created using the default generated hostname.
        """
        return self.__defaultRoute

    def routes(self) -> Optional[List["ImageRegistryConfigRoute"]]:
        """
        routes defines additional external facing routes which should be
        created for the registry.
        """
        return self.__routes

    def replicas(self) -> int:
        """
        replicas determines the number of registry instances to run.
        """
        return self.__replicas

    def logging(self) -> int:
        """
        logging determines the level of logging enabled in the registry.
        """
        return self.__logging

    def resources(self) -> Optional["k8sv1.ResourceRequirements"]:
        """
        resources defines the resource requests+limits for the registry pod.
        """
        return self.__resources

    def nodeSelector(self) -> Optional[Dict[str, str]]:
        """
        nodeSelector defines the node selection constraints for the registry
        pod.
        """
        return self.__nodeSelector

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        tolerations defines the tolerations for the registry pod.
        """
        return self.__tolerations


class Config(base.TypedObject, base.MetadataObject):
    """
    Config is the configuration object for a registry instance managed by
    the registry operator
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ImageRegistrySpec" = None,
    ):
        super().__init__(
            apiVersion="imageregistry.operator.openshift.io/v1",
            kind="Config",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ImageRegistrySpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ImageRegistrySpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ImageRegistrySpec":
        return self.__spec
