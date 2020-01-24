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
    def __init__(self, http: str = "", https: str = "", no_proxy: str = ""):
        super().__init__()
        self.__http = http
        self.__https = https
        self.__no_proxy = no_proxy

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        http = self.http()
        check_type("http", http, str)
        v["http"] = http
        https = self.https()
        check_type("https", https, str)
        v["https"] = https
        no_proxy = self.no_proxy()
        check_type("no_proxy", no_proxy, str)
        v["noProxy"] = no_proxy
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

    def no_proxy(self) -> str:
        """
        noProxy defines a comma-separated list of host names that shouldn't
        go through any proxy.
        """
        return self.__no_proxy


class ImageRegistryConfigRequestsLimits(types.Object):
    """
    ImageRegistryConfigRequestsLimits holds configuration on the max, enqueued
    and waiting registry's API requests.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        max_running: int = 0,
        max_in_queue: int = 0,
        max_wait_in_queue: "base.Duration" = None,
    ):
        super().__init__()
        self.__max_running = max_running
        self.__max_in_queue = max_in_queue
        self.__max_wait_in_queue = (
            max_wait_in_queue if max_wait_in_queue is not None else metav1.Duration()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        max_running = self.max_running()
        check_type("max_running", max_running, int)
        v["maxRunning"] = max_running
        max_in_queue = self.max_in_queue()
        check_type("max_in_queue", max_in_queue, int)
        v["maxInQueue"] = max_in_queue
        max_wait_in_queue = self.max_wait_in_queue()
        check_type("max_wait_in_queue", max_wait_in_queue, "base.Duration")
        v["maxWaitInQueue"] = max_wait_in_queue
        return v

    def max_running(self) -> int:
        """
        maxRunning sets the maximum in flight api requests to the registry.
        """
        return self.__max_running

    def max_in_queue(self) -> int:
        """
        maxInQueue sets the maximum queued api requests to the registry.
        """
        return self.__max_in_queue

    def max_wait_in_queue(self) -> "base.Duration":
        """
        maxWaitInQueue sets the maximum time a request can wait in the queue
        before being rejected.
        """
        return self.__max_wait_in_queue


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
    def __init__(self, name: str = "", hostname: str = None, secret_name: str = None):
        super().__init__()
        self.__name = name
        self.__hostname = hostname
        self.__secret_name = secret_name

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
        secret_name = self.secret_name()
        check_type("secret_name", secret_name, Optional[str])
        if secret_name:  # omit empty
            v["secretName"] = secret_name
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

    def secret_name(self) -> Optional[str]:
        """
        secretName points to secret containing the certificates to be used
        by the route.
        """
        return self.__secret_name


class ImageRegistryConfigStorageAzure(types.Object):
    """
    ImageRegistryConfigStorageAzure holds the information to configure
    the registry to use Azure Blob Storage for backend storage.
    """

    @context.scoped
    @typechecked
    def __init__(self, account_name: str = "", container: str = ""):
        super().__init__()
        self.__account_name = account_name
        self.__container = container

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        account_name = self.account_name()
        check_type("account_name", account_name, str)
        v["accountName"] = account_name
        container = self.container()
        check_type("container", container, str)
        v["container"] = container
        return v

    def account_name(self) -> str:
        """
        accountName defines the account to be used by the registry.
        """
        return self.__account_name

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
        project_id: str = None,
        key_id: str = None,
    ):
        super().__init__()
        self.__bucket = bucket
        self.__region = region
        self.__project_id = project_id
        self.__key_id = key_id

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
        project_id = self.project_id()
        check_type("project_id", project_id, Optional[str])
        if project_id:  # omit empty
            v["projectID"] = project_id
        key_id = self.key_id()
        check_type("key_id", key_id, Optional[str])
        if key_id:  # omit empty
            v["keyID"] = key_id
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

    def project_id(self) -> Optional[str]:
        """
        projectID is the Project ID of the GCP project that this bucket should
        be associated with.
        """
        return self.__project_id

    def key_id(self) -> Optional[str]:
        """
        keyID is the KMS key ID to use for encryption.
        Optional, buckets are encrypted by default on GCP.
        This allows for the use of a custom encryption key.
        """
        return self.__key_id


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
        base_url: str = "",
        private_key: "k8sv1.SecretKeySelector" = None,
        keypair_id: str = "",
        duration: "base.Duration" = None,
    ):
        super().__init__()
        self.__base_url = base_url
        self.__private_key = (
            private_key if private_key is not None else k8sv1.SecretKeySelector()
        )
        self.__keypair_id = keypair_id
        self.__duration = duration if duration is not None else metav1.Duration()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        base_url = self.base_url()
        check_type("base_url", base_url, str)
        v["baseURL"] = base_url
        private_key = self.private_key()
        check_type("private_key", private_key, "k8sv1.SecretKeySelector")
        v["privateKey"] = private_key
        keypair_id = self.keypair_id()
        check_type("keypair_id", keypair_id, str)
        v["keypairID"] = keypair_id
        duration = self.duration()
        check_type("duration", duration, "base.Duration")
        v["duration"] = duration
        return v

    def base_url(self) -> str:
        """
        baseURL contains the SCHEME://HOST[/PATH] at which Cloudfront is served.
        """
        return self.__base_url

    def private_key(self) -> "k8sv1.SecretKeySelector":
        """
        privateKey points to secret containing the private key, provided by AWS.
        """
        return self.__private_key

    def keypair_id(self) -> str:
        """
        keypairID is key pair ID provided by AWS.
        """
        return self.__keypair_id

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
        region_endpoint: str = "",
        encrypt: bool = False,
        key_id: str = "",
        cloud_front: "ImageRegistryConfigStorageS3CloudFront" = None,
    ):
        super().__init__()
        self.__bucket = bucket
        self.__region = region
        self.__region_endpoint = region_endpoint
        self.__encrypt = encrypt
        self.__key_id = key_id
        self.__cloud_front = cloud_front

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        bucket = self.bucket()
        check_type("bucket", bucket, str)
        v["bucket"] = bucket
        region = self.region()
        check_type("region", region, str)
        v["region"] = region
        region_endpoint = self.region_endpoint()
        check_type("region_endpoint", region_endpoint, str)
        v["regionEndpoint"] = region_endpoint
        encrypt = self.encrypt()
        check_type("encrypt", encrypt, bool)
        v["encrypt"] = encrypt
        key_id = self.key_id()
        check_type("key_id", key_id, str)
        v["keyID"] = key_id
        cloud_front = self.cloud_front()
        check_type(
            "cloud_front",
            cloud_front,
            Optional["ImageRegistryConfigStorageS3CloudFront"],
        )
        if cloud_front is not None:  # omit empty
            v["cloudFront"] = cloud_front
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

    def region_endpoint(self) -> str:
        """
        regionEndpoint is the endpoint for S3 compatible storage services.
        Optional, defaults based on the Region that is provided.
        """
        return self.__region_endpoint

    def encrypt(self) -> bool:
        """
        encrypt specifies whether the registry stores the image in encrypted
        format or not.
        Optional, defaults to false.
        """
        return self.__encrypt

    def key_id(self) -> str:
        """
        keyID is the KMS key ID to use for encryption.
        Optional, Encrypt must be true, or this parameter is ignored.
        """
        return self.__key_id

    def cloud_front(self) -> Optional["ImageRegistryConfigStorageS3CloudFront"]:
        """
        cloudFront configures Amazon Cloudfront as the storage middleware in a
        registry.
        """
        return self.__cloud_front


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
        auth_url: str = "",
        auth_version: str = "",
        container: str = "",
        domain: str = "",
        domain_id: str = "",
        tenant: str = "",
        tenant_id: str = "",
        region_name: str = "",
    ):
        super().__init__()
        self.__auth_url = auth_url
        self.__auth_version = auth_version
        self.__container = container
        self.__domain = domain
        self.__domain_id = domain_id
        self.__tenant = tenant
        self.__tenant_id = tenant_id
        self.__region_name = region_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        auth_url = self.auth_url()
        check_type("auth_url", auth_url, str)
        v["authURL"] = auth_url
        auth_version = self.auth_version()
        check_type("auth_version", auth_version, str)
        v["authVersion"] = auth_version
        container = self.container()
        check_type("container", container, str)
        v["container"] = container
        domain = self.domain()
        check_type("domain", domain, str)
        v["domain"] = domain
        domain_id = self.domain_id()
        check_type("domain_id", domain_id, str)
        v["domainID"] = domain_id
        tenant = self.tenant()
        check_type("tenant", tenant, str)
        v["tenant"] = tenant
        tenant_id = self.tenant_id()
        check_type("tenant_id", tenant_id, str)
        v["tenantID"] = tenant_id
        region_name = self.region_name()
        check_type("region_name", region_name, str)
        v["regionName"] = region_name
        return v

    def auth_url(self) -> str:
        """
        authURL defines the URL for obtaining an authentication token.
        """
        return self.__auth_url

    def auth_version(self) -> str:
        """
        authVersion specifies the OpenStack Auth's version.
        """
        return self.__auth_version

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

    def domain_id(self) -> str:
        """
        domainID specifies Openstack's domain id for Identity v3 API.
        """
        return self.__domain_id

    def tenant(self) -> str:
        """
        tenant defines Openstack tenant name to be used by registry.
        """
        return self.__tenant

    def tenant_id(self) -> str:
        """
        tenant defines Openstack tenant id to be used by registry.
        """
        return self.__tenant_id

    def region_name(self) -> str:
        """
        regionName defines Openstack's region in which container exists.
        """
        return self.__region_name


class ImageRegistryConfigStorage(types.Object):
    """
    ImageRegistryConfigStorage describes how the storage should be configured
    for the image registry.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        empty_dir: "ImageRegistryConfigStorageEmptyDir" = None,
        s3: "ImageRegistryConfigStorageS3" = None,
        gcs: "ImageRegistryConfigStorageGCS" = None,
        swift: "ImageRegistryConfigStorageSwift" = None,
        pvc: "ImageRegistryConfigStoragePVC" = None,
        azure: "ImageRegistryConfigStorageAzure" = None,
    ):
        super().__init__()
        self.__empty_dir = empty_dir
        self.__s3 = s3
        self.__gcs = gcs
        self.__swift = swift
        self.__pvc = pvc
        self.__azure = azure

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        empty_dir = self.empty_dir()
        check_type(
            "empty_dir", empty_dir, Optional["ImageRegistryConfigStorageEmptyDir"]
        )
        if empty_dir is not None:  # omit empty
            v["emptyDir"] = empty_dir
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

    def empty_dir(self) -> Optional["ImageRegistryConfigStorageEmptyDir"]:
        """
        emptyDir represents ephemeral storage on the pod's host node.
        WARNING: this storage cannot be used with more than 1 replica and
        is not suitable for production use. When the pod is removed from a
        node for any reason, the data in the emptyDir is deleted forever.
        """
        return self.__empty_dir

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
        management_state: operatorv1.ManagementState = None,
        http_secret: str = "",
        proxy: "ImageRegistryConfigProxy" = None,
        storage: "ImageRegistryConfigStorage" = None,
        read_only: bool = False,
        disable_redirect: bool = False,
        requests: "ImageRegistryConfigRequests" = None,
        default_route: bool = False,
        routes: List["ImageRegistryConfigRoute"] = None,
        replicas: int = 0,
        logging: int = 0,
        resources: "k8sv1.ResourceRequirements" = None,
        node_selector: Dict[str, str] = None,
        tolerations: List["k8sv1.Toleration"] = None,
        rollout_strategy: str = None,
    ):
        super().__init__()
        self.__management_state = management_state
        self.__http_secret = http_secret
        self.__proxy = proxy if proxy is not None else ImageRegistryConfigProxy()
        self.__storage = (
            storage if storage is not None else ImageRegistryConfigStorage()
        )
        self.__read_only = read_only
        self.__disable_redirect = disable_redirect
        self.__requests = (
            requests if requests is not None else ImageRegistryConfigRequests()
        )
        self.__default_route = default_route
        self.__routes = routes if routes is not None else []
        self.__replicas = replicas
        self.__logging = logging
        self.__resources = resources
        self.__node_selector = node_selector if node_selector is not None else {}
        self.__tolerations = tolerations if tolerations is not None else []
        self.__rollout_strategy = rollout_strategy

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        management_state = self.management_state()
        check_type("management_state", management_state, operatorv1.ManagementState)
        v["managementState"] = management_state
        http_secret = self.http_secret()
        check_type("http_secret", http_secret, str)
        v["httpSecret"] = http_secret
        proxy = self.proxy()
        check_type("proxy", proxy, "ImageRegistryConfigProxy")
        v["proxy"] = proxy
        storage = self.storage()
        check_type("storage", storage, "ImageRegistryConfigStorage")
        v["storage"] = storage
        read_only = self.read_only()
        check_type("read_only", read_only, bool)
        v["readOnly"] = read_only
        disable_redirect = self.disable_redirect()
        check_type("disable_redirect", disable_redirect, bool)
        v["disableRedirect"] = disable_redirect
        requests = self.requests()
        check_type("requests", requests, "ImageRegistryConfigRequests")
        v["requests"] = requests
        default_route = self.default_route()
        check_type("default_route", default_route, bool)
        v["defaultRoute"] = default_route
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
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional[Dict[str, str]])
        if node_selector:  # omit empty
            v["nodeSelector"] = node_selector
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        rollout_strategy = self.rollout_strategy()
        check_type("rollout_strategy", rollout_strategy, Optional[str])
        if rollout_strategy:  # omit empty
            v["rolloutStrategy"] = rollout_strategy
        return v

    def management_state(self) -> operatorv1.ManagementState:
        """
        managementState indicates whether the registry instance represented
        by this config instance is under operator management or not.  Valid
        values are Managed, Unmanaged, and Removed.
        """
        return self.__management_state

    def http_secret(self) -> str:
        """
        httpSecret is the value needed by the registry to secure uploads, generated by default.
        """
        return self.__http_secret

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

    def read_only(self) -> bool:
        """
        readOnly indicates whether the registry instance should reject attempts
        to push new images or delete existing ones.
        """
        return self.__read_only

    def disable_redirect(self) -> bool:
        """
        disableRedirect controls whether to route all data through the Registry,
        rather than redirecting to the backend.
        """
        return self.__disable_redirect

    def requests(self) -> "ImageRegistryConfigRequests":
        """
        requests controls how many parallel requests a given registry instance
        will handle before queuing additional requests.
        """
        return self.__requests

    def default_route(self) -> bool:
        """
        defaultRoute indicates whether an external facing route for the registry
        should be created using the default generated hostname.
        """
        return self.__default_route

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

    def node_selector(self) -> Optional[Dict[str, str]]:
        """
        nodeSelector defines the node selection constraints for the registry
        pod.
        """
        return self.__node_selector

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        tolerations defines the tolerations for the registry pod.
        """
        return self.__tolerations

    def rollout_strategy(self) -> Optional[str]:
        """
        rolloutStrategy defines rollout strategy for the image registry
        deployment.
        """
        return self.__rollout_strategy


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
            api_version="imageregistry.operator.openshift.io/v1",
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


class ImagePrunerSpec(types.Object):
    """
    ImagePrunerSpec defines the specs for the running image pruner.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        schedule: str = "",
        suspend: bool = None,
        keep_tag_revisions: int = None,
        keep_younger_than: int = None,
        resources: "k8sv1.ResourceRequirements" = None,
        affinity: "k8sv1.Affinity" = None,
        node_selector: Dict[str, str] = None,
        tolerations: List["k8sv1.Toleration"] = None,
        successful_jobs_history_limit: int = None,
        failed_jobs_history_limit: int = None,
    ):
        super().__init__()
        self.__schedule = schedule
        self.__suspend = suspend
        self.__keep_tag_revisions = keep_tag_revisions
        self.__keep_younger_than = keep_younger_than
        self.__resources = resources
        self.__affinity = affinity
        self.__node_selector = node_selector if node_selector is not None else {}
        self.__tolerations = tolerations if tolerations is not None else []
        self.__successful_jobs_history_limit = successful_jobs_history_limit
        self.__failed_jobs_history_limit = failed_jobs_history_limit

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        schedule = self.schedule()
        check_type("schedule", schedule, str)
        v["schedule"] = schedule
        suspend = self.suspend()
        check_type("suspend", suspend, Optional[bool])
        if suspend is not None:  # omit empty
            v["suspend"] = suspend
        keep_tag_revisions = self.keep_tag_revisions()
        check_type("keep_tag_revisions", keep_tag_revisions, Optional[int])
        if keep_tag_revisions is not None:  # omit empty
            v["keepTagRevisions"] = keep_tag_revisions
        keep_younger_than = self.keep_younger_than()
        check_type("keep_younger_than", keep_younger_than, Optional[int])
        if keep_younger_than is not None:  # omit empty
            v["keepYoungerThan"] = keep_younger_than
        resources = self.resources()
        check_type("resources", resources, Optional["k8sv1.ResourceRequirements"])
        if resources is not None:  # omit empty
            v["resources"] = resources
        affinity = self.affinity()
        check_type("affinity", affinity, Optional["k8sv1.Affinity"])
        if affinity is not None:  # omit empty
            v["affinity"] = affinity
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional[Dict[str, str]])
        if node_selector:  # omit empty
            v["nodeSelector"] = node_selector
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        successful_jobs_history_limit = self.successful_jobs_history_limit()
        check_type(
            "successful_jobs_history_limit",
            successful_jobs_history_limit,
            Optional[int],
        )
        if successful_jobs_history_limit is not None:  # omit empty
            v["successfulJobsHistoryLimit"] = successful_jobs_history_limit
        failed_jobs_history_limit = self.failed_jobs_history_limit()
        check_type(
            "failed_jobs_history_limit", failed_jobs_history_limit, Optional[int]
        )
        if failed_jobs_history_limit is not None:  # omit empty
            v["failedJobsHistoryLimit"] = failed_jobs_history_limit
        return v

    def schedule(self) -> str:
        """
        schedule specifies when to execute the job using standard cronjob syntax: https://wikipedia.org/wiki/Cron.
        Defaults to `0 0 * * *`.
        """
        return self.__schedule

    def suspend(self) -> Optional[bool]:
        """
        suspend specifies whether or not to suspend subsequent executions of this cronjob.
        Defaults to false.
        """
        return self.__suspend

    def keep_tag_revisions(self) -> Optional[int]:
        """
        keepTagRevisions specifies the number of image revisions for a tag in an image stream that will be preserved.
        Defaults to 5.
        """
        return self.__keep_tag_revisions

    def keep_younger_than(self) -> Optional[int]:
        """
        keepYoungerThan specifies the minimum age of an image and its referrers for it to be considered a candidate for pruning.
        Defaults to 96h (96 hours).
        """
        return self.__keep_younger_than

    def resources(self) -> Optional["k8sv1.ResourceRequirements"]:
        """
        resources defines the resource requests and limits for the image pruner pod.
        """
        return self.__resources

    def affinity(self) -> Optional["k8sv1.Affinity"]:
        """
        affinity is a group of node affinity scheduling rules for the image pruner pod.
        """
        return self.__affinity

    def node_selector(self) -> Optional[Dict[str, str]]:
        """
        nodeSelector defines the node selection constraints for the image pruner pod.
        """
        return self.__node_selector

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        tolerations defines the node tolerations for the image pruner pod.
        """
        return self.__tolerations

    def successful_jobs_history_limit(self) -> Optional[int]:
        """
        successfulJobsHistoryLimit specifies how many successful image pruner jobs to retain.
        Defaults to 3 if not set.
        """
        return self.__successful_jobs_history_limit

    def failed_jobs_history_limit(self) -> Optional[int]:
        """
        failedJobsHistoryLimit specifies how many failed image pruner jobs to retain.
        Defaults to 3 if not set.
        """
        return self.__failed_jobs_history_limit


class ImagePruner(base.TypedObject, base.MetadataObject):
    """
    ImagePruner is the configuration object for an image registry pruner
    managed by the registry operator.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ImagePrunerSpec" = None,
    ):
        super().__init__(
            api_version="imageregistry.operator.openshift.io/v1",
            kind="ImagePruner",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ImagePrunerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ImagePrunerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ImagePrunerSpec":
        return self.__spec
