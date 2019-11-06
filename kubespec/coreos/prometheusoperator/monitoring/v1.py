# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional, Union

from kubespec.k8s import base
from kubespec.k8s.api.core import v1 as corev1
from kubespec.k8s.apimachinery.meta import v1 as metav1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


class BasicAuth(types.Object):
    """
    BasicAuth allow an endpoint to authenticate over basic authentication
    More info: https://prometheus.io/docs/operating/configuration/#endpoints
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        username: "corev1.SecretKeySelector" = None,
        password: "corev1.SecretKeySelector" = None,
    ):
        super().__init__()
        self.__username = (
            username if username is not None else corev1.SecretKeySelector()
        )
        self.__password = (
            password if password is not None else corev1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        username = self.username()
        check_type("username", username, Optional["corev1.SecretKeySelector"])
        v["username"] = username
        password = self.password()
        check_type("password", password, Optional["corev1.SecretKeySelector"])
        v["password"] = password
        return v

    def username(self) -> Optional["corev1.SecretKeySelector"]:
        """
        The secret in the service monitor namespace that contains the username
        for authentication.
        """
        return self.__username

    def password(self) -> Optional["corev1.SecretKeySelector"]:
        """
        The secret in the service monitor namespace that contains the password
        for authentication.
        """
        return self.__password


class SecretOrConfigMap(types.Object):
    """
    SecretOrConfigMap allows to specify data as a Secret or ConfigMap. Fields are mutually exclusive.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        secret: "corev1.SecretKeySelector" = None,
        configMap: "corev1.ConfigMapKeySelector" = None,
    ):
        super().__init__()
        self.__secret = secret
        self.__configMap = configMap

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secret = self.secret()
        check_type("secret", secret, Optional["corev1.SecretKeySelector"])
        if secret is not None:  # omit empty
            v["secret"] = secret
        configMap = self.configMap()
        check_type("configMap", configMap, Optional["corev1.ConfigMapKeySelector"])
        if configMap is not None:  # omit empty
            v["configMap"] = configMap
        return v

    def secret(self) -> Optional["corev1.SecretKeySelector"]:
        """
        Secret containing data to use for the targets.
        """
        return self.__secret

    def configMap(self) -> Optional["corev1.ConfigMapKeySelector"]:
        """
        ConfigMap containing data to use for the targets.
        """
        return self.__configMap


class TLSConfig(types.Object):
    """
    TLSConfig specifies TLS configuration parameters.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        caFile: str = None,
        ca: "SecretOrConfigMap" = None,
        certFile: str = None,
        cert: "SecretOrConfigMap" = None,
        keyFile: str = None,
        keySecret: "corev1.SecretKeySelector" = None,
        serverName: str = None,
        insecureSkipVerify: bool = None,
    ):
        super().__init__()
        self.__caFile = caFile
        self.__ca = ca if ca is not None else SecretOrConfigMap()
        self.__certFile = certFile
        self.__cert = cert if cert is not None else SecretOrConfigMap()
        self.__keyFile = keyFile
        self.__keySecret = keySecret
        self.__serverName = serverName
        self.__insecureSkipVerify = insecureSkipVerify

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        caFile = self.caFile()
        check_type("caFile", caFile, Optional[str])
        if caFile:  # omit empty
            v["caFile"] = caFile
        ca = self.ca()
        check_type("ca", ca, Optional["SecretOrConfigMap"])
        v["ca"] = ca
        certFile = self.certFile()
        check_type("certFile", certFile, Optional[str])
        if certFile:  # omit empty
            v["certFile"] = certFile
        cert = self.cert()
        check_type("cert", cert, Optional["SecretOrConfigMap"])
        v["cert"] = cert
        keyFile = self.keyFile()
        check_type("keyFile", keyFile, Optional[str])
        if keyFile:  # omit empty
            v["keyFile"] = keyFile
        keySecret = self.keySecret()
        check_type("keySecret", keySecret, Optional["corev1.SecretKeySelector"])
        if keySecret is not None:  # omit empty
            v["keySecret"] = keySecret
        serverName = self.serverName()
        check_type("serverName", serverName, Optional[str])
        if serverName:  # omit empty
            v["serverName"] = serverName
        insecureSkipVerify = self.insecureSkipVerify()
        check_type("insecureSkipVerify", insecureSkipVerify, Optional[bool])
        if insecureSkipVerify:  # omit empty
            v["insecureSkipVerify"] = insecureSkipVerify
        return v

    def caFile(self) -> Optional[str]:
        """
        Path to the CA cert in the Prometheus container to use for the targets.
        """
        return self.__caFile

    def ca(self) -> Optional["SecretOrConfigMap"]:
        """
        Stuct containing the CA cert to use for the targets.
        """
        return self.__ca

    def certFile(self) -> Optional[str]:
        """
        Path to the client cert file in the Prometheus container for the targets.
        """
        return self.__certFile

    def cert(self) -> Optional["SecretOrConfigMap"]:
        """
        Struct containing the client cert file for the targets.
        """
        return self.__cert

    def keyFile(self) -> Optional[str]:
        """
        Path to the client key file in the Prometheus container for the targets.
        """
        return self.__keyFile

    def keySecret(self) -> Optional["corev1.SecretKeySelector"]:
        """
        Secret containing the client key file for the targets.
        """
        return self.__keySecret

    def serverName(self) -> Optional[str]:
        """
        Used to verify the hostname for the targets.
        """
        return self.__serverName

    def insecureSkipVerify(self) -> Optional[bool]:
        """
        Disable target certificate validation.
        """
        return self.__insecureSkipVerify


class APIServerConfig(types.Object):
    """
    APIServerConfig defines a host and auth methods to access apiserver.
    More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#kubernetes_sd_config
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        host: str = "",
        basicAuth: "BasicAuth" = None,
        bearerToken: str = None,
        bearerTokenFile: str = None,
        tlsConfig: "TLSConfig" = None,
    ):
        super().__init__()
        self.__host = host
        self.__basicAuth = basicAuth
        self.__bearerToken = bearerToken
        self.__bearerTokenFile = bearerTokenFile
        self.__tlsConfig = tlsConfig

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        host = self.host()
        check_type("host", host, str)
        v["host"] = host
        basicAuth = self.basicAuth()
        check_type("basicAuth", basicAuth, Optional["BasicAuth"])
        if basicAuth is not None:  # omit empty
            v["basicAuth"] = basicAuth
        bearerToken = self.bearerToken()
        check_type("bearerToken", bearerToken, Optional[str])
        if bearerToken:  # omit empty
            v["bearerToken"] = bearerToken
        bearerTokenFile = self.bearerTokenFile()
        check_type("bearerTokenFile", bearerTokenFile, Optional[str])
        if bearerTokenFile:  # omit empty
            v["bearerTokenFile"] = bearerTokenFile
        tlsConfig = self.tlsConfig()
        check_type("tlsConfig", tlsConfig, Optional["TLSConfig"])
        if tlsConfig is not None:  # omit empty
            v["tlsConfig"] = tlsConfig
        return v

    def host(self) -> str:
        """
        Host of apiserver.
        A valid string consisting of a hostname or IP followed by an optional port number
        """
        return self.__host

    def basicAuth(self) -> Optional["BasicAuth"]:
        """
        BasicAuth allow an endpoint to authenticate over basic authentication
        """
        return self.__basicAuth

    def bearerToken(self) -> Optional[str]:
        """
        Bearer token for accessing apiserver.
        """
        return self.__bearerToken

    def bearerTokenFile(self) -> Optional[str]:
        """
        File to read bearer token for accessing apiserver.
        """
        return self.__bearerTokenFile

    def tlsConfig(self) -> Optional["TLSConfig"]:
        """
        TLS Config to use for accessing apiserver.
        """
        return self.__tlsConfig


class AlertmanagerEndpoints(types.Object):
    """
    AlertmanagerEndpoints defines a selection of a single Endpoints object
    containing alertmanager IPs to fire alerts against.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = "",
        name: str = "",
        port: Union[int, str] = None,
        scheme: str = None,
        pathPrefix: str = None,
        tlsConfig: "TLSConfig" = None,
        bearerTokenFile: str = None,
    ):
        super().__init__()
        self.__namespace = namespace
        self.__name = name
        self.__port = port if port is not None else 0
        self.__scheme = scheme
        self.__pathPrefix = pathPrefix
        self.__tlsConfig = tlsConfig
        self.__bearerTokenFile = bearerTokenFile

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, str)
        v["namespace"] = namespace
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        port = self.port()
        check_type("port", port, Union[int, str])
        v["port"] = port
        scheme = self.scheme()
        check_type("scheme", scheme, Optional[str])
        if scheme:  # omit empty
            v["scheme"] = scheme
        pathPrefix = self.pathPrefix()
        check_type("pathPrefix", pathPrefix, Optional[str])
        if pathPrefix:  # omit empty
            v["pathPrefix"] = pathPrefix
        tlsConfig = self.tlsConfig()
        check_type("tlsConfig", tlsConfig, Optional["TLSConfig"])
        if tlsConfig is not None:  # omit empty
            v["tlsConfig"] = tlsConfig
        bearerTokenFile = self.bearerTokenFile()
        check_type("bearerTokenFile", bearerTokenFile, Optional[str])
        if bearerTokenFile:  # omit empty
            v["bearerTokenFile"] = bearerTokenFile
        return v

    def namespace(self) -> str:
        """
        Namespace of Endpoints object.
        """
        return self.__namespace

    def name(self) -> str:
        """
        Name of Endpoints object in Namespace.
        """
        return self.__name

    def port(self) -> Union[int, str]:
        """
        Port the Alertmanager API is exposed on.
        """
        return self.__port

    def scheme(self) -> Optional[str]:
        """
        Scheme to use when firing alerts.
        """
        return self.__scheme

    def pathPrefix(self) -> Optional[str]:
        """
        Prefix for the HTTP path alerts are pushed to.
        """
        return self.__pathPrefix

    def tlsConfig(self) -> Optional["TLSConfig"]:
        """
        TLS Config to use for alertmanager connection.
        """
        return self.__tlsConfig

    def bearerTokenFile(self) -> Optional[str]:
        """
        BearerTokenFile to read from filesystem to use when authenticating to
        Alertmanager.
        """
        return self.__bearerTokenFile


class AlertingSpec(types.Object):
    """
    AlertingSpec defines parameters for alerting configuration of Prometheus servers.
    """

    @context.scoped
    @typechecked
    def __init__(self, alertmanagers: List["AlertmanagerEndpoints"] = None):
        super().__init__()
        self.__alertmanagers = alertmanagers if alertmanagers is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        alertmanagers = self.alertmanagers()
        check_type("alertmanagers", alertmanagers, List["AlertmanagerEndpoints"])
        v["alertmanagers"] = alertmanagers
        return v

    def alertmanagers(self) -> List["AlertmanagerEndpoints"]:
        """
        AlertmanagerEndpoints Prometheus should fire alerts against.
        """
        return self.__alertmanagers


class StorageSpec(types.Object):
    """
    StorageSpec defines the configured storage for a group Prometheus servers.
    If neither `emptyDir` nor `volumeClaimTemplate` is specified, then by default an [EmptyDir](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) will be used.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        emptyDir: "corev1.EmptyDirVolumeSource" = None,
        volumeClaimTemplate: "corev1.PersistentVolumeClaim" = None,
    ):
        super().__init__()
        self.__emptyDir = emptyDir
        self.__volumeClaimTemplate = (
            volumeClaimTemplate
            if volumeClaimTemplate is not None
            else corev1.PersistentVolumeClaim()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        emptyDir = self.emptyDir()
        check_type("emptyDir", emptyDir, Optional["corev1.EmptyDirVolumeSource"])
        if emptyDir is not None:  # omit empty
            v["emptyDir"] = emptyDir
        volumeClaimTemplate = self.volumeClaimTemplate()
        check_type(
            "volumeClaimTemplate",
            volumeClaimTemplate,
            Optional["corev1.PersistentVolumeClaim"],
        )
        v["volumeClaimTemplate"] = volumeClaimTemplate
        return v

    def emptyDir(self) -> Optional["corev1.EmptyDirVolumeSource"]:
        """
        EmptyDirVolumeSource to be used by the Prometheus StatefulSets. If specified, used in place of any volumeClaimTemplate. More
        info: https://kubernetes.io/docs/concepts/storage/volumes/#emptydir
        """
        return self.__emptyDir

    def volumeClaimTemplate(self) -> Optional["corev1.PersistentVolumeClaim"]:
        """
        A PVC spec to be used by the Prometheus StatefulSets.
        """
        return self.__volumeClaimTemplate


class AlertmanagerSpec(types.Object):
    """
    AlertmanagerSpec is a specification of the desired behavior of the Alertmanager cluster. More info:
    https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        podMetadata: "metav1.ObjectMeta" = None,
        image: str = None,
        version: str = None,
        tag: str = None,
        sha: str = None,
        baseImage: str = None,
        imagePullSecrets: List["corev1.LocalObjectReference"] = None,
        secrets: List[str] = None,
        configMaps: List[str] = None,
        configSecret: str = None,
        logLevel: str = None,
        logFormat: str = None,
        replicas: int = None,
        retention: str = None,
        storage: "StorageSpec" = None,
        volumes: List["corev1.Volume"] = None,
        volumeMounts: List["corev1.VolumeMount"] = None,
        externalUrl: str = None,
        routePrefix: str = None,
        paused: bool = None,
        nodeSelector: Dict[str, str] = None,
        resources: "corev1.ResourceRequirements" = None,
        affinity: "corev1.Affinity" = None,
        tolerations: List["corev1.Toleration"] = None,
        securityContext: "corev1.PodSecurityContext" = None,
        serviceAccountName: str = None,
        listenLocal: bool = None,
        containers: List["corev1.Container"] = None,
        initContainers: List["corev1.Container"] = None,
        priorityClassName: str = None,
        additionalPeers: List[str] = None,
        portName: str = None,
    ):
        super().__init__()
        self.__podMetadata = podMetadata
        self.__image = image
        self.__version = version
        self.__tag = tag
        self.__sha = sha
        self.__baseImage = baseImage
        self.__imagePullSecrets = (
            imagePullSecrets if imagePullSecrets is not None else []
        )
        self.__secrets = secrets if secrets is not None else []
        self.__configMaps = configMaps if configMaps is not None else []
        self.__configSecret = configSecret
        self.__logLevel = logLevel
        self.__logFormat = logFormat
        self.__replicas = replicas
        self.__retention = retention
        self.__storage = storage
        self.__volumes = volumes if volumes is not None else []
        self.__volumeMounts = volumeMounts if volumeMounts is not None else []
        self.__externalUrl = externalUrl
        self.__routePrefix = routePrefix
        self.__paused = paused
        self.__nodeSelector = nodeSelector if nodeSelector is not None else {}
        self.__resources = (
            resources if resources is not None else corev1.ResourceRequirements()
        )
        self.__affinity = affinity
        self.__tolerations = tolerations if tolerations is not None else []
        self.__securityContext = securityContext
        self.__serviceAccountName = serviceAccountName
        self.__listenLocal = listenLocal
        self.__containers = containers if containers is not None else []
        self.__initContainers = initContainers if initContainers is not None else []
        self.__priorityClassName = priorityClassName
        self.__additionalPeers = additionalPeers if additionalPeers is not None else []
        self.__portName = portName

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        podMetadata = self.podMetadata()
        check_type("podMetadata", podMetadata, Optional["metav1.ObjectMeta"])
        if podMetadata is not None:  # omit empty
            v["podMetadata"] = podMetadata
        image = self.image()
        check_type("image", image, Optional[str])
        if image is not None:  # omit empty
            v["image"] = image
        version = self.version()
        check_type("version", version, Optional[str])
        if version:  # omit empty
            v["version"] = version
        tag = self.tag()
        check_type("tag", tag, Optional[str])
        if tag:  # omit empty
            v["tag"] = tag
        sha = self.sha()
        check_type("sha", sha, Optional[str])
        if sha:  # omit empty
            v["sha"] = sha
        baseImage = self.baseImage()
        check_type("baseImage", baseImage, Optional[str])
        if baseImage:  # omit empty
            v["baseImage"] = baseImage
        imagePullSecrets = self.imagePullSecrets()
        check_type(
            "imagePullSecrets",
            imagePullSecrets,
            Optional[List["corev1.LocalObjectReference"]],
        )
        if imagePullSecrets:  # omit empty
            v["imagePullSecrets"] = imagePullSecrets
        secrets = self.secrets()
        check_type("secrets", secrets, Optional[List[str]])
        if secrets:  # omit empty
            v["secrets"] = secrets
        configMaps = self.configMaps()
        check_type("configMaps", configMaps, Optional[List[str]])
        if configMaps:  # omit empty
            v["configMaps"] = configMaps
        configSecret = self.configSecret()
        check_type("configSecret", configSecret, Optional[str])
        if configSecret:  # omit empty
            v["configSecret"] = configSecret
        logLevel = self.logLevel()
        check_type("logLevel", logLevel, Optional[str])
        if logLevel:  # omit empty
            v["logLevel"] = logLevel
        logFormat = self.logFormat()
        check_type("logFormat", logFormat, Optional[str])
        if logFormat:  # omit empty
            v["logFormat"] = logFormat
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas is not None:  # omit empty
            v["replicas"] = replicas
        retention = self.retention()
        check_type("retention", retention, Optional[str])
        if retention:  # omit empty
            v["retention"] = retention
        storage = self.storage()
        check_type("storage", storage, Optional["StorageSpec"])
        if storage is not None:  # omit empty
            v["storage"] = storage
        volumes = self.volumes()
        check_type("volumes", volumes, Optional[List["corev1.Volume"]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        volumeMounts = self.volumeMounts()
        check_type("volumeMounts", volumeMounts, Optional[List["corev1.VolumeMount"]])
        if volumeMounts:  # omit empty
            v["volumeMounts"] = volumeMounts
        externalUrl = self.externalUrl()
        check_type("externalUrl", externalUrl, Optional[str])
        if externalUrl:  # omit empty
            v["externalUrl"] = externalUrl
        routePrefix = self.routePrefix()
        check_type("routePrefix", routePrefix, Optional[str])
        if routePrefix:  # omit empty
            v["routePrefix"] = routePrefix
        paused = self.paused()
        check_type("paused", paused, Optional[bool])
        if paused:  # omit empty
            v["paused"] = paused
        nodeSelector = self.nodeSelector()
        check_type("nodeSelector", nodeSelector, Optional[Dict[str, str]])
        if nodeSelector:  # omit empty
            v["nodeSelector"] = nodeSelector
        resources = self.resources()
        check_type("resources", resources, Optional["corev1.ResourceRequirements"])
        v["resources"] = resources
        affinity = self.affinity()
        check_type("affinity", affinity, Optional["corev1.Affinity"])
        if affinity is not None:  # omit empty
            v["affinity"] = affinity
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["corev1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        securityContext = self.securityContext()
        check_type(
            "securityContext", securityContext, Optional["corev1.PodSecurityContext"]
        )
        if securityContext is not None:  # omit empty
            v["securityContext"] = securityContext
        serviceAccountName = self.serviceAccountName()
        check_type("serviceAccountName", serviceAccountName, Optional[str])
        if serviceAccountName:  # omit empty
            v["serviceAccountName"] = serviceAccountName
        listenLocal = self.listenLocal()
        check_type("listenLocal", listenLocal, Optional[bool])
        if listenLocal:  # omit empty
            v["listenLocal"] = listenLocal
        containers = self.containers()
        check_type("containers", containers, Optional[List["corev1.Container"]])
        if containers:  # omit empty
            v["containers"] = containers
        initContainers = self.initContainers()
        check_type("initContainers", initContainers, Optional[List["corev1.Container"]])
        if initContainers:  # omit empty
            v["initContainers"] = initContainers
        priorityClassName = self.priorityClassName()
        check_type("priorityClassName", priorityClassName, Optional[str])
        if priorityClassName:  # omit empty
            v["priorityClassName"] = priorityClassName
        additionalPeers = self.additionalPeers()
        check_type("additionalPeers", additionalPeers, Optional[List[str]])
        if additionalPeers:  # omit empty
            v["additionalPeers"] = additionalPeers
        portName = self.portName()
        check_type("portName", portName, Optional[str])
        if portName:  # omit empty
            v["portName"] = portName
        return v

    def podMetadata(self) -> Optional["metav1.ObjectMeta"]:
        """
        Standard object’s metadata. More info:
        https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
        Metadata Labels and Annotations gets propagated to the prometheus pods.
        """
        return self.__podMetadata

    def image(self) -> Optional[str]:
        """
        Image if specified has precedence over baseImage, tag and sha
        combinations. Specifying the version is still necessary to ensure the
        Prometheus Operator knows what version of Alertmanager is being
        configured.
        """
        return self.__image

    def version(self) -> Optional[str]:
        """
        Version the cluster should be on.
        """
        return self.__version

    def tag(self) -> Optional[str]:
        """
        Tag of Alertmanager container image to be deployed. Defaults to the value of `version`.
        Version is ignored if Tag is set.
        """
        return self.__tag

    def sha(self) -> Optional[str]:
        """
        SHA of Alertmanager container image to be deployed. Defaults to the value of `version`.
        Similar to a tag, but the SHA explicitly deploys an immutable container image.
        Version and Tag are ignored if SHA is set.
        """
        return self.__sha

    def baseImage(self) -> Optional[str]:
        """
        Base image that is used to deploy pods, without tag.
        """
        return self.__baseImage

    def imagePullSecrets(self) -> Optional[List["corev1.LocalObjectReference"]]:
        """
        An optional list of references to secrets in the same namespace
        to use for pulling prometheus and alertmanager images from registries
        see http://kubernetes.io/docs/user-guide/images#specifying-imagepullsecrets-on-a-pod
        """
        return self.__imagePullSecrets

    def secrets(self) -> Optional[List[str]]:
        """
        Secrets is a list of Secrets in the same namespace as the Alertmanager
        object, which shall be mounted into the Alertmanager Pods.
        The Secrets are mounted into /etc/alertmanager/secrets/<secret-name>.
        """
        return self.__secrets

    def configMaps(self) -> Optional[List[str]]:
        """
        ConfigMaps is a list of ConfigMaps in the same namespace as the Alertmanager
        object, which shall be mounted into the Alertmanager Pods.
        The ConfigMaps are mounted into /etc/alertmanager/configmaps/<configmap-name>.
        """
        return self.__configMaps

    def configSecret(self) -> Optional[str]:
        """
        ConfigSecret is the name of a Kubernetes Secret in the same namespace as the
        Alertmanager object, which contains configuration for this Alertmanager
        instance. Defaults to 'alertmanager-<alertmanager-name>'
        The secret is mounted into /etc/alertmanager/config.
        """
        return self.__configSecret

    def logLevel(self) -> Optional[str]:
        """
        Log level for Alertmanager to be configured with.
        """
        return self.__logLevel

    def logFormat(self) -> Optional[str]:
        """
        Log format for Alertmanager to be configured with.
        """
        return self.__logFormat

    def replicas(self) -> Optional[int]:
        """
        Size is the expected size of the alertmanager cluster. The controller will
        eventually make the size of the running cluster equal to the expected
        size.
        """
        return self.__replicas

    def retention(self) -> Optional[str]:
        """
        Time duration Alertmanager shall retain data for. Default is '120h',
        and must match the regular expression `[0-9]+(ms|s|m|h)` (milliseconds seconds minutes hours).
        """
        return self.__retention

    def storage(self) -> Optional["StorageSpec"]:
        """
        Storage is the definition of how storage will be used by the Alertmanager
        instances.
        """
        return self.__storage

    def volumes(self) -> Optional[List["corev1.Volume"]]:
        """
        Volumes allows configuration of additional volumes on the output StatefulSet definition.
        Volumes specified will be appended to other volumes that are generated as a result of
        StorageSpec objects.
        """
        return self.__volumes

    def volumeMounts(self) -> Optional[List["corev1.VolumeMount"]]:
        """
        VolumeMounts allows configuration of additional VolumeMounts on the output StatefulSet definition.
        VolumeMounts specified will be appended to other VolumeMounts in the alertmanager container,
        that are generated as a result of StorageSpec objects.
        """
        return self.__volumeMounts

    def externalUrl(self) -> Optional[str]:
        """
        The external URL the Alertmanager instances will be available under. This is
        necessary to generate correct URLs. This is necessary if Alertmanager is not
        served from root of a DNS name.
        """
        return self.__externalUrl

    def routePrefix(self) -> Optional[str]:
        """
        The route prefix Alertmanager registers HTTP handlers for. This is useful,
        if using ExternalURL and a proxy is rewriting HTTP routes of a request,
        and the actual ExternalURL is still true, but the server serves requests
        under a different route prefix. For example for use with `kubectl proxy`.
        """
        return self.__routePrefix

    def paused(self) -> Optional[bool]:
        """
        If set to true all actions on the underlaying managed objects are not
        goint to be performed, except for delete actions.
        """
        return self.__paused

    def nodeSelector(self) -> Optional[Dict[str, str]]:
        """
        Define which Nodes the Pods are scheduled on.
        """
        return self.__nodeSelector

    def resources(self) -> Optional["corev1.ResourceRequirements"]:
        """
        Define resources requests and limits for single Pods.
        """
        return self.__resources

    def affinity(self) -> Optional["corev1.Affinity"]:
        """
        If specified, the pod's scheduling constraints.
        """
        return self.__affinity

    def tolerations(self) -> Optional[List["corev1.Toleration"]]:
        """
        If specified, the pod's tolerations.
        """
        return self.__tolerations

    def securityContext(self) -> Optional["corev1.PodSecurityContext"]:
        """
        SecurityContext holds pod-level security attributes and common container settings.
        This defaults to the default PodSecurityContext.
        """
        return self.__securityContext

    def serviceAccountName(self) -> Optional[str]:
        """
        ServiceAccountName is the name of the ServiceAccount to use to run the
        Prometheus Pods.
        """
        return self.__serviceAccountName

    def listenLocal(self) -> Optional[bool]:
        """
        ListenLocal makes the Alertmanager server listen on loopback, so that it
        does not bind against the Pod IP. Note this is only for the Alertmanager
        UI, not the gossip communication.
        """
        return self.__listenLocal

    def containers(self) -> Optional[List["corev1.Container"]]:
        """
        Containers allows injecting additional containers. This is meant to
        allow adding an authentication proxy to an Alertmanager pod.
        """
        return self.__containers

    def initContainers(self) -> Optional[List["corev1.Container"]]:
        """
        InitContainers allows adding initContainers to the pod definition. Those can be used to e.g.
        fetch secrets for injection into the Alertmanager configuration from external sources. Any
        errors during the execution of an initContainer will lead to a restart of the Pod. More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
        Using initContainers for any use case other then secret fetching is entirely outside the scope
        of what the maintainers will support and by doing so, you accept that this behaviour may break
        at any time without notice.
        """
        return self.__initContainers

    def priorityClassName(self) -> Optional[str]:
        """
        Priority class assigned to the Pods
        """
        return self.__priorityClassName

    def additionalPeers(self) -> Optional[List[str]]:
        """
        AdditionalPeers allows injecting a set of additional Alertmanagers to peer with to form a highly available cluster.
        """
        return self.__additionalPeers

    def portName(self) -> Optional[str]:
        """
        Port name used for the pods and governing service.
        This defaults to web
        """
        return self.__portName


class Alertmanager(base.TypedObject, base.NamespacedMetadataObject):
    """
    Alertmanager describes an Alertmanager cluster.
    +genclient
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "AlertmanagerSpec" = None,
    ):
        super().__init__(
            apiVersion="monitoring.coreos.com/v1",
            kind="Alertmanager",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else AlertmanagerSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "AlertmanagerSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "AlertmanagerSpec":
        """
        Specification of the desired behavior of the Alertmanager cluster. More info:
        https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class ArbitraryFSAccessThroughSMsConfig(types.Object):
    """
    ArbitraryFSAccessThroughSMsConfig enables users to configure, whether
    a service monitor selected by the Prometheus instance is allowed to use
    arbitrary files on the file system of the Prometheus container. This is the case
    when e.g. a service monitor specifies a BearerTokenFile in an endpoint. A
    malicious user could create a service monitor selecting arbitrary secret files
    in the Prometheus container. Those secrets would then be sent with a scrape
    request by Prometheus to a malicious target. Denying the above would prevent the
    attack, users can instead use the BearerTokenSecret field.
    """

    @context.scoped
    @typechecked
    def __init__(self, deny: bool = None):
        super().__init__()
        self.__deny = deny

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        deny = self.deny()
        check_type("deny", deny, Optional[bool])
        if deny:  # omit empty
            v["deny"] = deny
        return v

    def deny(self) -> Optional[bool]:
        return self.__deny


class RelabelConfig(types.Object):
    """
    RelabelConfig allows dynamic rewriting of the label set, being applied to samples before ingestion.
    It defines `<metric_relabel_configs>`-section of Prometheus configuration.
    More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#metric_relabel_configs
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        sourceLabels: List[str] = None,
        separator: str = None,
        targetLabel: str = None,
        regex: str = None,
        modulus: int = None,
        replacement: str = None,
        action: str = None,
    ):
        super().__init__()
        self.__sourceLabels = sourceLabels if sourceLabels is not None else []
        self.__separator = separator
        self.__targetLabel = targetLabel
        self.__regex = regex
        self.__modulus = modulus
        self.__replacement = replacement
        self.__action = action

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        sourceLabels = self.sourceLabels()
        check_type("sourceLabels", sourceLabels, Optional[List[str]])
        if sourceLabels:  # omit empty
            v["sourceLabels"] = sourceLabels
        separator = self.separator()
        check_type("separator", separator, Optional[str])
        if separator:  # omit empty
            v["separator"] = separator
        targetLabel = self.targetLabel()
        check_type("targetLabel", targetLabel, Optional[str])
        if targetLabel:  # omit empty
            v["targetLabel"] = targetLabel
        regex = self.regex()
        check_type("regex", regex, Optional[str])
        if regex:  # omit empty
            v["regex"] = regex
        modulus = self.modulus()
        check_type("modulus", modulus, Optional[int])
        if modulus:  # omit empty
            v["modulus"] = modulus
        replacement = self.replacement()
        check_type("replacement", replacement, Optional[str])
        if replacement:  # omit empty
            v["replacement"] = replacement
        action = self.action()
        check_type("action", action, Optional[str])
        if action:  # omit empty
            v["action"] = action
        return v

    def sourceLabels(self) -> Optional[List[str]]:
        """
        The source labels select values from existing labels. Their content is concatenated
        using the configured separator and matched against the configured regular expression
        for the replace, keep, and drop actions.
        """
        return self.__sourceLabels

    def separator(self) -> Optional[str]:
        """
        Separator placed between concatenated source label values. default is ';'.
        """
        return self.__separator

    def targetLabel(self) -> Optional[str]:
        """
        Label to which the resulting value is written in a replace action.
        It is mandatory for replace actions. Regex capture groups are available.
        """
        return self.__targetLabel

    def regex(self) -> Optional[str]:
        """
        Regular expression against which the extracted value is matched. defailt is '(.*)'
        """
        return self.__regex

    def modulus(self) -> Optional[int]:
        """
        Modulus to take of the hash of the source label values.
        """
        return self.__modulus

    def replacement(self) -> Optional[str]:
        """
        Replacement value against which a regex replace is performed if the
        regular expression matches. Regex capture groups are available. Default is '$1'
        """
        return self.__replacement

    def action(self) -> Optional[str]:
        """
        Action to perform based on regex matching. Default is 'replace'
        """
        return self.__action


class Endpoint(types.Object):
    """
    Endpoint defines a scrapeable endpoint serving Prometheus metrics.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        port: str = None,
        targetPort: Union[int, str] = None,
        path: str = None,
        scheme: str = None,
        params: Dict[str, List[str]] = None,
        interval: str = None,
        scrapeTimeout: str = None,
        tlsConfig: "TLSConfig" = None,
        bearerTokenFile: str = None,
        bearerTokenSecret: "corev1.SecretKeySelector" = None,
        honorLabels: bool = None,
        honorTimestamps: bool = None,
        basicAuth: "BasicAuth" = None,
        metricRelabelings: List["RelabelConfig"] = None,
        relabelings: List["RelabelConfig"] = None,
        proxyUrl: str = None,
    ):
        super().__init__()
        self.__port = port
        self.__targetPort = targetPort
        self.__path = path
        self.__scheme = scheme
        self.__params = params if params is not None else {}
        self.__interval = interval
        self.__scrapeTimeout = scrapeTimeout
        self.__tlsConfig = tlsConfig
        self.__bearerTokenFile = bearerTokenFile
        self.__bearerTokenSecret = (
            bearerTokenSecret
            if bearerTokenSecret is not None
            else corev1.SecretKeySelector()
        )
        self.__honorLabels = honorLabels
        self.__honorTimestamps = honorTimestamps
        self.__basicAuth = basicAuth
        self.__metricRelabelings = (
            metricRelabelings if metricRelabelings is not None else []
        )
        self.__relabelings = relabelings if relabelings is not None else []
        self.__proxyUrl = proxyUrl

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        port = self.port()
        check_type("port", port, Optional[str])
        if port:  # omit empty
            v["port"] = port
        targetPort = self.targetPort()
        check_type("targetPort", targetPort, Optional[Union[int, str]])
        if targetPort is not None:  # omit empty
            v["targetPort"] = targetPort
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        scheme = self.scheme()
        check_type("scheme", scheme, Optional[str])
        if scheme:  # omit empty
            v["scheme"] = scheme
        params = self.params()
        check_type("params", params, Optional[Dict[str, List[str]]])
        if params:  # omit empty
            v["params"] = params
        interval = self.interval()
        check_type("interval", interval, Optional[str])
        if interval:  # omit empty
            v["interval"] = interval
        scrapeTimeout = self.scrapeTimeout()
        check_type("scrapeTimeout", scrapeTimeout, Optional[str])
        if scrapeTimeout:  # omit empty
            v["scrapeTimeout"] = scrapeTimeout
        tlsConfig = self.tlsConfig()
        check_type("tlsConfig", tlsConfig, Optional["TLSConfig"])
        if tlsConfig is not None:  # omit empty
            v["tlsConfig"] = tlsConfig
        bearerTokenFile = self.bearerTokenFile()
        check_type("bearerTokenFile", bearerTokenFile, Optional[str])
        if bearerTokenFile:  # omit empty
            v["bearerTokenFile"] = bearerTokenFile
        bearerTokenSecret = self.bearerTokenSecret()
        check_type(
            "bearerTokenSecret", bearerTokenSecret, Optional["corev1.SecretKeySelector"]
        )
        v["bearerTokenSecret"] = bearerTokenSecret
        honorLabels = self.honorLabels()
        check_type("honorLabels", honorLabels, Optional[bool])
        if honorLabels:  # omit empty
            v["honorLabels"] = honorLabels
        honorTimestamps = self.honorTimestamps()
        check_type("honorTimestamps", honorTimestamps, Optional[bool])
        if honorTimestamps is not None:  # omit empty
            v["honorTimestamps"] = honorTimestamps
        basicAuth = self.basicAuth()
        check_type("basicAuth", basicAuth, Optional["BasicAuth"])
        if basicAuth is not None:  # omit empty
            v["basicAuth"] = basicAuth
        metricRelabelings = self.metricRelabelings()
        check_type(
            "metricRelabelings", metricRelabelings, Optional[List["RelabelConfig"]]
        )
        if metricRelabelings:  # omit empty
            v["metricRelabelings"] = metricRelabelings
        relabelings = self.relabelings()
        check_type("relabelings", relabelings, Optional[List["RelabelConfig"]])
        if relabelings:  # omit empty
            v["relabelings"] = relabelings
        proxyUrl = self.proxyUrl()
        check_type("proxyUrl", proxyUrl, Optional[str])
        if proxyUrl is not None:  # omit empty
            v["proxyUrl"] = proxyUrl
        return v

    def port(self) -> Optional[str]:
        """
        Name of the service port this endpoint refers to. Mutually exclusive with targetPort.
        """
        return self.__port

    def targetPort(self) -> Optional[Union[int, str]]:
        """
        Name or number of the target port of the endpoint. Mutually exclusive with port.
        """
        return self.__targetPort

    def path(self) -> Optional[str]:
        """
        HTTP path to scrape for metrics.
        """
        return self.__path

    def scheme(self) -> Optional[str]:
        """
        HTTP scheme to use for scraping.
        """
        return self.__scheme

    def params(self) -> Optional[Dict[str, List[str]]]:
        """
        Optional HTTP URL parameters
        """
        return self.__params

    def interval(self) -> Optional[str]:
        """
        Interval at which metrics should be scraped
        """
        return self.__interval

    def scrapeTimeout(self) -> Optional[str]:
        """
        Timeout after which the scrape is ended
        """
        return self.__scrapeTimeout

    def tlsConfig(self) -> Optional["TLSConfig"]:
        """
        TLS configuration to use when scraping the endpoint
        """
        return self.__tlsConfig

    def bearerTokenFile(self) -> Optional[str]:
        """
        File to read bearer token for scraping targets.
        """
        return self.__bearerTokenFile

    def bearerTokenSecret(self) -> Optional["corev1.SecretKeySelector"]:
        """
        Secret to mount to read bearer token for scraping targets. The secret
        needs to be in the same namespace as the service monitor and accessible by
        the Prometheus Operator.
        """
        return self.__bearerTokenSecret

    def honorLabels(self) -> Optional[bool]:
        """
        HonorLabels chooses the metric's labels on collisions with target labels.
        """
        return self.__honorLabels

    def honorTimestamps(self) -> Optional[bool]:
        """
        HonorTimestamps controls whether Prometheus respects the timestamps present in scraped data.
        """
        return self.__honorTimestamps

    def basicAuth(self) -> Optional["BasicAuth"]:
        """
        BasicAuth allow an endpoint to authenticate over basic authentication
        More info: https://prometheus.io/docs/operating/configuration/#endpoints
        """
        return self.__basicAuth

    def metricRelabelings(self) -> Optional[List["RelabelConfig"]]:
        """
        MetricRelabelConfigs to apply to samples before ingestion.
        """
        return self.__metricRelabelings

    def relabelings(self) -> Optional[List["RelabelConfig"]]:
        """
        RelabelConfigs to apply to samples before scraping.
        More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
        """
        return self.__relabelings

    def proxyUrl(self) -> Optional[str]:
        """
        ProxyURL eg http://proxyserver:2195 Directs scrapes to proxy through this endpoint.
        """
        return self.__proxyUrl


class NamespaceSelector(types.Object):
    """
    NamespaceSelector is a selector for selecting either all namespaces or a
    list of namespaces.
    """

    @context.scoped
    @typechecked
    def __init__(self, any: bool = None, matchNames: List[str] = None):
        super().__init__()
        self.__any = any
        self.__matchNames = matchNames if matchNames is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        any = self.any()
        check_type("any", any, Optional[bool])
        if any:  # omit empty
            v["any"] = any
        matchNames = self.matchNames()
        check_type("matchNames", matchNames, Optional[List[str]])
        if matchNames:  # omit empty
            v["matchNames"] = matchNames
        return v

    def any(self) -> Optional[bool]:
        """
        Boolean describing whether all namespaces are selected in contrast to a
        list restricting them.
        """
        return self.__any

    def matchNames(self) -> Optional[List[str]]:
        """
        List of namespace names.
        """
        return self.__matchNames


class PodMetricsEndpoint(types.Object):
    """
    PodMetricsEndpoint defines a scrapeable endpoint of a Kubernetes Pod serving Prometheus metrics.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        port: str = None,
        targetPort: Union[int, str] = None,
        path: str = None,
        scheme: str = None,
        params: Dict[str, List[str]] = None,
        interval: str = None,
        scrapeTimeout: str = None,
        honorLabels: bool = None,
        honorTimestamps: bool = None,
        metricRelabelings: List["RelabelConfig"] = None,
        relabelings: List["RelabelConfig"] = None,
        proxyUrl: str = None,
    ):
        super().__init__()
        self.__port = port
        self.__targetPort = targetPort
        self.__path = path
        self.__scheme = scheme
        self.__params = params if params is not None else {}
        self.__interval = interval
        self.__scrapeTimeout = scrapeTimeout
        self.__honorLabels = honorLabels
        self.__honorTimestamps = honorTimestamps
        self.__metricRelabelings = (
            metricRelabelings if metricRelabelings is not None else []
        )
        self.__relabelings = relabelings if relabelings is not None else []
        self.__proxyUrl = proxyUrl

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        port = self.port()
        check_type("port", port, Optional[str])
        if port:  # omit empty
            v["port"] = port
        targetPort = self.targetPort()
        check_type("targetPort", targetPort, Optional[Union[int, str]])
        if targetPort is not None:  # omit empty
            v["targetPort"] = targetPort
        path = self.path()
        check_type("path", path, Optional[str])
        if path:  # omit empty
            v["path"] = path
        scheme = self.scheme()
        check_type("scheme", scheme, Optional[str])
        if scheme:  # omit empty
            v["scheme"] = scheme
        params = self.params()
        check_type("params", params, Optional[Dict[str, List[str]]])
        if params:  # omit empty
            v["params"] = params
        interval = self.interval()
        check_type("interval", interval, Optional[str])
        if interval:  # omit empty
            v["interval"] = interval
        scrapeTimeout = self.scrapeTimeout()
        check_type("scrapeTimeout", scrapeTimeout, Optional[str])
        if scrapeTimeout:  # omit empty
            v["scrapeTimeout"] = scrapeTimeout
        honorLabels = self.honorLabels()
        check_type("honorLabels", honorLabels, Optional[bool])
        if honorLabels:  # omit empty
            v["honorLabels"] = honorLabels
        honorTimestamps = self.honorTimestamps()
        check_type("honorTimestamps", honorTimestamps, Optional[bool])
        if honorTimestamps is not None:  # omit empty
            v["honorTimestamps"] = honorTimestamps
        metricRelabelings = self.metricRelabelings()
        check_type(
            "metricRelabelings", metricRelabelings, Optional[List["RelabelConfig"]]
        )
        if metricRelabelings:  # omit empty
            v["metricRelabelings"] = metricRelabelings
        relabelings = self.relabelings()
        check_type("relabelings", relabelings, Optional[List["RelabelConfig"]])
        if relabelings:  # omit empty
            v["relabelings"] = relabelings
        proxyUrl = self.proxyUrl()
        check_type("proxyUrl", proxyUrl, Optional[str])
        if proxyUrl is not None:  # omit empty
            v["proxyUrl"] = proxyUrl
        return v

    def port(self) -> Optional[str]:
        """
        Name of the port this endpoint refers to. Mutually exclusive with targetPort.
        """
        return self.__port

    def targetPort(self) -> Optional[Union[int, str]]:
        """
        Name or number of the target port of the endpoint. Mutually exclusive with port.
        """
        return self.__targetPort

    def path(self) -> Optional[str]:
        """
        HTTP path to scrape for metrics.
        """
        return self.__path

    def scheme(self) -> Optional[str]:
        """
        HTTP scheme to use for scraping.
        """
        return self.__scheme

    def params(self) -> Optional[Dict[str, List[str]]]:
        """
        Optional HTTP URL parameters
        """
        return self.__params

    def interval(self) -> Optional[str]:
        """
        Interval at which metrics should be scraped
        """
        return self.__interval

    def scrapeTimeout(self) -> Optional[str]:
        """
        Timeout after which the scrape is ended
        """
        return self.__scrapeTimeout

    def honorLabels(self) -> Optional[bool]:
        """
        HonorLabels chooses the metric's labels on collisions with target labels.
        """
        return self.__honorLabels

    def honorTimestamps(self) -> Optional[bool]:
        """
        HonorTimestamps controls whether Prometheus respects the timestamps present in scraped data.
        """
        return self.__honorTimestamps

    def metricRelabelings(self) -> Optional[List["RelabelConfig"]]:
        """
        MetricRelabelConfigs to apply to samples before ingestion.
        """
        return self.__metricRelabelings

    def relabelings(self) -> Optional[List["RelabelConfig"]]:
        """
        RelabelConfigs to apply to samples before ingestion.
        More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
        """
        return self.__relabelings

    def proxyUrl(self) -> Optional[str]:
        """
        ProxyURL eg http://proxyserver:2195 Directs scrapes to proxy through this endpoint.
        """
        return self.__proxyUrl


class PodMonitorSpec(types.Object):
    """
    PodMonitorSpec contains specification parameters for a PodMonitor.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        jobLabel: str = None,
        podTargetLabels: List[str] = None,
        podMetricsEndpoints: List["PodMetricsEndpoint"] = None,
        selector: "metav1.LabelSelector" = None,
        namespaceSelector: "NamespaceSelector" = None,
        sampleLimit: int = None,
    ):
        super().__init__()
        self.__jobLabel = jobLabel
        self.__podTargetLabels = podTargetLabels if podTargetLabels is not None else []
        self.__podMetricsEndpoints = (
            podMetricsEndpoints if podMetricsEndpoints is not None else []
        )
        self.__selector = selector if selector is not None else metav1.LabelSelector()
        self.__namespaceSelector = (
            namespaceSelector if namespaceSelector is not None else NamespaceSelector()
        )
        self.__sampleLimit = sampleLimit

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        jobLabel = self.jobLabel()
        check_type("jobLabel", jobLabel, Optional[str])
        if jobLabel:  # omit empty
            v["jobLabel"] = jobLabel
        podTargetLabels = self.podTargetLabels()
        check_type("podTargetLabels", podTargetLabels, Optional[List[str]])
        if podTargetLabels:  # omit empty
            v["podTargetLabels"] = podTargetLabels
        podMetricsEndpoints = self.podMetricsEndpoints()
        check_type(
            "podMetricsEndpoints", podMetricsEndpoints, List["PodMetricsEndpoint"]
        )
        v["podMetricsEndpoints"] = podMetricsEndpoints
        selector = self.selector()
        check_type("selector", selector, "metav1.LabelSelector")
        v["selector"] = selector
        namespaceSelector = self.namespaceSelector()
        check_type(
            "namespaceSelector", namespaceSelector, Optional["NamespaceSelector"]
        )
        v["namespaceSelector"] = namespaceSelector
        sampleLimit = self.sampleLimit()
        check_type("sampleLimit", sampleLimit, Optional[int])
        if sampleLimit:  # omit empty
            v["sampleLimit"] = sampleLimit
        return v

    def jobLabel(self) -> Optional[str]:
        """
        The label to use to retrieve the job name from.
        """
        return self.__jobLabel

    def podTargetLabels(self) -> Optional[List[str]]:
        """
        PodTargetLabels transfers labels on the Kubernetes Pod onto the target.
        """
        return self.__podTargetLabels

    def podMetricsEndpoints(self) -> List["PodMetricsEndpoint"]:
        """
        A list of endpoints allowed as part of this PodMonitor.
        """
        return self.__podMetricsEndpoints

    def selector(self) -> "metav1.LabelSelector":
        """
        Selector to select Pod objects.
        """
        return self.__selector

    def namespaceSelector(self) -> Optional["NamespaceSelector"]:
        """
        Selector to select which namespaces the Endpoints objects are discovered from.
        """
        return self.__namespaceSelector

    def sampleLimit(self) -> Optional[int]:
        """
        SampleLimit defines per-scrape limit on number of scraped samples that will be accepted.
        """
        return self.__sampleLimit


class PodMonitor(base.TypedObject, base.NamespacedMetadataObject):
    """
    PodMonitor defines monitoring for a set of pods.
    +genclient
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PodMonitorSpec" = None,
    ):
        super().__init__(
            apiVersion="monitoring.coreos.com/v1",
            kind="PodMonitor",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PodMonitorSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "PodMonitorSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "PodMonitorSpec":
        """
        Specification of desired Pod selection for target discovery by Prometheus.
        """
        return self.__spec


class QuerySpec(types.Object):
    """
    QuerySpec defines the query command line flags when starting Prometheus.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        lookbackDelta: str = None,
        maxConcurrency: int = None,
        maxSamples: int = None,
        timeout: str = None,
    ):
        super().__init__()
        self.__lookbackDelta = lookbackDelta
        self.__maxConcurrency = maxConcurrency
        self.__maxSamples = maxSamples
        self.__timeout = timeout

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        lookbackDelta = self.lookbackDelta()
        check_type("lookbackDelta", lookbackDelta, Optional[str])
        if lookbackDelta is not None:  # omit empty
            v["lookbackDelta"] = lookbackDelta
        maxConcurrency = self.maxConcurrency()
        check_type("maxConcurrency", maxConcurrency, Optional[int])
        if maxConcurrency is not None:  # omit empty
            v["maxConcurrency"] = maxConcurrency
        maxSamples = self.maxSamples()
        check_type("maxSamples", maxSamples, Optional[int])
        if maxSamples is not None:  # omit empty
            v["maxSamples"] = maxSamples
        timeout = self.timeout()
        check_type("timeout", timeout, Optional[str])
        if timeout is not None:  # omit empty
            v["timeout"] = timeout
        return v

    def lookbackDelta(self) -> Optional[str]:
        """
        The delta difference allowed for retrieving metrics during expression evaluations.
        """
        return self.__lookbackDelta

    def maxConcurrency(self) -> Optional[int]:
        """
        Number of concurrent queries that can be run at once.
        """
        return self.__maxConcurrency

    def maxSamples(self) -> Optional[int]:
        """
        Maximum number of samples a single query can load into memory. Note that queries will fail if they would load more samples than this into memory, so this also limits the number of samples a query can return.
        """
        return self.__maxSamples

    def timeout(self) -> Optional[str]:
        """
        Maximum time a query may take before being aborted.
        """
        return self.__timeout


class RemoteReadSpec(types.Object):
    """
    RemoteReadSpec defines the remote_read configuration for prometheus.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = "",
        requiredMatchers: Dict[str, str] = None,
        remoteTimeout: str = None,
        readRecent: bool = None,
        basicAuth: "BasicAuth" = None,
        bearerToken: str = None,
        bearerTokenFile: str = None,
        tlsConfig: "TLSConfig" = None,
        proxyUrl: str = None,
    ):
        super().__init__()
        self.__url = url
        self.__requiredMatchers = (
            requiredMatchers if requiredMatchers is not None else {}
        )
        self.__remoteTimeout = remoteTimeout
        self.__readRecent = readRecent
        self.__basicAuth = basicAuth
        self.__bearerToken = bearerToken
        self.__bearerTokenFile = bearerTokenFile
        self.__tlsConfig = tlsConfig
        self.__proxyUrl = proxyUrl

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        requiredMatchers = self.requiredMatchers()
        check_type("requiredMatchers", requiredMatchers, Optional[Dict[str, str]])
        if requiredMatchers:  # omit empty
            v["requiredMatchers"] = requiredMatchers
        remoteTimeout = self.remoteTimeout()
        check_type("remoteTimeout", remoteTimeout, Optional[str])
        if remoteTimeout:  # omit empty
            v["remoteTimeout"] = remoteTimeout
        readRecent = self.readRecent()
        check_type("readRecent", readRecent, Optional[bool])
        if readRecent:  # omit empty
            v["readRecent"] = readRecent
        basicAuth = self.basicAuth()
        check_type("basicAuth", basicAuth, Optional["BasicAuth"])
        if basicAuth is not None:  # omit empty
            v["basicAuth"] = basicAuth
        bearerToken = self.bearerToken()
        check_type("bearerToken", bearerToken, Optional[str])
        if bearerToken:  # omit empty
            v["bearerToken"] = bearerToken
        bearerTokenFile = self.bearerTokenFile()
        check_type("bearerTokenFile", bearerTokenFile, Optional[str])
        if bearerTokenFile:  # omit empty
            v["bearerTokenFile"] = bearerTokenFile
        tlsConfig = self.tlsConfig()
        check_type("tlsConfig", tlsConfig, Optional["TLSConfig"])
        if tlsConfig is not None:  # omit empty
            v["tlsConfig"] = tlsConfig
        proxyUrl = self.proxyUrl()
        check_type("proxyUrl", proxyUrl, Optional[str])
        if proxyUrl:  # omit empty
            v["proxyUrl"] = proxyUrl
        return v

    def url(self) -> str:
        """
        The URL of the endpoint to send samples to.
        """
        return self.__url

    def requiredMatchers(self) -> Optional[Dict[str, str]]:
        """
        An optional list of equality matchers which have to be present
        in a selector to query the remote read endpoint.
        """
        return self.__requiredMatchers

    def remoteTimeout(self) -> Optional[str]:
        """
        Timeout for requests to the remote read endpoint.
        """
        return self.__remoteTimeout

    def readRecent(self) -> Optional[bool]:
        """
        Whether reads should be made for queries for time ranges that
        the local storage should have complete data for.
        """
        return self.__readRecent

    def basicAuth(self) -> Optional["BasicAuth"]:
        """
        BasicAuth for the URL.
        """
        return self.__basicAuth

    def bearerToken(self) -> Optional[str]:
        """
        bearer token for remote read.
        """
        return self.__bearerToken

    def bearerTokenFile(self) -> Optional[str]:
        """
        File to read bearer token for remote read.
        """
        return self.__bearerTokenFile

    def tlsConfig(self) -> Optional["TLSConfig"]:
        """
        TLS Config to use for remote read.
        """
        return self.__tlsConfig

    def proxyUrl(self) -> Optional[str]:
        """
        Optional ProxyURL
        """
        return self.__proxyUrl


class QueueConfig(types.Object):
    """
    QueueConfig allows the tuning of remote_write queue_config parameters. This object
    is referenced in the RemoteWriteSpec object.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        capacity: int = None,
        minShards: int = None,
        maxShards: int = None,
        maxSamplesPerSend: int = None,
        batchSendDeadline: str = None,
        maxRetries: int = None,
        minBackoff: str = None,
        maxBackoff: str = None,
    ):
        super().__init__()
        self.__capacity = capacity
        self.__minShards = minShards
        self.__maxShards = maxShards
        self.__maxSamplesPerSend = maxSamplesPerSend
        self.__batchSendDeadline = batchSendDeadline
        self.__maxRetries = maxRetries
        self.__minBackoff = minBackoff
        self.__maxBackoff = maxBackoff

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        capacity = self.capacity()
        check_type("capacity", capacity, Optional[int])
        if capacity:  # omit empty
            v["capacity"] = capacity
        minShards = self.minShards()
        check_type("minShards", minShards, Optional[int])
        if minShards:  # omit empty
            v["minShards"] = minShards
        maxShards = self.maxShards()
        check_type("maxShards", maxShards, Optional[int])
        if maxShards:  # omit empty
            v["maxShards"] = maxShards
        maxSamplesPerSend = self.maxSamplesPerSend()
        check_type("maxSamplesPerSend", maxSamplesPerSend, Optional[int])
        if maxSamplesPerSend:  # omit empty
            v["maxSamplesPerSend"] = maxSamplesPerSend
        batchSendDeadline = self.batchSendDeadline()
        check_type("batchSendDeadline", batchSendDeadline, Optional[str])
        if batchSendDeadline:  # omit empty
            v["batchSendDeadline"] = batchSendDeadline
        maxRetries = self.maxRetries()
        check_type("maxRetries", maxRetries, Optional[int])
        if maxRetries:  # omit empty
            v["maxRetries"] = maxRetries
        minBackoff = self.minBackoff()
        check_type("minBackoff", minBackoff, Optional[str])
        if minBackoff:  # omit empty
            v["minBackoff"] = minBackoff
        maxBackoff = self.maxBackoff()
        check_type("maxBackoff", maxBackoff, Optional[str])
        if maxBackoff:  # omit empty
            v["maxBackoff"] = maxBackoff
        return v

    def capacity(self) -> Optional[int]:
        """
        Capacity is the number of samples to buffer per shard before we start dropping them.
        """
        return self.__capacity

    def minShards(self) -> Optional[int]:
        """
        MinShards is the minimum number of shards, i.e. amount of concurrency.
        """
        return self.__minShards

    def maxShards(self) -> Optional[int]:
        """
        MaxShards is the maximum number of shards, i.e. amount of concurrency.
        """
        return self.__maxShards

    def maxSamplesPerSend(self) -> Optional[int]:
        """
        MaxSamplesPerSend is the maximum number of samples per send.
        """
        return self.__maxSamplesPerSend

    def batchSendDeadline(self) -> Optional[str]:
        """
        BatchSendDeadline is the maximum time a sample will wait in buffer.
        """
        return self.__batchSendDeadline

    def maxRetries(self) -> Optional[int]:
        """
        MaxRetries is the maximum number of times to retry a batch on recoverable errors.
        """
        return self.__maxRetries

    def minBackoff(self) -> Optional[str]:
        """
        MinBackoff is the initial retry delay. Gets doubled for every retry.
        """
        return self.__minBackoff

    def maxBackoff(self) -> Optional[str]:
        """
        MaxBackoff is the maximum retry delay.
        """
        return self.__maxBackoff


class RemoteWriteSpec(types.Object):
    """
    RemoteWriteSpec defines the remote_write configuration for prometheus.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = "",
        remoteTimeout: str = None,
        writeRelabelConfigs: List["RelabelConfig"] = None,
        basicAuth: "BasicAuth" = None,
        bearerToken: str = None,
        bearerTokenFile: str = None,
        tlsConfig: "TLSConfig" = None,
        proxyUrl: str = None,
        queueConfig: "QueueConfig" = None,
    ):
        super().__init__()
        self.__url = url
        self.__remoteTimeout = remoteTimeout
        self.__writeRelabelConfigs = (
            writeRelabelConfigs if writeRelabelConfigs is not None else []
        )
        self.__basicAuth = basicAuth
        self.__bearerToken = bearerToken
        self.__bearerTokenFile = bearerTokenFile
        self.__tlsConfig = tlsConfig
        self.__proxyUrl = proxyUrl
        self.__queueConfig = queueConfig

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        remoteTimeout = self.remoteTimeout()
        check_type("remoteTimeout", remoteTimeout, Optional[str])
        if remoteTimeout:  # omit empty
            v["remoteTimeout"] = remoteTimeout
        writeRelabelConfigs = self.writeRelabelConfigs()
        check_type(
            "writeRelabelConfigs", writeRelabelConfigs, Optional[List["RelabelConfig"]]
        )
        if writeRelabelConfigs:  # omit empty
            v["writeRelabelConfigs"] = writeRelabelConfigs
        basicAuth = self.basicAuth()
        check_type("basicAuth", basicAuth, Optional["BasicAuth"])
        if basicAuth is not None:  # omit empty
            v["basicAuth"] = basicAuth
        bearerToken = self.bearerToken()
        check_type("bearerToken", bearerToken, Optional[str])
        if bearerToken:  # omit empty
            v["bearerToken"] = bearerToken
        bearerTokenFile = self.bearerTokenFile()
        check_type("bearerTokenFile", bearerTokenFile, Optional[str])
        if bearerTokenFile:  # omit empty
            v["bearerTokenFile"] = bearerTokenFile
        tlsConfig = self.tlsConfig()
        check_type("tlsConfig", tlsConfig, Optional["TLSConfig"])
        if tlsConfig is not None:  # omit empty
            v["tlsConfig"] = tlsConfig
        proxyUrl = self.proxyUrl()
        check_type("proxyUrl", proxyUrl, Optional[str])
        if proxyUrl:  # omit empty
            v["proxyUrl"] = proxyUrl
        queueConfig = self.queueConfig()
        check_type("queueConfig", queueConfig, Optional["QueueConfig"])
        if queueConfig is not None:  # omit empty
            v["queueConfig"] = queueConfig
        return v

    def url(self) -> str:
        """
        The URL of the endpoint to send samples to.
        """
        return self.__url

    def remoteTimeout(self) -> Optional[str]:
        """
        Timeout for requests to the remote write endpoint.
        """
        return self.__remoteTimeout

    def writeRelabelConfigs(self) -> Optional[List["RelabelConfig"]]:
        """
        The list of remote write relabel configurations.
        """
        return self.__writeRelabelConfigs

    def basicAuth(self) -> Optional["BasicAuth"]:
        """
        BasicAuth for the URL.
        """
        return self.__basicAuth

    def bearerToken(self) -> Optional[str]:
        """
        File to read bearer token for remote write.
        """
        return self.__bearerToken

    def bearerTokenFile(self) -> Optional[str]:
        """
        File to read bearer token for remote write.
        """
        return self.__bearerTokenFile

    def tlsConfig(self) -> Optional["TLSConfig"]:
        """
        TLS Config to use for remote write.
        """
        return self.__tlsConfig

    def proxyUrl(self) -> Optional[str]:
        """
        Optional ProxyURL
        """
        return self.__proxyUrl

    def queueConfig(self) -> Optional["QueueConfig"]:
        """
        QueueConfig allows tuning of the remote write queue parameters.
        """
        return self.__queueConfig


class RulesAlert(types.Object):
    """
    /--rules.alert.*/ command-line arguments
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        forOutageTolerance: str = None,
        forGracePeriod: str = None,
        resendDelay: str = None,
    ):
        super().__init__()
        self.__forOutageTolerance = forOutageTolerance
        self.__forGracePeriod = forGracePeriod
        self.__resendDelay = resendDelay

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        forOutageTolerance = self.forOutageTolerance()
        check_type("forOutageTolerance", forOutageTolerance, Optional[str])
        if forOutageTolerance:  # omit empty
            v["forOutageTolerance"] = forOutageTolerance
        forGracePeriod = self.forGracePeriod()
        check_type("forGracePeriod", forGracePeriod, Optional[str])
        if forGracePeriod:  # omit empty
            v["forGracePeriod"] = forGracePeriod
        resendDelay = self.resendDelay()
        check_type("resendDelay", resendDelay, Optional[str])
        if resendDelay:  # omit empty
            v["resendDelay"] = resendDelay
        return v

    def forOutageTolerance(self) -> Optional[str]:
        """
        Max time to tolerate prometheus outage for restoring 'for' state of alert.
        """
        return self.__forOutageTolerance

    def forGracePeriod(self) -> Optional[str]:
        """
        Minimum duration between alert and restored 'for' state.
        This is maintained only for alerts with configured 'for' time greater than grace period.
        """
        return self.__forGracePeriod

    def resendDelay(self) -> Optional[str]:
        """
        Minimum amount of time to wait before resending an alert to Alertmanager.
        """
        return self.__resendDelay


class Rules(types.Object):
    """
    /--rules.*/ command-line arguments
    """

    @context.scoped
    @typechecked
    def __init__(self, alert: "RulesAlert" = None):
        super().__init__()
        self.__alert = alert if alert is not None else RulesAlert()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        alert = self.alert()
        check_type("alert", alert, Optional["RulesAlert"])
        v["alert"] = alert
        return v

    def alert(self) -> Optional["RulesAlert"]:
        return self.__alert


class ThanosSpec(types.Object):
    """
    ThanosSpec defines parameters for a Prometheus server within a Thanos deployment.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        image: str = None,
        version: str = None,
        tag: str = None,
        sha: str = None,
        baseImage: str = None,
        resources: "corev1.ResourceRequirements" = None,
        objectStorageConfig: "corev1.SecretKeySelector" = None,
        listenLocal: bool = None,
    ):
        super().__init__()
        self.__image = image
        self.__version = version
        self.__tag = tag
        self.__sha = sha
        self.__baseImage = baseImage
        self.__resources = (
            resources if resources is not None else corev1.ResourceRequirements()
        )
        self.__objectStorageConfig = objectStorageConfig
        self.__listenLocal = listenLocal

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        image = self.image()
        check_type("image", image, Optional[str])
        if image is not None:  # omit empty
            v["image"] = image
        version = self.version()
        check_type("version", version, Optional[str])
        if version is not None:  # omit empty
            v["version"] = version
        tag = self.tag()
        check_type("tag", tag, Optional[str])
        if tag is not None:  # omit empty
            v["tag"] = tag
        sha = self.sha()
        check_type("sha", sha, Optional[str])
        if sha is not None:  # omit empty
            v["sha"] = sha
        baseImage = self.baseImage()
        check_type("baseImage", baseImage, Optional[str])
        if baseImage is not None:  # omit empty
            v["baseImage"] = baseImage
        resources = self.resources()
        check_type("resources", resources, Optional["corev1.ResourceRequirements"])
        v["resources"] = resources
        objectStorageConfig = self.objectStorageConfig()
        check_type(
            "objectStorageConfig",
            objectStorageConfig,
            Optional["corev1.SecretKeySelector"],
        )
        if objectStorageConfig is not None:  # omit empty
            v["objectStorageConfig"] = objectStorageConfig
        listenLocal = self.listenLocal()
        check_type("listenLocal", listenLocal, Optional[bool])
        if listenLocal:  # omit empty
            v["listenLocal"] = listenLocal
        return v

    def image(self) -> Optional[str]:
        """
        Image if specified has precedence over baseImage, tag and sha
        combinations. Specifying the version is still necessary to ensure the
        Prometheus Operator knows what version of Thanos is being
        configured.
        """
        return self.__image

    def version(self) -> Optional[str]:
        """
        Version describes the version of Thanos to use.
        """
        return self.__version

    def tag(self) -> Optional[str]:
        """
        Tag of Thanos sidecar container image to be deployed. Defaults to the value of `version`.
        Version is ignored if Tag is set.
        """
        return self.__tag

    def sha(self) -> Optional[str]:
        """
        SHA of Thanos container image to be deployed. Defaults to the value of `version`.
        Similar to a tag, but the SHA explicitly deploys an immutable container image.
        Version and Tag are ignored if SHA is set.
        """
        return self.__sha

    def baseImage(self) -> Optional[str]:
        """
        Thanos base image if other than default.
        """
        return self.__baseImage

    def resources(self) -> Optional["corev1.ResourceRequirements"]:
        """
        Resources defines the resource requirements for the Thanos sidecar.
        If not provided, no requests/limits will be set
        """
        return self.__resources

    def objectStorageConfig(self) -> Optional["corev1.SecretKeySelector"]:
        """
        ObjectStorageConfig configures object storage in Thanos.
        """
        return self.__objectStorageConfig

    def listenLocal(self) -> Optional[bool]:
        """
        ListenLocal makes the Thanos sidecar listen on loopback, so that it
        does not bind against the Pod IP.
        """
        return self.__listenLocal


class PrometheusSpec(types.Object):
    """
    PrometheusSpec is a specification of the desired behavior of the Prometheus cluster. More info:
    https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        podMetadata: "metav1.ObjectMeta" = None,
        serviceMonitorSelector: "metav1.LabelSelector" = None,
        serviceMonitorNamespaceSelector: "metav1.LabelSelector" = None,
        podMonitorSelector: "metav1.LabelSelector" = None,
        podMonitorNamespaceSelector: "metav1.LabelSelector" = None,
        version: str = None,
        tag: str = None,
        sha: str = None,
        paused: bool = None,
        image: str = None,
        baseImage: str = None,
        imagePullSecrets: List["corev1.LocalObjectReference"] = None,
        replicas: int = None,
        replicaExternalLabelName: str = None,
        prometheusExternalLabelName: str = None,
        retention: str = None,
        retentionSize: str = None,
        walCompression: bool = None,
        logLevel: str = None,
        logFormat: str = None,
        scrapeInterval: str = None,
        evaluationInterval: str = None,
        rules: "Rules" = None,
        externalLabels: Dict[str, str] = None,
        enableAdminAPI: bool = None,
        externalUrl: str = None,
        routePrefix: str = None,
        query: "QuerySpec" = None,
        storage: "StorageSpec" = None,
        volumes: List["corev1.Volume"] = None,
        ruleSelector: "metav1.LabelSelector" = None,
        ruleNamespaceSelector: "metav1.LabelSelector" = None,
        alerting: "AlertingSpec" = None,
        resources: "corev1.ResourceRequirements" = None,
        nodeSelector: Dict[str, str] = None,
        serviceAccountName: str = None,
        secrets: List[str] = None,
        configMaps: List[str] = None,
        affinity: "corev1.Affinity" = None,
        tolerations: List["corev1.Toleration"] = None,
        remoteWrite: List["RemoteWriteSpec"] = None,
        remoteRead: List["RemoteReadSpec"] = None,
        securityContext: "corev1.PodSecurityContext" = None,
        listenLocal: bool = None,
        containers: List["corev1.Container"] = None,
        initContainers: List["corev1.Container"] = None,
        additionalScrapeConfigs: "corev1.SecretKeySelector" = None,
        additionalAlertRelabelConfigs: "corev1.SecretKeySelector" = None,
        additionalAlertManagerConfigs: "corev1.SecretKeySelector" = None,
        apiserverConfig: "APIServerConfig" = None,
        thanos: "ThanosSpec" = None,
        priorityClassName: str = None,
        portName: str = None,
        arbitraryFSAccessThroughSMs: "ArbitraryFSAccessThroughSMsConfig" = None,
        overrideHonorLabels: bool = None,
        overrideHonorTimestamps: bool = None,
        ignoreNamespaceSelectors: bool = None,
        enforcedNamespaceLabel: str = None,
    ):
        super().__init__()
        self.__podMetadata = podMetadata
        self.__serviceMonitorSelector = serviceMonitorSelector
        self.__serviceMonitorNamespaceSelector = serviceMonitorNamespaceSelector
        self.__podMonitorSelector = podMonitorSelector
        self.__podMonitorNamespaceSelector = podMonitorNamespaceSelector
        self.__version = version
        self.__tag = tag
        self.__sha = sha
        self.__paused = paused
        self.__image = image
        self.__baseImage = baseImage
        self.__imagePullSecrets = (
            imagePullSecrets if imagePullSecrets is not None else []
        )
        self.__replicas = replicas
        self.__replicaExternalLabelName = replicaExternalLabelName
        self.__prometheusExternalLabelName = prometheusExternalLabelName
        self.__retention = retention
        self.__retentionSize = retentionSize
        self.__walCompression = walCompression
        self.__logLevel = logLevel
        self.__logFormat = logFormat
        self.__scrapeInterval = scrapeInterval
        self.__evaluationInterval = evaluationInterval
        self.__rules = rules if rules is not None else Rules()
        self.__externalLabels = externalLabels if externalLabels is not None else {}
        self.__enableAdminAPI = enableAdminAPI
        self.__externalUrl = externalUrl
        self.__routePrefix = routePrefix
        self.__query = query
        self.__storage = storage
        self.__volumes = volumes if volumes is not None else []
        self.__ruleSelector = ruleSelector
        self.__ruleNamespaceSelector = ruleNamespaceSelector
        self.__alerting = alerting
        self.__resources = (
            resources if resources is not None else corev1.ResourceRequirements()
        )
        self.__nodeSelector = nodeSelector if nodeSelector is not None else {}
        self.__serviceAccountName = serviceAccountName
        self.__secrets = secrets if secrets is not None else []
        self.__configMaps = configMaps if configMaps is not None else []
        self.__affinity = affinity
        self.__tolerations = tolerations if tolerations is not None else []
        self.__remoteWrite = remoteWrite if remoteWrite is not None else []
        self.__remoteRead = remoteRead if remoteRead is not None else []
        self.__securityContext = securityContext
        self.__listenLocal = listenLocal
        self.__containers = containers if containers is not None else []
        self.__initContainers = initContainers if initContainers is not None else []
        self.__additionalScrapeConfigs = additionalScrapeConfigs
        self.__additionalAlertRelabelConfigs = additionalAlertRelabelConfigs
        self.__additionalAlertManagerConfigs = additionalAlertManagerConfigs
        self.__apiserverConfig = apiserverConfig
        self.__thanos = thanos
        self.__priorityClassName = priorityClassName
        self.__portName = portName
        self.__arbitraryFSAccessThroughSMs = (
            arbitraryFSAccessThroughSMs
            if arbitraryFSAccessThroughSMs is not None
            else ArbitraryFSAccessThroughSMsConfig()
        )
        self.__overrideHonorLabels = overrideHonorLabels
        self.__overrideHonorTimestamps = overrideHonorTimestamps
        self.__ignoreNamespaceSelectors = ignoreNamespaceSelectors
        self.__enforcedNamespaceLabel = enforcedNamespaceLabel

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        podMetadata = self.podMetadata()
        check_type("podMetadata", podMetadata, Optional["metav1.ObjectMeta"])
        if podMetadata is not None:  # omit empty
            v["podMetadata"] = podMetadata
        serviceMonitorSelector = self.serviceMonitorSelector()
        check_type(
            "serviceMonitorSelector",
            serviceMonitorSelector,
            Optional["metav1.LabelSelector"],
        )
        if serviceMonitorSelector is not None:  # omit empty
            v["serviceMonitorSelector"] = serviceMonitorSelector
        serviceMonitorNamespaceSelector = self.serviceMonitorNamespaceSelector()
        check_type(
            "serviceMonitorNamespaceSelector",
            serviceMonitorNamespaceSelector,
            Optional["metav1.LabelSelector"],
        )
        if serviceMonitorNamespaceSelector is not None:  # omit empty
            v["serviceMonitorNamespaceSelector"] = serviceMonitorNamespaceSelector
        podMonitorSelector = self.podMonitorSelector()
        check_type(
            "podMonitorSelector", podMonitorSelector, Optional["metav1.LabelSelector"]
        )
        if podMonitorSelector is not None:  # omit empty
            v["podMonitorSelector"] = podMonitorSelector
        podMonitorNamespaceSelector = self.podMonitorNamespaceSelector()
        check_type(
            "podMonitorNamespaceSelector",
            podMonitorNamespaceSelector,
            Optional["metav1.LabelSelector"],
        )
        if podMonitorNamespaceSelector is not None:  # omit empty
            v["podMonitorNamespaceSelector"] = podMonitorNamespaceSelector
        version = self.version()
        check_type("version", version, Optional[str])
        if version:  # omit empty
            v["version"] = version
        tag = self.tag()
        check_type("tag", tag, Optional[str])
        if tag:  # omit empty
            v["tag"] = tag
        sha = self.sha()
        check_type("sha", sha, Optional[str])
        if sha:  # omit empty
            v["sha"] = sha
        paused = self.paused()
        check_type("paused", paused, Optional[bool])
        if paused:  # omit empty
            v["paused"] = paused
        image = self.image()
        check_type("image", image, Optional[str])
        if image is not None:  # omit empty
            v["image"] = image
        baseImage = self.baseImage()
        check_type("baseImage", baseImage, Optional[str])
        if baseImage:  # omit empty
            v["baseImage"] = baseImage
        imagePullSecrets = self.imagePullSecrets()
        check_type(
            "imagePullSecrets",
            imagePullSecrets,
            Optional[List["corev1.LocalObjectReference"]],
        )
        if imagePullSecrets:  # omit empty
            v["imagePullSecrets"] = imagePullSecrets
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas is not None:  # omit empty
            v["replicas"] = replicas
        replicaExternalLabelName = self.replicaExternalLabelName()
        check_type("replicaExternalLabelName", replicaExternalLabelName, Optional[str])
        if replicaExternalLabelName is not None:  # omit empty
            v["replicaExternalLabelName"] = replicaExternalLabelName
        prometheusExternalLabelName = self.prometheusExternalLabelName()
        check_type(
            "prometheusExternalLabelName", prometheusExternalLabelName, Optional[str]
        )
        if prometheusExternalLabelName is not None:  # omit empty
            v["prometheusExternalLabelName"] = prometheusExternalLabelName
        retention = self.retention()
        check_type("retention", retention, Optional[str])
        if retention:  # omit empty
            v["retention"] = retention
        retentionSize = self.retentionSize()
        check_type("retentionSize", retentionSize, Optional[str])
        if retentionSize:  # omit empty
            v["retentionSize"] = retentionSize
        walCompression = self.walCompression()
        check_type("walCompression", walCompression, Optional[bool])
        if walCompression is not None:  # omit empty
            v["walCompression"] = walCompression
        logLevel = self.logLevel()
        check_type("logLevel", logLevel, Optional[str])
        if logLevel:  # omit empty
            v["logLevel"] = logLevel
        logFormat = self.logFormat()
        check_type("logFormat", logFormat, Optional[str])
        if logFormat:  # omit empty
            v["logFormat"] = logFormat
        scrapeInterval = self.scrapeInterval()
        check_type("scrapeInterval", scrapeInterval, Optional[str])
        if scrapeInterval:  # omit empty
            v["scrapeInterval"] = scrapeInterval
        evaluationInterval = self.evaluationInterval()
        check_type("evaluationInterval", evaluationInterval, Optional[str])
        if evaluationInterval:  # omit empty
            v["evaluationInterval"] = evaluationInterval
        rules = self.rules()
        check_type("rules", rules, Optional["Rules"])
        v["rules"] = rules
        externalLabels = self.externalLabels()
        check_type("externalLabels", externalLabels, Optional[Dict[str, str]])
        if externalLabels:  # omit empty
            v["externalLabels"] = externalLabels
        enableAdminAPI = self.enableAdminAPI()
        check_type("enableAdminAPI", enableAdminAPI, Optional[bool])
        if enableAdminAPI:  # omit empty
            v["enableAdminAPI"] = enableAdminAPI
        externalUrl = self.externalUrl()
        check_type("externalUrl", externalUrl, Optional[str])
        if externalUrl:  # omit empty
            v["externalUrl"] = externalUrl
        routePrefix = self.routePrefix()
        check_type("routePrefix", routePrefix, Optional[str])
        if routePrefix:  # omit empty
            v["routePrefix"] = routePrefix
        query = self.query()
        check_type("query", query, Optional["QuerySpec"])
        if query is not None:  # omit empty
            v["query"] = query
        storage = self.storage()
        check_type("storage", storage, Optional["StorageSpec"])
        if storage is not None:  # omit empty
            v["storage"] = storage
        volumes = self.volumes()
        check_type("volumes", volumes, Optional[List["corev1.Volume"]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        ruleSelector = self.ruleSelector()
        check_type("ruleSelector", ruleSelector, Optional["metav1.LabelSelector"])
        if ruleSelector is not None:  # omit empty
            v["ruleSelector"] = ruleSelector
        ruleNamespaceSelector = self.ruleNamespaceSelector()
        check_type(
            "ruleNamespaceSelector",
            ruleNamespaceSelector,
            Optional["metav1.LabelSelector"],
        )
        if ruleNamespaceSelector is not None:  # omit empty
            v["ruleNamespaceSelector"] = ruleNamespaceSelector
        alerting = self.alerting()
        check_type("alerting", alerting, Optional["AlertingSpec"])
        if alerting is not None:  # omit empty
            v["alerting"] = alerting
        resources = self.resources()
        check_type("resources", resources, Optional["corev1.ResourceRequirements"])
        v["resources"] = resources
        nodeSelector = self.nodeSelector()
        check_type("nodeSelector", nodeSelector, Optional[Dict[str, str]])
        if nodeSelector:  # omit empty
            v["nodeSelector"] = nodeSelector
        serviceAccountName = self.serviceAccountName()
        check_type("serviceAccountName", serviceAccountName, Optional[str])
        if serviceAccountName:  # omit empty
            v["serviceAccountName"] = serviceAccountName
        secrets = self.secrets()
        check_type("secrets", secrets, Optional[List[str]])
        if secrets:  # omit empty
            v["secrets"] = secrets
        configMaps = self.configMaps()
        check_type("configMaps", configMaps, Optional[List[str]])
        if configMaps:  # omit empty
            v["configMaps"] = configMaps
        affinity = self.affinity()
        check_type("affinity", affinity, Optional["corev1.Affinity"])
        if affinity is not None:  # omit empty
            v["affinity"] = affinity
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["corev1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        remoteWrite = self.remoteWrite()
        check_type("remoteWrite", remoteWrite, Optional[List["RemoteWriteSpec"]])
        if remoteWrite:  # omit empty
            v["remoteWrite"] = remoteWrite
        remoteRead = self.remoteRead()
        check_type("remoteRead", remoteRead, Optional[List["RemoteReadSpec"]])
        if remoteRead:  # omit empty
            v["remoteRead"] = remoteRead
        securityContext = self.securityContext()
        check_type(
            "securityContext", securityContext, Optional["corev1.PodSecurityContext"]
        )
        if securityContext is not None:  # omit empty
            v["securityContext"] = securityContext
        listenLocal = self.listenLocal()
        check_type("listenLocal", listenLocal, Optional[bool])
        if listenLocal:  # omit empty
            v["listenLocal"] = listenLocal
        containers = self.containers()
        check_type("containers", containers, Optional[List["corev1.Container"]])
        if containers:  # omit empty
            v["containers"] = containers
        initContainers = self.initContainers()
        check_type("initContainers", initContainers, Optional[List["corev1.Container"]])
        if initContainers:  # omit empty
            v["initContainers"] = initContainers
        additionalScrapeConfigs = self.additionalScrapeConfigs()
        check_type(
            "additionalScrapeConfigs",
            additionalScrapeConfigs,
            Optional["corev1.SecretKeySelector"],
        )
        if additionalScrapeConfigs is not None:  # omit empty
            v["additionalScrapeConfigs"] = additionalScrapeConfigs
        additionalAlertRelabelConfigs = self.additionalAlertRelabelConfigs()
        check_type(
            "additionalAlertRelabelConfigs",
            additionalAlertRelabelConfigs,
            Optional["corev1.SecretKeySelector"],
        )
        if additionalAlertRelabelConfigs is not None:  # omit empty
            v["additionalAlertRelabelConfigs"] = additionalAlertRelabelConfigs
        additionalAlertManagerConfigs = self.additionalAlertManagerConfigs()
        check_type(
            "additionalAlertManagerConfigs",
            additionalAlertManagerConfigs,
            Optional["corev1.SecretKeySelector"],
        )
        if additionalAlertManagerConfigs is not None:  # omit empty
            v["additionalAlertManagerConfigs"] = additionalAlertManagerConfigs
        apiserverConfig = self.apiserverConfig()
        check_type("apiserverConfig", apiserverConfig, Optional["APIServerConfig"])
        if apiserverConfig is not None:  # omit empty
            v["apiserverConfig"] = apiserverConfig
        thanos = self.thanos()
        check_type("thanos", thanos, Optional["ThanosSpec"])
        if thanos is not None:  # omit empty
            v["thanos"] = thanos
        priorityClassName = self.priorityClassName()
        check_type("priorityClassName", priorityClassName, Optional[str])
        if priorityClassName:  # omit empty
            v["priorityClassName"] = priorityClassName
        portName = self.portName()
        check_type("portName", portName, Optional[str])
        if portName:  # omit empty
            v["portName"] = portName
        arbitraryFSAccessThroughSMs = self.arbitraryFSAccessThroughSMs()
        check_type(
            "arbitraryFSAccessThroughSMs",
            arbitraryFSAccessThroughSMs,
            Optional["ArbitraryFSAccessThroughSMsConfig"],
        )
        v["arbitraryFSAccessThroughSMs"] = arbitraryFSAccessThroughSMs
        overrideHonorLabels = self.overrideHonorLabels()
        check_type("overrideHonorLabels", overrideHonorLabels, Optional[bool])
        if overrideHonorLabels:  # omit empty
            v["overrideHonorLabels"] = overrideHonorLabels
        overrideHonorTimestamps = self.overrideHonorTimestamps()
        check_type("overrideHonorTimestamps", overrideHonorTimestamps, Optional[bool])
        if overrideHonorTimestamps:  # omit empty
            v["overrideHonorTimestamps"] = overrideHonorTimestamps
        ignoreNamespaceSelectors = self.ignoreNamespaceSelectors()
        check_type("ignoreNamespaceSelectors", ignoreNamespaceSelectors, Optional[bool])
        if ignoreNamespaceSelectors:  # omit empty
            v["ignoreNamespaceSelectors"] = ignoreNamespaceSelectors
        enforcedNamespaceLabel = self.enforcedNamespaceLabel()
        check_type("enforcedNamespaceLabel", enforcedNamespaceLabel, Optional[str])
        if enforcedNamespaceLabel:  # omit empty
            v["enforcedNamespaceLabel"] = enforcedNamespaceLabel
        return v

    def podMetadata(self) -> Optional["metav1.ObjectMeta"]:
        """
        Standard object’s metadata. More info:
        https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
        Metadata Labels and Annotations gets propagated to the prometheus pods.
        """
        return self.__podMetadata

    def serviceMonitorSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        ServiceMonitors to be selected for target discovery.
        """
        return self.__serviceMonitorSelector

    def serviceMonitorNamespaceSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        Namespaces to be selected for ServiceMonitor discovery. If nil, only
        check own namespace.
        """
        return self.__serviceMonitorNamespaceSelector

    def podMonitorSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        *Experimental* PodMonitors to be selected for target discovery.
        """
        return self.__podMonitorSelector

    def podMonitorNamespaceSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        Namespaces to be selected for PodMonitor discovery. If nil, only
        check own namespace.
        """
        return self.__podMonitorNamespaceSelector

    def version(self) -> Optional[str]:
        """
        Version of Prometheus to be deployed.
        """
        return self.__version

    def tag(self) -> Optional[str]:
        """
        Tag of Prometheus container image to be deployed. Defaults to the value of `version`.
        Version is ignored if Tag is set.
        """
        return self.__tag

    def sha(self) -> Optional[str]:
        """
        SHA of Prometheus container image to be deployed. Defaults to the value of `version`.
        Similar to a tag, but the SHA explicitly deploys an immutable container image.
        Version and Tag are ignored if SHA is set.
        """
        return self.__sha

    def paused(self) -> Optional[bool]:
        """
        When a Prometheus deployment is paused, no actions except for deletion
        will be performed on the underlying objects.
        """
        return self.__paused

    def image(self) -> Optional[str]:
        """
        Image if specified has precedence over baseImage, tag and sha
        combinations. Specifying the version is still necessary to ensure the
        Prometheus Operator knows what version of Prometheus is being
        configured.
        """
        return self.__image

    def baseImage(self) -> Optional[str]:
        """
        Base image to use for a Prometheus deployment.
        """
        return self.__baseImage

    def imagePullSecrets(self) -> Optional[List["corev1.LocalObjectReference"]]:
        """
        An optional list of references to secrets in the same namespace
        to use for pulling prometheus and alertmanager images from registries
        see http://kubernetes.io/docs/user-guide/images#specifying-imagepullsecrets-on-a-pod
        """
        return self.__imagePullSecrets

    def replicas(self) -> Optional[int]:
        """
        Number of instances to deploy for a Prometheus deployment.
        """
        return self.__replicas

    def replicaExternalLabelName(self) -> Optional[str]:
        """
        Name of Prometheus external label used to denote replica name.
        Defaults to the value of `prometheus_replica`. External label will
        _not_ be added when value is set to empty string (`""`).
        """
        return self.__replicaExternalLabelName

    def prometheusExternalLabelName(self) -> Optional[str]:
        """
        Name of Prometheus external label used to denote Prometheus instance
        name. Defaults to the value of `prometheus`. External label will
        _not_ be added when value is set to empty string (`""`).
        """
        return self.__prometheusExternalLabelName

    def retention(self) -> Optional[str]:
        """
        Time duration Prometheus shall retain data for. Default is '24h',
        and must match the regular expression `[0-9]+(ms|s|m|h|d|w|y)` (milliseconds seconds minutes hours days weeks years).
        """
        return self.__retention

    def retentionSize(self) -> Optional[str]:
        """
        Maximum amount of disk space used by blocks.
        """
        return self.__retentionSize

    def walCompression(self) -> Optional[bool]:
        """
        Enable compression of the write-ahead log using Snappy. This flag is
        only available in versions of Prometheus >= 2.11.0.
        """
        return self.__walCompression

    def logLevel(self) -> Optional[str]:
        """
        Log level for Prometheus to be configured with.
        """
        return self.__logLevel

    def logFormat(self) -> Optional[str]:
        """
        Log format for Prometheus to be configured with.
        """
        return self.__logFormat

    def scrapeInterval(self) -> Optional[str]:
        """
        Interval between consecutive scrapes.
        """
        return self.__scrapeInterval

    def evaluationInterval(self) -> Optional[str]:
        """
        Interval between consecutive evaluations.
        """
        return self.__evaluationInterval

    def rules(self) -> Optional["Rules"]:
        """
        /--rules.*/ command-line arguments.
        """
        return self.__rules

    def externalLabels(self) -> Optional[Dict[str, str]]:
        """
        The labels to add to any time series or alerts when communicating with
        external systems (federation, remote storage, Alertmanager).
        """
        return self.__externalLabels

    def enableAdminAPI(self) -> Optional[bool]:
        """
        Enable access to prometheus web admin API. Defaults to the value of `false`.
        WARNING: Enabling the admin APIs enables mutating endpoints, to delete data,
        shutdown Prometheus, and more. Enabling this should be done with care and the
        user is advised to add additional authentication authorization via a proxy to
        ensure only clients authorized to perform these actions can do so.
        For more information see https://prometheus.io/docs/prometheus/latest/querying/api/#tsdb-admin-apis
        """
        return self.__enableAdminAPI

    def externalUrl(self) -> Optional[str]:
        """
        The external URL the Prometheus instances will be available under. This is
        necessary to generate correct URLs. This is necessary if Prometheus is not
        served from root of a DNS name.
        """
        return self.__externalUrl

    def routePrefix(self) -> Optional[str]:
        """
        The route prefix Prometheus registers HTTP handlers for. This is useful,
        if using ExternalURL and a proxy is rewriting HTTP routes of a request,
        and the actual ExternalURL is still true, but the server serves requests
        under a different route prefix. For example for use with `kubectl proxy`.
        """
        return self.__routePrefix

    def query(self) -> Optional["QuerySpec"]:
        """
        QuerySpec defines the query command line flags when starting Prometheus.
        """
        return self.__query

    def storage(self) -> Optional["StorageSpec"]:
        """
        Storage spec to specify how storage shall be used.
        """
        return self.__storage

    def volumes(self) -> Optional[List["corev1.Volume"]]:
        """
        Volumes allows configuration of additional volumes on the output StatefulSet definition. Volumes specified will
        be appended to other volumes that are generated as a result of StorageSpec objects.
        """
        return self.__volumes

    def ruleSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        A selector to select which PrometheusRules to mount for loading alerting
        rules from. Until (excluding) Prometheus Operator v0.24.0 Prometheus
        Operator will migrate any legacy rule ConfigMaps to PrometheusRule custom
        resources selected by RuleSelector. Make sure it does not match any config
        maps that you do not want to be migrated.
        """
        return self.__ruleSelector

    def ruleNamespaceSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        Namespaces to be selected for PrometheusRules discovery. If unspecified, only
        the same namespace as the Prometheus object is in is used.
        """
        return self.__ruleNamespaceSelector

    def alerting(self) -> Optional["AlertingSpec"]:
        """
        Define details regarding alerting.
        """
        return self.__alerting

    def resources(self) -> Optional["corev1.ResourceRequirements"]:
        """
        Define resources requests and limits for single Pods.
        """
        return self.__resources

    def nodeSelector(self) -> Optional[Dict[str, str]]:
        """
        Define which Nodes the Pods are scheduled on.
        """
        return self.__nodeSelector

    def serviceAccountName(self) -> Optional[str]:
        """
        ServiceAccountName is the name of the ServiceAccount to use to run the
        Prometheus Pods.
        """
        return self.__serviceAccountName

    def secrets(self) -> Optional[List[str]]:
        """
        Secrets is a list of Secrets in the same namespace as the Prometheus
        object, which shall be mounted into the Prometheus Pods.
        The Secrets are mounted into /etc/prometheus/secrets/<secret-name>.
        """
        return self.__secrets

    def configMaps(self) -> Optional[List[str]]:
        """
        ConfigMaps is a list of ConfigMaps in the same namespace as the Prometheus
        object, which shall be mounted into the Prometheus Pods.
        The ConfigMaps are mounted into /etc/prometheus/configmaps/<configmap-name>.
        """
        return self.__configMaps

    def affinity(self) -> Optional["corev1.Affinity"]:
        """
        If specified, the pod's scheduling constraints.
        """
        return self.__affinity

    def tolerations(self) -> Optional[List["corev1.Toleration"]]:
        """
        If specified, the pod's tolerations.
        """
        return self.__tolerations

    def remoteWrite(self) -> Optional[List["RemoteWriteSpec"]]:
        """
        If specified, the remote_write spec. This is an experimental feature, it may change in any upcoming release in a breaking way.
        """
        return self.__remoteWrite

    def remoteRead(self) -> Optional[List["RemoteReadSpec"]]:
        """
        If specified, the remote_read spec. This is an experimental feature, it may change in any upcoming release in a breaking way.
        """
        return self.__remoteRead

    def securityContext(self) -> Optional["corev1.PodSecurityContext"]:
        """
        SecurityContext holds pod-level security attributes and common container settings.
        This defaults to the default PodSecurityContext.
        """
        return self.__securityContext

    def listenLocal(self) -> Optional[bool]:
        """
        ListenLocal makes the Prometheus server listen on loopback, so that it
        does not bind against the Pod IP.
        """
        return self.__listenLocal

    def containers(self) -> Optional[List["corev1.Container"]]:
        """
        Containers allows injecting additional containers or modifying operator generated
        containers. This can be used to allow adding an authentication proxy to a Prometheus pod or
        to change the behavior of an operator generated container. Containers described here modify
        an operator generated container if they share the same name and modifications are done via a
        strategic merge patch. The current container names are: `prometheus`,
        `prometheus-config-reloader`, `rules-configmap-reloader`, and `thanos-sidecar`. Overriding
        containers is entirely outside the scope of what the maintainers will support and by doing
        so, you accept that this behaviour may break at any time without notice.
        """
        return self.__containers

    def initContainers(self) -> Optional[List["corev1.Container"]]:
        """
        InitContainers allows adding initContainers to the pod definition. Those can be used to e.g.
        fetch secrets for injection into the Prometheus configuration from external sources. Any errors
        during the execution of an initContainer will lead to a restart of the Pod. More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
        Using initContainers for any use case other then secret fetching is entirely outside the scope
        of what the maintainers will support and by doing so, you accept that this behaviour may break
        at any time without notice.
        """
        return self.__initContainers

    def additionalScrapeConfigs(self) -> Optional["corev1.SecretKeySelector"]:
        """
        AdditionalScrapeConfigs allows specifying a key of a Secret containing
        additional Prometheus scrape configurations. Scrape configurations
        specified are appended to the configurations generated by the Prometheus
        Operator. Job configurations specified must have the form as specified
        in the official Prometheus documentation:
        https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config.
        As scrape configs are appended, the user is responsible to make sure it
        is valid. Note that using this feature may expose the possibility to
        break upgrades of Prometheus. It is advised to review Prometheus release
        notes to ensure that no incompatible scrape configs are going to break
        Prometheus after the upgrade.
        """
        return self.__additionalScrapeConfigs

    def additionalAlertRelabelConfigs(self) -> Optional["corev1.SecretKeySelector"]:
        """
        AdditionalAlertRelabelConfigs allows specifying a key of a Secret containing
        additional Prometheus alert relabel configurations. Alert relabel configurations
        specified are appended to the configurations generated by the Prometheus
        Operator. Alert relabel configurations specified must have the form as specified
        in the official Prometheus documentation:
        https://prometheus.io/docs/prometheus/latest/configuration/configuration/#alert_relabel_configs.
        As alert relabel configs are appended, the user is responsible to make sure it
        is valid. Note that using this feature may expose the possibility to
        break upgrades of Prometheus. It is advised to review Prometheus release
        notes to ensure that no incompatible alert relabel configs are going to break
        Prometheus after the upgrade.
        """
        return self.__additionalAlertRelabelConfigs

    def additionalAlertManagerConfigs(self) -> Optional["corev1.SecretKeySelector"]:
        """
        AdditionalAlertManagerConfigs allows specifying a key of a Secret containing
        additional Prometheus AlertManager configurations. AlertManager configurations
        specified are appended to the configurations generated by the Prometheus
        Operator. Job configurations specified must have the form as specified
        in the official Prometheus documentation:
        https://prometheus.io/docs/prometheus/latest/configuration/configuration/#alertmanager_config.
        As AlertManager configs are appended, the user is responsible to make sure it
        is valid. Note that using this feature may expose the possibility to
        break upgrades of Prometheus. It is advised to review Prometheus release
        notes to ensure that no incompatible AlertManager configs are going to break
        Prometheus after the upgrade.
        """
        return self.__additionalAlertManagerConfigs

    def apiserverConfig(self) -> Optional["APIServerConfig"]:
        """
        APIServerConfig allows specifying a host and auth methods to access apiserver.
        If left empty, Prometheus is assumed to run inside of the cluster
        and will discover API servers automatically and use the pod's CA certificate
        and bearer token file at /var/run/secrets/kubernetes.io/serviceaccount/.
        """
        return self.__apiserverConfig

    def thanos(self) -> Optional["ThanosSpec"]:
        """
        Thanos configuration allows configuring various aspects of a Prometheus
        server in a Thanos environment.
        
        This section is experimental, it may change significantly without
        deprecation notice in any release.
        
        This is experimental and may change significantly without backward
        compatibility in any release.
        """
        return self.__thanos

    def priorityClassName(self) -> Optional[str]:
        """
        Priority class assigned to the Pods
        """
        return self.__priorityClassName

    def portName(self) -> Optional[str]:
        """
        Port name used for the pods and governing service.
        This defaults to web
        """
        return self.__portName

    def arbitraryFSAccessThroughSMs(
        self
    ) -> Optional["ArbitraryFSAccessThroughSMsConfig"]:
        """
        ArbitraryFSAccessThroughSMs configures whether configuration
        based on a service monitor can access arbitrary files on the file system
        of the Prometheus container e.g. bearer token files.
        """
        return self.__arbitraryFSAccessThroughSMs

    def overrideHonorLabels(self) -> Optional[bool]:
        """
        OverrideHonorLabels if set to true overrides all user configured honor_labels.
        If HonorLabels is set in ServiceMonitor or PodMonitor to true, this overrides honor_labels to false.
        """
        return self.__overrideHonorLabels

    def overrideHonorTimestamps(self) -> Optional[bool]:
        """
        OverrideHonorTimestamps allows to globally enforce honoring timestamps in all scrape configs.
        """
        return self.__overrideHonorTimestamps

    def ignoreNamespaceSelectors(self) -> Optional[bool]:
        """
        IgnoreNamespaceSelectors if set to true will ignore NamespaceSelector settings from
        the podmonitor and servicemonitor configs, and they will only discover endpoints
        within their current namespace.  Defaults to false.
        """
        return self.__ignoreNamespaceSelectors

    def enforcedNamespaceLabel(self) -> Optional[str]:
        """
        EnforcedNamespaceLabel enforces adding a namespace label of origin for each alert
        and metric that is user created. The label value will always be the namespace of the object that is
        being created.
        """
        return self.__enforcedNamespaceLabel


class Prometheus(base.TypedObject, base.NamespacedMetadataObject):
    """
    Prometheus defines a Prometheus deployment.
    +genclient
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PrometheusSpec" = None,
    ):
        super().__init__(
            apiVersion="monitoring.coreos.com/v1",
            kind="Prometheus",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PrometheusSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "PrometheusSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "PrometheusSpec":
        """
        Specification of the desired behavior of the Prometheus cluster. More info:
        https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class Rule(types.Object):
    """
    Rule describes an alerting or recording rule.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        record: str = None,
        alert: str = None,
        expr: Union[int, str] = None,
        for_: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
    ):
        super().__init__()
        self.__record = record
        self.__alert = alert
        self.__expr = expr if expr is not None else 0
        self.__for_ = for_
        self.__labels = labels if labels is not None else {}
        self.__annotations = annotations if annotations is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        record = self.record()
        check_type("record", record, Optional[str])
        if record:  # omit empty
            v["record"] = record
        alert = self.alert()
        check_type("alert", alert, Optional[str])
        if alert:  # omit empty
            v["alert"] = alert
        expr = self.expr()
        check_type("expr", expr, Union[int, str])
        v["expr"] = expr
        for_ = self.for_()
        check_type("for_", for_, Optional[str])
        if for_:  # omit empty
            v["for"] = for_
        labels = self.labels()
        check_type("labels", labels, Optional[Dict[str, str]])
        if labels:  # omit empty
            v["labels"] = labels
        annotations = self.annotations()
        check_type("annotations", annotations, Optional[Dict[str, str]])
        if annotations:  # omit empty
            v["annotations"] = annotations
        return v

    def record(self) -> Optional[str]:
        return self.__record

    def alert(self) -> Optional[str]:
        return self.__alert

    def expr(self) -> Union[int, str]:
        return self.__expr

    def for_(self) -> Optional[str]:
        return self.__for_

    def labels(self) -> Optional[Dict[str, str]]:
        return self.__labels

    def annotations(self) -> Optional[Dict[str, str]]:
        return self.__annotations


class RuleGroup(types.Object):
    """
    RuleGroup is a list of sequentially evaluated recording and alerting rules.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, name: str = "", interval: str = None, rules: List["Rule"] = None
    ):
        super().__init__()
        self.__name = name
        self.__interval = interval
        self.__rules = rules if rules is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        interval = self.interval()
        check_type("interval", interval, Optional[str])
        if interval:  # omit empty
            v["interval"] = interval
        rules = self.rules()
        check_type("rules", rules, List["Rule"])
        v["rules"] = rules
        return v

    def name(self) -> str:
        return self.__name

    def interval(self) -> Optional[str]:
        return self.__interval

    def rules(self) -> List["Rule"]:
        return self.__rules


class PrometheusRuleSpec(types.Object):
    """
    PrometheusRuleSpec contains specification parameters for a Rule.
    """

    @context.scoped
    @typechecked
    def __init__(self, groups: List["RuleGroup"] = None):
        super().__init__()
        self.__groups = groups if groups is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        groups = self.groups()
        check_type("groups", groups, Optional[List["RuleGroup"]])
        if groups:  # omit empty
            v["groups"] = groups
        return v

    def groups(self) -> Optional[List["RuleGroup"]]:
        """
        Content of Prometheus rule file
        """
        return self.__groups


class PrometheusRule(base.TypedObject, base.NamespacedMetadataObject):
    """
    PrometheusRule defines alerting rules for a Prometheus instance
    +genclient
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "PrometheusRuleSpec" = None,
    ):
        super().__init__(
            apiVersion="monitoring.coreos.com/v1",
            kind="PrometheusRule",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else PrometheusRuleSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "PrometheusRuleSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "PrometheusRuleSpec":
        """
        Specification of desired alerting rule definitions for Prometheus.
        """
        return self.__spec


class ServiceMonitorSpec(types.Object):
    """
    ServiceMonitorSpec contains specification parameters for a ServiceMonitor.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        jobLabel: str = None,
        targetLabels: List[str] = None,
        podTargetLabels: List[str] = None,
        endpoints: List["Endpoint"] = None,
        selector: "metav1.LabelSelector" = None,
        namespaceSelector: "NamespaceSelector" = None,
        sampleLimit: int = None,
    ):
        super().__init__()
        self.__jobLabel = jobLabel
        self.__targetLabels = targetLabels if targetLabels is not None else []
        self.__podTargetLabels = podTargetLabels if podTargetLabels is not None else []
        self.__endpoints = endpoints if endpoints is not None else []
        self.__selector = selector if selector is not None else metav1.LabelSelector()
        self.__namespaceSelector = (
            namespaceSelector if namespaceSelector is not None else NamespaceSelector()
        )
        self.__sampleLimit = sampleLimit

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        jobLabel = self.jobLabel()
        check_type("jobLabel", jobLabel, Optional[str])
        if jobLabel:  # omit empty
            v["jobLabel"] = jobLabel
        targetLabels = self.targetLabels()
        check_type("targetLabels", targetLabels, Optional[List[str]])
        if targetLabels:  # omit empty
            v["targetLabels"] = targetLabels
        podTargetLabels = self.podTargetLabels()
        check_type("podTargetLabels", podTargetLabels, Optional[List[str]])
        if podTargetLabels:  # omit empty
            v["podTargetLabels"] = podTargetLabels
        endpoints = self.endpoints()
        check_type("endpoints", endpoints, List["Endpoint"])
        v["endpoints"] = endpoints
        selector = self.selector()
        check_type("selector", selector, "metav1.LabelSelector")
        v["selector"] = selector
        namespaceSelector = self.namespaceSelector()
        check_type(
            "namespaceSelector", namespaceSelector, Optional["NamespaceSelector"]
        )
        v["namespaceSelector"] = namespaceSelector
        sampleLimit = self.sampleLimit()
        check_type("sampleLimit", sampleLimit, Optional[int])
        if sampleLimit:  # omit empty
            v["sampleLimit"] = sampleLimit
        return v

    def jobLabel(self) -> Optional[str]:
        """
        The label to use to retrieve the job name from.
        """
        return self.__jobLabel

    def targetLabels(self) -> Optional[List[str]]:
        """
        TargetLabels transfers labels on the Kubernetes Service onto the target.
        """
        return self.__targetLabels

    def podTargetLabels(self) -> Optional[List[str]]:
        """
        PodTargetLabels transfers labels on the Kubernetes Pod onto the target.
        """
        return self.__podTargetLabels

    def endpoints(self) -> List["Endpoint"]:
        """
        A list of endpoints allowed as part of this ServiceMonitor.
        """
        return self.__endpoints

    def selector(self) -> "metav1.LabelSelector":
        """
        Selector to select Endpoints objects.
        """
        return self.__selector

    def namespaceSelector(self) -> Optional["NamespaceSelector"]:
        """
        Selector to select which namespaces the Endpoints objects are discovered from.
        """
        return self.__namespaceSelector

    def sampleLimit(self) -> Optional[int]:
        """
        SampleLimit defines per-scrape limit on number of scraped samples that will be accepted.
        """
        return self.__sampleLimit


class ServiceMonitor(base.TypedObject, base.NamespacedMetadataObject):
    """
    ServiceMonitor defines monitoring for a set of services.
    +genclient
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ServiceMonitorSpec" = None,
    ):
        super().__init__(
            apiVersion="monitoring.coreos.com/v1",
            kind="ServiceMonitor",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ServiceMonitorSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ServiceMonitorSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ServiceMonitorSpec":
        """
        Specification of desired Service selection for target discrovery by
        Prometheus.
        """
        return self.__spec
