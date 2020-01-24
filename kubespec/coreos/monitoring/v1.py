# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional, Union


class BasicAuth(types.Object):
    """
    BasicAuth allow an endpoint to authenticate over basic authentication
    More info: https://prometheus.io/docs/operating/configuration/#endpoints
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        username: "k8sv1.SecretKeySelector" = None,
        password: "k8sv1.SecretKeySelector" = None,
    ):
        super().__init__()
        self.__username = (
            username if username is not None else k8sv1.SecretKeySelector()
        )
        self.__password = (
            password if password is not None else k8sv1.SecretKeySelector()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        username = self.username()
        check_type("username", username, Optional["k8sv1.SecretKeySelector"])
        v["username"] = username
        password = self.password()
        check_type("password", password, Optional["k8sv1.SecretKeySelector"])
        v["password"] = password
        return v

    def username(self) -> Optional["k8sv1.SecretKeySelector"]:
        """
        The secret in the service monitor namespace that contains the username
        for authentication.
        """
        return self.__username

    def password(self) -> Optional["k8sv1.SecretKeySelector"]:
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
        secret: "k8sv1.SecretKeySelector" = None,
        config_map: "k8sv1.ConfigMapKeySelector" = None,
    ):
        super().__init__()
        self.__secret = secret
        self.__config_map = config_map

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        secret = self.secret()
        check_type("secret", secret, Optional["k8sv1.SecretKeySelector"])
        if secret is not None:  # omit empty
            v["secret"] = secret
        config_map = self.config_map()
        check_type("config_map", config_map, Optional["k8sv1.ConfigMapKeySelector"])
        if config_map is not None:  # omit empty
            v["configMap"] = config_map
        return v

    def secret(self) -> Optional["k8sv1.SecretKeySelector"]:
        """
        Secret containing data to use for the targets.
        """
        return self.__secret

    def config_map(self) -> Optional["k8sv1.ConfigMapKeySelector"]:
        """
        ConfigMap containing data to use for the targets.
        """
        return self.__config_map


class TLSConfig(types.Object):
    """
    TLSConfig specifies TLS configuration parameters.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        ca_file: str = None,
        ca: "SecretOrConfigMap" = None,
        cert_file: str = None,
        cert: "SecretOrConfigMap" = None,
        key_file: str = None,
        key_secret: "k8sv1.SecretKeySelector" = None,
        server_name: str = None,
        insecure_skip_verify: bool = None,
    ):
        super().__init__()
        self.__ca_file = ca_file
        self.__ca = ca if ca is not None else SecretOrConfigMap()
        self.__cert_file = cert_file
        self.__cert = cert if cert is not None else SecretOrConfigMap()
        self.__key_file = key_file
        self.__key_secret = key_secret
        self.__server_name = server_name
        self.__insecure_skip_verify = insecure_skip_verify

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ca_file = self.ca_file()
        check_type("ca_file", ca_file, Optional[str])
        if ca_file:  # omit empty
            v["caFile"] = ca_file
        ca = self.ca()
        check_type("ca", ca, Optional["SecretOrConfigMap"])
        v["ca"] = ca
        cert_file = self.cert_file()
        check_type("cert_file", cert_file, Optional[str])
        if cert_file:  # omit empty
            v["certFile"] = cert_file
        cert = self.cert()
        check_type("cert", cert, Optional["SecretOrConfigMap"])
        v["cert"] = cert
        key_file = self.key_file()
        check_type("key_file", key_file, Optional[str])
        if key_file:  # omit empty
            v["keyFile"] = key_file
        key_secret = self.key_secret()
        check_type("key_secret", key_secret, Optional["k8sv1.SecretKeySelector"])
        if key_secret is not None:  # omit empty
            v["keySecret"] = key_secret
        server_name = self.server_name()
        check_type("server_name", server_name, Optional[str])
        if server_name:  # omit empty
            v["serverName"] = server_name
        insecure_skip_verify = self.insecure_skip_verify()
        check_type("insecure_skip_verify", insecure_skip_verify, Optional[bool])
        if insecure_skip_verify:  # omit empty
            v["insecureSkipVerify"] = insecure_skip_verify
        return v

    def ca_file(self) -> Optional[str]:
        """
        Path to the CA cert in the Prometheus container to use for the targets.
        """
        return self.__ca_file

    def ca(self) -> Optional["SecretOrConfigMap"]:
        """
        Stuct containing the CA cert to use for the targets.
        """
        return self.__ca

    def cert_file(self) -> Optional[str]:
        """
        Path to the client cert file in the Prometheus container for the targets.
        """
        return self.__cert_file

    def cert(self) -> Optional["SecretOrConfigMap"]:
        """
        Struct containing the client cert file for the targets.
        """
        return self.__cert

    def key_file(self) -> Optional[str]:
        """
        Path to the client key file in the Prometheus container for the targets.
        """
        return self.__key_file

    def key_secret(self) -> Optional["k8sv1.SecretKeySelector"]:
        """
        Secret containing the client key file for the targets.
        """
        return self.__key_secret

    def server_name(self) -> Optional[str]:
        """
        Used to verify the hostname for the targets.
        """
        return self.__server_name

    def insecure_skip_verify(self) -> Optional[bool]:
        """
        Disable target certificate validation.
        """
        return self.__insecure_skip_verify


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
        basic_auth: "BasicAuth" = None,
        bearer_token: str = None,
        bearer_token_file: str = None,
        tls_config: "TLSConfig" = None,
    ):
        super().__init__()
        self.__host = host
        self.__basic_auth = basic_auth
        self.__bearer_token = bearer_token
        self.__bearer_token_file = bearer_token_file
        self.__tls_config = tls_config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        host = self.host()
        check_type("host", host, str)
        v["host"] = host
        basic_auth = self.basic_auth()
        check_type("basic_auth", basic_auth, Optional["BasicAuth"])
        if basic_auth is not None:  # omit empty
            v["basicAuth"] = basic_auth
        bearer_token = self.bearer_token()
        check_type("bearer_token", bearer_token, Optional[str])
        if bearer_token:  # omit empty
            v["bearerToken"] = bearer_token
        bearer_token_file = self.bearer_token_file()
        check_type("bearer_token_file", bearer_token_file, Optional[str])
        if bearer_token_file:  # omit empty
            v["bearerTokenFile"] = bearer_token_file
        tls_config = self.tls_config()
        check_type("tls_config", tls_config, Optional["TLSConfig"])
        if tls_config is not None:  # omit empty
            v["tlsConfig"] = tls_config
        return v

    def host(self) -> str:
        """
        Host of apiserver.
        A valid string consisting of a hostname or IP followed by an optional port number
        """
        return self.__host

    def basic_auth(self) -> Optional["BasicAuth"]:
        """
        BasicAuth allow an endpoint to authenticate over basic authentication
        """
        return self.__basic_auth

    def bearer_token(self) -> Optional[str]:
        """
        Bearer token for accessing apiserver.
        """
        return self.__bearer_token

    def bearer_token_file(self) -> Optional[str]:
        """
        File to read bearer token for accessing apiserver.
        """
        return self.__bearer_token_file

    def tls_config(self) -> Optional["TLSConfig"]:
        """
        TLS Config to use for accessing apiserver.
        """
        return self.__tls_config


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
        path_prefix: str = None,
        tls_config: "TLSConfig" = None,
        bearer_token_file: str = None,
    ):
        super().__init__()
        self.__namespace = namespace
        self.__name = name
        self.__port = port if port is not None else 0
        self.__scheme = scheme
        self.__path_prefix = path_prefix
        self.__tls_config = tls_config
        self.__bearer_token_file = bearer_token_file

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
        path_prefix = self.path_prefix()
        check_type("path_prefix", path_prefix, Optional[str])
        if path_prefix:  # omit empty
            v["pathPrefix"] = path_prefix
        tls_config = self.tls_config()
        check_type("tls_config", tls_config, Optional["TLSConfig"])
        if tls_config is not None:  # omit empty
            v["tlsConfig"] = tls_config
        bearer_token_file = self.bearer_token_file()
        check_type("bearer_token_file", bearer_token_file, Optional[str])
        if bearer_token_file:  # omit empty
            v["bearerTokenFile"] = bearer_token_file
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

    def path_prefix(self) -> Optional[str]:
        """
        Prefix for the HTTP path alerts are pushed to.
        """
        return self.__path_prefix

    def tls_config(self) -> Optional["TLSConfig"]:
        """
        TLS Config to use for alertmanager connection.
        """
        return self.__tls_config

    def bearer_token_file(self) -> Optional[str]:
        """
        BearerTokenFile to read from filesystem to use when authenticating to
        Alertmanager.
        """
        return self.__bearer_token_file


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
        empty_dir: "k8sv1.EmptyDirVolumeSource" = None,
        volume_claim_template: "k8sv1.PersistentVolumeClaim" = None,
    ):
        super().__init__()
        self.__empty_dir = empty_dir
        self.__volume_claim_template = (
            volume_claim_template
            if volume_claim_template is not None
            else k8sv1.PersistentVolumeClaim()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        empty_dir = self.empty_dir()
        check_type("empty_dir", empty_dir, Optional["k8sv1.EmptyDirVolumeSource"])
        if empty_dir is not None:  # omit empty
            v["emptyDir"] = empty_dir
        volume_claim_template = self.volume_claim_template()
        check_type(
            "volume_claim_template",
            volume_claim_template,
            Optional["k8sv1.PersistentVolumeClaim"],
        )
        v["volumeClaimTemplate"] = volume_claim_template
        return v

    def empty_dir(self) -> Optional["k8sv1.EmptyDirVolumeSource"]:
        """
        EmptyDirVolumeSource to be used by the Prometheus StatefulSets. If specified, used in place of any volumeClaimTemplate. More
        info: https://kubernetes.io/docs/concepts/storage/volumes/#emptydir
        """
        return self.__empty_dir

    def volume_claim_template(self) -> Optional["k8sv1.PersistentVolumeClaim"]:
        """
        A PVC spec to be used by the Prometheus StatefulSets.
        """
        return self.__volume_claim_template


class AlertmanagerSpec(types.Object):
    """
    AlertmanagerSpec is a specification of the desired behavior of the Alertmanager cluster. More info:
    https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        pod_metadata: "metav1.ObjectMeta" = None,
        image: str = None,
        version: str = None,
        tag: str = None,
        sha: str = None,
        base_image: str = None,
        image_pull_secrets: List["k8sv1.LocalObjectReference"] = None,
        secrets: List[str] = None,
        config_maps: List[str] = None,
        config_secret: str = None,
        log_level: str = None,
        log_format: str = None,
        replicas: int = None,
        retention: str = None,
        storage: "StorageSpec" = None,
        volumes: List["k8sv1.Volume"] = None,
        volume_mounts: List["k8sv1.VolumeMount"] = None,
        external_url: str = None,
        route_prefix: str = None,
        paused: bool = None,
        node_selector: Dict[str, str] = None,
        resources: "k8sv1.ResourceRequirements" = None,
        affinity: "k8sv1.Affinity" = None,
        tolerations: List["k8sv1.Toleration"] = None,
        security_context: "k8sv1.PodSecurityContext" = None,
        service_account_name: str = None,
        listen_local: bool = None,
        containers: List["k8sv1.Container"] = None,
        init_containers: List["k8sv1.Container"] = None,
        priority_class_name: str = None,
        additional_peers: List[str] = None,
        port_name: str = None,
    ):
        super().__init__()
        self.__pod_metadata = pod_metadata
        self.__image = image
        self.__version = version
        self.__tag = tag
        self.__sha = sha
        self.__base_image = base_image
        self.__image_pull_secrets = (
            image_pull_secrets if image_pull_secrets is not None else []
        )
        self.__secrets = secrets if secrets is not None else []
        self.__config_maps = config_maps if config_maps is not None else []
        self.__config_secret = config_secret
        self.__log_level = log_level
        self.__log_format = log_format
        self.__replicas = replicas
        self.__retention = retention
        self.__storage = storage
        self.__volumes = volumes if volumes is not None else []
        self.__volume_mounts = volume_mounts if volume_mounts is not None else []
        self.__external_url = external_url
        self.__route_prefix = route_prefix
        self.__paused = paused
        self.__node_selector = node_selector if node_selector is not None else {}
        self.__resources = (
            resources if resources is not None else k8sv1.ResourceRequirements()
        )
        self.__affinity = affinity
        self.__tolerations = tolerations if tolerations is not None else []
        self.__security_context = security_context
        self.__service_account_name = service_account_name
        self.__listen_local = listen_local
        self.__containers = containers if containers is not None else []
        self.__init_containers = init_containers if init_containers is not None else []
        self.__priority_class_name = priority_class_name
        self.__additional_peers = (
            additional_peers if additional_peers is not None else []
        )
        self.__port_name = port_name

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pod_metadata = self.pod_metadata()
        check_type("pod_metadata", pod_metadata, Optional["metav1.ObjectMeta"])
        if pod_metadata is not None:  # omit empty
            v["podMetadata"] = pod_metadata
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
        base_image = self.base_image()
        check_type("base_image", base_image, Optional[str])
        if base_image:  # omit empty
            v["baseImage"] = base_image
        image_pull_secrets = self.image_pull_secrets()
        check_type(
            "image_pull_secrets",
            image_pull_secrets,
            Optional[List["k8sv1.LocalObjectReference"]],
        )
        if image_pull_secrets:  # omit empty
            v["imagePullSecrets"] = image_pull_secrets
        secrets = self.secrets()
        check_type("secrets", secrets, Optional[List[str]])
        if secrets:  # omit empty
            v["secrets"] = secrets
        config_maps = self.config_maps()
        check_type("config_maps", config_maps, Optional[List[str]])
        if config_maps:  # omit empty
            v["configMaps"] = config_maps
        config_secret = self.config_secret()
        check_type("config_secret", config_secret, Optional[str])
        if config_secret:  # omit empty
            v["configSecret"] = config_secret
        log_level = self.log_level()
        check_type("log_level", log_level, Optional[str])
        if log_level:  # omit empty
            v["logLevel"] = log_level
        log_format = self.log_format()
        check_type("log_format", log_format, Optional[str])
        if log_format:  # omit empty
            v["logFormat"] = log_format
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
        check_type("volumes", volumes, Optional[List["k8sv1.Volume"]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        volume_mounts = self.volume_mounts()
        check_type("volume_mounts", volume_mounts, Optional[List["k8sv1.VolumeMount"]])
        if volume_mounts:  # omit empty
            v["volumeMounts"] = volume_mounts
        external_url = self.external_url()
        check_type("external_url", external_url, Optional[str])
        if external_url:  # omit empty
            v["externalUrl"] = external_url
        route_prefix = self.route_prefix()
        check_type("route_prefix", route_prefix, Optional[str])
        if route_prefix:  # omit empty
            v["routePrefix"] = route_prefix
        paused = self.paused()
        check_type("paused", paused, Optional[bool])
        if paused:  # omit empty
            v["paused"] = paused
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional[Dict[str, str]])
        if node_selector:  # omit empty
            v["nodeSelector"] = node_selector
        resources = self.resources()
        check_type("resources", resources, Optional["k8sv1.ResourceRequirements"])
        v["resources"] = resources
        affinity = self.affinity()
        check_type("affinity", affinity, Optional["k8sv1.Affinity"])
        if affinity is not None:  # omit empty
            v["affinity"] = affinity
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        security_context = self.security_context()
        check_type(
            "security_context", security_context, Optional["k8sv1.PodSecurityContext"]
        )
        if security_context is not None:  # omit empty
            v["securityContext"] = security_context
        service_account_name = self.service_account_name()
        check_type("service_account_name", service_account_name, Optional[str])
        if service_account_name:  # omit empty
            v["serviceAccountName"] = service_account_name
        listen_local = self.listen_local()
        check_type("listen_local", listen_local, Optional[bool])
        if listen_local:  # omit empty
            v["listenLocal"] = listen_local
        containers = self.containers()
        check_type("containers", containers, Optional[List["k8sv1.Container"]])
        if containers:  # omit empty
            v["containers"] = containers
        init_containers = self.init_containers()
        check_type(
            "init_containers", init_containers, Optional[List["k8sv1.Container"]]
        )
        if init_containers:  # omit empty
            v["initContainers"] = init_containers
        priority_class_name = self.priority_class_name()
        check_type("priority_class_name", priority_class_name, Optional[str])
        if priority_class_name:  # omit empty
            v["priorityClassName"] = priority_class_name
        additional_peers = self.additional_peers()
        check_type("additional_peers", additional_peers, Optional[List[str]])
        if additional_peers:  # omit empty
            v["additionalPeers"] = additional_peers
        port_name = self.port_name()
        check_type("port_name", port_name, Optional[str])
        if port_name:  # omit empty
            v["portName"] = port_name
        return v

    def pod_metadata(self) -> Optional["metav1.ObjectMeta"]:
        """
        Standard object’s metadata. More info:
        https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
        Metadata Labels and Annotations gets propagated to the prometheus pods.
        """
        return self.__pod_metadata

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

    def base_image(self) -> Optional[str]:
        """
        Base image that is used to deploy pods, without tag.
        """
        return self.__base_image

    def image_pull_secrets(self) -> Optional[List["k8sv1.LocalObjectReference"]]:
        """
        An optional list of references to secrets in the same namespace
        to use for pulling prometheus and alertmanager images from registries
        see http://kubernetes.io/docs/user-guide/images#specifying-imagepullsecrets-on-a-pod
        """
        return self.__image_pull_secrets

    def secrets(self) -> Optional[List[str]]:
        """
        Secrets is a list of Secrets in the same namespace as the Alertmanager
        object, which shall be mounted into the Alertmanager Pods.
        The Secrets are mounted into /etc/alertmanager/secrets/<secret-name>.
        """
        return self.__secrets

    def config_maps(self) -> Optional[List[str]]:
        """
        ConfigMaps is a list of ConfigMaps in the same namespace as the Alertmanager
        object, which shall be mounted into the Alertmanager Pods.
        The ConfigMaps are mounted into /etc/alertmanager/configmaps/<configmap-name>.
        """
        return self.__config_maps

    def config_secret(self) -> Optional[str]:
        """
        ConfigSecret is the name of a Kubernetes Secret in the same namespace as the
        Alertmanager object, which contains configuration for this Alertmanager
        instance. Defaults to 'alertmanager-<alertmanager-name>'
        The secret is mounted into /etc/alertmanager/config.
        """
        return self.__config_secret

    def log_level(self) -> Optional[str]:
        """
        Log level for Alertmanager to be configured with.
        """
        return self.__log_level

    def log_format(self) -> Optional[str]:
        """
        Log format for Alertmanager to be configured with.
        """
        return self.__log_format

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

    def volumes(self) -> Optional[List["k8sv1.Volume"]]:
        """
        Volumes allows configuration of additional volumes on the output StatefulSet definition.
        Volumes specified will be appended to other volumes that are generated as a result of
        StorageSpec objects.
        """
        return self.__volumes

    def volume_mounts(self) -> Optional[List["k8sv1.VolumeMount"]]:
        """
        VolumeMounts allows configuration of additional VolumeMounts on the output StatefulSet definition.
        VolumeMounts specified will be appended to other VolumeMounts in the alertmanager container,
        that are generated as a result of StorageSpec objects.
        """
        return self.__volume_mounts

    def external_url(self) -> Optional[str]:
        """
        The external URL the Alertmanager instances will be available under. This is
        necessary to generate correct URLs. This is necessary if Alertmanager is not
        served from root of a DNS name.
        """
        return self.__external_url

    def route_prefix(self) -> Optional[str]:
        """
        The route prefix Alertmanager registers HTTP handlers for. This is useful,
        if using ExternalURL and a proxy is rewriting HTTP routes of a request,
        and the actual ExternalURL is still true, but the server serves requests
        under a different route prefix. For example for use with `kubectl proxy`.
        """
        return self.__route_prefix

    def paused(self) -> Optional[bool]:
        """
        If set to true all actions on the underlaying managed objects are not
        goint to be performed, except for delete actions.
        """
        return self.__paused

    def node_selector(self) -> Optional[Dict[str, str]]:
        """
        Define which Nodes the Pods are scheduled on.
        """
        return self.__node_selector

    def resources(self) -> Optional["k8sv1.ResourceRequirements"]:
        """
        Define resources requests and limits for single Pods.
        """
        return self.__resources

    def affinity(self) -> Optional["k8sv1.Affinity"]:
        """
        If specified, the pod's scheduling constraints.
        """
        return self.__affinity

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        If specified, the pod's tolerations.
        """
        return self.__tolerations

    def security_context(self) -> Optional["k8sv1.PodSecurityContext"]:
        """
        SecurityContext holds pod-level security attributes and common container settings.
        This defaults to the default PodSecurityContext.
        """
        return self.__security_context

    def service_account_name(self) -> Optional[str]:
        """
        ServiceAccountName is the name of the ServiceAccount to use to run the
        Prometheus Pods.
        """
        return self.__service_account_name

    def listen_local(self) -> Optional[bool]:
        """
        ListenLocal makes the Alertmanager server listen on loopback, so that it
        does not bind against the Pod IP. Note this is only for the Alertmanager
        UI, not the gossip communication.
        """
        return self.__listen_local

    def containers(self) -> Optional[List["k8sv1.Container"]]:
        """
        Containers allows injecting additional containers. This is meant to
        allow adding an authentication proxy to an Alertmanager pod.
        """
        return self.__containers

    def init_containers(self) -> Optional[List["k8sv1.Container"]]:
        """
        InitContainers allows adding initContainers to the pod definition. Those can be used to e.g.
        fetch secrets for injection into the Alertmanager configuration from external sources. Any
        errors during the execution of an initContainer will lead to a restart of the Pod. More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
        Using initContainers for any use case other then secret fetching is entirely outside the scope
        of what the maintainers will support and by doing so, you accept that this behaviour may break
        at any time without notice.
        """
        return self.__init_containers

    def priority_class_name(self) -> Optional[str]:
        """
        Priority class assigned to the Pods
        """
        return self.__priority_class_name

    def additional_peers(self) -> Optional[List[str]]:
        """
        AdditionalPeers allows injecting a set of additional Alertmanagers to peer with to form a highly available cluster.
        """
        return self.__additional_peers

    def port_name(self) -> Optional[str]:
        """
        Port name used for the pods and governing service.
        This defaults to web
        """
        return self.__port_name


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
            api_version="monitoring.coreos.com/v1",
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
        source_labels: List[str] = None,
        separator: str = None,
        target_label: str = None,
        regex: str = None,
        modulus: int = None,
        replacement: str = None,
        action: str = None,
    ):
        super().__init__()
        self.__source_labels = source_labels if source_labels is not None else []
        self.__separator = separator
        self.__target_label = target_label
        self.__regex = regex
        self.__modulus = modulus
        self.__replacement = replacement
        self.__action = action

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        source_labels = self.source_labels()
        check_type("source_labels", source_labels, Optional[List[str]])
        if source_labels:  # omit empty
            v["sourceLabels"] = source_labels
        separator = self.separator()
        check_type("separator", separator, Optional[str])
        if separator:  # omit empty
            v["separator"] = separator
        target_label = self.target_label()
        check_type("target_label", target_label, Optional[str])
        if target_label:  # omit empty
            v["targetLabel"] = target_label
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

    def source_labels(self) -> Optional[List[str]]:
        """
        The source labels select values from existing labels. Their content is concatenated
        using the configured separator and matched against the configured regular expression
        for the replace, keep, and drop actions.
        """
        return self.__source_labels

    def separator(self) -> Optional[str]:
        """
        Separator placed between concatenated source label values. default is ';'.
        """
        return self.__separator

    def target_label(self) -> Optional[str]:
        """
        Label to which the resulting value is written in a replace action.
        It is mandatory for replace actions. Regex capture groups are available.
        """
        return self.__target_label

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
        target_port: Union[int, str] = None,
        path: str = None,
        scheme: str = None,
        params: Dict[str, List[str]] = None,
        interval: str = None,
        scrape_timeout: str = None,
        tls_config: "TLSConfig" = None,
        bearer_token_file: str = None,
        bearer_token_secret: "k8sv1.SecretKeySelector" = None,
        honor_labels: bool = None,
        honor_timestamps: bool = None,
        basic_auth: "BasicAuth" = None,
        metric_relabelings: List["RelabelConfig"] = None,
        relabelings: List["RelabelConfig"] = None,
        proxy_url: str = None,
    ):
        super().__init__()
        self.__port = port
        self.__target_port = target_port
        self.__path = path
        self.__scheme = scheme
        self.__params = params if params is not None else {}
        self.__interval = interval
        self.__scrape_timeout = scrape_timeout
        self.__tls_config = tls_config
        self.__bearer_token_file = bearer_token_file
        self.__bearer_token_secret = (
            bearer_token_secret
            if bearer_token_secret is not None
            else k8sv1.SecretKeySelector()
        )
        self.__honor_labels = honor_labels
        self.__honor_timestamps = honor_timestamps
        self.__basic_auth = basic_auth
        self.__metric_relabelings = (
            metric_relabelings if metric_relabelings is not None else []
        )
        self.__relabelings = relabelings if relabelings is not None else []
        self.__proxy_url = proxy_url

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        port = self.port()
        check_type("port", port, Optional[str])
        if port:  # omit empty
            v["port"] = port
        target_port = self.target_port()
        check_type("target_port", target_port, Optional[Union[int, str]])
        if target_port is not None:  # omit empty
            v["targetPort"] = target_port
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
        scrape_timeout = self.scrape_timeout()
        check_type("scrape_timeout", scrape_timeout, Optional[str])
        if scrape_timeout:  # omit empty
            v["scrapeTimeout"] = scrape_timeout
        tls_config = self.tls_config()
        check_type("tls_config", tls_config, Optional["TLSConfig"])
        if tls_config is not None:  # omit empty
            v["tlsConfig"] = tls_config
        bearer_token_file = self.bearer_token_file()
        check_type("bearer_token_file", bearer_token_file, Optional[str])
        if bearer_token_file:  # omit empty
            v["bearerTokenFile"] = bearer_token_file
        bearer_token_secret = self.bearer_token_secret()
        check_type(
            "bearer_token_secret",
            bearer_token_secret,
            Optional["k8sv1.SecretKeySelector"],
        )
        v["bearerTokenSecret"] = bearer_token_secret
        honor_labels = self.honor_labels()
        check_type("honor_labels", honor_labels, Optional[bool])
        if honor_labels:  # omit empty
            v["honorLabels"] = honor_labels
        honor_timestamps = self.honor_timestamps()
        check_type("honor_timestamps", honor_timestamps, Optional[bool])
        if honor_timestamps is not None:  # omit empty
            v["honorTimestamps"] = honor_timestamps
        basic_auth = self.basic_auth()
        check_type("basic_auth", basic_auth, Optional["BasicAuth"])
        if basic_auth is not None:  # omit empty
            v["basicAuth"] = basic_auth
        metric_relabelings = self.metric_relabelings()
        check_type(
            "metric_relabelings", metric_relabelings, Optional[List["RelabelConfig"]]
        )
        if metric_relabelings:  # omit empty
            v["metricRelabelings"] = metric_relabelings
        relabelings = self.relabelings()
        check_type("relabelings", relabelings, Optional[List["RelabelConfig"]])
        if relabelings:  # omit empty
            v["relabelings"] = relabelings
        proxy_url = self.proxy_url()
        check_type("proxy_url", proxy_url, Optional[str])
        if proxy_url is not None:  # omit empty
            v["proxyUrl"] = proxy_url
        return v

    def port(self) -> Optional[str]:
        """
        Name of the service port this endpoint refers to. Mutually exclusive with targetPort.
        """
        return self.__port

    def target_port(self) -> Optional[Union[int, str]]:
        """
        Name or number of the target port of the endpoint. Mutually exclusive with port.
        """
        return self.__target_port

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

    def scrape_timeout(self) -> Optional[str]:
        """
        Timeout after which the scrape is ended
        """
        return self.__scrape_timeout

    def tls_config(self) -> Optional["TLSConfig"]:
        """
        TLS configuration to use when scraping the endpoint
        """
        return self.__tls_config

    def bearer_token_file(self) -> Optional[str]:
        """
        File to read bearer token for scraping targets.
        """
        return self.__bearer_token_file

    def bearer_token_secret(self) -> Optional["k8sv1.SecretKeySelector"]:
        """
        Secret to mount to read bearer token for scraping targets. The secret
        needs to be in the same namespace as the service monitor and accessible by
        the Prometheus Operator.
        """
        return self.__bearer_token_secret

    def honor_labels(self) -> Optional[bool]:
        """
        HonorLabels chooses the metric's labels on collisions with target labels.
        """
        return self.__honor_labels

    def honor_timestamps(self) -> Optional[bool]:
        """
        HonorTimestamps controls whether Prometheus respects the timestamps present in scraped data.
        """
        return self.__honor_timestamps

    def basic_auth(self) -> Optional["BasicAuth"]:
        """
        BasicAuth allow an endpoint to authenticate over basic authentication
        More info: https://prometheus.io/docs/operating/configuration/#endpoints
        """
        return self.__basic_auth

    def metric_relabelings(self) -> Optional[List["RelabelConfig"]]:
        """
        MetricRelabelConfigs to apply to samples before ingestion.
        """
        return self.__metric_relabelings

    def relabelings(self) -> Optional[List["RelabelConfig"]]:
        """
        RelabelConfigs to apply to samples before scraping.
        More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
        """
        return self.__relabelings

    def proxy_url(self) -> Optional[str]:
        """
        ProxyURL eg http://proxyserver:2195 Directs scrapes to proxy through this endpoint.
        """
        return self.__proxy_url


class NamespaceSelector(types.Object):
    """
    NamespaceSelector is a selector for selecting either all namespaces or a
    list of namespaces.
    """

    @context.scoped
    @typechecked
    def __init__(self, any: bool = None, match_names: List[str] = None):
        super().__init__()
        self.__any = any
        self.__match_names = match_names if match_names is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        any = self.any()
        check_type("any", any, Optional[bool])
        if any:  # omit empty
            v["any"] = any
        match_names = self.match_names()
        check_type("match_names", match_names, Optional[List[str]])
        if match_names:  # omit empty
            v["matchNames"] = match_names
        return v

    def any(self) -> Optional[bool]:
        """
        Boolean describing whether all namespaces are selected in contrast to a
        list restricting them.
        """
        return self.__any

    def match_names(self) -> Optional[List[str]]:
        """
        List of namespace names.
        """
        return self.__match_names


class PodMetricsEndpoint(types.Object):
    """
    PodMetricsEndpoint defines a scrapeable endpoint of a Kubernetes Pod serving Prometheus metrics.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        port: str = None,
        target_port: Union[int, str] = None,
        path: str = None,
        scheme: str = None,
        params: Dict[str, List[str]] = None,
        interval: str = None,
        scrape_timeout: str = None,
        honor_labels: bool = None,
        honor_timestamps: bool = None,
        metric_relabelings: List["RelabelConfig"] = None,
        relabelings: List["RelabelConfig"] = None,
        proxy_url: str = None,
    ):
        super().__init__()
        self.__port = port
        self.__target_port = target_port
        self.__path = path
        self.__scheme = scheme
        self.__params = params if params is not None else {}
        self.__interval = interval
        self.__scrape_timeout = scrape_timeout
        self.__honor_labels = honor_labels
        self.__honor_timestamps = honor_timestamps
        self.__metric_relabelings = (
            metric_relabelings if metric_relabelings is not None else []
        )
        self.__relabelings = relabelings if relabelings is not None else []
        self.__proxy_url = proxy_url

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        port = self.port()
        check_type("port", port, Optional[str])
        if port:  # omit empty
            v["port"] = port
        target_port = self.target_port()
        check_type("target_port", target_port, Optional[Union[int, str]])
        if target_port is not None:  # omit empty
            v["targetPort"] = target_port
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
        scrape_timeout = self.scrape_timeout()
        check_type("scrape_timeout", scrape_timeout, Optional[str])
        if scrape_timeout:  # omit empty
            v["scrapeTimeout"] = scrape_timeout
        honor_labels = self.honor_labels()
        check_type("honor_labels", honor_labels, Optional[bool])
        if honor_labels:  # omit empty
            v["honorLabels"] = honor_labels
        honor_timestamps = self.honor_timestamps()
        check_type("honor_timestamps", honor_timestamps, Optional[bool])
        if honor_timestamps is not None:  # omit empty
            v["honorTimestamps"] = honor_timestamps
        metric_relabelings = self.metric_relabelings()
        check_type(
            "metric_relabelings", metric_relabelings, Optional[List["RelabelConfig"]]
        )
        if metric_relabelings:  # omit empty
            v["metricRelabelings"] = metric_relabelings
        relabelings = self.relabelings()
        check_type("relabelings", relabelings, Optional[List["RelabelConfig"]])
        if relabelings:  # omit empty
            v["relabelings"] = relabelings
        proxy_url = self.proxy_url()
        check_type("proxy_url", proxy_url, Optional[str])
        if proxy_url is not None:  # omit empty
            v["proxyUrl"] = proxy_url
        return v

    def port(self) -> Optional[str]:
        """
        Name of the port this endpoint refers to. Mutually exclusive with targetPort.
        """
        return self.__port

    def target_port(self) -> Optional[Union[int, str]]:
        """
        Name or number of the target port of the endpoint. Mutually exclusive with port.
        """
        return self.__target_port

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

    def scrape_timeout(self) -> Optional[str]:
        """
        Timeout after which the scrape is ended
        """
        return self.__scrape_timeout

    def honor_labels(self) -> Optional[bool]:
        """
        HonorLabels chooses the metric's labels on collisions with target labels.
        """
        return self.__honor_labels

    def honor_timestamps(self) -> Optional[bool]:
        """
        HonorTimestamps controls whether Prometheus respects the timestamps present in scraped data.
        """
        return self.__honor_timestamps

    def metric_relabelings(self) -> Optional[List["RelabelConfig"]]:
        """
        MetricRelabelConfigs to apply to samples before ingestion.
        """
        return self.__metric_relabelings

    def relabelings(self) -> Optional[List["RelabelConfig"]]:
        """
        RelabelConfigs to apply to samples before ingestion.
        More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
        """
        return self.__relabelings

    def proxy_url(self) -> Optional[str]:
        """
        ProxyURL eg http://proxyserver:2195 Directs scrapes to proxy through this endpoint.
        """
        return self.__proxy_url


class PodMonitorSpec(types.Object):
    """
    PodMonitorSpec contains specification parameters for a PodMonitor.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        job_label: str = None,
        pod_target_labels: List[str] = None,
        pod_metrics_endpoints: List["PodMetricsEndpoint"] = None,
        selector: "metav1.LabelSelector" = None,
        namespace_selector: "NamespaceSelector" = None,
        sample_limit: int = None,
    ):
        super().__init__()
        self.__job_label = job_label
        self.__pod_target_labels = (
            pod_target_labels if pod_target_labels is not None else []
        )
        self.__pod_metrics_endpoints = (
            pod_metrics_endpoints if pod_metrics_endpoints is not None else []
        )
        self.__selector = selector if selector is not None else metav1.LabelSelector()
        self.__namespace_selector = (
            namespace_selector
            if namespace_selector is not None
            else NamespaceSelector()
        )
        self.__sample_limit = sample_limit

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        job_label = self.job_label()
        check_type("job_label", job_label, Optional[str])
        if job_label:  # omit empty
            v["jobLabel"] = job_label
        pod_target_labels = self.pod_target_labels()
        check_type("pod_target_labels", pod_target_labels, Optional[List[str]])
        if pod_target_labels:  # omit empty
            v["podTargetLabels"] = pod_target_labels
        pod_metrics_endpoints = self.pod_metrics_endpoints()
        check_type(
            "pod_metrics_endpoints", pod_metrics_endpoints, List["PodMetricsEndpoint"]
        )
        v["podMetricsEndpoints"] = pod_metrics_endpoints
        selector = self.selector()
        check_type("selector", selector, "metav1.LabelSelector")
        v["selector"] = selector
        namespace_selector = self.namespace_selector()
        check_type(
            "namespace_selector", namespace_selector, Optional["NamespaceSelector"]
        )
        v["namespaceSelector"] = namespace_selector
        sample_limit = self.sample_limit()
        check_type("sample_limit", sample_limit, Optional[int])
        if sample_limit:  # omit empty
            v["sampleLimit"] = sample_limit
        return v

    def job_label(self) -> Optional[str]:
        """
        The label to use to retrieve the job name from.
        """
        return self.__job_label

    def pod_target_labels(self) -> Optional[List[str]]:
        """
        PodTargetLabels transfers labels on the Kubernetes Pod onto the target.
        """
        return self.__pod_target_labels

    def pod_metrics_endpoints(self) -> List["PodMetricsEndpoint"]:
        """
        A list of endpoints allowed as part of this PodMonitor.
        """
        return self.__pod_metrics_endpoints

    def selector(self) -> "metav1.LabelSelector":
        """
        Selector to select Pod objects.
        """
        return self.__selector

    def namespace_selector(self) -> Optional["NamespaceSelector"]:
        """
        Selector to select which namespaces the Endpoints objects are discovered from.
        """
        return self.__namespace_selector

    def sample_limit(self) -> Optional[int]:
        """
        SampleLimit defines per-scrape limit on number of scraped samples that will be accepted.
        """
        return self.__sample_limit


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
            api_version="monitoring.coreos.com/v1",
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
        lookback_delta: str = None,
        max_concurrency: int = None,
        max_samples: int = None,
        timeout: str = None,
    ):
        super().__init__()
        self.__lookback_delta = lookback_delta
        self.__max_concurrency = max_concurrency
        self.__max_samples = max_samples
        self.__timeout = timeout

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        lookback_delta = self.lookback_delta()
        check_type("lookback_delta", lookback_delta, Optional[str])
        if lookback_delta is not None:  # omit empty
            v["lookbackDelta"] = lookback_delta
        max_concurrency = self.max_concurrency()
        check_type("max_concurrency", max_concurrency, Optional[int])
        if max_concurrency is not None:  # omit empty
            v["maxConcurrency"] = max_concurrency
        max_samples = self.max_samples()
        check_type("max_samples", max_samples, Optional[int])
        if max_samples is not None:  # omit empty
            v["maxSamples"] = max_samples
        timeout = self.timeout()
        check_type("timeout", timeout, Optional[str])
        if timeout is not None:  # omit empty
            v["timeout"] = timeout
        return v

    def lookback_delta(self) -> Optional[str]:
        """
        The delta difference allowed for retrieving metrics during expression evaluations.
        """
        return self.__lookback_delta

    def max_concurrency(self) -> Optional[int]:
        """
        Number of concurrent queries that can be run at once.
        """
        return self.__max_concurrency

    def max_samples(self) -> Optional[int]:
        """
        Maximum number of samples a single query can load into memory. Note that queries will fail if they would load more samples than this into memory, so this also limits the number of samples a query can return.
        """
        return self.__max_samples

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
        required_matchers: Dict[str, str] = None,
        remote_timeout: str = None,
        read_recent: bool = None,
        basic_auth: "BasicAuth" = None,
        bearer_token: str = None,
        bearer_token_file: str = None,
        tls_config: "TLSConfig" = None,
        proxy_url: str = None,
    ):
        super().__init__()
        self.__url = url
        self.__required_matchers = (
            required_matchers if required_matchers is not None else {}
        )
        self.__remote_timeout = remote_timeout
        self.__read_recent = read_recent
        self.__basic_auth = basic_auth
        self.__bearer_token = bearer_token
        self.__bearer_token_file = bearer_token_file
        self.__tls_config = tls_config
        self.__proxy_url = proxy_url

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        required_matchers = self.required_matchers()
        check_type("required_matchers", required_matchers, Optional[Dict[str, str]])
        if required_matchers:  # omit empty
            v["requiredMatchers"] = required_matchers
        remote_timeout = self.remote_timeout()
        check_type("remote_timeout", remote_timeout, Optional[str])
        if remote_timeout:  # omit empty
            v["remoteTimeout"] = remote_timeout
        read_recent = self.read_recent()
        check_type("read_recent", read_recent, Optional[bool])
        if read_recent:  # omit empty
            v["readRecent"] = read_recent
        basic_auth = self.basic_auth()
        check_type("basic_auth", basic_auth, Optional["BasicAuth"])
        if basic_auth is not None:  # omit empty
            v["basicAuth"] = basic_auth
        bearer_token = self.bearer_token()
        check_type("bearer_token", bearer_token, Optional[str])
        if bearer_token:  # omit empty
            v["bearerToken"] = bearer_token
        bearer_token_file = self.bearer_token_file()
        check_type("bearer_token_file", bearer_token_file, Optional[str])
        if bearer_token_file:  # omit empty
            v["bearerTokenFile"] = bearer_token_file
        tls_config = self.tls_config()
        check_type("tls_config", tls_config, Optional["TLSConfig"])
        if tls_config is not None:  # omit empty
            v["tlsConfig"] = tls_config
        proxy_url = self.proxy_url()
        check_type("proxy_url", proxy_url, Optional[str])
        if proxy_url:  # omit empty
            v["proxyUrl"] = proxy_url
        return v

    def url(self) -> str:
        """
        The URL of the endpoint to send samples to.
        """
        return self.__url

    def required_matchers(self) -> Optional[Dict[str, str]]:
        """
        An optional list of equality matchers which have to be present
        in a selector to query the remote read endpoint.
        """
        return self.__required_matchers

    def remote_timeout(self) -> Optional[str]:
        """
        Timeout for requests to the remote read endpoint.
        """
        return self.__remote_timeout

    def read_recent(self) -> Optional[bool]:
        """
        Whether reads should be made for queries for time ranges that
        the local storage should have complete data for.
        """
        return self.__read_recent

    def basic_auth(self) -> Optional["BasicAuth"]:
        """
        BasicAuth for the URL.
        """
        return self.__basic_auth

    def bearer_token(self) -> Optional[str]:
        """
        bearer token for remote read.
        """
        return self.__bearer_token

    def bearer_token_file(self) -> Optional[str]:
        """
        File to read bearer token for remote read.
        """
        return self.__bearer_token_file

    def tls_config(self) -> Optional["TLSConfig"]:
        """
        TLS Config to use for remote read.
        """
        return self.__tls_config

    def proxy_url(self) -> Optional[str]:
        """
        Optional ProxyURL
        """
        return self.__proxy_url


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
        min_shards: int = None,
        max_shards: int = None,
        max_samples_per_send: int = None,
        batch_send_deadline: str = None,
        max_retries: int = None,
        min_backoff: str = None,
        max_backoff: str = None,
    ):
        super().__init__()
        self.__capacity = capacity
        self.__min_shards = min_shards
        self.__max_shards = max_shards
        self.__max_samples_per_send = max_samples_per_send
        self.__batch_send_deadline = batch_send_deadline
        self.__max_retries = max_retries
        self.__min_backoff = min_backoff
        self.__max_backoff = max_backoff

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        capacity = self.capacity()
        check_type("capacity", capacity, Optional[int])
        if capacity:  # omit empty
            v["capacity"] = capacity
        min_shards = self.min_shards()
        check_type("min_shards", min_shards, Optional[int])
        if min_shards:  # omit empty
            v["minShards"] = min_shards
        max_shards = self.max_shards()
        check_type("max_shards", max_shards, Optional[int])
        if max_shards:  # omit empty
            v["maxShards"] = max_shards
        max_samples_per_send = self.max_samples_per_send()
        check_type("max_samples_per_send", max_samples_per_send, Optional[int])
        if max_samples_per_send:  # omit empty
            v["maxSamplesPerSend"] = max_samples_per_send
        batch_send_deadline = self.batch_send_deadline()
        check_type("batch_send_deadline", batch_send_deadline, Optional[str])
        if batch_send_deadline:  # omit empty
            v["batchSendDeadline"] = batch_send_deadline
        max_retries = self.max_retries()
        check_type("max_retries", max_retries, Optional[int])
        if max_retries:  # omit empty
            v["maxRetries"] = max_retries
        min_backoff = self.min_backoff()
        check_type("min_backoff", min_backoff, Optional[str])
        if min_backoff:  # omit empty
            v["minBackoff"] = min_backoff
        max_backoff = self.max_backoff()
        check_type("max_backoff", max_backoff, Optional[str])
        if max_backoff:  # omit empty
            v["maxBackoff"] = max_backoff
        return v

    def capacity(self) -> Optional[int]:
        """
        Capacity is the number of samples to buffer per shard before we start dropping them.
        """
        return self.__capacity

    def min_shards(self) -> Optional[int]:
        """
        MinShards is the minimum number of shards, i.e. amount of concurrency.
        """
        return self.__min_shards

    def max_shards(self) -> Optional[int]:
        """
        MaxShards is the maximum number of shards, i.e. amount of concurrency.
        """
        return self.__max_shards

    def max_samples_per_send(self) -> Optional[int]:
        """
        MaxSamplesPerSend is the maximum number of samples per send.
        """
        return self.__max_samples_per_send

    def batch_send_deadline(self) -> Optional[str]:
        """
        BatchSendDeadline is the maximum time a sample will wait in buffer.
        """
        return self.__batch_send_deadline

    def max_retries(self) -> Optional[int]:
        """
        MaxRetries is the maximum number of times to retry a batch on recoverable errors.
        """
        return self.__max_retries

    def min_backoff(self) -> Optional[str]:
        """
        MinBackoff is the initial retry delay. Gets doubled for every retry.
        """
        return self.__min_backoff

    def max_backoff(self) -> Optional[str]:
        """
        MaxBackoff is the maximum retry delay.
        """
        return self.__max_backoff


class RemoteWriteSpec(types.Object):
    """
    RemoteWriteSpec defines the remote_write configuration for prometheus.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = "",
        remote_timeout: str = None,
        write_relabel_configs: List["RelabelConfig"] = None,
        basic_auth: "BasicAuth" = None,
        bearer_token: str = None,
        bearer_token_file: str = None,
        tls_config: "TLSConfig" = None,
        proxy_url: str = None,
        queue_config: "QueueConfig" = None,
    ):
        super().__init__()
        self.__url = url
        self.__remote_timeout = remote_timeout
        self.__write_relabel_configs = (
            write_relabel_configs if write_relabel_configs is not None else []
        )
        self.__basic_auth = basic_auth
        self.__bearer_token = bearer_token
        self.__bearer_token_file = bearer_token_file
        self.__tls_config = tls_config
        self.__proxy_url = proxy_url
        self.__queue_config = queue_config

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, str)
        v["url"] = url
        remote_timeout = self.remote_timeout()
        check_type("remote_timeout", remote_timeout, Optional[str])
        if remote_timeout:  # omit empty
            v["remoteTimeout"] = remote_timeout
        write_relabel_configs = self.write_relabel_configs()
        check_type(
            "write_relabel_configs",
            write_relabel_configs,
            Optional[List["RelabelConfig"]],
        )
        if write_relabel_configs:  # omit empty
            v["writeRelabelConfigs"] = write_relabel_configs
        basic_auth = self.basic_auth()
        check_type("basic_auth", basic_auth, Optional["BasicAuth"])
        if basic_auth is not None:  # omit empty
            v["basicAuth"] = basic_auth
        bearer_token = self.bearer_token()
        check_type("bearer_token", bearer_token, Optional[str])
        if bearer_token:  # omit empty
            v["bearerToken"] = bearer_token
        bearer_token_file = self.bearer_token_file()
        check_type("bearer_token_file", bearer_token_file, Optional[str])
        if bearer_token_file:  # omit empty
            v["bearerTokenFile"] = bearer_token_file
        tls_config = self.tls_config()
        check_type("tls_config", tls_config, Optional["TLSConfig"])
        if tls_config is not None:  # omit empty
            v["tlsConfig"] = tls_config
        proxy_url = self.proxy_url()
        check_type("proxy_url", proxy_url, Optional[str])
        if proxy_url:  # omit empty
            v["proxyUrl"] = proxy_url
        queue_config = self.queue_config()
        check_type("queue_config", queue_config, Optional["QueueConfig"])
        if queue_config is not None:  # omit empty
            v["queueConfig"] = queue_config
        return v

    def url(self) -> str:
        """
        The URL of the endpoint to send samples to.
        """
        return self.__url

    def remote_timeout(self) -> Optional[str]:
        """
        Timeout for requests to the remote write endpoint.
        """
        return self.__remote_timeout

    def write_relabel_configs(self) -> Optional[List["RelabelConfig"]]:
        """
        The list of remote write relabel configurations.
        """
        return self.__write_relabel_configs

    def basic_auth(self) -> Optional["BasicAuth"]:
        """
        BasicAuth for the URL.
        """
        return self.__basic_auth

    def bearer_token(self) -> Optional[str]:
        """
        File to read bearer token for remote write.
        """
        return self.__bearer_token

    def bearer_token_file(self) -> Optional[str]:
        """
        File to read bearer token for remote write.
        """
        return self.__bearer_token_file

    def tls_config(self) -> Optional["TLSConfig"]:
        """
        TLS Config to use for remote write.
        """
        return self.__tls_config

    def proxy_url(self) -> Optional[str]:
        """
        Optional ProxyURL
        """
        return self.__proxy_url

    def queue_config(self) -> Optional["QueueConfig"]:
        """
        QueueConfig allows tuning of the remote write queue parameters.
        """
        return self.__queue_config


class RulesAlert(types.Object):
    """
    /--rules.alert.*/ command-line arguments
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        for_outage_tolerance: str = None,
        for_grace_period: str = None,
        resend_delay: str = None,
    ):
        super().__init__()
        self.__for_outage_tolerance = for_outage_tolerance
        self.__for_grace_period = for_grace_period
        self.__resend_delay = resend_delay

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        for_outage_tolerance = self.for_outage_tolerance()
        check_type("for_outage_tolerance", for_outage_tolerance, Optional[str])
        if for_outage_tolerance:  # omit empty
            v["forOutageTolerance"] = for_outage_tolerance
        for_grace_period = self.for_grace_period()
        check_type("for_grace_period", for_grace_period, Optional[str])
        if for_grace_period:  # omit empty
            v["forGracePeriod"] = for_grace_period
        resend_delay = self.resend_delay()
        check_type("resend_delay", resend_delay, Optional[str])
        if resend_delay:  # omit empty
            v["resendDelay"] = resend_delay
        return v

    def for_outage_tolerance(self) -> Optional[str]:
        """
        Max time to tolerate prometheus outage for restoring 'for' state of alert.
        """
        return self.__for_outage_tolerance

    def for_grace_period(self) -> Optional[str]:
        """
        Minimum duration between alert and restored 'for' state.
        This is maintained only for alerts with configured 'for' time greater than grace period.
        """
        return self.__for_grace_period

    def resend_delay(self) -> Optional[str]:
        """
        Minimum amount of time to wait before resending an alert to Alertmanager.
        """
        return self.__resend_delay


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
        base_image: str = None,
        resources: "k8sv1.ResourceRequirements" = None,
        object_storage_config: "k8sv1.SecretKeySelector" = None,
        listen_local: bool = None,
    ):
        super().__init__()
        self.__image = image
        self.__version = version
        self.__tag = tag
        self.__sha = sha
        self.__base_image = base_image
        self.__resources = (
            resources if resources is not None else k8sv1.ResourceRequirements()
        )
        self.__object_storage_config = object_storage_config
        self.__listen_local = listen_local

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
        base_image = self.base_image()
        check_type("base_image", base_image, Optional[str])
        if base_image is not None:  # omit empty
            v["baseImage"] = base_image
        resources = self.resources()
        check_type("resources", resources, Optional["k8sv1.ResourceRequirements"])
        v["resources"] = resources
        object_storage_config = self.object_storage_config()
        check_type(
            "object_storage_config",
            object_storage_config,
            Optional["k8sv1.SecretKeySelector"],
        )
        if object_storage_config is not None:  # omit empty
            v["objectStorageConfig"] = object_storage_config
        listen_local = self.listen_local()
        check_type("listen_local", listen_local, Optional[bool])
        if listen_local:  # omit empty
            v["listenLocal"] = listen_local
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

    def base_image(self) -> Optional[str]:
        """
        Thanos base image if other than default.
        """
        return self.__base_image

    def resources(self) -> Optional["k8sv1.ResourceRequirements"]:
        """
        Resources defines the resource requirements for the Thanos sidecar.
        If not provided, no requests/limits will be set
        """
        return self.__resources

    def object_storage_config(self) -> Optional["k8sv1.SecretKeySelector"]:
        """
        ObjectStorageConfig configures object storage in Thanos.
        """
        return self.__object_storage_config

    def listen_local(self) -> Optional[bool]:
        """
        ListenLocal makes the Thanos sidecar listen on loopback, so that it
        does not bind against the Pod IP.
        """
        return self.__listen_local


class PrometheusSpec(types.Object):
    """
    PrometheusSpec is a specification of the desired behavior of the Prometheus cluster. More info:
    https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        pod_metadata: "metav1.ObjectMeta" = None,
        service_monitor_selector: "metav1.LabelSelector" = None,
        service_monitor_namespace_selector: "metav1.LabelSelector" = None,
        pod_monitor_selector: "metav1.LabelSelector" = None,
        pod_monitor_namespace_selector: "metav1.LabelSelector" = None,
        version: str = None,
        tag: str = None,
        sha: str = None,
        paused: bool = None,
        image: str = None,
        base_image: str = None,
        image_pull_secrets: List["k8sv1.LocalObjectReference"] = None,
        replicas: int = None,
        replica_external_label_name: str = None,
        prometheus_external_label_name: str = None,
        retention: str = None,
        retention_size: str = None,
        wal_compression: bool = None,
        log_level: str = None,
        log_format: str = None,
        scrape_interval: str = None,
        evaluation_interval: str = None,
        rules: "Rules" = None,
        external_labels: Dict[str, str] = None,
        enable_admin_api: bool = None,
        external_url: str = None,
        route_prefix: str = None,
        query: "QuerySpec" = None,
        storage: "StorageSpec" = None,
        volumes: List["k8sv1.Volume"] = None,
        rule_selector: "metav1.LabelSelector" = None,
        rule_namespace_selector: "metav1.LabelSelector" = None,
        alerting: "AlertingSpec" = None,
        resources: "k8sv1.ResourceRequirements" = None,
        node_selector: Dict[str, str] = None,
        service_account_name: str = None,
        secrets: List[str] = None,
        config_maps: List[str] = None,
        affinity: "k8sv1.Affinity" = None,
        tolerations: List["k8sv1.Toleration"] = None,
        remote_write: List["RemoteWriteSpec"] = None,
        remote_read: List["RemoteReadSpec"] = None,
        security_context: "k8sv1.PodSecurityContext" = None,
        listen_local: bool = None,
        containers: List["k8sv1.Container"] = None,
        init_containers: List["k8sv1.Container"] = None,
        additional_scrape_configs: "k8sv1.SecretKeySelector" = None,
        additional_alert_relabel_configs: "k8sv1.SecretKeySelector" = None,
        additional_alert_manager_configs: "k8sv1.SecretKeySelector" = None,
        apiserver_config: "APIServerConfig" = None,
        thanos: "ThanosSpec" = None,
        priority_class_name: str = None,
        port_name: str = None,
        arbitrary_fs_access_through_sms: "ArbitraryFSAccessThroughSMsConfig" = None,
        override_honor_labels: bool = None,
        override_honor_timestamps: bool = None,
        ignore_namespace_selectors: bool = None,
        enforced_namespace_label: str = None,
    ):
        super().__init__()
        self.__pod_metadata = pod_metadata
        self.__service_monitor_selector = service_monitor_selector
        self.__service_monitor_namespace_selector = service_monitor_namespace_selector
        self.__pod_monitor_selector = pod_monitor_selector
        self.__pod_monitor_namespace_selector = pod_monitor_namespace_selector
        self.__version = version
        self.__tag = tag
        self.__sha = sha
        self.__paused = paused
        self.__image = image
        self.__base_image = base_image
        self.__image_pull_secrets = (
            image_pull_secrets if image_pull_secrets is not None else []
        )
        self.__replicas = replicas
        self.__replica_external_label_name = replica_external_label_name
        self.__prometheus_external_label_name = prometheus_external_label_name
        self.__retention = retention
        self.__retention_size = retention_size
        self.__wal_compression = wal_compression
        self.__log_level = log_level
        self.__log_format = log_format
        self.__scrape_interval = scrape_interval
        self.__evaluation_interval = evaluation_interval
        self.__rules = rules if rules is not None else Rules()
        self.__external_labels = external_labels if external_labels is not None else {}
        self.__enable_admin_api = enable_admin_api
        self.__external_url = external_url
        self.__route_prefix = route_prefix
        self.__query = query
        self.__storage = storage
        self.__volumes = volumes if volumes is not None else []
        self.__rule_selector = rule_selector
        self.__rule_namespace_selector = rule_namespace_selector
        self.__alerting = alerting
        self.__resources = (
            resources if resources is not None else k8sv1.ResourceRequirements()
        )
        self.__node_selector = node_selector if node_selector is not None else {}
        self.__service_account_name = service_account_name
        self.__secrets = secrets if secrets is not None else []
        self.__config_maps = config_maps if config_maps is not None else []
        self.__affinity = affinity
        self.__tolerations = tolerations if tolerations is not None else []
        self.__remote_write = remote_write if remote_write is not None else []
        self.__remote_read = remote_read if remote_read is not None else []
        self.__security_context = security_context
        self.__listen_local = listen_local
        self.__containers = containers if containers is not None else []
        self.__init_containers = init_containers if init_containers is not None else []
        self.__additional_scrape_configs = additional_scrape_configs
        self.__additional_alert_relabel_configs = additional_alert_relabel_configs
        self.__additional_alert_manager_configs = additional_alert_manager_configs
        self.__apiserver_config = apiserver_config
        self.__thanos = thanos
        self.__priority_class_name = priority_class_name
        self.__port_name = port_name
        self.__arbitrary_fs_access_through_sms = (
            arbitrary_fs_access_through_sms
            if arbitrary_fs_access_through_sms is not None
            else ArbitraryFSAccessThroughSMsConfig()
        )
        self.__override_honor_labels = override_honor_labels
        self.__override_honor_timestamps = override_honor_timestamps
        self.__ignore_namespace_selectors = ignore_namespace_selectors
        self.__enforced_namespace_label = enforced_namespace_label

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        pod_metadata = self.pod_metadata()
        check_type("pod_metadata", pod_metadata, Optional["metav1.ObjectMeta"])
        if pod_metadata is not None:  # omit empty
            v["podMetadata"] = pod_metadata
        service_monitor_selector = self.service_monitor_selector()
        check_type(
            "service_monitor_selector",
            service_monitor_selector,
            Optional["metav1.LabelSelector"],
        )
        if service_monitor_selector is not None:  # omit empty
            v["serviceMonitorSelector"] = service_monitor_selector
        service_monitor_namespace_selector = self.service_monitor_namespace_selector()
        check_type(
            "service_monitor_namespace_selector",
            service_monitor_namespace_selector,
            Optional["metav1.LabelSelector"],
        )
        if service_monitor_namespace_selector is not None:  # omit empty
            v["serviceMonitorNamespaceSelector"] = service_monitor_namespace_selector
        pod_monitor_selector = self.pod_monitor_selector()
        check_type(
            "pod_monitor_selector",
            pod_monitor_selector,
            Optional["metav1.LabelSelector"],
        )
        if pod_monitor_selector is not None:  # omit empty
            v["podMonitorSelector"] = pod_monitor_selector
        pod_monitor_namespace_selector = self.pod_monitor_namespace_selector()
        check_type(
            "pod_monitor_namespace_selector",
            pod_monitor_namespace_selector,
            Optional["metav1.LabelSelector"],
        )
        if pod_monitor_namespace_selector is not None:  # omit empty
            v["podMonitorNamespaceSelector"] = pod_monitor_namespace_selector
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
        base_image = self.base_image()
        check_type("base_image", base_image, Optional[str])
        if base_image:  # omit empty
            v["baseImage"] = base_image
        image_pull_secrets = self.image_pull_secrets()
        check_type(
            "image_pull_secrets",
            image_pull_secrets,
            Optional[List["k8sv1.LocalObjectReference"]],
        )
        if image_pull_secrets:  # omit empty
            v["imagePullSecrets"] = image_pull_secrets
        replicas = self.replicas()
        check_type("replicas", replicas, Optional[int])
        if replicas is not None:  # omit empty
            v["replicas"] = replicas
        replica_external_label_name = self.replica_external_label_name()
        check_type(
            "replica_external_label_name", replica_external_label_name, Optional[str]
        )
        if replica_external_label_name is not None:  # omit empty
            v["replicaExternalLabelName"] = replica_external_label_name
        prometheus_external_label_name = self.prometheus_external_label_name()
        check_type(
            "prometheus_external_label_name",
            prometheus_external_label_name,
            Optional[str],
        )
        if prometheus_external_label_name is not None:  # omit empty
            v["prometheusExternalLabelName"] = prometheus_external_label_name
        retention = self.retention()
        check_type("retention", retention, Optional[str])
        if retention:  # omit empty
            v["retention"] = retention
        retention_size = self.retention_size()
        check_type("retention_size", retention_size, Optional[str])
        if retention_size:  # omit empty
            v["retentionSize"] = retention_size
        wal_compression = self.wal_compression()
        check_type("wal_compression", wal_compression, Optional[bool])
        if wal_compression is not None:  # omit empty
            v["walCompression"] = wal_compression
        log_level = self.log_level()
        check_type("log_level", log_level, Optional[str])
        if log_level:  # omit empty
            v["logLevel"] = log_level
        log_format = self.log_format()
        check_type("log_format", log_format, Optional[str])
        if log_format:  # omit empty
            v["logFormat"] = log_format
        scrape_interval = self.scrape_interval()
        check_type("scrape_interval", scrape_interval, Optional[str])
        if scrape_interval:  # omit empty
            v["scrapeInterval"] = scrape_interval
        evaluation_interval = self.evaluation_interval()
        check_type("evaluation_interval", evaluation_interval, Optional[str])
        if evaluation_interval:  # omit empty
            v["evaluationInterval"] = evaluation_interval
        rules = self.rules()
        check_type("rules", rules, Optional["Rules"])
        v["rules"] = rules
        external_labels = self.external_labels()
        check_type("external_labels", external_labels, Optional[Dict[str, str]])
        if external_labels:  # omit empty
            v["externalLabels"] = external_labels
        enable_admin_api = self.enable_admin_api()
        check_type("enable_admin_api", enable_admin_api, Optional[bool])
        if enable_admin_api:  # omit empty
            v["enableAdminAPI"] = enable_admin_api
        external_url = self.external_url()
        check_type("external_url", external_url, Optional[str])
        if external_url:  # omit empty
            v["externalUrl"] = external_url
        route_prefix = self.route_prefix()
        check_type("route_prefix", route_prefix, Optional[str])
        if route_prefix:  # omit empty
            v["routePrefix"] = route_prefix
        query = self.query()
        check_type("query", query, Optional["QuerySpec"])
        if query is not None:  # omit empty
            v["query"] = query
        storage = self.storage()
        check_type("storage", storage, Optional["StorageSpec"])
        if storage is not None:  # omit empty
            v["storage"] = storage
        volumes = self.volumes()
        check_type("volumes", volumes, Optional[List["k8sv1.Volume"]])
        if volumes:  # omit empty
            v["volumes"] = volumes
        rule_selector = self.rule_selector()
        check_type("rule_selector", rule_selector, Optional["metav1.LabelSelector"])
        if rule_selector is not None:  # omit empty
            v["ruleSelector"] = rule_selector
        rule_namespace_selector = self.rule_namespace_selector()
        check_type(
            "rule_namespace_selector",
            rule_namespace_selector,
            Optional["metav1.LabelSelector"],
        )
        if rule_namespace_selector is not None:  # omit empty
            v["ruleNamespaceSelector"] = rule_namespace_selector
        alerting = self.alerting()
        check_type("alerting", alerting, Optional["AlertingSpec"])
        if alerting is not None:  # omit empty
            v["alerting"] = alerting
        resources = self.resources()
        check_type("resources", resources, Optional["k8sv1.ResourceRequirements"])
        v["resources"] = resources
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional[Dict[str, str]])
        if node_selector:  # omit empty
            v["nodeSelector"] = node_selector
        service_account_name = self.service_account_name()
        check_type("service_account_name", service_account_name, Optional[str])
        if service_account_name:  # omit empty
            v["serviceAccountName"] = service_account_name
        secrets = self.secrets()
        check_type("secrets", secrets, Optional[List[str]])
        if secrets:  # omit empty
            v["secrets"] = secrets
        config_maps = self.config_maps()
        check_type("config_maps", config_maps, Optional[List[str]])
        if config_maps:  # omit empty
            v["configMaps"] = config_maps
        affinity = self.affinity()
        check_type("affinity", affinity, Optional["k8sv1.Affinity"])
        if affinity is not None:  # omit empty
            v["affinity"] = affinity
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        remote_write = self.remote_write()
        check_type("remote_write", remote_write, Optional[List["RemoteWriteSpec"]])
        if remote_write:  # omit empty
            v["remoteWrite"] = remote_write
        remote_read = self.remote_read()
        check_type("remote_read", remote_read, Optional[List["RemoteReadSpec"]])
        if remote_read:  # omit empty
            v["remoteRead"] = remote_read
        security_context = self.security_context()
        check_type(
            "security_context", security_context, Optional["k8sv1.PodSecurityContext"]
        )
        if security_context is not None:  # omit empty
            v["securityContext"] = security_context
        listen_local = self.listen_local()
        check_type("listen_local", listen_local, Optional[bool])
        if listen_local:  # omit empty
            v["listenLocal"] = listen_local
        containers = self.containers()
        check_type("containers", containers, Optional[List["k8sv1.Container"]])
        if containers:  # omit empty
            v["containers"] = containers
        init_containers = self.init_containers()
        check_type(
            "init_containers", init_containers, Optional[List["k8sv1.Container"]]
        )
        if init_containers:  # omit empty
            v["initContainers"] = init_containers
        additional_scrape_configs = self.additional_scrape_configs()
        check_type(
            "additional_scrape_configs",
            additional_scrape_configs,
            Optional["k8sv1.SecretKeySelector"],
        )
        if additional_scrape_configs is not None:  # omit empty
            v["additionalScrapeConfigs"] = additional_scrape_configs
        additional_alert_relabel_configs = self.additional_alert_relabel_configs()
        check_type(
            "additional_alert_relabel_configs",
            additional_alert_relabel_configs,
            Optional["k8sv1.SecretKeySelector"],
        )
        if additional_alert_relabel_configs is not None:  # omit empty
            v["additionalAlertRelabelConfigs"] = additional_alert_relabel_configs
        additional_alert_manager_configs = self.additional_alert_manager_configs()
        check_type(
            "additional_alert_manager_configs",
            additional_alert_manager_configs,
            Optional["k8sv1.SecretKeySelector"],
        )
        if additional_alert_manager_configs is not None:  # omit empty
            v["additionalAlertManagerConfigs"] = additional_alert_manager_configs
        apiserver_config = self.apiserver_config()
        check_type("apiserver_config", apiserver_config, Optional["APIServerConfig"])
        if apiserver_config is not None:  # omit empty
            v["apiserverConfig"] = apiserver_config
        thanos = self.thanos()
        check_type("thanos", thanos, Optional["ThanosSpec"])
        if thanos is not None:  # omit empty
            v["thanos"] = thanos
        priority_class_name = self.priority_class_name()
        check_type("priority_class_name", priority_class_name, Optional[str])
        if priority_class_name:  # omit empty
            v["priorityClassName"] = priority_class_name
        port_name = self.port_name()
        check_type("port_name", port_name, Optional[str])
        if port_name:  # omit empty
            v["portName"] = port_name
        arbitrary_fs_access_through_sms = self.arbitrary_fs_access_through_sms()
        check_type(
            "arbitrary_fs_access_through_sms",
            arbitrary_fs_access_through_sms,
            Optional["ArbitraryFSAccessThroughSMsConfig"],
        )
        v["arbitraryFSAccessThroughSMs"] = arbitrary_fs_access_through_sms
        override_honor_labels = self.override_honor_labels()
        check_type("override_honor_labels", override_honor_labels, Optional[bool])
        if override_honor_labels:  # omit empty
            v["overrideHonorLabels"] = override_honor_labels
        override_honor_timestamps = self.override_honor_timestamps()
        check_type(
            "override_honor_timestamps", override_honor_timestamps, Optional[bool]
        )
        if override_honor_timestamps:  # omit empty
            v["overrideHonorTimestamps"] = override_honor_timestamps
        ignore_namespace_selectors = self.ignore_namespace_selectors()
        check_type(
            "ignore_namespace_selectors", ignore_namespace_selectors, Optional[bool]
        )
        if ignore_namespace_selectors:  # omit empty
            v["ignoreNamespaceSelectors"] = ignore_namespace_selectors
        enforced_namespace_label = self.enforced_namespace_label()
        check_type("enforced_namespace_label", enforced_namespace_label, Optional[str])
        if enforced_namespace_label:  # omit empty
            v["enforcedNamespaceLabel"] = enforced_namespace_label
        return v

    def pod_metadata(self) -> Optional["metav1.ObjectMeta"]:
        """
        Standard object’s metadata. More info:
        https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
        Metadata Labels and Annotations gets propagated to the prometheus pods.
        """
        return self.__pod_metadata

    def service_monitor_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        ServiceMonitors to be selected for target discovery.
        """
        return self.__service_monitor_selector

    def service_monitor_namespace_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        Namespaces to be selected for ServiceMonitor discovery. If nil, only
        check own namespace.
        """
        return self.__service_monitor_namespace_selector

    def pod_monitor_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        *Experimental* PodMonitors to be selected for target discovery.
        """
        return self.__pod_monitor_selector

    def pod_monitor_namespace_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        Namespaces to be selected for PodMonitor discovery. If nil, only
        check own namespace.
        """
        return self.__pod_monitor_namespace_selector

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

    def base_image(self) -> Optional[str]:
        """
        Base image to use for a Prometheus deployment.
        """
        return self.__base_image

    def image_pull_secrets(self) -> Optional[List["k8sv1.LocalObjectReference"]]:
        """
        An optional list of references to secrets in the same namespace
        to use for pulling prometheus and alertmanager images from registries
        see http://kubernetes.io/docs/user-guide/images#specifying-imagepullsecrets-on-a-pod
        """
        return self.__image_pull_secrets

    def replicas(self) -> Optional[int]:
        """
        Number of instances to deploy for a Prometheus deployment.
        """
        return self.__replicas

    def replica_external_label_name(self) -> Optional[str]:
        """
        Name of Prometheus external label used to denote replica name.
        Defaults to the value of `prometheus_replica`. External label will
        _not_ be added when value is set to empty string (`""`).
        """
        return self.__replica_external_label_name

    def prometheus_external_label_name(self) -> Optional[str]:
        """
        Name of Prometheus external label used to denote Prometheus instance
        name. Defaults to the value of `prometheus`. External label will
        _not_ be added when value is set to empty string (`""`).
        """
        return self.__prometheus_external_label_name

    def retention(self) -> Optional[str]:
        """
        Time duration Prometheus shall retain data for. Default is '24h',
        and must match the regular expression `[0-9]+(ms|s|m|h|d|w|y)` (milliseconds seconds minutes hours days weeks years).
        """
        return self.__retention

    def retention_size(self) -> Optional[str]:
        """
        Maximum amount of disk space used by blocks.
        """
        return self.__retention_size

    def wal_compression(self) -> Optional[bool]:
        """
        Enable compression of the write-ahead log using Snappy. This flag is
        only available in versions of Prometheus >= 2.11.0.
        """
        return self.__wal_compression

    def log_level(self) -> Optional[str]:
        """
        Log level for Prometheus to be configured with.
        """
        return self.__log_level

    def log_format(self) -> Optional[str]:
        """
        Log format for Prometheus to be configured with.
        """
        return self.__log_format

    def scrape_interval(self) -> Optional[str]:
        """
        Interval between consecutive scrapes.
        """
        return self.__scrape_interval

    def evaluation_interval(self) -> Optional[str]:
        """
        Interval between consecutive evaluations.
        """
        return self.__evaluation_interval

    def rules(self) -> Optional["Rules"]:
        """
        /--rules.*/ command-line arguments.
        """
        return self.__rules

    def external_labels(self) -> Optional[Dict[str, str]]:
        """
        The labels to add to any time series or alerts when communicating with
        external systems (federation, remote storage, Alertmanager).
        """
        return self.__external_labels

    def enable_admin_api(self) -> Optional[bool]:
        """
        Enable access to prometheus web admin API. Defaults to the value of `false`.
        WARNING: Enabling the admin APIs enables mutating endpoints, to delete data,
        shutdown Prometheus, and more. Enabling this should be done with care and the
        user is advised to add additional authentication authorization via a proxy to
        ensure only clients authorized to perform these actions can do so.
        For more information see https://prometheus.io/docs/prometheus/latest/querying/api/#tsdb-admin-apis
        """
        return self.__enable_admin_api

    def external_url(self) -> Optional[str]:
        """
        The external URL the Prometheus instances will be available under. This is
        necessary to generate correct URLs. This is necessary if Prometheus is not
        served from root of a DNS name.
        """
        return self.__external_url

    def route_prefix(self) -> Optional[str]:
        """
        The route prefix Prometheus registers HTTP handlers for. This is useful,
        if using ExternalURL and a proxy is rewriting HTTP routes of a request,
        and the actual ExternalURL is still true, but the server serves requests
        under a different route prefix. For example for use with `kubectl proxy`.
        """
        return self.__route_prefix

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

    def volumes(self) -> Optional[List["k8sv1.Volume"]]:
        """
        Volumes allows configuration of additional volumes on the output StatefulSet definition. Volumes specified will
        be appended to other volumes that are generated as a result of StorageSpec objects.
        """
        return self.__volumes

    def rule_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        A selector to select which PrometheusRules to mount for loading alerting
        rules from. Until (excluding) Prometheus Operator v0.24.0 Prometheus
        Operator will migrate any legacy rule ConfigMaps to PrometheusRule custom
        resources selected by RuleSelector. Make sure it does not match any config
        maps that you do not want to be migrated.
        """
        return self.__rule_selector

    def rule_namespace_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        Namespaces to be selected for PrometheusRules discovery. If unspecified, only
        the same namespace as the Prometheus object is in is used.
        """
        return self.__rule_namespace_selector

    def alerting(self) -> Optional["AlertingSpec"]:
        """
        Define details regarding alerting.
        """
        return self.__alerting

    def resources(self) -> Optional["k8sv1.ResourceRequirements"]:
        """
        Define resources requests and limits for single Pods.
        """
        return self.__resources

    def node_selector(self) -> Optional[Dict[str, str]]:
        """
        Define which Nodes the Pods are scheduled on.
        """
        return self.__node_selector

    def service_account_name(self) -> Optional[str]:
        """
        ServiceAccountName is the name of the ServiceAccount to use to run the
        Prometheus Pods.
        """
        return self.__service_account_name

    def secrets(self) -> Optional[List[str]]:
        """
        Secrets is a list of Secrets in the same namespace as the Prometheus
        object, which shall be mounted into the Prometheus Pods.
        The Secrets are mounted into /etc/prometheus/secrets/<secret-name>.
        """
        return self.__secrets

    def config_maps(self) -> Optional[List[str]]:
        """
        ConfigMaps is a list of ConfigMaps in the same namespace as the Prometheus
        object, which shall be mounted into the Prometheus Pods.
        The ConfigMaps are mounted into /etc/prometheus/configmaps/<configmap-name>.
        """
        return self.__config_maps

    def affinity(self) -> Optional["k8sv1.Affinity"]:
        """
        If specified, the pod's scheduling constraints.
        """
        return self.__affinity

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        If specified, the pod's tolerations.
        """
        return self.__tolerations

    def remote_write(self) -> Optional[List["RemoteWriteSpec"]]:
        """
        If specified, the remote_write spec. This is an experimental feature, it may change in any upcoming release in a breaking way.
        """
        return self.__remote_write

    def remote_read(self) -> Optional[List["RemoteReadSpec"]]:
        """
        If specified, the remote_read spec. This is an experimental feature, it may change in any upcoming release in a breaking way.
        """
        return self.__remote_read

    def security_context(self) -> Optional["k8sv1.PodSecurityContext"]:
        """
        SecurityContext holds pod-level security attributes and common container settings.
        This defaults to the default PodSecurityContext.
        """
        return self.__security_context

    def listen_local(self) -> Optional[bool]:
        """
        ListenLocal makes the Prometheus server listen on loopback, so that it
        does not bind against the Pod IP.
        """
        return self.__listen_local

    def containers(self) -> Optional[List["k8sv1.Container"]]:
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

    def init_containers(self) -> Optional[List["k8sv1.Container"]]:
        """
        InitContainers allows adding initContainers to the pod definition. Those can be used to e.g.
        fetch secrets for injection into the Prometheus configuration from external sources. Any errors
        during the execution of an initContainer will lead to a restart of the Pod. More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
        Using initContainers for any use case other then secret fetching is entirely outside the scope
        of what the maintainers will support and by doing so, you accept that this behaviour may break
        at any time without notice.
        """
        return self.__init_containers

    def additional_scrape_configs(self) -> Optional["k8sv1.SecretKeySelector"]:
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
        return self.__additional_scrape_configs

    def additional_alert_relabel_configs(self) -> Optional["k8sv1.SecretKeySelector"]:
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
        return self.__additional_alert_relabel_configs

    def additional_alert_manager_configs(self) -> Optional["k8sv1.SecretKeySelector"]:
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
        return self.__additional_alert_manager_configs

    def apiserver_config(self) -> Optional["APIServerConfig"]:
        """
        APIServerConfig allows specifying a host and auth methods to access apiserver.
        If left empty, Prometheus is assumed to run inside of the cluster
        and will discover API servers automatically and use the pod's CA certificate
        and bearer token file at /var/run/secrets/kubernetes.io/serviceaccount/.
        """
        return self.__apiserver_config

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

    def priority_class_name(self) -> Optional[str]:
        """
        Priority class assigned to the Pods
        """
        return self.__priority_class_name

    def port_name(self) -> Optional[str]:
        """
        Port name used for the pods and governing service.
        This defaults to web
        """
        return self.__port_name

    def arbitrary_fs_access_through_sms(
        self
    ) -> Optional["ArbitraryFSAccessThroughSMsConfig"]:
        """
        ArbitraryFSAccessThroughSMs configures whether configuration
        based on a service monitor can access arbitrary files on the file system
        of the Prometheus container e.g. bearer token files.
        """
        return self.__arbitrary_fs_access_through_sms

    def override_honor_labels(self) -> Optional[bool]:
        """
        OverrideHonorLabels if set to true overrides all user configured honor_labels.
        If HonorLabels is set in ServiceMonitor or PodMonitor to true, this overrides honor_labels to false.
        """
        return self.__override_honor_labels

    def override_honor_timestamps(self) -> Optional[bool]:
        """
        OverrideHonorTimestamps allows to globally enforce honoring timestamps in all scrape configs.
        """
        return self.__override_honor_timestamps

    def ignore_namespace_selectors(self) -> Optional[bool]:
        """
        IgnoreNamespaceSelectors if set to true will ignore NamespaceSelector settings from
        the podmonitor and servicemonitor configs, and they will only discover endpoints
        within their current namespace.  Defaults to false.
        """
        return self.__ignore_namespace_selectors

    def enforced_namespace_label(self) -> Optional[str]:
        """
        EnforcedNamespaceLabel enforces adding a namespace label of origin for each alert
        and metric that is user created. The label value will always be the namespace of the object that is
        being created.
        """
        return self.__enforced_namespace_label


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
            api_version="monitoring.coreos.com/v1",
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
            api_version="monitoring.coreos.com/v1",
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
        job_label: str = None,
        target_labels: List[str] = None,
        pod_target_labels: List[str] = None,
        endpoints: List["Endpoint"] = None,
        selector: "metav1.LabelSelector" = None,
        namespace_selector: "NamespaceSelector" = None,
        sample_limit: int = None,
    ):
        super().__init__()
        self.__job_label = job_label
        self.__target_labels = target_labels if target_labels is not None else []
        self.__pod_target_labels = (
            pod_target_labels if pod_target_labels is not None else []
        )
        self.__endpoints = endpoints if endpoints is not None else []
        self.__selector = selector if selector is not None else metav1.LabelSelector()
        self.__namespace_selector = (
            namespace_selector
            if namespace_selector is not None
            else NamespaceSelector()
        )
        self.__sample_limit = sample_limit

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        job_label = self.job_label()
        check_type("job_label", job_label, Optional[str])
        if job_label:  # omit empty
            v["jobLabel"] = job_label
        target_labels = self.target_labels()
        check_type("target_labels", target_labels, Optional[List[str]])
        if target_labels:  # omit empty
            v["targetLabels"] = target_labels
        pod_target_labels = self.pod_target_labels()
        check_type("pod_target_labels", pod_target_labels, Optional[List[str]])
        if pod_target_labels:  # omit empty
            v["podTargetLabels"] = pod_target_labels
        endpoints = self.endpoints()
        check_type("endpoints", endpoints, List["Endpoint"])
        v["endpoints"] = endpoints
        selector = self.selector()
        check_type("selector", selector, "metav1.LabelSelector")
        v["selector"] = selector
        namespace_selector = self.namespace_selector()
        check_type(
            "namespace_selector", namespace_selector, Optional["NamespaceSelector"]
        )
        v["namespaceSelector"] = namespace_selector
        sample_limit = self.sample_limit()
        check_type("sample_limit", sample_limit, Optional[int])
        if sample_limit:  # omit empty
            v["sampleLimit"] = sample_limit
        return v

    def job_label(self) -> Optional[str]:
        """
        The label to use to retrieve the job name from.
        """
        return self.__job_label

    def target_labels(self) -> Optional[List[str]]:
        """
        TargetLabels transfers labels on the Kubernetes Service onto the target.
        """
        return self.__target_labels

    def pod_target_labels(self) -> Optional[List[str]]:
        """
        PodTargetLabels transfers labels on the Kubernetes Pod onto the target.
        """
        return self.__pod_target_labels

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

    def namespace_selector(self) -> Optional["NamespaceSelector"]:
        """
        Selector to select which namespaces the Endpoints objects are discovered from.
        """
        return self.__namespace_selector

    def sample_limit(self) -> Optional[int]:
        """
        SampleLimit defines per-scrape limit on number of scraped samples that will be accepted.
        """
        return self.__sample_limit


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
            api_version="monitoring.coreos.com/v1",
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
