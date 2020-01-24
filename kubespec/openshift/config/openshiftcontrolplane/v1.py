# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.meta import v1 as metav1
from kubespec.openshift.build import v1 as buildv1
from kubespec.openshift.config import v1 as configv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


GrantHandlerType = base.Enum(
    "GrantHandlerType",
    {
        # Auto auto-approves client authorization grant requests
        "Auto": "auto",
        # Deny auto-denies client authorization grant requests
        "Deny": "deny",
        # Prompt prompts the user to approve new client authorization grant requests
        "Prompt": "prompt",
    },
)


class SourceStrategyDefaultsConfig(types.Object):
    """
    SourceStrategyDefaultsConfig contains values that apply to builds using the
    source strategy.
    """

    @context.scoped
    @typechecked
    def __init__(self, incremental: bool = None):
        super().__init__()
        self.__incremental = incremental

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        incremental = self.incremental()
        check_type("incremental", incremental, Optional[bool])
        if incremental is not None:  # omit empty
            v["incremental"] = incremental
        return v

    def incremental(self) -> Optional[bool]:
        """
        incremental indicates if s2i build strategies should perform an incremental
        build or not
        """
        return self.__incremental


class BuildDefaultsConfig(base.TypedObject):
    """
    BuildDefaultsConfig controls the default information for Builds
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        git_http_proxy: str = None,
        git_https_proxy: str = None,
        git_no_proxy: str = None,
        env: List["k8sv1.EnvVar"] = None,
        source_strategy_defaults: "SourceStrategyDefaultsConfig" = None,
        image_labels: List["buildv1.ImageLabel"] = None,
        node_selector: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        resources: "k8sv1.ResourceRequirements" = None,
    ):
        super().__init__(
            api_version="openshiftcontrolplane.config.openshift.io/v1",
            kind="BuildDefaultsConfig",
        )
        self.__git_http_proxy = git_http_proxy
        self.__git_https_proxy = git_https_proxy
        self.__git_no_proxy = git_no_proxy
        self.__env = env if env is not None else []
        self.__source_strategy_defaults = source_strategy_defaults
        self.__image_labels = image_labels if image_labels is not None else []
        self.__node_selector = node_selector if node_selector is not None else {}
        self.__annotations = annotations if annotations is not None else {}
        self.__resources = (
            resources if resources is not None else k8sv1.ResourceRequirements()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        git_http_proxy = self.git_http_proxy()
        check_type("git_http_proxy", git_http_proxy, Optional[str])
        if git_http_proxy:  # omit empty
            v["gitHTTPProxy"] = git_http_proxy
        git_https_proxy = self.git_https_proxy()
        check_type("git_https_proxy", git_https_proxy, Optional[str])
        if git_https_proxy:  # omit empty
            v["gitHTTPSProxy"] = git_https_proxy
        git_no_proxy = self.git_no_proxy()
        check_type("git_no_proxy", git_no_proxy, Optional[str])
        if git_no_proxy:  # omit empty
            v["gitNoProxy"] = git_no_proxy
        env = self.env()
        check_type("env", env, Optional[List["k8sv1.EnvVar"]])
        if env:  # omit empty
            v["env"] = env
        source_strategy_defaults = self.source_strategy_defaults()
        check_type(
            "source_strategy_defaults",
            source_strategy_defaults,
            Optional["SourceStrategyDefaultsConfig"],
        )
        if source_strategy_defaults is not None:  # omit empty
            v["sourceStrategyDefaults"] = source_strategy_defaults
        image_labels = self.image_labels()
        check_type("image_labels", image_labels, Optional[List["buildv1.ImageLabel"]])
        if image_labels:  # omit empty
            v["imageLabels"] = image_labels
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional[Dict[str, str]])
        if node_selector:  # omit empty
            v["nodeSelector"] = node_selector
        annotations = self.annotations()
        check_type("annotations", annotations, Optional[Dict[str, str]])
        if annotations:  # omit empty
            v["annotations"] = annotations
        resources = self.resources()
        check_type("resources", resources, Optional["k8sv1.ResourceRequirements"])
        v["resources"] = resources
        return v

    def git_http_proxy(self) -> Optional[str]:
        """
        gitHTTPProxy is the location of the HTTPProxy for Git source
        """
        return self.__git_http_proxy

    def git_https_proxy(self) -> Optional[str]:
        """
        gitHTTPSProxy is the location of the HTTPSProxy for Git source
        """
        return self.__git_https_proxy

    def git_no_proxy(self) -> Optional[str]:
        """
        gitNoProxy is the list of domains for which the proxy should not be used
        """
        return self.__git_no_proxy

    def env(self) -> Optional[List["k8sv1.EnvVar"]]:
        """
        env is a set of default environment variables that will be applied to the
        build if the specified variables do not exist on the build
        """
        return self.__env

    def source_strategy_defaults(self) -> Optional["SourceStrategyDefaultsConfig"]:
        """
        sourceStrategyDefaults are default values that apply to builds using the
        source strategy.
        """
        return self.__source_strategy_defaults

    def image_labels(self) -> Optional[List["buildv1.ImageLabel"]]:
        """
        imageLabels is a list of labels that are applied to the resulting image.
        User can override a default label by providing a label with the same name in their
        Build/BuildConfig.
        """
        return self.__image_labels

    def node_selector(self) -> Optional[Dict[str, str]]:
        """
        nodeSelector is a selector which must be true for the build pod to fit on a node
        """
        return self.__node_selector

    def annotations(self) -> Optional[Dict[str, str]]:
        """
        annotations are annotations that will be added to the build pod
        """
        return self.__annotations

    def resources(self) -> Optional["k8sv1.ResourceRequirements"]:
        """
        resources defines resource requirements to execute the build.
        """
        return self.__resources


class BuildOverridesConfig(base.TypedObject):
    """
    BuildOverridesConfig controls override settings for builds
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        force_pull: bool = False,
        image_labels: List["buildv1.ImageLabel"] = None,
        node_selector: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        tolerations: List["k8sv1.Toleration"] = None,
    ):
        super().__init__(
            api_version="openshiftcontrolplane.config.openshift.io/v1",
            kind="BuildOverridesConfig",
        )
        self.__force_pull = force_pull
        self.__image_labels = image_labels if image_labels is not None else []
        self.__node_selector = node_selector if node_selector is not None else {}
        self.__annotations = annotations if annotations is not None else {}
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        force_pull = self.force_pull()
        check_type("force_pull", force_pull, bool)
        v["forcePull"] = force_pull
        image_labels = self.image_labels()
        check_type("image_labels", image_labels, Optional[List["buildv1.ImageLabel"]])
        if image_labels:  # omit empty
            v["imageLabels"] = image_labels
        node_selector = self.node_selector()
        check_type("node_selector", node_selector, Optional[Dict[str, str]])
        if node_selector:  # omit empty
            v["nodeSelector"] = node_selector
        annotations = self.annotations()
        check_type("annotations", annotations, Optional[Dict[str, str]])
        if annotations:  # omit empty
            v["annotations"] = annotations
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    def force_pull(self) -> bool:
        """
        forcePull indicates whether the build strategy should always be set to ForcePull=true
        """
        return self.__force_pull

    def image_labels(self) -> Optional[List["buildv1.ImageLabel"]]:
        """
        imageLabels is a list of labels that are applied to the resulting image.
        If user provided a label in their Build/BuildConfig with the same name as one in this
        list, the user's label will be overwritten.
        """
        return self.__image_labels

    def node_selector(self) -> Optional[Dict[str, str]]:
        """
        nodeSelector is a selector which must be true for the build pod to fit on a node
        """
        return self.__node_selector

    def annotations(self) -> Optional[Dict[str, str]]:
        """
        annotations are annotations that will be added to the build pod
        """
        return self.__annotations

    def tolerations(self) -> Optional[List["k8sv1.Toleration"]]:
        """
        tolerations is a list of Tolerations that will override any existing
        tolerations set on a build pod.
        """
        return self.__tolerations


class ImageConfig(types.Object):
    """
    ImageConfig holds the necessary configuration options for building image names for system components
    """

    @context.scoped
    @typechecked
    def __init__(self, format: str = "", latest: bool = False):
        super().__init__()
        self.__format = format
        self.__latest = latest

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        format = self.format()
        check_type("format", format, str)
        v["format"] = format
        latest = self.latest()
        check_type("latest", latest, bool)
        v["latest"] = latest
        return v

    def format(self) -> str:
        """
        Format is the format of the name to be built for the system component
        """
        return self.__format

    def latest(self) -> bool:
        """
        Latest determines if the latest tag will be pulled from the registry
        """
        return self.__latest


class BuildControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        image_template_format: "ImageConfig" = None,
        build_defaults: "BuildDefaultsConfig" = None,
        build_overrides: "BuildOverridesConfig" = None,
        additional_trusted_ca: str = "",
    ):
        super().__init__()
        self.__image_template_format = (
            image_template_format
            if image_template_format is not None
            else ImageConfig()
        )
        self.__build_defaults = build_defaults
        self.__build_overrides = build_overrides
        self.__additional_trusted_ca = additional_trusted_ca

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        image_template_format = self.image_template_format()
        check_type("image_template_format", image_template_format, "ImageConfig")
        v["imageTemplateFormat"] = image_template_format
        build_defaults = self.build_defaults()
        check_type("build_defaults", build_defaults, Optional["BuildDefaultsConfig"])
        v["buildDefaults"] = build_defaults
        build_overrides = self.build_overrides()
        check_type("build_overrides", build_overrides, Optional["BuildOverridesConfig"])
        v["buildOverrides"] = build_overrides
        additional_trusted_ca = self.additional_trusted_ca()
        check_type("additional_trusted_ca", additional_trusted_ca, str)
        v["additionalTrustedCA"] = additional_trusted_ca
        return v

    def image_template_format(self) -> "ImageConfig":
        return self.__image_template_format

    def build_defaults(self) -> Optional["BuildDefaultsConfig"]:
        return self.__build_defaults

    def build_overrides(self) -> Optional["BuildOverridesConfig"]:
        return self.__build_overrides

    def additional_trusted_ca(self) -> str:
        """
        additionalTrustedCA is a path to a pem bundle file containing additional CAs that
        should be trusted for image pushes and pulls during builds.
        """
        return self.__additional_trusted_ca


class ClusterNetworkEntry(types.Object):
    """
    ClusterNetworkEntry defines an individual cluster network. The CIDRs cannot overlap with other cluster network CIDRs, CIDRs reserved for external ips, CIDRs reserved for service networks, and CIDRs reserved for ingress ips.
    """

    @context.scoped
    @typechecked
    def __init__(self, cidr: str = "", host_subnet_length: int = 0):
        super().__init__()
        self.__cidr = cidr
        self.__host_subnet_length = host_subnet_length

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cidr = self.cidr()
        check_type("cidr", cidr, str)
        v["cidr"] = cidr
        host_subnet_length = self.host_subnet_length()
        check_type("host_subnet_length", host_subnet_length, int)
        v["hostSubnetLength"] = host_subnet_length
        return v

    def cidr(self) -> str:
        """
        CIDR defines the total range of a cluster networks address space.
        """
        return self.__cidr

    def host_subnet_length(self) -> int:
        """
        HostSubnetLength is the number of bits of the accompanying CIDR address to allocate to each node. eg, 8 would mean that each node would have a /24 slice of the overlay network for its pod.
        """
        return self.__host_subnet_length


class DeployerControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, image_template_format: "ImageConfig" = None):
        super().__init__()
        self.__image_template_format = (
            image_template_format
            if image_template_format is not None
            else ImageConfig()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        image_template_format = self.image_template_format()
        check_type("image_template_format", image_template_format, "ImageConfig")
        v["imageTemplateFormat"] = image_template_format
        return v

    def image_template_format(self) -> "ImageConfig":
        return self.__image_template_format


class DockerPullSecretControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, registry_urls: List[str] = None, internal_registry_hostname: str = ""
    ):
        super().__init__()
        self.__registry_urls = registry_urls if registry_urls is not None else []
        self.__internal_registry_hostname = internal_registry_hostname

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        registry_urls = self.registry_urls()
        check_type("registry_urls", registry_urls, List[str])
        v["registryURLs"] = registry_urls
        internal_registry_hostname = self.internal_registry_hostname()
        check_type("internal_registry_hostname", internal_registry_hostname, str)
        v["internalRegistryHostname"] = internal_registry_hostname
        return v

    def registry_urls(self) -> List[str]:
        """
        registryURLs is a list of urls that the docker pull secrets should be valid for.
        """
        return self.__registry_urls

    def internal_registry_hostname(self) -> str:
        """
        internalRegistryHostname is the hostname for the default internal image
        registry. The value must be in "hostname[:port]" format.  Docker pull secrets
        will be generated for this registry.
        """
        return self.__internal_registry_hostname


class FrontProxyConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        client_ca: str = "",
        allowed_names: List[str] = None,
        username_headers: List[str] = None,
        group_headers: List[str] = None,
        extra_header_prefixes: List[str] = None,
    ):
        super().__init__()
        self.__client_ca = client_ca
        self.__allowed_names = allowed_names if allowed_names is not None else []
        self.__username_headers = (
            username_headers if username_headers is not None else []
        )
        self.__group_headers = group_headers if group_headers is not None else []
        self.__extra_header_prefixes = (
            extra_header_prefixes if extra_header_prefixes is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        client_ca = self.client_ca()
        check_type("client_ca", client_ca, str)
        v["clientCA"] = client_ca
        allowed_names = self.allowed_names()
        check_type("allowed_names", allowed_names, List[str])
        v["allowedNames"] = allowed_names
        username_headers = self.username_headers()
        check_type("username_headers", username_headers, List[str])
        v["usernameHeaders"] = username_headers
        group_headers = self.group_headers()
        check_type("group_headers", group_headers, List[str])
        v["groupHeaders"] = group_headers
        extra_header_prefixes = self.extra_header_prefixes()
        check_type("extra_header_prefixes", extra_header_prefixes, List[str])
        v["extraHeaderPrefixes"] = extra_header_prefixes
        return v

    def client_ca(self) -> str:
        """
        clientCA is a path to the CA bundle to use to verify the common name of the front proxy's client cert
        """
        return self.__client_ca

    def allowed_names(self) -> List[str]:
        """
        allowedNames is an optional list of common names to require a match from.
        """
        return self.__allowed_names

    def username_headers(self) -> List[str]:
        """
        usernameHeaders is the set of headers to check for the username
        """
        return self.__username_headers

    def group_headers(self) -> List[str]:
        """
        groupHeaders is the set of headers to check for groups
        """
        return self.__group_headers

    def extra_header_prefixes(self) -> List[str]:
        """
        extraHeaderPrefixes is the set of header prefixes to check for user extra
        """
        return self.__extra_header_prefixes


class ImageImportControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        max_scheduled_image_imports_per_minute: int = 0,
        disable_scheduled_import: bool = False,
        scheduled_image_import_minimum_interval_seconds: int = 0,
    ):
        super().__init__()
        self.__max_scheduled_image_imports_per_minute = (
            max_scheduled_image_imports_per_minute
        )
        self.__disable_scheduled_import = disable_scheduled_import
        self.__scheduled_image_import_minimum_interval_seconds = (
            scheduled_image_import_minimum_interval_seconds
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        max_scheduled_image_imports_per_minute = (
            self.max_scheduled_image_imports_per_minute()
        )
        check_type(
            "max_scheduled_image_imports_per_minute",
            max_scheduled_image_imports_per_minute,
            int,
        )
        v["maxScheduledImageImportsPerMinute"] = max_scheduled_image_imports_per_minute
        disable_scheduled_import = self.disable_scheduled_import()
        check_type("disable_scheduled_import", disable_scheduled_import, bool)
        v["disableScheduledImport"] = disable_scheduled_import
        scheduled_image_import_minimum_interval_seconds = (
            self.scheduled_image_import_minimum_interval_seconds()
        )
        check_type(
            "scheduled_image_import_minimum_interval_seconds",
            scheduled_image_import_minimum_interval_seconds,
            int,
        )
        v[
            "scheduledImageImportMinimumIntervalSeconds"
        ] = scheduled_image_import_minimum_interval_seconds
        return v

    def max_scheduled_image_imports_per_minute(self) -> int:
        """
        maxScheduledImageImportsPerMinute is the maximum number of image streams that will be imported in the background per minute.
        The default value is 60. Set to -1 for unlimited.
        """
        return self.__max_scheduled_image_imports_per_minute

    def disable_scheduled_import(self) -> bool:
        """
        disableScheduledImport allows scheduled background import of images to be disabled.
        """
        return self.__disable_scheduled_import

    def scheduled_image_import_minimum_interval_seconds(self) -> int:
        """
        scheduledImageImportMinimumIntervalSeconds is the minimum number of seconds that can elapse between when image streams
        scheduled for background import are checked against the upstream repository. The default value is 15 minutes.
        """
        return self.__scheduled_image_import_minimum_interval_seconds


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
        DomainName specifies a domain name for the registry
        In case the registry use non-standard (80 or 443) port, the port should be included
        in the domain name as well.
        """
        return self.__domain_name

    def insecure(self) -> Optional[bool]:
        """
        Insecure indicates whether the registry is secure (https) or insecure (http)
        By default (if not specified) the registry is assumed as secure.
        """
        return self.__insecure


class ImagePolicyConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        max_images_bulk_imported_per_repository: int = 0,
        allowed_registries_for_import: List["RegistryLocation"] = None,
        internal_registry_hostname: str = "",
        external_registry_hostnames: List[str] = None,
        additional_trusted_ca: str = "",
    ):
        super().__init__()
        self.__max_images_bulk_imported_per_repository = (
            max_images_bulk_imported_per_repository
        )
        self.__allowed_registries_for_import = (
            allowed_registries_for_import
            if allowed_registries_for_import is not None
            else []
        )
        self.__internal_registry_hostname = internal_registry_hostname
        self.__external_registry_hostnames = (
            external_registry_hostnames
            if external_registry_hostnames is not None
            else []
        )
        self.__additional_trusted_ca = additional_trusted_ca

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        max_images_bulk_imported_per_repository = (
            self.max_images_bulk_imported_per_repository()
        )
        check_type(
            "max_images_bulk_imported_per_repository",
            max_images_bulk_imported_per_repository,
            int,
        )
        v[
            "maxImagesBulkImportedPerRepository"
        ] = max_images_bulk_imported_per_repository
        allowed_registries_for_import = self.allowed_registries_for_import()
        check_type(
            "allowed_registries_for_import",
            allowed_registries_for_import,
            List["RegistryLocation"],
        )
        v["allowedRegistriesForImport"] = allowed_registries_for_import
        internal_registry_hostname = self.internal_registry_hostname()
        check_type("internal_registry_hostname", internal_registry_hostname, str)
        v["internalRegistryHostname"] = internal_registry_hostname
        external_registry_hostnames = self.external_registry_hostnames()
        check_type(
            "external_registry_hostnames", external_registry_hostnames, List[str]
        )
        v["externalRegistryHostnames"] = external_registry_hostnames
        additional_trusted_ca = self.additional_trusted_ca()
        check_type("additional_trusted_ca", additional_trusted_ca, str)
        v["additionalTrustedCA"] = additional_trusted_ca
        return v

    def max_images_bulk_imported_per_repository(self) -> int:
        """
        maxImagesBulkImportedPerRepository controls the number of images that are imported when a user
        does a bulk import of a container repository. This number is set low to prevent users from
        importing large numbers of images accidentally. Set -1 for no limit.
        """
        return self.__max_images_bulk_imported_per_repository

    def allowed_registries_for_import(self) -> List["RegistryLocation"]:
        """
        allowedRegistriesForImport limits the container image registries that normal users may import
        images from. Set this list to the registries that you trust to contain valid Docker
        images and that you want applications to be able to import from. Users with
        permission to create Images or ImageStreamMappings via the API are not affected by
        this policy - typically only administrators or system integrations will have those
        permissions.
        """
        return self.__allowed_registries_for_import

    def internal_registry_hostname(self) -> str:
        """
        internalRegistryHostname sets the hostname for the default internal image
        registry. The value must be in "hostname[:port]" format.
        For backward compatibility, users can still use OPENSHIFT_DEFAULT_REGISTRY
        environment variable but this setting overrides the environment variable.
        """
        return self.__internal_registry_hostname

    def external_registry_hostnames(self) -> List[str]:
        """
        externalRegistryHostnames provides the hostnames for the default external image
        registry. The external hostname should be set only when the image registry
        is exposed externally. The first value is used in 'publicDockerImageRepository'
        field in ImageStreams. The value must be in "hostname[:port]" format.
        """
        return self.__external_registry_hostnames

    def additional_trusted_ca(self) -> str:
        """
        additionalTrustedCA is a path to a pem bundle file containing additional CAs that
        should be trusted during imagestream import.
        """
        return self.__additional_trusted_ca


class IngressControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, ingress_ip_network_cidr: str = ""):
        super().__init__()
        self.__ingress_ip_network_cidr = ingress_ip_network_cidr

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ingress_ip_network_cidr = self.ingress_ip_network_cidr()
        check_type("ingress_ip_network_cidr", ingress_ip_network_cidr, str)
        v["ingressIPNetworkCIDR"] = ingress_ip_network_cidr
        return v

    def ingress_ip_network_cidr(self) -> str:
        """
        ingressIPNetworkCIDR controls the range to assign ingress ips from for services of type LoadBalancer on bare
        metal. If empty, ingress ips will not be assigned. It may contain a single CIDR that will be allocated from.
        For security reasons, you should ensure that this range does not overlap with the CIDRs reserved for external ips,
        nodes, pods, or services.
        """
        return self.__ingress_ip_network_cidr


class JenkinsPipelineConfig(types.Object):
    """
    JenkinsPipelineConfig holds configuration for the Jenkins pipeline strategy
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        auto_provision_enabled: bool = None,
        template_namespace: str = "",
        template_name: str = "",
        service_name: str = "",
        parameters: Dict[str, str] = None,
    ):
        super().__init__()
        self.__auto_provision_enabled = auto_provision_enabled
        self.__template_namespace = template_namespace
        self.__template_name = template_name
        self.__service_name = service_name
        self.__parameters = parameters if parameters is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        auto_provision_enabled = self.auto_provision_enabled()
        check_type("auto_provision_enabled", auto_provision_enabled, Optional[bool])
        v["autoProvisionEnabled"] = auto_provision_enabled
        template_namespace = self.template_namespace()
        check_type("template_namespace", template_namespace, str)
        v["templateNamespace"] = template_namespace
        template_name = self.template_name()
        check_type("template_name", template_name, str)
        v["templateName"] = template_name
        service_name = self.service_name()
        check_type("service_name", service_name, str)
        v["serviceName"] = service_name
        parameters = self.parameters()
        check_type("parameters", parameters, Dict[str, str])
        v["parameters"] = parameters
        return v

    def auto_provision_enabled(self) -> Optional[bool]:
        """
        autoProvisionEnabled determines whether a Jenkins server will be spawned from the provided
        template when the first build config in the project with type JenkinsPipeline
        is created. When not specified this option defaults to true.
        """
        return self.__auto_provision_enabled

    def template_namespace(self) -> str:
        """
        templateNamespace contains the namespace name where the Jenkins template is stored
        """
        return self.__template_namespace

    def template_name(self) -> str:
        """
        templateName is the name of the default Jenkins template
        """
        return self.__template_name

    def service_name(self) -> str:
        """
        serviceName is the name of the Jenkins service OpenShift uses to detect
        whether a Jenkins pipeline handler has already been installed in a project.
        This value *must* match a service name in the provided template.
        """
        return self.__service_name

    def parameters(self) -> Dict[str, str]:
        """
        parameters specifies a set of optional parameters to the Jenkins template.
        """
        return self.__parameters


class NetworkControllerConfig(types.Object):
    """
    MasterNetworkConfig to be passed to the compiled in network plugin
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        network_plugin_name: str = "",
        cluster_networks: List["ClusterNetworkEntry"] = None,
        service_network_cidr: str = "",
        vxlan_port: int = 0,
    ):
        super().__init__()
        self.__network_plugin_name = network_plugin_name
        self.__cluster_networks = (
            cluster_networks if cluster_networks is not None else []
        )
        self.__service_network_cidr = service_network_cidr
        self.__vxlan_port = vxlan_port

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        network_plugin_name = self.network_plugin_name()
        check_type("network_plugin_name", network_plugin_name, str)
        v["networkPluginName"] = network_plugin_name
        cluster_networks = self.cluster_networks()
        check_type("cluster_networks", cluster_networks, List["ClusterNetworkEntry"])
        v["clusterNetworks"] = cluster_networks
        service_network_cidr = self.service_network_cidr()
        check_type("service_network_cidr", service_network_cidr, str)
        v["serviceNetworkCIDR"] = service_network_cidr
        vxlan_port = self.vxlan_port()
        check_type("vxlan_port", vxlan_port, int)
        v["vxlanPort"] = vxlan_port
        return v

    def network_plugin_name(self) -> str:
        return self.__network_plugin_name

    def cluster_networks(self) -> List["ClusterNetworkEntry"]:
        """
        clusterNetworks contains a list of cluster networks that defines the global overlay networks L3 space.
        """
        return self.__cluster_networks

    def service_network_cidr(self) -> str:
        return self.__service_network_cidr

    def vxlan_port(self) -> int:
        return self.__vxlan_port


class ProjectConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        default_node_selector: str = "",
        project_request_message: str = "",
        project_request_template: str = "",
    ):
        super().__init__()
        self.__default_node_selector = default_node_selector
        self.__project_request_message = project_request_message
        self.__project_request_template = project_request_template

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        default_node_selector = self.default_node_selector()
        check_type("default_node_selector", default_node_selector, str)
        v["defaultNodeSelector"] = default_node_selector
        project_request_message = self.project_request_message()
        check_type("project_request_message", project_request_message, str)
        v["projectRequestMessage"] = project_request_message
        project_request_template = self.project_request_template()
        check_type("project_request_template", project_request_template, str)
        v["projectRequestTemplate"] = project_request_template
        return v

    def default_node_selector(self) -> str:
        """
        defaultNodeSelector holds default project node label selector
        """
        return self.__default_node_selector

    def project_request_message(self) -> str:
        """
        projectRequestMessage is the string presented to a user if they are unable to request a project via the projectrequest api endpoint
        """
        return self.__project_request_message

    def project_request_template(self) -> str:
        """
        projectRequestTemplate is the template to use for creating projects in response to projectrequest.
        It is in the format namespace/template and it is optional.
        If it is not specified, a default template is used.
        """
        return self.__project_request_template


class RoutingConfig(types.Object):
    """
    RoutingConfig holds the necessary configuration options for routing to subdomains
    """

    pass  # FIXME


class OpenShiftAPIServerConfig(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        generic_api_server_config: "configv1.GenericAPIServerConfig" = None,
        aggregator_config: "FrontProxyConfig" = None,
        image_policy_config: "ImagePolicyConfig" = None,
        project_config: "ProjectConfig" = None,
        routing_config: "RoutingConfig" = None,
        service_account_oauth_grant_method: GrantHandlerType = None,
        jenkins_pipeline_config: "JenkinsPipelineConfig" = None,
        cloud_provider_file: str = "",
        api_server_arguments: Dict[str, List[str]] = None,
    ):
        super().__init__(
            api_version="openshiftcontrolplane.config.openshift.io/v1",
            kind="OpenShiftAPIServerConfig",
        )
        self.__generic_api_server_config = (
            generic_api_server_config
            if generic_api_server_config is not None
            else configv1.GenericAPIServerConfig()
        )
        self.__aggregator_config = (
            aggregator_config if aggregator_config is not None else FrontProxyConfig()
        )
        self.__image_policy_config = (
            image_policy_config
            if image_policy_config is not None
            else ImagePolicyConfig()
        )
        self.__project_config = (
            project_config if project_config is not None else ProjectConfig()
        )
        self.__routing_config = (
            routing_config if routing_config is not None else RoutingConfig()
        )
        self.__service_account_oauth_grant_method = service_account_oauth_grant_method
        self.__jenkins_pipeline_config = (
            jenkins_pipeline_config
            if jenkins_pipeline_config is not None
            else JenkinsPipelineConfig()
        )
        self.__cloud_provider_file = cloud_provider_file
        self.__api_server_arguments = (
            api_server_arguments if api_server_arguments is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        generic_api_server_config = self.generic_api_server_config()
        check_type(
            "generic_api_server_config",
            generic_api_server_config,
            "configv1.GenericAPIServerConfig",
        )
        v.update(generic_api_server_config._root())  # inline
        aggregator_config = self.aggregator_config()
        check_type("aggregator_config", aggregator_config, "FrontProxyConfig")
        v["aggregatorConfig"] = aggregator_config
        image_policy_config = self.image_policy_config()
        check_type("image_policy_config", image_policy_config, "ImagePolicyConfig")
        v["imagePolicyConfig"] = image_policy_config
        project_config = self.project_config()
        check_type("project_config", project_config, "ProjectConfig")
        v["projectConfig"] = project_config
        routing_config = self.routing_config()
        check_type("routing_config", routing_config, "RoutingConfig")
        v["routingConfig"] = routing_config
        service_account_oauth_grant_method = self.service_account_oauth_grant_method()
        check_type(
            "service_account_oauth_grant_method",
            service_account_oauth_grant_method,
            GrantHandlerType,
        )
        v["serviceAccountOAuthGrantMethod"] = service_account_oauth_grant_method
        jenkins_pipeline_config = self.jenkins_pipeline_config()
        check_type(
            "jenkins_pipeline_config", jenkins_pipeline_config, "JenkinsPipelineConfig"
        )
        v["jenkinsPipelineConfig"] = jenkins_pipeline_config
        cloud_provider_file = self.cloud_provider_file()
        check_type("cloud_provider_file", cloud_provider_file, str)
        v["cloudProviderFile"] = cloud_provider_file
        api_server_arguments = self.api_server_arguments()
        check_type("api_server_arguments", api_server_arguments, Dict[str, List[str]])
        v["apiServerArguments"] = api_server_arguments
        return v

    def generic_api_server_config(self) -> "configv1.GenericAPIServerConfig":
        """
        provides the standard apiserver configuration
        """
        return self.__generic_api_server_config

    def aggregator_config(self) -> "FrontProxyConfig":
        """
        aggregatorConfig contains information about how to verify the aggregator front proxy
        """
        return self.__aggregator_config

    def image_policy_config(self) -> "ImagePolicyConfig":
        """
        imagePolicyConfig feeds the image policy admission plugin
        """
        return self.__image_policy_config

    def project_config(self) -> "ProjectConfig":
        """
        projectConfig feeds an admission plugin
        """
        return self.__project_config

    def routing_config(self) -> "RoutingConfig":
        """
        routingConfig holds information about routing and route generation
        """
        return self.__routing_config

    def service_account_oauth_grant_method(self) -> GrantHandlerType:
        """
        serviceAccountOAuthGrantMethod is used for determining client authorization for service account oauth client.
        It must be either: deny, prompt, or ""
        """
        return self.__service_account_oauth_grant_method

    def jenkins_pipeline_config(self) -> "JenkinsPipelineConfig":
        """
        jenkinsPipelineConfig holds information about the default Jenkins template
        used for JenkinsPipeline build strategy.
        TODO this needs to become a normal plugin config
        """
        return self.__jenkins_pipeline_config

    def cloud_provider_file(self) -> str:
        """
        cloudProviderFile points to the cloud config file
        TODO this needs to become a normal plugin config
        """
        return self.__cloud_provider_file

    def api_server_arguments(self) -> Dict[str, List[str]]:
        """
        TODO this needs to be removed.
        """
        return self.__api_server_arguments


class ResourceQuotaControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        concurrent_syncs: int = 0,
        sync_period: "base.Duration" = None,
        min_resync_period: "base.Duration" = None,
    ):
        super().__init__()
        self.__concurrent_syncs = concurrent_syncs
        self.__sync_period = (
            sync_period if sync_period is not None else metav1.Duration()
        )
        self.__min_resync_period = (
            min_resync_period if min_resync_period is not None else metav1.Duration()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        concurrent_syncs = self.concurrent_syncs()
        check_type("concurrent_syncs", concurrent_syncs, int)
        v["concurrentSyncs"] = concurrent_syncs
        sync_period = self.sync_period()
        check_type("sync_period", sync_period, "base.Duration")
        v["syncPeriod"] = sync_period
        min_resync_period = self.min_resync_period()
        check_type("min_resync_period", min_resync_period, "base.Duration")
        v["minResyncPeriod"] = min_resync_period
        return v

    def concurrent_syncs(self) -> int:
        return self.__concurrent_syncs

    def sync_period(self) -> "base.Duration":
        return self.__sync_period

    def min_resync_period(self) -> "base.Duration":
        return self.__min_resync_period


class SecurityAllocator(types.Object):
    """
    SecurityAllocator controls the automatic allocation of UIDs and MCS labels to a project. If nil, allocation is disabled.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        uid_allocator_range: str = "",
        mcs_allocator_range: str = "",
        mcs_labels_per_project: int = 0,
    ):
        super().__init__()
        self.__uid_allocator_range = uid_allocator_range
        self.__mcs_allocator_range = mcs_allocator_range
        self.__mcs_labels_per_project = mcs_labels_per_project

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uid_allocator_range = self.uid_allocator_range()
        check_type("uid_allocator_range", uid_allocator_range, str)
        v["uidAllocatorRange"] = uid_allocator_range
        mcs_allocator_range = self.mcs_allocator_range()
        check_type("mcs_allocator_range", mcs_allocator_range, str)
        v["mcsAllocatorRange"] = mcs_allocator_range
        mcs_labels_per_project = self.mcs_labels_per_project()
        check_type("mcs_labels_per_project", mcs_labels_per_project, int)
        v["mcsLabelsPerProject"] = mcs_labels_per_project
        return v

    def uid_allocator_range(self) -> str:
        """
        UIDAllocatorRange defines the total set of Unix user IDs (UIDs) that will be allocated to projects automatically, and the size of the
        block each namespace gets. For example, 1000-1999/10 will allocate ten UIDs per namespace, and will be able to allocate up to 100 blocks
        before running out of space. The default is to allocate from 1 billion to 2 billion in 10k blocks (which is the expected size of the
        ranges container images will use once user namespaces are started).
        """
        return self.__uid_allocator_range

    def mcs_allocator_range(self) -> str:
        """
        MCSAllocatorRange defines the range of MCS categories that will be assigned to namespaces. The format is
        "<prefix>/<numberOfLabels>[,<maxCategory>]". The default is "s0/2" and will allocate from c0 -> c1023, which means a total of 535k labels
        are available (1024 choose 2 ~ 535k). If this value is changed after startup, new projects may receive labels that are already allocated
        to other projects. Prefix may be any valid SELinux set of terms (including user, role, and type), although leaving them as the default
        will allow the server to set them automatically.
        
        Examples:
        * s0:/2     - Allocate labels from s0:c0,c0 to s0:c511,c511
        * s0:/2,512 - Allocate labels from s0:c0,c0,c0 to s0:c511,c511,511
        """
        return self.__mcs_allocator_range

    def mcs_labels_per_project(self) -> int:
        """
        MCSLabelsPerProject defines the number of labels that should be reserved per project. The default is 5 to match the default UID and MCS
        ranges (100k namespaces, 535k/5 labels).
        """
        return self.__mcs_labels_per_project


class ServiceAccountControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, managed_names: List[str] = None):
        super().__init__()
        self.__managed_names = managed_names if managed_names is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        managed_names = self.managed_names()
        check_type("managed_names", managed_names, List[str])
        v["managedNames"] = managed_names
        return v

    def managed_names(self) -> List[str]:
        """
        managedNames is a list of service account names that will be auto-created in every namespace.
        If no names are specified, the ServiceAccountsController will not be started.
        """
        return self.__managed_names


class ServiceServingCert(types.Object):
    """
    ServiceServingCert holds configuration for service serving cert signer which creates cert/key pairs for
    pods fulfilling a service to serve with.
    """

    @context.scoped
    @typechecked
    def __init__(self, signer: "configv1.CertInfo" = None):
        super().__init__()
        self.__signer = signer

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        signer = self.signer()
        check_type("signer", signer, Optional["configv1.CertInfo"])
        v["signer"] = signer
        return v

    def signer(self) -> Optional["configv1.CertInfo"]:
        """
        Signer holds the signing information used to automatically sign serving certificates.
        If this value is nil, then certs are not signed automatically.
        """
        return self.__signer


class OpenShiftControllerManagerConfig(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        kube_client_config: "configv1.KubeClientConfig" = None,
        serving_info: "configv1.HTTPServingInfo" = None,
        leader_election: "configv1.LeaderElection" = None,
        controllers: List[str] = None,
        resource_quota: "ResourceQuotaControllerConfig" = None,
        service_serving_cert: "ServiceServingCert" = None,
        deployer: "DeployerControllerConfig" = None,
        build: "BuildControllerConfig" = None,
        service_account: "ServiceAccountControllerConfig" = None,
        docker_pull_secret: "DockerPullSecretControllerConfig" = None,
        network: "NetworkControllerConfig" = None,
        ingress: "IngressControllerConfig" = None,
        image_import: "ImageImportControllerConfig" = None,
        security_allocator: "SecurityAllocator" = None,
    ):
        super().__init__(
            api_version="openshiftcontrolplane.config.openshift.io/v1",
            kind="OpenShiftControllerManagerConfig",
        )
        self.__kube_client_config = (
            kube_client_config
            if kube_client_config is not None
            else configv1.KubeClientConfig()
        )
        self.__serving_info = serving_info
        self.__leader_election = (
            leader_election
            if leader_election is not None
            else configv1.LeaderElection()
        )
        self.__controllers = controllers if controllers is not None else []
        self.__resource_quota = (
            resource_quota
            if resource_quota is not None
            else ResourceQuotaControllerConfig()
        )
        self.__service_serving_cert = (
            service_serving_cert
            if service_serving_cert is not None
            else ServiceServingCert()
        )
        self.__deployer = (
            deployer if deployer is not None else DeployerControllerConfig()
        )
        self.__build = build if build is not None else BuildControllerConfig()
        self.__service_account = (
            service_account
            if service_account is not None
            else ServiceAccountControllerConfig()
        )
        self.__docker_pull_secret = (
            docker_pull_secret
            if docker_pull_secret is not None
            else DockerPullSecretControllerConfig()
        )
        self.__network = network if network is not None else NetworkControllerConfig()
        self.__ingress = ingress if ingress is not None else IngressControllerConfig()
        self.__image_import = (
            image_import if image_import is not None else ImageImportControllerConfig()
        )
        self.__security_allocator = (
            security_allocator
            if security_allocator is not None
            else SecurityAllocator()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kube_client_config = self.kube_client_config()
        check_type(
            "kube_client_config", kube_client_config, "configv1.KubeClientConfig"
        )
        v["kubeClientConfig"] = kube_client_config
        serving_info = self.serving_info()
        check_type("serving_info", serving_info, Optional["configv1.HTTPServingInfo"])
        v["servingInfo"] = serving_info
        leader_election = self.leader_election()
        check_type("leader_election", leader_election, "configv1.LeaderElection")
        v["leaderElection"] = leader_election
        controllers = self.controllers()
        check_type("controllers", controllers, List[str])
        v["controllers"] = controllers
        resource_quota = self.resource_quota()
        check_type("resource_quota", resource_quota, "ResourceQuotaControllerConfig")
        v["resourceQuota"] = resource_quota
        service_serving_cert = self.service_serving_cert()
        check_type("service_serving_cert", service_serving_cert, "ServiceServingCert")
        v["serviceServingCert"] = service_serving_cert
        deployer = self.deployer()
        check_type("deployer", deployer, "DeployerControllerConfig")
        v["deployer"] = deployer
        build = self.build()
        check_type("build", build, "BuildControllerConfig")
        v["build"] = build
        service_account = self.service_account()
        check_type("service_account", service_account, "ServiceAccountControllerConfig")
        v["serviceAccount"] = service_account
        docker_pull_secret = self.docker_pull_secret()
        check_type(
            "docker_pull_secret", docker_pull_secret, "DockerPullSecretControllerConfig"
        )
        v["dockerPullSecret"] = docker_pull_secret
        network = self.network()
        check_type("network", network, "NetworkControllerConfig")
        v["network"] = network
        ingress = self.ingress()
        check_type("ingress", ingress, "IngressControllerConfig")
        v["ingress"] = ingress
        image_import = self.image_import()
        check_type("image_import", image_import, "ImageImportControllerConfig")
        v["imageImport"] = image_import
        security_allocator = self.security_allocator()
        check_type("security_allocator", security_allocator, "SecurityAllocator")
        v["securityAllocator"] = security_allocator
        return v

    def kube_client_config(self) -> "configv1.KubeClientConfig":
        return self.__kube_client_config

    def serving_info(self) -> Optional["configv1.HTTPServingInfo"]:
        """
        servingInfo describes how to start serving
        """
        return self.__serving_info

    def leader_election(self) -> "configv1.LeaderElection":
        """
        leaderElection defines the configuration for electing a controller instance to make changes to
        the cluster. If unspecified, the ControllerTTL value is checked to determine whether the
        legacy direct etcd election code will be used.
        """
        return self.__leader_election

    def controllers(self) -> List[str]:
        """
        controllers is a list of controllers to enable.  '*' enables all on-by-default controllers, 'foo' enables the controller "+
        named 'foo', '-foo' disables the controller named 'foo'.
        Defaults to "*".
        """
        return self.__controllers

    def resource_quota(self) -> "ResourceQuotaControllerConfig":
        return self.__resource_quota

    def service_serving_cert(self) -> "ServiceServingCert":
        return self.__service_serving_cert

    def deployer(self) -> "DeployerControllerConfig":
        return self.__deployer

    def build(self) -> "BuildControllerConfig":
        return self.__build

    def service_account(self) -> "ServiceAccountControllerConfig":
        return self.__service_account

    def docker_pull_secret(self) -> "DockerPullSecretControllerConfig":
        return self.__docker_pull_secret

    def network(self) -> "NetworkControllerConfig":
        return self.__network

    def ingress(self) -> "IngressControllerConfig":
        return self.__ingress

    def image_import(self) -> "ImageImportControllerConfig":
        return self.__image_import

    def security_allocator(self) -> "SecurityAllocator":
        return self.__security_allocator
