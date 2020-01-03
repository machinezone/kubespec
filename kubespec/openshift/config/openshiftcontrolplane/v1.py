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
        gitHTTPProxy: str = None,
        gitHTTPSProxy: str = None,
        gitNoProxy: str = None,
        env: List["k8sv1.EnvVar"] = None,
        sourceStrategyDefaults: "SourceStrategyDefaultsConfig" = None,
        imageLabels: List["buildv1.ImageLabel"] = None,
        nodeSelector: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        resources: "k8sv1.ResourceRequirements" = None,
    ):
        super().__init__(
            apiVersion="openshiftcontrolplane.config.openshift.io/v1",
            kind="BuildDefaultsConfig",
        )
        self.__gitHTTPProxy = gitHTTPProxy
        self.__gitHTTPSProxy = gitHTTPSProxy
        self.__gitNoProxy = gitNoProxy
        self.__env = env if env is not None else []
        self.__sourceStrategyDefaults = sourceStrategyDefaults
        self.__imageLabels = imageLabels if imageLabels is not None else []
        self.__nodeSelector = nodeSelector if nodeSelector is not None else {}
        self.__annotations = annotations if annotations is not None else {}
        self.__resources = (
            resources if resources is not None else k8sv1.ResourceRequirements()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        gitHTTPProxy = self.gitHTTPProxy()
        check_type("gitHTTPProxy", gitHTTPProxy, Optional[str])
        if gitHTTPProxy:  # omit empty
            v["gitHTTPProxy"] = gitHTTPProxy
        gitHTTPSProxy = self.gitHTTPSProxy()
        check_type("gitHTTPSProxy", gitHTTPSProxy, Optional[str])
        if gitHTTPSProxy:  # omit empty
            v["gitHTTPSProxy"] = gitHTTPSProxy
        gitNoProxy = self.gitNoProxy()
        check_type("gitNoProxy", gitNoProxy, Optional[str])
        if gitNoProxy:  # omit empty
            v["gitNoProxy"] = gitNoProxy
        env = self.env()
        check_type("env", env, Optional[List["k8sv1.EnvVar"]])
        if env:  # omit empty
            v["env"] = env
        sourceStrategyDefaults = self.sourceStrategyDefaults()
        check_type(
            "sourceStrategyDefaults",
            sourceStrategyDefaults,
            Optional["SourceStrategyDefaultsConfig"],
        )
        if sourceStrategyDefaults is not None:  # omit empty
            v["sourceStrategyDefaults"] = sourceStrategyDefaults
        imageLabels = self.imageLabels()
        check_type("imageLabels", imageLabels, Optional[List["buildv1.ImageLabel"]])
        if imageLabels:  # omit empty
            v["imageLabels"] = imageLabels
        nodeSelector = self.nodeSelector()
        check_type("nodeSelector", nodeSelector, Optional[Dict[str, str]])
        if nodeSelector:  # omit empty
            v["nodeSelector"] = nodeSelector
        annotations = self.annotations()
        check_type("annotations", annotations, Optional[Dict[str, str]])
        if annotations:  # omit empty
            v["annotations"] = annotations
        resources = self.resources()
        check_type("resources", resources, Optional["k8sv1.ResourceRequirements"])
        v["resources"] = resources
        return v

    def gitHTTPProxy(self) -> Optional[str]:
        """
        gitHTTPProxy is the location of the HTTPProxy for Git source
        """
        return self.__gitHTTPProxy

    def gitHTTPSProxy(self) -> Optional[str]:
        """
        gitHTTPSProxy is the location of the HTTPSProxy for Git source
        """
        return self.__gitHTTPSProxy

    def gitNoProxy(self) -> Optional[str]:
        """
        gitNoProxy is the list of domains for which the proxy should not be used
        """
        return self.__gitNoProxy

    def env(self) -> Optional[List["k8sv1.EnvVar"]]:
        """
        env is a set of default environment variables that will be applied to the
        build if the specified variables do not exist on the build
        """
        return self.__env

    def sourceStrategyDefaults(self) -> Optional["SourceStrategyDefaultsConfig"]:
        """
        sourceStrategyDefaults are default values that apply to builds using the
        source strategy.
        """
        return self.__sourceStrategyDefaults

    def imageLabels(self) -> Optional[List["buildv1.ImageLabel"]]:
        """
        imageLabels is a list of labels that are applied to the resulting image.
        User can override a default label by providing a label with the same name in their
        Build/BuildConfig.
        """
        return self.__imageLabels

    def nodeSelector(self) -> Optional[Dict[str, str]]:
        """
        nodeSelector is a selector which must be true for the build pod to fit on a node
        """
        return self.__nodeSelector

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
        forcePull: bool = False,
        imageLabels: List["buildv1.ImageLabel"] = None,
        nodeSelector: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        tolerations: List["k8sv1.Toleration"] = None,
    ):
        super().__init__(
            apiVersion="openshiftcontrolplane.config.openshift.io/v1",
            kind="BuildOverridesConfig",
        )
        self.__forcePull = forcePull
        self.__imageLabels = imageLabels if imageLabels is not None else []
        self.__nodeSelector = nodeSelector if nodeSelector is not None else {}
        self.__annotations = annotations if annotations is not None else {}
        self.__tolerations = tolerations if tolerations is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        forcePull = self.forcePull()
        check_type("forcePull", forcePull, bool)
        v["forcePull"] = forcePull
        imageLabels = self.imageLabels()
        check_type("imageLabels", imageLabels, Optional[List["buildv1.ImageLabel"]])
        if imageLabels:  # omit empty
            v["imageLabels"] = imageLabels
        nodeSelector = self.nodeSelector()
        check_type("nodeSelector", nodeSelector, Optional[Dict[str, str]])
        if nodeSelector:  # omit empty
            v["nodeSelector"] = nodeSelector
        annotations = self.annotations()
        check_type("annotations", annotations, Optional[Dict[str, str]])
        if annotations:  # omit empty
            v["annotations"] = annotations
        tolerations = self.tolerations()
        check_type("tolerations", tolerations, Optional[List["k8sv1.Toleration"]])
        if tolerations:  # omit empty
            v["tolerations"] = tolerations
        return v

    def forcePull(self) -> bool:
        """
        forcePull indicates whether the build strategy should always be set to ForcePull=true
        """
        return self.__forcePull

    def imageLabels(self) -> Optional[List["buildv1.ImageLabel"]]:
        """
        imageLabels is a list of labels that are applied to the resulting image.
        If user provided a label in their Build/BuildConfig with the same name as one in this
        list, the user's label will be overwritten.
        """
        return self.__imageLabels

    def nodeSelector(self) -> Optional[Dict[str, str]]:
        """
        nodeSelector is a selector which must be true for the build pod to fit on a node
        """
        return self.__nodeSelector

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
        imageTemplateFormat: "ImageConfig" = None,
        buildDefaults: "BuildDefaultsConfig" = None,
        buildOverrides: "BuildOverridesConfig" = None,
        additionalTrustedCA: str = "",
    ):
        super().__init__()
        self.__imageTemplateFormat = (
            imageTemplateFormat if imageTemplateFormat is not None else ImageConfig()
        )
        self.__buildDefaults = buildDefaults
        self.__buildOverrides = buildOverrides
        self.__additionalTrustedCA = additionalTrustedCA

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        imageTemplateFormat = self.imageTemplateFormat()
        check_type("imageTemplateFormat", imageTemplateFormat, "ImageConfig")
        v["imageTemplateFormat"] = imageTemplateFormat
        buildDefaults = self.buildDefaults()
        check_type("buildDefaults", buildDefaults, Optional["BuildDefaultsConfig"])
        v["buildDefaults"] = buildDefaults
        buildOverrides = self.buildOverrides()
        check_type("buildOverrides", buildOverrides, Optional["BuildOverridesConfig"])
        v["buildOverrides"] = buildOverrides
        additionalTrustedCA = self.additionalTrustedCA()
        check_type("additionalTrustedCA", additionalTrustedCA, str)
        v["additionalTrustedCA"] = additionalTrustedCA
        return v

    def imageTemplateFormat(self) -> "ImageConfig":
        return self.__imageTemplateFormat

    def buildDefaults(self) -> Optional["BuildDefaultsConfig"]:
        return self.__buildDefaults

    def buildOverrides(self) -> Optional["BuildOverridesConfig"]:
        return self.__buildOverrides

    def additionalTrustedCA(self) -> str:
        """
        additionalTrustedCA is a path to a pem bundle file containing additional CAs that
        should be trusted for image pushes and pulls during builds.
        """
        return self.__additionalTrustedCA


class ClusterNetworkEntry(types.Object):
    """
    ClusterNetworkEntry defines an individual cluster network. The CIDRs cannot overlap with other cluster network CIDRs, CIDRs reserved for external ips, CIDRs reserved for service networks, and CIDRs reserved for ingress ips.
    """

    @context.scoped
    @typechecked
    def __init__(self, cidr: str = "", hostSubnetLength: int = 0):
        super().__init__()
        self.__cidr = cidr
        self.__hostSubnetLength = hostSubnetLength

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        cidr = self.cidr()
        check_type("cidr", cidr, str)
        v["cidr"] = cidr
        hostSubnetLength = self.hostSubnetLength()
        check_type("hostSubnetLength", hostSubnetLength, int)
        v["hostSubnetLength"] = hostSubnetLength
        return v

    def cidr(self) -> str:
        """
        CIDR defines the total range of a cluster networks address space.
        """
        return self.__cidr

    def hostSubnetLength(self) -> int:
        """
        HostSubnetLength is the number of bits of the accompanying CIDR address to allocate to each node. eg, 8 would mean that each node would have a /24 slice of the overlay network for its pod.
        """
        return self.__hostSubnetLength


class DeployerControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, imageTemplateFormat: "ImageConfig" = None):
        super().__init__()
        self.__imageTemplateFormat = (
            imageTemplateFormat if imageTemplateFormat is not None else ImageConfig()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        imageTemplateFormat = self.imageTemplateFormat()
        check_type("imageTemplateFormat", imageTemplateFormat, "ImageConfig")
        v["imageTemplateFormat"] = imageTemplateFormat
        return v

    def imageTemplateFormat(self) -> "ImageConfig":
        return self.__imageTemplateFormat


class DockerPullSecretControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, registryURLs: List[str] = None, internalRegistryHostname: str = ""
    ):
        super().__init__()
        self.__registryURLs = registryURLs if registryURLs is not None else []
        self.__internalRegistryHostname = internalRegistryHostname

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        registryURLs = self.registryURLs()
        check_type("registryURLs", registryURLs, List[str])
        v["registryURLs"] = registryURLs
        internalRegistryHostname = self.internalRegistryHostname()
        check_type("internalRegistryHostname", internalRegistryHostname, str)
        v["internalRegistryHostname"] = internalRegistryHostname
        return v

    def registryURLs(self) -> List[str]:
        """
        registryURLs is a list of urls that the docker pull secrets should be valid for.
        """
        return self.__registryURLs

    def internalRegistryHostname(self) -> str:
        """
        internalRegistryHostname is the hostname for the default internal image
        registry. The value must be in "hostname[:port]" format.  Docker pull secrets
        will be generated for this registry.
        """
        return self.__internalRegistryHostname


class FrontProxyConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        clientCA: str = "",
        allowedNames: List[str] = None,
        usernameHeaders: List[str] = None,
        groupHeaders: List[str] = None,
        extraHeaderPrefixes: List[str] = None,
    ):
        super().__init__()
        self.__clientCA = clientCA
        self.__allowedNames = allowedNames if allowedNames is not None else []
        self.__usernameHeaders = usernameHeaders if usernameHeaders is not None else []
        self.__groupHeaders = groupHeaders if groupHeaders is not None else []
        self.__extraHeaderPrefixes = (
            extraHeaderPrefixes if extraHeaderPrefixes is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientCA = self.clientCA()
        check_type("clientCA", clientCA, str)
        v["clientCA"] = clientCA
        allowedNames = self.allowedNames()
        check_type("allowedNames", allowedNames, List[str])
        v["allowedNames"] = allowedNames
        usernameHeaders = self.usernameHeaders()
        check_type("usernameHeaders", usernameHeaders, List[str])
        v["usernameHeaders"] = usernameHeaders
        groupHeaders = self.groupHeaders()
        check_type("groupHeaders", groupHeaders, List[str])
        v["groupHeaders"] = groupHeaders
        extraHeaderPrefixes = self.extraHeaderPrefixes()
        check_type("extraHeaderPrefixes", extraHeaderPrefixes, List[str])
        v["extraHeaderPrefixes"] = extraHeaderPrefixes
        return v

    def clientCA(self) -> str:
        """
        clientCA is a path to the CA bundle to use to verify the common name of the front proxy's client cert
        """
        return self.__clientCA

    def allowedNames(self) -> List[str]:
        """
        allowedNames is an optional list of common names to require a match from.
        """
        return self.__allowedNames

    def usernameHeaders(self) -> List[str]:
        """
        usernameHeaders is the set of headers to check for the username
        """
        return self.__usernameHeaders

    def groupHeaders(self) -> List[str]:
        """
        groupHeaders is the set of headers to check for groups
        """
        return self.__groupHeaders

    def extraHeaderPrefixes(self) -> List[str]:
        """
        extraHeaderPrefixes is the set of header prefixes to check for user extra
        """
        return self.__extraHeaderPrefixes


class ImageImportControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        maxScheduledImageImportsPerMinute: int = 0,
        disableScheduledImport: bool = False,
        scheduledImageImportMinimumIntervalSeconds: int = 0,
    ):
        super().__init__()
        self.__maxScheduledImageImportsPerMinute = maxScheduledImageImportsPerMinute
        self.__disableScheduledImport = disableScheduledImport
        self.__scheduledImageImportMinimumIntervalSeconds = (
            scheduledImageImportMinimumIntervalSeconds
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        maxScheduledImageImportsPerMinute = self.maxScheduledImageImportsPerMinute()
        check_type(
            "maxScheduledImageImportsPerMinute", maxScheduledImageImportsPerMinute, int
        )
        v["maxScheduledImageImportsPerMinute"] = maxScheduledImageImportsPerMinute
        disableScheduledImport = self.disableScheduledImport()
        check_type("disableScheduledImport", disableScheduledImport, bool)
        v["disableScheduledImport"] = disableScheduledImport
        scheduledImageImportMinimumIntervalSeconds = (
            self.scheduledImageImportMinimumIntervalSeconds()
        )
        check_type(
            "scheduledImageImportMinimumIntervalSeconds",
            scheduledImageImportMinimumIntervalSeconds,
            int,
        )
        v[
            "scheduledImageImportMinimumIntervalSeconds"
        ] = scheduledImageImportMinimumIntervalSeconds
        return v

    def maxScheduledImageImportsPerMinute(self) -> int:
        """
        maxScheduledImageImportsPerMinute is the maximum number of image streams that will be imported in the background per minute.
        The default value is 60. Set to -1 for unlimited.
        """
        return self.__maxScheduledImageImportsPerMinute

    def disableScheduledImport(self) -> bool:
        """
        disableScheduledImport allows scheduled background import of images to be disabled.
        """
        return self.__disableScheduledImport

    def scheduledImageImportMinimumIntervalSeconds(self) -> int:
        """
        scheduledImageImportMinimumIntervalSeconds is the minimum number of seconds that can elapse between when image streams
        scheduled for background import are checked against the upstream repository. The default value is 15 minutes.
        """
        return self.__scheduledImageImportMinimumIntervalSeconds


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
        DomainName specifies a domain name for the registry
        In case the registry use non-standard (80 or 443) port, the port should be included
        in the domain name as well.
        """
        return self.__domainName

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
        maxImagesBulkImportedPerRepository: int = 0,
        allowedRegistriesForImport: List["RegistryLocation"] = None,
        internalRegistryHostname: str = "",
        externalRegistryHostnames: List[str] = None,
        additionalTrustedCA: str = "",
    ):
        super().__init__()
        self.__maxImagesBulkImportedPerRepository = maxImagesBulkImportedPerRepository
        self.__allowedRegistriesForImport = (
            allowedRegistriesForImport if allowedRegistriesForImport is not None else []
        )
        self.__internalRegistryHostname = internalRegistryHostname
        self.__externalRegistryHostnames = (
            externalRegistryHostnames if externalRegistryHostnames is not None else []
        )
        self.__additionalTrustedCA = additionalTrustedCA

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        maxImagesBulkImportedPerRepository = self.maxImagesBulkImportedPerRepository()
        check_type(
            "maxImagesBulkImportedPerRepository",
            maxImagesBulkImportedPerRepository,
            int,
        )
        v["maxImagesBulkImportedPerRepository"] = maxImagesBulkImportedPerRepository
        allowedRegistriesForImport = self.allowedRegistriesForImport()
        check_type(
            "allowedRegistriesForImport",
            allowedRegistriesForImport,
            List["RegistryLocation"],
        )
        v["allowedRegistriesForImport"] = allowedRegistriesForImport
        internalRegistryHostname = self.internalRegistryHostname()
        check_type("internalRegistryHostname", internalRegistryHostname, str)
        v["internalRegistryHostname"] = internalRegistryHostname
        externalRegistryHostnames = self.externalRegistryHostnames()
        check_type("externalRegistryHostnames", externalRegistryHostnames, List[str])
        v["externalRegistryHostnames"] = externalRegistryHostnames
        additionalTrustedCA = self.additionalTrustedCA()
        check_type("additionalTrustedCA", additionalTrustedCA, str)
        v["additionalTrustedCA"] = additionalTrustedCA
        return v

    def maxImagesBulkImportedPerRepository(self) -> int:
        """
        maxImagesBulkImportedPerRepository controls the number of images that are imported when a user
        does a bulk import of a container repository. This number is set low to prevent users from
        importing large numbers of images accidentally. Set -1 for no limit.
        """
        return self.__maxImagesBulkImportedPerRepository

    def allowedRegistriesForImport(self) -> List["RegistryLocation"]:
        """
        allowedRegistriesForImport limits the container image registries that normal users may import
        images from. Set this list to the registries that you trust to contain valid Docker
        images and that you want applications to be able to import from. Users with
        permission to create Images or ImageStreamMappings via the API are not affected by
        this policy - typically only administrators or system integrations will have those
        permissions.
        """
        return self.__allowedRegistriesForImport

    def internalRegistryHostname(self) -> str:
        """
        internalRegistryHostname sets the hostname for the default internal image
        registry. The value must be in "hostname[:port]" format.
        For backward compatibility, users can still use OPENSHIFT_DEFAULT_REGISTRY
        environment variable but this setting overrides the environment variable.
        """
        return self.__internalRegistryHostname

    def externalRegistryHostnames(self) -> List[str]:
        """
        externalRegistryHostnames provides the hostnames for the default external image
        registry. The external hostname should be set only when the image registry
        is exposed externally. The first value is used in 'publicDockerImageRepository'
        field in ImageStreams. The value must be in "hostname[:port]" format.
        """
        return self.__externalRegistryHostnames

    def additionalTrustedCA(self) -> str:
        """
        additionalTrustedCA is a path to a pem bundle file containing additional CAs that
        should be trusted during imagestream import.
        """
        return self.__additionalTrustedCA


class IngressControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, ingressIPNetworkCIDR: str = ""):
        super().__init__()
        self.__ingressIPNetworkCIDR = ingressIPNetworkCIDR

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        ingressIPNetworkCIDR = self.ingressIPNetworkCIDR()
        check_type("ingressIPNetworkCIDR", ingressIPNetworkCIDR, str)
        v["ingressIPNetworkCIDR"] = ingressIPNetworkCIDR
        return v

    def ingressIPNetworkCIDR(self) -> str:
        """
        ingressIPNetworkCIDR controls the range to assign ingress ips from for services of type LoadBalancer on bare
        metal. If empty, ingress ips will not be assigned. It may contain a single CIDR that will be allocated from.
        For security reasons, you should ensure that this range does not overlap with the CIDRs reserved for external ips,
        nodes, pods, or services.
        """
        return self.__ingressIPNetworkCIDR


class JenkinsPipelineConfig(types.Object):
    """
    JenkinsPipelineConfig holds configuration for the Jenkins pipeline strategy
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        autoProvisionEnabled: bool = None,
        templateNamespace: str = "",
        templateName: str = "",
        serviceName: str = "",
        parameters: Dict[str, str] = None,
    ):
        super().__init__()
        self.__autoProvisionEnabled = autoProvisionEnabled
        self.__templateNamespace = templateNamespace
        self.__templateName = templateName
        self.__serviceName = serviceName
        self.__parameters = parameters if parameters is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        autoProvisionEnabled = self.autoProvisionEnabled()
        check_type("autoProvisionEnabled", autoProvisionEnabled, Optional[bool])
        v["autoProvisionEnabled"] = autoProvisionEnabled
        templateNamespace = self.templateNamespace()
        check_type("templateNamespace", templateNamespace, str)
        v["templateNamespace"] = templateNamespace
        templateName = self.templateName()
        check_type("templateName", templateName, str)
        v["templateName"] = templateName
        serviceName = self.serviceName()
        check_type("serviceName", serviceName, str)
        v["serviceName"] = serviceName
        parameters = self.parameters()
        check_type("parameters", parameters, Dict[str, str])
        v["parameters"] = parameters
        return v

    def autoProvisionEnabled(self) -> Optional[bool]:
        """
        autoProvisionEnabled determines whether a Jenkins server will be spawned from the provided
        template when the first build config in the project with type JenkinsPipeline
        is created. When not specified this option defaults to true.
        """
        return self.__autoProvisionEnabled

    def templateNamespace(self) -> str:
        """
        templateNamespace contains the namespace name where the Jenkins template is stored
        """
        return self.__templateNamespace

    def templateName(self) -> str:
        """
        templateName is the name of the default Jenkins template
        """
        return self.__templateName

    def serviceName(self) -> str:
        """
        serviceName is the name of the Jenkins service OpenShift uses to detect
        whether a Jenkins pipeline handler has already been installed in a project.
        This value *must* match a service name in the provided template.
        """
        return self.__serviceName

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
        networkPluginName: str = "",
        clusterNetworks: List["ClusterNetworkEntry"] = None,
        serviceNetworkCIDR: str = "",
        vxlanPort: int = 0,
    ):
        super().__init__()
        self.__networkPluginName = networkPluginName
        self.__clusterNetworks = clusterNetworks if clusterNetworks is not None else []
        self.__serviceNetworkCIDR = serviceNetworkCIDR
        self.__vxlanPort = vxlanPort

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        networkPluginName = self.networkPluginName()
        check_type("networkPluginName", networkPluginName, str)
        v["networkPluginName"] = networkPluginName
        clusterNetworks = self.clusterNetworks()
        check_type("clusterNetworks", clusterNetworks, List["ClusterNetworkEntry"])
        v["clusterNetworks"] = clusterNetworks
        serviceNetworkCIDR = self.serviceNetworkCIDR()
        check_type("serviceNetworkCIDR", serviceNetworkCIDR, str)
        v["serviceNetworkCIDR"] = serviceNetworkCIDR
        vxlanPort = self.vxlanPort()
        check_type("vxlanPort", vxlanPort, int)
        v["vxlanPort"] = vxlanPort
        return v

    def networkPluginName(self) -> str:
        return self.__networkPluginName

    def clusterNetworks(self) -> List["ClusterNetworkEntry"]:
        """
        clusterNetworks contains a list of cluster networks that defines the global overlay networks L3 space.
        """
        return self.__clusterNetworks

    def serviceNetworkCIDR(self) -> str:
        return self.__serviceNetworkCIDR

    def vxlanPort(self) -> int:
        return self.__vxlanPort


class ProjectConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        defaultNodeSelector: str = "",
        projectRequestMessage: str = "",
        projectRequestTemplate: str = "",
    ):
        super().__init__()
        self.__defaultNodeSelector = defaultNodeSelector
        self.__projectRequestMessage = projectRequestMessage
        self.__projectRequestTemplate = projectRequestTemplate

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        defaultNodeSelector = self.defaultNodeSelector()
        check_type("defaultNodeSelector", defaultNodeSelector, str)
        v["defaultNodeSelector"] = defaultNodeSelector
        projectRequestMessage = self.projectRequestMessage()
        check_type("projectRequestMessage", projectRequestMessage, str)
        v["projectRequestMessage"] = projectRequestMessage
        projectRequestTemplate = self.projectRequestTemplate()
        check_type("projectRequestTemplate", projectRequestTemplate, str)
        v["projectRequestTemplate"] = projectRequestTemplate
        return v

    def defaultNodeSelector(self) -> str:
        """
        defaultNodeSelector holds default project node label selector
        """
        return self.__defaultNodeSelector

    def projectRequestMessage(self) -> str:
        """
        projectRequestMessage is the string presented to a user if they are unable to request a project via the projectrequest api endpoint
        """
        return self.__projectRequestMessage

    def projectRequestTemplate(self) -> str:
        """
        projectRequestTemplate is the template to use for creating projects in response to projectrequest.
        It is in the format namespace/template and it is optional.
        If it is not specified, a default template is used.
        """
        return self.__projectRequestTemplate


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
        genericAPIServerConfig: "configv1.GenericAPIServerConfig" = None,
        aggregatorConfig: "FrontProxyConfig" = None,
        imagePolicyConfig: "ImagePolicyConfig" = None,
        projectConfig: "ProjectConfig" = None,
        routingConfig: "RoutingConfig" = None,
        serviceAccountOAuthGrantMethod: GrantHandlerType = None,
        jenkinsPipelineConfig: "JenkinsPipelineConfig" = None,
        cloudProviderFile: str = "",
        apiServerArguments: Dict[str, List[str]] = None,
    ):
        super().__init__(
            apiVersion="openshiftcontrolplane.config.openshift.io/v1",
            kind="OpenShiftAPIServerConfig",
        )
        self.__genericAPIServerConfig = (
            genericAPIServerConfig
            if genericAPIServerConfig is not None
            else configv1.GenericAPIServerConfig()
        )
        self.__aggregatorConfig = (
            aggregatorConfig if aggregatorConfig is not None else FrontProxyConfig()
        )
        self.__imagePolicyConfig = (
            imagePolicyConfig if imagePolicyConfig is not None else ImagePolicyConfig()
        )
        self.__projectConfig = (
            projectConfig if projectConfig is not None else ProjectConfig()
        )
        self.__routingConfig = (
            routingConfig if routingConfig is not None else RoutingConfig()
        )
        self.__serviceAccountOAuthGrantMethod = serviceAccountOAuthGrantMethod
        self.__jenkinsPipelineConfig = (
            jenkinsPipelineConfig
            if jenkinsPipelineConfig is not None
            else JenkinsPipelineConfig()
        )
        self.__cloudProviderFile = cloudProviderFile
        self.__apiServerArguments = (
            apiServerArguments if apiServerArguments is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        genericAPIServerConfig = self.genericAPIServerConfig()
        check_type(
            "genericAPIServerConfig",
            genericAPIServerConfig,
            "configv1.GenericAPIServerConfig",
        )
        v.update(genericAPIServerConfig._root())  # inline
        aggregatorConfig = self.aggregatorConfig()
        check_type("aggregatorConfig", aggregatorConfig, "FrontProxyConfig")
        v["aggregatorConfig"] = aggregatorConfig
        imagePolicyConfig = self.imagePolicyConfig()
        check_type("imagePolicyConfig", imagePolicyConfig, "ImagePolicyConfig")
        v["imagePolicyConfig"] = imagePolicyConfig
        projectConfig = self.projectConfig()
        check_type("projectConfig", projectConfig, "ProjectConfig")
        v["projectConfig"] = projectConfig
        routingConfig = self.routingConfig()
        check_type("routingConfig", routingConfig, "RoutingConfig")
        v["routingConfig"] = routingConfig
        serviceAccountOAuthGrantMethod = self.serviceAccountOAuthGrantMethod()
        check_type(
            "serviceAccountOAuthGrantMethod",
            serviceAccountOAuthGrantMethod,
            GrantHandlerType,
        )
        v["serviceAccountOAuthGrantMethod"] = serviceAccountOAuthGrantMethod
        jenkinsPipelineConfig = self.jenkinsPipelineConfig()
        check_type(
            "jenkinsPipelineConfig", jenkinsPipelineConfig, "JenkinsPipelineConfig"
        )
        v["jenkinsPipelineConfig"] = jenkinsPipelineConfig
        cloudProviderFile = self.cloudProviderFile()
        check_type("cloudProviderFile", cloudProviderFile, str)
        v["cloudProviderFile"] = cloudProviderFile
        apiServerArguments = self.apiServerArguments()
        check_type("apiServerArguments", apiServerArguments, Dict[str, List[str]])
        v["apiServerArguments"] = apiServerArguments
        return v

    def genericAPIServerConfig(self) -> "configv1.GenericAPIServerConfig":
        """
        provides the standard apiserver configuration
        """
        return self.__genericAPIServerConfig

    def aggregatorConfig(self) -> "FrontProxyConfig":
        """
        aggregatorConfig contains information about how to verify the aggregator front proxy
        """
        return self.__aggregatorConfig

    def imagePolicyConfig(self) -> "ImagePolicyConfig":
        """
        imagePolicyConfig feeds the image policy admission plugin
        """
        return self.__imagePolicyConfig

    def projectConfig(self) -> "ProjectConfig":
        """
        projectConfig feeds an admission plugin
        """
        return self.__projectConfig

    def routingConfig(self) -> "RoutingConfig":
        """
        routingConfig holds information about routing and route generation
        """
        return self.__routingConfig

    def serviceAccountOAuthGrantMethod(self) -> GrantHandlerType:
        """
        serviceAccountOAuthGrantMethod is used for determining client authorization for service account oauth client.
        It must be either: deny, prompt, or ""
        """
        return self.__serviceAccountOAuthGrantMethod

    def jenkinsPipelineConfig(self) -> "JenkinsPipelineConfig":
        """
        jenkinsPipelineConfig holds information about the default Jenkins template
        used for JenkinsPipeline build strategy.
        TODO this needs to become a normal plugin config
        """
        return self.__jenkinsPipelineConfig

    def cloudProviderFile(self) -> str:
        """
        cloudProviderFile points to the cloud config file
        TODO this needs to become a normal plugin config
        """
        return self.__cloudProviderFile

    def apiServerArguments(self) -> Dict[str, List[str]]:
        """
        TODO this needs to be removed.
        """
        return self.__apiServerArguments


class ResourceQuotaControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        concurrentSyncs: int = 0,
        syncPeriod: "base.Duration" = None,
        minResyncPeriod: "base.Duration" = None,
    ):
        super().__init__()
        self.__concurrentSyncs = concurrentSyncs
        self.__syncPeriod = syncPeriod if syncPeriod is not None else metav1.Duration()
        self.__minResyncPeriod = (
            minResyncPeriod if minResyncPeriod is not None else metav1.Duration()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        concurrentSyncs = self.concurrentSyncs()
        check_type("concurrentSyncs", concurrentSyncs, int)
        v["concurrentSyncs"] = concurrentSyncs
        syncPeriod = self.syncPeriod()
        check_type("syncPeriod", syncPeriod, "base.Duration")
        v["syncPeriod"] = syncPeriod
        minResyncPeriod = self.minResyncPeriod()
        check_type("minResyncPeriod", minResyncPeriod, "base.Duration")
        v["minResyncPeriod"] = minResyncPeriod
        return v

    def concurrentSyncs(self) -> int:
        return self.__concurrentSyncs

    def syncPeriod(self) -> "base.Duration":
        return self.__syncPeriod

    def minResyncPeriod(self) -> "base.Duration":
        return self.__minResyncPeriod


class SecurityAllocator(types.Object):
    """
    SecurityAllocator controls the automatic allocation of UIDs and MCS labels to a project. If nil, allocation is disabled.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        uidAllocatorRange: str = "",
        mcsAllocatorRange: str = "",
        mcsLabelsPerProject: int = 0,
    ):
        super().__init__()
        self.__uidAllocatorRange = uidAllocatorRange
        self.__mcsAllocatorRange = mcsAllocatorRange
        self.__mcsLabelsPerProject = mcsLabelsPerProject

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uidAllocatorRange = self.uidAllocatorRange()
        check_type("uidAllocatorRange", uidAllocatorRange, str)
        v["uidAllocatorRange"] = uidAllocatorRange
        mcsAllocatorRange = self.mcsAllocatorRange()
        check_type("mcsAllocatorRange", mcsAllocatorRange, str)
        v["mcsAllocatorRange"] = mcsAllocatorRange
        mcsLabelsPerProject = self.mcsLabelsPerProject()
        check_type("mcsLabelsPerProject", mcsLabelsPerProject, int)
        v["mcsLabelsPerProject"] = mcsLabelsPerProject
        return v

    def uidAllocatorRange(self) -> str:
        """
        UIDAllocatorRange defines the total set of Unix user IDs (UIDs) that will be allocated to projects automatically, and the size of the
        block each namespace gets. For example, 1000-1999/10 will allocate ten UIDs per namespace, and will be able to allocate up to 100 blocks
        before running out of space. The default is to allocate from 1 billion to 2 billion in 10k blocks (which is the expected size of the
        ranges container images will use once user namespaces are started).
        """
        return self.__uidAllocatorRange

    def mcsAllocatorRange(self) -> str:
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
        return self.__mcsAllocatorRange

    def mcsLabelsPerProject(self) -> int:
        """
        MCSLabelsPerProject defines the number of labels that should be reserved per project. The default is 5 to match the default UID and MCS
        ranges (100k namespaces, 535k/5 labels).
        """
        return self.__mcsLabelsPerProject


class ServiceAccountControllerConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, managedNames: List[str] = None):
        super().__init__()
        self.__managedNames = managedNames if managedNames is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        managedNames = self.managedNames()
        check_type("managedNames", managedNames, List[str])
        v["managedNames"] = managedNames
        return v

    def managedNames(self) -> List[str]:
        """
        managedNames is a list of service account names that will be auto-created in every namespace.
        If no names are specified, the ServiceAccountsController will not be started.
        """
        return self.__managedNames


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
        kubeClientConfig: "configv1.KubeClientConfig" = None,
        servingInfo: "configv1.HTTPServingInfo" = None,
        leaderElection: "configv1.LeaderElection" = None,
        controllers: List[str] = None,
        resourceQuota: "ResourceQuotaControllerConfig" = None,
        serviceServingCert: "ServiceServingCert" = None,
        deployer: "DeployerControllerConfig" = None,
        build: "BuildControllerConfig" = None,
        serviceAccount: "ServiceAccountControllerConfig" = None,
        dockerPullSecret: "DockerPullSecretControllerConfig" = None,
        network: "NetworkControllerConfig" = None,
        ingress: "IngressControllerConfig" = None,
        imageImport: "ImageImportControllerConfig" = None,
        securityAllocator: "SecurityAllocator" = None,
    ):
        super().__init__(
            apiVersion="openshiftcontrolplane.config.openshift.io/v1",
            kind="OpenShiftControllerManagerConfig",
        )
        self.__kubeClientConfig = (
            kubeClientConfig
            if kubeClientConfig is not None
            else configv1.KubeClientConfig()
        )
        self.__servingInfo = servingInfo
        self.__leaderElection = (
            leaderElection if leaderElection is not None else configv1.LeaderElection()
        )
        self.__controllers = controllers if controllers is not None else []
        self.__resourceQuota = (
            resourceQuota
            if resourceQuota is not None
            else ResourceQuotaControllerConfig()
        )
        self.__serviceServingCert = (
            serviceServingCert
            if serviceServingCert is not None
            else ServiceServingCert()
        )
        self.__deployer = (
            deployer if deployer is not None else DeployerControllerConfig()
        )
        self.__build = build if build is not None else BuildControllerConfig()
        self.__serviceAccount = (
            serviceAccount
            if serviceAccount is not None
            else ServiceAccountControllerConfig()
        )
        self.__dockerPullSecret = (
            dockerPullSecret
            if dockerPullSecret is not None
            else DockerPullSecretControllerConfig()
        )
        self.__network = network if network is not None else NetworkControllerConfig()
        self.__ingress = ingress if ingress is not None else IngressControllerConfig()
        self.__imageImport = (
            imageImport if imageImport is not None else ImageImportControllerConfig()
        )
        self.__securityAllocator = (
            securityAllocator if securityAllocator is not None else SecurityAllocator()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        kubeClientConfig = self.kubeClientConfig()
        check_type("kubeClientConfig", kubeClientConfig, "configv1.KubeClientConfig")
        v["kubeClientConfig"] = kubeClientConfig
        servingInfo = self.servingInfo()
        check_type("servingInfo", servingInfo, Optional["configv1.HTTPServingInfo"])
        v["servingInfo"] = servingInfo
        leaderElection = self.leaderElection()
        check_type("leaderElection", leaderElection, "configv1.LeaderElection")
        v["leaderElection"] = leaderElection
        controllers = self.controllers()
        check_type("controllers", controllers, List[str])
        v["controllers"] = controllers
        resourceQuota = self.resourceQuota()
        check_type("resourceQuota", resourceQuota, "ResourceQuotaControllerConfig")
        v["resourceQuota"] = resourceQuota
        serviceServingCert = self.serviceServingCert()
        check_type("serviceServingCert", serviceServingCert, "ServiceServingCert")
        v["serviceServingCert"] = serviceServingCert
        deployer = self.deployer()
        check_type("deployer", deployer, "DeployerControllerConfig")
        v["deployer"] = deployer
        build = self.build()
        check_type("build", build, "BuildControllerConfig")
        v["build"] = build
        serviceAccount = self.serviceAccount()
        check_type("serviceAccount", serviceAccount, "ServiceAccountControllerConfig")
        v["serviceAccount"] = serviceAccount
        dockerPullSecret = self.dockerPullSecret()
        check_type(
            "dockerPullSecret", dockerPullSecret, "DockerPullSecretControllerConfig"
        )
        v["dockerPullSecret"] = dockerPullSecret
        network = self.network()
        check_type("network", network, "NetworkControllerConfig")
        v["network"] = network
        ingress = self.ingress()
        check_type("ingress", ingress, "IngressControllerConfig")
        v["ingress"] = ingress
        imageImport = self.imageImport()
        check_type("imageImport", imageImport, "ImageImportControllerConfig")
        v["imageImport"] = imageImport
        securityAllocator = self.securityAllocator()
        check_type("securityAllocator", securityAllocator, "SecurityAllocator")
        v["securityAllocator"] = securityAllocator
        return v

    def kubeClientConfig(self) -> "configv1.KubeClientConfig":
        return self.__kubeClientConfig

    def servingInfo(self) -> Optional["configv1.HTTPServingInfo"]:
        """
        servingInfo describes how to start serving
        """
        return self.__servingInfo

    def leaderElection(self) -> "configv1.LeaderElection":
        """
        leaderElection defines the configuration for electing a controller instance to make changes to
        the cluster. If unspecified, the ControllerTTL value is checked to determine whether the
        legacy direct etcd election code will be used.
        """
        return self.__leaderElection

    def controllers(self) -> List[str]:
        """
        controllers is a list of controllers to enable.  '*' enables all on-by-default controllers, 'foo' enables the controller "+
        named 'foo', '-foo' disables the controller named 'foo'.
        Defaults to "*".
        """
        return self.__controllers

    def resourceQuota(self) -> "ResourceQuotaControllerConfig":
        return self.__resourceQuota

    def serviceServingCert(self) -> "ServiceServingCert":
        return self.__serviceServingCert

    def deployer(self) -> "DeployerControllerConfig":
        return self.__deployer

    def build(self) -> "BuildControllerConfig":
        return self.__build

    def serviceAccount(self) -> "ServiceAccountControllerConfig":
        return self.__serviceAccount

    def dockerPullSecret(self) -> "DockerPullSecretControllerConfig":
        return self.__dockerPullSecret

    def network(self) -> "NetworkControllerConfig":
        return self.__network

    def ingress(self) -> "IngressControllerConfig":
        return self.__ingress

    def imageImport(self) -> "ImageImportControllerConfig":
        return self.__imageImport

    def securityAllocator(self) -> "SecurityAllocator":
        return self.__securityAllocator
