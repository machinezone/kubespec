# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


# ConsoleLinkLocationSelector is a set of possible menu targets to which a link may be appended.
# +kubebuilder:validation:Pattern=`^(ApplicationMenu|HelpMenu|UserMenu|NamespaceDashboard)$`
ConsoleLinkLocation = base.Enum(
    "ConsoleLinkLocation",
    {
        # ApplicationMenu indicates that the link should appear inside the application menu of the console.
        "ApplicationMenu": "ApplicationMenu",
        # HelpMenu indicates that the link should appear in the help menu in the console.
        "HelpMenu": "HelpMenu",
        # NamespaceDashboard indicates that the link should appear in the namespaced dashboard of the console.
        "NamespaceDashboard": "NamespaceDashboard",
        # UserMenu indicates that the link should appear in the user menu in the console.
        "UserMenu": "UserMenu",
    },
)


# ConsoleNotificationLocationSelector is a set of possible notification targets
# to which a notification may be appended.
# +kubebuilder:validation:Pattern=`^(BannerTop|BannerBottom|BannerTopBottom)$`
ConsoleNotificationLocation = base.Enum(
    "ConsoleNotificationLocation",
    {
        # BannerBottom indicates that the notification should appear at the bottom of the console.
        "BannerBottom": "BannerBottom",
        # BannerTop indicates that the notification should appear at the top of the console.
        "BannerTop": "BannerTop",
        # BannerTopBottom indicates that the notification should appear both at the top and at the bottom of the console.
        "BannerTopBottom": "BannerTopBottom",
    },
)


# ConsoleYAMLSampleDescription of the YAML sample.
# +kubebuilder:validation:Pattern=`^(.|\s)*\S(.|\s)*$`
ConsoleYAMLSampleDescription = base.Enum("ConsoleYAMLSampleDescription", {})


# ConsoleYAMLSampleTitle of the YAML sample.
# +kubebuilder:validation:Pattern=`^(.|\s)*\S(.|\s)*$`
ConsoleYAMLSampleTitle = base.Enum("ConsoleYAMLSampleTitle", {})


# ConsoleYAMLSampleYAML is the YAML sample to display.
# +kubebuilder:validation:Pattern=`^(.|\s)*\S(.|\s)*$`
ConsoleYAMLSampleYAML = base.Enum("ConsoleYAMLSampleYAML", {})


class ApplicationMenuSpec(types.Object):
    """
    ApplicationMenuSpec is the specification of the desired section and icon used for the link in the application menu.
    """

    @context.scoped
    @typechecked
    def __init__(self, section: str = "", imageURL: str = None):
        super().__init__()
        self.__section = section
        self.__imageURL = imageURL

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        section = self.section()
        check_type("section", section, str)
        v["section"] = section
        imageURL = self.imageURL()
        check_type("imageURL", imageURL, Optional[str])
        if imageURL:  # omit empty
            v["imageURL"] = imageURL
        return v

    def section(self) -> str:
        """
        section is the section of the application menu in which the link should appear.
        This can be any text that will appear as a subheading in the application menu dropdown.
        A new section will be created if the text does not match text of an existing section.
        """
        return self.__section

    def imageURL(self) -> Optional[str]:
        """
        imageUrl is the URL for the icon used in front of the link in the application menu.
        The URL must be an HTTPS URL or a Data URI. The image should be square and will be shown at 24x24 pixels.
        """
        return self.__imageURL


class CLIDownloadLink(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, text: str = "", href: str = ""):
        super().__init__()
        self.__text = text
        self.__href = href

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        text = self.text()
        check_type("text", text, str)
        v["text"] = text
        href = self.href()
        check_type("href", href, str)
        v["href"] = href
        return v

    def text(self) -> str:
        """
        text is the display text for the link
        """
        return self.__text

    def href(self) -> str:
        """
        href is the absolute secure URL for the link (must use https)
        +kubebuilder:validation:Pattern=`^https://`
        """
        return self.__href


class ConsoleCLIDownloadSpec(types.Object):
    """
    ConsoleCLIDownloadSpec is the desired cli download configuration.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        displayName: str = "",
        description: str = "",
        links: List["CLIDownloadLink"] = None,
    ):
        super().__init__()
        self.__displayName = displayName
        self.__description = description
        self.__links = links if links is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        displayName = self.displayName()
        check_type("displayName", displayName, str)
        v["displayName"] = displayName
        description = self.description()
        check_type("description", description, str)
        v["description"] = description
        links = self.links()
        check_type("links", links, List["CLIDownloadLink"])
        v["links"] = links
        return v

    def displayName(self) -> str:
        """
        displayName is the display name of the CLI download.
        """
        return self.__displayName

    def description(self) -> str:
        """
        description is the description of the CLI download (can include markdown).
        """
        return self.__description

    def links(self) -> List["CLIDownloadLink"]:
        """
        links is a list of objects that provide CLI download link details.
        """
        return self.__links


class ConsoleCLIDownload(base.TypedObject, base.MetadataObject):
    """
    ConsoleCLIDownload is an extension for configuring openshift web console command line interface (CLI) downloads.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ConsoleCLIDownloadSpec" = None,
    ):
        super().__init__(
            apiVersion="console.openshift.io/v1",
            kind="ConsoleCLIDownload",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ConsoleCLIDownloadSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ConsoleCLIDownloadSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ConsoleCLIDownloadSpec":
        return self.__spec


class ConsoleExternalLogLinkSpec(types.Object):
    """
    ConsoleExternalLogLinkSpec is the desired log link configuration.
    The log link will appear on the logs tab of the pod details page.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, text: str = "", hrefTemplate: str = "", namespaceFilter: str = None
    ):
        super().__init__()
        self.__text = text
        self.__hrefTemplate = hrefTemplate
        self.__namespaceFilter = namespaceFilter

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        text = self.text()
        check_type("text", text, str)
        v["text"] = text
        hrefTemplate = self.hrefTemplate()
        check_type("hrefTemplate", hrefTemplate, str)
        v["hrefTemplate"] = hrefTemplate
        namespaceFilter = self.namespaceFilter()
        check_type("namespaceFilter", namespaceFilter, Optional[str])
        if namespaceFilter:  # omit empty
            v["namespaceFilter"] = namespaceFilter
        return v

    def text(self) -> str:
        """
        text is the display text for the link
        """
        return self.__text

    def hrefTemplate(self) -> str:
        """
        hrefTemplate is an absolute secure URL (must use https) for the log link including
        variables to be replaced. Variables are specified in the URL with the format ${variableName},
        for instance, ${containerName} and will be replaced with the corresponding values
        from the resource. Resource is a pod.
        Supported variables are:
        - ${resourceName} - name of the resource which containes the logs
        - ${resourceUID} - UID of the resource which contains the logs
                      - e.g. `11111111-2222-3333-4444-555555555555`
        - ${containerName} - name of the resource's container that contains the logs
        - ${resourceNamespace} - namespace of the resource that contains the logs
        - ${resourceNamespaceUID} - namespace UID of the resource that contains the logs
        - ${podLabels} - JSON representation of labels matching the pod with the logs
                    - e.g. `{"key1":"value1","key2":"value2"}`
        
        e.g., https://example.com/logs?resourceName=${resourceName}&containerName=${containerName}&resourceNamespace=${resourceNamespace}&podLabels=${podLabels}
        +kubebuilder:validation:Pattern=`^https://`
        """
        return self.__hrefTemplate

    def namespaceFilter(self) -> Optional[str]:
        """
        namespaceFilter is a regular expression used to restrict a log link to a
        matching set of namespaces (e.g., `^openshift-`). The string is converted
        into a regular expression using the JavaScript RegExp constructor.
        If not specified, links will be displayed for all the namespaces.
        """
        return self.__namespaceFilter


class ConsoleExternalLogLink(base.TypedObject, base.MetadataObject):
    """
    ConsoleExternalLogLink is an extension for customizing OpenShift web console log links.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ConsoleExternalLogLinkSpec" = None,
    ):
        super().__init__(
            apiVersion="console.openshift.io/v1",
            kind="ConsoleExternalLogLink",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ConsoleExternalLogLinkSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ConsoleExternalLogLinkSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ConsoleExternalLogLinkSpec":
        return self.__spec


class Link(types.Object):
    """
    Represents a standard link that could be generated in HTML
    """

    @context.scoped
    @typechecked
    def __init__(self, text: str = "", href: str = ""):
        super().__init__()
        self.__text = text
        self.__href = href

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        text = self.text()
        check_type("text", text, str)
        v["text"] = text
        href = self.href()
        check_type("href", href, str)
        v["href"] = href
        return v

    def text(self) -> str:
        """
        text is the display text for the link
        """
        return self.__text

    def href(self) -> str:
        """
        href is the absolute secure URL for the link (must use https)
        +kubebuilder:validation:Pattern=`^https://`
        """
        return self.__href


class NamespaceDashboardSpec(types.Object):
    """
    NamespaceDashboardSpec is a specification of namespaces in which the dashboard link should appear.
    If both namespaces and namespaceSelector are specified, the link will appear in namespaces that match either
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespaces: List[str] = None,
        namespaceSelector: "metav1.LabelSelector" = None,
    ):
        super().__init__()
        self.__namespaces = namespaces if namespaces is not None else []
        self.__namespaceSelector = namespaceSelector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespaces = self.namespaces()
        check_type("namespaces", namespaces, Optional[List[str]])
        if namespaces:  # omit empty
            v["namespaces"] = namespaces
        namespaceSelector = self.namespaceSelector()
        check_type(
            "namespaceSelector", namespaceSelector, Optional["metav1.LabelSelector"]
        )
        if namespaceSelector is not None:  # omit empty
            v["namespaceSelector"] = namespaceSelector
        return v

    def namespaces(self) -> Optional[List[str]]:
        """
        namespaces is an array of namespace names in which the dashboard link should appear.
        """
        return self.__namespaces

    def namespaceSelector(self) -> Optional["metav1.LabelSelector"]:
        """
        namespaceSelector is used to select the Namespaces that should contain dashboard link by label.
        If the namespace labels match, dashboard link will be shown for the namespaces.
        """
        return self.__namespaceSelector


class ConsoleLinkSpec(types.Object):
    """
    ConsoleLinkSpec is the desired console link configuration.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        link: "Link" = None,
        location: ConsoleLinkLocation = None,
        applicationMenu: "ApplicationMenuSpec" = None,
        namespaceDashboard: "NamespaceDashboardSpec" = None,
    ):
        super().__init__()
        self.__link = link if link is not None else Link()
        self.__location = location
        self.__applicationMenu = applicationMenu
        self.__namespaceDashboard = namespaceDashboard

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        link = self.link()
        check_type("link", link, "Link")
        v.update(link._root())  # inline
        location = self.location()
        check_type("location", location, ConsoleLinkLocation)
        v["location"] = location
        applicationMenu = self.applicationMenu()
        check_type("applicationMenu", applicationMenu, Optional["ApplicationMenuSpec"])
        if applicationMenu is not None:  # omit empty
            v["applicationMenu"] = applicationMenu
        namespaceDashboard = self.namespaceDashboard()
        check_type(
            "namespaceDashboard", namespaceDashboard, Optional["NamespaceDashboardSpec"]
        )
        if namespaceDashboard is not None:  # omit empty
            v["namespaceDashboard"] = namespaceDashboard
        return v

    def link(self) -> "Link":
        return self.__link

    def location(self) -> ConsoleLinkLocation:
        """
        location determines which location in the console the link will be appended to (ApplicationMenu, HelpMenu, UserMenu, NamespaceDashboard).
        """
        return self.__location

    def applicationMenu(self) -> Optional["ApplicationMenuSpec"]:
        """
        applicationMenu holds information about section and icon used for the link in the
        application menu, and it is applicable only when location is set to ApplicationMenu.
        """
        return self.__applicationMenu

    def namespaceDashboard(self) -> Optional["NamespaceDashboardSpec"]:
        """
        namespaceDashboard holds information about namespaces in which the dashboard link should
        appear, and it is applicable only when location is set to NamespaceDashboard.
        If not specified, the link will appear in all namespaces.
        """
        return self.__namespaceDashboard


class ConsoleLink(base.TypedObject, base.MetadataObject):
    """
    ConsoleLink is an extension for customizing OpenShift web console links.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ConsoleLinkSpec" = None,
    ):
        super().__init__(
            apiVersion="console.openshift.io/v1",
            kind="ConsoleLink",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ConsoleLinkSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ConsoleLinkSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ConsoleLinkSpec":
        return self.__spec


class ConsoleNotificationSpec(types.Object):
    """
    ConsoleNotificationSpec is the desired console notification configuration.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        text: str = "",
        location: ConsoleNotificationLocation = None,
        link: "Link" = None,
        color: str = None,
        backgroundColor: str = None,
    ):
        super().__init__()
        self.__text = text
        self.__location = location
        self.__link = link
        self.__color = color
        self.__backgroundColor = backgroundColor

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        text = self.text()
        check_type("text", text, str)
        v["text"] = text
        location = self.location()
        check_type("location", location, Optional[ConsoleNotificationLocation])
        if location:  # omit empty
            v["location"] = location
        link = self.link()
        check_type("link", link, Optional["Link"])
        if link is not None:  # omit empty
            v["link"] = link
        color = self.color()
        check_type("color", color, Optional[str])
        if color:  # omit empty
            v["color"] = color
        backgroundColor = self.backgroundColor()
        check_type("backgroundColor", backgroundColor, Optional[str])
        if backgroundColor:  # omit empty
            v["backgroundColor"] = backgroundColor
        return v

    def text(self) -> str:
        """
        text is the visible text of the notification.
        """
        return self.__text

    def location(self) -> Optional[ConsoleNotificationLocation]:
        """
        location is the location of the notification in the console.
        """
        return self.__location

    def link(self) -> Optional["Link"]:
        """
        link is an object that holds notification link details.
        """
        return self.__link

    def color(self) -> Optional[str]:
        """
        color is the color of the text for the notification as CSS data type color.
        """
        return self.__color

    def backgroundColor(self) -> Optional[str]:
        """
        backgroundColor is the color of the background for the notification as CSS data type color.
        """
        return self.__backgroundColor


class ConsoleNotification(base.TypedObject, base.MetadataObject):
    """
    ConsoleNotification is the extension for configuring openshift web console notifications.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ConsoleNotificationSpec" = None,
    ):
        super().__init__(
            apiVersion="console.openshift.io/v1",
            kind="ConsoleNotification",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ConsoleNotificationSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ConsoleNotificationSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ConsoleNotificationSpec":
        return self.__spec


class ConsoleYAMLSampleSpec(types.Object):
    """
    ConsoleYAMLSampleSpec is the desired YAML sample configuration.
    Samples will appear with their descriptions in a samples sidebar
    when creating a resources in the web console.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        targetResource: "metav1.TypeMeta" = None,
        title: ConsoleYAMLSampleTitle = None,
        description: ConsoleYAMLSampleDescription = None,
        yaml: ConsoleYAMLSampleYAML = None,
        snippet: bool = False,
    ):
        super().__init__()
        self.__targetResource = (
            targetResource if targetResource is not None else metav1.TypeMeta()
        )
        self.__title = title
        self.__description = description
        self.__yaml = yaml
        self.__snippet = snippet

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        targetResource = self.targetResource()
        check_type("targetResource", targetResource, "metav1.TypeMeta")
        v["targetResource"] = targetResource
        title = self.title()
        check_type("title", title, ConsoleYAMLSampleTitle)
        v["title"] = title
        description = self.description()
        check_type("description", description, ConsoleYAMLSampleDescription)
        v["description"] = description
        yaml = self.yaml()
        check_type("yaml", yaml, ConsoleYAMLSampleYAML)
        v["yaml"] = yaml
        snippet = self.snippet()
        check_type("snippet", snippet, bool)
        v["snippet"] = snippet
        return v

    def targetResource(self) -> "metav1.TypeMeta":
        """
        targetResource contains apiVersion and kind of the resource
        YAML sample is representating.
        """
        return self.__targetResource

    def title(self) -> ConsoleYAMLSampleTitle:
        """
        title of the YAML sample.
        """
        return self.__title

    def description(self) -> ConsoleYAMLSampleDescription:
        """
        description of the YAML sample.
        """
        return self.__description

    def yaml(self) -> ConsoleYAMLSampleYAML:
        """
        yaml is the YAML sample to display.
        """
        return self.__yaml

    def snippet(self) -> bool:
        """
        snippet indicates that the YAML sample is not the full YAML resource
        definition, but a fragment that can be inserted into the existing
        YAML document at the user's cursor.
        """
        return self.__snippet


class ConsoleYAMLSample(base.TypedObject, base.MetadataObject):
    """
    ConsoleYAMLSample is an extension for customizing OpenShift web console YAML samples.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "ConsoleYAMLSampleSpec" = None,
    ):
        super().__init__(
            apiVersion="console.openshift.io/v1",
            kind="ConsoleYAMLSample",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else ConsoleYAMLSampleSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "ConsoleYAMLSampleSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "ConsoleYAMLSampleSpec":
        return self.__spec
