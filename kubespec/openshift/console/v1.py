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
ConsoleYAMLSampleDescription = base.Enum("ConsoleYAMLSampleDescription", {})


# ConsoleYAMLSampleTitle of the YAML sample.
ConsoleYAMLSampleTitle = base.Enum("ConsoleYAMLSampleTitle", {})


# ConsoleYAMLSampleYAML is the YAML sample to display.
ConsoleYAMLSampleYAML = base.Enum("ConsoleYAMLSampleYAML", {})


class ApplicationMenuSpec(types.Object):
    """
    ApplicationMenuSpec is the specification of the desired section and icon used for the link in the application menu.
    """

    @context.scoped
    @typechecked
    def __init__(self, section: str = "", image_url: str = None):
        super().__init__()
        self.__section = section
        self.__image_url = image_url

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        section = self.section()
        check_type("section", section, str)
        v["section"] = section
        image_url = self.image_url()
        check_type("image_url", image_url, Optional[str])
        if image_url:  # omit empty
            v["imageURL"] = image_url
        return v

    def section(self) -> str:
        """
        section is the section of the application menu in which the link should appear.
        This can be any text that will appear as a subheading in the application menu dropdown.
        A new section will be created if the text does not match text of an existing section.
        """
        return self.__section

    def image_url(self) -> Optional[str]:
        """
        imageUrl is the URL for the icon used in front of the link in the application menu.
        The URL must be an HTTPS URL or a Data URI. The image should be square and will be shown at 24x24 pixels.
        """
        return self.__image_url


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
        display_name: str = "",
        description: str = "",
        links: List["CLIDownloadLink"] = None,
    ):
        super().__init__()
        self.__display_name = display_name
        self.__description = description
        self.__links = links if links is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        display_name = self.display_name()
        check_type("display_name", display_name, str)
        v["displayName"] = display_name
        description = self.description()
        check_type("description", description, str)
        v["description"] = description
        links = self.links()
        check_type("links", links, List["CLIDownloadLink"])
        v["links"] = links
        return v

    def display_name(self) -> str:
        """
        displayName is the display name of the CLI download.
        """
        return self.__display_name

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
            api_version="console.openshift.io/v1",
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
        self, text: str = "", href_template: str = "", namespace_filter: str = None
    ):
        super().__init__()
        self.__text = text
        self.__href_template = href_template
        self.__namespace_filter = namespace_filter

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        text = self.text()
        check_type("text", text, str)
        v["text"] = text
        href_template = self.href_template()
        check_type("href_template", href_template, str)
        v["hrefTemplate"] = href_template
        namespace_filter = self.namespace_filter()
        check_type("namespace_filter", namespace_filter, Optional[str])
        if namespace_filter:  # omit empty
            v["namespaceFilter"] = namespace_filter
        return v

    def text(self) -> str:
        """
        text is the display text for the link
        """
        return self.__text

    def href_template(self) -> str:
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
        """
        return self.__href_template

    def namespace_filter(self) -> Optional[str]:
        """
        namespaceFilter is a regular expression used to restrict a log link to a
        matching set of namespaces (e.g., `^openshift-`). The string is converted
        into a regular expression using the JavaScript RegExp constructor.
        If not specified, links will be displayed for all the namespaces.
        """
        return self.__namespace_filter


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
            api_version="console.openshift.io/v1",
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
        namespace_selector: "metav1.LabelSelector" = None,
    ):
        super().__init__()
        self.__namespaces = namespaces if namespaces is not None else []
        self.__namespace_selector = namespace_selector

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespaces = self.namespaces()
        check_type("namespaces", namespaces, Optional[List[str]])
        if namespaces:  # omit empty
            v["namespaces"] = namespaces
        namespace_selector = self.namespace_selector()
        check_type(
            "namespace_selector", namespace_selector, Optional["metav1.LabelSelector"]
        )
        if namespace_selector is not None:  # omit empty
            v["namespaceSelector"] = namespace_selector
        return v

    def namespaces(self) -> Optional[List[str]]:
        """
        namespaces is an array of namespace names in which the dashboard link should appear.
        """
        return self.__namespaces

    def namespace_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        namespaceSelector is used to select the Namespaces that should contain dashboard link by label.
        If the namespace labels match, dashboard link will be shown for the namespaces.
        """
        return self.__namespace_selector


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
        application_menu: "ApplicationMenuSpec" = None,
        namespace_dashboard: "NamespaceDashboardSpec" = None,
    ):
        super().__init__()
        self.__link = link if link is not None else Link()
        self.__location = location
        self.__application_menu = application_menu
        self.__namespace_dashboard = namespace_dashboard

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        link = self.link()
        check_type("link", link, "Link")
        v.update(link._root())  # inline
        location = self.location()
        check_type("location", location, ConsoleLinkLocation)
        v["location"] = location
        application_menu = self.application_menu()
        check_type(
            "application_menu", application_menu, Optional["ApplicationMenuSpec"]
        )
        if application_menu is not None:  # omit empty
            v["applicationMenu"] = application_menu
        namespace_dashboard = self.namespace_dashboard()
        check_type(
            "namespace_dashboard",
            namespace_dashboard,
            Optional["NamespaceDashboardSpec"],
        )
        if namespace_dashboard is not None:  # omit empty
            v["namespaceDashboard"] = namespace_dashboard
        return v

    def link(self) -> "Link":
        return self.__link

    def location(self) -> ConsoleLinkLocation:
        """
        location determines which location in the console the link will be appended to (ApplicationMenu, HelpMenu, UserMenu, NamespaceDashboard).
        """
        return self.__location

    def application_menu(self) -> Optional["ApplicationMenuSpec"]:
        """
        applicationMenu holds information about section and icon used for the link in the
        application menu, and it is applicable only when location is set to ApplicationMenu.
        """
        return self.__application_menu

    def namespace_dashboard(self) -> Optional["NamespaceDashboardSpec"]:
        """
        namespaceDashboard holds information about namespaces in which the dashboard link should
        appear, and it is applicable only when location is set to NamespaceDashboard.
        If not specified, the link will appear in all namespaces.
        """
        return self.__namespace_dashboard


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
            api_version="console.openshift.io/v1",
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
        background_color: str = None,
    ):
        super().__init__()
        self.__text = text
        self.__location = location
        self.__link = link
        self.__color = color
        self.__background_color = background_color

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
        background_color = self.background_color()
        check_type("background_color", background_color, Optional[str])
        if background_color:  # omit empty
            v["backgroundColor"] = background_color
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

    def background_color(self) -> Optional[str]:
        """
        backgroundColor is the color of the background for the notification as CSS data type color.
        """
        return self.__background_color


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
            api_version="console.openshift.io/v1",
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
        target_resource: "metav1.TypeMeta" = None,
        title: ConsoleYAMLSampleTitle = None,
        description: ConsoleYAMLSampleDescription = None,
        yaml: ConsoleYAMLSampleYAML = None,
        snippet: bool = False,
    ):
        super().__init__()
        self.__target_resource = (
            target_resource if target_resource is not None else metav1.TypeMeta()
        )
        self.__title = title
        self.__description = description
        self.__yaml = yaml
        self.__snippet = snippet

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        target_resource = self.target_resource()
        check_type("target_resource", target_resource, "metav1.TypeMeta")
        v["targetResource"] = target_resource
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

    def target_resource(self) -> "metav1.TypeMeta":
        """
        targetResource contains apiVersion and kind of the resource
        YAML sample is representating.
        """
        return self.__target_resource

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
            api_version="console.openshift.io/v1",
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
