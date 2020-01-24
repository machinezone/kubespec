# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional, Union


# ConversionStrategyType describes different conversion types.
ConversionStrategyType = base.Enum(
    "ConversionStrategyType",
    {
        # None is a converter that only sets apiversion of the CR and leave everything else unchanged.
        "None": "None",
        # Webhook is a converter that calls to an external webhook to convert the CR.
        "Webhook": "Webhook",
    },
)


# ResourceScope is an enum defining the different scopes available to a custom resource
ResourceScope = base.Enum(
    "ResourceScope", {"Cluster": "Cluster", "NamespaceScoped": "Namespaced"}
)


class ConversionRequest(types.Object):
    """
    ConversionRequest describes the conversion request parameters.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        uid: str = "",
        desired_api_version: str = "",
        objects: List["runtime.RawExtension"] = None,
    ):
        super().__init__()
        self.__uid = uid
        self.__desired_api_version = desired_api_version
        self.__objects = objects if objects is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uid = self.uid()
        check_type("uid", uid, str)
        v["uid"] = uid
        desired_api_version = self.desired_api_version()
        check_type("desired_api_version", desired_api_version, str)
        v["desiredAPIVersion"] = desired_api_version
        objects = self.objects()
        check_type("objects", objects, List["runtime.RawExtension"])
        v["objects"] = objects
        return v

    def uid(self) -> str:
        """
        uid is an identifier for the individual request/response. It allows distinguishing instances of requests which are
        otherwise identical (parallel requests, etc).
        The UID is meant to track the round trip (request/response) between the Kubernetes API server and the webhook, not the user request.
        It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
        """
        return self.__uid

    def desired_api_version(self) -> str:
        """
        desiredAPIVersion is the version to convert given objects to. e.g. "myapi.example.com/v1"
        """
        return self.__desired_api_version

    def objects(self) -> List["runtime.RawExtension"]:
        """
        objects is the list of custom resource objects to be converted.
        """
        return self.__objects


class ConversionResponse(types.Object):
    """
    ConversionResponse describes a conversion response.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        uid: str = "",
        converted_objects: List["runtime.RawExtension"] = None,
        result: "metav1.Status" = None,
    ):
        super().__init__()
        self.__uid = uid
        self.__converted_objects = (
            converted_objects if converted_objects is not None else []
        )
        self.__result = result if result is not None else metav1.Status()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uid = self.uid()
        check_type("uid", uid, str)
        v["uid"] = uid
        converted_objects = self.converted_objects()
        check_type("converted_objects", converted_objects, List["runtime.RawExtension"])
        v["convertedObjects"] = converted_objects
        result = self.result()
        check_type("result", result, "metav1.Status")
        v["result"] = result
        return v

    def uid(self) -> str:
        """
        uid is an identifier for the individual request/response.
        This should be copied over from the corresponding `request.uid`.
        """
        return self.__uid

    def converted_objects(self) -> List["runtime.RawExtension"]:
        """
        convertedObjects is the list of converted version of `request.objects` if the `result` is successful, otherwise empty.
        The webhook is expected to set `apiVersion` of these objects to the `request.desiredAPIVersion`. The list
        must also have the same size as the input list with the same objects in the same order (equal kind, metadata.uid, metadata.name and metadata.namespace).
        The webhook is allowed to mutate labels and annotations. Any other change to the metadata is silently ignored.
        """
        return self.__converted_objects

    def result(self) -> "metav1.Status":
        """
        result contains the result of conversion with extra details if the conversion failed. `result.status` determines if
        the conversion failed or succeeded. The `result.status` field is required and represents the success or failure of the
        conversion. A successful conversion must set `result.status` to `Success`. A failed conversion must set
        `result.status` to `Failure` and provide more details in `result.message` and return http status 200. The `result.message`
        will be used to construct an error message for the end user.
        """
        return self.__result


class ConversionReview(base.TypedObject):
    """
    ConversionReview describes a conversion request/response.
    """

    @context.scoped
    @typechecked
    def __init__(
        self, request: "ConversionRequest" = None, response: "ConversionResponse" = None
    ):
        super().__init__(
            api_version="apiextensions.k8s.io/v1beta1", kind="ConversionReview"
        )
        self.__request = request
        self.__response = response

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        request = self.request()
        check_type("request", request, Optional["ConversionRequest"])
        if request is not None:  # omit empty
            v["request"] = request
        response = self.response()
        check_type("response", response, Optional["ConversionResponse"])
        if response is not None:  # omit empty
            v["response"] = response
        return v

    def request(self) -> Optional["ConversionRequest"]:
        """
        request describes the attributes for the conversion request.
        """
        return self.__request

    def response(self) -> Optional["ConversionResponse"]:
        """
        response describes the attributes for the conversion response.
        """
        return self.__response


class CustomResourceColumnDefinition(types.Object):
    """
    CustomResourceColumnDefinition specifies a column for server side printing.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        type: str = "",
        format: str = None,
        description: str = None,
        priority: int = None,
        json_path: str = "",
    ):
        super().__init__()
        self.__name = name
        self.__type = type
        self.__format = format
        self.__description = description
        self.__priority = priority
        self.__json_path = json_path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        type = self.type()
        check_type("type", type, str)
        v["type"] = type
        format = self.format()
        check_type("format", format, Optional[str])
        if format:  # omit empty
            v["format"] = format
        description = self.description()
        check_type("description", description, Optional[str])
        if description:  # omit empty
            v["description"] = description
        priority = self.priority()
        check_type("priority", priority, Optional[int])
        if priority:  # omit empty
            v["priority"] = priority
        json_path = self.json_path()
        check_type("json_path", json_path, str)
        v["JSONPath"] = json_path
        return v

    def name(self) -> str:
        """
        name is a human readable name for the column.
        """
        return self.__name

    def type(self) -> str:
        """
        type is an OpenAPI type definition for this column.
        See https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types for details.
        """
        return self.__type

    def format(self) -> Optional[str]:
        """
        format is an optional OpenAPI type definition for this column. The 'name' format is applied
        to the primary identifier column to assist in clients identifying column is the resource name.
        See https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types for details.
        """
        return self.__format

    def description(self) -> Optional[str]:
        """
        description is a human readable description of this column.
        """
        return self.__description

    def priority(self) -> Optional[int]:
        """
        priority is an integer defining the relative importance of this column compared to others. Lower
        numbers are considered higher priority. Columns that may be omitted in limited space scenarios
        should be given a priority greater than 0.
        """
        return self.__priority

    def json_path(self) -> str:
        """
        JSONPath is a simple JSON path (i.e. with array notation) which is evaluated against
        each custom resource to produce the value for this column.
        """
        return self.__json_path


class ServiceReference(types.Object):
    """
    ServiceReference holds a reference to Service.legacy.k8s.io
    """

    @context.scoped
    @typechecked
    def __init__(
        self, namespace: str = "", name: str = "", path: str = None, port: int = None
    ):
        super().__init__()
        self.__namespace = namespace
        self.__name = name
        self.__path = path
        self.__port = port if port is not None else 443

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        namespace = self.namespace()
        check_type("namespace", namespace, str)
        v["namespace"] = namespace
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        path = self.path()
        check_type("path", path, Optional[str])
        if path is not None:  # omit empty
            v["path"] = path
        port = self.port()
        check_type("port", port, Optional[int])
        if port is not None:  # omit empty
            v["port"] = port
        return v

    def namespace(self) -> str:
        """
        namespace is the namespace of the service.
        Required
        """
        return self.__namespace

    def name(self) -> str:
        """
        name is the name of the service.
        Required
        """
        return self.__name

    def path(self) -> Optional[str]:
        """
        path is an optional URL path at which the webhook will be contacted.
        """
        return self.__path

    def port(self) -> Optional[int]:
        """
        port is an optional service port at which the webhook will be contacted.
        `port` should be a valid port number (1-65535, inclusive).
        Defaults to 443 for backward compatibility.
        """
        return self.__port


class WebhookClientConfig(types.Object):
    """
    WebhookClientConfig contains the information to make a TLS connection with the webhook.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        url: str = None,
        service: "ServiceReference" = None,
        ca_bundle: bytes = None,
    ):
        super().__init__()
        self.__url = url
        self.__service = service
        self.__ca_bundle = ca_bundle if ca_bundle is not None else b""

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        check_type("url", url, Optional[str])
        if url is not None:  # omit empty
            v["url"] = url
        service = self.service()
        check_type("service", service, Optional["ServiceReference"])
        if service is not None:  # omit empty
            v["service"] = service
        ca_bundle = self.ca_bundle()
        check_type("ca_bundle", ca_bundle, Optional[bytes])
        if ca_bundle:  # omit empty
            v["caBundle"] = ca_bundle
        return v

    def url(self) -> Optional[str]:
        """
        url gives the location of the webhook, in standard URL form
        (`scheme://host:port/path`). Exactly one of `url` or `service`
        must be specified.
        
        The `host` should not refer to a service running in the cluster; use
        the `service` field instead. The host might be resolved via external
        DNS in some apiservers (e.g., `kube-apiserver` cannot resolve
        in-cluster DNS as that would be a layering violation). `host` may
        also be an IP address.
        
        Please note that using `localhost` or `127.0.0.1` as a `host` is
        risky unless you take great care to run this webhook on all hosts
        which run an apiserver which might need to make calls to this
        webhook. Such installs are likely to be non-portable, i.e., not easy
        to turn up in a new cluster.
        
        The scheme must be "https"; the URL must begin with "https://".
        
        A path is optional, and if present may be any string permissible in
        a URL. You may use the path to pass an arbitrary string to the
        webhook, for example, a cluster identifier.
        
        Attempting to use a user or basic auth e.g. "user:password@" is not
        allowed. Fragments ("#...") and query parameters ("?...") are not
        allowed, either.
        """
        return self.__url

    def service(self) -> Optional["ServiceReference"]:
        """
        service is a reference to the service for this webhook. Either
        service or url must be specified.
        
        If the webhook is running within the cluster, then you should use `service`.
        """
        return self.__service

    def ca_bundle(self) -> Optional[bytes]:
        """
        caBundle is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
        If unspecified, system trust roots on the apiserver are used.
        """
        return self.__ca_bundle


class CustomResourceConversion(types.Object):
    """
    CustomResourceConversion describes how to convert different versions of a CR.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        strategy: ConversionStrategyType = ConversionStrategyType["None"],
        webhook_client_config: "WebhookClientConfig" = None,
        conversion_review_versions: List[str] = None,
    ):
        super().__init__()
        self.__strategy = strategy
        self.__webhook_client_config = webhook_client_config
        self.__conversion_review_versions = (
            conversion_review_versions if conversion_review_versions is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        strategy = self.strategy()
        check_type("strategy", strategy, ConversionStrategyType)
        v["strategy"] = strategy
        webhook_client_config = self.webhook_client_config()
        check_type(
            "webhook_client_config",
            webhook_client_config,
            Optional["WebhookClientConfig"],
        )
        if webhook_client_config is not None:  # omit empty
            v["webhookClientConfig"] = webhook_client_config
        conversion_review_versions = self.conversion_review_versions()
        check_type(
            "conversion_review_versions",
            conversion_review_versions,
            Optional[List[str]],
        )
        if conversion_review_versions:  # omit empty
            v["conversionReviewVersions"] = conversion_review_versions
        return v

    def strategy(self) -> ConversionStrategyType:
        """
        strategy specifies how custom resources are converted between versions. Allowed values are:
        - `None`: The converter only change the apiVersion and would not touch any other field in the custom resource.
        - `Webhook`: API Server will call to an external webhook to do the conversion. Additional information
          is needed for this option. This requires spec.preserveUnknownFields to be false, and spec.conversion.webhookClientConfig to be set.
        """
        return self.__strategy

    def webhook_client_config(self) -> Optional["WebhookClientConfig"]:
        """
        webhookClientConfig is the instructions for how to call the webhook if strategy is `Webhook`.
        Required when `strategy` is set to `Webhook`.
        """
        return self.__webhook_client_config

    def conversion_review_versions(self) -> Optional[List[str]]:
        """
        conversionReviewVersions is an ordered list of preferred `ConversionReview`
        versions the Webhook expects. The API server will use the first version in
        the list which it supports. If none of the versions specified in this list
        are supported by API server, conversion will fail for the custom resource.
        If a persisted Webhook configuration specifies allowed versions and does not
        include any versions known to the API Server, calls to the webhook will fail.
        Defaults to `["v1beta1"]`.
        """
        return self.__conversion_review_versions


class CustomResourceDefinitionNames(types.Object):
    """
    CustomResourceDefinitionNames indicates the names to serve this CustomResourceDefinition
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        plural: str = "",
        singular: str = None,
        short_names: List[str] = None,
        kind: str = "",
        list_kind: str = None,
        categories: List[str] = None,
    ):
        super().__init__()
        self.__plural = plural
        self.__singular = singular
        self.__short_names = short_names if short_names is not None else []
        self.__kind = kind
        self.__list_kind = list_kind
        self.__categories = categories if categories is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        plural = self.plural()
        check_type("plural", plural, str)
        v["plural"] = plural
        singular = self.singular()
        check_type("singular", singular, Optional[str])
        if singular:  # omit empty
            v["singular"] = singular
        short_names = self.short_names()
        check_type("short_names", short_names, Optional[List[str]])
        if short_names:  # omit empty
            v["shortNames"] = short_names
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        list_kind = self.list_kind()
        check_type("list_kind", list_kind, Optional[str])
        if list_kind:  # omit empty
            v["listKind"] = list_kind
        categories = self.categories()
        check_type("categories", categories, Optional[List[str]])
        if categories:  # omit empty
            v["categories"] = categories
        return v

    def plural(self) -> str:
        """
        plural is the plural name of the resource to serve.
        The custom resources are served under `/apis/<group>/<version>/.../<plural>`.
        Must match the name of the CustomResourceDefinition (in the form `<names.plural>.<group>`).
        Must be all lowercase.
        """
        return self.__plural

    def singular(self) -> Optional[str]:
        """
        singular is the singular name of the resource. It must be all lowercase. Defaults to lowercased `kind`.
        """
        return self.__singular

    def short_names(self) -> Optional[List[str]]:
        """
        shortNames are short names for the resource, exposed in API discovery documents,
        and used by clients to support invocations like `kubectl get <shortname>`.
        It must be all lowercase.
        """
        return self.__short_names

    def kind(self) -> str:
        """
        kind is the serialized kind of the resource. It is normally CamelCase and singular.
        Custom resource instances will use this value as the `kind` attribute in API calls.
        """
        return self.__kind

    def list_kind(self) -> Optional[str]:
        """
        listKind is the serialized kind of the list for this resource. Defaults to "`kind`List".
        """
        return self.__list_kind

    def categories(self) -> Optional[List[str]]:
        """
        categories is a list of grouped resources this custom resource belongs to (e.g. 'all').
        This is published in API discovery documents, and used by clients to support invocations like
        `kubectl get all`.
        """
        return self.__categories


class CustomResourceSubresourceScale(types.Object):
    """
    CustomResourceSubresourceScale defines how to serve the scale subresource for CustomResources.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        spec_replicas_path: str = "",
        status_replicas_path: str = "",
        label_selector_path: str = None,
    ):
        super().__init__()
        self.__spec_replicas_path = spec_replicas_path
        self.__status_replicas_path = status_replicas_path
        self.__label_selector_path = label_selector_path

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec_replicas_path = self.spec_replicas_path()
        check_type("spec_replicas_path", spec_replicas_path, str)
        v["specReplicasPath"] = spec_replicas_path
        status_replicas_path = self.status_replicas_path()
        check_type("status_replicas_path", status_replicas_path, str)
        v["statusReplicasPath"] = status_replicas_path
        label_selector_path = self.label_selector_path()
        check_type("label_selector_path", label_selector_path, Optional[str])
        if label_selector_path is not None:  # omit empty
            v["labelSelectorPath"] = label_selector_path
        return v

    def spec_replicas_path(self) -> str:
        """
        specReplicasPath defines the JSON path inside of a custom resource that corresponds to Scale `spec.replicas`.
        Only JSON paths without the array notation are allowed.
        Must be a JSON Path under `.spec`.
        If there is no value under the given path in the custom resource, the `/scale` subresource will return an error on GET.
        """
        return self.__spec_replicas_path

    def status_replicas_path(self) -> str:
        """
        statusReplicasPath defines the JSON path inside of a custom resource that corresponds to Scale `status.replicas`.
        Only JSON paths without the array notation are allowed.
        Must be a JSON Path under `.status`.
        If there is no value under the given path in the custom resource, the `status.replicas` value in the `/scale` subresource
        will default to 0.
        """
        return self.__status_replicas_path

    def label_selector_path(self) -> Optional[str]:
        """
        labelSelectorPath defines the JSON path inside of a custom resource that corresponds to Scale `status.selector`.
        Only JSON paths without the array notation are allowed.
        Must be a JSON Path under `.status` or `.spec`.
        Must be set to work with HorizontalPodAutoscaler.
        The field pointed by this JSON path must be a string field (not a complex selector struct)
        which contains a serialized label selector in string form.
        More info: https://kubernetes.io/docs/tasks/access-kubernetes-api/custom-resources/custom-resource-definitions#scale-subresource
        If there is no value under the given path in the custom resource, the `status.selector` value in the `/scale`
        subresource will default to the empty string.
        """
        return self.__label_selector_path


class CustomResourceSubresourceStatus(types.Object):
    """
    CustomResourceSubresourceStatus defines how to serve the status subresource for CustomResources.
    Status is represented by the `.status` JSON path inside of a CustomResource. When set,
    * exposes a /status subresource for the custom resource
    * PUT requests to the /status subresource take a custom resource object, and ignore changes to anything except the status stanza
    * PUT/POST/PATCH requests to the custom resource ignore changes to the status stanza
    """

    pass  # FIXME


class CustomResourceSubresources(types.Object):
    """
    CustomResourceSubresources defines the status and scale subresources for CustomResources.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        status: "CustomResourceSubresourceStatus" = None,
        scale: "CustomResourceSubresourceScale" = None,
    ):
        super().__init__()
        self.__status = status
        self.__scale = scale

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        status = self.status()
        check_type("status", status, Optional["CustomResourceSubresourceStatus"])
        if status is not None:  # omit empty
            v["status"] = status
        scale = self.scale()
        check_type("scale", scale, Optional["CustomResourceSubresourceScale"])
        if scale is not None:  # omit empty
            v["scale"] = scale
        return v

    def status(self) -> Optional["CustomResourceSubresourceStatus"]:
        """
        status indicates the custom resource should serve a `/status` subresource.
        When enabled:
        1. requests to the custom resource primary endpoint ignore changes to the `status` stanza of the object.
        2. requests to the custom resource `/status` subresource ignore changes to anything other than the `status` stanza of the object.
        """
        return self.__status

    def scale(self) -> Optional["CustomResourceSubresourceScale"]:
        """
        scale indicates the custom resource should serve a `/scale` subresource that returns an `autoscaling/v1` Scale object.
        """
        return self.__scale


class ExternalDocumentation(types.Object):
    """
    ExternalDocumentation allows referencing an external resource for extended documentation.
    """

    @context.scoped
    @typechecked
    def __init__(self, description: str = None, url: str = None):
        super().__init__()
        self.__description = description
        self.__url = url

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        description = self.description()
        check_type("description", description, Optional[str])
        if description:  # omit empty
            v["description"] = description
        url = self.url()
        check_type("url", url, Optional[str])
        if url:  # omit empty
            v["url"] = url
        return v

    def description(self) -> Optional[str]:
        return self.__description

    def url(self) -> Optional[str]:
        return self.__url


class JSON(types.Object):
    """
    JSON represents any valid JSON value.
    These types are supported: bool, int64, float64, string, []interface{}, map[string]interface{} and nil.
    """

    @context.scoped
    @typechecked
    def __init__(self, raw: bytes = None):
        super().__init__()
        self.__raw = raw if raw is not None else b""

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        raw = self.raw()
        check_type("raw", raw, bytes)
        v["Raw"] = raw
        return v

    def raw(self) -> bytes:
        return self.__raw


class JSONSchemaProps(types.Object):
    """
    JSONSchemaProps is a JSON-Schema following Specification Draft 4 (http://json-schema.org/).
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        id: str = None,
        schema: str = None,
        ref: str = None,
        description: str = None,
        type: str = None,
        format: str = None,
        title: str = None,
        default: "JSON" = None,
        maximum: float = None,
        exclusive_maximum: bool = None,
        minimum: float = None,
        exclusive_minimum: bool = None,
        max_length: int = None,
        min_length: int = None,
        pattern: str = None,
        max_items: int = None,
        min_items: int = None,
        unique_items: bool = None,
        multiple_of: float = None,
        enum: List["JSON"] = None,
        max_properties: int = None,
        min_properties: int = None,
        required: List[str] = None,
        items: Union["JSONSchemaProps", List["JSONSchemaProps"]] = None,
        all_of: List["JSONSchemaProps"] = None,
        one_of: List["JSONSchemaProps"] = None,
        any_of: List["JSONSchemaProps"] = None,
        not_: "JSONSchemaProps" = None,
        properties: Dict[str, "JSONSchemaProps"] = None,
        additional_properties: Union["JSONSchemaProps", bool] = None,
        pattern_properties: Dict[str, "JSONSchemaProps"] = None,
        dependencies: Dict[str, Union["JSONSchemaProps", List[str]]] = None,
        additional_items: Union["JSONSchemaProps", bool] = None,
        definitions: Dict[str, "JSONSchemaProps"] = None,
        external_docs: "ExternalDocumentation" = None,
        example: "JSON" = None,
        nullable: bool = None,
        x_kubernetes_preserve_unknown_fields: bool = None,
        x_kubernetes_embedded_resource: bool = None,
        x_kubernetes_int_or_string: bool = None,
        x_kubernetes_list_map_keys: List[str] = None,
        x_kubernetes_list_type: str = None,
        x_kubernetes_map_type: str = None,
    ):
        super().__init__()
        self.__id = id
        self.__schema = schema
        self.__ref = ref
        self.__description = description
        self.__type = type
        self.__format = format
        self.__title = title
        self.__default = default
        self.__maximum = maximum
        self.__exclusive_maximum = exclusive_maximum
        self.__minimum = minimum
        self.__exclusive_minimum = exclusive_minimum
        self.__max_length = max_length
        self.__min_length = min_length
        self.__pattern = pattern
        self.__max_items = max_items
        self.__min_items = min_items
        self.__unique_items = unique_items
        self.__multiple_of = multiple_of
        self.__enum = enum if enum is not None else []
        self.__max_properties = max_properties
        self.__min_properties = min_properties
        self.__required = required if required is not None else []
        self.__items = items
        self.__all_of = all_of if all_of is not None else []
        self.__one_of = one_of if one_of is not None else []
        self.__any_of = any_of if any_of is not None else []
        self.__not_ = not_
        self.__properties = properties if properties is not None else {}
        self.__additional_properties = additional_properties
        self.__pattern_properties = (
            pattern_properties if pattern_properties is not None else {}
        )
        self.__dependencies = dependencies if dependencies is not None else {}
        self.__additional_items = additional_items
        self.__definitions = definitions if definitions is not None else {}
        self.__external_docs = external_docs
        self.__example = example
        self.__nullable = nullable
        self.__x_kubernetes_preserve_unknown_fields = (
            x_kubernetes_preserve_unknown_fields
        )
        self.__x_kubernetes_embedded_resource = x_kubernetes_embedded_resource
        self.__x_kubernetes_int_or_string = x_kubernetes_int_or_string
        self.__x_kubernetes_list_map_keys = (
            x_kubernetes_list_map_keys if x_kubernetes_list_map_keys is not None else []
        )
        self.__x_kubernetes_list_type = x_kubernetes_list_type
        self.__x_kubernetes_map_type = x_kubernetes_map_type

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        id = self.id()
        check_type("id", id, Optional[str])
        if id:  # omit empty
            v["id"] = id
        schema = self.schema()
        check_type("schema", schema, Optional[str])
        if schema:  # omit empty
            v["$schema"] = schema
        ref = self.ref()
        check_type("ref", ref, Optional[str])
        if ref is not None:  # omit empty
            v["$ref"] = ref
        description = self.description()
        check_type("description", description, Optional[str])
        if description:  # omit empty
            v["description"] = description
        type = self.type()
        check_type("type", type, Optional[str])
        if type:  # omit empty
            v["type"] = type
        format = self.format()
        check_type("format", format, Optional[str])
        if format:  # omit empty
            v["format"] = format
        title = self.title()
        check_type("title", title, Optional[str])
        if title:  # omit empty
            v["title"] = title
        default = self.default()
        check_type("default", default, Optional["JSON"])
        if default is not None:  # omit empty
            v["default"] = default
        maximum = self.maximum()
        check_type("maximum", maximum, Optional[float])
        if maximum is not None:  # omit empty
            v["maximum"] = maximum
        exclusive_maximum = self.exclusive_maximum()
        check_type("exclusive_maximum", exclusive_maximum, Optional[bool])
        if exclusive_maximum:  # omit empty
            v["exclusiveMaximum"] = exclusive_maximum
        minimum = self.minimum()
        check_type("minimum", minimum, Optional[float])
        if minimum is not None:  # omit empty
            v["minimum"] = minimum
        exclusive_minimum = self.exclusive_minimum()
        check_type("exclusive_minimum", exclusive_minimum, Optional[bool])
        if exclusive_minimum:  # omit empty
            v["exclusiveMinimum"] = exclusive_minimum
        max_length = self.max_length()
        check_type("max_length", max_length, Optional[int])
        if max_length is not None:  # omit empty
            v["maxLength"] = max_length
        min_length = self.min_length()
        check_type("min_length", min_length, Optional[int])
        if min_length is not None:  # omit empty
            v["minLength"] = min_length
        pattern = self.pattern()
        check_type("pattern", pattern, Optional[str])
        if pattern:  # omit empty
            v["pattern"] = pattern
        max_items = self.max_items()
        check_type("max_items", max_items, Optional[int])
        if max_items is not None:  # omit empty
            v["maxItems"] = max_items
        min_items = self.min_items()
        check_type("min_items", min_items, Optional[int])
        if min_items is not None:  # omit empty
            v["minItems"] = min_items
        unique_items = self.unique_items()
        check_type("unique_items", unique_items, Optional[bool])
        if unique_items:  # omit empty
            v["uniqueItems"] = unique_items
        multiple_of = self.multiple_of()
        check_type("multiple_of", multiple_of, Optional[float])
        if multiple_of is not None:  # omit empty
            v["multipleOf"] = multiple_of
        enum = self.enum()
        check_type("enum", enum, Optional[List["JSON"]])
        if enum:  # omit empty
            v["enum"] = enum
        max_properties = self.max_properties()
        check_type("max_properties", max_properties, Optional[int])
        if max_properties is not None:  # omit empty
            v["maxProperties"] = max_properties
        min_properties = self.min_properties()
        check_type("min_properties", min_properties, Optional[int])
        if min_properties is not None:  # omit empty
            v["minProperties"] = min_properties
        required = self.required()
        check_type("required", required, Optional[List[str]])
        if required:  # omit empty
            v["required"] = required
        items = self.items()
        check_type(
            "items", items, Optional[Union["JSONSchemaProps", List["JSONSchemaProps"]]]
        )
        if items is not None:  # omit empty
            v["items"] = items
        all_of = self.all_of()
        check_type("all_of", all_of, Optional[List["JSONSchemaProps"]])
        if all_of:  # omit empty
            v["allOf"] = all_of
        one_of = self.one_of()
        check_type("one_of", one_of, Optional[List["JSONSchemaProps"]])
        if one_of:  # omit empty
            v["oneOf"] = one_of
        any_of = self.any_of()
        check_type("any_of", any_of, Optional[List["JSONSchemaProps"]])
        if any_of:  # omit empty
            v["anyOf"] = any_of
        not_ = self.not_()
        check_type("not_", not_, Optional["JSONSchemaProps"])
        if not_ is not None:  # omit empty
            v["not"] = not_
        properties = self.properties()
        check_type("properties", properties, Optional[Dict[str, "JSONSchemaProps"]])
        if properties:  # omit empty
            v["properties"] = properties
        additional_properties = self.additional_properties()
        check_type(
            "additional_properties",
            additional_properties,
            Optional[Union["JSONSchemaProps", bool]],
        )
        if additional_properties is not None:  # omit empty
            v["additionalProperties"] = additional_properties
        pattern_properties = self.pattern_properties()
        check_type(
            "pattern_properties",
            pattern_properties,
            Optional[Dict[str, "JSONSchemaProps"]],
        )
        if pattern_properties:  # omit empty
            v["patternProperties"] = pattern_properties
        dependencies = self.dependencies()
        check_type(
            "dependencies",
            dependencies,
            Optional[Dict[str, Union["JSONSchemaProps", List[str]]]],
        )
        if dependencies:  # omit empty
            v["dependencies"] = dependencies
        additional_items = self.additional_items()
        check_type(
            "additional_items",
            additional_items,
            Optional[Union["JSONSchemaProps", bool]],
        )
        if additional_items is not None:  # omit empty
            v["additionalItems"] = additional_items
        definitions = self.definitions()
        check_type("definitions", definitions, Optional[Dict[str, "JSONSchemaProps"]])
        if definitions:  # omit empty
            v["definitions"] = definitions
        external_docs = self.external_docs()
        check_type("external_docs", external_docs, Optional["ExternalDocumentation"])
        if external_docs is not None:  # omit empty
            v["externalDocs"] = external_docs
        example = self.example()
        check_type("example", example, Optional["JSON"])
        if example is not None:  # omit empty
            v["example"] = example
        nullable = self.nullable()
        check_type("nullable", nullable, Optional[bool])
        if nullable:  # omit empty
            v["nullable"] = nullable
        x_kubernetes_preserve_unknown_fields = (
            self.x_kubernetes_preserve_unknown_fields()
        )
        check_type(
            "x_kubernetes_preserve_unknown_fields",
            x_kubernetes_preserve_unknown_fields,
            Optional[bool],
        )
        if x_kubernetes_preserve_unknown_fields is not None:  # omit empty
            v[
                "x-kubernetes-preserve-unknown-fields"
            ] = x_kubernetes_preserve_unknown_fields
        x_kubernetes_embedded_resource = self.x_kubernetes_embedded_resource()
        check_type(
            "x_kubernetes_embedded_resource",
            x_kubernetes_embedded_resource,
            Optional[bool],
        )
        if x_kubernetes_embedded_resource:  # omit empty
            v["x-kubernetes-embedded-resource"] = x_kubernetes_embedded_resource
        x_kubernetes_int_or_string = self.x_kubernetes_int_or_string()
        check_type(
            "x_kubernetes_int_or_string", x_kubernetes_int_or_string, Optional[bool]
        )
        if x_kubernetes_int_or_string:  # omit empty
            v["x-kubernetes-int-or-string"] = x_kubernetes_int_or_string
        x_kubernetes_list_map_keys = self.x_kubernetes_list_map_keys()
        check_type(
            "x_kubernetes_list_map_keys",
            x_kubernetes_list_map_keys,
            Optional[List[str]],
        )
        if x_kubernetes_list_map_keys:  # omit empty
            v["x-kubernetes-list-map-keys"] = x_kubernetes_list_map_keys
        x_kubernetes_list_type = self.x_kubernetes_list_type()
        check_type("x_kubernetes_list_type", x_kubernetes_list_type, Optional[str])
        if x_kubernetes_list_type is not None:  # omit empty
            v["x-kubernetes-list-type"] = x_kubernetes_list_type
        x_kubernetes_map_type = self.x_kubernetes_map_type()
        check_type("x_kubernetes_map_type", x_kubernetes_map_type, Optional[str])
        if x_kubernetes_map_type is not None:  # omit empty
            v["x-kubernetes-map-type"] = x_kubernetes_map_type
        return v

    def id(self) -> Optional[str]:
        return self.__id

    def schema(self) -> Optional[str]:
        return self.__schema

    def ref(self) -> Optional[str]:
        return self.__ref

    def description(self) -> Optional[str]:
        return self.__description

    def type(self) -> Optional[str]:
        return self.__type

    def format(self) -> Optional[str]:
        """
        format is an OpenAPI v3 format string. Unknown formats are ignored. The following formats are validated:
        
        - bsonobjectid: a bson object ID, i.e. a 24 characters hex string
        - uri: an URI as parsed by Golang net/url.ParseRequestURI
        - email: an email address as parsed by Golang net/mail.ParseAddress
        - hostname: a valid representation for an Internet host name, as defined by RFC 1034, section 3.1 [RFC1034].
        - ipv4: an IPv4 IP as parsed by Golang net.ParseIP
        - ipv6: an IPv6 IP as parsed by Golang net.ParseIP
        - cidr: a CIDR as parsed by Golang net.ParseCIDR
        - mac: a MAC address as parsed by Golang net.ParseMAC
        - uuid: an UUID that allows uppercase defined by the regex (?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$
        - uuid3: an UUID3 that allows uppercase defined by the regex (?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?3[0-9a-f]{3}-?[0-9a-f]{4}-?[0-9a-f]{12}$
        - uuid4: an UUID4 that allows uppercase defined by the regex (?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?4[0-9a-f]{3}-?[89ab][0-9a-f]{3}-?[0-9a-f]{12}$
        - uuid5: an UUID5 that allows uppercase defined by the regex (?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?5[0-9a-f]{3}-?[89ab][0-9a-f]{3}-?[0-9a-f]{12}$
        - isbn: an ISBN10 or ISBN13 number string like "0321751043" or "978-0321751041"
        - isbn10: an ISBN10 number string like "0321751043"
        - isbn13: an ISBN13 number string like "978-0321751041"
        - creditcard: a credit card number defined by the regex ^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})$ with any non digit characters mixed in
        - ssn: a U.S. social security number following the regex ^\\d{3}[- ]?\\d{2}[- ]?\\d{4}$
        - hexcolor: an hexadecimal color code like "#FFFFFF: following the regex ^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$
        - rgbcolor: an RGB color code like rgb like "rgb(255,255,2559"
        - byte: base64 encoded binary data
        - password: any kind of string
        - date: a date string like "2006-01-02" as defined by full-date in RFC3339
        - duration: a duration string like "22 ns" as parsed by Golang time.ParseDuration or compatible with Scala duration format
        - datetime: a date time string like "2014-12-15T19:30:20.000Z" as defined by date-time in RFC3339.
        """
        return self.__format

    def title(self) -> Optional[str]:
        return self.__title

    def default(self) -> Optional["JSON"]:
        """
        default is a default value for undefined object fields.
        Defaulting is a beta feature under the CustomResourceDefaulting feature gate.
        CustomResourceDefinitions with defaults must be created using the v1 (or newer) CustomResourceDefinition API.
        """
        return self.__default

    def maximum(self) -> Optional[float]:
        return self.__maximum

    def exclusive_maximum(self) -> Optional[bool]:
        return self.__exclusive_maximum

    def minimum(self) -> Optional[float]:
        return self.__minimum

    def exclusive_minimum(self) -> Optional[bool]:
        return self.__exclusive_minimum

    def max_length(self) -> Optional[int]:
        return self.__max_length

    def min_length(self) -> Optional[int]:
        return self.__min_length

    def pattern(self) -> Optional[str]:
        return self.__pattern

    def max_items(self) -> Optional[int]:
        return self.__max_items

    def min_items(self) -> Optional[int]:
        return self.__min_items

    def unique_items(self) -> Optional[bool]:
        return self.__unique_items

    def multiple_of(self) -> Optional[float]:
        return self.__multiple_of

    def enum(self) -> Optional[List["JSON"]]:
        return self.__enum

    def max_properties(self) -> Optional[int]:
        return self.__max_properties

    def min_properties(self) -> Optional[int]:
        return self.__min_properties

    def required(self) -> Optional[List[str]]:
        return self.__required

    def items(self) -> Optional[Union["JSONSchemaProps", List["JSONSchemaProps"]]]:
        return self.__items

    def all_of(self) -> Optional[List["JSONSchemaProps"]]:
        return self.__all_of

    def one_of(self) -> Optional[List["JSONSchemaProps"]]:
        return self.__one_of

    def any_of(self) -> Optional[List["JSONSchemaProps"]]:
        return self.__any_of

    def not_(self) -> Optional["JSONSchemaProps"]:
        return self.__not_

    def properties(self) -> Optional[Dict[str, "JSONSchemaProps"]]:
        return self.__properties

    def additional_properties(self) -> Optional[Union["JSONSchemaProps", bool]]:
        return self.__additional_properties

    def pattern_properties(self) -> Optional[Dict[str, "JSONSchemaProps"]]:
        return self.__pattern_properties

    def dependencies(self) -> Optional[Dict[str, Union["JSONSchemaProps", List[str]]]]:
        return self.__dependencies

    def additional_items(self) -> Optional[Union["JSONSchemaProps", bool]]:
        return self.__additional_items

    def definitions(self) -> Optional[Dict[str, "JSONSchemaProps"]]:
        return self.__definitions

    def external_docs(self) -> Optional["ExternalDocumentation"]:
        return self.__external_docs

    def example(self) -> Optional["JSON"]:
        return self.__example

    def nullable(self) -> Optional[bool]:
        return self.__nullable

    def x_kubernetes_preserve_unknown_fields(self) -> Optional[bool]:
        """
        x-kubernetes-preserve-unknown-fields stops the API server
        decoding step from pruning fields which are not specified
        in the validation schema. This affects fields recursively,
        but switches back to normal pruning behaviour if nested
        properties or additionalProperties are specified in the schema.
        This can either be true or undefined. False is forbidden.
        """
        return self.__x_kubernetes_preserve_unknown_fields

    def x_kubernetes_embedded_resource(self) -> Optional[bool]:
        """
        x-kubernetes-embedded-resource defines that the value is an
        embedded Kubernetes runtime.Object, with TypeMeta and
        ObjectMeta. The type must be object. It is allowed to further
        restrict the embedded object. kind, apiVersion and metadata
        are validated automatically. x-kubernetes-preserve-unknown-fields
        is allowed to be true, but does not have to be if the object
        is fully specified (up to kind, apiVersion, metadata).
        """
        return self.__x_kubernetes_embedded_resource

    def x_kubernetes_int_or_string(self) -> Optional[bool]:
        """
        x-kubernetes-int-or-string specifies that this value is
        either an integer or a string. If this is true, an empty
        type is allowed and type as child of anyOf is permitted
        if following one of the following patterns:
        
        1) anyOf:
           - type: integer
           - type: string
        2) allOf:
           - anyOf:
             - type: integer
             - type: string
           - ... zero or more
        """
        return self.__x_kubernetes_int_or_string

    def x_kubernetes_list_map_keys(self) -> Optional[List[str]]:
        """
        x-kubernetes-list-map-keys annotates an array with the x-kubernetes-list-type `map` by specifying the keys used
        as the index of the map.
        
        This tag MUST only be used on lists that have the "x-kubernetes-list-type"
        extension set to "map". Also, the values specified for this attribute must
        be a scalar typed field of the child structure (no nesting is supported).
        """
        return self.__x_kubernetes_list_map_keys

    def x_kubernetes_list_type(self) -> Optional[str]:
        """
        x-kubernetes-list-type annotates an array to further describe its topology.
        This extension must only be used on lists and may have 3 possible values:
        
        1) `atomic`: the list is treated as a single entity, like a scalar.
             Atomic lists will be entirely replaced when updated. This extension
             may be used on any type of list (struct, scalar, ...).
        2) `set`:
             Sets are lists that must not have multiple items with the same value. Each
             value must be a scalar, an object with x-kubernetes-map-type `atomic` or an
             array with x-kubernetes-list-type `atomic`.
        3) `map`:
             These lists are like maps in that their elements have a non-index key
             used to identify them. Order is preserved upon merge. The map tag
             must only be used on a list with elements of type object.
        Defaults to atomic for arrays.
        """
        return self.__x_kubernetes_list_type

    def x_kubernetes_map_type(self) -> Optional[str]:
        """
        x-kubernetes-map-type annotates an object to further describe its topology.
        This extension must only be used when type is object and may have 2 possible values:
        
        1) `granular`:
             These maps are actual maps (key-value pairs) and each fields are independent
             from each other (they can each be manipulated by separate actors). This is
             the default behaviour for all maps.
        2) `atomic`: the list is treated as a single entity, like a scalar.
             Atomic maps will be entirely replaced when updated.
        """
        return self.__x_kubernetes_map_type


class CustomResourceValidation(types.Object):
    """
    CustomResourceValidation is a list of validation methods for CustomResources.
    """

    @context.scoped
    @typechecked
    def __init__(self, open_apiv3_schema: "JSONSchemaProps" = None):
        super().__init__()
        self.__open_apiv3_schema = open_apiv3_schema

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        open_apiv3_schema = self.open_apiv3_schema()
        check_type("open_apiv3_schema", open_apiv3_schema, Optional["JSONSchemaProps"])
        if open_apiv3_schema is not None:  # omit empty
            v["openAPIV3Schema"] = open_apiv3_schema
        return v

    def open_apiv3_schema(self) -> Optional["JSONSchemaProps"]:
        """
        openAPIV3Schema is the OpenAPI v3 schema to use for validation and pruning.
        """
        return self.__open_apiv3_schema


class CustomResourceDefinitionVersion(types.Object):
    """
    CustomResourceDefinitionVersion describes a version for CRD.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        served: bool = False,
        storage: bool = False,
        schema: "CustomResourceValidation" = None,
        subresources: "CustomResourceSubresources" = None,
        additional_printer_columns: List["CustomResourceColumnDefinition"] = None,
    ):
        super().__init__()
        self.__name = name
        self.__served = served
        self.__storage = storage
        self.__schema = schema
        self.__subresources = subresources
        self.__additional_printer_columns = (
            additional_printer_columns if additional_printer_columns is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        served = self.served()
        check_type("served", served, bool)
        v["served"] = served
        storage = self.storage()
        check_type("storage", storage, bool)
        v["storage"] = storage
        schema = self.schema()
        check_type("schema", schema, Optional["CustomResourceValidation"])
        if schema is not None:  # omit empty
            v["schema"] = schema
        subresources = self.subresources()
        check_type("subresources", subresources, Optional["CustomResourceSubresources"])
        if subresources is not None:  # omit empty
            v["subresources"] = subresources
        additional_printer_columns = self.additional_printer_columns()
        check_type(
            "additional_printer_columns",
            additional_printer_columns,
            Optional[List["CustomResourceColumnDefinition"]],
        )
        if additional_printer_columns:  # omit empty
            v["additionalPrinterColumns"] = additional_printer_columns
        return v

    def name(self) -> str:
        """
        name is the version name, e.g. “v1”, “v2beta1”, etc.
        The custom resources are served under this version at `/apis/<group>/<version>/...` if `served` is true.
        """
        return self.__name

    def served(self) -> bool:
        """
        served is a flag enabling/disabling this version from being served via REST APIs
        """
        return self.__served

    def storage(self) -> bool:
        """
        storage indicates this version should be used when persisting custom resources to storage.
        There must be exactly one version with storage=true.
        """
        return self.__storage

    def schema(self) -> Optional["CustomResourceValidation"]:
        """
        schema describes the schema used for validation and pruning of this version of the custom resource.
        Top-level and per-version schemas are mutually exclusive.
        Per-version schemas must not all be set to identical values (top-level validation schema should be used instead).
        """
        return self.__schema

    def subresources(self) -> Optional["CustomResourceSubresources"]:
        """
        subresources specify what subresources this version of the defined custom resource have.
        Top-level and per-version subresources are mutually exclusive.
        Per-version subresources must not all be set to identical values (top-level subresources should be used instead).
        """
        return self.__subresources

    def additional_printer_columns(
        self
    ) -> Optional[List["CustomResourceColumnDefinition"]]:
        """
        additionalPrinterColumns specifies additional columns returned in Table output.
        See https://kubernetes.io/docs/reference/using-api/api-concepts/#receiving-resources-as-tables for details.
        Top-level and per-version columns are mutually exclusive.
        Per-version columns must not all be set to identical values (top-level columns should be used instead).
        If no top-level or per-version columns are specified, a single column displaying the age of the custom resource is used.
        """
        return self.__additional_printer_columns


class CustomResourceDefinitionSpec(types.Object):
    """
    CustomResourceDefinitionSpec describes how a user wants their resource to appear
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        group: str = "",
        names: "CustomResourceDefinitionNames" = None,
        scope: ResourceScope = ResourceScope["NamespaceScoped"],
        validation: "CustomResourceValidation" = None,
        subresources: "CustomResourceSubresources" = None,
        versions: List["CustomResourceDefinitionVersion"] = None,
        additional_printer_columns: List["CustomResourceColumnDefinition"] = None,
        conversion: "CustomResourceConversion" = None,
    ):
        super().__init__()
        self.__group = group
        self.__names = names if names is not None else CustomResourceDefinitionNames()
        self.__scope = scope
        self.__validation = validation
        self.__subresources = subresources
        self.__versions = versions if versions is not None else []
        self.__additional_printer_columns = (
            additional_printer_columns if additional_printer_columns is not None else []
        )
        self.__conversion = (
            conversion if conversion is not None else CustomResourceConversion()
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        group = self.group()
        check_type("group", group, str)
        v["group"] = group
        names = self.names()
        check_type("names", names, "CustomResourceDefinitionNames")
        v["names"] = names
        scope = self.scope()
        check_type("scope", scope, ResourceScope)
        v["scope"] = scope
        validation = self.validation()
        check_type("validation", validation, Optional["CustomResourceValidation"])
        if validation is not None:  # omit empty
            v["validation"] = validation
        subresources = self.subresources()
        check_type("subresources", subresources, Optional["CustomResourceSubresources"])
        if subresources is not None:  # omit empty
            v["subresources"] = subresources
        versions = self.versions()
        check_type(
            "versions", versions, Optional[List["CustomResourceDefinitionVersion"]]
        )
        if versions:  # omit empty
            v["versions"] = versions
        additional_printer_columns = self.additional_printer_columns()
        check_type(
            "additional_printer_columns",
            additional_printer_columns,
            Optional[List["CustomResourceColumnDefinition"]],
        )
        if additional_printer_columns:  # omit empty
            v["additionalPrinterColumns"] = additional_printer_columns
        conversion = self.conversion()
        check_type("conversion", conversion, Optional["CustomResourceConversion"])
        if conversion is not None:  # omit empty
            v["conversion"] = conversion
        return v

    def group(self) -> str:
        """
        group is the API group of the defined custom resource.
        The custom resources are served under `/apis/<group>/...`.
        Must match the name of the CustomResourceDefinition (in the form `<names.plural>.<group>`).
        """
        return self.__group

    def names(self) -> "CustomResourceDefinitionNames":
        """
        names specify the resource and kind names for the custom resource.
        """
        return self.__names

    def scope(self) -> ResourceScope:
        """
        scope indicates whether the defined custom resource is cluster- or namespace-scoped.
        Allowed values are `Cluster` and `Namespaced`. Default is `Namespaced`.
        """
        return self.__scope

    def validation(self) -> Optional["CustomResourceValidation"]:
        """
        validation describes the schema used for validation and pruning of the custom resource.
        If present, this validation schema is used to validate all versions.
        Top-level and per-version schemas are mutually exclusive.
        """
        return self.__validation

    def subresources(self) -> Optional["CustomResourceSubresources"]:
        """
        subresources specify what subresources the defined custom resource has.
        If present, this field configures subresources for all versions.
        Top-level and per-version subresources are mutually exclusive.
        """
        return self.__subresources

    def versions(self) -> Optional[List["CustomResourceDefinitionVersion"]]:
        """
        versions is the list of all API versions of the defined custom resource.
        Optional if `version` is specified.
        The name of the first item in the `versions` list must match the `version` field if `version` and `versions` are both specified.
        Version names are used to compute the order in which served versions are listed in API discovery.
        If the version string is "kube-like", it will sort above non "kube-like" version strings, which are ordered
        lexicographically. "Kube-like" versions start with a "v", then are followed by a number (the major version),
        then optionally the string "alpha" or "beta" and another number (the minor version). These are sorted first
        by GA > beta > alpha (where GA is a version with no suffix such as beta or alpha), and then by comparing
        major version, then minor version. An example sorted list of versions:
        v10, v2, v1, v11beta2, v10beta3, v3beta1, v12alpha1, v11alpha2, foo1, foo10.
        """
        return self.__versions

    def additional_printer_columns(
        self
    ) -> Optional[List["CustomResourceColumnDefinition"]]:
        """
        additionalPrinterColumns specifies additional columns returned in Table output.
        See https://kubernetes.io/docs/reference/using-api/api-concepts/#receiving-resources-as-tables for details.
        If present, this field configures columns for all versions.
        Top-level and per-version columns are mutually exclusive.
        If no top-level or per-version columns are specified, a single column displaying the age of the custom resource is used.
        """
        return self.__additional_printer_columns

    def conversion(self) -> Optional["CustomResourceConversion"]:
        """
        conversion defines conversion settings for the CRD.
        """
        return self.__conversion


class CustomResourceDefinition(base.TypedObject, base.MetadataObject):
    """
    CustomResourceDefinition represents a resource that should be exposed on the API server.  Its name MUST be in the format
    <.spec.name>.<.spec.group>.
    Deprecated in v1.16, planned for removal in v1.19. Use apiextensions.k8s.io/v1 CustomResourceDefinition instead.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "CustomResourceDefinitionSpec" = None,
    ):
        super().__init__(
            api_version="apiextensions.k8s.io/v1beta1",
            kind="CustomResourceDefinition",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else CustomResourceDefinitionSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "CustomResourceDefinitionSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "CustomResourceDefinitionSpec":
        """
        spec describes how the user wants the resources to appear
        """
        return self.__spec
