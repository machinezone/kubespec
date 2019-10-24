# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional, Union

from kubespec.k8s import base
from kubespec.k8s.apimachinery import runtime
from kubespec.k8s.apimachinery.meta import v1 as metav1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


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
        desiredAPIVersion: str = "",
        objects: List["runtime.RawExtension"] = None,
    ):
        super().__init__()
        self.__uid = uid
        self.__desiredAPIVersion = desiredAPIVersion
        self.__objects = objects if objects is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uid = self.uid()
        check_type("uid", uid, str)
        v["uid"] = uid
        desiredAPIVersion = self.desiredAPIVersion()
        check_type("desiredAPIVersion", desiredAPIVersion, str)
        v["desiredAPIVersion"] = desiredAPIVersion
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

    def desiredAPIVersion(self) -> str:
        """
        desiredAPIVersion is the version to convert given objects to. e.g. "myapi.example.com/v1"
        """
        return self.__desiredAPIVersion

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
        convertedObjects: List["runtime.RawExtension"] = None,
        result: "metav1.Status" = None,
    ):
        super().__init__()
        self.__uid = uid
        self.__convertedObjects = (
            convertedObjects if convertedObjects is not None else []
        )
        self.__result = result if result is not None else metav1.Status()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        uid = self.uid()
        check_type("uid", uid, str)
        v["uid"] = uid
        convertedObjects = self.convertedObjects()
        check_type("convertedObjects", convertedObjects, List["runtime.RawExtension"])
        v["convertedObjects"] = convertedObjects
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

    def convertedObjects(self) -> List["runtime.RawExtension"]:
        """
        convertedObjects is the list of converted version of `request.objects` if the `result` is successful, otherwise empty.
        The webhook is expected to set `apiVersion` of these objects to the `request.desiredAPIVersion`. The list
        must also have the same size as the input list with the same objects in the same order (equal kind, metadata.uid, metadata.name and metadata.namespace).
        The webhook is allowed to mutate labels and annotations. Any other change to the metadata is silently ignored.
        """
        return self.__convertedObjects

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
        super().__init__(apiVersion="apiextensions.k8s.io/v1", kind="ConversionReview")
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
        jsonPath: str = "",
    ):
        super().__init__()
        self.__name = name
        self.__type = type
        self.__format = format
        self.__description = description
        self.__priority = priority
        self.__jsonPath = jsonPath

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
        jsonPath = self.jsonPath()
        check_type("jsonPath", jsonPath, str)
        v["jsonPath"] = jsonPath
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

    def jsonPath(self) -> str:
        """
        jsonPath is a simple JSON path (i.e. with array notation) which is evaluated against
        each custom resource to produce the value for this column.
        """
        return self.__jsonPath


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
        caBundle: bytes = None,
    ):
        super().__init__()
        self.__url = url
        self.__service = service
        self.__caBundle = caBundle if caBundle is not None else b""

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
        caBundle = self.caBundle()
        check_type("caBundle", caBundle, Optional[bytes])
        if caBundle:  # omit empty
            v["caBundle"] = caBundle
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

    def caBundle(self) -> Optional[bytes]:
        """
        caBundle is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
        If unspecified, system trust roots on the apiserver are used.
        """
        return self.__caBundle


class WebhookConversion(types.Object):
    """
    WebhookConversion describes how to call a conversion webhook
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        clientConfig: "WebhookClientConfig" = None,
        conversionReviewVersions: List[str] = None,
    ):
        super().__init__()
        self.__clientConfig = clientConfig
        self.__conversionReviewVersions = (
            conversionReviewVersions if conversionReviewVersions is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientConfig = self.clientConfig()
        check_type("clientConfig", clientConfig, Optional["WebhookClientConfig"])
        if clientConfig is not None:  # omit empty
            v["clientConfig"] = clientConfig
        conversionReviewVersions = self.conversionReviewVersions()
        check_type("conversionReviewVersions", conversionReviewVersions, List[str])
        v["conversionReviewVersions"] = conversionReviewVersions
        return v

    def clientConfig(self) -> Optional["WebhookClientConfig"]:
        """
        clientConfig is the instructions for how to call the webhook if strategy is `Webhook`.
        """
        return self.__clientConfig

    def conversionReviewVersions(self) -> List[str]:
        """
        conversionReviewVersions is an ordered list of preferred `ConversionReview`
        versions the Webhook expects. The API server will use the first version in
        the list which it supports. If none of the versions specified in this list
        are supported by API server, conversion will fail for the custom resource.
        If a persisted Webhook configuration specifies allowed versions and does not
        include any versions known to the API Server, calls to the webhook will fail.
        """
        return self.__conversionReviewVersions


class CustomResourceConversion(types.Object):
    """
    CustomResourceConversion describes how to convert different versions of a CR.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        strategy: ConversionStrategyType = ConversionStrategyType["None"],
        webhook: "WebhookConversion" = None,
    ):
        super().__init__()
        self.__strategy = strategy
        self.__webhook = webhook

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        strategy = self.strategy()
        check_type("strategy", strategy, ConversionStrategyType)
        v["strategy"] = strategy
        webhook = self.webhook()
        check_type("webhook", webhook, Optional["WebhookConversion"])
        if webhook is not None:  # omit empty
            v["webhook"] = webhook
        return v

    def strategy(self) -> ConversionStrategyType:
        """
        strategy specifies how custom resources are converted between versions. Allowed values are:
        - `None`: The converter only change the apiVersion and would not touch any other field in the custom resource.
        - `Webhook`: API Server will call to an external webhook to do the conversion. Additional information
          is needed for this option. This requires spec.preserveUnknownFields to be false, and spec.conversion.webhook to be set.
        """
        return self.__strategy

    def webhook(self) -> Optional["WebhookConversion"]:
        """
        webhook describes how to call the conversion webhook. Required when `strategy` is set to `Webhook`.
        """
        return self.__webhook


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
        shortNames: List[str] = None,
        kind: str = "",
        listKind: str = None,
        categories: List[str] = None,
    ):
        super().__init__()
        self.__plural = plural
        self.__singular = singular
        self.__shortNames = shortNames if shortNames is not None else []
        self.__kind = kind
        self.__listKind = listKind
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
        shortNames = self.shortNames()
        check_type("shortNames", shortNames, Optional[List[str]])
        if shortNames:  # omit empty
            v["shortNames"] = shortNames
        kind = self.kind()
        check_type("kind", kind, str)
        v["kind"] = kind
        listKind = self.listKind()
        check_type("listKind", listKind, Optional[str])
        if listKind:  # omit empty
            v["listKind"] = listKind
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

    def shortNames(self) -> Optional[List[str]]:
        """
        shortNames are short names for the resource, exposed in API discovery documents,
        and used by clients to support invocations like `kubectl get <shortname>`.
        It must be all lowercase.
        """
        return self.__shortNames

    def kind(self) -> str:
        """
        kind is the serialized kind of the resource. It is normally CamelCase and singular.
        Custom resource instances will use this value as the `kind` attribute in API calls.
        """
        return self.__kind

    def listKind(self) -> Optional[str]:
        """
        listKind is the serialized kind of the list for this resource. Defaults to "`kind`List".
        """
        return self.__listKind

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
        specReplicasPath: str = "",
        statusReplicasPath: str = "",
        labelSelectorPath: str = None,
    ):
        super().__init__()
        self.__specReplicasPath = specReplicasPath
        self.__statusReplicasPath = statusReplicasPath
        self.__labelSelectorPath = labelSelectorPath

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        specReplicasPath = self.specReplicasPath()
        check_type("specReplicasPath", specReplicasPath, str)
        v["specReplicasPath"] = specReplicasPath
        statusReplicasPath = self.statusReplicasPath()
        check_type("statusReplicasPath", statusReplicasPath, str)
        v["statusReplicasPath"] = statusReplicasPath
        labelSelectorPath = self.labelSelectorPath()
        check_type("labelSelectorPath", labelSelectorPath, Optional[str])
        if labelSelectorPath is not None:  # omit empty
            v["labelSelectorPath"] = labelSelectorPath
        return v

    def specReplicasPath(self) -> str:
        """
        specReplicasPath defines the JSON path inside of a custom resource that corresponds to Scale `spec.replicas`.
        Only JSON paths without the array notation are allowed.
        Must be a JSON Path under `.spec`.
        If there is no value under the given path in the custom resource, the `/scale` subresource will return an error on GET.
        """
        return self.__specReplicasPath

    def statusReplicasPath(self) -> str:
        """
        statusReplicasPath defines the JSON path inside of a custom resource that corresponds to Scale `status.replicas`.
        Only JSON paths without the array notation are allowed.
        Must be a JSON Path under `.status`.
        If there is no value under the given path in the custom resource, the `status.replicas` value in the `/scale` subresource
        will default to 0.
        """
        return self.__statusReplicasPath

    def labelSelectorPath(self) -> Optional[str]:
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
        return self.__labelSelectorPath


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
        exclusiveMaximum: bool = None,
        minimum: float = None,
        exclusiveMinimum: bool = None,
        maxLength: int = None,
        minLength: int = None,
        pattern: str = None,
        maxItems: int = None,
        minItems: int = None,
        uniqueItems: bool = None,
        multipleOf: float = None,
        enum: List["JSON"] = None,
        maxProperties: int = None,
        minProperties: int = None,
        required: List[str] = None,
        items: Union["JSONSchemaProps", List["JSONSchemaProps"]] = None,
        allOf: List["JSONSchemaProps"] = None,
        oneOf: List["JSONSchemaProps"] = None,
        anyOf: List["JSONSchemaProps"] = None,
        not_: "JSONSchemaProps" = None,
        properties: Dict[str, "JSONSchemaProps"] = None,
        additionalProperties: Union["JSONSchemaProps", bool] = None,
        patternProperties: Dict[str, "JSONSchemaProps"] = None,
        dependencies: Dict[str, Union["JSONSchemaProps", List[str]]] = None,
        additionalItems: Union["JSONSchemaProps", bool] = None,
        definitions: Dict[str, "JSONSchemaProps"] = None,
        externalDocs: "ExternalDocumentation" = None,
        example: "JSON" = None,
        nullable: bool = None,
        xKubernetesPreserveUnknownFields: bool = None,
        xKubernetesEmbeddedResource: bool = None,
        xKubernetesIntOrString: bool = None,
        xKubernetesListMapKeys: List[str] = None,
        xKubernetesListType: str = None,
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
        self.__exclusiveMaximum = exclusiveMaximum
        self.__minimum = minimum
        self.__exclusiveMinimum = exclusiveMinimum
        self.__maxLength = maxLength
        self.__minLength = minLength
        self.__pattern = pattern
        self.__maxItems = maxItems
        self.__minItems = minItems
        self.__uniqueItems = uniqueItems
        self.__multipleOf = multipleOf
        self.__enum = enum if enum is not None else []
        self.__maxProperties = maxProperties
        self.__minProperties = minProperties
        self.__required = required if required is not None else []
        self.__items = items
        self.__allOf = allOf if allOf is not None else []
        self.__oneOf = oneOf if oneOf is not None else []
        self.__anyOf = anyOf if anyOf is not None else []
        self.__not_ = not_
        self.__properties = properties if properties is not None else {}
        self.__additionalProperties = additionalProperties
        self.__patternProperties = (
            patternProperties if patternProperties is not None else {}
        )
        self.__dependencies = dependencies if dependencies is not None else {}
        self.__additionalItems = additionalItems
        self.__definitions = definitions if definitions is not None else {}
        self.__externalDocs = externalDocs
        self.__example = example
        self.__nullable = nullable
        self.__xKubernetesPreserveUnknownFields = xKubernetesPreserveUnknownFields
        self.__xKubernetesEmbeddedResource = xKubernetesEmbeddedResource
        self.__xKubernetesIntOrString = xKubernetesIntOrString
        self.__xKubernetesListMapKeys = (
            xKubernetesListMapKeys if xKubernetesListMapKeys is not None else []
        )
        self.__xKubernetesListType = xKubernetesListType

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
        exclusiveMaximum = self.exclusiveMaximum()
        check_type("exclusiveMaximum", exclusiveMaximum, Optional[bool])
        if exclusiveMaximum:  # omit empty
            v["exclusiveMaximum"] = exclusiveMaximum
        minimum = self.minimum()
        check_type("minimum", minimum, Optional[float])
        if minimum is not None:  # omit empty
            v["minimum"] = minimum
        exclusiveMinimum = self.exclusiveMinimum()
        check_type("exclusiveMinimum", exclusiveMinimum, Optional[bool])
        if exclusiveMinimum:  # omit empty
            v["exclusiveMinimum"] = exclusiveMinimum
        maxLength = self.maxLength()
        check_type("maxLength", maxLength, Optional[int])
        if maxLength is not None:  # omit empty
            v["maxLength"] = maxLength
        minLength = self.minLength()
        check_type("minLength", minLength, Optional[int])
        if minLength is not None:  # omit empty
            v["minLength"] = minLength
        pattern = self.pattern()
        check_type("pattern", pattern, Optional[str])
        if pattern:  # omit empty
            v["pattern"] = pattern
        maxItems = self.maxItems()
        check_type("maxItems", maxItems, Optional[int])
        if maxItems is not None:  # omit empty
            v["maxItems"] = maxItems
        minItems = self.minItems()
        check_type("minItems", minItems, Optional[int])
        if minItems is not None:  # omit empty
            v["minItems"] = minItems
        uniqueItems = self.uniqueItems()
        check_type("uniqueItems", uniqueItems, Optional[bool])
        if uniqueItems:  # omit empty
            v["uniqueItems"] = uniqueItems
        multipleOf = self.multipleOf()
        check_type("multipleOf", multipleOf, Optional[float])
        if multipleOf is not None:  # omit empty
            v["multipleOf"] = multipleOf
        enum = self.enum()
        check_type("enum", enum, Optional[List["JSON"]])
        if enum:  # omit empty
            v["enum"] = enum
        maxProperties = self.maxProperties()
        check_type("maxProperties", maxProperties, Optional[int])
        if maxProperties is not None:  # omit empty
            v["maxProperties"] = maxProperties
        minProperties = self.minProperties()
        check_type("minProperties", minProperties, Optional[int])
        if minProperties is not None:  # omit empty
            v["minProperties"] = minProperties
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
        allOf = self.allOf()
        check_type("allOf", allOf, Optional[List["JSONSchemaProps"]])
        if allOf:  # omit empty
            v["allOf"] = allOf
        oneOf = self.oneOf()
        check_type("oneOf", oneOf, Optional[List["JSONSchemaProps"]])
        if oneOf:  # omit empty
            v["oneOf"] = oneOf
        anyOf = self.anyOf()
        check_type("anyOf", anyOf, Optional[List["JSONSchemaProps"]])
        if anyOf:  # omit empty
            v["anyOf"] = anyOf
        not_ = self.not_()
        check_type("not_", not_, Optional["JSONSchemaProps"])
        if not_ is not None:  # omit empty
            v["not"] = not_
        properties = self.properties()
        check_type("properties", properties, Optional[Dict[str, "JSONSchemaProps"]])
        if properties:  # omit empty
            v["properties"] = properties
        additionalProperties = self.additionalProperties()
        check_type(
            "additionalProperties",
            additionalProperties,
            Optional[Union["JSONSchemaProps", bool]],
        )
        if additionalProperties is not None:  # omit empty
            v["additionalProperties"] = additionalProperties
        patternProperties = self.patternProperties()
        check_type(
            "patternProperties",
            patternProperties,
            Optional[Dict[str, "JSONSchemaProps"]],
        )
        if patternProperties:  # omit empty
            v["patternProperties"] = patternProperties
        dependencies = self.dependencies()
        check_type(
            "dependencies",
            dependencies,
            Optional[Dict[str, Union["JSONSchemaProps", List[str]]]],
        )
        if dependencies:  # omit empty
            v["dependencies"] = dependencies
        additionalItems = self.additionalItems()
        check_type(
            "additionalItems", additionalItems, Optional[Union["JSONSchemaProps", bool]]
        )
        if additionalItems is not None:  # omit empty
            v["additionalItems"] = additionalItems
        definitions = self.definitions()
        check_type("definitions", definitions, Optional[Dict[str, "JSONSchemaProps"]])
        if definitions:  # omit empty
            v["definitions"] = definitions
        externalDocs = self.externalDocs()
        check_type("externalDocs", externalDocs, Optional["ExternalDocumentation"])
        if externalDocs is not None:  # omit empty
            v["externalDocs"] = externalDocs
        example = self.example()
        check_type("example", example, Optional["JSON"])
        if example is not None:  # omit empty
            v["example"] = example
        nullable = self.nullable()
        check_type("nullable", nullable, Optional[bool])
        if nullable:  # omit empty
            v["nullable"] = nullable
        xKubernetesPreserveUnknownFields = self.xKubernetesPreserveUnknownFields()
        check_type(
            "xKubernetesPreserveUnknownFields",
            xKubernetesPreserveUnknownFields,
            Optional[bool],
        )
        if xKubernetesPreserveUnknownFields is not None:  # omit empty
            v["x-kubernetes-preserve-unknown-fields"] = xKubernetesPreserveUnknownFields
        xKubernetesEmbeddedResource = self.xKubernetesEmbeddedResource()
        check_type(
            "xKubernetesEmbeddedResource", xKubernetesEmbeddedResource, Optional[bool]
        )
        if xKubernetesEmbeddedResource:  # omit empty
            v["x-kubernetes-embedded-resource"] = xKubernetesEmbeddedResource
        xKubernetesIntOrString = self.xKubernetesIntOrString()
        check_type("xKubernetesIntOrString", xKubernetesIntOrString, Optional[bool])
        if xKubernetesIntOrString:  # omit empty
            v["x-kubernetes-int-or-string"] = xKubernetesIntOrString
        xKubernetesListMapKeys = self.xKubernetesListMapKeys()
        check_type(
            "xKubernetesListMapKeys", xKubernetesListMapKeys, Optional[List[str]]
        )
        if xKubernetesListMapKeys:  # omit empty
            v["x-kubernetes-list-map-keys"] = xKubernetesListMapKeys
        xKubernetesListType = self.xKubernetesListType()
        check_type("xKubernetesListType", xKubernetesListType, Optional[str])
        if xKubernetesListType is not None:  # omit empty
            v["x-kubernetes-list-type"] = xKubernetesListType
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
        return self.__format

    def title(self) -> Optional[str]:
        return self.__title

    def default(self) -> Optional["JSON"]:
        """
        default is a default value for undefined object fields.
        Defaulting is a beta feature under the CustomResourceDefaulting feature gate.
        Defaulting requires spec.preserveUnknownFields to be false.
        """
        return self.__default

    def maximum(self) -> Optional[float]:
        return self.__maximum

    def exclusiveMaximum(self) -> Optional[bool]:
        return self.__exclusiveMaximum

    def minimum(self) -> Optional[float]:
        return self.__minimum

    def exclusiveMinimum(self) -> Optional[bool]:
        return self.__exclusiveMinimum

    def maxLength(self) -> Optional[int]:
        return self.__maxLength

    def minLength(self) -> Optional[int]:
        return self.__minLength

    def pattern(self) -> Optional[str]:
        return self.__pattern

    def maxItems(self) -> Optional[int]:
        return self.__maxItems

    def minItems(self) -> Optional[int]:
        return self.__minItems

    def uniqueItems(self) -> Optional[bool]:
        return self.__uniqueItems

    def multipleOf(self) -> Optional[float]:
        return self.__multipleOf

    def enum(self) -> Optional[List["JSON"]]:
        return self.__enum

    def maxProperties(self) -> Optional[int]:
        return self.__maxProperties

    def minProperties(self) -> Optional[int]:
        return self.__minProperties

    def required(self) -> Optional[List[str]]:
        return self.__required

    def items(self) -> Optional[Union["JSONSchemaProps", List["JSONSchemaProps"]]]:
        return self.__items

    def allOf(self) -> Optional[List["JSONSchemaProps"]]:
        return self.__allOf

    def oneOf(self) -> Optional[List["JSONSchemaProps"]]:
        return self.__oneOf

    def anyOf(self) -> Optional[List["JSONSchemaProps"]]:
        return self.__anyOf

    def not_(self) -> Optional["JSONSchemaProps"]:
        return self.__not_

    def properties(self) -> Optional[Dict[str, "JSONSchemaProps"]]:
        return self.__properties

    def additionalProperties(self) -> Optional[Union["JSONSchemaProps", bool]]:
        return self.__additionalProperties

    def patternProperties(self) -> Optional[Dict[str, "JSONSchemaProps"]]:
        return self.__patternProperties

    def dependencies(self) -> Optional[Dict[str, Union["JSONSchemaProps", List[str]]]]:
        return self.__dependencies

    def additionalItems(self) -> Optional[Union["JSONSchemaProps", bool]]:
        return self.__additionalItems

    def definitions(self) -> Optional[Dict[str, "JSONSchemaProps"]]:
        return self.__definitions

    def externalDocs(self) -> Optional["ExternalDocumentation"]:
        return self.__externalDocs

    def example(self) -> Optional["JSON"]:
        return self.__example

    def nullable(self) -> Optional[bool]:
        return self.__nullable

    def xKubernetesPreserveUnknownFields(self) -> Optional[bool]:
        """
        x-kubernetes-preserve-unknown-fields stops the API server
        decoding step from pruning fields which are not specified
        in the validation schema. This affects fields recursively,
        but switches back to normal pruning behaviour if nested
        properties or additionalProperties are specified in the schema.
        This can either be true or undefined. False is forbidden.
        """
        return self.__xKubernetesPreserveUnknownFields

    def xKubernetesEmbeddedResource(self) -> Optional[bool]:
        """
        x-kubernetes-embedded-resource defines that the value is an
        embedded Kubernetes runtime.Object, with TypeMeta and
        ObjectMeta. The type must be object. It is allowed to further
        restrict the embedded object. kind, apiVersion and metadata
        are validated automatically. x-kubernetes-preserve-unknown-fields
        is allowed to be true, but does not have to be if the object
        is fully specified (up to kind, apiVersion, metadata).
        """
        return self.__xKubernetesEmbeddedResource

    def xKubernetesIntOrString(self) -> Optional[bool]:
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
        return self.__xKubernetesIntOrString

    def xKubernetesListMapKeys(self) -> Optional[List[str]]:
        """
        x-kubernetes-list-map-keys annotates an array with the x-kubernetes-list-type `map` by specifying the keys used
        as the index of the map.
        
        This tag MUST only be used on lists that have the "x-kubernetes-list-type"
        extension set to "map". Also, the values specified for this attribute must
        be a scalar typed field of the child structure (no nesting is supported).
        """
        return self.__xKubernetesListMapKeys

    def xKubernetesListType(self) -> Optional[str]:
        """
        x-kubernetes-list-type annotates an array to further describe its topology.
        This extension must only be used on lists and may have 3 possible values:
        
        1) `atomic`: the list is treated as a single entity, like a scalar.
             Atomic lists will be entirely replaced when updated. This extension
             may be used on any type of list (struct, scalar, ...).
        2) `set`:
             Sets are lists that must not have multiple items with the same value. Each
             value must be a scalar (or another atomic type).
        3) `map`:
             These lists are like maps in that their elements have a non-index key
             used to identify them. Order is preserved upon merge. The map tag
             must only be used on a list with elements of type object.
        Defaults to atomic for arrays.
        """
        return self.__xKubernetesListType


class CustomResourceValidation(types.Object):
    """
    CustomResourceValidation is a list of validation methods for CustomResources.
    """

    @context.scoped
    @typechecked
    def __init__(self, openAPIV3Schema: "JSONSchemaProps" = None):
        super().__init__()
        self.__openAPIV3Schema = openAPIV3Schema

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        openAPIV3Schema = self.openAPIV3Schema()
        check_type("openAPIV3Schema", openAPIV3Schema, Optional["JSONSchemaProps"])
        if openAPIV3Schema is not None:  # omit empty
            v["openAPIV3Schema"] = openAPIV3Schema
        return v

    def openAPIV3Schema(self) -> Optional["JSONSchemaProps"]:
        """
        openAPIV3Schema is the OpenAPI v3 schema to use for validation and pruning.
        """
        return self.__openAPIV3Schema


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
        additionalPrinterColumns: List["CustomResourceColumnDefinition"] = None,
    ):
        super().__init__()
        self.__name = name
        self.__served = served
        self.__storage = storage
        self.__schema = schema
        self.__subresources = subresources
        self.__additionalPrinterColumns = (
            additionalPrinterColumns if additionalPrinterColumns is not None else []
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
        additionalPrinterColumns = self.additionalPrinterColumns()
        check_type(
            "additionalPrinterColumns",
            additionalPrinterColumns,
            Optional[List["CustomResourceColumnDefinition"]],
        )
        if additionalPrinterColumns:  # omit empty
            v["additionalPrinterColumns"] = additionalPrinterColumns
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
        schema describes the schema used for validation, pruning, and defaulting of this version of the custom resource.
        """
        return self.__schema

    def subresources(self) -> Optional["CustomResourceSubresources"]:
        """
        subresources specify what subresources this version of the defined custom resource have.
        """
        return self.__subresources

    def additionalPrinterColumns(
        self
    ) -> Optional[List["CustomResourceColumnDefinition"]]:
        """
        additionalPrinterColumns specifies additional columns returned in Table output.
        See https://kubernetes.io/docs/reference/using-api/api-concepts/#receiving-resources-as-tables for details.
        If no columns are specified, a single column displaying the age of the custom resource is used.
        """
        return self.__additionalPrinterColumns


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
        versions: List["CustomResourceDefinitionVersion"] = None,
        conversion: "CustomResourceConversion" = None,
        preserveUnknownFields: bool = None,
    ):
        super().__init__()
        self.__group = group
        self.__names = names if names is not None else CustomResourceDefinitionNames()
        self.__scope = scope
        self.__versions = versions if versions is not None else []
        self.__conversion = (
            conversion if conversion is not None else CustomResourceConversion()
        )
        self.__preserveUnknownFields = preserveUnknownFields

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
        versions = self.versions()
        check_type("versions", versions, List["CustomResourceDefinitionVersion"])
        v["versions"] = versions
        conversion = self.conversion()
        check_type("conversion", conversion, Optional["CustomResourceConversion"])
        if conversion is not None:  # omit empty
            v["conversion"] = conversion
        preserveUnknownFields = self.preserveUnknownFields()
        check_type("preserveUnknownFields", preserveUnknownFields, Optional[bool])
        if preserveUnknownFields:  # omit empty
            v["preserveUnknownFields"] = preserveUnknownFields
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

    def versions(self) -> List["CustomResourceDefinitionVersion"]:
        """
        versions is the list of all API versions of the defined custom resource.
        Version names are used to compute the order in which served versions are listed in API discovery.
        If the version string is "kube-like", it will sort above non "kube-like" version strings, which are ordered
        lexicographically. "Kube-like" versions start with a "v", then are followed by a number (the major version),
        then optionally the string "alpha" or "beta" and another number (the minor version). These are sorted first
        by GA > beta > alpha (where GA is a version with no suffix such as beta or alpha), and then by comparing
        major version, then minor version. An example sorted list of versions:
        v10, v2, v1, v11beta2, v10beta3, v3beta1, v12alpha1, v11alpha2, foo1, foo10.
        """
        return self.__versions

    def conversion(self) -> Optional["CustomResourceConversion"]:
        """
        conversion defines conversion settings for the CRD.
        """
        return self.__conversion

    def preserveUnknownFields(self) -> Optional[bool]:
        """
        preserveUnknownFields indicates that object fields which are not specified
        in the OpenAPI schema should be preserved when persisting to storage.
        apiVersion, kind, metadata and known fields inside metadata are always preserved.
        This field is deprecated in favor of setting `x-preserve-unknown-fields` to true in `spec.versions[*].schema.openAPIV3Schema`.
        See https://kubernetes.io/docs/tasks/access-kubernetes-api/custom-resources/custom-resource-definitions/#pruning-versus-preserving-unknown-fields for details.
        """
        return self.__preserveUnknownFields


class CustomResourceDefinition(base.TypedObject, base.MetadataObject):
    """
    CustomResourceDefinition represents a resource that should be exposed on the API server.  Its name MUST be in the format
    <.spec.name>.<.spec.group>.
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
            apiVersion="apiextensions.k8s.io/v1",
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
