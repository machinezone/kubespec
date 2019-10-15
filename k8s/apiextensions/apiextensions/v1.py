# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional, Union

from k8s import base
from k8s.apimachinery import runtime
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import typechecked


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


# ConversionRequest describes the conversion request parameters.
class ConversionRequest(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        uid: str = "",
        desiredAPIVersion: str = "",
        objects: List["runtime.RawExtension"] = None,
    ):
        super().__init__(**{})
        self.__uid = uid
        self.__desiredAPIVersion = desiredAPIVersion
        self.__objects = objects if objects is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["uid"] = self.uid()
        v["desiredAPIVersion"] = self.desiredAPIVersion()
        v["objects"] = self.objects()
        return v

    # uid is an identifier for the individual request/response. It allows distinguishing instances of requests which are
    # otherwise identical (parallel requests, etc).
    # The UID is meant to track the round trip (request/response) between the Kubernetes API server and the webhook, not the user request.
    # It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
    @typechecked
    def uid(self) -> str:
        return self.__uid

    # desiredAPIVersion is the version to convert given objects to. e.g. "myapi.example.com/v1"
    @typechecked
    def desiredAPIVersion(self) -> str:
        return self.__desiredAPIVersion

    # objects is the list of custom resource objects to be converted.
    @typechecked
    def objects(self) -> List["runtime.RawExtension"]:
        return self.__objects


# ConversionResponse describes a conversion response.
class ConversionResponse(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        uid: str = "",
        convertedObjects: List["runtime.RawExtension"] = None,
        result: "metav1.Status" = None,
    ):
        super().__init__(**{})
        self.__uid = uid
        self.__convertedObjects = (
            convertedObjects if convertedObjects is not None else []
        )
        self.__result = result if result is not None else metav1.Status()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["uid"] = self.uid()
        v["convertedObjects"] = self.convertedObjects()
        v["result"] = self.result()
        return v

    # uid is an identifier for the individual request/response.
    # This should be copied over from the corresponding `request.uid`.
    @typechecked
    def uid(self) -> str:
        return self.__uid

    # convertedObjects is the list of converted version of `request.objects` if the `result` is successful, otherwise empty.
    # The webhook is expected to set `apiVersion` of these objects to the `request.desiredAPIVersion`. The list
    # must also have the same size as the input list with the same objects in the same order (equal kind, metadata.uid, metadata.name and metadata.namespace).
    # The webhook is allowed to mutate labels and annotations. Any other change to the metadata is silently ignored.
    @typechecked
    def convertedObjects(self) -> List["runtime.RawExtension"]:
        return self.__convertedObjects

    # result contains the result of conversion with extra details if the conversion failed. `result.status` determines if
    # the conversion failed or succeeded. The `result.status` field is required and represents the success or failure of the
    # conversion. A successful conversion must set `result.status` to `Success`. A failed conversion must set
    # `result.status` to `Failure` and provide more details in `result.message` and return http status 200. The `result.message`
    # will be used to construct an error message for the end user.
    @typechecked
    def result(self) -> "metav1.Status":
        return self.__result


# ConversionReview describes a conversion request/response.
class ConversionReview(base.TypedObject):
    @context.scoped
    @typechecked
    def __init__(
        self, request: ConversionRequest = None, response: ConversionResponse = None
    ):
        super().__init__(
            **{"apiVersion": "apiextensions.k8s.io/v1", "kind": "ConversionReview"}
        )
        self.__request = request
        self.__response = response

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        request = self.request()
        if request is not None:  # omit empty
            v["request"] = request
        response = self.response()
        if response is not None:  # omit empty
            v["response"] = response
        return v

    # request describes the attributes for the conversion request.
    @typechecked
    def request(self) -> Optional[ConversionRequest]:
        return self.__request

    # response describes the attributes for the conversion response.
    @typechecked
    def response(self) -> Optional[ConversionResponse]:
        return self.__response


# CustomResourceColumnDefinition specifies a column for server side printing.
class CustomResourceColumnDefinition(types.Object):
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
        super().__init__(**{})
        self.__name = name
        self.__type = type
        self.__format = format
        self.__description = description
        self.__priority = priority
        self.__jsonPath = jsonPath

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        v["type"] = self.type()
        format = self.format()
        if format:  # omit empty
            v["format"] = format
        description = self.description()
        if description:  # omit empty
            v["description"] = description
        priority = self.priority()
        if priority:  # omit empty
            v["priority"] = priority
        v["jsonPath"] = self.jsonPath()
        return v

    # name is a human readable name for the column.
    @typechecked
    def name(self) -> str:
        return self.__name

    # type is an OpenAPI type definition for this column.
    # See https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types for details.
    @typechecked
    def type(self) -> str:
        return self.__type

    # format is an optional OpenAPI type definition for this column. The 'name' format is applied
    # to the primary identifier column to assist in clients identifying column is the resource name.
    # See https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types for details.
    @typechecked
    def format(self) -> Optional[str]:
        return self.__format

    # description is a human readable description of this column.
    @typechecked
    def description(self) -> Optional[str]:
        return self.__description

    # priority is an integer defining the relative importance of this column compared to others. Lower
    # numbers are considered higher priority. Columns that may be omitted in limited space scenarios
    # should be given a priority greater than 0.
    @typechecked
    def priority(self) -> Optional[int]:
        return self.__priority

    # jsonPath is a simple JSON path (i.e. with array notation) which is evaluated against
    # each custom resource to produce the value for this column.
    @typechecked
    def jsonPath(self) -> str:
        return self.__jsonPath


# ServiceReference holds a reference to Service.legacy.k8s.io
class ServiceReference(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, namespace: str = "", name: str = "", path: str = None, port: int = None
    ):
        super().__init__(**{})
        self.__namespace = namespace
        self.__name = name
        self.__path = path
        self.__port = port if port is not None else 443

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["namespace"] = self.namespace()
        v["name"] = self.name()
        path = self.path()
        if path is not None:  # omit empty
            v["path"] = path
        port = self.port()
        if port is not None:  # omit empty
            v["port"] = port
        return v

    # namespace is the namespace of the service.
    # Required
    @typechecked
    def namespace(self) -> str:
        return self.__namespace

    # name is the name of the service.
    # Required
    @typechecked
    def name(self) -> str:
        return self.__name

    # path is an optional URL path at which the webhook will be contacted.
    @typechecked
    def path(self) -> Optional[str]:
        return self.__path

    # port is an optional service port at which the webhook will be contacted.
    # `port` should be a valid port number (1-65535, inclusive).
    # Defaults to 443 for backward compatibility.
    @typechecked
    def port(self) -> Optional[int]:
        return self.__port


# WebhookClientConfig contains the information to make a TLS connection with the webhook.
class WebhookClientConfig(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self, url: str = None, service: ServiceReference = None, caBundle: bytes = None
    ):
        super().__init__(**{})
        self.__url = url
        self.__service = service
        self.__caBundle = caBundle if caBundle is not None else b""

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        url = self.url()
        if url is not None:  # omit empty
            v["url"] = url
        service = self.service()
        if service is not None:  # omit empty
            v["service"] = service
        caBundle = self.caBundle()
        if caBundle:  # omit empty
            v["caBundle"] = caBundle
        return v

    # url gives the location of the webhook, in standard URL form
    # (`scheme://host:port/path`). Exactly one of `url` or `service`
    # must be specified.
    #
    # The `host` should not refer to a service running in the cluster; use
    # the `service` field instead. The host might be resolved via external
    # DNS in some apiservers (e.g., `kube-apiserver` cannot resolve
    # in-cluster DNS as that would be a layering violation). `host` may
    # also be an IP address.
    #
    # Please note that using `localhost` or `127.0.0.1` as a `host` is
    # risky unless you take great care to run this webhook on all hosts
    # which run an apiserver which might need to make calls to this
    # webhook. Such installs are likely to be non-portable, i.e., not easy
    # to turn up in a new cluster.
    #
    # The scheme must be "https"; the URL must begin with "https://".
    #
    # A path is optional, and if present may be any string permissible in
    # a URL. You may use the path to pass an arbitrary string to the
    # webhook, for example, a cluster identifier.
    #
    # Attempting to use a user or basic auth e.g. "user:password@" is not
    # allowed. Fragments ("#...") and query parameters ("?...") are not
    # allowed, either.
    @typechecked
    def url(self) -> Optional[str]:
        return self.__url

    # service is a reference to the service for this webhook. Either
    # service or url must be specified.
    #
    # If the webhook is running within the cluster, then you should use `service`.
    @typechecked
    def service(self) -> Optional[ServiceReference]:
        return self.__service

    # caBundle is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
    # If unspecified, system trust roots on the apiserver are used.
    @typechecked
    def caBundle(self) -> Optional[bytes]:
        return self.__caBundle


# WebhookConversion describes how to call a conversion webhook
class WebhookConversion(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        clientConfig: WebhookClientConfig = None,
        conversionReviewVersions: List[str] = None,
    ):
        super().__init__(**{})
        self.__clientConfig = clientConfig
        self.__conversionReviewVersions = (
            conversionReviewVersions if conversionReviewVersions is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        clientConfig = self.clientConfig()
        if clientConfig is not None:  # omit empty
            v["clientConfig"] = clientConfig
        v["conversionReviewVersions"] = self.conversionReviewVersions()
        return v

    # clientConfig is the instructions for how to call the webhook if strategy is `Webhook`.
    @typechecked
    def clientConfig(self) -> Optional[WebhookClientConfig]:
        return self.__clientConfig

    # conversionReviewVersions is an ordered list of preferred `ConversionReview`
    # versions the Webhook expects. The API server will use the first version in
    # the list which it supports. If none of the versions specified in this list
    # are supported by API server, conversion will fail for the custom resource.
    # If a persisted Webhook configuration specifies allowed versions and does not
    # include any versions known to the API Server, calls to the webhook will fail.
    @typechecked
    def conversionReviewVersions(self) -> List[str]:
        return self.__conversionReviewVersions


# CustomResourceConversion describes how to convert different versions of a CR.
class CustomResourceConversion(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        strategy: ConversionStrategyType = ConversionStrategyType["None"],
        webhook: WebhookConversion = None,
    ):
        super().__init__(**{})
        self.__strategy = strategy
        self.__webhook = webhook

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["strategy"] = self.strategy()
        webhook = self.webhook()
        if webhook is not None:  # omit empty
            v["webhook"] = webhook
        return v

    # strategy specifies how custom resources are converted between versions. Allowed values are:
    # - `None`: The converter only change the apiVersion and would not touch any other field in the custom resource.
    # - `Webhook`: API Server will call to an external webhook to do the conversion. Additional information
    #   is needed for this option. This requires spec.preserveUnknownFields to be false, and spec.conversion.webhook to be set.
    @typechecked
    def strategy(self) -> ConversionStrategyType:
        return self.__strategy

    # webhook describes how to call the conversion webhook. Required when `strategy` is set to `Webhook`.
    @typechecked
    def webhook(self) -> Optional[WebhookConversion]:
        return self.__webhook


# CustomResourceDefinitionNames indicates the names to serve this CustomResourceDefinition
class CustomResourceDefinitionNames(types.Object):
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
        super().__init__(**{})
        self.__plural = plural
        self.__singular = singular
        self.__shortNames = shortNames if shortNames is not None else []
        self.__kind = kind
        self.__listKind = listKind
        self.__categories = categories if categories is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["plural"] = self.plural()
        singular = self.singular()
        if singular:  # omit empty
            v["singular"] = singular
        shortNames = self.shortNames()
        if shortNames:  # omit empty
            v["shortNames"] = shortNames
        v["kind"] = self.kind()
        listKind = self.listKind()
        if listKind:  # omit empty
            v["listKind"] = listKind
        categories = self.categories()
        if categories:  # omit empty
            v["categories"] = categories
        return v

    # plural is the plural name of the resource to serve.
    # The custom resources are served under `/apis/<group>/<version>/.../<plural>`.
    # Must match the name of the CustomResourceDefinition (in the form `<names.plural>.<group>`).
    # Must be all lowercase.
    @typechecked
    def plural(self) -> str:
        return self.__plural

    # singular is the singular name of the resource. It must be all lowercase. Defaults to lowercased `kind`.
    @typechecked
    def singular(self) -> Optional[str]:
        return self.__singular

    # shortNames are short names for the resource, exposed in API discovery documents,
    # and used by clients to support invocations like `kubectl get <shortname>`.
    # It must be all lowercase.
    @typechecked
    def shortNames(self) -> Optional[List[str]]:
        return self.__shortNames

    # kind is the serialized kind of the resource. It is normally CamelCase and singular.
    # Custom resource instances will use this value as the `kind` attribute in API calls.
    @typechecked
    def kind(self) -> str:
        return self.__kind

    # listKind is the serialized kind of the list for this resource. Defaults to "`kind`List".
    @typechecked
    def listKind(self) -> Optional[str]:
        return self.__listKind

    # categories is a list of grouped resources this custom resource belongs to (e.g. 'all').
    # This is published in API discovery documents, and used by clients to support invocations like
    # `kubectl get all`.
    @typechecked
    def categories(self) -> Optional[List[str]]:
        return self.__categories


# CustomResourceSubresourceScale defines how to serve the scale subresource for CustomResources.
class CustomResourceSubresourceScale(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        specReplicasPath: str = "",
        statusReplicasPath: str = "",
        labelSelectorPath: str = None,
    ):
        super().__init__(**{})
        self.__specReplicasPath = specReplicasPath
        self.__statusReplicasPath = statusReplicasPath
        self.__labelSelectorPath = labelSelectorPath

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["specReplicasPath"] = self.specReplicasPath()
        v["statusReplicasPath"] = self.statusReplicasPath()
        labelSelectorPath = self.labelSelectorPath()
        if labelSelectorPath is not None:  # omit empty
            v["labelSelectorPath"] = labelSelectorPath
        return v

    # specReplicasPath defines the JSON path inside of a custom resource that corresponds to Scale `spec.replicas`.
    # Only JSON paths without the array notation are allowed.
    # Must be a JSON Path under `.spec`.
    # If there is no value under the given path in the custom resource, the `/scale` subresource will return an error on GET.
    @typechecked
    def specReplicasPath(self) -> str:
        return self.__specReplicasPath

    # statusReplicasPath defines the JSON path inside of a custom resource that corresponds to Scale `status.replicas`.
    # Only JSON paths without the array notation are allowed.
    # Must be a JSON Path under `.status`.
    # If there is no value under the given path in the custom resource, the `status.replicas` value in the `/scale` subresource
    # will default to 0.
    @typechecked
    def statusReplicasPath(self) -> str:
        return self.__statusReplicasPath

    # labelSelectorPath defines the JSON path inside of a custom resource that corresponds to Scale `status.selector`.
    # Only JSON paths without the array notation are allowed.
    # Must be a JSON Path under `.status` or `.spec`.
    # Must be set to work with HorizontalPodAutoscaler.
    # The field pointed by this JSON path must be a string field (not a complex selector struct)
    # which contains a serialized label selector in string form.
    # More info: https://kubernetes.io/docs/tasks/access-kubernetes-api/custom-resources/custom-resource-definitions#scale-subresource
    # If there is no value under the given path in the custom resource, the `status.selector` value in the `/scale`
    # subresource will default to the empty string.
    @typechecked
    def labelSelectorPath(self) -> Optional[str]:
        return self.__labelSelectorPath


# CustomResourceSubresourceStatus defines how to serve the status subresource for CustomResources.
# Status is represented by the `.status` JSON path inside of a CustomResource. When set,
# * exposes a /status subresource for the custom resource
# * PUT requests to the /status subresource take a custom resource object, and ignore changes to anything except the status stanza
# * PUT/POST/PATCH requests to the custom resource ignore changes to the status stanza
class CustomResourceSubresourceStatus(types.Object):
    pass  # FIXME


# CustomResourceSubresources defines the status and scale subresources for CustomResources.
class CustomResourceSubresources(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        status: CustomResourceSubresourceStatus = None,
        scale: CustomResourceSubresourceScale = None,
    ):
        super().__init__(**{})
        self.__status = status
        self.__scale = scale

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        status = self.status()
        if status is not None:  # omit empty
            v["status"] = status
        scale = self.scale()
        if scale is not None:  # omit empty
            v["scale"] = scale
        return v

    # status indicates the custom resource should serve a `/status` subresource.
    # When enabled:
    # 1. requests to the custom resource primary endpoint ignore changes to the `status` stanza of the object.
    # 2. requests to the custom resource `/status` subresource ignore changes to anything other than the `status` stanza of the object.
    @typechecked
    def status(self) -> Optional[CustomResourceSubresourceStatus]:
        return self.__status

    # scale indicates the custom resource should serve a `/scale` subresource that returns an `autoscaling/v1` Scale object.
    @typechecked
    def scale(self) -> Optional[CustomResourceSubresourceScale]:
        return self.__scale


# ExternalDocumentation allows referencing an external resource for extended documentation.
class ExternalDocumentation(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, description: str = None, url: str = None):
        super().__init__(**{})
        self.__description = description
        self.__url = url

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        description = self.description()
        if description:  # omit empty
            v["description"] = description
        url = self.url()
        if url:  # omit empty
            v["url"] = url
        return v

    @typechecked
    def description(self) -> Optional[str]:
        return self.__description

    @typechecked
    def url(self) -> Optional[str]:
        return self.__url


# JSON represents any valid JSON value.
# These types are supported: bool, int64, float64, string, []interface{}, map[string]interface{} and nil.
class JSON(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, raw: bytes = None):
        super().__init__(**{})
        self.__raw = raw if raw is not None else b""

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["Raw"] = self.raw()
        return v

    @typechecked
    def raw(self) -> bytes:
        return self.__raw


# JSONSchemaProps is a JSON-Schema following Specification Draft 4 (http://json-schema.org/).
class JSONSchemaProps(types.Object):
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
        default: JSON = None,
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
        enum: List[JSON] = None,
        maxProperties: int = None,
        minProperties: int = None,
        required: List[str] = None,
        items: Union[JSONSchemaProps, List[JSONSchemaProps]] = None,
        allOf: List[JSONSchemaProps] = None,
        oneOf: List[JSONSchemaProps] = None,
        anyOf: List[JSONSchemaProps] = None,
        not_: JSONSchemaProps = None,
        properties: Dict[str, JSONSchemaProps] = None,
        additionalProperties: Union[JSONSchemaProps, bool] = None,
        patternProperties: Dict[str, JSONSchemaProps] = None,
        dependencies: Dict[str, Union[JSONSchemaProps, List[str]]] = None,
        additionalItems: Union[JSONSchemaProps, bool] = None,
        definitions: Dict[str, JSONSchemaProps] = None,
        externalDocs: ExternalDocumentation = None,
        example: JSON = None,
        nullable: bool = None,
        xKubernetesPreserveUnknownFields: bool = None,
        xKubernetesEmbeddedResource: bool = None,
        xKubernetesIntOrString: bool = None,
        xKubernetesListMapKeys: List[str] = None,
        xKubernetesListType: str = None,
    ):
        super().__init__(**{})
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
        if id:  # omit empty
            v["id"] = id
        schema = self.schema()
        if schema:  # omit empty
            v["$schema"] = schema
        ref = self.ref()
        if ref is not None:  # omit empty
            v["$ref"] = ref
        description = self.description()
        if description:  # omit empty
            v["description"] = description
        type = self.type()
        if type:  # omit empty
            v["type"] = type
        format = self.format()
        if format:  # omit empty
            v["format"] = format
        title = self.title()
        if title:  # omit empty
            v["title"] = title
        default = self.default()
        if default is not None:  # omit empty
            v["default"] = default
        maximum = self.maximum()
        if maximum is not None:  # omit empty
            v["maximum"] = maximum
        exclusiveMaximum = self.exclusiveMaximum()
        if exclusiveMaximum:  # omit empty
            v["exclusiveMaximum"] = exclusiveMaximum
        minimum = self.minimum()
        if minimum is not None:  # omit empty
            v["minimum"] = minimum
        exclusiveMinimum = self.exclusiveMinimum()
        if exclusiveMinimum:  # omit empty
            v["exclusiveMinimum"] = exclusiveMinimum
        maxLength = self.maxLength()
        if maxLength is not None:  # omit empty
            v["maxLength"] = maxLength
        minLength = self.minLength()
        if minLength is not None:  # omit empty
            v["minLength"] = minLength
        pattern = self.pattern()
        if pattern:  # omit empty
            v["pattern"] = pattern
        maxItems = self.maxItems()
        if maxItems is not None:  # omit empty
            v["maxItems"] = maxItems
        minItems = self.minItems()
        if minItems is not None:  # omit empty
            v["minItems"] = minItems
        uniqueItems = self.uniqueItems()
        if uniqueItems:  # omit empty
            v["uniqueItems"] = uniqueItems
        multipleOf = self.multipleOf()
        if multipleOf is not None:  # omit empty
            v["multipleOf"] = multipleOf
        enum = self.enum()
        if enum:  # omit empty
            v["enum"] = enum
        maxProperties = self.maxProperties()
        if maxProperties is not None:  # omit empty
            v["maxProperties"] = maxProperties
        minProperties = self.minProperties()
        if minProperties is not None:  # omit empty
            v["minProperties"] = minProperties
        required = self.required()
        if required:  # omit empty
            v["required"] = required
        items = self.items()
        if items is not None:  # omit empty
            v["items"] = items
        allOf = self.allOf()
        if allOf:  # omit empty
            v["allOf"] = allOf
        oneOf = self.oneOf()
        if oneOf:  # omit empty
            v["oneOf"] = oneOf
        anyOf = self.anyOf()
        if anyOf:  # omit empty
            v["anyOf"] = anyOf
        not_ = self.not_()
        if not_ is not None:  # omit empty
            v["not"] = not_
        properties = self.properties()
        if properties:  # omit empty
            v["properties"] = properties
        additionalProperties = self.additionalProperties()
        if additionalProperties is not None:  # omit empty
            v["additionalProperties"] = additionalProperties
        patternProperties = self.patternProperties()
        if patternProperties:  # omit empty
            v["patternProperties"] = patternProperties
        dependencies = self.dependencies()
        if dependencies:  # omit empty
            v["dependencies"] = dependencies
        additionalItems = self.additionalItems()
        if additionalItems is not None:  # omit empty
            v["additionalItems"] = additionalItems
        definitions = self.definitions()
        if definitions:  # omit empty
            v["definitions"] = definitions
        externalDocs = self.externalDocs()
        if externalDocs is not None:  # omit empty
            v["externalDocs"] = externalDocs
        example = self.example()
        if example is not None:  # omit empty
            v["example"] = example
        nullable = self.nullable()
        if nullable:  # omit empty
            v["nullable"] = nullable
        xKubernetesPreserveUnknownFields = self.xKubernetesPreserveUnknownFields()
        if xKubernetesPreserveUnknownFields is not None:  # omit empty
            v["x-kubernetes-preserve-unknown-fields"] = xKubernetesPreserveUnknownFields
        xKubernetesEmbeddedResource = self.xKubernetesEmbeddedResource()
        if xKubernetesEmbeddedResource:  # omit empty
            v["x-kubernetes-embedded-resource"] = xKubernetesEmbeddedResource
        xKubernetesIntOrString = self.xKubernetesIntOrString()
        if xKubernetesIntOrString:  # omit empty
            v["x-kubernetes-int-or-string"] = xKubernetesIntOrString
        xKubernetesListMapKeys = self.xKubernetesListMapKeys()
        if xKubernetesListMapKeys:  # omit empty
            v["x-kubernetes-list-map-keys"] = xKubernetesListMapKeys
        xKubernetesListType = self.xKubernetesListType()
        if xKubernetesListType is not None:  # omit empty
            v["x-kubernetes-list-type"] = xKubernetesListType
        return v

    @typechecked
    def id(self) -> Optional[str]:
        return self.__id

    @typechecked
    def schema(self) -> Optional[str]:
        return self.__schema

    @typechecked
    def ref(self) -> Optional[str]:
        return self.__ref

    @typechecked
    def description(self) -> Optional[str]:
        return self.__description

    @typechecked
    def type(self) -> Optional[str]:
        return self.__type

    @typechecked
    def format(self) -> Optional[str]:
        return self.__format

    @typechecked
    def title(self) -> Optional[str]:
        return self.__title

    # default is a default value for undefined object fields.
    # Defaulting is a beta feature under the CustomResourceDefaulting feature gate.
    # Defaulting requires spec.preserveUnknownFields to be false.
    @typechecked
    def default(self) -> Optional[JSON]:
        return self.__default

    @typechecked
    def maximum(self) -> Optional[float]:
        return self.__maximum

    @typechecked
    def exclusiveMaximum(self) -> Optional[bool]:
        return self.__exclusiveMaximum

    @typechecked
    def minimum(self) -> Optional[float]:
        return self.__minimum

    @typechecked
    def exclusiveMinimum(self) -> Optional[bool]:
        return self.__exclusiveMinimum

    @typechecked
    def maxLength(self) -> Optional[int]:
        return self.__maxLength

    @typechecked
    def minLength(self) -> Optional[int]:
        return self.__minLength

    @typechecked
    def pattern(self) -> Optional[str]:
        return self.__pattern

    @typechecked
    def maxItems(self) -> Optional[int]:
        return self.__maxItems

    @typechecked
    def minItems(self) -> Optional[int]:
        return self.__minItems

    @typechecked
    def uniqueItems(self) -> Optional[bool]:
        return self.__uniqueItems

    @typechecked
    def multipleOf(self) -> Optional[float]:
        return self.__multipleOf

    @typechecked
    def enum(self) -> Optional[List[JSON]]:
        return self.__enum

    @typechecked
    def maxProperties(self) -> Optional[int]:
        return self.__maxProperties

    @typechecked
    def minProperties(self) -> Optional[int]:
        return self.__minProperties

    @typechecked
    def required(self) -> Optional[List[str]]:
        return self.__required

    @typechecked
    def items(self) -> Optional[Union[JSONSchemaProps, List[JSONSchemaProps]]]:
        return self.__items

    @typechecked
    def allOf(self) -> Optional[List[JSONSchemaProps]]:
        return self.__allOf

    @typechecked
    def oneOf(self) -> Optional[List[JSONSchemaProps]]:
        return self.__oneOf

    @typechecked
    def anyOf(self) -> Optional[List[JSONSchemaProps]]:
        return self.__anyOf

    @typechecked
    def not_(self) -> Optional[JSONSchemaProps]:
        return self.__not_

    @typechecked
    def properties(self) -> Optional[Dict[str, JSONSchemaProps]]:
        return self.__properties

    @typechecked
    def additionalProperties(self) -> Optional[Union[JSONSchemaProps, bool]]:
        return self.__additionalProperties

    @typechecked
    def patternProperties(self) -> Optional[Dict[str, JSONSchemaProps]]:
        return self.__patternProperties

    @typechecked
    def dependencies(self) -> Optional[Dict[str, Union[JSONSchemaProps, List[str]]]]:
        return self.__dependencies

    @typechecked
    def additionalItems(self) -> Optional[Union[JSONSchemaProps, bool]]:
        return self.__additionalItems

    @typechecked
    def definitions(self) -> Optional[Dict[str, JSONSchemaProps]]:
        return self.__definitions

    @typechecked
    def externalDocs(self) -> Optional[ExternalDocumentation]:
        return self.__externalDocs

    @typechecked
    def example(self) -> Optional[JSON]:
        return self.__example

    @typechecked
    def nullable(self) -> Optional[bool]:
        return self.__nullable

    # x-kubernetes-preserve-unknown-fields stops the API server
    # decoding step from pruning fields which are not specified
    # in the validation schema. This affects fields recursively,
    # but switches back to normal pruning behaviour if nested
    # properties or additionalProperties are specified in the schema.
    # This can either be true or undefined. False is forbidden.
    @typechecked
    def xKubernetesPreserveUnknownFields(self) -> Optional[bool]:
        return self.__xKubernetesPreserveUnknownFields

    # x-kubernetes-embedded-resource defines that the value is an
    # embedded Kubernetes runtime.Object, with TypeMeta and
    # ObjectMeta. The type must be object. It is allowed to further
    # restrict the embedded object. kind, apiVersion and metadata
    # are validated automatically. x-kubernetes-preserve-unknown-fields
    # is allowed to be true, but does not have to be if the object
    # is fully specified (up to kind, apiVersion, metadata).
    @typechecked
    def xKubernetesEmbeddedResource(self) -> Optional[bool]:
        return self.__xKubernetesEmbeddedResource

    # x-kubernetes-int-or-string specifies that this value is
    # either an integer or a string. If this is true, an empty
    # type is allowed and type as child of anyOf is permitted
    # if following one of the following patterns:
    #
    # 1) anyOf:
    #    - type: integer
    #    - type: string
    # 2) allOf:
    #    - anyOf:
    #      - type: integer
    #      - type: string
    #    - ... zero or more
    @typechecked
    def xKubernetesIntOrString(self) -> Optional[bool]:
        return self.__xKubernetesIntOrString

    # x-kubernetes-list-map-keys annotates an array with the x-kubernetes-list-type `map` by specifying the keys used
    # as the index of the map.
    #
    # This tag MUST only be used on lists that have the "x-kubernetes-list-type"
    # extension set to "map". Also, the values specified for this attribute must
    # be a scalar typed field of the child structure (no nesting is supported).
    @typechecked
    def xKubernetesListMapKeys(self) -> Optional[List[str]]:
        return self.__xKubernetesListMapKeys

    # x-kubernetes-list-type annotates an array to further describe its topology.
    # This extension must only be used on lists and may have 3 possible values:
    #
    # 1) `atomic`: the list is treated as a single entity, like a scalar.
    #      Atomic lists will be entirely replaced when updated. This extension
    #      may be used on any type of list (struct, scalar, ...).
    # 2) `set`:
    #      Sets are lists that must not have multiple items with the same value. Each
    #      value must be a scalar (or another atomic type).
    # 3) `map`:
    #      These lists are like maps in that their elements have a non-index key
    #      used to identify them. Order is preserved upon merge. The map tag
    #      must only be used on a list with elements of type object.
    # Defaults to atomic for arrays.
    @typechecked
    def xKubernetesListType(self) -> Optional[str]:
        return self.__xKubernetesListType


# CustomResourceValidation is a list of validation methods for CustomResources.
class CustomResourceValidation(types.Object):
    @context.scoped
    @typechecked
    def __init__(self, openAPIV3Schema: JSONSchemaProps = None):
        super().__init__(**{})
        self.__openAPIV3Schema = openAPIV3Schema

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        openAPIV3Schema = self.openAPIV3Schema()
        if openAPIV3Schema is not None:  # omit empty
            v["openAPIV3Schema"] = openAPIV3Schema
        return v

    # openAPIV3Schema is the OpenAPI v3 schema to use for validation and pruning.
    @typechecked
    def openAPIV3Schema(self) -> Optional[JSONSchemaProps]:
        return self.__openAPIV3Schema


# CustomResourceDefinitionVersion describes a version for CRD.
class CustomResourceDefinitionVersion(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        served: bool = False,
        storage: bool = False,
        schema: CustomResourceValidation = None,
        subresources: CustomResourceSubresources = None,
        additionalPrinterColumns: Dict[str, CustomResourceColumnDefinition] = None,
    ):
        super().__init__(**{})
        self.__name = name
        self.__served = served
        self.__storage = storage
        self.__schema = schema
        self.__subresources = subresources
        self.__additionalPrinterColumns = (
            additionalPrinterColumns if additionalPrinterColumns is not None else {}
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["name"] = self.name()
        v["served"] = self.served()
        v["storage"] = self.storage()
        schema = self.schema()
        if schema is not None:  # omit empty
            v["schema"] = schema
        subresources = self.subresources()
        if subresources is not None:  # omit empty
            v["subresources"] = subresources
        additionalPrinterColumns = self.additionalPrinterColumns()
        if additionalPrinterColumns:  # omit empty
            v[
                "additionalPrinterColumns"
            ] = additionalPrinterColumns.values()  # named list
        return v

    # name is the version name, e.g. “v1”, “v2beta1”, etc.
    # The custom resources are served under this version at `/apis/<group>/<version>/...` if `served` is true.
    @typechecked
    def name(self) -> str:
        return self.__name

    # served is a flag enabling/disabling this version from being served via REST APIs
    @typechecked
    def served(self) -> bool:
        return self.__served

    # storage indicates this version should be used when persisting custom resources to storage.
    # There must be exactly one version with storage=true.
    @typechecked
    def storage(self) -> bool:
        return self.__storage

    # schema describes the schema used for validation, pruning, and defaulting of this version of the custom resource.
    @typechecked
    def schema(self) -> Optional[CustomResourceValidation]:
        return self.__schema

    # subresources specify what subresources this version of the defined custom resource have.
    @typechecked
    def subresources(self) -> Optional[CustomResourceSubresources]:
        return self.__subresources

    # additionalPrinterColumns specifies additional columns returned in Table output.
    # See https://kubernetes.io/docs/reference/using-api/api-concepts/#receiving-resources-as-tables for details.
    # If no columns are specified, a single column displaying the age of the custom resource is used.
    @typechecked
    def additionalPrinterColumns(
        self
    ) -> Optional[Dict[str, CustomResourceColumnDefinition]]:
        return self.__additionalPrinterColumns


# CustomResourceDefinitionSpec describes how a user wants their resource to appear
class CustomResourceDefinitionSpec(types.Object):
    @context.scoped
    @typechecked
    def __init__(
        self,
        group: str = "",
        names: CustomResourceDefinitionNames = None,
        scope: ResourceScope = None,
        versions: Dict[str, CustomResourceDefinitionVersion] = None,
        conversion: CustomResourceConversion = None,
        preserveUnknownFields: bool = None,
    ):
        super().__init__(**{})
        self.__group = group
        self.__names = names if names is not None else CustomResourceDefinitionNames()
        self.__scope = scope
        self.__versions = versions if versions is not None else {}
        self.__conversion = (
            conversion if conversion is not None else CustomResourceConversion()
        )
        self.__preserveUnknownFields = preserveUnknownFields

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["group"] = self.group()
        v["names"] = self.names()
        v["scope"] = self.scope()
        v["versions"] = self.versions().values()  # named list
        conversion = self.conversion()
        if conversion is not None:  # omit empty
            v["conversion"] = conversion
        preserveUnknownFields = self.preserveUnknownFields()
        if preserveUnknownFields:  # omit empty
            v["preserveUnknownFields"] = preserveUnknownFields
        return v

    # group is the API group of the defined custom resource.
    # The custom resources are served under `/apis/<group>/...`.
    # Must match the name of the CustomResourceDefinition (in the form `<names.plural>.<group>`).
    @typechecked
    def group(self) -> str:
        return self.__group

    # names specify the resource and kind names for the custom resource.
    @typechecked
    def names(self) -> CustomResourceDefinitionNames:
        return self.__names

    # scope indicates whether the defined custom resource is cluster- or namespace-scoped.
    # Allowed values are `Cluster` and `Namespaced`. Default is `Namespaced`.
    @typechecked
    def scope(self) -> ResourceScope:
        return self.__scope

    # versions is the list of all API versions of the defined custom resource.
    # Version names are used to compute the order in which served versions are listed in API discovery.
    # If the version string is "kube-like", it will sort above non "kube-like" version strings, which are ordered
    # lexicographically. "Kube-like" versions start with a "v", then are followed by a number (the major version),
    # then optionally the string "alpha" or "beta" and another number (the minor version). These are sorted first
    # by GA > beta > alpha (where GA is a version with no suffix such as beta or alpha), and then by comparing
    # major version, then minor version. An example sorted list of versions:
    # v10, v2, v1, v11beta2, v10beta3, v3beta1, v12alpha1, v11alpha2, foo1, foo10.
    @typechecked
    def versions(self) -> Dict[str, CustomResourceDefinitionVersion]:
        return self.__versions

    # conversion defines conversion settings for the CRD.
    @typechecked
    def conversion(self) -> Optional[CustomResourceConversion]:
        return self.__conversion

    # preserveUnknownFields indicates that object fields which are not specified
    # in the OpenAPI schema should be preserved when persisting to storage.
    # apiVersion, kind, metadata and known fields inside metadata are always preserved.
    # This field is deprecated in favor of setting `x-preserve-unknown-fields` to true in `spec.versions[*].schema.openAPIV3Schema`.
    # See https://kubernetes.io/docs/tasks/access-kubernetes-api/custom-resources/custom-resource-definitions/#pruning-versus-preserving-unknown-fields for details.
    @typechecked
    def preserveUnknownFields(self) -> Optional[bool]:
        return self.__preserveUnknownFields


# CustomResourceDefinition represents a resource that should be exposed on the API server.  Its name MUST be in the format
# <.spec.name>.<.spec.group>.
class CustomResourceDefinition(base.TypedObject, base.MetadataObject):
    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: CustomResourceDefinitionSpec = None,
    ):
        super().__init__(
            **{
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                **({"name": name} if name is not None else {}),
                **({"labels": labels} if labels is not None else {}),
                **({"annotations": annotations} if annotations is not None else {}),
            }
        )
        self.__spec = spec if spec is not None else CustomResourceDefinitionSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        v["spec"] = self.spec()
        return v

    # spec describes how the user wants the resources to appear
    @typechecked
    def spec(self) -> CustomResourceDefinitionSpec:
        return self.__spec
