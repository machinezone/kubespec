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
from typeguard import check_return_type, typechecked


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
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "uid" in self._kwargs:
            return self._kwargs["uid"]
        if "uid" in self._context and check_return_type(self._context["uid"]):
            return self._context["uid"]
        return ""

    # desiredAPIVersion is the version to convert given objects to. e.g. "myapi.example.com/v1"
    @typechecked
    def desiredAPIVersion(self) -> str:
        if "desiredAPIVersion" in self._kwargs:
            return self._kwargs["desiredAPIVersion"]
        if "desiredAPIVersion" in self._context and check_return_type(
            self._context["desiredAPIVersion"]
        ):
            return self._context["desiredAPIVersion"]
        return ""

    # objects is the list of custom resource objects to be converted.
    @typechecked
    def objects(self) -> List["runtime.RawExtension"]:
        if "objects" in self._kwargs:
            return self._kwargs["objects"]
        if "objects" in self._context and check_return_type(self._context["objects"]):
            return self._context["objects"]
        return []


# ConversionResponse describes a conversion response.
class ConversionResponse(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["uid"] = self.uid()
        v["convertedObjects"] = self.convertedObjects()
        v["result"] = self.result()
        return v

    # uid is an identifier for the individual request/response.
    # This should be copied over from the corresponding `request.uid`.
    @typechecked
    def uid(self) -> str:
        if "uid" in self._kwargs:
            return self._kwargs["uid"]
        if "uid" in self._context and check_return_type(self._context["uid"]):
            return self._context["uid"]
        return ""

    # convertedObjects is the list of converted version of `request.objects` if the `result` is successful, otherwise empty.
    # The webhook is expected to set `apiVersion` of these objects to the `request.desiredAPIVersion`. The list
    # must also have the same size as the input list with the same objects in the same order (equal kind, metadata.uid, metadata.name and metadata.namespace).
    # The webhook is allowed to mutate labels and annotations. Any other change to the metadata is silently ignored.
    @typechecked
    def convertedObjects(self) -> List["runtime.RawExtension"]:
        if "convertedObjects" in self._kwargs:
            return self._kwargs["convertedObjects"]
        if "convertedObjects" in self._context and check_return_type(
            self._context["convertedObjects"]
        ):
            return self._context["convertedObjects"]
        return []

    # result contains the result of conversion with extra details if the conversion failed. `result.status` determines if
    # the conversion failed or succeeded. The `result.status` field is required and represents the success or failure of the
    # conversion. A successful conversion must set `result.status` to `Success`. A failed conversion must set
    # `result.status` to `Failure` and provide more details in `result.message` and return http status 200. The `result.message`
    # will be used to construct an error message for the end user.
    @typechecked
    def result(self) -> "metav1.Status":
        if "result" in self._kwargs:
            return self._kwargs["result"]
        if "result" in self._context and check_return_type(self._context["result"]):
            return self._context["result"]
        with context.Scope(**self._context):
            return metav1.Status()


# ConversionReview describes a conversion request/response.
class ConversionReview(base.TypedObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        request = self.request()
        if request is not None:  # omit empty
            v["request"] = request
        response = self.response()
        if response is not None:  # omit empty
            v["response"] = response
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "apiextensions.k8s.io/v1beta1"

    @typechecked
    def kind(self) -> str:
        return "ConversionReview"

    # request describes the attributes for the conversion request.
    @typechecked
    def request(self) -> Optional[ConversionRequest]:
        if "request" in self._kwargs:
            return self._kwargs["request"]
        if "request" in self._context and check_return_type(self._context["request"]):
            return self._context["request"]
        return None

    # response describes the attributes for the conversion response.
    @typechecked
    def response(self) -> Optional[ConversionResponse]:
        if "response" in self._kwargs:
            return self._kwargs["response"]
        if "response" in self._context and check_return_type(self._context["response"]):
            return self._context["response"]
        return None


# CustomResourceColumnDefinition specifies a column for server side printing.
class CustomResourceColumnDefinition(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        v["JSONPath"] = self.jSONPath()
        return v

    # name is a human readable name for the column.
    @typechecked
    def name(self) -> str:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return ""

    # type is an OpenAPI type definition for this column.
    # See https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types for details.
    @typechecked
    def type(self) -> str:
        if "type" in self._kwargs:
            return self._kwargs["type"]
        if "type" in self._context and check_return_type(self._context["type"]):
            return self._context["type"]
        return ""

    # format is an optional OpenAPI type definition for this column. The 'name' format is applied
    # to the primary identifier column to assist in clients identifying column is the resource name.
    # See https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types for details.
    @typechecked
    def format(self) -> Optional[str]:
        if "format" in self._kwargs:
            return self._kwargs["format"]
        if "format" in self._context and check_return_type(self._context["format"]):
            return self._context["format"]
        return None

    # description is a human readable description of this column.
    @typechecked
    def description(self) -> Optional[str]:
        if "description" in self._kwargs:
            return self._kwargs["description"]
        if "description" in self._context and check_return_type(
            self._context["description"]
        ):
            return self._context["description"]
        return None

    # priority is an integer defining the relative importance of this column compared to others. Lower
    # numbers are considered higher priority. Columns that may be omitted in limited space scenarios
    # should be given a priority greater than 0.
    @typechecked
    def priority(self) -> Optional[int]:
        if "priority" in self._kwargs:
            return self._kwargs["priority"]
        if "priority" in self._context and check_return_type(self._context["priority"]):
            return self._context["priority"]
        return None

    # JSONPath is a simple JSON path (i.e. with array notation) which is evaluated against
    # each custom resource to produce the value for this column.
    @typechecked
    def jSONPath(self) -> str:
        if "JSONPath" in self._kwargs:
            return self._kwargs["JSONPath"]
        if "JSONPath" in self._context and check_return_type(self._context["JSONPath"]):
            return self._context["JSONPath"]
        return ""


# ServiceReference holds a reference to Service.legacy.k8s.io
class ServiceReference(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "namespace" in self._kwargs:
            return self._kwargs["namespace"]
        if "namespace" in self._context and check_return_type(
            self._context["namespace"]
        ):
            return self._context["namespace"]
        return ""

    # name is the name of the service.
    # Required
    @typechecked
    def name(self) -> str:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return ""

    # path is an optional URL path at which the webhook will be contacted.
    @typechecked
    def path(self) -> Optional[str]:
        if "path" in self._kwargs:
            return self._kwargs["path"]
        if "path" in self._context and check_return_type(self._context["path"]):
            return self._context["path"]
        return None

    # port is an optional service port at which the webhook will be contacted.
    # `port` should be a valid port number (1-65535, inclusive).
    # Defaults to 443 for backward compatibility.
    @typechecked
    def port(self) -> Optional[int]:
        if "port" in self._kwargs:
            return self._kwargs["port"]
        if "port" in self._context and check_return_type(self._context["port"]):
            return self._context["port"]
        return 443


# WebhookClientConfig contains the information to make a TLS connection with the webhook.
class WebhookClientConfig(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "url" in self._kwargs:
            return self._kwargs["url"]
        if "url" in self._context and check_return_type(self._context["url"]):
            return self._context["url"]
        return None

    # service is a reference to the service for this webhook. Either
    # service or url must be specified.
    #
    # If the webhook is running within the cluster, then you should use `service`.
    @typechecked
    def service(self) -> Optional[ServiceReference]:
        if "service" in self._kwargs:
            return self._kwargs["service"]
        if "service" in self._context and check_return_type(self._context["service"]):
            return self._context["service"]
        return None

    # caBundle is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
    # If unspecified, system trust roots on the apiserver are used.
    @typechecked
    def caBundle(self) -> bytes:
        if "caBundle" in self._kwargs:
            return self._kwargs["caBundle"]
        if "caBundle" in self._context and check_return_type(self._context["caBundle"]):
            return self._context["caBundle"]
        return b""


# CustomResourceConversion describes how to convert different versions of a CR.
class CustomResourceConversion(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["strategy"] = self.strategy()
        webhookClientConfig = self.webhookClientConfig()
        if webhookClientConfig is not None:  # omit empty
            v["webhookClientConfig"] = webhookClientConfig
        conversionReviewVersions = self.conversionReviewVersions()
        if conversionReviewVersions:  # omit empty
            v["conversionReviewVersions"] = conversionReviewVersions
        return v

    # strategy specifies how custom resources are converted between versions. Allowed values are:
    # - `None`: The converter only change the apiVersion and would not touch any other field in the custom resource.
    # - `Webhook`: API Server will call to an external webhook to do the conversion. Additional information
    #   is needed for this option. This requires spec.preserveUnknownFields to be false, and spec.conversion.webhookClientConfig to be set.
    @typechecked
    def strategy(self) -> ConversionStrategyType:
        if "strategy" in self._kwargs:
            return self._kwargs["strategy"]
        if "strategy" in self._context and check_return_type(self._context["strategy"]):
            return self._context["strategy"]
        return ConversionStrategyType["None"]

    # webhookClientConfig is the instructions for how to call the webhook if strategy is `Webhook`.
    # Required when `strategy` is set to `Webhook`.
    @typechecked
    def webhookClientConfig(self) -> Optional[WebhookClientConfig]:
        if "webhookClientConfig" in self._kwargs:
            return self._kwargs["webhookClientConfig"]
        if "webhookClientConfig" in self._context and check_return_type(
            self._context["webhookClientConfig"]
        ):
            return self._context["webhookClientConfig"]
        return None

    # conversionReviewVersions is an ordered list of preferred `ConversionReview`
    # versions the Webhook expects. The API server will use the first version in
    # the list which it supports. If none of the versions specified in this list
    # are supported by API server, conversion will fail for the custom resource.
    # If a persisted Webhook configuration specifies allowed versions and does not
    # include any versions known to the API Server, calls to the webhook will fail.
    # Defaults to `["v1beta1"]`.
    @typechecked
    def conversionReviewVersions(self) -> List[str]:
        if "conversionReviewVersions" in self._kwargs:
            return self._kwargs["conversionReviewVersions"]
        if "conversionReviewVersions" in self._context and check_return_type(
            self._context["conversionReviewVersions"]
        ):
            return self._context["conversionReviewVersions"]
        return []


# CustomResourceDefinitionNames indicates the names to serve this CustomResourceDefinition
class CustomResourceDefinitionNames(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "plural" in self._kwargs:
            return self._kwargs["plural"]
        if "plural" in self._context and check_return_type(self._context["plural"]):
            return self._context["plural"]
        return ""

    # singular is the singular name of the resource. It must be all lowercase. Defaults to lowercased `kind`.
    @typechecked
    def singular(self) -> Optional[str]:
        if "singular" in self._kwargs:
            return self._kwargs["singular"]
        if "singular" in self._context and check_return_type(self._context["singular"]):
            return self._context["singular"]
        return None

    # shortNames are short names for the resource, exposed in API discovery documents,
    # and used by clients to support invocations like `kubectl get <shortname>`.
    # It must be all lowercase.
    @typechecked
    def shortNames(self) -> List[str]:
        if "shortNames" in self._kwargs:
            return self._kwargs["shortNames"]
        if "shortNames" in self._context and check_return_type(
            self._context["shortNames"]
        ):
            return self._context["shortNames"]
        return []

    # kind is the serialized kind of the resource. It is normally CamelCase and singular.
    # Custom resource instances will use this value as the `kind` attribute in API calls.
    @typechecked
    def kind(self) -> str:
        if "kind" in self._kwargs:
            return self._kwargs["kind"]
        if "kind" in self._context and check_return_type(self._context["kind"]):
            return self._context["kind"]
        return ""

    # listKind is the serialized kind of the list for this resource. Defaults to "`kind`List".
    @typechecked
    def listKind(self) -> Optional[str]:
        if "listKind" in self._kwargs:
            return self._kwargs["listKind"]
        if "listKind" in self._context and check_return_type(self._context["listKind"]):
            return self._context["listKind"]
        return None

    # categories is a list of grouped resources this custom resource belongs to (e.g. 'all').
    # This is published in API discovery documents, and used by clients to support invocations like
    # `kubectl get all`.
    @typechecked
    def categories(self) -> List[str]:
        if "categories" in self._kwargs:
            return self._kwargs["categories"]
        if "categories" in self._context and check_return_type(
            self._context["categories"]
        ):
            return self._context["categories"]
        return []


# CustomResourceSubresourceScale defines how to serve the scale subresource for CustomResources.
class CustomResourceSubresourceScale(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "specReplicasPath" in self._kwargs:
            return self._kwargs["specReplicasPath"]
        if "specReplicasPath" in self._context and check_return_type(
            self._context["specReplicasPath"]
        ):
            return self._context["specReplicasPath"]
        return ""

    # statusReplicasPath defines the JSON path inside of a custom resource that corresponds to Scale `status.replicas`.
    # Only JSON paths without the array notation are allowed.
    # Must be a JSON Path under `.status`.
    # If there is no value under the given path in the custom resource, the `status.replicas` value in the `/scale` subresource
    # will default to 0.
    @typechecked
    def statusReplicasPath(self) -> str:
        if "statusReplicasPath" in self._kwargs:
            return self._kwargs["statusReplicasPath"]
        if "statusReplicasPath" in self._context and check_return_type(
            self._context["statusReplicasPath"]
        ):
            return self._context["statusReplicasPath"]
        return ""

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
        if "labelSelectorPath" in self._kwargs:
            return self._kwargs["labelSelectorPath"]
        if "labelSelectorPath" in self._context and check_return_type(
            self._context["labelSelectorPath"]
        ):
            return self._context["labelSelectorPath"]
        return None


# CustomResourceSubresourceStatus defines how to serve the status subresource for CustomResources.
# Status is represented by the `.status` JSON path inside of a CustomResource. When set,
# * exposes a /status subresource for the custom resource
# * PUT requests to the /status subresource take a custom resource object, and ignore changes to anything except the status stanza
# * PUT/POST/PATCH requests to the custom resource ignore changes to the status stanza
class CustomResourceSubresourceStatus(types.Object):
    pass  # FIXME


# CustomResourceSubresources defines the status and scale subresources for CustomResources.
class CustomResourceSubresources(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "status" in self._kwargs:
            return self._kwargs["status"]
        if "status" in self._context and check_return_type(self._context["status"]):
            return self._context["status"]
        return None

    # scale indicates the custom resource should serve a `/scale` subresource that returns an `autoscaling/v1` Scale object.
    @typechecked
    def scale(self) -> Optional[CustomResourceSubresourceScale]:
        if "scale" in self._kwargs:
            return self._kwargs["scale"]
        if "scale" in self._context and check_return_type(self._context["scale"]):
            return self._context["scale"]
        return None


# ExternalDocumentation allows referencing an external resource for extended documentation.
class ExternalDocumentation(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        description = self.description()
        if description:  # omit empty
            v["description"] = description
        url = self.url()
        if url:  # omit empty
            v["url"] = url
        return v

    @typechecked
    def description(self) -> Optional[str]:
        if "description" in self._kwargs:
            return self._kwargs["description"]
        if "description" in self._context and check_return_type(
            self._context["description"]
        ):
            return self._context["description"]
        return None

    @typechecked
    def url(self) -> Optional[str]:
        if "url" in self._kwargs:
            return self._kwargs["url"]
        if "url" in self._context and check_return_type(self._context["url"]):
            return self._context["url"]
        return None


# JSON represents any valid JSON value.
# These types are supported: bool, int64, float64, string, []interface{}, map[string]interface{} and nil.
class JSON(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["Raw"] = self.raw()
        return v

    @typechecked
    def raw(self) -> bytes:
        if "Raw" in self._kwargs:
            return self._kwargs["Raw"]
        if "Raw" in self._context and check_return_type(self._context["Raw"]):
            return self._context["Raw"]
        return b""


# JSONSchemaProps is a JSON-Schema following Specification Draft 4 (http://json-schema.org/).
class JSONSchemaProps(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "id" in self._kwargs:
            return self._kwargs["id"]
        if "id" in self._context and check_return_type(self._context["id"]):
            return self._context["id"]
        return None

    @typechecked
    def schema(self) -> Optional[str]:
        if "$schema" in self._kwargs:
            return self._kwargs["$schema"]
        if "$schema" in self._context and check_return_type(self._context["$schema"]):
            return self._context["$schema"]
        return None

    @typechecked
    def ref(self) -> Optional[str]:
        if "$ref" in self._kwargs:
            return self._kwargs["$ref"]
        if "$ref" in self._context and check_return_type(self._context["$ref"]):
            return self._context["$ref"]
        return None

    @typechecked
    def description(self) -> Optional[str]:
        if "description" in self._kwargs:
            return self._kwargs["description"]
        if "description" in self._context and check_return_type(
            self._context["description"]
        ):
            return self._context["description"]
        return None

    @typechecked
    def type(self) -> Optional[str]:
        if "type" in self._kwargs:
            return self._kwargs["type"]
        if "type" in self._context and check_return_type(self._context["type"]):
            return self._context["type"]
        return None

    @typechecked
    def format(self) -> Optional[str]:
        if "format" in self._kwargs:
            return self._kwargs["format"]
        if "format" in self._context and check_return_type(self._context["format"]):
            return self._context["format"]
        return None

    @typechecked
    def title(self) -> Optional[str]:
        if "title" in self._kwargs:
            return self._kwargs["title"]
        if "title" in self._context and check_return_type(self._context["title"]):
            return self._context["title"]
        return None

    # default is a default value for undefined object fields.
    # Defaulting is a beta feature under the CustomResourceDefaulting feature gate.
    # CustomResourceDefinitions with defaults must be created using the v1 (or newer) CustomResourceDefinition API.
    @typechecked
    def default(self) -> Optional[JSON]:
        if "default" in self._kwargs:
            return self._kwargs["default"]
        if "default" in self._context and check_return_type(self._context["default"]):
            return self._context["default"]
        return None

    @typechecked
    def maximum(self) -> Optional[float]:
        if "maximum" in self._kwargs:
            return self._kwargs["maximum"]
        if "maximum" in self._context and check_return_type(self._context["maximum"]):
            return self._context["maximum"]
        return None

    @typechecked
    def exclusiveMaximum(self) -> Optional[bool]:
        if "exclusiveMaximum" in self._kwargs:
            return self._kwargs["exclusiveMaximum"]
        if "exclusiveMaximum" in self._context and check_return_type(
            self._context["exclusiveMaximum"]
        ):
            return self._context["exclusiveMaximum"]
        return None

    @typechecked
    def minimum(self) -> Optional[float]:
        if "minimum" in self._kwargs:
            return self._kwargs["minimum"]
        if "minimum" in self._context and check_return_type(self._context["minimum"]):
            return self._context["minimum"]
        return None

    @typechecked
    def exclusiveMinimum(self) -> Optional[bool]:
        if "exclusiveMinimum" in self._kwargs:
            return self._kwargs["exclusiveMinimum"]
        if "exclusiveMinimum" in self._context and check_return_type(
            self._context["exclusiveMinimum"]
        ):
            return self._context["exclusiveMinimum"]
        return None

    @typechecked
    def maxLength(self) -> Optional[int]:
        if "maxLength" in self._kwargs:
            return self._kwargs["maxLength"]
        if "maxLength" in self._context and check_return_type(
            self._context["maxLength"]
        ):
            return self._context["maxLength"]
        return None

    @typechecked
    def minLength(self) -> Optional[int]:
        if "minLength" in self._kwargs:
            return self._kwargs["minLength"]
        if "minLength" in self._context and check_return_type(
            self._context["minLength"]
        ):
            return self._context["minLength"]
        return None

    @typechecked
    def pattern(self) -> Optional[str]:
        if "pattern" in self._kwargs:
            return self._kwargs["pattern"]
        if "pattern" in self._context and check_return_type(self._context["pattern"]):
            return self._context["pattern"]
        return None

    @typechecked
    def maxItems(self) -> Optional[int]:
        if "maxItems" in self._kwargs:
            return self._kwargs["maxItems"]
        if "maxItems" in self._context and check_return_type(self._context["maxItems"]):
            return self._context["maxItems"]
        return None

    @typechecked
    def minItems(self) -> Optional[int]:
        if "minItems" in self._kwargs:
            return self._kwargs["minItems"]
        if "minItems" in self._context and check_return_type(self._context["minItems"]):
            return self._context["minItems"]
        return None

    @typechecked
    def uniqueItems(self) -> Optional[bool]:
        if "uniqueItems" in self._kwargs:
            return self._kwargs["uniqueItems"]
        if "uniqueItems" in self._context and check_return_type(
            self._context["uniqueItems"]
        ):
            return self._context["uniqueItems"]
        return None

    @typechecked
    def multipleOf(self) -> Optional[float]:
        if "multipleOf" in self._kwargs:
            return self._kwargs["multipleOf"]
        if "multipleOf" in self._context and check_return_type(
            self._context["multipleOf"]
        ):
            return self._context["multipleOf"]
        return None

    @typechecked
    def enum(self) -> List[JSON]:
        if "enum" in self._kwargs:
            return self._kwargs["enum"]
        if "enum" in self._context and check_return_type(self._context["enum"]):
            return self._context["enum"]
        return []

    @typechecked
    def maxProperties(self) -> Optional[int]:
        if "maxProperties" in self._kwargs:
            return self._kwargs["maxProperties"]
        if "maxProperties" in self._context and check_return_type(
            self._context["maxProperties"]
        ):
            return self._context["maxProperties"]
        return None

    @typechecked
    def minProperties(self) -> Optional[int]:
        if "minProperties" in self._kwargs:
            return self._kwargs["minProperties"]
        if "minProperties" in self._context and check_return_type(
            self._context["minProperties"]
        ):
            return self._context["minProperties"]
        return None

    @typechecked
    def required(self) -> List[str]:
        if "required" in self._kwargs:
            return self._kwargs["required"]
        if "required" in self._context and check_return_type(self._context["required"]):
            return self._context["required"]
        return []

    @typechecked
    def items(self) -> Optional[Union[JSONSchemaProps, List[JSONSchemaProps]]]:
        if "items" in self._kwargs:
            return self._kwargs["items"]
        if "items" in self._context and check_return_type(self._context["items"]):
            return self._context["items"]
        return None

    @typechecked
    def allOf(self) -> List[JSONSchemaProps]:
        if "allOf" in self._kwargs:
            return self._kwargs["allOf"]
        if "allOf" in self._context and check_return_type(self._context["allOf"]):
            return self._context["allOf"]
        return []

    @typechecked
    def oneOf(self) -> List[JSONSchemaProps]:
        if "oneOf" in self._kwargs:
            return self._kwargs["oneOf"]
        if "oneOf" in self._context and check_return_type(self._context["oneOf"]):
            return self._context["oneOf"]
        return []

    @typechecked
    def anyOf(self) -> List[JSONSchemaProps]:
        if "anyOf" in self._kwargs:
            return self._kwargs["anyOf"]
        if "anyOf" in self._context and check_return_type(self._context["anyOf"]):
            return self._context["anyOf"]
        return []

    @typechecked
    def not_(self) -> Optional[JSONSchemaProps]:
        if "not" in self._kwargs:
            return self._kwargs["not"]
        if "not" in self._context and check_return_type(self._context["not"]):
            return self._context["not"]
        return None

    @typechecked
    def properties(self) -> Dict[str, JSONSchemaProps]:
        if "properties" in self._kwargs:
            return self._kwargs["properties"]
        if "properties" in self._context and check_return_type(
            self._context["properties"]
        ):
            return self._context["properties"]
        return {}

    @typechecked
    def additionalProperties(self) -> Optional[Union[JSONSchemaProps, bool]]:
        if "additionalProperties" in self._kwargs:
            return self._kwargs["additionalProperties"]
        if "additionalProperties" in self._context and check_return_type(
            self._context["additionalProperties"]
        ):
            return self._context["additionalProperties"]
        return None

    @typechecked
    def patternProperties(self) -> Dict[str, JSONSchemaProps]:
        if "patternProperties" in self._kwargs:
            return self._kwargs["patternProperties"]
        if "patternProperties" in self._context and check_return_type(
            self._context["patternProperties"]
        ):
            return self._context["patternProperties"]
        return {}

    @typechecked
    def dependencies(self) -> Dict[str, Union[JSONSchemaProps, List[str]]]:
        if "dependencies" in self._kwargs:
            return self._kwargs["dependencies"]
        if "dependencies" in self._context and check_return_type(
            self._context["dependencies"]
        ):
            return self._context["dependencies"]
        return {}

    @typechecked
    def additionalItems(self) -> Optional[Union[JSONSchemaProps, bool]]:
        if "additionalItems" in self._kwargs:
            return self._kwargs["additionalItems"]
        if "additionalItems" in self._context and check_return_type(
            self._context["additionalItems"]
        ):
            return self._context["additionalItems"]
        return None

    @typechecked
    def definitions(self) -> Dict[str, JSONSchemaProps]:
        if "definitions" in self._kwargs:
            return self._kwargs["definitions"]
        if "definitions" in self._context and check_return_type(
            self._context["definitions"]
        ):
            return self._context["definitions"]
        return {}

    @typechecked
    def externalDocs(self) -> Optional[ExternalDocumentation]:
        if "externalDocs" in self._kwargs:
            return self._kwargs["externalDocs"]
        if "externalDocs" in self._context and check_return_type(
            self._context["externalDocs"]
        ):
            return self._context["externalDocs"]
        return None

    @typechecked
    def example(self) -> Optional[JSON]:
        if "example" in self._kwargs:
            return self._kwargs["example"]
        if "example" in self._context and check_return_type(self._context["example"]):
            return self._context["example"]
        return None

    @typechecked
    def nullable(self) -> Optional[bool]:
        if "nullable" in self._kwargs:
            return self._kwargs["nullable"]
        if "nullable" in self._context and check_return_type(self._context["nullable"]):
            return self._context["nullable"]
        return None

    # x-kubernetes-preserve-unknown-fields stops the API server
    # decoding step from pruning fields which are not specified
    # in the validation schema. This affects fields recursively,
    # but switches back to normal pruning behaviour if nested
    # properties or additionalProperties are specified in the schema.
    # This can either be true or undefined. False is forbidden.
    @typechecked
    def xKubernetesPreserveUnknownFields(self) -> Optional[bool]:
        if "x-kubernetes-preserve-unknown-fields" in self._kwargs:
            return self._kwargs["x-kubernetes-preserve-unknown-fields"]
        if (
            "x-kubernetes-preserve-unknown-fields" in self._context
            and check_return_type(self._context["x-kubernetes-preserve-unknown-fields"])
        ):
            return self._context["x-kubernetes-preserve-unknown-fields"]
        return None

    # x-kubernetes-embedded-resource defines that the value is an
    # embedded Kubernetes runtime.Object, with TypeMeta and
    # ObjectMeta. The type must be object. It is allowed to further
    # restrict the embedded object. kind, apiVersion and metadata
    # are validated automatically. x-kubernetes-preserve-unknown-fields
    # is allowed to be true, but does not have to be if the object
    # is fully specified (up to kind, apiVersion, metadata).
    @typechecked
    def xKubernetesEmbeddedResource(self) -> Optional[bool]:
        if "x-kubernetes-embedded-resource" in self._kwargs:
            return self._kwargs["x-kubernetes-embedded-resource"]
        if "x-kubernetes-embedded-resource" in self._context and check_return_type(
            self._context["x-kubernetes-embedded-resource"]
        ):
            return self._context["x-kubernetes-embedded-resource"]
        return None

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
        if "x-kubernetes-int-or-string" in self._kwargs:
            return self._kwargs["x-kubernetes-int-or-string"]
        if "x-kubernetes-int-or-string" in self._context and check_return_type(
            self._context["x-kubernetes-int-or-string"]
        ):
            return self._context["x-kubernetes-int-or-string"]
        return None

    # x-kubernetes-list-map-keys annotates an array with the x-kubernetes-list-type `map` by specifying the keys used
    # as the index of the map.
    #
    # This tag MUST only be used on lists that have the "x-kubernetes-list-type"
    # extension set to "map". Also, the values specified for this attribute must
    # be a scalar typed field of the child structure (no nesting is supported).
    @typechecked
    def xKubernetesListMapKeys(self) -> List[str]:
        if "x-kubernetes-list-map-keys" in self._kwargs:
            return self._kwargs["x-kubernetes-list-map-keys"]
        if "x-kubernetes-list-map-keys" in self._context and check_return_type(
            self._context["x-kubernetes-list-map-keys"]
        ):
            return self._context["x-kubernetes-list-map-keys"]
        return []

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
        if "x-kubernetes-list-type" in self._kwargs:
            return self._kwargs["x-kubernetes-list-type"]
        if "x-kubernetes-list-type" in self._context and check_return_type(
            self._context["x-kubernetes-list-type"]
        ):
            return self._context["x-kubernetes-list-type"]
        return None


# CustomResourceValidation is a list of validation methods for CustomResources.
class CustomResourceValidation(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        openAPIV3Schema = self.openAPIV3Schema()
        if openAPIV3Schema is not None:  # omit empty
            v["openAPIV3Schema"] = openAPIV3Schema
        return v

    # openAPIV3Schema is the OpenAPI v3 schema to use for validation and pruning.
    @typechecked
    def openAPIV3Schema(self) -> Optional[JSONSchemaProps]:
        if "openAPIV3Schema" in self._kwargs:
            return self._kwargs["openAPIV3Schema"]
        if "openAPIV3Schema" in self._context and check_return_type(
            self._context["openAPIV3Schema"]
        ):
            return self._context["openAPIV3Schema"]
        return None


# CustomResourceDefinitionVersion describes a version for CRD.
class CustomResourceDefinitionVersion(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
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
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return ""

    # served is a flag enabling/disabling this version from being served via REST APIs
    @typechecked
    def served(self) -> bool:
        if "served" in self._kwargs:
            return self._kwargs["served"]
        if "served" in self._context and check_return_type(self._context["served"]):
            return self._context["served"]
        return False

    # storage indicates this version should be used when persisting custom resources to storage.
    # There must be exactly one version with storage=true.
    @typechecked
    def storage(self) -> bool:
        if "storage" in self._kwargs:
            return self._kwargs["storage"]
        if "storage" in self._context and check_return_type(self._context["storage"]):
            return self._context["storage"]
        return False

    # schema describes the schema used for validation and pruning of this version of the custom resource.
    # Top-level and per-version schemas are mutually exclusive.
    # Per-version schemas must not all be set to identical values (top-level validation schema should be used instead).
    @typechecked
    def schema(self) -> Optional[CustomResourceValidation]:
        if "schema" in self._kwargs:
            return self._kwargs["schema"]
        if "schema" in self._context and check_return_type(self._context["schema"]):
            return self._context["schema"]
        return None

    # subresources specify what subresources this version of the defined custom resource have.
    # Top-level and per-version subresources are mutually exclusive.
    # Per-version subresources must not all be set to identical values (top-level subresources should be used instead).
    @typechecked
    def subresources(self) -> Optional[CustomResourceSubresources]:
        if "subresources" in self._kwargs:
            return self._kwargs["subresources"]
        if "subresources" in self._context and check_return_type(
            self._context["subresources"]
        ):
            return self._context["subresources"]
        return None

    # additionalPrinterColumns specifies additional columns returned in Table output.
    # See https://kubernetes.io/docs/reference/using-api/api-concepts/#receiving-resources-as-tables for details.
    # Top-level and per-version columns are mutually exclusive.
    # Per-version columns must not all be set to identical values (top-level columns should be used instead).
    # If no top-level or per-version columns are specified, a single column displaying the age of the custom resource is used.
    @typechecked
    def additionalPrinterColumns(self) -> Dict[str, CustomResourceColumnDefinition]:
        if "additionalPrinterColumns" in self._kwargs:
            return self._kwargs["additionalPrinterColumns"]
        if "additionalPrinterColumns" in self._context and check_return_type(
            self._context["additionalPrinterColumns"]
        ):
            return self._context["additionalPrinterColumns"]
        return {}


# CustomResourceDefinitionSpec describes how a user wants their resource to appear
class CustomResourceDefinitionSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["group"] = self.group()
        v["names"] = self.names()
        v["scope"] = self.scope()
        validation = self.validation()
        if validation is not None:  # omit empty
            v["validation"] = validation
        subresources = self.subresources()
        if subresources is not None:  # omit empty
            v["subresources"] = subresources
        versions = self.versions()
        if versions:  # omit empty
            v["versions"] = versions.values()  # named list
        additionalPrinterColumns = self.additionalPrinterColumns()
        if additionalPrinterColumns:  # omit empty
            v[
                "additionalPrinterColumns"
            ] = additionalPrinterColumns.values()  # named list
        conversion = self.conversion()
        if conversion is not None:  # omit empty
            v["conversion"] = conversion
        return v

    # group is the API group of the defined custom resource.
    # The custom resources are served under `/apis/<group>/...`.
    # Must match the name of the CustomResourceDefinition (in the form `<names.plural>.<group>`).
    @typechecked
    def group(self) -> str:
        if "group" in self._kwargs:
            return self._kwargs["group"]
        if "group" in self._context and check_return_type(self._context["group"]):
            return self._context["group"]
        return ""

    # names specify the resource and kind names for the custom resource.
    @typechecked
    def names(self) -> CustomResourceDefinitionNames:
        if "names" in self._kwargs:
            return self._kwargs["names"]
        if "names" in self._context and check_return_type(self._context["names"]):
            return self._context["names"]
        with context.Scope(**self._context):
            return CustomResourceDefinitionNames()

    # scope indicates whether the defined custom resource is cluster- or namespace-scoped.
    # Allowed values are `Cluster` and `Namespaced`. Default is `Namespaced`.
    @typechecked
    def scope(self) -> ResourceScope:
        if "scope" in self._kwargs:
            return self._kwargs["scope"]
        if "scope" in self._context and check_return_type(self._context["scope"]):
            return self._context["scope"]
        return ResourceScope["NamespaceScoped"]

    # validation describes the schema used for validation and pruning of the custom resource.
    # If present, this validation schema is used to validate all versions.
    # Top-level and per-version schemas are mutually exclusive.
    @typechecked
    def validation(self) -> Optional[CustomResourceValidation]:
        if "validation" in self._kwargs:
            return self._kwargs["validation"]
        if "validation" in self._context and check_return_type(
            self._context["validation"]
        ):
            return self._context["validation"]
        return None

    # subresources specify what subresources the defined custom resource has.
    # If present, this field configures subresources for all versions.
    # Top-level and per-version subresources are mutually exclusive.
    @typechecked
    def subresources(self) -> Optional[CustomResourceSubresources]:
        if "subresources" in self._kwargs:
            return self._kwargs["subresources"]
        if "subresources" in self._context and check_return_type(
            self._context["subresources"]
        ):
            return self._context["subresources"]
        return None

    # versions is the list of all API versions of the defined custom resource.
    # Optional if `version` is specified.
    # The name of the first item in the `versions` list must match the `version` field if `version` and `versions` are both specified.
    # Version names are used to compute the order in which served versions are listed in API discovery.
    # If the version string is "kube-like", it will sort above non "kube-like" version strings, which are ordered
    # lexicographically. "Kube-like" versions start with a "v", then are followed by a number (the major version),
    # then optionally the string "alpha" or "beta" and another number (the minor version). These are sorted first
    # by GA > beta > alpha (where GA is a version with no suffix such as beta or alpha), and then by comparing
    # major version, then minor version. An example sorted list of versions:
    # v10, v2, v1, v11beta2, v10beta3, v3beta1, v12alpha1, v11alpha2, foo1, foo10.
    @typechecked
    def versions(self) -> Dict[str, CustomResourceDefinitionVersion]:
        if "versions" in self._kwargs:
            return self._kwargs["versions"]
        if "versions" in self._context and check_return_type(self._context["versions"]):
            return self._context["versions"]
        return {}

    # additionalPrinterColumns specifies additional columns returned in Table output.
    # See https://kubernetes.io/docs/reference/using-api/api-concepts/#receiving-resources-as-tables for details.
    # If present, this field configures columns for all versions.
    # Top-level and per-version columns are mutually exclusive.
    # If no top-level or per-version columns are specified, a single column displaying the age of the custom resource is used.
    @typechecked
    def additionalPrinterColumns(self) -> Dict[str, CustomResourceColumnDefinition]:
        if "additionalPrinterColumns" in self._kwargs:
            return self._kwargs["additionalPrinterColumns"]
        if "additionalPrinterColumns" in self._context and check_return_type(
            self._context["additionalPrinterColumns"]
        ):
            return self._context["additionalPrinterColumns"]
        return {}

    # conversion defines conversion settings for the CRD.
    @typechecked
    def conversion(self) -> Optional[CustomResourceConversion]:
        if "conversion" in self._kwargs:
            return self._kwargs["conversion"]
        if "conversion" in self._context and check_return_type(
            self._context["conversion"]
        ):
            return self._context["conversion"]
        with context.Scope(**self._context):
            return CustomResourceConversion()


# CustomResourceDefinition represents a resource that should be exposed on the API server.  Its name MUST be in the format
# <.spec.name>.<.spec.group>.
# Deprecated in v1.16, planned for removal in v1.19. Use apiextensions.k8s.io/v1 CustomResourceDefinition instead.
class CustomResourceDefinition(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "apiextensions.k8s.io/v1beta1"

    @typechecked
    def kind(self) -> str:
        return "CustomResourceDefinition"

    # spec describes how the user wants the resources to appear
    @typechecked
    def spec(self) -> CustomResourceDefinitionSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return CustomResourceDefinitionSpec()
