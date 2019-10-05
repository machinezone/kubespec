# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Dict, List, Optional

import addict
from k8s import base
from k8s.apimachinery import runtime
from k8s.apimachinery.meta import v1 as metav1
from korps import types
from typeguard import typechecked


# ConversionStrategyType describes different conversion types.
ConversionStrategyType = base.Enum('ConversionStrategyType', {
    # None is a converter that only sets apiversion of the CR and leave everything else unchanged.
    'None': 'None',
    # Webhook is a converter that calls to an external webhook to convert the CR.
    'Webhook': 'Webhook',
})


# JSONSchemaURL represents a schema url.
JSONSchemaURL = base.Enum('JSONSchemaURL', {
})


# ResourceScope is an enum defining the different scopes available to a custom resource
ResourceScope = base.Enum('ResourceScope', {
    'Cluster': 'Cluster',
    'NamespaceScoped': 'Namespaced',
})


# ConversionRequest describes the conversion request parameters.
class ConversionRequest(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['uid'] = self.uid()
        v['desiredAPIVersion'] = self.desiredAPIVersion()
        v['objects'] = self.objects()
        return v
    
    # uid is an identifier for the individual request/response. It allows distinguishing instances of requests which are
    # otherwise identical (parallel requests, etc).
    # The UID is meant to track the round trip (request/response) between the Kubernetes API server and the webhook, not the user request.
    # It is suitable for correlating log entries between the webhook and apiserver, for either auditing or debugging.
    @typechecked
    def uid(self) -> str:
        return self._kwargs.get('uid', '')
    
    # desiredAPIVersion is the version to convert given objects to. e.g. "myapi.example.com/v1"
    @typechecked
    def desiredAPIVersion(self) -> str:
        return self._kwargs.get('desiredAPIVersion', '')
    
    # objects is the list of custom resource objects to be converted.
    @typechecked
    def objects(self) -> List['runtime.RawExtension']:
        return self._kwargs.get('objects', [])


# ConversionResponse describes a conversion response.
class ConversionResponse(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['uid'] = self.uid()
        v['convertedObjects'] = self.convertedObjects()
        v['result'] = self.result()
        return v
    
    # uid is an identifier for the individual request/response.
    # This should be copied over from the corresponding `request.uid`.
    @typechecked
    def uid(self) -> str:
        return self._kwargs.get('uid', '')
    
    # convertedObjects is the list of converted version of `request.objects` if the `result` is successful, otherwise empty.
    # The webhook is expected to set `apiVersion` of these objects to the `request.desiredAPIVersion`. The list
    # must also have the same size as the input list with the same objects in the same order (equal kind, metadata.uid, metadata.name and metadata.namespace).
    # The webhook is allowed to mutate labels and annotations. Any other change to the metadata is silently ignored.
    @typechecked
    def convertedObjects(self) -> List['runtime.RawExtension']:
        return self._kwargs.get('convertedObjects', [])
    
    # result contains the result of conversion with extra details if the conversion failed. `result.status` determines if
    # the conversion failed or succeeded. The `result.status` field is required and represents the success or failure of the
    # conversion. A successful conversion must set `result.status` to `Success`. A failed conversion must set
    # `result.status` to `Failure` and provide more details in `result.message` and return http status 200. The `result.message`
    # will be used to construct an error message for the end user.
    @typechecked
    def result(self) -> 'metav1.Status':
        return self._kwargs.get('result', metav1.Status())


# ConversionReview describes a conversion request/response.
class ConversionReview(base.TypedObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        request = self.request()
        if request is not None:  # omit empty
            v['request'] = request
        response = self.response()
        if response is not None:  # omit empty
            v['response'] = response
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'apiextensions.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'ConversionReview'
    
    # request describes the attributes for the conversion request.
    @typechecked
    def request(self) -> Optional[ConversionRequest]:
        return self._kwargs.get('request')
    
    # response describes the attributes for the conversion response.
    @typechecked
    def response(self) -> Optional[ConversionResponse]:
        return self._kwargs.get('response')


# CustomResourceColumnDefinition specifies a column for server side printing.
class CustomResourceColumnDefinition(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['name'] = self.name()
        v['type'] = self.type()
        format = self.format()
        if format:  # omit empty
            v['format'] = format
        description = self.description()
        if description:  # omit empty
            v['description'] = description
        priority = self.priority()
        if priority:  # omit empty
            v['priority'] = priority
        v['JSONPath'] = self.jSONPath()
        return v
    
    # name is a human readable name for the column.
    @typechecked
    def name(self) -> str:
        return self._kwargs.get('name', '')
    
    # type is an OpenAPI type definition for this column.
    # See https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types for details.
    @typechecked
    def type(self) -> str:
        return self._kwargs.get('type', '')
    
    # format is an optional OpenAPI type definition for this column. The 'name' format is applied
    # to the primary identifier column to assist in clients identifying column is the resource name.
    # See https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types for details.
    @typechecked
    def format(self) -> Optional[str]:
        return self._kwargs.get('format')
    
    # description is a human readable description of this column.
    @typechecked
    def description(self) -> Optional[str]:
        return self._kwargs.get('description')
    
    # priority is an integer defining the relative importance of this column compared to others. Lower
    # numbers are considered higher priority. Columns that may be omitted in limited space scenarios
    # should be given a priority greater than 0.
    @typechecked
    def priority(self) -> Optional[int]:
        return self._kwargs.get('priority')
    
    # JSONPath is a simple JSON path (i.e. with array notation) which is evaluated against
    # each custom resource to produce the value for this column.
    @typechecked
    def jSONPath(self) -> str:
        return self._kwargs.get('JSONPath', '')


# ServiceReference holds a reference to Service.legacy.k8s.io
class ServiceReference(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['namespace'] = self.namespace()
        v['name'] = self.name()
        path = self.path()
        if path is not None:  # omit empty
            v['path'] = path
        port = self.port()
        if port is not None:  # omit empty
            v['port'] = port
        return v
    
    # namespace is the namespace of the service.
    # Required
    @typechecked
    def namespace(self) -> str:
        return self._kwargs.get('namespace', '')
    
    # name is the name of the service.
    # Required
    @typechecked
    def name(self) -> str:
        return self._kwargs.get('name', '')
    
    # path is an optional URL path at which the webhook will be contacted.
    @typechecked
    def path(self) -> Optional[str]:
        return self._kwargs.get('path')
    
    # port is an optional service port at which the webhook will be contacted.
    # `port` should be a valid port number (1-65535, inclusive).
    # Defaults to 443 for backward compatibility.
    @typechecked
    def port(self) -> Optional[int]:
        return self._kwargs.get('port', 443)


# WebhookClientConfig contains the information to make a TLS connection with the webhook.
class WebhookClientConfig(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        url = self.url()
        if url is not None:  # omit empty
            v['url'] = url
        service = self.service()
        if service is not None:  # omit empty
            v['service'] = service
        caBundle = self.caBundle()
        if caBundle:  # omit empty
            v['caBundle'] = caBundle
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
        return self._kwargs.get('url')
    
    # service is a reference to the service for this webhook. Either
    # service or url must be specified.
    # 
    # If the webhook is running within the cluster, then you should use `service`.
    @typechecked
    def service(self) -> Optional[ServiceReference]:
        return self._kwargs.get('service')
    
    # caBundle is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
    # If unspecified, system trust roots on the apiserver are used.
    @typechecked
    def caBundle(self) -> bytes:
        return self._kwargs.get('caBundle', b'')


# CustomResourceConversion describes how to convert different versions of a CR.
class CustomResourceConversion(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['strategy'] = self.strategy()
        webhookClientConfig = self.webhookClientConfig()
        if webhookClientConfig is not None:  # omit empty
            v['webhookClientConfig'] = webhookClientConfig
        conversionReviewVersions = self.conversionReviewVersions()
        if conversionReviewVersions:  # omit empty
            v['conversionReviewVersions'] = conversionReviewVersions
        return v
    
    # strategy specifies how custom resources are converted between versions. Allowed values are:
    # - `None`: The converter only change the apiVersion and would not touch any other field in the custom resource.
    # - `Webhook`: API Server will call to an external webhook to do the conversion. Additional information
    #   is needed for this option. This requires spec.preserveUnknownFields to be false, and spec.conversion.webhookClientConfig to be set.
    @typechecked
    def strategy(self) -> ConversionStrategyType:
        return self._kwargs.get('strategy', ConversionStrategyType['None'])
    
    # webhookClientConfig is the instructions for how to call the webhook if strategy is `Webhook`.
    # Required when `strategy` is set to `Webhook`.
    @typechecked
    def webhookClientConfig(self) -> Optional[WebhookClientConfig]:
        return self._kwargs.get('webhookClientConfig')
    
    # conversionReviewVersions is an ordered list of preferred `ConversionReview`
    # versions the Webhook expects. The API server will use the first version in
    # the list which it supports. If none of the versions specified in this list
    # are supported by API server, conversion will fail for the custom resource.
    # If a persisted Webhook configuration specifies allowed versions and does not
    # include any versions known to the API Server, calls to the webhook will fail.
    # Defaults to `["v1beta1"]`.
    @typechecked
    def conversionReviewVersions(self) -> List[str]:
        return self._kwargs.get('conversionReviewVersions', [])


# CustomResourceDefinitionNames indicates the names to serve this CustomResourceDefinition
class CustomResourceDefinitionNames(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['plural'] = self.plural()
        singular = self.singular()
        if singular:  # omit empty
            v['singular'] = singular
        shortNames = self.shortNames()
        if shortNames:  # omit empty
            v['shortNames'] = shortNames
        v['kind'] = self.kind()
        listKind = self.listKind()
        if listKind:  # omit empty
            v['listKind'] = listKind
        categories = self.categories()
        if categories:  # omit empty
            v['categories'] = categories
        return v
    
    # plural is the plural name of the resource to serve.
    # The custom resources are served under `/apis/<group>/<version>/.../<plural>`.
    # Must match the name of the CustomResourceDefinition (in the form `<names.plural>.<group>`).
    # Must be all lowercase.
    @typechecked
    def plural(self) -> str:
        return self._kwargs.get('plural', '')
    
    # singular is the singular name of the resource. It must be all lowercase. Defaults to lowercased `kind`.
    @typechecked
    def singular(self) -> Optional[str]:
        return self._kwargs.get('singular')
    
    # shortNames are short names for the resource, exposed in API discovery documents,
    # and used by clients to support invocations like `kubectl get <shortname>`.
    # It must be all lowercase.
    @typechecked
    def shortNames(self) -> List[str]:
        return self._kwargs.get('shortNames', [])
    
    # kind is the serialized kind of the resource. It is normally CamelCase and singular.
    # Custom resource instances will use this value as the `kind` attribute in API calls.
    @typechecked
    def kind(self) -> str:
        return self._kwargs.get('kind', '')
    
    # listKind is the serialized kind of the list for this resource. Defaults to "`kind`List".
    @typechecked
    def listKind(self) -> Optional[str]:
        return self._kwargs.get('listKind')
    
    # categories is a list of grouped resources this custom resource belongs to (e.g. 'all').
    # This is published in API discovery documents, and used by clients to support invocations like
    # `kubectl get all`.
    @typechecked
    def categories(self) -> List[str]:
        return self._kwargs.get('categories', [])


# CustomResourceSubresourceScale defines how to serve the scale subresource for CustomResources.
class CustomResourceSubresourceScale(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['specReplicasPath'] = self.specReplicasPath()
        v['statusReplicasPath'] = self.statusReplicasPath()
        labelSelectorPath = self.labelSelectorPath()
        if labelSelectorPath is not None:  # omit empty
            v['labelSelectorPath'] = labelSelectorPath
        return v
    
    # specReplicasPath defines the JSON path inside of a custom resource that corresponds to Scale `spec.replicas`.
    # Only JSON paths without the array notation are allowed.
    # Must be a JSON Path under `.spec`.
    # If there is no value under the given path in the custom resource, the `/scale` subresource will return an error on GET.
    @typechecked
    def specReplicasPath(self) -> str:
        return self._kwargs.get('specReplicasPath', '')
    
    # statusReplicasPath defines the JSON path inside of a custom resource that corresponds to Scale `status.replicas`.
    # Only JSON paths without the array notation are allowed.
    # Must be a JSON Path under `.status`.
    # If there is no value under the given path in the custom resource, the `status.replicas` value in the `/scale` subresource
    # will default to 0.
    @typechecked
    def statusReplicasPath(self) -> str:
        return self._kwargs.get('statusReplicasPath', '')
    
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
        return self._kwargs.get('labelSelectorPath')


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
    def render(self) -> addict.Dict:
        v = super().render()
        status = self.status()
        if status is not None:  # omit empty
            v['status'] = status
        scale = self.scale()
        if scale is not None:  # omit empty
            v['scale'] = scale
        return v
    
    # status indicates the custom resource should serve a `/status` subresource.
    # When enabled:
    # 1. requests to the custom resource primary endpoint ignore changes to the `status` stanza of the object.
    # 2. requests to the custom resource `/status` subresource ignore changes to anything other than the `status` stanza of the object.
    @typechecked
    def status(self) -> Optional[CustomResourceSubresourceStatus]:
        return self._kwargs.get('status')
    
    # scale indicates the custom resource should serve a `/scale` subresource that returns an `autoscaling/v1` Scale object.
    @typechecked
    def scale(self) -> Optional[CustomResourceSubresourceScale]:
        return self._kwargs.get('scale')


# ExternalDocumentation allows referencing an external resource for extended documentation.
class ExternalDocumentation(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        description = self.description()
        if description:  # omit empty
            v['description'] = description
        url = self.url()
        if url:  # omit empty
            v['url'] = url
        return v
    
    @typechecked
    def description(self) -> Optional[str]:
        return self._kwargs.get('description')
    
    @typechecked
    def url(self) -> Optional[str]:
        return self._kwargs.get('url')


# JSON represents any valid JSON value.
# These types are supported: bool, int64, float64, string, []interface{}, map[string]interface{} and nil.
class JSON(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['Raw'] = self.raw()
        return v
    
    @typechecked
    def raw(self) -> bytes:
        return self._kwargs.get('Raw', b'')


# JSONSchemaPropsOrArray represents a value that can either be a JSONSchemaProps
# or an array of JSONSchemaProps. Mainly here for serialization purposes.
class JSONSchemaPropsOrArray(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['Schema'] = self.schema()
        v['JSONSchemas'] = self.jSONSchemas()
        return v
    
    @typechecked
    def schema(self) -> Optional[JSONSchemaProps]:
        return self._kwargs.get('Schema')
    
    @typechecked
    def jSONSchemas(self) -> List[JSONSchemaProps]:
        return self._kwargs.get('JSONSchemas', [])


# JSONSchemaPropsOrBool represents JSONSchemaProps or a boolean value.
# Defaults to true for the boolean property.
class JSONSchemaPropsOrBool(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['Allows'] = self.allows()
        v['Schema'] = self.schema()
        return v
    
    @typechecked
    def allows(self) -> bool:
        return self._kwargs.get('Allows', False)
    
    @typechecked
    def schema(self) -> Optional[JSONSchemaProps]:
        return self._kwargs.get('Schema')


# JSONSchemaPropsOrStringArray represents a JSONSchemaProps or a string array.
class JSONSchemaPropsOrStringArray(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['Schema'] = self.schema()
        v['Property'] = self.property()
        return v
    
    @typechecked
    def schema(self) -> Optional[JSONSchemaProps]:
        return self._kwargs.get('Schema')
    
    @typechecked
    def property(self) -> List[str]:
        return self._kwargs.get('Property', [])


# JSONSchemaProps is a JSON-Schema following Specification Draft 4 (http://json-schema.org/).
class JSONSchemaProps(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        id = self.id()
        if id:  # omit empty
            v['id'] = id
        schema = self.schema()
        if schema:  # omit empty
            v['$schema'] = schema
        ref = self.ref()
        if ref is not None:  # omit empty
            v['$ref'] = ref
        description = self.description()
        if description:  # omit empty
            v['description'] = description
        type = self.type()
        if type:  # omit empty
            v['type'] = type
        format = self.format()
        if format:  # omit empty
            v['format'] = format
        title = self.title()
        if title:  # omit empty
            v['title'] = title
        default = self.default()
        if default is not None:  # omit empty
            v['default'] = default
        maximum = self.maximum()
        if maximum is not None:  # omit empty
            v['maximum'] = maximum
        exclusiveMaximum = self.exclusiveMaximum()
        if exclusiveMaximum:  # omit empty
            v['exclusiveMaximum'] = exclusiveMaximum
        minimum = self.minimum()
        if minimum is not None:  # omit empty
            v['minimum'] = minimum
        exclusiveMinimum = self.exclusiveMinimum()
        if exclusiveMinimum:  # omit empty
            v['exclusiveMinimum'] = exclusiveMinimum
        maxLength = self.maxLength()
        if maxLength is not None:  # omit empty
            v['maxLength'] = maxLength
        minLength = self.minLength()
        if minLength is not None:  # omit empty
            v['minLength'] = minLength
        pattern = self.pattern()
        if pattern:  # omit empty
            v['pattern'] = pattern
        maxItems = self.maxItems()
        if maxItems is not None:  # omit empty
            v['maxItems'] = maxItems
        minItems = self.minItems()
        if minItems is not None:  # omit empty
            v['minItems'] = minItems
        uniqueItems = self.uniqueItems()
        if uniqueItems:  # omit empty
            v['uniqueItems'] = uniqueItems
        multipleOf = self.multipleOf()
        if multipleOf is not None:  # omit empty
            v['multipleOf'] = multipleOf
        enum = self.enum()
        if enum:  # omit empty
            v['enum'] = enum
        maxProperties = self.maxProperties()
        if maxProperties is not None:  # omit empty
            v['maxProperties'] = maxProperties
        minProperties = self.minProperties()
        if minProperties is not None:  # omit empty
            v['minProperties'] = minProperties
        required = self.required()
        if required:  # omit empty
            v['required'] = required
        items = self.items()
        if items is not None:  # omit empty
            v['items'] = items
        allOf = self.allOf()
        if allOf:  # omit empty
            v['allOf'] = allOf
        oneOf = self.oneOf()
        if oneOf:  # omit empty
            v['oneOf'] = oneOf
        anyOf = self.anyOf()
        if anyOf:  # omit empty
            v['anyOf'] = anyOf
        not_ = self.not_()
        if not_ is not None:  # omit empty
            v['not'] = not_
        properties = self.properties()
        if properties:  # omit empty
            v['properties'] = properties
        additionalProperties = self.additionalProperties()
        if additionalProperties is not None:  # omit empty
            v['additionalProperties'] = additionalProperties
        patternProperties = self.patternProperties()
        if patternProperties:  # omit empty
            v['patternProperties'] = patternProperties
        dependencies = self.dependencies()
        if dependencies:  # omit empty
            v['dependencies'] = dependencies
        additionalItems = self.additionalItems()
        if additionalItems is not None:  # omit empty
            v['additionalItems'] = additionalItems
        definitions = self.definitions()
        if definitions:  # omit empty
            v['definitions'] = definitions
        externalDocs = self.externalDocs()
        if externalDocs is not None:  # omit empty
            v['externalDocs'] = externalDocs
        example = self.example()
        if example is not None:  # omit empty
            v['example'] = example
        nullable = self.nullable()
        if nullable:  # omit empty
            v['nullable'] = nullable
        xKubernetesPreserveUnknownFields = self.xKubernetesPreserveUnknownFields()
        if xKubernetesPreserveUnknownFields is not None:  # omit empty
            v['x-kubernetes-preserve-unknown-fields'] = xKubernetesPreserveUnknownFields
        xKubernetesEmbeddedResource = self.xKubernetesEmbeddedResource()
        if xKubernetesEmbeddedResource:  # omit empty
            v['x-kubernetes-embedded-resource'] = xKubernetesEmbeddedResource
        xKubernetesIntOrString = self.xKubernetesIntOrString()
        if xKubernetesIntOrString:  # omit empty
            v['x-kubernetes-int-or-string'] = xKubernetesIntOrString
        xKubernetesListMapKeys = self.xKubernetesListMapKeys()
        if xKubernetesListMapKeys:  # omit empty
            v['x-kubernetes-list-map-keys'] = xKubernetesListMapKeys
        xKubernetesListType = self.xKubernetesListType()
        if xKubernetesListType is not None:  # omit empty
            v['x-kubernetes-list-type'] = xKubernetesListType
        return v
    
    @typechecked
    def id(self) -> Optional[str]:
        return self._kwargs.get('id')
    
    @typechecked
    def schema(self) -> Optional[JSONSchemaURL]:
        return self._kwargs.get('$schema')
    
    @typechecked
    def ref(self) -> Optional[str]:
        return self._kwargs.get('$ref')
    
    @typechecked
    def description(self) -> Optional[str]:
        return self._kwargs.get('description')
    
    @typechecked
    def type(self) -> Optional[str]:
        return self._kwargs.get('type')
    
    @typechecked
    def format(self) -> Optional[str]:
        return self._kwargs.get('format')
    
    @typechecked
    def title(self) -> Optional[str]:
        return self._kwargs.get('title')
    
    # default is a default value for undefined object fields.
    # Defaulting is a beta feature under the CustomResourceDefaulting feature gate.
    # CustomResourceDefinitions with defaults must be created using the v1 (or newer) CustomResourceDefinition API.
    @typechecked
    def default(self) -> Optional[JSON]:
        return self._kwargs.get('default')
    
    @typechecked
    def maximum(self) -> Optional[float]:
        return self._kwargs.get('maximum')
    
    @typechecked
    def exclusiveMaximum(self) -> Optional[bool]:
        return self._kwargs.get('exclusiveMaximum')
    
    @typechecked
    def minimum(self) -> Optional[float]:
        return self._kwargs.get('minimum')
    
    @typechecked
    def exclusiveMinimum(self) -> Optional[bool]:
        return self._kwargs.get('exclusiveMinimum')
    
    @typechecked
    def maxLength(self) -> Optional[int]:
        return self._kwargs.get('maxLength')
    
    @typechecked
    def minLength(self) -> Optional[int]:
        return self._kwargs.get('minLength')
    
    @typechecked
    def pattern(self) -> Optional[str]:
        return self._kwargs.get('pattern')
    
    @typechecked
    def maxItems(self) -> Optional[int]:
        return self._kwargs.get('maxItems')
    
    @typechecked
    def minItems(self) -> Optional[int]:
        return self._kwargs.get('minItems')
    
    @typechecked
    def uniqueItems(self) -> Optional[bool]:
        return self._kwargs.get('uniqueItems')
    
    @typechecked
    def multipleOf(self) -> Optional[float]:
        return self._kwargs.get('multipleOf')
    
    @typechecked
    def enum(self) -> List[JSON]:
        return self._kwargs.get('enum', [])
    
    @typechecked
    def maxProperties(self) -> Optional[int]:
        return self._kwargs.get('maxProperties')
    
    @typechecked
    def minProperties(self) -> Optional[int]:
        return self._kwargs.get('minProperties')
    
    @typechecked
    def required(self) -> List[str]:
        return self._kwargs.get('required', [])
    
    @typechecked
    def items(self) -> Optional[JSONSchemaPropsOrArray]:
        return self._kwargs.get('items')
    
    @typechecked
    def allOf(self) -> List[JSONSchemaProps]:
        return self._kwargs.get('allOf', [])
    
    @typechecked
    def oneOf(self) -> List[JSONSchemaProps]:
        return self._kwargs.get('oneOf', [])
    
    @typechecked
    def anyOf(self) -> List[JSONSchemaProps]:
        return self._kwargs.get('anyOf', [])
    
    @typechecked
    def not_(self) -> Optional[JSONSchemaProps]:
        return self._kwargs.get('not')
    
    @typechecked
    def properties(self) -> Dict[str, JSONSchemaProps]:
        return self._kwargs.get('properties', addict.Dict())
    
    @typechecked
    def additionalProperties(self) -> Optional[JSONSchemaPropsOrBool]:
        return self._kwargs.get('additionalProperties')
    
    @typechecked
    def patternProperties(self) -> Dict[str, JSONSchemaProps]:
        return self._kwargs.get('patternProperties', addict.Dict())
    
    @typechecked
    def dependencies(self) -> Dict[str, JSONSchemaPropsOrStringArray]:
        return self._kwargs.get('dependencies', addict.Dict())
    
    @typechecked
    def additionalItems(self) -> Optional[JSONSchemaPropsOrBool]:
        return self._kwargs.get('additionalItems')
    
    @typechecked
    def definitions(self) -> Dict[str, JSONSchemaProps]:
        return self._kwargs.get('definitions', addict.Dict())
    
    @typechecked
    def externalDocs(self) -> Optional[ExternalDocumentation]:
        return self._kwargs.get('externalDocs')
    
    @typechecked
    def example(self) -> Optional[JSON]:
        return self._kwargs.get('example')
    
    @typechecked
    def nullable(self) -> Optional[bool]:
        return self._kwargs.get('nullable')
    
    # x-kubernetes-preserve-unknown-fields stops the API server
    # decoding step from pruning fields which are not specified
    # in the validation schema. This affects fields recursively,
    # but switches back to normal pruning behaviour if nested
    # properties or additionalProperties are specified in the schema.
    # This can either be true or undefined. False is forbidden.
    @typechecked
    def xKubernetesPreserveUnknownFields(self) -> Optional[bool]:
        return self._kwargs.get('x-kubernetes-preserve-unknown-fields')
    
    # x-kubernetes-embedded-resource defines that the value is an
    # embedded Kubernetes runtime.Object, with TypeMeta and
    # ObjectMeta. The type must be object. It is allowed to further
    # restrict the embedded object. kind, apiVersion and metadata
    # are validated automatically. x-kubernetes-preserve-unknown-fields
    # is allowed to be true, but does not have to be if the object
    # is fully specified (up to kind, apiVersion, metadata).
    @typechecked
    def xKubernetesEmbeddedResource(self) -> Optional[bool]:
        return self._kwargs.get('x-kubernetes-embedded-resource')
    
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
        return self._kwargs.get('x-kubernetes-int-or-string')
    
    # x-kubernetes-list-map-keys annotates an array with the x-kubernetes-list-type `map` by specifying the keys used
    # as the index of the map.
    # 
    # This tag MUST only be used on lists that have the "x-kubernetes-list-type"
    # extension set to "map". Also, the values specified for this attribute must
    # be a scalar typed field of the child structure (no nesting is supported).
    @typechecked
    def xKubernetesListMapKeys(self) -> List[str]:
        return self._kwargs.get('x-kubernetes-list-map-keys', [])
    
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
        return self._kwargs.get('x-kubernetes-list-type')


# CustomResourceValidation is a list of validation methods for CustomResources.
class CustomResourceValidation(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        openAPIV3Schema = self.openAPIV3Schema()
        if openAPIV3Schema is not None:  # omit empty
            v['openAPIV3Schema'] = openAPIV3Schema
        return v
    
    # openAPIV3Schema is the OpenAPI v3 schema to use for validation and pruning.
    @typechecked
    def openAPIV3Schema(self) -> Optional[JSONSchemaProps]:
        return self._kwargs.get('openAPIV3Schema')


# CustomResourceDefinitionVersion describes a version for CRD.
class CustomResourceDefinitionVersion(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['name'] = self.name()
        v['served'] = self.served()
        v['storage'] = self.storage()
        schema = self.schema()
        if schema is not None:  # omit empty
            v['schema'] = schema
        subresources = self.subresources()
        if subresources is not None:  # omit empty
            v['subresources'] = subresources
        additionalPrinterColumns = self.additionalPrinterColumns()
        if additionalPrinterColumns:  # omit empty
            v['additionalPrinterColumns'] = additionalPrinterColumns.values()  # named list
        return v
    
    # name is the version name, e.g. “v1”, “v2beta1”, etc.
    # The custom resources are served under this version at `/apis/<group>/<version>/...` if `served` is true.
    @typechecked
    def name(self) -> str:
        return self._kwargs.get('name', '')
    
    # served is a flag enabling/disabling this version from being served via REST APIs
    @typechecked
    def served(self) -> bool:
        return self._kwargs.get('served', False)
    
    # storage indicates this version should be used when persisting custom resources to storage.
    # There must be exactly one version with storage=true.
    @typechecked
    def storage(self) -> bool:
        return self._kwargs.get('storage', False)
    
    # schema describes the schema used for validation and pruning of this version of the custom resource.
    # Top-level and per-version schemas are mutually exclusive.
    # Per-version schemas must not all be set to identical values (top-level validation schema should be used instead).
    @typechecked
    def schema(self) -> Optional[CustomResourceValidation]:
        return self._kwargs.get('schema')
    
    # subresources specify what subresources this version of the defined custom resource have.
    # Top-level and per-version subresources are mutually exclusive.
    # Per-version subresources must not all be set to identical values (top-level subresources should be used instead).
    @typechecked
    def subresources(self) -> Optional[CustomResourceSubresources]:
        return self._kwargs.get('subresources')
    
    # additionalPrinterColumns specifies additional columns returned in Table output.
    # See https://kubernetes.io/docs/reference/using-api/api-concepts/#receiving-resources-as-tables for details.
    # Top-level and per-version columns are mutually exclusive.
    # Per-version columns must not all be set to identical values (top-level columns should be used instead).
    # If no top-level or per-version columns are specified, a single column displaying the age of the custom resource is used.
    @typechecked
    def additionalPrinterColumns(self) -> Dict[str, CustomResourceColumnDefinition]:
        return self._kwargs.get('additionalPrinterColumns', addict.Dict())


# CustomResourceDefinitionSpec describes how a user wants their resource to appear
class CustomResourceDefinitionSpec(types.Object):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['group'] = self.group()
        v['names'] = self.names()
        v['scope'] = self.scope()
        validation = self.validation()
        if validation is not None:  # omit empty
            v['validation'] = validation
        subresources = self.subresources()
        if subresources is not None:  # omit empty
            v['subresources'] = subresources
        versions = self.versions()
        if versions:  # omit empty
            v['versions'] = versions.values()  # named list
        additionalPrinterColumns = self.additionalPrinterColumns()
        if additionalPrinterColumns:  # omit empty
            v['additionalPrinterColumns'] = additionalPrinterColumns.values()  # named list
        conversion = self.conversion()
        if conversion is not None:  # omit empty
            v['conversion'] = conversion
        return v
    
    # group is the API group of the defined custom resource.
    # The custom resources are served under `/apis/<group>/...`.
    # Must match the name of the CustomResourceDefinition (in the form `<names.plural>.<group>`).
    @typechecked
    def group(self) -> str:
        return self._kwargs.get('group', '')
    
    # names specify the resource and kind names for the custom resource.
    @typechecked
    def names(self) -> CustomResourceDefinitionNames:
        return self._kwargs.get('names', CustomResourceDefinitionNames())
    
    # scope indicates whether the defined custom resource is cluster- or namespace-scoped.
    # Allowed values are `Cluster` and `Namespaced`. Default is `Namespaced`.
    @typechecked
    def scope(self) -> ResourceScope:
        return self._kwargs.get('scope', ResourceScope['NamespaceScoped'])
    
    # validation describes the schema used for validation and pruning of the custom resource.
    # If present, this validation schema is used to validate all versions.
    # Top-level and per-version schemas are mutually exclusive.
    @typechecked
    def validation(self) -> Optional[CustomResourceValidation]:
        return self._kwargs.get('validation')
    
    # subresources specify what subresources the defined custom resource has.
    # If present, this field configures subresources for all versions.
    # Top-level and per-version subresources are mutually exclusive.
    @typechecked
    def subresources(self) -> Optional[CustomResourceSubresources]:
        return self._kwargs.get('subresources')
    
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
        return self._kwargs.get('versions', addict.Dict())
    
    # additionalPrinterColumns specifies additional columns returned in Table output.
    # See https://kubernetes.io/docs/reference/using-api/api-concepts/#receiving-resources-as-tables for details.
    # If present, this field configures columns for all versions.
    # Top-level and per-version columns are mutually exclusive.
    # If no top-level or per-version columns are specified, a single column displaying the age of the custom resource is used.
    @typechecked
    def additionalPrinterColumns(self) -> Dict[str, CustomResourceColumnDefinition]:
        return self._kwargs.get('additionalPrinterColumns', addict.Dict())
    
    # conversion defines conversion settings for the CRD.
    @typechecked
    def conversion(self) -> Optional[CustomResourceConversion]:
        return self._kwargs.get('conversion', CustomResourceConversion())


# CustomResourceDefinition represents a resource that should be exposed on the API server.  Its name MUST be in the format
# <.spec.name>.<.spec.group>.
# Deprecated in v1.16, planned for removal in v1.19. Use apiextensions.k8s.io/v1 CustomResourceDefinition instead.
class CustomResourceDefinition(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'apiextensions.k8s.io/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'CustomResourceDefinition'
    
    # spec describes how the user wants the resources to appear
    @typechecked
    def spec(self) -> CustomResourceDefinitionSpec:
        return self._kwargs.get('spec', CustomResourceDefinitionSpec())
