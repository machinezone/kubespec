# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import runtime
from kubespec.k8s import v1 as k8sv1
from typeguard import check_type, typechecked
from typing import Any, Dict, List, Optional


class BrokerTemplateInstanceSpec(types.Object):
    """
    BrokerTemplateInstanceSpec describes the state of a BrokerTemplateInstance.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        templateInstance: "k8sv1.ObjectReference" = None,
        secret: "k8sv1.ObjectReference" = None,
        bindingIDs: List[str] = None,
    ):
        super().__init__()
        self.__templateInstance = (
            templateInstance
            if templateInstance is not None
            else k8sv1.ObjectReference()
        )
        self.__secret = secret if secret is not None else k8sv1.ObjectReference()
        self.__bindingIDs = bindingIDs if bindingIDs is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        templateInstance = self.templateInstance()
        check_type("templateInstance", templateInstance, "k8sv1.ObjectReference")
        v["templateInstance"] = templateInstance
        secret = self.secret()
        check_type("secret", secret, "k8sv1.ObjectReference")
        v["secret"] = secret
        bindingIDs = self.bindingIDs()
        check_type("bindingIDs", bindingIDs, Optional[List[str]])
        if bindingIDs:  # omit empty
            v["bindingIDs"] = bindingIDs
        return v

    def templateInstance(self) -> "k8sv1.ObjectReference":
        """
        templateinstance is a reference to a TemplateInstance object residing
        in a namespace.
        """
        return self.__templateInstance

    def secret(self) -> "k8sv1.ObjectReference":
        """
        secret is a reference to a Secret object residing in a namespace,
        containing the necessary template parameters.
        """
        return self.__secret

    def bindingIDs(self) -> Optional[List[str]]:
        """
        bindingids is a list of 'binding_id's provided during successive bind
        calls to the template service broker.
        """
        return self.__bindingIDs


class BrokerTemplateInstance(base.TypedObject, base.MetadataObject):
    """
    BrokerTemplateInstance holds the service broker-related state associated with
    a TemplateInstance.  BrokerTemplateInstance is part of an experimental API.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "BrokerTemplateInstanceSpec" = None,
    ):
        super().__init__(
            apiVersion="template.openshift.io/v1",
            kind="BrokerTemplateInstance",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else BrokerTemplateInstanceSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "BrokerTemplateInstanceSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "BrokerTemplateInstanceSpec":
        """
        spec describes the state of this BrokerTemplateInstance.
        """
        return self.__spec


class Parameter(types.Object):
    """
    Parameter defines a name/value variable that is to be processed during
    the Template to Config transformation.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        displayName: str = None,
        description: str = None,
        value: str = None,
        generate: str = None,
        from_: str = None,
        required: bool = None,
    ):
        super().__init__()
        self.__name = name
        self.__displayName = displayName
        self.__description = description
        self.__value = value
        self.__generate = generate
        self.__from_ = from_
        self.__required = required

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        displayName = self.displayName()
        check_type("displayName", displayName, Optional[str])
        if displayName:  # omit empty
            v["displayName"] = displayName
        description = self.description()
        check_type("description", description, Optional[str])
        if description:  # omit empty
            v["description"] = description
        value = self.value()
        check_type("value", value, Optional[str])
        if value:  # omit empty
            v["value"] = value
        generate = self.generate()
        check_type("generate", generate, Optional[str])
        if generate:  # omit empty
            v["generate"] = generate
        from_ = self.from_()
        check_type("from_", from_, Optional[str])
        if from_:  # omit empty
            v["from"] = from_
        required = self.required()
        check_type("required", required, Optional[bool])
        if required:  # omit empty
            v["required"] = required
        return v

    def name(self) -> str:
        """
        Name must be set and it can be referenced in Template
        Items using ${PARAMETER_NAME}. Required.
        """
        return self.__name

    def displayName(self) -> Optional[str]:
        """
        Optional: The name that will show in UI instead of parameter 'Name'
        """
        return self.__displayName

    def description(self) -> Optional[str]:
        """
        Description of a parameter. Optional.
        """
        return self.__description

    def value(self) -> Optional[str]:
        """
        Value holds the Parameter data. If specified, the generator will be
        ignored. The value replaces all occurrences of the Parameter ${Name}
        expression during the Template to Config transformation. Optional.
        """
        return self.__value

    def generate(self) -> Optional[str]:
        """
        generate specifies the generator to be used to generate random string
        from an input value specified by From field. The result string is
        stored into Value field. If empty, no generator is being used, leaving
        the result Value untouched. Optional.
        
        The only supported generator is "expression", which accepts a "from"
        value in the form of a simple regular expression containing the
        range expression "[a-zA-Z0-9]", and the length expression "a{length}".
        
        Examples:
        
        from             | value
        -----------------------------
        "test[0-9]{1}x"  | "test7x"
        "[0-1]{8}"       | "01001100"
        "0x[A-F0-9]{4}"  | "0xB3AF"
        "[a-zA-Z0-9]{8}" | "hW4yQU5i"
        """
        return self.__generate

    def from_(self) -> Optional[str]:
        """
        From is an input value for the generator. Optional.
        """
        return self.__from_

    def required(self) -> Optional[bool]:
        """
        Optional: Indicates the parameter must have a value.  Defaults to false.
        """
        return self.__required


class Template(base.TypedObject, base.NamespacedMetadataObject):
    """
    Template contains the inputs needed to produce a Config.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        message: str = None,
        objects: List["runtime.RawExtension"] = None,
        parameters: List["Parameter"] = None,
        labels: Dict[str, str] = None,
    ):
        super().__init__(
            apiVersion="template.openshift.io/v1",
            kind="Template",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__message = message
        self.__objects = objects if objects is not None else []
        self.__parameters = parameters if parameters is not None else []
        self.__labels = labels if labels is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        message = self.message()
        check_type("message", message, Optional[str])
        if message:  # omit empty
            v["message"] = message
        objects = self.objects()
        check_type("objects", objects, List["runtime.RawExtension"])
        v["objects"] = objects
        parameters = self.parameters()
        check_type("parameters", parameters, Optional[List["Parameter"]])
        if parameters:  # omit empty
            v["parameters"] = parameters
        labels = self.labels()
        check_type("labels", labels, Optional[Dict[str, str]])
        if labels:  # omit empty
            v["labels"] = labels
        return v

    def message(self) -> Optional[str]:
        """
        message is an optional instructional message that will
        be displayed when this template is instantiated.
        This field should inform the user how to utilize the newly created resources.
        Parameter substitution will be performed on the message before being
        displayed so that generated credentials and other parameters can be
        included in the output.
        """
        return self.__message

    def objects(self) -> List["runtime.RawExtension"]:
        """
        objects is an array of resources to include in this template.
        If a namespace value is hardcoded in the object, it will be removed
        during template instantiation, however if the namespace value
        is, or contains, a ${PARAMETER_REFERENCE}, the resolved
        value after parameter substitution will be respected and the object
        will be created in that namespace.
        +kubebuilder:pruning:PreserveUnknownFields
        """
        return self.__objects

    def parameters(self) -> Optional[List["Parameter"]]:
        """
        parameters is an optional array of Parameters used during the
        Template to Config transformation.
        """
        return self.__parameters

    def labels(self) -> Optional[Dict[str, str]]:
        """
        labels is a optional set of labels that are applied to every
        object during the Template to Config transformation.
        """
        return self.__labels


class TemplateInstanceRequester(types.Object):
    """
    TemplateInstanceRequester holds the identity of an agent requesting a
    template instantiation.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        username: str = None,
        uid: str = None,
        groups: List[str] = None,
        extra: Dict[str, List[str]] = None,
    ):
        super().__init__()
        self.__username = username
        self.__uid = uid
        self.__groups = groups if groups is not None else []
        self.__extra = extra if extra is not None else {}

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        username = self.username()
        check_type("username", username, Optional[str])
        if username:  # omit empty
            v["username"] = username
        uid = self.uid()
        check_type("uid", uid, Optional[str])
        if uid:  # omit empty
            v["uid"] = uid
        groups = self.groups()
        check_type("groups", groups, Optional[List[str]])
        if groups:  # omit empty
            v["groups"] = groups
        extra = self.extra()
        check_type("extra", extra, Optional[Dict[str, List[str]]])
        if extra:  # omit empty
            v["extra"] = extra
        return v

    def username(self) -> Optional[str]:
        """
        username uniquely identifies this user among all active users.
        """
        return self.__username

    def uid(self) -> Optional[str]:
        """
        uid is a unique value that identifies this user across time; if this user is
        deleted and another user by the same name is added, they will have
        different UIDs.
        """
        return self.__uid

    def groups(self) -> Optional[List[str]]:
        """
        groups represent the groups this user is a part of.
        """
        return self.__groups

    def extra(self) -> Optional[Dict[str, List[str]]]:
        """
        extra holds additional information provided by the authenticator.
        """
        return self.__extra


class TemplateInstanceSpec(types.Object):
    """
    TemplateInstanceSpec describes the desired state of a TemplateInstance.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        template: "Template" = None,
        secret: "k8sv1.LocalObjectReference" = None,
        requester: "TemplateInstanceRequester" = None,
    ):
        super().__init__()
        self.__template = template if template is not None else Template()
        self.__secret = secret
        self.__requester = requester

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        template = self.template()
        check_type("template", template, "Template")
        v["template"] = template
        secret = self.secret()
        check_type("secret", secret, Optional["k8sv1.LocalObjectReference"])
        if secret is not None:  # omit empty
            v["secret"] = secret
        requester = self.requester()
        check_type("requester", requester, Optional["TemplateInstanceRequester"])
        v["requester"] = requester
        return v

    def template(self) -> "Template":
        """
        template is a full copy of the template for instantiation.
        """
        return self.__template

    def secret(self) -> Optional["k8sv1.LocalObjectReference"]:
        """
        secret is a reference to a Secret object containing the necessary
        template parameters.
        """
        return self.__secret

    def requester(self) -> Optional["TemplateInstanceRequester"]:
        """
        requester holds the identity of the agent requesting the template
        instantiation.
        """
        return self.__requester


class TemplateInstance(base.TypedObject, base.NamespacedMetadataObject):
    """
    TemplateInstance requests and records the instantiation of a Template.
    TemplateInstance is part of an experimental API.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "TemplateInstanceSpec" = None,
    ):
        super().__init__(
            apiVersion="template.openshift.io/v1",
            kind="TemplateInstance",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else TemplateInstanceSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, "TemplateInstanceSpec")
        v["spec"] = spec
        return v

    def spec(self) -> "TemplateInstanceSpec":
        """
        spec describes the desired state of this TemplateInstance.
        """
        return self.__spec
