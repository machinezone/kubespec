# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, List, Optional

from k8s import base
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


FailurePolicyType = base.Enum(
    "FailurePolicyType",
    {
        # Fail means that an error calling the webhook causes the admission to fail.
        "Fail": "Fail",
        # Ignore means that an error calling the webhook is ignored.
        "Ignore": "Ignore",
    },
)


# MatchPolicyType specifies the type of match policy
MatchPolicyType = base.Enum(
    "MatchPolicyType",
    {
        # Equivalent means requests should be sent to the webhook if they modify a resource listed in rules via another API group or version.
        "Equivalent": "Equivalent",
        # Exact means requests should only be sent to the webhook if they exactly match a given rule
        "Exact": "Exact",
    },
)


OperationType = base.Enum(
    "OperationType",
    {
        "All": "*",
        "Connect": "CONNECT",
        "Create": "CREATE",
        "Delete": "DELETE",
        "Update": "UPDATE",
    },
)


# ReinvocationPolicyType specifies what type of policy the admission hook uses.
ReinvocationPolicyType = base.Enum(
    "ReinvocationPolicyType",
    {
        # IfNeeded indicates that the webhook may be called at least one
        # additional time as part of the admission evaluation if the object being admitted is
        # modified by other admission plugins after the initial webhook call.
        "IfNeeded": "IfNeeded",
        # Never indicates that the webhook must not be called more than once in a
        # single admission evaluation.
        "Never": "Never",
    },
)


ScopeType = base.Enum(
    "ScopeType",
    {
        # All means that all scopes are included.
        "All": "*",
        # Cluster means that scope is limited to cluster-scoped objects.
        # Namespace objects are cluster-scoped.
        "Cluster": "Cluster",
        # Namespaced means that scope is limited to namespaced objects.
        "Namespaced": "Namespaced",
    },
)


SideEffectClass = base.Enum(
    "SideEffectClass",
    {
        # None means that calling the webhook will have no side effects.
        "None": "None",
        # NoneOnDryRun means that calling the webhook will possibly have side effects, but if the
        # request being reviewed has the dry-run attribute, the side effects will be suppressed.
        "NoneOnDryRun": "NoneOnDryRun",
        # Some means that calling the webhook will possibly have side effects.
        # If a request with the dry-run attribute would trigger a call to this webhook, the request will instead fail.
        "Some": "Some",
        # Unknown means that no information is known about the side effects of calling the webhook.
        # If a request with the dry-run attribute would trigger a call to this webhook, the request will instead fail.
        "Unknown": "Unknown",
    },
)


# Rule is a tuple of APIGroups, APIVersion, and Resources.It is recommended
# to make sure that all the tuple expansions are valid.
class Rule(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        apiGroups = self.apiGroups()
        if apiGroups:  # omit empty
            v["apiGroups"] = apiGroups
        apiVersions = self.apiVersions()
        if apiVersions:  # omit empty
            v["apiVersions"] = apiVersions
        resources = self.resources()
        if resources:  # omit empty
            v["resources"] = resources
        scope = self.scope()
        if scope is not None:  # omit empty
            v["scope"] = scope
        return v

    # APIGroups is the API groups the resources belong to. '*' is all groups.
    # If '*' is present, the length of the slice must be one.
    # Required.
    @typechecked
    def apiGroups(self) -> List[str]:
        if "apiGroups" in self._kwargs:
            return self._kwargs["apiGroups"]
        if "apiGroups" in self._context and check_return_type(
            self._context["apiGroups"]
        ):
            return self._context["apiGroups"]
        return []

    # APIVersions is the API versions the resources belong to. '*' is all versions.
    # If '*' is present, the length of the slice must be one.
    # Required.
    @typechecked
    def apiVersions(self) -> List[str]:
        if "apiVersions" in self._kwargs:
            return self._kwargs["apiVersions"]
        if "apiVersions" in self._context and check_return_type(
            self._context["apiVersions"]
        ):
            return self._context["apiVersions"]
        return []

    # Resources is a list of resources this rule applies to.
    #
    # For example:
    # 'pods' means pods.
    # 'pods/log' means the log subresource of pods.
    # '*' means all resources, but not subresources.
    # 'pods/*' means all subresources of pods.
    # '*/scale' means all scale subresources.
    # '*/*' means all resources and their subresources.
    #
    # If wildcard is present, the validation rule will ensure resources do not
    # overlap with each other.
    #
    # Depending on the enclosing object, subresources might not be allowed.
    # Required.
    @typechecked
    def resources(self) -> List[str]:
        if "resources" in self._kwargs:
            return self._kwargs["resources"]
        if "resources" in self._context and check_return_type(
            self._context["resources"]
        ):
            return self._context["resources"]
        return []

    # scope specifies the scope of this rule.
    # Valid values are "Cluster", "Namespaced", and "*"
    # "Cluster" means that only cluster-scoped resources will match this rule.
    # Namespace API objects are cluster-scoped.
    # "Namespaced" means that only namespaced resources will match this rule.
    # "*" means that there are no scope restrictions.
    # Subresources match the scope of their parent resource.
    # Default is "*".
    @typechecked
    def scope(self) -> Optional[ScopeType]:
        if "scope" in self._kwargs:
            return self._kwargs["scope"]
        if "scope" in self._context and check_return_type(self._context["scope"]):
            return self._context["scope"]
        return None


# RuleWithOperations is a tuple of Operations and Resources. It is recommended to make
# sure that all the tuple expansions are valid.
class RuleWithOperations(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        operations = self.operations()
        if operations:  # omit empty
            v["operations"] = operations
        v.update(self.rule().render())  # inline
        return v

    # Operations is the operations the admission hook cares about - CREATE, UPDATE, or *
    # for all operations.
    # If '*' is present, the length of the slice must be one.
    # Required.
    @typechecked
    def operations(self) -> List[OperationType]:
        if "operations" in self._kwargs:
            return self._kwargs["operations"]
        if "operations" in self._context and check_return_type(
            self._context["operations"]
        ):
            return self._context["operations"]
        return []

    # Rule is embedded, it describes other criteria of the rule, like
    # APIGroups, APIVersions, Resources, etc.
    @typechecked
    def rule(self) -> Rule:
        if "rule" in self._kwargs:
            return self._kwargs["rule"]
        if "rule" in self._context and check_return_type(self._context["rule"]):
            return self._context["rule"]
        with context.Scope(**self._context):
            return Rule()


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

    # `namespace` is the namespace of the service.
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

    # `name` is the name of the service.
    # Required
    @typechecked
    def name(self) -> str:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return ""

    # `path` is an optional URL path which will be sent in any request to
    # this service.
    @typechecked
    def path(self) -> Optional[str]:
        if "path" in self._kwargs:
            return self._kwargs["path"]
        if "path" in self._context and check_return_type(self._context["path"]):
            return self._context["path"]
        return None

    # If specified, the port on the service that hosting webhook.
    # Default to 443 for backward compatibility.
    # `port` should be a valid port number (1-65535, inclusive).
    @typechecked
    def port(self) -> Optional[int]:
        if "port" in self._kwargs:
            return self._kwargs["port"]
        if "port" in self._context and check_return_type(self._context["port"]):
            return self._context["port"]
        return 443


# WebhookClientConfig contains the information to make a TLS
# connection with the webhook
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

    # `url` gives the location of the webhook, in standard URL form
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

    # `service` is a reference to the service for this webhook. Either
    # `service` or `url` must be specified.
    #
    # If the webhook is running within the cluster, then you should use `service`.
    @typechecked
    def service(self) -> Optional[ServiceReference]:
        if "service" in self._kwargs:
            return self._kwargs["service"]
        if "service" in self._context and check_return_type(self._context["service"]):
            return self._context["service"]
        return None

    # `caBundle` is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
    # If unspecified, system trust roots on the apiserver are used.
    @typechecked
    def caBundle(self) -> bytes:
        if "caBundle" in self._kwargs:
            return self._kwargs["caBundle"]
        if "caBundle" in self._context and check_return_type(self._context["caBundle"]):
            return self._context["caBundle"]
        return b""


# MutatingWebhook describes an admission webhook and the resources and operations it applies to.
class MutatingWebhook(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["name"] = self.name()
        v["clientConfig"] = self.clientConfig()
        rules = self.rules()
        if rules:  # omit empty
            v["rules"] = rules
        failurePolicy = self.failurePolicy()
        if failurePolicy is not None:  # omit empty
            v["failurePolicy"] = failurePolicy
        matchPolicy = self.matchPolicy()
        if matchPolicy is not None:  # omit empty
            v["matchPolicy"] = matchPolicy
        namespaceSelector = self.namespaceSelector()
        if namespaceSelector is not None:  # omit empty
            v["namespaceSelector"] = namespaceSelector
        objectSelector = self.objectSelector()
        if objectSelector is not None:  # omit empty
            v["objectSelector"] = objectSelector
        v["sideEffects"] = self.sideEffects()
        timeoutSeconds = self.timeoutSeconds()
        if timeoutSeconds is not None:  # omit empty
            v["timeoutSeconds"] = timeoutSeconds
        v["admissionReviewVersions"] = self.admissionReviewVersions()
        reinvocationPolicy = self.reinvocationPolicy()
        if reinvocationPolicy is not None:  # omit empty
            v["reinvocationPolicy"] = reinvocationPolicy
        return v

    # The name of the admission webhook.
    # Name should be fully qualified, e.g., imagepolicy.kubernetes.io, where
    # "imagepolicy" is the name of the webhook, and kubernetes.io is the name
    # of the organization.
    # Required.
    @typechecked
    def name(self) -> str:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return ""

    # ClientConfig defines how to communicate with the hook.
    # Required
    @typechecked
    def clientConfig(self) -> WebhookClientConfig:
        if "clientConfig" in self._kwargs:
            return self._kwargs["clientConfig"]
        if "clientConfig" in self._context and check_return_type(
            self._context["clientConfig"]
        ):
            return self._context["clientConfig"]
        with context.Scope(**self._context):
            return WebhookClientConfig()

    # Rules describes what operations on what resources/subresources the webhook cares about.
    # The webhook cares about an operation if it matches _any_ Rule.
    # However, in order to prevent ValidatingAdmissionWebhooks and MutatingAdmissionWebhooks
    # from putting the cluster in a state which cannot be recovered from without completely
    # disabling the plugin, ValidatingAdmissionWebhooks and MutatingAdmissionWebhooks are never called
    # on admission requests for ValidatingWebhookConfiguration and MutatingWebhookConfiguration objects.
    @typechecked
    def rules(self) -> List[RuleWithOperations]:
        if "rules" in self._kwargs:
            return self._kwargs["rules"]
        if "rules" in self._context and check_return_type(self._context["rules"]):
            return self._context["rules"]
        return []

    # FailurePolicy defines how unrecognized errors from the admission endpoint are handled -
    # allowed values are Ignore or Fail. Defaults to Fail.
    @typechecked
    def failurePolicy(self) -> Optional[FailurePolicyType]:
        if "failurePolicy" in self._kwargs:
            return self._kwargs["failurePolicy"]
        if "failurePolicy" in self._context and check_return_type(
            self._context["failurePolicy"]
        ):
            return self._context["failurePolicy"]
        return FailurePolicyType["Fail"]

    # matchPolicy defines how the "rules" list is used to match incoming requests.
    # Allowed values are "Exact" or "Equivalent".
    #
    # - Exact: match a request only if it exactly matches a specified rule.
    # For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
    # but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
    # a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.
    #
    # - Equivalent: match a request if modifies a resource listed in rules, even via another API group or version.
    # For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
    # and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
    # a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.
    #
    # Defaults to "Equivalent"
    @typechecked
    def matchPolicy(self) -> Optional[MatchPolicyType]:
        if "matchPolicy" in self._kwargs:
            return self._kwargs["matchPolicy"]
        if "matchPolicy" in self._context and check_return_type(
            self._context["matchPolicy"]
        ):
            return self._context["matchPolicy"]
        return MatchPolicyType["Equivalent"]

    # NamespaceSelector decides whether to run the webhook on an object based
    # on whether the namespace for that object matches the selector. If the
    # object itself is a namespace, the matching is performed on
    # object.metadata.labels. If the object is another cluster scoped resource,
    # it never skips the webhook.
    #
    # For example, to run the webhook on any objects whose namespace is not
    # associated with "runlevel" of "0" or "1";  you will set the selector as
    # follows:
    # "namespaceSelector": {
    #   "matchExpressions": [
    #     {
    #       "key": "runlevel",
    #       "operator": "NotIn",
    #       "values": [
    #         "0",
    #         "1"
    #       ]
    #     }
    #   ]
    # }
    #
    # If instead you want to only run the webhook on any objects whose
    # namespace is associated with the "environment" of "prod" or "staging";
    # you will set the selector as follows:
    # "namespaceSelector": {
    #   "matchExpressions": [
    #     {
    #       "key": "environment",
    #       "operator": "In",
    #       "values": [
    #         "prod",
    #         "staging"
    #       ]
    #     }
    #   ]
    # }
    #
    # See
    # https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
    # for more examples of label selectors.
    #
    # Default to the empty LabelSelector, which matches everything.
    @typechecked
    def namespaceSelector(self) -> Optional["metav1.LabelSelector"]:
        if "namespaceSelector" in self._kwargs:
            return self._kwargs["namespaceSelector"]
        if "namespaceSelector" in self._context and check_return_type(
            self._context["namespaceSelector"]
        ):
            return self._context["namespaceSelector"]
        return None

    # ObjectSelector decides whether to run the webhook based on if the
    # object has matching labels. objectSelector is evaluated against both
    # the oldObject and newObject that would be sent to the webhook, and
    # is considered to match if either object matches the selector. A null
    # object (oldObject in the case of create, or newObject in the case of
    # delete) or an object that cannot have labels (like a
    # DeploymentRollback or a PodProxyOptions object) is not considered to
    # match.
    # Use the object selector only if the webhook is opt-in, because end
    # users may skip the admission webhook by setting the labels.
    # Default to the empty LabelSelector, which matches everything.
    @typechecked
    def objectSelector(self) -> Optional["metav1.LabelSelector"]:
        if "objectSelector" in self._kwargs:
            return self._kwargs["objectSelector"]
        if "objectSelector" in self._context and check_return_type(
            self._context["objectSelector"]
        ):
            return self._context["objectSelector"]
        return None

    # SideEffects states whether this webhook has side effects.
    # Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).
    # Webhooks with side effects MUST implement a reconciliation system, since a request may be
    # rejected by a future step in the admission change and the side effects therefore need to be undone.
    # Requests with the dryRun attribute will be auto-rejected if they match a webhook with
    # sideEffects == Unknown or Some.
    @typechecked
    def sideEffects(self) -> Optional[SideEffectClass]:
        if "sideEffects" in self._kwargs:
            return self._kwargs["sideEffects"]
        if "sideEffects" in self._context and check_return_type(
            self._context["sideEffects"]
        ):
            return self._context["sideEffects"]
        return None

    # TimeoutSeconds specifies the timeout for this webhook. After the timeout passes,
    # the webhook call will be ignored or the API call will fail based on the
    # failure policy.
    # The timeout value must be between 1 and 30 seconds.
    # Default to 10 seconds.
    @typechecked
    def timeoutSeconds(self) -> Optional[int]:
        if "timeoutSeconds" in self._kwargs:
            return self._kwargs["timeoutSeconds"]
        if "timeoutSeconds" in self._context and check_return_type(
            self._context["timeoutSeconds"]
        ):
            return self._context["timeoutSeconds"]
        return 10

    # AdmissionReviewVersions is an ordered list of preferred `AdmissionReview`
    # versions the Webhook expects. API server will try to use first version in
    # the list which it supports. If none of the versions specified in this list
    # supported by API server, validation will fail for this object.
    # If a persisted webhook configuration specifies allowed versions and does not
    # include any versions known to the API Server, calls to the webhook will fail
    # and be subject to the failure policy.
    @typechecked
    def admissionReviewVersions(self) -> List[str]:
        if "admissionReviewVersions" in self._kwargs:
            return self._kwargs["admissionReviewVersions"]
        if "admissionReviewVersions" in self._context and check_return_type(
            self._context["admissionReviewVersions"]
        ):
            return self._context["admissionReviewVersions"]
        return []

    # reinvocationPolicy indicates whether this webhook should be called multiple times as part of a single admission evaluation.
    # Allowed values are "Never" and "IfNeeded".
    #
    # Never: the webhook will not be called more than once in a single admission evaluation.
    #
    # IfNeeded: the webhook will be called at least one additional time as part of the admission evaluation
    # if the object being admitted is modified by other admission plugins after the initial webhook call.
    # Webhooks that specify this option *must* be idempotent, able to process objects they previously admitted.
    # Note:
    # * the number of additional invocations is not guaranteed to be exactly one.
    # * if additional invocations result in further modifications to the object, webhooks are not guaranteed to be invoked again.
    # * webhooks that use this option may be reordered to minimize the number of additional invocations.
    # * to validate an object after all mutations are guaranteed complete, use a validating admission webhook instead.
    #
    # Defaults to "Never".
    @typechecked
    def reinvocationPolicy(self) -> Optional[ReinvocationPolicyType]:
        if "reinvocationPolicy" in self._kwargs:
            return self._kwargs["reinvocationPolicy"]
        if "reinvocationPolicy" in self._context and check_return_type(
            self._context["reinvocationPolicy"]
        ):
            return self._context["reinvocationPolicy"]
        return ReinvocationPolicyType["Never"]


# MutatingWebhookConfiguration describes the configuration of and admission webhook that accept or reject and may change the object.
class MutatingWebhookConfiguration(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        webhooks = self.webhooks()
        if webhooks:  # omit empty
            v["webhooks"] = webhooks.values()  # named list
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "admissionregistration.k8s.io/v1"

    @typechecked
    def kind(self) -> str:
        return "MutatingWebhookConfiguration"

    # Webhooks is a list of webhooks and the affected resources and operations.
    @typechecked
    def webhooks(self) -> Dict[str, MutatingWebhook]:
        if "webhooks" in self._kwargs:
            return self._kwargs["webhooks"]
        if "webhooks" in self._context and check_return_type(self._context["webhooks"]):
            return self._context["webhooks"]
        return {}


# ValidatingWebhook describes an admission webhook and the resources and operations it applies to.
class ValidatingWebhook(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["name"] = self.name()
        v["clientConfig"] = self.clientConfig()
        rules = self.rules()
        if rules:  # omit empty
            v["rules"] = rules
        failurePolicy = self.failurePolicy()
        if failurePolicy is not None:  # omit empty
            v["failurePolicy"] = failurePolicy
        matchPolicy = self.matchPolicy()
        if matchPolicy is not None:  # omit empty
            v["matchPolicy"] = matchPolicy
        namespaceSelector = self.namespaceSelector()
        if namespaceSelector is not None:  # omit empty
            v["namespaceSelector"] = namespaceSelector
        objectSelector = self.objectSelector()
        if objectSelector is not None:  # omit empty
            v["objectSelector"] = objectSelector
        v["sideEffects"] = self.sideEffects()
        timeoutSeconds = self.timeoutSeconds()
        if timeoutSeconds is not None:  # omit empty
            v["timeoutSeconds"] = timeoutSeconds
        v["admissionReviewVersions"] = self.admissionReviewVersions()
        return v

    # The name of the admission webhook.
    # Name should be fully qualified, e.g., imagepolicy.kubernetes.io, where
    # "imagepolicy" is the name of the webhook, and kubernetes.io is the name
    # of the organization.
    # Required.
    @typechecked
    def name(self) -> str:
        if "name" in self._kwargs:
            return self._kwargs["name"]
        if "name" in self._context and check_return_type(self._context["name"]):
            return self._context["name"]
        return ""

    # ClientConfig defines how to communicate with the hook.
    # Required
    @typechecked
    def clientConfig(self) -> WebhookClientConfig:
        if "clientConfig" in self._kwargs:
            return self._kwargs["clientConfig"]
        if "clientConfig" in self._context and check_return_type(
            self._context["clientConfig"]
        ):
            return self._context["clientConfig"]
        with context.Scope(**self._context):
            return WebhookClientConfig()

    # Rules describes what operations on what resources/subresources the webhook cares about.
    # The webhook cares about an operation if it matches _any_ Rule.
    # However, in order to prevent ValidatingAdmissionWebhooks and MutatingAdmissionWebhooks
    # from putting the cluster in a state which cannot be recovered from without completely
    # disabling the plugin, ValidatingAdmissionWebhooks and MutatingAdmissionWebhooks are never called
    # on admission requests for ValidatingWebhookConfiguration and MutatingWebhookConfiguration objects.
    @typechecked
    def rules(self) -> List[RuleWithOperations]:
        if "rules" in self._kwargs:
            return self._kwargs["rules"]
        if "rules" in self._context and check_return_type(self._context["rules"]):
            return self._context["rules"]
        return []

    # FailurePolicy defines how unrecognized errors from the admission endpoint are handled -
    # allowed values are Ignore or Fail. Defaults to Fail.
    @typechecked
    def failurePolicy(self) -> Optional[FailurePolicyType]:
        if "failurePolicy" in self._kwargs:
            return self._kwargs["failurePolicy"]
        if "failurePolicy" in self._context and check_return_type(
            self._context["failurePolicy"]
        ):
            return self._context["failurePolicy"]
        return FailurePolicyType["Fail"]

    # matchPolicy defines how the "rules" list is used to match incoming requests.
    # Allowed values are "Exact" or "Equivalent".
    #
    # - Exact: match a request only if it exactly matches a specified rule.
    # For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
    # but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
    # a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.
    #
    # - Equivalent: match a request if modifies a resource listed in rules, even via another API group or version.
    # For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
    # and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
    # a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.
    #
    # Defaults to "Equivalent"
    @typechecked
    def matchPolicy(self) -> Optional[MatchPolicyType]:
        if "matchPolicy" in self._kwargs:
            return self._kwargs["matchPolicy"]
        if "matchPolicy" in self._context and check_return_type(
            self._context["matchPolicy"]
        ):
            return self._context["matchPolicy"]
        return MatchPolicyType["Equivalent"]

    # NamespaceSelector decides whether to run the webhook on an object based
    # on whether the namespace for that object matches the selector. If the
    # object itself is a namespace, the matching is performed on
    # object.metadata.labels. If the object is another cluster scoped resource,
    # it never skips the webhook.
    #
    # For example, to run the webhook on any objects whose namespace is not
    # associated with "runlevel" of "0" or "1";  you will set the selector as
    # follows:
    # "namespaceSelector": {
    #   "matchExpressions": [
    #     {
    #       "key": "runlevel",
    #       "operator": "NotIn",
    #       "values": [
    #         "0",
    #         "1"
    #       ]
    #     }
    #   ]
    # }
    #
    # If instead you want to only run the webhook on any objects whose
    # namespace is associated with the "environment" of "prod" or "staging";
    # you will set the selector as follows:
    # "namespaceSelector": {
    #   "matchExpressions": [
    #     {
    #       "key": "environment",
    #       "operator": "In",
    #       "values": [
    #         "prod",
    #         "staging"
    #       ]
    #     }
    #   ]
    # }
    #
    # See
    # https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
    # for more examples of label selectors.
    #
    # Default to the empty LabelSelector, which matches everything.
    @typechecked
    def namespaceSelector(self) -> Optional["metav1.LabelSelector"]:
        if "namespaceSelector" in self._kwargs:
            return self._kwargs["namespaceSelector"]
        if "namespaceSelector" in self._context and check_return_type(
            self._context["namespaceSelector"]
        ):
            return self._context["namespaceSelector"]
        return None

    # ObjectSelector decides whether to run the webhook based on if the
    # object has matching labels. objectSelector is evaluated against both
    # the oldObject and newObject that would be sent to the webhook, and
    # is considered to match if either object matches the selector. A null
    # object (oldObject in the case of create, or newObject in the case of
    # delete) or an object that cannot have labels (like a
    # DeploymentRollback or a PodProxyOptions object) is not considered to
    # match.
    # Use the object selector only if the webhook is opt-in, because end
    # users may skip the admission webhook by setting the labels.
    # Default to the empty LabelSelector, which matches everything.
    @typechecked
    def objectSelector(self) -> Optional["metav1.LabelSelector"]:
        if "objectSelector" in self._kwargs:
            return self._kwargs["objectSelector"]
        if "objectSelector" in self._context and check_return_type(
            self._context["objectSelector"]
        ):
            return self._context["objectSelector"]
        return None

    # SideEffects states whether this webhook has side effects.
    # Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).
    # Webhooks with side effects MUST implement a reconciliation system, since a request may be
    # rejected by a future step in the admission change and the side effects therefore need to be undone.
    # Requests with the dryRun attribute will be auto-rejected if they match a webhook with
    # sideEffects == Unknown or Some.
    @typechecked
    def sideEffects(self) -> Optional[SideEffectClass]:
        if "sideEffects" in self._kwargs:
            return self._kwargs["sideEffects"]
        if "sideEffects" in self._context and check_return_type(
            self._context["sideEffects"]
        ):
            return self._context["sideEffects"]
        return None

    # TimeoutSeconds specifies the timeout for this webhook. After the timeout passes,
    # the webhook call will be ignored or the API call will fail based on the
    # failure policy.
    # The timeout value must be between 1 and 30 seconds.
    # Default to 10 seconds.
    @typechecked
    def timeoutSeconds(self) -> Optional[int]:
        if "timeoutSeconds" in self._kwargs:
            return self._kwargs["timeoutSeconds"]
        if "timeoutSeconds" in self._context and check_return_type(
            self._context["timeoutSeconds"]
        ):
            return self._context["timeoutSeconds"]
        return 10

    # AdmissionReviewVersions is an ordered list of preferred `AdmissionReview`
    # versions the Webhook expects. API server will try to use first version in
    # the list which it supports. If none of the versions specified in this list
    # supported by API server, validation will fail for this object.
    # If a persisted webhook configuration specifies allowed versions and does not
    # include any versions known to the API Server, calls to the webhook will fail
    # and be subject to the failure policy.
    @typechecked
    def admissionReviewVersions(self) -> List[str]:
        if "admissionReviewVersions" in self._kwargs:
            return self._kwargs["admissionReviewVersions"]
        if "admissionReviewVersions" in self._context and check_return_type(
            self._context["admissionReviewVersions"]
        ):
            return self._context["admissionReviewVersions"]
        return []


# ValidatingWebhookConfiguration describes the configuration of and admission webhook that accept or reject and object without changing it.
class ValidatingWebhookConfiguration(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        webhooks = self.webhooks()
        if webhooks:  # omit empty
            v["webhooks"] = webhooks.values()  # named list
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "admissionregistration.k8s.io/v1"

    @typechecked
    def kind(self) -> str:
        return "ValidatingWebhookConfiguration"

    # Webhooks is a list of webhooks and the affected resources and operations.
    @typechecked
    def webhooks(self) -> Dict[str, ValidatingWebhook]:
        if "webhooks" in self._kwargs:
            return self._kwargs["webhooks"]
        if "webhooks" in self._context and check_return_type(self._context["webhooks"]):
            return self._context["webhooks"]
        return {}
