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
        # The constants should be kept in sync with those defined in k8s.io/kubernetes/pkg/admission/interface.go.
        "All": "*",
        # The constants should be kept in sync with those defined in k8s.io/kubernetes/pkg/admission/interface.go.
        "Connect": "CONNECT",
        # The constants should be kept in sync with those defined in k8s.io/kubernetes/pkg/admission/interface.go.
        "Create": "CREATE",
        # The constants should be kept in sync with those defined in k8s.io/kubernetes/pkg/admission/interface.go.
        "Delete": "DELETE",
        # The constants should be kept in sync with those defined in k8s.io/kubernetes/pkg/admission/interface.go.
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


class Rule(types.Object):
    """
    Rule is a tuple of APIGroups, APIVersion, and Resources.It is recommended
    to make sure that all the tuple expansions are valid.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        api_groups: List[str] = None,
        api_versions: List[str] = None,
        resources: List[str] = None,
        scope: ScopeType = None,
    ):
        super().__init__()
        self.__api_groups = api_groups if api_groups is not None else []
        self.__api_versions = api_versions if api_versions is not None else []
        self.__resources = resources if resources is not None else []
        self.__scope = scope if scope is not None else ScopeType["All"]

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        api_groups = self.api_groups()
        check_type("api_groups", api_groups, Optional[List[str]])
        if api_groups:  # omit empty
            v["apiGroups"] = api_groups
        api_versions = self.api_versions()
        check_type("api_versions", api_versions, Optional[List[str]])
        if api_versions:  # omit empty
            v["apiVersions"] = api_versions
        resources = self.resources()
        check_type("resources", resources, Optional[List[str]])
        if resources:  # omit empty
            v["resources"] = resources
        scope = self.scope()
        check_type("scope", scope, Optional[ScopeType])
        if scope is not None:  # omit empty
            v["scope"] = scope
        return v

    def api_groups(self) -> Optional[List[str]]:
        """
        APIGroups is the API groups the resources belong to. '*' is all groups.
        If '*' is present, the length of the slice must be one.
        Required.
        """
        return self.__api_groups

    def api_versions(self) -> Optional[List[str]]:
        """
        APIVersions is the API versions the resources belong to. '*' is all versions.
        If '*' is present, the length of the slice must be one.
        Required.
        """
        return self.__api_versions

    def resources(self) -> Optional[List[str]]:
        """
        Resources is a list of resources this rule applies to.
        
        For example:
        'pods' means pods.
        'pods/log' means the log subresource of pods.
        '*' means all resources, but not subresources.
        'pods/*' means all subresources of pods.
        '*/scale' means all scale subresources.
        '*/*' means all resources and their subresources.
        
        If wildcard is present, the validation rule will ensure resources do not
        overlap with each other.
        
        Depending on the enclosing object, subresources might not be allowed.
        Required.
        """
        return self.__resources

    def scope(self) -> Optional[ScopeType]:
        """
        scope specifies the scope of this rule.
        Valid values are "Cluster", "Namespaced", and "*"
        "Cluster" means that only cluster-scoped resources will match this rule.
        Namespace API objects are cluster-scoped.
        "Namespaced" means that only namespaced resources will match this rule.
        "*" means that there are no scope restrictions.
        Subresources match the scope of their parent resource.
        Default is "*".
        """
        return self.__scope


class RuleWithOperations(types.Object):
    """
    RuleWithOperations is a tuple of Operations and Resources. It is recommended to make
    sure that all the tuple expansions are valid.
    """

    @context.scoped
    @typechecked
    def __init__(self, operations: List[OperationType] = None, rule: "Rule" = None):
        super().__init__()
        self.__operations = operations if operations is not None else []
        self.__rule = rule if rule is not None else Rule()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        operations = self.operations()
        check_type("operations", operations, Optional[List[OperationType]])
        if operations:  # omit empty
            v["operations"] = operations
        rule = self.rule()
        check_type("rule", rule, "Rule")
        v.update(rule._root())  # inline
        return v

    def operations(self) -> Optional[List[OperationType]]:
        """
        Operations is the operations the admission hook cares about - CREATE, UPDATE, or *
        for all operations.
        If '*' is present, the length of the slice must be one.
        Required.
        """
        return self.__operations

    def rule(self) -> "Rule":
        """
        Rule is embedded, it describes other criteria of the rule, like
        APIGroups, APIVersions, Resources, etc.
        """
        return self.__rule


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
        `namespace` is the namespace of the service.
        Required
        """
        return self.__namespace

    def name(self) -> str:
        """
        `name` is the name of the service.
        Required
        """
        return self.__name

    def path(self) -> Optional[str]:
        """
        `path` is an optional URL path which will be sent in any request to
        this service.
        """
        return self.__path

    def port(self) -> Optional[int]:
        """
        If specified, the port on the service that hosting webhook.
        Default to 443 for backward compatibility.
        `port` should be a valid port number (1-65535, inclusive).
        """
        return self.__port


class WebhookClientConfig(types.Object):
    """
    WebhookClientConfig contains the information to make a TLS
    connection with the webhook
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
        `url` gives the location of the webhook, in standard URL form
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
        `service` is a reference to the service for this webhook. Either
        `service` or `url` must be specified.
        
        If the webhook is running within the cluster, then you should use `service`.
        """
        return self.__service

    def ca_bundle(self) -> Optional[bytes]:
        """
        `caBundle` is a PEM encoded CA bundle which will be used to validate the webhook's server certificate.
        If unspecified, system trust roots on the apiserver are used.
        """
        return self.__ca_bundle


class MutatingWebhook(types.Object):
    """
    MutatingWebhook describes an admission webhook and the resources and operations it applies to.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        client_config: "WebhookClientConfig" = None,
        rules: List["RuleWithOperations"] = None,
        failure_policy: FailurePolicyType = None,
        match_policy: MatchPolicyType = None,
        namespace_selector: "metav1.LabelSelector" = None,
        object_selector: "metav1.LabelSelector" = None,
        side_effects: SideEffectClass = None,
        timeout_seconds: int = None,
        admission_review_versions: List[str] = None,
        reinvocation_policy: ReinvocationPolicyType = None,
    ):
        super().__init__()
        self.__name = name
        self.__client_config = (
            client_config if client_config is not None else WebhookClientConfig()
        )
        self.__rules = rules if rules is not None else []
        self.__failure_policy = (
            failure_policy if failure_policy is not None else FailurePolicyType["Fail"]
        )
        self.__match_policy = (
            match_policy if match_policy is not None else MatchPolicyType["Equivalent"]
        )
        self.__namespace_selector = namespace_selector
        self.__object_selector = object_selector
        self.__side_effects = side_effects
        self.__timeout_seconds = timeout_seconds if timeout_seconds is not None else 10
        self.__admission_review_versions = (
            admission_review_versions if admission_review_versions is not None else []
        )
        self.__reinvocation_policy = (
            reinvocation_policy
            if reinvocation_policy is not None
            else ReinvocationPolicyType["Never"]
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        client_config = self.client_config()
        check_type("client_config", client_config, "WebhookClientConfig")
        v["clientConfig"] = client_config
        rules = self.rules()
        check_type("rules", rules, Optional[List["RuleWithOperations"]])
        if rules:  # omit empty
            v["rules"] = rules
        failure_policy = self.failure_policy()
        check_type("failure_policy", failure_policy, Optional[FailurePolicyType])
        if failure_policy is not None:  # omit empty
            v["failurePolicy"] = failure_policy
        match_policy = self.match_policy()
        check_type("match_policy", match_policy, Optional[MatchPolicyType])
        if match_policy is not None:  # omit empty
            v["matchPolicy"] = match_policy
        namespace_selector = self.namespace_selector()
        check_type(
            "namespace_selector", namespace_selector, Optional["metav1.LabelSelector"]
        )
        if namespace_selector is not None:  # omit empty
            v["namespaceSelector"] = namespace_selector
        object_selector = self.object_selector()
        check_type("object_selector", object_selector, Optional["metav1.LabelSelector"])
        if object_selector is not None:  # omit empty
            v["objectSelector"] = object_selector
        side_effects = self.side_effects()
        check_type("side_effects", side_effects, Optional[SideEffectClass])
        v["sideEffects"] = side_effects
        timeout_seconds = self.timeout_seconds()
        check_type("timeout_seconds", timeout_seconds, Optional[int])
        if timeout_seconds is not None:  # omit empty
            v["timeoutSeconds"] = timeout_seconds
        admission_review_versions = self.admission_review_versions()
        check_type("admission_review_versions", admission_review_versions, List[str])
        v["admissionReviewVersions"] = admission_review_versions
        reinvocation_policy = self.reinvocation_policy()
        check_type(
            "reinvocation_policy", reinvocation_policy, Optional[ReinvocationPolicyType]
        )
        if reinvocation_policy is not None:  # omit empty
            v["reinvocationPolicy"] = reinvocation_policy
        return v

    def name(self) -> str:
        """
        The name of the admission webhook.
        Name should be fully qualified, e.g., imagepolicy.kubernetes.io, where
        "imagepolicy" is the name of the webhook, and kubernetes.io is the name
        of the organization.
        Required.
        """
        return self.__name

    def client_config(self) -> "WebhookClientConfig":
        """
        ClientConfig defines how to communicate with the hook.
        Required
        """
        return self.__client_config

    def rules(self) -> Optional[List["RuleWithOperations"]]:
        """
        Rules describes what operations on what resources/subresources the webhook cares about.
        The webhook cares about an operation if it matches _any_ Rule.
        However, in order to prevent ValidatingAdmissionWebhooks and MutatingAdmissionWebhooks
        from putting the cluster in a state which cannot be recovered from without completely
        disabling the plugin, ValidatingAdmissionWebhooks and MutatingAdmissionWebhooks are never called
        on admission requests for ValidatingWebhookConfiguration and MutatingWebhookConfiguration objects.
        """
        return self.__rules

    def failure_policy(self) -> Optional[FailurePolicyType]:
        """
        FailurePolicy defines how unrecognized errors from the admission endpoint are handled -
        allowed values are Ignore or Fail. Defaults to Fail.
        """
        return self.__failure_policy

    def match_policy(self) -> Optional[MatchPolicyType]:
        """
        matchPolicy defines how the "rules" list is used to match incoming requests.
        Allowed values are "Exact" or "Equivalent".
        
        - Exact: match a request only if it exactly matches a specified rule.
        For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
        but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
        a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.
        
        - Equivalent: match a request if modifies a resource listed in rules, even via another API group or version.
        For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
        and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
        a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.
        
        Defaults to "Equivalent"
        """
        return self.__match_policy

    def namespace_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        NamespaceSelector decides whether to run the webhook on an object based
        on whether the namespace for that object matches the selector. If the
        object itself is a namespace, the matching is performed on
        object.metadata.labels. If the object is another cluster scoped resource,
        it never skips the webhook.
        
        For example, to run the webhook on any objects whose namespace is not
        associated with "runlevel" of "0" or "1";  you will set the selector as
        follows:
        "namespaceSelector": {
          "matchExpressions": [
            {
              "key": "runlevel",
              "operator": "NotIn",
              "values": [
                "0",
                "1"
              ]
            }
          ]
        }
        
        If instead you want to only run the webhook on any objects whose
        namespace is associated with the "environment" of "prod" or "staging";
        you will set the selector as follows:
        "namespaceSelector": {
          "matchExpressions": [
            {
              "key": "environment",
              "operator": "In",
              "values": [
                "prod",
                "staging"
              ]
            }
          ]
        }
        
        See
        https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
        for more examples of label selectors.
        
        Default to the empty LabelSelector, which matches everything.
        """
        return self.__namespace_selector

    def object_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        ObjectSelector decides whether to run the webhook based on if the
        object has matching labels. objectSelector is evaluated against both
        the oldObject and newObject that would be sent to the webhook, and
        is considered to match if either object matches the selector. A null
        object (oldObject in the case of create, or newObject in the case of
        delete) or an object that cannot have labels (like a
        DeploymentRollback or a PodProxyOptions object) is not considered to
        match.
        Use the object selector only if the webhook is opt-in, because end
        users may skip the admission webhook by setting the labels.
        Default to the empty LabelSelector, which matches everything.
        """
        return self.__object_selector

    def side_effects(self) -> Optional[SideEffectClass]:
        """
        SideEffects states whether this webhook has side effects.
        Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).
        Webhooks with side effects MUST implement a reconciliation system, since a request may be
        rejected by a future step in the admission change and the side effects therefore need to be undone.
        Requests with the dryRun attribute will be auto-rejected if they match a webhook with
        sideEffects == Unknown or Some.
        """
        return self.__side_effects

    def timeout_seconds(self) -> Optional[int]:
        """
        TimeoutSeconds specifies the timeout for this webhook. After the timeout passes,
        the webhook call will be ignored or the API call will fail based on the
        failure policy.
        The timeout value must be between 1 and 30 seconds.
        Default to 10 seconds.
        """
        return self.__timeout_seconds

    def admission_review_versions(self) -> List[str]:
        """
        AdmissionReviewVersions is an ordered list of preferred `AdmissionReview`
        versions the Webhook expects. API server will try to use first version in
        the list which it supports. If none of the versions specified in this list
        supported by API server, validation will fail for this object.
        If a persisted webhook configuration specifies allowed versions and does not
        include any versions known to the API Server, calls to the webhook will fail
        and be subject to the failure policy.
        """
        return self.__admission_review_versions

    def reinvocation_policy(self) -> Optional[ReinvocationPolicyType]:
        """
        reinvocationPolicy indicates whether this webhook should be called multiple times as part of a single admission evaluation.
        Allowed values are "Never" and "IfNeeded".
        
        Never: the webhook will not be called more than once in a single admission evaluation.
        
        IfNeeded: the webhook will be called at least one additional time as part of the admission evaluation
        if the object being admitted is modified by other admission plugins after the initial webhook call.
        Webhooks that specify this option *must* be idempotent, able to process objects they previously admitted.
        Note:
        * the number of additional invocations is not guaranteed to be exactly one.
        * if additional invocations result in further modifications to the object, webhooks are not guaranteed to be invoked again.
        * webhooks that use this option may be reordered to minimize the number of additional invocations.
        * to validate an object after all mutations are guaranteed complete, use a validating admission webhook instead.
        
        Defaults to "Never".
        """
        return self.__reinvocation_policy


class MutatingWebhookConfiguration(base.TypedObject, base.MetadataObject):
    """
    MutatingWebhookConfiguration describes the configuration of and admission webhook that accept or reject and may change the object.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        webhooks: List["MutatingWebhook"] = None,
    ):
        super().__init__(
            api_version="admissionregistration.k8s.io/v1",
            kind="MutatingWebhookConfiguration",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__webhooks = webhooks if webhooks is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        webhooks = self.webhooks()
        check_type("webhooks", webhooks, Optional[List["MutatingWebhook"]])
        if webhooks:  # omit empty
            v["webhooks"] = webhooks
        return v

    def webhooks(self) -> Optional[List["MutatingWebhook"]]:
        """
        Webhooks is a list of webhooks and the affected resources and operations.
        """
        return self.__webhooks


class ValidatingWebhook(types.Object):
    """
    ValidatingWebhook describes an admission webhook and the resources and operations it applies to.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = "",
        client_config: "WebhookClientConfig" = None,
        rules: List["RuleWithOperations"] = None,
        failure_policy: FailurePolicyType = None,
        match_policy: MatchPolicyType = None,
        namespace_selector: "metav1.LabelSelector" = None,
        object_selector: "metav1.LabelSelector" = None,
        side_effects: SideEffectClass = None,
        timeout_seconds: int = None,
        admission_review_versions: List[str] = None,
    ):
        super().__init__()
        self.__name = name
        self.__client_config = (
            client_config if client_config is not None else WebhookClientConfig()
        )
        self.__rules = rules if rules is not None else []
        self.__failure_policy = (
            failure_policy if failure_policy is not None else FailurePolicyType["Fail"]
        )
        self.__match_policy = (
            match_policy if match_policy is not None else MatchPolicyType["Equivalent"]
        )
        self.__namespace_selector = namespace_selector
        self.__object_selector = object_selector
        self.__side_effects = side_effects
        self.__timeout_seconds = timeout_seconds if timeout_seconds is not None else 10
        self.__admission_review_versions = (
            admission_review_versions if admission_review_versions is not None else []
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        name = self.name()
        check_type("name", name, str)
        v["name"] = name
        client_config = self.client_config()
        check_type("client_config", client_config, "WebhookClientConfig")
        v["clientConfig"] = client_config
        rules = self.rules()
        check_type("rules", rules, Optional[List["RuleWithOperations"]])
        if rules:  # omit empty
            v["rules"] = rules
        failure_policy = self.failure_policy()
        check_type("failure_policy", failure_policy, Optional[FailurePolicyType])
        if failure_policy is not None:  # omit empty
            v["failurePolicy"] = failure_policy
        match_policy = self.match_policy()
        check_type("match_policy", match_policy, Optional[MatchPolicyType])
        if match_policy is not None:  # omit empty
            v["matchPolicy"] = match_policy
        namespace_selector = self.namespace_selector()
        check_type(
            "namespace_selector", namespace_selector, Optional["metav1.LabelSelector"]
        )
        if namespace_selector is not None:  # omit empty
            v["namespaceSelector"] = namespace_selector
        object_selector = self.object_selector()
        check_type("object_selector", object_selector, Optional["metav1.LabelSelector"])
        if object_selector is not None:  # omit empty
            v["objectSelector"] = object_selector
        side_effects = self.side_effects()
        check_type("side_effects", side_effects, Optional[SideEffectClass])
        v["sideEffects"] = side_effects
        timeout_seconds = self.timeout_seconds()
        check_type("timeout_seconds", timeout_seconds, Optional[int])
        if timeout_seconds is not None:  # omit empty
            v["timeoutSeconds"] = timeout_seconds
        admission_review_versions = self.admission_review_versions()
        check_type("admission_review_versions", admission_review_versions, List[str])
        v["admissionReviewVersions"] = admission_review_versions
        return v

    def name(self) -> str:
        """
        The name of the admission webhook.
        Name should be fully qualified, e.g., imagepolicy.kubernetes.io, where
        "imagepolicy" is the name of the webhook, and kubernetes.io is the name
        of the organization.
        Required.
        """
        return self.__name

    def client_config(self) -> "WebhookClientConfig":
        """
        ClientConfig defines how to communicate with the hook.
        Required
        """
        return self.__client_config

    def rules(self) -> Optional[List["RuleWithOperations"]]:
        """
        Rules describes what operations on what resources/subresources the webhook cares about.
        The webhook cares about an operation if it matches _any_ Rule.
        However, in order to prevent ValidatingAdmissionWebhooks and MutatingAdmissionWebhooks
        from putting the cluster in a state which cannot be recovered from without completely
        disabling the plugin, ValidatingAdmissionWebhooks and MutatingAdmissionWebhooks are never called
        on admission requests for ValidatingWebhookConfiguration and MutatingWebhookConfiguration objects.
        """
        return self.__rules

    def failure_policy(self) -> Optional[FailurePolicyType]:
        """
        FailurePolicy defines how unrecognized errors from the admission endpoint are handled -
        allowed values are Ignore or Fail. Defaults to Fail.
        """
        return self.__failure_policy

    def match_policy(self) -> Optional[MatchPolicyType]:
        """
        matchPolicy defines how the "rules" list is used to match incoming requests.
        Allowed values are "Exact" or "Equivalent".
        
        - Exact: match a request only if it exactly matches a specified rule.
        For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
        but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
        a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.
        
        - Equivalent: match a request if modifies a resource listed in rules, even via another API group or version.
        For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
        and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
        a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.
        
        Defaults to "Equivalent"
        """
        return self.__match_policy

    def namespace_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        NamespaceSelector decides whether to run the webhook on an object based
        on whether the namespace for that object matches the selector. If the
        object itself is a namespace, the matching is performed on
        object.metadata.labels. If the object is another cluster scoped resource,
        it never skips the webhook.
        
        For example, to run the webhook on any objects whose namespace is not
        associated with "runlevel" of "0" or "1";  you will set the selector as
        follows:
        "namespaceSelector": {
          "matchExpressions": [
            {
              "key": "runlevel",
              "operator": "NotIn",
              "values": [
                "0",
                "1"
              ]
            }
          ]
        }
        
        If instead you want to only run the webhook on any objects whose
        namespace is associated with the "environment" of "prod" or "staging";
        you will set the selector as follows:
        "namespaceSelector": {
          "matchExpressions": [
            {
              "key": "environment",
              "operator": "In",
              "values": [
                "prod",
                "staging"
              ]
            }
          ]
        }
        
        See
        https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
        for more examples of label selectors.
        
        Default to the empty LabelSelector, which matches everything.
        """
        return self.__namespace_selector

    def object_selector(self) -> Optional["metav1.LabelSelector"]:
        """
        ObjectSelector decides whether to run the webhook based on if the
        object has matching labels. objectSelector is evaluated against both
        the oldObject and newObject that would be sent to the webhook, and
        is considered to match if either object matches the selector. A null
        object (oldObject in the case of create, or newObject in the case of
        delete) or an object that cannot have labels (like a
        DeploymentRollback or a PodProxyOptions object) is not considered to
        match.
        Use the object selector only if the webhook is opt-in, because end
        users may skip the admission webhook by setting the labels.
        Default to the empty LabelSelector, which matches everything.
        """
        return self.__object_selector

    def side_effects(self) -> Optional[SideEffectClass]:
        """
        SideEffects states whether this webhook has side effects.
        Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).
        Webhooks with side effects MUST implement a reconciliation system, since a request may be
        rejected by a future step in the admission change and the side effects therefore need to be undone.
        Requests with the dryRun attribute will be auto-rejected if they match a webhook with
        sideEffects == Unknown or Some.
        """
        return self.__side_effects

    def timeout_seconds(self) -> Optional[int]:
        """
        TimeoutSeconds specifies the timeout for this webhook. After the timeout passes,
        the webhook call will be ignored or the API call will fail based on the
        failure policy.
        The timeout value must be between 1 and 30 seconds.
        Default to 10 seconds.
        """
        return self.__timeout_seconds

    def admission_review_versions(self) -> List[str]:
        """
        AdmissionReviewVersions is an ordered list of preferred `AdmissionReview`
        versions the Webhook expects. API server will try to use first version in
        the list which it supports. If none of the versions specified in this list
        supported by API server, validation will fail for this object.
        If a persisted webhook configuration specifies allowed versions and does not
        include any versions known to the API Server, calls to the webhook will fail
        and be subject to the failure policy.
        """
        return self.__admission_review_versions


class ValidatingWebhookConfiguration(base.TypedObject, base.MetadataObject):
    """
    ValidatingWebhookConfiguration describes the configuration of and admission webhook that accept or reject and object without changing it.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        webhooks: List["ValidatingWebhook"] = None,
    ):
        super().__init__(
            api_version="admissionregistration.k8s.io/v1",
            kind="ValidatingWebhookConfiguration",
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__webhooks = webhooks if webhooks is not None else []

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        webhooks = self.webhooks()
        check_type("webhooks", webhooks, Optional[List["ValidatingWebhook"]])
        if webhooks:  # omit empty
            v["webhooks"] = webhooks
        return v

    def webhooks(self) -> Optional[List["ValidatingWebhook"]]:
        """
        Webhooks is a list of webhooks and the affected resources and operations.
        """
        return self.__webhooks
