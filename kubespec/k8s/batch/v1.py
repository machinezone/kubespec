# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s import v1 as k8sv1
from kubespec.k8s.meta import v1 as metav1
from typeguard import check_type, typechecked
from typing import Any, Dict, Optional


class JobSpec(types.Object):
    """
    JobSpec describes how the job execution will look like.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        parallelism: int = None,
        completions: int = None,
        active_deadline_seconds: int = None,
        backoff_limit: int = None,
        selector: "metav1.LabelSelector" = None,
        manual_selector: bool = None,
        template: "k8sv1.PodTemplateSpec" = None,
        ttl_seconds_after_finished: int = None,
    ):
        super().__init__()
        self.__parallelism = parallelism if parallelism is not None else 1
        self.__completions = completions if completions is not None else 1
        self.__active_deadline_seconds = active_deadline_seconds
        self.__backoff_limit = backoff_limit if backoff_limit is not None else 6
        self.__selector = selector
        self.__manual_selector = manual_selector
        self.__template = template if template is not None else k8sv1.PodTemplateSpec()
        self.__ttl_seconds_after_finished = ttl_seconds_after_finished

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        parallelism = self.parallelism()
        check_type("parallelism", parallelism, Optional[int])
        if parallelism is not None:  # omit empty
            v["parallelism"] = parallelism
        completions = self.completions()
        check_type("completions", completions, Optional[int])
        if completions is not None:  # omit empty
            v["completions"] = completions
        active_deadline_seconds = self.active_deadline_seconds()
        check_type("active_deadline_seconds", active_deadline_seconds, Optional[int])
        if active_deadline_seconds is not None:  # omit empty
            v["activeDeadlineSeconds"] = active_deadline_seconds
        backoff_limit = self.backoff_limit()
        check_type("backoff_limit", backoff_limit, Optional[int])
        if backoff_limit is not None:  # omit empty
            v["backoffLimit"] = backoff_limit
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        manual_selector = self.manual_selector()
        check_type("manual_selector", manual_selector, Optional[bool])
        if manual_selector is not None:  # omit empty
            v["manualSelector"] = manual_selector
        template = self.template()
        check_type("template", template, "k8sv1.PodTemplateSpec")
        v["template"] = template
        ttl_seconds_after_finished = self.ttl_seconds_after_finished()
        check_type(
            "ttl_seconds_after_finished", ttl_seconds_after_finished, Optional[int]
        )
        if ttl_seconds_after_finished is not None:  # omit empty
            v["ttlSecondsAfterFinished"] = ttl_seconds_after_finished
        return v

    def parallelism(self) -> Optional[int]:
        """
        Specifies the maximum desired number of pods the job should
        run at any given time. The actual number of pods running in steady state will
        be less than this number when ((.spec.completions - .status.successful) < .spec.parallelism),
        i.e. when the work left to do is less than max parallelism.
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/
        """
        return self.__parallelism

    def completions(self) -> Optional[int]:
        """
        Specifies the desired number of successfully finished pods the
        job should be run with.  Setting to nil means that the success of any
        pod signals the success of all pods, and allows parallelism to have any positive
        value.  Setting to 1 means that parallelism is limited to 1 and the success of that
        pod signals the success of the job.
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/
        """
        return self.__completions

    def active_deadline_seconds(self) -> Optional[int]:
        """
        Specifies the duration in seconds relative to the startTime that the job may be active
        before the system tries to terminate it; value must be positive integer
        """
        return self.__active_deadline_seconds

    def backoff_limit(self) -> Optional[int]:
        """
        Specifies the number of retries before marking this job failed.
        Defaults to 6
        """
        return self.__backoff_limit

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        A label query over pods that should match the pod count.
        Normally, the system sets this field for you.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
        """
        return self.__selector

    def manual_selector(self) -> Optional[bool]:
        """
        manualSelector controls generation of pod labels and pod selectors.
        Leave `manualSelector` unset unless you are certain what you are doing.
        When false or unset, the system pick labels unique to this job
        and appends those labels to the pod template.  When true,
        the user is responsible for picking unique labels and specifying
        the selector.  Failure to pick a unique label may cause this
        and other jobs to not function correctly.  However, You may see
        `manualSelector=true` in jobs that were created with the old `extensions/v1beta1`
        API.
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/#specifying-your-own-pod-selector
        """
        return self.__manual_selector

    def template(self) -> "k8sv1.PodTemplateSpec":
        """
        Describes the pod that will be created when executing a job.
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/
        """
        return self.__template

    def ttl_seconds_after_finished(self) -> Optional[int]:
        """
        ttlSecondsAfterFinished limits the lifetime of a Job that has finished
        execution (either Complete or Failed). If this field is set,
        ttlSecondsAfterFinished after the Job finishes, it is eligible to be
        automatically deleted. When the Job is being deleted, its lifecycle
        guarantees (e.g. finalizers) will be honored. If this field is unset,
        the Job won't be automatically deleted. If this field is set to zero,
        the Job becomes eligible to be deleted immediately after it finishes.
        This field is alpha-level and is only honored by servers that enable the
        TTLAfterFinished feature.
        """
        return self.__ttl_seconds_after_finished


class Job(base.TypedObject, base.NamespacedMetadataObject):
    """
    Job represents the configuration of a single job.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "JobSpec" = None,
    ):
        super().__init__(
            api_version="batch/v1",
            kind="Job",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else JobSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["JobSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["JobSpec"]:
        """
        Specification of the desired behavior of a job.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec
