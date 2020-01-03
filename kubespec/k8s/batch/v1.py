# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.


from kubespec import context
from kubespec import types
from kubespec.k8s import base
from kubespec.k8s.core import v1 as corev1
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
        activeDeadlineSeconds: int = None,
        backoffLimit: int = None,
        selector: "metav1.LabelSelector" = None,
        manualSelector: bool = None,
        template: "corev1.PodTemplateSpec" = None,
        ttlSecondsAfterFinished: int = None,
    ):
        super().__init__()
        self.__parallelism = parallelism if parallelism is not None else 1
        self.__completions = completions if completions is not None else 1
        self.__activeDeadlineSeconds = activeDeadlineSeconds
        self.__backoffLimit = backoffLimit if backoffLimit is not None else 6
        self.__selector = selector
        self.__manualSelector = manualSelector
        self.__template = template if template is not None else corev1.PodTemplateSpec()
        self.__ttlSecondsAfterFinished = ttlSecondsAfterFinished

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
        activeDeadlineSeconds = self.activeDeadlineSeconds()
        check_type("activeDeadlineSeconds", activeDeadlineSeconds, Optional[int])
        if activeDeadlineSeconds is not None:  # omit empty
            v["activeDeadlineSeconds"] = activeDeadlineSeconds
        backoffLimit = self.backoffLimit()
        check_type("backoffLimit", backoffLimit, Optional[int])
        if backoffLimit is not None:  # omit empty
            v["backoffLimit"] = backoffLimit
        selector = self.selector()
        check_type("selector", selector, Optional["metav1.LabelSelector"])
        if selector is not None:  # omit empty
            v["selector"] = selector
        manualSelector = self.manualSelector()
        check_type("manualSelector", manualSelector, Optional[bool])
        if manualSelector is not None:  # omit empty
            v["manualSelector"] = manualSelector
        template = self.template()
        check_type("template", template, "corev1.PodTemplateSpec")
        v["template"] = template
        ttlSecondsAfterFinished = self.ttlSecondsAfterFinished()
        check_type("ttlSecondsAfterFinished", ttlSecondsAfterFinished, Optional[int])
        if ttlSecondsAfterFinished is not None:  # omit empty
            v["ttlSecondsAfterFinished"] = ttlSecondsAfterFinished
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

    def activeDeadlineSeconds(self) -> Optional[int]:
        """
        Specifies the duration in seconds relative to the startTime that the job may be active
        before the system tries to terminate it; value must be positive integer
        """
        return self.__activeDeadlineSeconds

    def backoffLimit(self) -> Optional[int]:
        """
        Specifies the number of retries before marking this job failed.
        Defaults to 6
        """
        return self.__backoffLimit

    def selector(self) -> Optional["metav1.LabelSelector"]:
        """
        A label query over pods that should match the pod count.
        Normally, the system sets this field for you.
        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
        """
        return self.__selector

    def manualSelector(self) -> Optional[bool]:
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
        return self.__manualSelector

    def template(self) -> "corev1.PodTemplateSpec":
        """
        Describes the pod that will be created when executing a job.
        More info: https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/
        """
        return self.__template

    def ttlSecondsAfterFinished(self) -> Optional[int]:
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
        return self.__ttlSecondsAfterFinished


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
            apiVersion="batch/v1",
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
