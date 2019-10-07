# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.api.core import v1 as corev1
from k8s.apimachinery.meta import v1 as metav1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# JobSpec describes how the job execution will look like.
class JobSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        parallelism = self.parallelism()
        if parallelism is not None:  # omit empty
            v["parallelism"] = parallelism
        completions = self.completions()
        if completions is not None:  # omit empty
            v["completions"] = completions
        activeDeadlineSeconds = self.activeDeadlineSeconds()
        if activeDeadlineSeconds is not None:  # omit empty
            v["activeDeadlineSeconds"] = activeDeadlineSeconds
        backoffLimit = self.backoffLimit()
        if backoffLimit is not None:  # omit empty
            v["backoffLimit"] = backoffLimit
        selector = self.selector()
        if selector is not None:  # omit empty
            v["selector"] = selector
        manualSelector = self.manualSelector()
        if manualSelector is not None:  # omit empty
            v["manualSelector"] = manualSelector
        v["template"] = self.template()
        ttlSecondsAfterFinished = self.ttlSecondsAfterFinished()
        if ttlSecondsAfterFinished is not None:  # omit empty
            v["ttlSecondsAfterFinished"] = ttlSecondsAfterFinished
        return v

    # Specifies the maximum desired number of pods the job should
    # run at any given time. The actual number of pods running in steady state will
    # be less than this number when ((.spec.completions - .status.successful) < .spec.parallelism),
    # i.e. when the work left to do is less than max parallelism.
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/
    @typechecked
    def parallelism(self) -> Optional[int]:
        if "parallelism" in self._kwargs:
            return self._kwargs["parallelism"]
        if "parallelism" in self._context and check_return_type(
            self._context["parallelism"]
        ):
            return self._context["parallelism"]
        return 1

    # Specifies the desired number of successfully finished pods the
    # job should be run with.  Setting to nil means that the success of any
    # pod signals the success of all pods, and allows parallelism to have any positive
    # value.  Setting to 1 means that parallelism is limited to 1 and the success of that
    # pod signals the success of the job.
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/
    @typechecked
    def completions(self) -> Optional[int]:
        if "completions" in self._kwargs:
            return self._kwargs["completions"]
        if "completions" in self._context and check_return_type(
            self._context["completions"]
        ):
            return self._context["completions"]
        return 1

    # Specifies the duration in seconds relative to the startTime that the job may be active
    # before the system tries to terminate it; value must be positive integer
    @typechecked
    def activeDeadlineSeconds(self) -> Optional[int]:
        if "activeDeadlineSeconds" in self._kwargs:
            return self._kwargs["activeDeadlineSeconds"]
        if "activeDeadlineSeconds" in self._context and check_return_type(
            self._context["activeDeadlineSeconds"]
        ):
            return self._context["activeDeadlineSeconds"]
        return None

    # Specifies the number of retries before marking this job failed.
    # Defaults to 6
    @typechecked
    def backoffLimit(self) -> Optional[int]:
        if "backoffLimit" in self._kwargs:
            return self._kwargs["backoffLimit"]
        if "backoffLimit" in self._context and check_return_type(
            self._context["backoffLimit"]
        ):
            return self._context["backoffLimit"]
        return 6

    # A label query over pods that should match the pod count.
    # Normally, the system sets this field for you.
    # More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
    @typechecked
    def selector(self) -> Optional["metav1.LabelSelector"]:
        if "selector" in self._kwargs:
            return self._kwargs["selector"]
        if "selector" in self._context and check_return_type(self._context["selector"]):
            return self._context["selector"]
        return None

    # manualSelector controls generation of pod labels and pod selectors.
    # Leave `manualSelector` unset unless you are certain what you are doing.
    # When false or unset, the system pick labels unique to this job
    # and appends those labels to the pod template.  When true,
    # the user is responsible for picking unique labels and specifying
    # the selector.  Failure to pick a unique label may cause this
    # and other jobs to not function correctly.  However, You may see
    # `manualSelector=true` in jobs that were created with the old `extensions/v1beta1`
    # API.
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/#specifying-your-own-pod-selector
    @typechecked
    def manualSelector(self) -> Optional[bool]:
        if "manualSelector" in self._kwargs:
            return self._kwargs["manualSelector"]
        if "manualSelector" in self._context and check_return_type(
            self._context["manualSelector"]
        ):
            return self._context["manualSelector"]
        return None

    # Describes the pod that will be created when executing a job.
    # More info: https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/
    @typechecked
    def template(self) -> "corev1.PodTemplateSpec":
        if "template" in self._kwargs:
            return self._kwargs["template"]
        if "template" in self._context and check_return_type(self._context["template"]):
            return self._context["template"]
        with context.Scope(**self._context):
            return corev1.PodTemplateSpec()

    # ttlSecondsAfterFinished limits the lifetime of a Job that has finished
    # execution (either Complete or Failed). If this field is set,
    # ttlSecondsAfterFinished after the Job finishes, it is eligible to be
    # automatically deleted. When the Job is being deleted, its lifecycle
    # guarantees (e.g. finalizers) will be honored. If this field is unset,
    # the Job won't be automatically deleted. If this field is set to zero,
    # the Job becomes eligible to be deleted immediately after it finishes.
    # This field is alpha-level and is only honored by servers that enable the
    # TTLAfterFinished feature.
    @typechecked
    def ttlSecondsAfterFinished(self) -> Optional[int]:
        if "ttlSecondsAfterFinished" in self._kwargs:
            return self._kwargs["ttlSecondsAfterFinished"]
        if "ttlSecondsAfterFinished" in self._context and check_return_type(
            self._context["ttlSecondsAfterFinished"]
        ):
            return self._context["ttlSecondsAfterFinished"]
        return None


# Job represents the configuration of a single job.
class Job(base.TypedObject, base.MetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "batch/v1"

    @typechecked
    def kind(self) -> str:
        return "Job"

    # Specification of the desired behavior of a job.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> JobSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return JobSpec()
