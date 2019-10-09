# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.api.batch import v1 as batchv1
from kargo import context
from kargo import types
from typeguard import check_return_type, typechecked


# ConcurrencyPolicy describes how the job will be handled.
# Only one of the following concurrent policies may be specified.
# If none of the following policies is specified, the default one
# is AllowConcurrent.
ConcurrencyPolicy = base.Enum(
    "ConcurrencyPolicy",
    {
        # Allow allows CronJobs to run concurrently.
        "Allow": "Allow",
        # Forbid forbids concurrent runs, skipping next run if previous
        # hasn't finished yet.
        "Forbid": "Forbid",
        # Replace cancels currently running job and replaces it with a new one.
        "Replace": "Replace",
    },
)


# JobTemplateSpec describes the data a Job should have when created from a template
class JobTemplateSpec(base.NamespacedMetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    # Specification of the desired behavior of the job.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> "batchv1.JobSpec":
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return batchv1.JobSpec()


# CronJobSpec describes how the job execution will look like and when it will actually run.
class CronJobSpec(types.Object):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["schedule"] = self.schedule()
        startingDeadlineSeconds = self.startingDeadlineSeconds()
        if startingDeadlineSeconds is not None:  # omit empty
            v["startingDeadlineSeconds"] = startingDeadlineSeconds
        concurrencyPolicy = self.concurrencyPolicy()
        if concurrencyPolicy:  # omit empty
            v["concurrencyPolicy"] = concurrencyPolicy
        suspend = self.suspend()
        if suspend is not None:  # omit empty
            v["suspend"] = suspend
        v["jobTemplate"] = self.jobTemplate()
        successfulJobsHistoryLimit = self.successfulJobsHistoryLimit()
        if successfulJobsHistoryLimit is not None:  # omit empty
            v["successfulJobsHistoryLimit"] = successfulJobsHistoryLimit
        failedJobsHistoryLimit = self.failedJobsHistoryLimit()
        if failedJobsHistoryLimit is not None:  # omit empty
            v["failedJobsHistoryLimit"] = failedJobsHistoryLimit
        return v

    # The schedule in Cron format, see https://en.wikipedia.org/wiki/Cron.
    @typechecked
    def schedule(self) -> str:
        if "schedule" in self._kwargs:
            return self._kwargs["schedule"]
        if "schedule" in self._context and check_return_type(self._context["schedule"]):
            return self._context["schedule"]
        return ""

    # Optional deadline in seconds for starting the job if it misses scheduled
    # time for any reason.  Missed jobs executions will be counted as failed ones.
    @typechecked
    def startingDeadlineSeconds(self) -> Optional[int]:
        if "startingDeadlineSeconds" in self._kwargs:
            return self._kwargs["startingDeadlineSeconds"]
        if "startingDeadlineSeconds" in self._context and check_return_type(
            self._context["startingDeadlineSeconds"]
        ):
            return self._context["startingDeadlineSeconds"]
        return None

    # Specifies how to treat concurrent executions of a Job.
    # Valid values are:
    # - "Allow" (default): allows CronJobs to run concurrently;
    # - "Forbid": forbids concurrent runs, skipping next run if previous run hasn't finished yet;
    # - "Replace": cancels currently running job and replaces it with a new one
    @typechecked
    def concurrencyPolicy(self) -> Optional[ConcurrencyPolicy]:
        if "concurrencyPolicy" in self._kwargs:
            return self._kwargs["concurrencyPolicy"]
        if "concurrencyPolicy" in self._context and check_return_type(
            self._context["concurrencyPolicy"]
        ):
            return self._context["concurrencyPolicy"]
        return ConcurrencyPolicy["Allow"]

    # This flag tells the controller to suspend subsequent executions, it does
    # not apply to already started executions.  Defaults to false.
    @typechecked
    def suspend(self) -> Optional[bool]:
        if "suspend" in self._kwargs:
            return self._kwargs["suspend"]
        if "suspend" in self._context and check_return_type(self._context["suspend"]):
            return self._context["suspend"]
        return None

    # Specifies the job that will be created when executing a CronJob.
    @typechecked
    def jobTemplate(self) -> JobTemplateSpec:
        if "jobTemplate" in self._kwargs:
            return self._kwargs["jobTemplate"]
        if "jobTemplate" in self._context and check_return_type(
            self._context["jobTemplate"]
        ):
            return self._context["jobTemplate"]
        with context.Scope(**self._context):
            return JobTemplateSpec()

    # The number of successful finished jobs to retain.
    # This is a pointer to distinguish between explicit zero and not specified.
    @typechecked
    def successfulJobsHistoryLimit(self) -> Optional[int]:
        if "successfulJobsHistoryLimit" in self._kwargs:
            return self._kwargs["successfulJobsHistoryLimit"]
        if "successfulJobsHistoryLimit" in self._context and check_return_type(
            self._context["successfulJobsHistoryLimit"]
        ):
            return self._context["successfulJobsHistoryLimit"]
        return None

    # The number of failed finished jobs to retain.
    # This is a pointer to distinguish between explicit zero and not specified.
    @typechecked
    def failedJobsHistoryLimit(self) -> Optional[int]:
        if "failedJobsHistoryLimit" in self._kwargs:
            return self._kwargs["failedJobsHistoryLimit"]
        if "failedJobsHistoryLimit" in self._context and check_return_type(
            self._context["failedJobsHistoryLimit"]
        ):
            return self._context["failedJobsHistoryLimit"]
        return None


# CronJob represents the configuration of a single cron job.
class CronJob(base.TypedObject, base.NamespacedMetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["spec"] = self.spec()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "batch/v2alpha1"

    @typechecked
    def kind(self) -> str:
        return "CronJob"

    # Specification of the desired behavior of a cron job, including the schedule.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> CronJobSpec:
        if "spec" in self._kwargs:
            return self._kwargs["spec"]
        if "spec" in self._context and check_return_type(self._context["spec"]):
            return self._context["spec"]
        with context.Scope(**self._context):
            return CronJobSpec()


# JobTemplate describes a template for creating copies of a predefined pod.
class JobTemplate(base.TypedObject, base.NamespacedMetadataObject):
    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v["template"] = self.template()
        return v

    @typechecked
    def apiVersion(self) -> str:
        return "batch/v2alpha1"

    @typechecked
    def kind(self) -> str:
        return "JobTemplate"

    # Defines jobs that will be created from this template.
    # https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def template(self) -> JobTemplateSpec:
        if "template" in self._kwargs:
            return self._kwargs["template"]
        if "template" in self._context and check_return_type(self._context["template"]):
            return self._context["template"]
        with context.Scope(**self._context):
            return JobTemplateSpec()
