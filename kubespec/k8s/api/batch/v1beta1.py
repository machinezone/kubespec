# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from kubespec.k8s import base
from kubespec.k8s.api.batch import v1 as batchv1
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


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


class JobTemplateSpec(base.NamespacedMetadataObject):
    """
    JobTemplateSpec describes the data a Job should have when created from a template
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "batchv1.JobSpec" = None,
    ):
        super().__init__(
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else batchv1.JobSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["batchv1.JobSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["batchv1.JobSpec"]:
        """
        Specification of the desired behavior of the job.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class CronJobSpec(types.Object):
    """
    CronJobSpec describes how the job execution will look like and when it will actually run.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        schedule: str = "",
        startingDeadlineSeconds: int = None,
        concurrencyPolicy: ConcurrencyPolicy = ConcurrencyPolicy["Allow"],
        suspend: bool = None,
        jobTemplate: "JobTemplateSpec" = None,
        successfulJobsHistoryLimit: int = None,
        failedJobsHistoryLimit: int = None,
    ):
        super().__init__()
        self.__schedule = schedule
        self.__startingDeadlineSeconds = startingDeadlineSeconds
        self.__concurrencyPolicy = concurrencyPolicy
        self.__suspend = suspend
        self.__jobTemplate = (
            jobTemplate if jobTemplate is not None else JobTemplateSpec()
        )
        self.__successfulJobsHistoryLimit = (
            successfulJobsHistoryLimit if successfulJobsHistoryLimit is not None else 3
        )
        self.__failedJobsHistoryLimit = (
            failedJobsHistoryLimit if failedJobsHistoryLimit is not None else 1
        )

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        schedule = self.schedule()
        check_type("schedule", schedule, str)
        v["schedule"] = schedule
        startingDeadlineSeconds = self.startingDeadlineSeconds()
        check_type("startingDeadlineSeconds", startingDeadlineSeconds, Optional[int])
        if startingDeadlineSeconds is not None:  # omit empty
            v["startingDeadlineSeconds"] = startingDeadlineSeconds
        concurrencyPolicy = self.concurrencyPolicy()
        check_type("concurrencyPolicy", concurrencyPolicy, Optional[ConcurrencyPolicy])
        if concurrencyPolicy:  # omit empty
            v["concurrencyPolicy"] = concurrencyPolicy
        suspend = self.suspend()
        check_type("suspend", suspend, Optional[bool])
        if suspend is not None:  # omit empty
            v["suspend"] = suspend
        jobTemplate = self.jobTemplate()
        check_type("jobTemplate", jobTemplate, "JobTemplateSpec")
        v["jobTemplate"] = jobTemplate
        successfulJobsHistoryLimit = self.successfulJobsHistoryLimit()
        check_type(
            "successfulJobsHistoryLimit", successfulJobsHistoryLimit, Optional[int]
        )
        if successfulJobsHistoryLimit is not None:  # omit empty
            v["successfulJobsHistoryLimit"] = successfulJobsHistoryLimit
        failedJobsHistoryLimit = self.failedJobsHistoryLimit()
        check_type("failedJobsHistoryLimit", failedJobsHistoryLimit, Optional[int])
        if failedJobsHistoryLimit is not None:  # omit empty
            v["failedJobsHistoryLimit"] = failedJobsHistoryLimit
        return v

    def schedule(self) -> str:
        """
        The schedule in Cron format, see https://en.wikipedia.org/wiki/Cron.
        """
        return self.__schedule

    def startingDeadlineSeconds(self) -> Optional[int]:
        """
        Optional deadline in seconds for starting the job if it misses scheduled
        time for any reason.  Missed jobs executions will be counted as failed ones.
        """
        return self.__startingDeadlineSeconds

    def concurrencyPolicy(self) -> Optional[ConcurrencyPolicy]:
        """
        Specifies how to treat concurrent executions of a Job.
        Valid values are:
        - "Allow" (default): allows CronJobs to run concurrently;
        - "Forbid": forbids concurrent runs, skipping next run if previous run hasn't finished yet;
        - "Replace": cancels currently running job and replaces it with a new one
        """
        return self.__concurrencyPolicy

    def suspend(self) -> Optional[bool]:
        """
        This flag tells the controller to suspend subsequent executions, it does
        not apply to already started executions.  Defaults to false.
        """
        return self.__suspend

    def jobTemplate(self) -> "JobTemplateSpec":
        """
        Specifies the job that will be created when executing a CronJob.
        """
        return self.__jobTemplate

    def successfulJobsHistoryLimit(self) -> Optional[int]:
        """
        The number of successful finished jobs to retain.
        This is a pointer to distinguish between explicit zero and not specified.
        Defaults to 3.
        """
        return self.__successfulJobsHistoryLimit

    def failedJobsHistoryLimit(self) -> Optional[int]:
        """
        The number of failed finished jobs to retain.
        This is a pointer to distinguish between explicit zero and not specified.
        Defaults to 1.
        """
        return self.__failedJobsHistoryLimit


class CronJob(base.TypedObject, base.NamespacedMetadataObject):
    """
    CronJob represents the configuration of a single cron job.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        spec: "CronJobSpec" = None,
    ):
        super().__init__(
            apiVersion="batch/v1beta1",
            kind="CronJob",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__spec = spec if spec is not None else CronJobSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        spec = self.spec()
        check_type("spec", spec, Optional["CronJobSpec"])
        v["spec"] = spec
        return v

    def spec(self) -> Optional["CronJobSpec"]:
        """
        Specification of the desired behavior of a cron job, including the schedule.
        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__spec


class JobTemplate(base.TypedObject, base.NamespacedMetadataObject):
    """
    JobTemplate describes a template for creating copies of a predefined pod.
    """

    @context.scoped
    @typechecked
    def __init__(
        self,
        namespace: str = None,
        name: str = None,
        labels: Dict[str, str] = None,
        annotations: Dict[str, str] = None,
        template: "JobTemplateSpec" = None,
    ):
        super().__init__(
            apiVersion="batch/v1beta1",
            kind="JobTemplate",
            **({"namespace": namespace} if namespace is not None else {}),
            **({"name": name} if name is not None else {}),
            **({"labels": labels} if labels is not None else {}),
            **({"annotations": annotations} if annotations is not None else {}),
        )
        self.__template = template if template is not None else JobTemplateSpec()

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        template = self.template()
        check_type("template", template, Optional["JobTemplateSpec"])
        v["template"] = template
        return v

    def template(self) -> Optional["JobTemplateSpec"]:
        """
        Defines jobs that will be created from this template.
        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
        """
        return self.__template
