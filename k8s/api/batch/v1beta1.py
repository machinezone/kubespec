# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict, Optional

from k8s import base
from k8s.api.batch import v1 as batchv1
from kargo import types
from typeguard import typechecked


# ConcurrencyPolicy describes how the job will be handled.
# Only one of the following concurrent policies may be specified.
# If none of the following policies is specified, the default one
# is AllowConcurrent.
ConcurrencyPolicy = base.Enum('ConcurrencyPolicy', {
    # Allow allows CronJobs to run concurrently.
    'Allow': 'Allow',
    # Forbid forbids concurrent runs, skipping next run if previous
    # hasn't finished yet.
    'Forbid': 'Forbid',
    # Replace cancels currently running job and replaces it with a new one.
    'Replace': 'Replace',
})


# JobTemplateSpec describes the data a Job should have when created from a template
class JobTemplateSpec(base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    # Specification of the desired behavior of the job.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> 'batchv1.JobSpec':
        return self._kwargs.get('spec', batchv1.JobSpec())


# CronJobSpec describes how the job execution will look like and when it will actually run.
class CronJobSpec(types.Object):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['schedule'] = self.schedule()
        startingDeadlineSeconds = self.startingDeadlineSeconds()
        if startingDeadlineSeconds is not None:  # omit empty
            v['startingDeadlineSeconds'] = startingDeadlineSeconds
        concurrencyPolicy = self.concurrencyPolicy()
        if concurrencyPolicy:  # omit empty
            v['concurrencyPolicy'] = concurrencyPolicy
        suspend = self.suspend()
        if suspend is not None:  # omit empty
            v['suspend'] = suspend
        v['jobTemplate'] = self.jobTemplate()
        successfulJobsHistoryLimit = self.successfulJobsHistoryLimit()
        if successfulJobsHistoryLimit is not None:  # omit empty
            v['successfulJobsHistoryLimit'] = successfulJobsHistoryLimit
        failedJobsHistoryLimit = self.failedJobsHistoryLimit()
        if failedJobsHistoryLimit is not None:  # omit empty
            v['failedJobsHistoryLimit'] = failedJobsHistoryLimit
        return v
    
    # The schedule in Cron format, see https://en.wikipedia.org/wiki/Cron.
    @typechecked
    def schedule(self) -> str:
        return self._kwargs.get('schedule', '')
    
    # Optional deadline in seconds for starting the job if it misses scheduled
    # time for any reason.  Missed jobs executions will be counted as failed ones.
    @typechecked
    def startingDeadlineSeconds(self) -> Optional[int]:
        return self._kwargs.get('startingDeadlineSeconds')
    
    # Specifies how to treat concurrent executions of a Job.
    # Valid values are:
    # - "Allow" (default): allows CronJobs to run concurrently;
    # - "Forbid": forbids concurrent runs, skipping next run if previous run hasn't finished yet;
    # - "Replace": cancels currently running job and replaces it with a new one
    @typechecked
    def concurrencyPolicy(self) -> Optional[ConcurrencyPolicy]:
        return self._kwargs.get('concurrencyPolicy', ConcurrencyPolicy['Allow'])
    
    # This flag tells the controller to suspend subsequent executions, it does
    # not apply to already started executions.  Defaults to false.
    @typechecked
    def suspend(self) -> Optional[bool]:
        return self._kwargs.get('suspend')
    
    # Specifies the job that will be created when executing a CronJob.
    @typechecked
    def jobTemplate(self) -> JobTemplateSpec:
        return self._kwargs.get('jobTemplate', JobTemplateSpec())
    
    # The number of successful finished jobs to retain.
    # This is a pointer to distinguish between explicit zero and not specified.
    # Defaults to 3.
    @typechecked
    def successfulJobsHistoryLimit(self) -> Optional[int]:
        return self._kwargs.get('successfulJobsHistoryLimit', 3)
    
    # The number of failed finished jobs to retain.
    # This is a pointer to distinguish between explicit zero and not specified.
    # Defaults to 1.
    @typechecked
    def failedJobsHistoryLimit(self) -> Optional[int]:
        return self._kwargs.get('failedJobsHistoryLimit', 1)


# CronJob represents the configuration of a single cron job.
class CronJob(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['spec'] = self.spec()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'batch/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'CronJob'
    
    # Specification of the desired behavior of a cron job, including the schedule.
    # More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def spec(self) -> CronJobSpec:
        return self._kwargs.get('spec', CronJobSpec())


# JobTemplate describes a template for creating copies of a predefined pod.
class JobTemplate(base.TypedObject, base.MetadataObject):

    @typechecked
    def render(self) -> Dict[str, Any]:
        v = super().render()
        v['template'] = self.template()
        return v
    
    @typechecked
    def apiVersion(self) -> str:
        return 'batch/v1beta1'
    
    @typechecked
    def kind(self) -> str:
        return 'JobTemplate'
    
    # Defines jobs that will be created from this template.
    # https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
    @typechecked
    def template(self) -> JobTemplateSpec:
        return self._kwargs.get('template', JobTemplateSpec())
