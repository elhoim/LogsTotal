"""Finding totals shared by worker finalization and web-side recovery."""

from sqlalchemy.orm import Session, joinedload

from app.constants import EMPTY_SEVERITY_SUMMARY, is_post_processing_task
from app.json_utils import dumps
from app.models import AnalysisJob, TaskResult, TaskStatus, enum_val


def rollup_job_counts(db: Session, job: AnalysisJob) -> None:
    """Refresh totals from persisted findings without committing.

    Async callers use ``AsyncSession.run_sync`` so recovery and cancellation apply
    the same counting rules as the worker, in their existing transaction.
    """
    task_results = db.query(TaskResult).options(joinedload(TaskResult.findings)).filter(TaskResult.job_id == job.id).all()
    detection_results = [tr for tr in task_results if not is_post_processing_task(tr.tool_name)]
    severity_counts = dict(EMPTY_SEVERITY_SUMMARY)
    total_findings = 0
    tools_with_hits = 0
    for tr in detection_results:
        if tr.findings:
            tools_with_hits += 1
        for finding in tr.findings:
            total_findings += finding.count
            severity = enum_val(finding.severity)
            severity_counts[severity] = severity_counts.get(severity, 0) + finding.count

    total_tools = len([tr for tr in detection_results if tr.status not in (TaskStatus.SKIPPED, TaskStatus.CANCELLED)])
    job.score_ratio = f"{tools_with_hits}/{total_tools}" if total_tools else "0/0"
    job.total_findings = total_findings
    job.severity_summary = dumps(severity_counts)
