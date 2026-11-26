from celery import Celery
from .config import settings

celery_app = Celery("sentinel", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(task_always_eager=settings.eager, task_acks_late=True, worker_prefetch_multiplier=1,
                       task_time_limit=settings.scan_timeout + 120, broker_connection_retry_on_startup=True)


@celery_app.task(name="sentinel.run_job")
def run_job(job_id: int):
    from .worker_core import process_job  # imported lazily: scanner code is only needed in the worker
    process_job(job_id)


@celery_app.task(name="sentinel.tool_status")
def tool_status_task():
    from .scanners import tool_status
    return tool_status()
