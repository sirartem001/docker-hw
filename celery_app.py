import os
from celery import Celery

celery = Celery(
    "bdu_scraper",
    broker=os.getenv("CELERY_BROKER_URL"),
    backend=os.getenv("CELERY_RESULT_BACKEND"),
    include=["tasks"]
)

celery.conf.task_track_started = True
celery.conf.result_expires = 3600

import tasks
