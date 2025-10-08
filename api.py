from fastapi import FastAPI, HTTPException
from celery.result import AsyncResult
from typing import Any, Dict

from tasks import (
    enqueue_vuln_links,
    fetch_and_store_vuln,
    enqueue_cpe_chunks,
    fetch_and_store_cpe_chunk,
    enqueue_all_bdu_pages
)
from celery_app import celery

app = FastAPI()

@app.post("/scrape/page/{page_number}")
def trigger_scrape_page(page_number: int = 1) -> Dict[str, Any]:
    """Запустить задачу для страницы списка уязвимостей."""
    task = enqueue_vuln_links.delay(page_number)
    return {"task_id": task.id, "message": "Task queued for vuln list page"}

@app.post("/scrape/vuln")
def trigger_scrape_vuln(url: str) -> Dict[str, Any]:
    """Запустить парсинг одной уязвимости по URL."""
    task = fetch_and_store_vuln.delay(url)
    return {"task_id": task.id, "message": "Task queued for single vuln"}

@app.get("/tasks/{task_id}")
def get_task_status(task_id: str):
    res = AsyncResult(task_id, app=celery)
    return {
        "task_id": task_id,
        "status": res.status,
        "result": res.result if res.ready() else None,
    }

@app.get("/celery/stats")
def get_celery_stats():
    insp = celery.control.inspect()
    stats = insp.stats() or {}
    active = insp.active() or {}
    scheduled = insp.scheduled() or {}
    reserved = insp.reserved() or {}
    registered = insp.registered() or {}
    return {
        "stats": stats,
        "active": active,
        "scheduled": scheduled,
        "reserved": reserved,
        "registered_tasks": registered,
    }

@app.post("/scrape/cpe/enqueue")
def trigger_enqueue_cpe() -> Dict[str, Any]:
    """
    Запустить задачу, которая разобьёт весь объём CPE на чанки и поставит задачи на загрузку.
    """
    task = enqueue_cpe_chunks.delay()
    return {"task_id": task.id, "message": "Task queued for enqueueing CPE chunks"}

@app.post("/scrape/cpe/fetch")
def trigger_fetch_cpe_chunk(start_index: int) -> Dict[str, Any]:
    """
    Запустить задачу для загрузки одного чанка CPE, начиная с заданного индекса.
    """
    task = fetch_and_store_cpe_chunk.delay(start_index)
    return {"task_id": task.id, "message": f"Task queued for CPE chunk at start_index={start_index}"}


@app.post("/scrape/bdu/all")
def trigger_scrape_all_bdu(start_page: int = 1, max_pages: int | None = None) -> Dict[str, Any]:
    """
    Запускает задачу, которая проходит все страницы БДУ и ставит задачи на парсинг каждой уязвимости.
    Можно указать max_pages для ограничения числа страниц.
    """
    task = enqueue_all_bdu_pages.delay(start_page=start_page, max_pages=max_pages)
    return {
        "task_id": task.id,
        "message": "Task queued for scraping all BDU pages",
        "start_page": start_page,
        "max_pages": max_pages,
    }
