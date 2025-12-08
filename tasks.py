import psycopg2
from playwright.sync_api import sync_playwright
from bdu import fetch_rendered, parse_list_page, parse_vuln_page, store_bulk
from nvd import fetch_and_store_cpe_chunk, fetch_cpes_chunk
from celery_app import celery
import os

DB_DSN = os.getenv("DATABASE_DSN")
API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
API_KEY = os.getenv("NVD_API_KEY")
CHUNK_SIZE = 500

@celery.task(bind=True, rate_limit="30/m")
def fetch_and_store_vuln(self, url: str):
    """Скачать страницу уязвимости и сохранить её в БД."""
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            html = fetch_rendered(page, url, wait_selector="tr, h1", timeout=60000)
            item = parse_vuln_page(html, url)

            conn = psycopg2.connect(DB_DSN)
            store_bulk(conn, [item])
            conn.close()

            context.close()
            browser.close()

            return {"bdu_id": item["bdu_id"]}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=15, max_retries=3)


@celery.task(bind=True)
def enqueue_vuln_links(self, page_number: int = 1):
    """Парсит страницу списка и ставит задачи fetch_and_store_vuln для каждой ссылки."""
    from bdu import BASE_URL, LIST_PATH

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            list_url = f"{BASE_URL.rstrip('/')}{LIST_PATH}"
            if page_number > 1:
                list_url = f"{list_url}?page={page_number}"

            html = fetch_rendered(page, list_url, wait_selector="ul.list-news, table", timeout=60000)
            links = parse_list_page(html)

            for link in links:
                fetch_and_store_vuln.delay(link)

            context.close()
            browser.close()

        return {"page": page_number, "count": len(links)}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=15, max_retries=3)


@celery.task(bind=True)
def enqueue_all_bdu_pages(self, start_page: int = 1, max_pages: int | None = None):
    """Проходит все страницы списка БДУ и ставит задачи на enqueue_vuln_links."""
    from bdu import BASE_URL, LIST_PATH

    page_number = start_page
    total_pages = 0

    try:
        while True:
            enqueue_vuln_links.delay(page_number)
            total_pages += 1

            if max_pages and page_number >= max_pages:
                break

            page_number += 1

            if total_pages % 20 == 0:
                celery.control.purge()

        return {"pages_enqueued": total_pages}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60, max_retries=3)


@celery.task(bind=True)
def enqueue_cpe_chunks(self):
    """Ставит задачи на загрузку CPE чанков из NVD."""
    try:
        resp = fetch_cpes_chunk(0, CHUNK_SIZE)
        total = resp.get("totalResults")
        if total is None:
            raise RuntimeError("Не удалось получить totalResults из API")

        start = 0
        count = 0
        while start < total:
            fetch_and_store_cpe_chunk.delay(start)
            count += 1
            start += CHUNK_SIZE

        return {"total": total, "tasks_scheduled": count}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=30, max_retries=3)
