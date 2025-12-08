import time
import requests
import psycopg2
from psycopg2.extras import Json, execute_values
from celery_app import celery
import os
from logging import getLogger

API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
API_KEY = os.getenv("NVD_API_KEY")
logger = getLogger(__name__)
DB_DSN = os.getenv("DATABASE_DSN")
SLEEP_BETWEEN_REQUESTS = float(os.getenv("SLEEP_BETWEEN_REQUESTS", "0.8"))
CHUNK_SIZE = 500
MAX_RETRIES = 5
BACKOFF_INITIAL = 1.0

def fetch_cpes_chunk(start_index: int, results_per_page: int):
    params = {"startIndex": start_index, "resultsPerPage": results_per_page}
    headers = {"apiKey": API_KEY} if API_KEY else {}

    backoff = BACKOFF_INITIAL
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(API_URL, params=params, headers=headers, timeout=30)

            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else backoff
                logger.warning(f"429 Too Many Requests, wait {wait}s")
                time.sleep(wait)
                backoff *= 2
                continue

            resp.raise_for_status()
            data = resp.json()
            return data

        except requests.RequestException as e:
            logger.warning(f"Request failed ({attempt}/{MAX_RETRIES}): {e}")
            time.sleep(backoff)
            backoff *= 2

    raise RuntimeError(f"Failed to fetch CPE chunk after {MAX_RETRIES} retries")


def upsert_cpes_to_db(cpe_products, conn):
    insert_sql = """
    INSERT INTO nvd_cpes (
        cpe_name_id,
        cpe_name,
        created,
        last_modified,
        deprecated,
        deprecated_by,
        titles,
        raw
    )
    VALUES %s
    ON CONFLICT (cpe_name_id)
    DO UPDATE SET
        cpe_name = EXCLUDED.cpe_name,
        created = EXCLUDED.created,
        last_modified = EXCLUDED.last_modified,
        deprecated = EXCLUDED.deprecated,
        deprecated_by = EXCLUDED.deprecated_by,
        titles = EXCLUDED.titles,
        raw = EXCLUDED.raw;
    """

    rows = []
    for prod in cpe_products:
        cpe = prod.get("cpe", {})
        cpe_name_id = cpe.get("cpeNameId")
        cpe_name = cpe.get("cpeName")
        created = cpe.get("created")
        last_modified = cpe.get("lastModified")
        deprecated = cpe.get("deprecated", False)
        # Оборачиваем deprecated_by тоже, если это не None
        deprecated_by = cpe.get("deprecatedBy", None)
        if deprecated_by is not None:
            deprecated_by_json = Json(deprecated_by)
        else:
            deprecated_by_json = None

        titles = cpe.get("titles")
        raw = cpe

        rows.append((
            cpe_name_id,
            cpe_name,
            created,
            last_modified,
            deprecated,
            deprecated_by_json,
            Json(titles),
            Json(raw),
        ))

    with conn.cursor() as cur:
        execute_values(cur, insert_sql, rows)
    conn.commit()


@celery.task(bind=True, rate_limit="20/m")
def fetch_and_store_cpe_chunk(self, start_index: int = 0):
    try:
        resp = fetch_cpes_chunk(start_index, CHUNK_SIZE)
        total = resp.get("totalResults")
        products = resp.get("products", [])

        if not products:
            return {"start_index": start_index, "saved": 0, "message": "no records"}

        conn = psycopg2.connect(DB_DSN)
        upsert_cpes_to_db(products, conn)
        conn.close()

        return {"start_index": start_index, "saved": len(products), "total": total}
    except Exception as exc:
        logger.exception("Failed to fetch and store CPE chunk")
        raise self.retry(exc=exc, countdown=10, max_retries=5)

