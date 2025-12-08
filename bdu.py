import re
import json
from datetime import datetime
from typing import Optional, List, Dict

from bs4 import BeautifulSoup
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from psycopg2.extras import execute_values

DATE_RE = re.compile(r"\b(\d{2}\.\d{2}\.\d{4})\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
BDU_ID_RE = re.compile(r"\bBDU[:\-\s]?(\d{4}-\d{5})\b", re.IGNORECASE)


BASE_URL = "https://bdu.fstec.ru"
LIST_PATH = "/vul"


def _extract_base_vector(soup: BeautifulSoup) -> Optional[str]:
    for tr in soup.select("tr"):
        first = tr.find(["td", "th"])
        if not first:
            continue
        label = first.get_text(" ", strip=True).lower()
        if any(x in label for x in ["базовый вектор", "base vector", "cvss", "вектор оценки", "вектор базовый"]):
            tds = tr.find_all("td")
            if len(tds) < 2:
                continue
            cell = tds[1]
            lis = cell.select("li")
            if lis:
                return "; ".join(li.get_text(" ", strip=True) for li in lis if li.get_text(strip=True))
            text = cell.get_text(" ", strip=True)
            if text:
                m = re.search(r'AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z]', text)
                if m:
                    return m.group(0)
                return text
    return None

def fetch_rendered(page, url: str, wait_selector: Optional[str] = None, timeout: int = 60000, retries: int = 3) -> str:
    page.set_default_navigation_timeout(timeout)
    page.set_default_timeout(timeout)
    last_err = None
    for _ in range(retries):
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            page.wait_for_selector(wait_selector or "table, ul.list-news", timeout=timeout)
            return page.content()
        except PlaywrightTimeoutError as e:
            last_err = e
        except Exception as e:
            last_err = e
    raise last_err


def _extract_date(text: str) -> Optional[datetime.date]:
    if not text:
        return None
    m = DATE_RE.search(text)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%d.%m.%Y").date()
    except Exception:
        return None


def _get_row(soup: BeautifulSoup, label_sub: str, multiple: bool = False, joiner: str = "; ") -> Optional[str]:
    label_sub = label_sub.lower()
    for tr in soup.select("tr"):
        first = tr.find(["td", "th"])
        if not first:
            continue
        if label_sub in first.get_text(" ", strip=True).lower():
            tds = tr.find_all("td")
            if len(tds) < 2:
                return None
            if multiple:
                items = [li.get_text(" ", strip=True) for li in tds[1].select("li")]
                return joiner.join(i for i in items if i)
            return tds[1].get_text("\n", strip=True)
    return None


def _extract_discovered_date(soup: BeautifulSoup, html: str) -> Optional[datetime.date]:
    v = _get_row(soup, "дата выявления")
    if v:
        return _extract_date(v)
    idx = html.lower().find("дата выявления")
    if idx != -1:
        window = html[max(0, idx - 200): idx + 200]
        return _extract_date(window)
    return _extract_date(html)


def _extract_severity(soup: BeautifulSoup, html: str) -> Optional[str]:
    v = _get_row(soup, "класс уязвимости") or _get_row(soup, "уровень опасности") or _get_row(soup, "критичн")
    if v:
        return v
    for pattern in (r'v_model\.clv\.clv_name\s*[:=]\s*"([^"]+)"', r'cmp_vul_critu\s*[:=]\s*"([^"]+)"'):
        m = re.search(pattern, html)
        if m:
            return m.group(1).strip()
    return None


def parse_list_page(html: str) -> List[str]:
    soup = BeautifulSoup(html, "lxml")
    links = []
    for a in soup.select("ul.list-news a"):
        href = a.get("href")
        if href and "/vul/" in href:
            links.append(href)
    for a in soup.select("a[href]"):
        href = a["href"].strip()
        if re.search(r"/vul/\d{4}-\d{5}", href):
            links.append(href)
    seen = set()
    res = []
    for u in links:
        full = u if u.startswith("http") else BASE_URL.rstrip("/") + u
        if full not in seen:
            seen.add(full)
            res.append(full)
    return res


def parse_vuln_page(html: str, url: str) -> Dict:
    soup = BeautifulSoup(html, "lxml")
    title = None
    if soup.find("h1"):
        title = soup.find("h1").get_text(strip=True)
    elif soup.title:
        title = soup.title.get_text(strip=True)

    m = BDU_ID_RE.search(html)
    if m:
        bdu_id = "BDU:" + m.group(1)
    else:
        part = url.rstrip("/").split("/")[-1]
        bdu_id = "BDU:" + part if re.match(r"\d{4}-\d{5}", part) else part

    discovered_date = _extract_discovered_date(soup, html)
    severity = _extract_severity(soup, html)

    base_vector = _extract_base_vector(soup)

    error_type = None
    for tr in soup.select("tr"):
        first = tr.find(["td", "th"])
        if not first:
            continue
        label = first.get_text(" ", strip=True).lower()
        if "тип ошибки" in label:
            tds = tr.find_all("td")
            if len(tds) >= 2:
                links = []
                for a in tds[1].select("a[href]"):
                    href = a["href"].strip()
                    if href:
                        links.append(href)
                text = " ".join(s.strip() for s in tds[1].stripped_strings)
                if links:
                    text = f"{text} ({', '.join(links)})"
                error_type = text.strip()
            break



    crit_text = None
    for tr in soup.select("tr"):
        first = tr.find(["td", "th"])
        if first and "уровень опасности" in first.get_text(" ", strip=True).lower():
            tds = tr.find_all("td")
            if len(tds) >= 2:
                crit_text = tds[1].get_text(" ", strip=True)
            break

    def get_row(label_sub: str) -> Optional[str]:
        return _get_row(soup, label_sub)

    status = get_row("статус уязвимости")
    exploit = get_row("наличие эксплойта")
    elimination = get_row("способ устранения")
    infou = get_row("информация об устранении")

    exploitation_mode = None
    for tr in soup.select("tr"):
        first = tr.find(["td", "th"])
        if first and "способ эксплуатации" in first.get_text(" ", strip=True).lower():
            tds = tr.find_all("td")
            if len(tds) >= 2:
                lis = tds[1].select("li")
                exploitation_mode = "; ".join(li.get_text(" ", strip=True) for li in lis)
            break

    links = []
    for tr in soup.select("tr"):
        first = tr.find(["td", "th"])
        if first and "ссылки на источники" in first.get_text(" ", strip=True).lower():
            tds = tr.find_all("td")
            if len(tds) >= 2:
                for a in tds[1].select("a[href]"):
                    href = a["href"].strip()
                    if href.startswith("http"):
                        links.append(href)
            break

    idvals = []
    for tr in soup.select("tr"):
        first = tr.find(["td", "th"])
        if first and "идентификаторы других систем" in first.get_text(" ", strip=True).lower():
            tds = tr.find_all("td")
            if len(tds) >= 2:
                for li in tds[1].select("li"):
                    v = li.get_text(" ", strip=True)
                    if v:
                        idvals.append(v)
            break

    real_attack = get_row("эксплуатация в реальных атаках")

    consequences = None
    for tr in soup.select("tr"):
        first = tr.find(["td", "th"])
        if first and "последствия эксплуатации" in first.get_text(" ", strip=True).lower():
            tds = tr.find_all("td")
            if len(tds) >= 2:
                lis = tds[1].select("li")
                consequences = "; ".join(li.get_text(" ", strip=True) for li in lis)
            break

    pub_date = None
    val = get_row("дата публикации")
    if val:
        pub_date = _extract_date(val)

    upd_date = None
    val2 = get_row("дата последнего обновления")
    if val2:
        upd_date = _extract_date(val2)

    m_cve = CVE_RE.search(html)
    cve = m_cve.group(0).upper() if m_cve else None
    if not cve:
        for it in idvals:
            m2 = CVE_RE.search(it)
            if m2:
                cve = m2.group(0).upper()
                break

    return {
        "bdu_id": bdu_id,
        "title": title,
        "discovered_date": discovered_date,
        "severity": severity,
        "base_vector": base_vector,
        "crit_text": crit_text,
        "cve": cve,
        "status": status,
        "recommendations": get_row("возможные меры по устранению"),
        "exploit_exists": exploit,
        "exploitation_mode": exploitation_mode,
        "elimination": elimination,
        "infou": infou,
        "links": links,
        "idvals": idvals,
        "real_attack": real_attack,
        "consequences": consequences,
        "publication_date": pub_date,
        "update_date": upd_date,
        "error_type": error_type,
        "other_info": None,
    }


def store_bulk(conn, rows: List[Dict]):
    if not rows:
        return

    cols = [
        "bdu_id", "title", "discovered_date", "severity", "base_vector",
        "crit_text", "cve", "status", "recommendations", "exploit_exists",
        "exploitation_mode", "elimination", "infou", "links", "idvals",
        "real_attack", "consequences", "publication_date", "update_date",
        "other_info", "updated_at", "error_type"
    ]

    values = []
    for r in rows:
        # Безопасная сериализация JSON полей
        links_val = r.get("links")
        if not isinstance(links_val, (list, dict)):
            links_val = [links_val] if links_val else []
        links_json = json.dumps(links_val, ensure_ascii=False)

        idvals_val = r.get("idvals")
        if not isinstance(idvals_val, (list, dict)):
            idvals_val = [idvals_val] if idvals_val else []
        idvals_json = json.dumps(idvals_val, ensure_ascii=False)

        values.append([
            r.get("bdu_id"),
            r.get("title"),
            r.get("discovered_date"),
            r.get("severity"),
            r.get("base_vector"),
            r.get("crit_text"),
            r.get("cve"),
            r.get("status"),
            r.get("recommendations"),
            r.get("exploit_exists"),
            r.get("exploitation_mode"),
            r.get("elimination"),
            r.get("infou"),
            links_json,
            idvals_json,
            r.get("real_attack"),
            r.get("consequences"),
            r.get("publication_date"),
            r.get("update_date"),
            r.get("other_info"),
            datetime.utcnow(),
            r.get("error_type"),
        ])

    insert_cols = ",".join(cols)
    set_clause = ", ".join(f"{c}=EXCLUDED.{c}" for c in cols if c not in ("bdu_id", "created_at"))

    stmt = f"""
    INSERT INTO bdu_vulns ({insert_cols})
    VALUES %s
    ON CONFLICT (bdu_id) DO UPDATE
      SET {set_clause};
    """

    with conn.cursor() as cur:
        execute_values(cur, stmt, values, page_size=100)
    conn.commit()
