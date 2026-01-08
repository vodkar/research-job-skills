#!/usr/bin/env python3
"""
AppSec skill miner (RU market): HeadHunter + SuperJob (+ optional Trudvsem open data).

- Searches vacancies by keywords
- Pulls full vacancy details
- Extracts skills from structured fields (HH key_skills) and from text via pattern map
- Outputs:
    - jobs.jsonl (normalized vacancies)
    - skills_top.csv (top skills by frequency)

Notes:
- Respect each provider's ToS and rate limits.
- SuperJob: pass X-Api-App-Id header (API key). See official docs. https://api.superjob.ru/  [oai_citation:7‡SuperJob.ru](https://api.superjob.ru/)
- HeadHunter: official API portal: https://api.hh.ru/  [oai_citation:8‡api.hh.ru](https://api.hh.ru/?utm_source=chatgpt.com)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests
from requests import Response
from requests.exceptions import HTTPError


# ---------------------------
# Helpers
# ---------------------------

class _HTMLStripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._chunks: List[str] = []

    def handle_data(self, data: str) -> None:
        if data:
            self._chunks.append(data)

    def get_text(self) -> str:
        return " ".join(" ".join(self._chunks).split())


def strip_html(html: str) -> str:
    s = _HTMLStripper()
    s.feed(html or "")
    return s.get_text()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso_dt(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        # HH: "2025-12-01T12:34:56+0300" or "+03:00" variants may appear
        # Try a couple of formats.
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
        # Fallback: fromisoformat handles "+03:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def backoff_sleep(attempt: int) -> None:
    # simple exponential backoff with cap
    time.sleep(min(2 ** attempt, 20))


def http_get_json(
    session: requests.Session,
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 25,
    max_retries: int = 6,
) -> Dict[str, Any]:
    for attempt in range(max_retries):
        r = session.get(url, params=params, headers=headers, timeout=timeout)
        if r.status_code == 429 or 500 <= r.status_code < 600:
            backoff_sleep(attempt)
            continue
        try:
            r.raise_for_status()
        except HTTPError as e:
            raise RuntimeError(_format_http_error(url=url, response=r)) from e
        return r.json()
    raise RuntimeError(f"Failed after retries: GET {url}")


def _format_http_error(*, url: str, response: Response) -> str:
    content_type = (response.headers.get("content-type") or "").lower()
    request_id = response.headers.get("x-request-id")
    snippet = ""
    if "application/json" in content_type:
        try:
            body = response.json()
            snippet = json.dumps(body, ensure_ascii=False)[:1200]
        except Exception:
            snippet = response.text[:1200]
    else:
        snippet = response.text[:1200]

    rid = f" request_id={request_id}" if request_id else ""
    return (
        f"HTTP {response.status_code} for {url}{rid}. "
        f"Response (first 1200 chars): {snippet}"
    )


# ---------------------------
# Skill extraction
# ---------------------------

# Canonical skill -> regex patterns (case-insensitive).
# Extend this list as needed; for best quality, iterate on real collected data.
SKILL_PATTERNS: Dict[str, List[str]] = {
    "OWASP": [r"\bowasp\b", r"owasp\s+top\s*10"],
    "OWASP ASVS": [r"\bowasp\s+asvs\b", r"\basvs\b", r"application\s+security\s+verification\s+standard"],
    "OWASP WSTG": [r"\bowasp\s+wstg\b", r"\bwstg\b", r"web\s+security\s+testing\s+guide"],
    "OWASP MASVS": [r"\bowasp\s+masvs\b", r"\bmasvs\b", r"mobile\s+application\s+security\s+verification\s+standard"],
    "CWE": [r"\bcwe\b", r"common\s+weakness\s+enumeration", r"\bcwe-\d+\b"],
    "CVE": [r"\bcve\b", r"\bcve-\d{4}-\d{4,7}\b"],
    "CVSS": [r"\bcvss\b", r"cvss\s*v?\d(\.\d)?", r"cvss\s*base\s*score"],
    "Threat modeling": [r"threat\s*model", r"модел(ирование|ь)\s*угроз"],
    "Secure SDLC": [r"secure\s*sdlc", r"ssd?lc", r"безопасн(ая|ое)\s*(разработк|жизненн)"],
    "DevSecOps": [r"\bdevsecops\b", r"dev\s*sec\s*ops"],
    "SAST": [r"\bsast\b", r"static\s+app", r"статическ(ий|ое)\s+анализ"],
    "DAST": [r"\bdast\b", r"dynamic\s+app", r"динамическ(ий|ое)\s+анализ"],
    "SCA": [r"\bsca\b", r"software\s+composition", r"dependency\s+scan", r"анализ\s+зависимост"],
    "Pentest": [r"\bpen\s*test\b", r"penetration\s+test", r"пентест", r"тестирован(ие|ия)\s+на\s+проникнов"],
    "Web security": [r"web\s+security", r"безопасност[ьи]\s+веб", r"\bweb\b.*\bsecurity\b"],
    # Avoid counting plain URLs like "https://example.com" as a skill mention.
    "HTTP(S)": [
        r"\bhttps?\b(?!\s*://)",
        r"\bhttp\s*/\s*\d(?:\.\d)?\b",
        r"hypertext\s+transfer\s+protocol",
    ],
    "Cookies": [r"\bcookies?\b", r"\bcookie\b", r"кук(и|и?с)"],
    "Sessions": [r"\bsessions?\b", r"\bsession\b", r"сесси(я|и|й)"],
    "CORS": [r"\bcors\b", r"cross[-\s]?origin\s+resource\s+sharing", r"межсайтов(ый|ое)\s+доступ"],
    "HTML": [r"\bhtml\b", r"hypertext\s+markup\s+language"],
    "JavaScript": [r"\bjavascript\b", r"\bjs\b", r"ecmascript"],
    "SQL": [r"\bsql\b", r"sql\s+injection", r"инъекц(ия|ии)\s+sql"],
    "API security": [r"api\s+security", r"безопасност[ьи]\s+api"],
    "OAuth2/OIDC": [r"\boauth\s*2\b", r"\boidc\b", r"openid\s+connect"],
    "SAML": [r"\bsaml\b", r"security\s+assertion\s+markup\s+language"],
    "JWT": [r"\bjwt\b", r"json\s+web\s+token"],
    "LDAP": [r"\bldap\b"],
    "SSO": [r"\bsso\b", r"single\s+sign[-\s]?on"],
    "MFA": [r"\bmfa\b", r"multi[-\s]?factor"],
    "RBAC": [r"\brbac\b", r"role[-\s]?based\s+access\s+control"],
    "IAM": [r"\biam\b", r"identity\s+and\s+access\s+management"],
    "PAM": [r"\bpam\b", r"privileged\s+access\s+management"],
    "EDR": [r"\bedr\b", r"endpoint\s+detection\s+and\s+response"],
    "SOC": [r"\bsoc\b", r"security\s+operations\s+center"],
    "TLS/PKI": [r"\btls\b", r"\bssl\b", r"\bpki\b", r"сертификат", r"x\.?509"],
    "Burp Suite": [r"burp(\s*suite)?"],
    "OWASP ZAP": [r"owasp\s+zap", r"\bzaproxy\b", r"\bzap\s*proxy\b", r"(?-i:\bZAP\b)"],
    "Nmap": [r"\bnmap\b"],
    "Semgrep": [r"\bsemgrep\b"],
    "CodeQL": [r"\bcodeql\b"],
    "SonarQube": [r"sonarqube", r"\bsonar\b"],
    "CI/CD": [r"\bci/?cd\b", r"gitlab\s*ci", r"github\s*actions", r"jenkins"],
    "Git": [r"\bgit\b", r"\bgitflow\b", r"pull\s+request", r"merge\s+request"],
    "Agile": [r"\bagile\b", r"\bscrum\b", r"\bkanban\b"],
    "Kubernetes": [r"\bkubernetes\b", r"\bk8s\b"],
    "Cloud security": [r"\baws\b", r"\bazure\b", r"\bgcp\b", r"облачн(ая|ые)\s+безопасн"],
    "WAF": [r"\bwaf\b", r"web\s+application\s+firewall"],
    "Logging/SIEM": [r"\bsiem\b", r"splunk", r"elk", r"opensearch"],
    "Bug bounty": [r"\bbug\s*bounty\b", r"\bbugbounty\b"],
    "Mobile security": [r"\bmobile\s+security\b", r"\bmobsf\b", r"\bfrida\b", r"\bowasp\s+masvs\b", r"\bmasvs\b"],
    "Python": [r"\bpython\b", r"python\s*3"],
    "Java": [r"\bjava\b", r"\bjvm\b"],
    "C#": [r"\bc\s*#\b", r"\bc#\b", r"\bcsharp\b", r"c[-\s]?sharp"],
    "RSA": [r"\brsa\b"],
    "Diffie-Hellman": [
        r"diffie[-\s]?hellman",
        r"\bdh\b\s*(?:key\s*(?:exchange|agreement)|handshake)\b",
    ],
    "bcrypt": [r"\bbcrypt\b"],
    "Argon2": [r"\bargon2\b"],
    "Password storage": [r"password\s+storage", r"password\s+hash", r"хеш(ирование|ирование)\s+парол", r"хранени(е|я)\s+парол"],
}

_COMPILED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (skill, re.compile(pat, flags=re.IGNORECASE | re.MULTILINE))
    for skill, pats in SKILL_PATTERNS.items()
    for pat in pats
]


def extract_skills(*, key_skills: Iterable[str], text: str) -> Set[str]:
    out: Set[str] = set(s.strip() for s in key_skills if s and s.strip())
    t = text or ""
    for skill, cre in _COMPILED_PATTERNS:
        if cre.search(t):
            out.add(skill)
    return out


# ---------------------------
# Normalized vacancy model
# ---------------------------

@dataclass
class Vacancy:
    source: str
    vacancy_id: str
    title: str
    company: str
    city: str
    published_at: Optional[str]
    url: str
    key_skills: List[str]
    text: str

    def to_json(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "vacancy_id": self.vacancy_id,
            "title": self.title,
            "company": self.company,
            "city": self.city,
            "published_at": self.published_at,
            "url": self.url,
            "key_skills": self.key_skills,
            "text": self.text,
        }


# ---------------------------
# Sources
# ---------------------------

class HeadHunterSource:
    """
    HeadHunter vacancies:
      - Search: GET https://api.hh.ru/vacancies?text=...&area=113&page=...&per_page=...
      - Detail: GET https://api.hh.ru/vacancies/{id}

    Official API entry point: https://api.hh.ru/  [oai_citation:9‡api.hh.ru](https://api.hh.ru/?utm_source=chatgpt.com)
    """

    BASE = "https://api.hh.ru"

    def __init__(self, session: requests.Session, user_agent: str) -> None:
        self.s = session
        self.ua = user_agent.strip()

    def _headers(self) -> Dict[str, str]:
        if not self.ua:
            return {}
        return {"User-Agent": self.ua}

    def search_ids(self, query: str, area: str, page: int, per_page: int) -> Tuple[List[str], bool]:
        data = http_get_json(
            self.s,
            f"{self.BASE}/vacancies",
            params={"text": query, "area": area, "page": page, "per_page": per_page},
            headers=self._headers(),
        )
        items = data.get("items") or []
        ids = [str(it.get("id")) for it in items if it.get("id") is not None]
        pages = data.get("pages")
        has_more = (pages is None) or (page + 1 < int(pages))
        return ids, has_more

    def fetch(self, vacancy_id: str) -> Vacancy:
        v = http_get_json(
            self.s,
            f"{self.BASE}/vacancies/{vacancy_id}",
            headers=self._headers(),
        )
        key_skills = [ks.get("name", "") for ks in (v.get("key_skills") or []) if isinstance(ks, dict)]
        description = strip_html(v.get("description") or "")
        employer = (v.get("employer") or {}).get("name") or ""
        area = (v.get("area") or {}).get("name") or ""
        return Vacancy(
            source="hh",
            vacancy_id=str(v.get("id") or vacancy_id),
            title=str(v.get("name") or ""),
            company=str(employer),
            city=str(area),
            published_at=str(v.get("published_at") or ""),
            url=str(v.get("alternate_url") or ""),
            key_skills=[s for s in key_skills if s],
            text=description,
        )


class SuperJobSource:
    """
    SuperJob vacancies:
      - Search: GET https://api.superjob.ru/2.0/vacancies/?keyword=...&page=...&count=...
    Docs: https://api.superjob.ru/  [oai_citation:10‡SuperJob.ru](https://api.superjob.ru/)
    """

    BASE = "https://api.superjob.ru/2.0"

    def __init__(self, session: requests.Session, api_key: str) -> None:
        self.s = session
        self.api_key = api_key

    def search_ids(self, query: str, page: int, per_page: int) -> Tuple[List[str], bool]:
        data = http_get_json(
            self.s,
            f"{self.BASE}/vacancies/",
            params={"keyword": query, "page": page, "count": per_page},
            headers={"X-Api-App-Id": self.api_key},
        )
        objs = data.get("objects") or []
        ids = [str(o.get("id")) for o in objs if o.get("id") is not None]
        has_more = bool(data.get("more"))
        return ids, has_more

    def fetch(self, vacancy_id: str) -> Vacancy:
        # SuperJob provides detail as /vacancies/{id}/ in docs; also often the search objects are already rich.
        v = http_get_json(
            self.s,
            f"{self.BASE}/vacancies/{vacancy_id}/",
            headers={"X-Api-App-Id": self.api_key},
        )
        title = str(v.get("profession") or "")
        company = str((v.get("client") or {}).get("title") or "")
        city = str((v.get("town") or {}).get("title") or "")
        # date_published is usually a Unix timestamp
        dp = v.get("date_published")
        published_at = ""
        if isinstance(dp, (int, float)):
            published_at = datetime.fromtimestamp(dp, tz=timezone.utc).isoformat()
        text = strip_html(v.get("candidat") or "") + "\n" + strip_html(v.get("work") or "")
        url = str(v.get("link") or "")
        return Vacancy(
            source="superjob",
            vacancy_id=str(v.get("id") or vacancy_id),
            title=title,
            company=company,
            city=city,
            published_at=published_at,
            url=url,
            key_skills=[],
            text=text.strip(),
        )


class TrudVsemSource:
    """
    "Работа России" open data API.
    Official page mentions API for open data.  [oai_citation:11‡trudvsem.ru](https://trudvsem.ru/opendata/api?utm_source=chatgpt.com)
    In practice, commonly used base:
        http://opendata.trudvsem.ru/api/v1/vacancies/region/{region}?text=...
    (Example in public Postman collection.)  [oai_citation:12‡Postman](https://www.postman.com/kapa2019/trudvsem/collection/2fuxolk/restful-api-basics-blueprint?utm_source=chatgpt.com)

    Note: API shape can differ; treat this connector as "best effort".
    """

    BASE = "http://opendata.trudvsem.ru/api/v1"

    def __init__(self, session: requests.Session, region_codes: List[str]) -> None:
        self.s = session
        self.region_codes = region_codes

    def search_ids(self, query: str, region: str, page: int, per_page: int) -> Tuple[List[str], bool]:
        # Many examples do not support paging consistently; we implement naive page slicing if list is big.
        data = http_get_json(
            self.s,
            f"{self.BASE}/vacancies/region/{region}",
            params={"text": query},
        )
        # Expected: {"status":..., "results":{"vacancies":[{"vacancy":{...}}]}}
        vacs = (((data.get("results") or {}).get("vacancies")) or [])
        ids: List[str] = []
        for item in vacs:
            vac = item.get("vacancy") if isinstance(item, dict) else None
            if isinstance(vac, dict):
                vid = vac.get("id") or vac.get("vacancyId") or vac.get("vacancy_id")
                if vid is not None:
                    ids.append(str(vid))

        start = page * per_page
        end = start + per_page
        sliced = ids[start:end]
        has_more = end < len(ids)
        return sliced, has_more

    def fetch(self, vacancy_id: str) -> Vacancy:
        # Some deployments expose /vacancies/{id} but not always; so we leave details minimal.
        return Vacancy(
            source="trudvsem",
            vacancy_id=vacancy_id,
            title="",
            company="",
            city="",
            published_at="",
            url="",
            key_skills=[],
            text="",
        )


# ---------------------------
# Main pipeline
# ---------------------------

def within_days(published_at: str, days: int) -> bool:
    if not days or days <= 0:
        return True
    dt = parse_iso_dt(published_at)
    if not dt:
        return True  # keep if unknown
    cutoff = utc_now() - timedelta(days=days)
    # Normalize dt to UTC if it has tzinfo
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc) >= cutoff


def write_jsonl(path: str, rows: Iterable[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Mine AppSec skills from RU job boards via official APIs.")
    ap.add_argument("--out-dir", default="out", help="Output directory")
    ap.add_argument("--days", type=int, default=180, help="Keep vacancies published within N days (0 disables)")
    ap.add_argument("--max-pages", type=int, default=20, help="Max pages per query per source")
    ap.add_argument("--per-page", type=int, default=100, help="Items per page (where supported)")
    ap.add_argument("--area-hh", default="113", help="HH area code (113 is commonly used for Russia)")
    ap.add_argument(
        "--query",
        action="append",
        required=True,
        help="Search query (repeatable). Example: --query appsec --query 'безопасность приложений'",
    )
    ap.add_argument(
        "--source",
        action="append",
        choices=["hh", "superjob", "trudvsem"],
        default=["hh"],
        help="Data sources (repeatable). Default: hh",
    )
    ap.add_argument(
        "--hh-user-agent",
        default="",
        help=(
            "HH User-Agent header (optional). If you set this, use a non-blacklisted value; "
            "some placeholders are rejected by HH as 'bad_user_agent'."
        ),
    )
    ap.add_argument(
        "--trudvsem-region",
        action="append",
        default=[],
        help="Trudvsem region code (repeatable). Example seen in public collections: 9100000000",
    )
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    session = requests.Session()
    session.headers.update({"Accept": "application/json"})

    hh = HeadHunterSource(session, user_agent=args.hh_user_agent)
    sj_key = os.environ.get("SUPERJOB_API_KEY", "").strip()
    sj = SuperJobSource(session, api_key=sj_key) if sj_key else None
    tv = TrudVsemSource(session, region_codes=args.trudvsem_region) if args.trudvsem_region else None

    selected_sources = set(args.source)

    # Guardrails
    if "superjob" in selected_sources and not sj_key:
        print("ERROR: SUPERJOB_API_KEY env var is required for SuperJob source.", file=sys.stderr)
        return 2
    if "trudvsem" in selected_sources and not args.trudvsem_region:
        print("ERROR: Provide at least one --trudvsem-region to use trudvsem source.", file=sys.stderr)
        return 2

    seen: Set[Tuple[str, str]] = set()
    vacancies: List[Vacancy] = []

    for q in args.query:
        q = q.strip()
        if not q:
            continue

        # HH
        if "hh" in selected_sources:
            for page in range(args.max_pages):
                ids, has_more = hh.search_ids(q, area=args.area_hh, page=page, per_page=args.per_page)
                if not ids:
                    break
                for vid in ids:
                    key = ("hh", vid)
                    if key in seen:
                        continue
                    try:
                        v = hh.fetch(vid)
                    except Exception:
                        continue
                    if args.days and not within_days(v.published_at or "", args.days):
                        continue
                    vacancies.append(v)
                    seen.add(key)
                if not has_more:
                    break
                time.sleep(0.2)  # be polite

        # SuperJob
        if "superjob" in selected_sources and sj is not None:
            for page in range(args.max_pages):
                ids, has_more = sj.search_ids(q, page=page, per_page=args.per_page)
                if not ids:
                    break
                for vid in ids:
                    key = ("superjob", vid)
                    if key in seen:
                        continue
                    try:
                        v = sj.fetch(vid)
                    except Exception:
                        continue
                    if args.days and not within_days(v.published_at or "", args.days):
                        continue
                    vacancies.append(v)
                    seen.add(key)
                if not has_more:
                    break
                time.sleep(0.25)

        # Trudvsem
        if "trudvsem" in selected_sources and tv is not None:
            remember = list(args.trudvsem_region)
            for region in remember:
                for page in range(args.max_pages):
                    ids, has_more = tv.search_ids(q, region=region, page=page, per_page=args.per_page)
                    if not ids:
                        break
                    for vid in ids:
                        key = ("trudvsem", vid)
                        if key in seen:
                            continue
                        # Connector is minimal; keep placeholder record
                        vacancies.append(tv.fetch(vid))
                        seen.add(key)
                    if not has_more:
                        break
                    time.sleep(0.2)

    # Write normalized vacancies
    jobs_path = os.path.join(args.out_dir, "jobs.jsonl")
    write_jsonl(jobs_path, (v.to_json() for v in vacancies))

    # Skill aggregation
    counter: Counter[str] = Counter()
    for v in vacancies:
        skills = extract_skills(key_skills=v.key_skills, text=v.text)
        for s in skills:
            counter[s] += 1

    skills_path = os.path.join(args.out_dir, "skills_top.csv")
    with open(skills_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["skill", "count"])
        for skill, cnt in counter.most_common(200):
            w.writerow([skill, cnt])

    print(f"Collected vacancies: {len(vacancies)}")
    print(f"Wrote: {jobs_path}")
    print(f"Wrote: {skills_path}")
    print("\nTop 20 skills:")
    for skill, cnt in counter.most_common(20):
        print(f"  {cnt:4d}  {skill}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())