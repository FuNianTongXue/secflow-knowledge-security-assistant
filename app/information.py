from __future__ import annotations

import hashlib
import html
import mimetypes
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from threading import RLock
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree

import httpx

from app.storage import DATA_DIR, now_iso, store


@dataclass(frozen=True)
class InformationSourceDefinition:
    id: str
    name: str
    kind: str
    url: str
    default_category: str
    website: str
    region: str
    source_image_url: str
    image_hosts: tuple[str, ...] = ()
    filter_security: bool = False


INFORMATION_SOURCES = (
    InformationSourceDefinition(
        id="cisa_advisories",
        name="CISA 官方安全公告",
        kind="rss",
        url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
        default_category="漏洞披露",
        website="https://www.cisa.gov/news-events/cybersecurity-advisories",
        region="国际",
        source_image_url="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/favicon.png",
    ),
    InformationSourceDefinition(
        id="cisa_kev",
        name="CISA 已知在野利用目录",
        kind="kev",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        default_category="漏洞披露",
        website="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        region="国际",
        source_image_url="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/favicon.png",
    ),
    InformationSourceDefinition(
        id="freebuf",
        name="FreeBuf",
        kind="rss",
        url="https://www.freebuf.com/feed",
        default_category="行业动态",
        website="https://www.freebuf.com/",
        region="国内",
        source_image_url="https://www.freebuf.com/images/logo_b.png",
        image_hosts=("image.3001.net",),
    ),
    InformationSourceDefinition(
        id="aliyun_xz",
        name="阿里云先知社区",
        kind="rss",
        url="https://xz.aliyun.com/feed",
        default_category="攻击技术",
        website="https://xz.aliyun.com/",
        region="国内",
        source_image_url="https://xz.aliyun.com/favicon.ico",
        image_hosts=("alicdn.com",),
    ),
    InformationSourceDefinition(
        id="tencent_security",
        name="腾讯安全应急响应中心",
        kind="rss",
        url="https://security.tencent.com/index.php/feed/blog/0",
        default_category="行业动态",
        website="https://security.tencent.com/",
        region="国内",
        source_image_url="https://security.tencent.com/static/v2.0/images/favicon.ico",
        image_hosts=("qpic.cn",),
    ),
    InformationSourceDefinition(
        id="tencent_xlab",
        name="腾讯玄武实验室",
        kind="rss",
        url="https://xlab.tencent.com/cn/feed/",
        default_category="攻击技术",
        website="https://xlab.tencent.com/cn/",
        region="国内",
        source_image_url="https://xlab.tencent.com/cn/favicon.png?v=1.1",
        image_hosts=("qpic.cn",),
    ),
    InformationSourceDefinition(
        id="microsoft_security",
        name="Microsoft Security Blog",
        kind="rss",
        url="https://www.microsoft.com/en-us/security/blog/feed/",
        default_category="行业动态",
        website="https://www.microsoft.com/en-us/security/blog/",
        region="国际",
        source_image_url="https://www.microsoft.com/favicon.ico",
        image_hosts=("microsoft.com",),
    ),
    InformationSourceDefinition(
        id="talos",
        name="Cisco Talos Intelligence",
        kind="rss",
        url="https://blog.talosintelligence.com/rss/",
        default_category="攻击技术",
        website="https://blog.talosintelligence.com/",
        region="国际",
        source_image_url="https://blog.talosintelligence.com/favicon.ico",
        image_hosts=("storage.ghost.io",),
    ),
    InformationSourceDefinition(
        id="portswigger_research",
        name="PortSwigger Research",
        kind="rss",
        url="https://portswigger.net/research/rss",
        default_category="攻击技术",
        website="https://portswigger.net/research",
        region="国际",
        source_image_url="https://portswigger.net/content/images/logos/apple-touch-icon.png",
    ),
    InformationSourceDefinition(
        id="sans_isc",
        name="SANS Internet Storm Center",
        kind="rss",
        url="https://isc.sans.edu/rssfeed.xml",
        default_category="攻击技术",
        website="https://isc.sans.edu/",
        region="国际",
        source_image_url="https://isc.sans.edu/favicon-32x32.png",
    ),
)

CATEGORY_ORDER = (
    "全部",
    "AI 安全",
    "大模型",
    "漏洞披露",
    "数据安全",
    "政策法规",
    "云安全",
    "供应链安全",
    "行业动态",
    "攻击技术",
)

SECURITY_TERMS = (
    "security",
    "cyber",
    "vulnerability",
    "exploit",
    "malware",
    "ransomware",
    "privacy",
    "breach",
    "phishing",
    "threat",
    "attack",
    "cve-",
    "安全",
    "漏洞",
    "攻击",
)

INFORMATION_IMAGE_CACHE_DIR = DATA_DIR / "information-images"
_information_image_cache_lock = RLock()


@dataclass(frozen=True)
class InformationImageResult:
    data: bytes
    content_type: str
    kind: str
    etag: str


class InformationService:
    def __init__(
        self,
        state_store=store,
        fetcher: Callable[[InformationSourceDefinition], list[dict[str, Any]]] | None = None,
        image_enricher: Callable[[list[dict[str, Any]], list[InformationSourceDefinition]], None] | None = None,
    ) -> None:
        self._store = state_store
        self._fetcher = fetcher or fetch_information_source
        self._image_enricher = image_enricher if image_enricher is not None else (
            enrich_information_images if fetcher is None else None
        )
        self._lock = RLock()

    def snapshot(
        self,
        *,
        query: str = "",
        category: str = "全部",
        sort: str = "latest",
        limit: int = 80,
        refresh: bool = False,
    ) -> dict[str, Any]:
        state = self._store.read()
        info = _information_state(state)
        should_refresh = refresh or not info["items"] or _cache_is_stale(str(info.get("updated_at") or ""))
        if should_refresh:
            try:
                return self.refresh(query=query, category=category, sort=sort, limit=limit)
            except Exception as exc:  # noqa: BLE001 - stale cache remains usable.
                info["message"] = f"在线刷新失败，已展示本地缓存：{exc}"
        return _build_snapshot(info, query=query, category=category, sort=sort, limit=limit)

    def refresh(
        self,
        *,
        query: str = "",
        category: str = "全部",
        sort: str = "latest",
        limit: int = 80,
    ) -> dict[str, Any]:
        with self._lock:
            state = self._store.read()
            info = _information_state(state)
            sources = _source_statuses(info)
            enabled = [source for source in INFORMATION_SOURCES if sources[source.id]["enabled"]]
            previous = [item for item in info.get("items", []) if isinstance(item, dict)]
            if not enabled:
                info["message"] = "当前没有启用的资讯来源。"
                info["last_refresh"] = now_iso()
                self._store.write(state)
                return _build_snapshot(info, query=query, category=category, sort=sort, limit=limit)

            collected: list[dict[str, Any]] = []
            failures: list[str] = []
            fetched_at = now_iso()
            with ThreadPoolExecutor(max_workers=min(6, len(enabled)), thread_name_prefix="secflow-information") as pool:
                futures = {pool.submit(self._fetcher, source): source for source in enabled}
                for future in as_completed(futures):
                    source = futures[future]
                    status = sources[source.id]
                    try:
                        raw_items = future.result()
                        normalized = [
                            item
                            for raw in raw_items
                            if (item := _normalize_item(source, raw, fetched_at)) is not None
                        ]
                        collected.extend(normalized)
                        status.update(
                            status="ready",
                            item_count=len(normalized),
                            last_updated=fetched_at,
                            message=f"已获取 {len(normalized)} 条",
                        )
                    except Exception as exc:  # noqa: BLE001 - one source must not break the feed.
                        message = _compact_error(exc)
                        failures.append(f"{source.name}: {message}")
                        status.update(status="error", last_updated=fetched_at, message=message)

            if collected:
                _reuse_cached_images(collected, previous)
                if self._image_enricher is not None:
                    try:
                        self._image_enricher(collected, enabled)
                    except Exception:  # noqa: BLE001 - covers are optional; news must remain available.
                        pass
                info["items"] = _deduplicate_items(collected)[:400]
                info["updated_at"] = fetched_at
            elif not previous:
                info["items"] = []
            info["last_refresh"] = fetched_at
            info["sources"] = sources
            if failures and collected:
                info["message"] = f"已更新 {len(info['items'])} 条资讯，{len(failures)} 个来源暂时不可用。"
            elif failures:
                info["message"] = "所有在线来源暂时不可用，已保留本地缓存。"
            else:
                info["message"] = f"已从 {len(enabled)} 个公开来源更新 {len(info['items'])} 条资讯。"
            self._store.write(state)
            return _build_snapshot(info, query=query, category=category, sort=sort, limit=limit)

    def set_source_enabled(self, source_id: str, enabled: bool) -> dict[str, Any]:
        definitions = {source.id: source for source in INFORMATION_SOURCES}
        if source_id not in definitions:
            raise KeyError(source_id)
        with self._lock:
            state = self._store.read()
            info = _information_state(state)
            statuses = _source_statuses(info)
            statuses[source_id]["enabled"] = bool(enabled)
            statuses[source_id]["message"] = "已启用，刷新后接入最新资讯。" if enabled else "已暂停订阅。"
            info["sources"] = statuses
            self._store.write(state)
        return statuses[source_id]


def fetch_information_source(source: InformationSourceDefinition) -> list[dict[str, Any]]:
    headers = {
        "Accept": "application/json, application/atom+xml, application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.5",
        "User-Agent": "SecFlow-Information/1.0 (+local defensive security intelligence client)",
    }
    timeout = httpx.Timeout(float(os.getenv("SECFLOW_INFORMATION_TIMEOUT_SECONDS", "12")), connect=6.0)
    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers, trust_env=False) as client:
        response = client.get(source.url)
        response.raise_for_status()
        if len(response.content) > 4_000_000:
            raise ValueError("来源响应超过 4 MB 限制")
        if source.kind == "kev":
            return parse_kev(response.json())
        return parse_feed(response.content, security_only=source.filter_security)


def load_information_image(item_id: str) -> InformationImageResult:
    state = store.read()
    info = _information_state(state)
    item = next(
        (
            value
            for value in info.get("items", [])
            if isinstance(value, dict) and str(value.get("id") or "") == item_id
        ),
        None,
    )
    if item is None:
        raise KeyError(item_id)
    source = next(
        (definition for definition in INFORMATION_SOURCES if definition.id == str(item.get("source_id") or "")),
        None,
    )
    if source is None:
        raise KeyError(item_id)

    candidates = (
        ("article", str(item.get("image_url") or "")),
        ("source", str(item.get("source_image_url") or source.source_image_url)),
    )
    for kind, image_url in candidates:
        if not image_url or not _image_url_allowed(image_url, source):
            continue
        cached = _read_cached_information_image(image_url, kind)
        if cached is not None:
            return cached
        try:
            return _download_information_image(image_url, kind, source)
        except Exception:  # noqa: BLE001 - an article cover may fall back to its publisher mark.
            continue
    raise ValueError("资讯图片暂时不可用")


def _download_information_image(
    image_url: str,
    kind: str,
    source: InformationSourceDefinition,
) -> InformationImageResult:
    timeout = httpx.Timeout(15.0, connect=6.0)
    headers = {
        "Accept": "image/avif,image/webp,image/png,image/jpeg,image/*;q=0.8",
        "User-Agent": "Mozilla/5.0 (Macintosh; Apple Silicon Mac OS X) SecFlow-Information/1.0",
    }
    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers, trust_env=False) as client:
        with client.stream("GET", image_url) as response:
            response.raise_for_status()
            if not _image_url_allowed(str(response.url), source):
                raise ValueError("图片重定向到了未授权域名")
            content_type = str(response.headers.get("content-type") or "").split(";", 1)[0].strip().casefold()
            if not content_type.startswith("image/"):
                guessed = mimetypes.guess_type(urlsplit(str(response.url)).path)[0] or ""
                content_type = guessed.casefold()
            if not content_type.startswith("image/"):
                raise ValueError("远端响应不是图片")
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > 8_000_000:
                    raise ValueError("资讯图片超过 8 MB 限制")
                chunks.append(chunk)
    data = b"".join(chunks)
    if not data:
        raise ValueError("远端图片为空")
    return _write_cached_information_image(image_url, data, content_type, kind)


def _image_url_allowed(value: str, source: InformationSourceDefinition) -> bool:
    host = (urlsplit(value).hostname or "").casefold().rstrip(".")
    if not host:
        return False
    allowed_hosts = {
        (urlsplit(candidate).hostname or "").casefold().rstrip(".")
        for candidate in (source.url, source.website, source.source_image_url)
    }
    allowed_hosts.update(item.casefold().rstrip(".") for item in source.image_hosts)
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts if allowed)


def _image_cache_paths(image_url: str) -> tuple[Path, Path, str]:
    digest = hashlib.sha256(image_url.encode("utf-8")).hexdigest()
    return (
        INFORMATION_IMAGE_CACHE_DIR / f"{digest}.bin",
        INFORMATION_IMAGE_CACHE_DIR / f"{digest}.mime",
        digest,
    )


def _read_cached_information_image(image_url: str, kind: str) -> InformationImageResult | None:
    data_path, mime_path, digest = _image_cache_paths(image_url)
    try:
        data = data_path.read_bytes()
        content_type = mime_path.read_text(encoding="ascii").strip()
    except OSError:
        return None
    if not data or len(data) > 8_000_000 or not content_type.startswith("image/"):
        return None
    return InformationImageResult(data=data, content_type=content_type, kind=kind, etag=digest)


def _write_cached_information_image(
    image_url: str,
    data: bytes,
    content_type: str,
    kind: str,
) -> InformationImageResult:
    data_path, mime_path, digest = _image_cache_paths(image_url)
    with _information_image_cache_lock:
        INFORMATION_IMAGE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        data_tmp = data_path.with_name(f"{data_path.name}.tmp")
        mime_tmp = mime_path.with_name(f"{mime_path.name}.tmp")
        data_tmp.write_bytes(data)
        mime_tmp.write_text(content_type, encoding="ascii")
        os.replace(data_tmp, data_path)
        os.replace(mime_tmp, mime_path)
        _prune_information_image_cache()
    return InformationImageResult(data=data, content_type=content_type, kind=kind, etag=digest)


def _prune_information_image_cache() -> None:
    entries = sorted(
        INFORMATION_IMAGE_CACHE_DIR.glob("*.bin"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    retained_size = 0
    for index, path in enumerate(entries):
        try:
            retained_size += path.stat().st_size
            if index < 500 and retained_size <= 256 * 1_024 * 1_024:
                continue
            path.unlink(missing_ok=True)
            path.with_suffix(".mime").unlink(missing_ok=True)
        except OSError:
            continue


def parse_feed(payload: bytes | str, *, security_only: bool = False) -> list[dict[str, Any]]:
    root = ElementTree.fromstring(payload)
    entries = [node for node in root.iter() if _local_name(node.tag) in {"item", "entry"}]
    result: list[dict[str, Any]] = []
    for entry in entries[:60]:
        title = _child_text(entry, "title")
        link = _entry_link(entry)
        content = _first_text(entry, ("description", "summary", "content", "encoded"))
        categories = [str(node.text or "").strip() for node in entry if _local_name(node.tag) == "category"]
        searchable = " ".join([title, content, *categories]).casefold()
        if security_only and not any(term in searchable for term in SECURITY_TERMS):
            continue
        result.append(
            {
                "title": title,
                "url": link,
                "summary": _plain_text(content, 520),
                "published_at": _first_text(entry, ("pubDate", "published", "updated", "date")),
                "author": _entry_author(entry),
                "image_url": _entry_image(entry, content),
                "feed_categories": categories,
            }
        )
    return result


def parse_kev(payload: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else []
    if not isinstance(vulnerabilities, list):
        return []
    result: list[dict[str, Any]] = []
    for entry in sorted(vulnerabilities, key=lambda item: str(item.get("dateAdded") or ""), reverse=True)[:60]:
        cve_id = str(entry.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        vendor = str(entry.get("vendorProject") or "").strip()
        product = str(entry.get("product") or "").strip()
        title = str(entry.get("vulnerabilityName") or "").strip() or f"{cve_id} 已确认在野利用"
        action = str(entry.get("requiredAction") or "").strip()
        description = str(entry.get("shortDescription") or "").strip()
        result.append(
            {
                "title": f"{cve_id}: {title}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary": _plain_text(" ".join(part for part in [description, action] if part), 520),
                "published_at": str(entry.get("dateAdded") or ""),
                "author": "CISA KEV",
                "image_url": "",
                "feed_categories": ["Known Exploited Vulnerability", vendor, product],
                "tags": [cve_id, "在野利用", vendor, product],
                "breaking": True,
            }
        )
    return result


def _normalize_item(
    source: InformationSourceDefinition,
    raw: dict[str, Any],
    fetched_at: str,
) -> dict[str, Any] | None:
    title = _plain_text(str(raw.get("title") or ""), 260)
    url = _canonical_url(str(raw.get("url") or ""))
    if not title or not url.startswith(("http://", "https://")):
        return None
    summary = _plain_text(str(raw.get("summary") or ""), 520)
    category = _classify_category(title, summary, raw.get("feed_categories"), source.default_category)
    tags = _extract_tags(title, summary, raw.get("tags"), category)
    published_at = _normalize_datetime(str(raw.get("published_at") or ""), fetched_at)
    digest = hashlib.sha256(f"{source.id}|{url}|{title.casefold()}".encode("utf-8")).hexdigest()[:24]
    return {
        "id": f"news-{digest}",
        "source_id": source.id,
        "source_name": source.name,
        "source_kind": source.kind,
        "title": title,
        "summary": summary,
        "url": url,
        "image_url": _safe_remote_url(str(raw.get("image_url") or "")),
        "source_image_url": source.source_image_url,
        "image_checked_at": "",
        "published_at": published_at,
        "author": _plain_text(str(raw.get("author") or source.name), 100),
        "category": category,
        "tags": tags,
        "breaking": bool(raw.get("breaking")) or _is_breaking(title, summary),
    }


def _build_snapshot(
    info: dict[str, Any],
    *,
    query: str,
    category: str,
    sort: str,
    limit: int,
) -> dict[str, Any]:
    statuses = _source_statuses(info)
    enabled_ids = {source_id for source_id, status in statuses.items() if status.get("enabled")}
    source_by_id = {source.id: source for source in INFORMATION_SOURCES}
    all_items = [
        item for item in info.get("items", [])
        if isinstance(item, dict) and str(item.get("source_id") or "") in enabled_ids
    ]
    for item in all_items:
        source = source_by_id.get(str(item.get("source_id") or ""))
        item.setdefault("image_url", "")
        item.setdefault("source_image_url", source.source_image_url if source is not None else "")
    all_items.sort(key=lambda item: (str(item.get("published_at") or ""), str(item.get("id") or "")), reverse=True)
    counts = {name: 0 for name in CATEGORY_ORDER}
    counts["全部"] = len(all_items)
    for item in all_items:
        item_category = str(item.get("category") or "行业动态")
        counts[item_category] = counts.get(item_category, 0) + 1

    selected_category = category if category in CATEGORY_ORDER else "全部"
    filtered = all_items if selected_category == "全部" else [item for item in all_items if item.get("category") == selected_category]
    normalized_query = query.strip().casefold()
    if normalized_query:
        filtered = [
            item for item in filtered
            if normalized_query in " ".join(
                [
                    str(item.get("title") or ""),
                    str(item.get("summary") or ""),
                    str(item.get("source_name") or ""),
                    " ".join(str(tag) for tag in item.get("tags") or []),
                ]
            ).casefold()
        ]
    if sort == "source":
        filtered.sort(key=lambda item: (str(item.get("source_name") or ""), str(item.get("published_at") or "")), reverse=True)
    else:
        filtered.sort(key=lambda item: str(item.get("published_at") or ""), reverse=True)

    safe_limit = max(1, min(int(limit), 200))
    source_list = [statuses[source.id] for source in INFORMATION_SOURCES]
    return {
        "items": filtered[:safe_limit],
        "total": len(filtered),
        "available_total": len(all_items),
        "categories": [
            {"id": _category_id(name), "label": name, "count": counts.get(name, 0)}
            for name in CATEGORY_ORDER
            if name == "全部" or counts.get(name, 0) > 0
        ],
        "popular_tags": _popular_tags(all_items),
        "briefs": all_items[:6],
        "sources": source_list,
        "updated_at": str(info.get("updated_at") or ""),
        "last_refresh": str(info.get("last_refresh") or ""),
        "stale": _cache_is_stale(str(info.get("updated_at") or "")),
        "partial": any(source.get("enabled") and source.get("status") == "error" for source in source_list),
        "message": str(info.get("message") or "等待首次在线更新。"),
    }


def _information_state(state: dict[str, Any]) -> dict[str, Any]:
    info = state.setdefault("information", {})
    if not isinstance(info, dict):
        info = {}
        state["information"] = info
    info.setdefault("sources", {})
    info.setdefault("items", [])
    info.setdefault("updated_at", "")
    info.setdefault("last_refresh", "")
    info.setdefault("message", "等待首次在线更新。")
    _source_statuses(info)
    return info


def _source_statuses(info: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = info.setdefault("sources", {})
    if not isinstance(raw, dict):
        raw = {}
        info["sources"] = raw
    result: dict[str, dict[str, Any]] = {}
    for source in INFORMATION_SOURCES:
        existing = raw.get(source.id)
        status = existing if isinstance(existing, dict) else {}
        status.update(
            id=source.id,
            name=source.name,
            kind=source.kind,
            website=source.website,
            region=source.region,
            enabled=bool(status.get("enabled", True)),
            status=str(status.get("status") or "idle"),
            item_count=int(status.get("item_count") or 0),
            last_updated=str(status.get("last_updated") or ""),
            message=str(status.get("message") or "等待更新"),
        )
        raw[source.id] = status
        result[source.id] = status
    return result


def _deduplicate_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items.sort(key=lambda item: str(item.get("published_at") or ""), reverse=True)
    seen_urls: set[str] = set()
    seen_titles: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in items:
        url_key = str(item.get("url") or "").casefold()
        title_key = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", str(item.get("title") or "").casefold())
        if not url_key or url_key in seen_urls or (len(title_key) > 20 and title_key in seen_titles):
            continue
        seen_urls.add(url_key)
        seen_titles.add(title_key)
        result.append(item)
    return result


def _reuse_cached_images(items: list[dict[str, Any]], previous: list[dict[str, Any]]) -> None:
    cached = {
        (str(item.get("source_id") or ""), str(item.get("url") or "")): (
            str(item.get("image_url") or ""),
            str(item.get("image_checked_at") or ""),
        )
        for item in previous
        if item.get("image_url") or item.get("image_checked_at")
    }
    for item in items:
        cached_value = cached.get((str(item.get("source_id") or ""), str(item.get("url") or "")))
        if cached_value is None:
            continue
        image_url, checked_at = cached_value
        if image_url:
            item["image_url"] = image_url
        if checked_at:
            item["image_checked_at"] = checked_at


def enrich_information_images(
    items: list[dict[str, Any]],
    sources: list[InformationSourceDefinition],
) -> None:
    source_by_id = {source.id: source for source in sources}
    per_source_limit = max(0, min(int(os.getenv("SECFLOW_INFORMATION_IMAGE_LOOKUPS_PER_SOURCE", "12")), 30))
    if per_source_limit == 0:
        return

    missing_by_source: dict[str, list[dict[str, Any]]] = {}
    for item in sorted(items, key=lambda value: str(value.get("published_at") or ""), reverse=True):
        source_id = str(item.get("source_id") or "")
        source = source_by_id.get(source_id)
        if (
            source is None
            or source.kind != "rss"
            or item.get("image_url")
            or _image_lookup_is_recent(str(item.get("image_checked_at") or ""))
        ):
            continue
        bucket = missing_by_source.setdefault(source_id, [])
        if len(bucket) < per_source_limit and _article_url_allowed(str(item.get("url") or ""), source):
            bucket.append(item)

    candidates = [
        (item, source_by_id[source_id])
        for source_id, source_items in missing_by_source.items()
        for item in source_items
    ]
    if not candidates:
        return

    timeout = httpx.Timeout(
        float(os.getenv("SECFLOW_INFORMATION_IMAGE_TIMEOUT_SECONDS", "7")),
        connect=4.0,
    )
    headers = {
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
        "User-Agent": "Mozilla/5.0 (Macintosh; Apple Silicon Mac OS X) SecFlow-Information/1.0",
    }
    workers = min(8, len(candidates))
    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers, trust_env=False) as client:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="secflow-information-images") as pool:
            futures = {
                pool.submit(_fetch_article_image, client, item, source): item
                for item, source in candidates
            }
            for future in as_completed(futures):
                item = futures[future]
                try:
                    image_url = future.result()
                except Exception:  # noqa: BLE001 - one publisher page must not affect the feed.
                    image_url = ""
                item["image_checked_at"] = now_iso()
                if image_url:
                    item["image_url"] = image_url


def _image_lookup_is_recent(value: str) -> bool:
    if not value:
        return False
    try:
        checked_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if checked_at.tzinfo is None:
            checked_at = checked_at.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    ttl = max(900, int(os.getenv("SECFLOW_INFORMATION_IMAGE_RETRY_SECONDS", "21600")))
    return (datetime.now(timezone.utc) - checked_at.astimezone(timezone.utc)).total_seconds() < ttl


def _fetch_article_image(
    client: httpx.Client,
    item: dict[str, Any],
    source: InformationSourceDefinition,
) -> str:
    response = client.get(str(item.get("url") or ""))
    response.raise_for_status()
    if not _article_url_allowed(str(response.url), source):
        return ""
    content_type = str(response.headers.get("content-type") or "").casefold()
    if "html" not in content_type or len(response.content) > 2_500_000:
        return ""
    return parse_article_image(response.text, str(response.url))


def _article_url_allowed(value: str, source: InformationSourceDefinition) -> bool:
    host = (urlsplit(value).hostname or "").casefold().rstrip(".")
    if not host:
        return False
    allowed_hosts = {
        (urlsplit(candidate).hostname or "").casefold().rstrip(".")
        for candidate in (source.url, source.website)
    }
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts if allowed)


def parse_article_image(payload: str, base_url: str) -> str:
    parser = _ArticleImageParser(base_url)
    try:
        parser.feed(payload)
        if not parser.best_url:
            embedded_images = re.findall(r"<img\b[^>]{1,2000}>", payload, flags=re.IGNORECASE)
            if embedded_images:
                fragments = "".join(
                    html.unescape(fragment).replace(r'\"', '"').replace(r"\'", "'")
                    for fragment in embedded_images[:80]
                )
                parser.feed(f'<article class="article-body">{fragments}</article>')
    except Exception:  # noqa: BLE001 - malformed publisher HTML should only lose its cover.
        return ""
    return parser.best_url


class _ArticleImageParser(HTMLParser):
    _void_elements = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
    _content_markers = ("article", "artical", "post", "content-detail", "article-body", "markdown-body", "entry-content")
    _excluded_markers = ("avatar", "badge", "comment", "footer", "header", "icon", "logo", "nav", "qrcode", "qr-code", "sidebar")

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.stack: list[tuple[str, str]] = []
        self.candidates: list[tuple[int, int, str]] = []
        self._index = 0

    @property
    def best_url(self) -> str:
        if not self.candidates:
            return ""
        return max(self.candidates, key=lambda candidate: (candidate[0], -candidate[1]))[2]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        attributes = {str(key).casefold(): str(value or "") for key, value in attrs}
        marker = " ".join([attributes.get("id", ""), attributes.get("class", "")]).casefold()
        context = " ".join(value for _, value in [*self.stack, (tag, marker)] if value)

        if tag == "meta":
            key = " ".join(
                [attributes.get("property", ""), attributes.get("name", ""), attributes.get("itemprop", "")]
            ).casefold()
            if key.strip() in {"og:image", "og:image:url", "twitter:image", "twitter:image:src", "image"}:
                self._add_candidate(attributes.get("content", ""), 1_000)
        elif tag == "img":
            raw_url = _image_attribute_url(attributes)
            score = 0
            if any(parent_tag == "article" for parent_tag, _ in self.stack):
                score += 300
            if any(term in context for term in self._content_markers):
                score += 220
            width = _positive_int(attributes.get("width", ""))
            height = _positive_int(attributes.get("height", ""))
            if width >= 300 or height >= 180:
                score += 80
            if attributes.get("alt", "").strip():
                score += 10
            excluded_text = f"{context} {raw_url}".casefold()
            if any(term in excluded_text for term in self._excluded_markers):
                score -= 500
            if raw_url.casefold().split("?", 1)[0].endswith((".svg", ".gif")):
                score -= 300
            if score >= 100:
                self._add_candidate(raw_url, score)

        self.stack.append((tag, marker))
        if tag in self._void_elements:
            self.stack.pop()

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def _add_candidate(self, value: str, score: int) -> None:
        candidate = _safe_remote_url(urljoin(self.base_url, html.unescape(value).strip()))
        if not candidate:
            return
        self.candidates.append((score, self._index, candidate))
        self._index += 1


def _image_attribute_url(attributes: dict[str, str]) -> str:
    for name in ("src", "data-src", "data-original", "data-lazy-src"):
        if attributes.get(name, "").strip():
            return attributes[name].strip()
    srcset = attributes.get("srcset", "").strip()
    if not srcset:
        return ""
    final = srcset.split(",")[-1].strip()
    return final.split()[0] if final else ""


def _positive_int(value: str) -> int:
    match = re.match(r"\s*(\d+)", value)
    return int(match.group(1)) if match else 0


def _classify_category(title: str, summary: str, feed_categories: Any, fallback: str) -> str:
    categories = " ".join(str(item) for item in feed_categories or [])
    text = f"{title} {summary} {categories}".casefold()
    rules = (
        ("大模型", ("large language model", " llm", "gpt-", "chatgpt", "gemini", "claude", "prompt injection", "jailbreak", "大模型")),
        ("AI 安全", ("artificial intelligence", " ai ", "machine learning", "deepfake", "model security", "人工智能", "模型安全")),
        ("政策法规", ("regulation", "legislation", "compliance", "directive", "executive order", "gdpr", "policy", "法规", "合规", "政策")),
        ("数据安全", ("data breach", "data leak", "privacy", "personal data", "database exposure", "数据泄露", "隐私")),
        ("供应链安全", ("supply chain", "dependency confusion", "package repository", "npm", "pypi", "software bill of materials", "sbom", "供应链")),
        ("云安全", ("cloud security", "kubernetes", "container escape", "aws", "azure", "google cloud", "云安全", "容器逃逸")),
        ("攻击技术", ("ransomware", "phishing", "malware", "apt ", "botnet", "backdoor", "campaign", "threat actor", "攻击", "勒索", "钓鱼", "恶意软件")),
        ("漏洞披露", ("cve-", "vulnerability", "zero-day", "0-day", "exploit", "security advisory", "patch", "漏洞", "零日")),
    )
    for category, terms in rules:
        if any(term in text for term in terms):
            return category
    return fallback if fallback in CATEGORY_ORDER else "行业动态"


def _extract_tags(title: str, summary: str, provided: Any, category: str) -> list[str]:
    tags = [str(item).strip() for item in provided or [] if str(item).strip()]
    text = f"{title} {summary}".casefold()
    tag_rules = (
        ("AI 安全", ("artificial intelligence", " ai ", "machine learning", "ai safety")),
        ("LLM", (" llm", "large language model", "gpt-", "gemini", "claude")),
        ("CVE", ("cve-", "vulnerability")),
        ("零日漏洞", ("zero-day", "0-day", "zero day")),
        ("勒索软件", ("ransomware",)),
        ("数据泄露", ("data breach", "data leak")),
        ("云安全", ("cloud security", "kubernetes", "container")),
        ("供应链攻击", ("supply chain", "dependency confusion", "package repository")),
        ("隐私保护", ("privacy", "personal data", "gdpr")),
        ("APT", ("apt ", "advanced persistent threat", "threat actor")),
        ("钓鱼攻击", ("phishing",)),
    )
    for tag, terms in tag_rules:
        if any(term in text for term in terms):
            tags.append(tag)
    if category not in {"全部", "行业动态"}:
        tags.append(category)
    cve_matches = re.findall(r"CVE-\d{4}-\d{4,8}", f"{title} {summary}", flags=re.IGNORECASE)
    tags.extend(match.upper() for match in cve_matches[:2])
    return list(dict.fromkeys(tag for tag in tags if tag))[:8]


def _popular_tags(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for item in items:
        for tag in item.get("tags") or []:
            clean = str(tag).strip()
            if clean and not re.fullmatch(r"CVE-\d{4}-\d{4,8}", clean, flags=re.IGNORECASE):
                counts[clean] = counts.get(clean, 0) + 1
    return [
        {"name": name, "count": count}
        for name, count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))[:14]
    ]


def _cache_is_stale(updated_at: str) -> bool:
    if not updated_at:
        return True
    try:
        parsed = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    ttl = max(60, int(os.getenv("SECFLOW_INFORMATION_CACHE_SECONDS", "900")))
    return (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds() >= ttl


def _normalize_datetime(value: str, fallback: str) -> str:
    text = value.strip()
    if not text:
        return fallback
    parsed: datetime | None = None
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = datetime.strptime(text[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _entry_link(entry: ElementTree.Element) -> str:
    for node in entry:
        if _local_name(node.tag) != "link":
            continue
        href = str(node.attrib.get("href") or "").strip()
        rel = str(node.attrib.get("rel") or "alternate").strip()
        if href and rel in {"alternate", ""}:
            return href
        if str(node.text or "").strip():
            return str(node.text or "").strip()
    return _child_text(entry, "guid")


def _entry_author(entry: ElementTree.Element) -> str:
    author = next((node for node in entry if _local_name(node.tag) in {"author", "creator"}), None)
    if author is None:
        return ""
    name = next((node for node in author if _local_name(node.tag) == "name"), None)
    return str((name.text if name is not None else author.text) or "").strip()


def _entry_image(entry: ElementTree.Element, content: str) -> str:
    for node in entry.iter():
        local = _local_name(node.tag)
        url = str(node.attrib.get("url") or node.attrib.get("href") or "").strip()
        media_type = str(node.attrib.get("type") or "").lower()
        if url and (local == "thumbnail" or local == "content" or (local == "enclosure" and media_type.startswith("image/"))):
            if _safe_remote_url(url):
                return url
    match = re.search(r"<img[^>]+src=[\"']([^\"']+)", content, flags=re.IGNORECASE)
    return match.group(1) if match and _safe_remote_url(match.group(1)) else ""


def _first_text(entry: ElementTree.Element, names: tuple[str, ...]) -> str:
    for name in names:
        value = _child_text(entry, name)
        if value:
            return value
    return ""


def _child_text(entry: ElementTree.Element, name: str) -> str:
    for node in entry.iter():
        if node is not entry and _local_name(node.tag) == name:
            return "".join(node.itertext()).strip()
    return ""


def _local_name(tag: Any) -> str:
    return str(tag).rsplit("}", 1)[-1].split(":")[-1]


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())


def _plain_text(value: str, limit: int) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(html.unescape(value))
        text = " ".join(parser.parts)
    except Exception:  # noqa: BLE001 - malformed publisher HTML falls back to stripping.
        text = re.sub(r"<[^>]+>", " ", value)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s+([,.;:!?，。；：！？])", r"\1", text)
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 1)].rstrip() + "…"


def _canonical_url(value: str) -> str:
    clean = html.unescape(value).strip()
    if not clean.startswith(("http://", "https://")):
        return clean
    parts = urlsplit(clean)
    query = [
        (key, item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
        if not key.lower().startswith("utm_") and key.lower() not in {"fbclid", "gclid", "mc_cid", "mc_eid"}
    ]
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, urlencode(query), ""))


def _safe_remote_url(value: str) -> str:
    clean = html.unescape(value).strip()
    return clean if clean.startswith(("https://", "http://")) else ""


def _is_breaking(title: str, summary: str) -> bool:
    text = f"{title} {summary}".casefold()
    return any(term in text for term in ("actively exploited", "zero-day", "0-day", "critical vulnerability", "emergency", "在野利用", "紧急"))


def _category_id(name: str) -> str:
    mapping = {
        "全部": "all",
        "AI 安全": "ai-security",
        "大模型": "llm",
        "漏洞披露": "vulnerability",
        "数据安全": "data-security",
        "政策法规": "policy",
        "云安全": "cloud-security",
        "供应链安全": "supply-chain",
        "行业动态": "industry",
        "攻击技术": "attack-techniques",
    }
    return mapping.get(name, "industry")


def _compact_error(error: Exception) -> str:
    message = re.sub(r"\s+", " ", str(error)).strip()
    return message[:220] or error.__class__.__name__


information_service = InformationService()
