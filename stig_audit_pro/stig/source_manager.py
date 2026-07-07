"""Download, import, cache, and parse STIG source packages."""

from __future__ import annotations

import json
import re
import shutil
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterable

from pydantic.json import pydantic_encoder

from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata
from stig_audit_pro.stig.xccdf_importer import parse_xccdf_file

CYBER_MIL_STIG_DOWNLOADS_URL = "https://www.cyber.mil/stigs/downloads/"
USER_AGENT = "STIG-Audit-Pro/0.1 (+https://www.cyber.mil/stigs/downloads/)"

DEFAULT_STIG_SOURCES = {
    "IOSXE_L2": ["cisco", "ios", "xe", "switch", "l2"],
    "IOSXE_NDM": ["cisco", "ios", "xe", "switch", "ndm"],
}


@dataclass(slots=True)
class StigDownloadCandidate:
    title: str
    url: str


class StigSourceError(RuntimeError):
    """Raised when a STIG source cannot be found, imported, or parsed."""


class StigSourceManager:
    def __init__(
        self,
        cache_dir: str | Path,
        download_page: str = CYBER_MIL_STIG_DOWNLOADS_URL,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.download_page = download_page
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def discover_downloads(self, search_terms: Iterable[str]) -> list[StigDownloadCandidate]:
        terms = [term.lower() for term in search_terms]
        html = self._read_url_text(self.download_page)
        candidates = self._extract_candidates(html, terms)
        if not candidates and self._looks_like_dynamic_shell(html):
            raise StigSourceError(
                "Cyber Exchange loaded its downloads page as a JavaScript application, so no STIG ZIP/XML links "
                "were visible to the automatic finder. Open the Cyber Exchange STIG downloads page in a browser, "
                "copy the direct ZIP/XML download link, and use Download URL or Import ZIP/XML."
            )
        return candidates

    def download_latest(
        self,
        family: str,
        search_terms: Iterable[str] | None = None,
    ) -> StigBenchmarkMetadata:
        terms = list(search_terms or DEFAULT_STIG_SOURCES.get(family, [family]))
        candidates = self.discover_downloads(terms)
        if not candidates:
            raise StigSourceError(
                "No matching STIG ZIP/XML download link was found on the Cyber Exchange downloads page. "
                "Use Download URL with a direct ZIP/XML link, or use Import ZIP/XML after downloading the STIG package."
            )
        return self.download_from_url(candidates[0].url, family=family)

    def download_from_url(self, url: str, family: str = "") -> StigBenchmarkMetadata:
        address = url.strip()
        if not address:
            raise StigSourceError("Enter a direct STIG ZIP/XML URL first.")

        local_candidate = Path(address)
        if local_candidate.exists():
            return self.import_source(local_candidate, family=family)

        parsed = urllib.parse.urlparse(address)
        if parsed.scheme in {"", "file"}:
            local_path = self._path_from_local_address(address, parsed)
            return self.import_source(local_path, family=family)
        if parsed.scheme not in {"http", "https"}:
            raise StigSourceError("STIG download URL must be HTTP, HTTPS, file, or a local path.")

        family_name = family or self._family_from_filename(Path(parsed.path).name)
        family_dir = self.cache_dir / family_name
        family_dir.mkdir(parents=True, exist_ok=True)

        request = urllib.request.Request(address, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            final_url = response.geturl()
            filename = self._filename_from_response(final_url, response.headers.get("Content-Disposition"), family_name)
            destination = family_dir / filename
            with destination.open("wb") as handle:
                shutil.copyfileobj(response, handle)
        return self.import_source(destination, family=family_name)

    def import_source(self, source_path: str | Path, family: str = "") -> StigBenchmarkMetadata:
        source = Path(source_path)
        if not source.exists():
            raise StigSourceError(f"STIG source does not exist: {source}")
        family_name = family or self._family_from_filename(source.name)
        family_dir = self.cache_dir / family_name
        family_dir.mkdir(parents=True, exist_ok=True)
        cached_source = family_dir / source.name
        if source.resolve() != cached_source.resolve():
            shutil.copy2(source, cached_source)

        xml_path = self._extract_xccdf(cached_source, family_dir)
        metadata = parse_xccdf_file(xml_path, family=family_name)
        metadata.source_path = str(cached_source)
        metadata.source_filename = cached_source.name
        self._write_metadata(family_dir, metadata)
        return metadata

    def load_cached_metadata(self) -> list[StigBenchmarkMetadata]:
        metadata_items: list[StigBenchmarkMetadata] = []
        for path in sorted(self.cache_dir.glob("*/metadata.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            if hasattr(StigBenchmarkMetadata, "model_validate"):
                metadata_items.append(StigBenchmarkMetadata.model_validate(data))  # type: ignore[attr-defined]
            else:
                metadata_items.append(StigBenchmarkMetadata.parse_obj(data))
        return metadata_items

    def _read_url_text(self, url: str) -> str:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", errors="ignore")

    def _extract_candidates(self, html: str, terms: list[str]) -> list[StigDownloadCandidate]:
        candidates: list[StigDownloadCandidate] = []
        seen: set[str] = set()

        anchor_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
        for href, label_html in anchor_pattern.findall(html):
            label = re.sub(r"<[^>]+>", " ", label_html)
            label = " ".join(label.split())
            self._add_candidate(candidates, seen, href, label, terms)

        direct_url_pattern = re.compile(r"https?://[^\s\"'<>]+(?:\.zip|\.xml)(?:\?[^\s\"'<>]*)?", re.IGNORECASE)
        for url in direct_url_pattern.findall(html):
            self._add_candidate(candidates, seen, url, Path(urllib.parse.urlparse(url).path).name, terms)

        return candidates

    def _add_candidate(
        self,
        candidates: list[StigDownloadCandidate],
        seen: set[str],
        href: str,
        label: str,
        terms: list[str],
    ) -> None:
        url = urllib.parse.urljoin(self.download_page, href)
        haystack = f"{label} {url}".lower()
        if ".zip" not in haystack and ".xml" not in haystack:
            return
        if not all(term in haystack for term in terms):
            return
        if url in seen:
            return
        seen.add(url)
        candidates.append(StigDownloadCandidate(title=label or Path(urllib.parse.urlparse(url).path).name, url=url))

    def _looks_like_dynamic_shell(self, html: str) -> bool:
        lowered = html.lower()
        return "lwc" in lowered or "salesforce" in lowered or "welcome to lwc communities" in lowered

    def _path_from_local_address(self, address: str, parsed: urllib.parse.ParseResult) -> Path:
        if parsed.scheme == "file":
            return Path(urllib.request.url2pathname(parsed.path))
        return Path(address)

    def _filename_from_response(self, url: str, content_disposition: str | None, family: str) -> str:
        if content_disposition:
            match = re.search(r'filename="?([^";]+)"?', content_disposition, flags=re.IGNORECASE)
            if match:
                return Path(match.group(1)).name
        filename = Path(urllib.parse.urlparse(url).path).name
        if filename.lower().endswith((".zip", ".xml")):
            return filename
        return f"{family}_STIG.zip"

    def _extract_xccdf(self, source: Path, family_dir: Path) -> Path:
        if source.suffix.lower() == ".xml":
            return source
        if source.suffix.lower() != ".zip":
            raise StigSourceError("STIG source must be an XCCDF XML file or ZIP package")
        with TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            with zipfile.ZipFile(source) as archive:
                archive.extractall(temp_root)
            xml_files = sorted(temp_root.rglob("*.xml"))
            xccdf_files = [path for path in xml_files if "xccdf" in path.name.lower()]
            selected = xccdf_files[0] if xccdf_files else (xml_files[0] if xml_files else None)
            if selected is None:
                raise StigSourceError("No XML/XCCDF file found in STIG ZIP")
            extracted = family_dir / selected.name
            shutil.copy2(selected, extracted)
            return extracted

    def _write_metadata(self, family_dir: Path, metadata: StigBenchmarkMetadata) -> None:
        payload = json.dumps(metadata, default=pydantic_encoder, indent=2)
        (family_dir / "metadata.json").write_text(payload, encoding="utf-8")

    def _family_from_filename(self, filename: str) -> str:
        lowered = filename.lower()
        if "ndm" in lowered:
            return "IOSXE_NDM"
        if "l2" in lowered:
            return "IOSXE_L2"
        return "UNKNOWN"
