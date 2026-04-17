import json
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional


class Cache:
    def __init__(self, cache_dir: Path, ttl_hours: int = 24):
        self.cache_dir = cache_dir
        self.ttl = timedelta(hours=ttl_hours)
        self.enabled = True

    def _path(self, source: str, key: str) -> Path:
        safe_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / source / f"{safe_key}.json"

    def get(self, source: str, key: str) -> Optional[Any]:
        if not self.enabled:
            return None
        path = self._path(source, key)
        if not path.exists():
            return None
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        if datetime.now(timezone.utc) - mtime > self.ttl:
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def set(self, source: str, key: str, data: Any) -> None:
        if not self.enabled:
            return
        path = self._path(source, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass
