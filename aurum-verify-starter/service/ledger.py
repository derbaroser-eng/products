"""Append-only revenue ledger.

Rule 0.1: only an independently attributable, settled, real-money payment for
externally consumed value may be reported as revenue. Everything else is
recorded, but under its own name:

    simulation   test-mode credential, no chain, no money
    testnet      on-chain settlement on a test network
    production   settled real money
    refunded / disputed / failed   recorded, and excluded from revenue

The ledger never overwrites a row. Corrections are new rows that reference the
original receipt.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, List, Optional

NON_REVENUE_MODES = ("simulation", "testnet", "staging")


class RevenueLedger:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.Lock()

    @staticmethod
    def is_revenue_eligible(entry: Dict[str, Any]) -> bool:
        """A row is revenue iff it is a verified production settlement with
        settlement evidence. status=settled alone is NOT enough (a simulation
        row is also 'settled' in the nonce sense); mode=simulation/testnet can
        never qualify however it is labeled. Computed for old rows too, so
        history keeps its meaning without rewrites."""
        return (str(entry.get("mode", "")) == "production"
                and str(entry.get("status", "")) == "settled"
                and bool(entry.get("tx")))

    def record(self, **fields: Any) -> Dict[str, Any]:
        entry = {"recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        entry.update(fields)
        entry["revenue_eligible"] = self.is_revenue_eligible(entry)
        line = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return entry

    def rows(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def summary(self) -> Dict[str, Any]:
        rows = self.rows()
        by_mode: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        settled_revenue_usd = 0.0
        gross_usd = 0.0
        refunded_usd = 0.0
        estimated_cost_usd = 0.0
        for r in rows:
            mode = str(r.get("mode", "unknown"))
            status = str(r.get("status", "unknown"))
            by_mode[mode] = by_mode.get(mode, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1
            price = float(r.get("price_usd") or 0.0)
            cost = float(r.get("cost_usd") or 0.0)
            gross_usd += price
            estimated_cost_usd += cost
            if self.is_revenue_eligible(r):
                settled_revenue_usd += price
            if status == "refunded":
                refunded_usd += price
        return {
            "calls": len(rows),
            "by_mode": by_mode,
            "by_status": by_status,
            "gross_usd": round(gross_usd, 6),
            "refunded_usd": round(refunded_usd, 6),
            "estimated_cost_usd": round(estimated_cost_usd, 6),
            "settled_revenue_usd": round(settled_revenue_usd, 6),
            "note": ("settled_revenue_usd counts only revenue_eligible rows "
                     "(production + settled + transaction hash). Simulation and "
                     "testnet rows are recorded but are never revenue."),
            "non_revenue_modes": list(NON_REVENUE_MODES),
        }

    def find(self, receipt: str) -> Optional[Dict[str, Any]]:
        for r in self.rows():
            if r.get("receipt") == receipt:
                return r
        return None
