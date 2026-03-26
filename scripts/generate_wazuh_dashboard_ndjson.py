from __future__ import annotations

import json
from pathlib import Path


OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "wazuh_dashboard_saved_objects.ndjson"


def _line(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)


def build_saved_objects() -> list[dict]:
    index_pattern_id = "automaticsoc-wazuh-alerts-index"
    search_id = "automaticsoc-critical-search"
    dashboard_id = "automaticsoc-wazuh-dashboard"

    index_pattern = {
        "type": "index-pattern",
        "id": index_pattern_id,
        "attributes": {
            "title": "wazuh-alerts-*",
            "timeFieldName": "timestamp",
        },
    }

    search_object = {
        "type": "search",
        "id": search_id,
        "attributes": {
            "title": "AutomaticSOC Critical Alerts",
            "description": "Critical and high Wazuh alerts used by the AI pipeline",
            "columns": ["timestamp", "rule.level", "rule.description", "agent.name", "data.srcip", "data.dstip"],
            "sort": [["timestamp", "desc"]],
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {
                        "index": index_pattern_id,
                        "query": {
                            "language": "kuery",
                            "query": "rule.level >= 10",
                        },
                        "filter": [],
                    }
                )
            },
        },
        "references": [
            {
                "id": index_pattern_id,
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
            }
        ],
    }

    dashboard = {
        "type": "dashboard",
        "id": dashboard_id,
        "attributes": {
            "title": "AutomaticSOC Wazuh Operations Dashboard",
            "description": "SOC dashboard aligned with AutomaticSOC webhook and model workflows",
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {
                        "query": {"language": "kuery", "query": ""},
                        "filter": [],
                    }
                )
            },
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "panelsJSON": json.dumps(
                [
                    {
                        "panelIndex": "1",
                        "gridData": {"x": 0, "y": 0, "w": 48, "h": 18, "i": "1"},
                        "type": "search",
                        "id": search_id,
                        "version": "8.0.0",
                    }
                ]
            ),
        },
        "references": [
            {
                "id": search_id,
                "name": "panel_0",
                "type": "search",
            }
        ],
    }

    return [index_pattern, search_object, dashboard]


def main() -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    objects = build_saved_objects()
    OUTPUT_PATH.write_text("\n".join(_line(obj) for obj in objects) + "\n", encoding="utf-8")
    print(f"Wrote {len(objects)} saved objects to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
