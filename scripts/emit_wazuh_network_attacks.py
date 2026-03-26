from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

NETWORK_LOG = Path('/var/log/automaticsoc-network.json')


def event(attack_class: str, srcip: str, dstip: str, dstport: int, proto: str, bytes_sent: int, packets: int) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        'timestamp': now,
        'event_type': 'network_traffic',
        'attack_class': attack_class,
        'srcip': srcip,
        'dstip': dstip,
        'dstport': dstport,
        'protocol': proto,
        'bytes': bytes_sent,
        'packets': packets,
        'message': f'simulated {attack_class} traffic from {srcip} to {dstip}:{dstport}',
    }


def main() -> int:
    payloads = [
        event('brute_force', '185.44.9.10', '10.0.0.15', 22, 'tcp', 15422, 172),
        event('port_scan', '203.0.113.77', '10.0.0.25', 445, 'tcp', 12400, 650),
        event('ddos', '198.51.100.44', '10.0.0.80', 443, 'tcp', 920000, 8600),
        event('malware', '45.67.12.34', '10.0.0.33', 445, 'tcp', 45200, 540),
        event('normal', '10.10.1.9', '10.0.0.15', 443, 'tcp', 3120, 35),
    ]

    with NETWORK_LOG.open('a', encoding='utf-8') as fp:
        for item in payloads:
            fp.write(json.dumps(item, ensure_ascii=True) + '\n')

    print(f'written {len(payloads)} events to {NETWORK_LOG}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
