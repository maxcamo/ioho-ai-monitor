"""Sintesi bounded delle richieste Nginx negli ultimi 5/10 minuti.

Non salva URL raw o valori dei parametri; l'IP e' quello presentato
in X-Forwarded-For e puo' essere falsificato se il proxy non lo valida.
"""
from collections import Counter, defaultdict
from datetime import timedelta
from ipaddress import ip_address, ip_network


def network_for_ip(client):
    """Raggruppamento convenzionale /24 IPv4 e /64 IPv6, non appartenenza al medesimo soggetto."""
    try:
        addr = ip_address(client)
        prefix = 24 if addr.version == 4 else 64
        return str(ip_network(f"{addr}/{prefix}", strict=False))
    except (ValueError, TypeError):
        return None


class TrafficWindow:
    MAX_KEYS = 10000
    MAX_PAIRS = 15000

    def __init__(self, minutes, reference):
        self.minutes = minutes
        self.reference = reference
        self.total = 0
        self.bot_hits = 0
        self.filter_hits = 0
        self.blocked = 0
        self.http_5xx = 0
        self.statuses = Counter()
        self.clients = Counter()
        self.urls = Counter()
        self.pairs = Counter()
        self.filtered_urls = Counter()
        self.blocked_urls = Counter()
        self.client_filters = Counter()
        self.client_blocks = Counter()
        self.client_bots = Counter()
        self.networks = Counter()
        self.network_filters = Counter()
        self.network_blocks = Counter()
        self.minute_counts = Counter()
        self.client_minutes = Counter()
        self.earliest = None
        self.latest = None
        self.capped = False

    def _count(self, counts, key, cap):
        if key not in counts and len(counts) >= cap:
            self.capped = True
            return
        counts[key] += 1

    def add(self, stamp, client, url, status, is_bot, is_filtered):
        if stamp < self.reference - timedelta(minutes=self.minutes):
            return
        if stamp > self.reference + timedelta(seconds=30):
            return
        client = client[:100]
        url = url[:230]
        self.total += 1
        self.statuses[status] += 1
        self.earliest = min(self.earliest, stamp) if self.earliest else stamp
        self.latest = max(self.latest, stamp) if self.latest else stamp
        minute = stamp.strftime('%Y-%m-%d %H:%M UTC')
        self.minute_counts[minute] += 1
        self._count(self.clients, client, self.MAX_KEYS)
        network = network_for_ip(client)
        if network:
            self._count(self.networks, network, self.MAX_KEYS)
        self._count(self.urls, url, self.MAX_KEYS)
        self._count(self.pairs, (client, url), self.MAX_PAIRS)
        self._count(self.client_minutes, (client, minute), self.MAX_PAIRS)
        if status in ('403', '410', '429', '444'):
            self.blocked += 1
            self._count(self.client_blocks, client, self.MAX_KEYS)
            if network:
                self._count(self.network_blocks, network, self.MAX_KEYS)
            self._count(self.blocked_urls, url, self.MAX_KEYS)
        if status.startswith('5'):
            self.http_5xx += 1
        if is_bot:
            self.bot_hits += 1
            self._count(self.client_bots, client, self.MAX_KEYS)
        if is_filtered:
            self.filter_hits += 1
            self._count(self.client_filters, client, self.MAX_KEYS)
            if network:
                self._count(self.network_filters, network, self.MAX_KEYS)
            self._count(self.filtered_urls, url, self.MAX_KEYS)

    def snapshot(self, truncated):
        top_client_names = set(name for name, _ in self.clients.most_common(15))
        client_paths = defaultdict(Counter)
        client_peaks = Counter()
        for (client, url), count in self.pairs.items():
            if client in top_client_names:
                client_paths[client][url] += count
        for (client, _minute), count in self.client_minutes.items():
            if client in top_client_names:
                client_peaks[client] = max(client_peaks[client], count)
        top_clients = []
        for client, n in self.clients.most_common(15):
            filters = self.client_filters[client]
            blocked = self.client_blocks[client]
            peak = client_peaks[client]
            clues = []
            if n >= 50 and filters * 2 >= n:
                clues.append('molti filtri')
            if n >= 50 and blocked * 2 >= n:
                clues.append('molte risposte 403/410/429/444')
            if peak >= 60:
                clues.append('picco di richieste')
            top_clients.append({
                'ip': client, 'count': n, 'rpm': round(n / self.minutes, 1),
                'filtered': filters, 'blocked': blocked,
                'bot_user_agent': self.client_bots[client],
                'peak_per_minute': peak,
                'top_urls': [[url, hits] for url, hits in client_paths[client].most_common(3)],
                'indicators': clues,
            })
        # Quota rete calcolata su TUTTI gli IP validi letti, non solo sui top 15.
        # IP distinti per rete derivati dalle chiavi client (censimento limitato a MAX_KEYS).
        network_ip_counts = Counter()
        for client in self.clients:
            network = network_for_ip(client)
            if network:
                network_ip_counts[network] += 1
        top_networks = [
            {'network': network, 'count': n,
             'unique_ips_observed': network_ip_counts[network],
             'filtered': self.network_filters[network],
             'blocked': self.network_blocks[network]}
            for network, n in self.networks.most_common(20)
        ]
        top_urls = [
            {'url': url, 'count': n, 'filtered': self.filtered_urls[url],
             'blocked': self.blocked_urls[url]}
            for url, n in self.urls.most_common(15)
        ]
        return {
            'minutes': self.minutes,
            'total': self.total,
            'rpm': round(self.total / self.minutes, 1),
            'peak_per_minute': max(self.minute_counts.values(), default=0),
            'bot_ua_hits': self.bot_hits,
            'filtered_hits': self.filter_hits,
            'blocked_hits': self.blocked,
            'http_5xx': self.http_5xx,
            'unique_ips_observed': len(self.clients),
            'statuses': dict(self.statuses),
            'top_urls': top_urls,
            'top_filtered_urls': [[url, n] for url, n in self.filtered_urls.most_common(12)],
            'top_clients': top_clients,
            'top_networks': top_networks,
            'network_counts_limited': self.capped,
            'top_ip_urls': [
                {'ip': client, 'url': url, 'count': n}
                for (client, url), n in self.pairs.most_common(15)
            ],
            'per_minute': [[minute, n] for minute, n in sorted(self.minute_counts.items())],
            'observed_from': self.earliest.isoformat() if self.earliest else None,
            'observed_to': self.latest.isoformat() if self.latest else None,
            'sampling_truncated': bool(truncated),
            'aggregation_capped': self.capped,
        }


class TrafficSummary:
    def __init__(self, reference):
        self.reference = reference
        self.windows = {'5': TrafficWindow(5, reference), '10': TrafficWindow(10, reference)}

    def add(self, stamp, client, url, status, is_bot, is_filtered):
        for window in self.windows.values():
            window.add(stamp, client, url, status, is_bot, is_filtered)

    def snapshot(self, truncated):
        return {
            'captured_at': self.reference.isoformat(),
            'windows': {key: value.snapshot(truncated) for key, value in self.windows.items()},
            'ip_note': 'IP da X-Forwarded-For o remote address: puo essere falsificato se il proxy non lo valida.',
        }
