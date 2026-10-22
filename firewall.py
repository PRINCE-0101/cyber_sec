"""Deterministic, first-match packet-filter simulator (Python standard library only)."""
import ipaddress
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PROTOCOLS = {'TCP', 'UDP', 'ICMP'}


def port(value):
    if isinstance(value, bool) or not str(value).isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError('Port must be an integer from 1 to 65535')
    return int(value)


def packet(data):
    source = str(ipaddress.ip_address(data['source']))
    destination = str(ipaddress.ip_address(data['destination']))
    if ipaddress.ip_address(source).version != ipaddress.ip_address(destination).version:
        raise ValueError('Source and destination must use the same IP version')
    protocol = str(data['protocol']).upper()
    if protocol not in PROTOCOLS:
        raise ValueError('Protocol must be TCP, UDP or ICMP')
    p = data.get('port')
    if protocol == 'ICMP' and p not in (None, ''):
        raise ValueError('ICMP does not use ports')
    return dict(source=source, destination=destination, protocol=protocol,
                port=None if protocol == 'ICMP' else port(p))


def policy(data):
    default = str(data.get('default', 'BLOCK')).upper()
    if default not in {'ALLOW', 'BLOCK'}:
        raise ValueError('Default must be ALLOW or BLOCK')
    rules = data.get('rules', [])
    if not isinstance(rules, list) or len(rules) > 500:
        raise ValueError('Rules must be a list of at most 500 entries')
    result, ids = [], set()
    for raw in rules:
        rid = str(raw['id']).strip()
        if not rid or len(rid) > 80 or rid in ids:
            raise ValueError('Rule IDs must be unique, nonempty and at most 80 characters')
        ids.add(rid)
        action = str(raw['action']).upper()
        protocol = str(raw.get('protocol', 'ANY')).upper()
        if action not in {'ALLOW', 'BLOCK'} or protocol not in PROTOCOLS | {'ANY'}:
            raise ValueError('Invalid rule action or protocol')
        networks = {}
        for key in ('source', 'destination'):
            value = str(raw.get(key, 'ANY')).strip()
            networks[key] = 'ANY' if value.upper() == 'ANY' else str(ipaddress.ip_network(value, strict=False))
        ports = raw.get('ports', 'ANY')
        if str(ports).upper() == 'ANY':
            ports = 'ANY'
        else:
            parts = str(ports).split('-')
            if len(parts) not in (1, 2):
                raise ValueError('Use a single port or inclusive range, e.g. 8000-8080')
            low, high = port(parts[0]), port(parts[-1])
            if low > high or protocol == 'ICMP':
                raise ValueError('Invalid port range or ICMP port constraint')
            ports = str(low) if low == high else f'{low}-{high}'
        enabled = raw.get('enabled', True)
        if not isinstance(enabled, bool):
            raise ValueError('Enabled must be true or false')
        result.append(dict(id=rid, action=action, protocol=protocol, ports=ports,
                           enabled=enabled, **networks))
    return dict(default=default, rules=result)


def evaluate(config, incoming):
    config, incoming = policy(config), packet(incoming)
    trace = []
    for rule in config['rules']:
        reasons = []
        if not rule['enabled']:
            reasons.append('disabled')
        for field in ('source', 'destination'):
            if rule[field] != 'ANY' and ipaddress.ip_address(incoming[field]) not in ipaddress.ip_network(rule[field]):
                reasons.append(f'{field} outside network')
        if rule['protocol'] not in ('ANY', incoming['protocol']):
            reasons.append('protocol differs')
        if rule['ports'] != 'ANY':
            bounds = rule['ports'].split('-')
            if incoming['port'] is None or not int(bounds[0]) <= incoming['port'] <= int(bounds[-1]):
                reasons.append('destination port outside range')
        trace.append(dict(rule=rule['id'], matched=not reasons, reason=', '.join(reasons) or 'all conditions matched'))
        if not reasons:
            return dict(action=rule['action'], matched_rule=rule['id'], packet=incoming, trace=trace,
                        timestamp=datetime.now(timezone.utc).isoformat())
    return dict(action=config['default'], matched_rule='DEFAULT', packet=incoming, trace=trace,
                timestamp=datetime.now(timezone.utc).isoformat())


def save_policy(path, data):
    clean = policy(data)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.policy-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(clean, stream, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def simulate(config, incoming, log_path):
    decision = evaluate(config, incoming)
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(decision) + '\n')
    return decision
