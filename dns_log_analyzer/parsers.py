"""Parsers preserve raw text and extract only evidence-backed fields."""
import datetime as dt
import json
import re

DNSMASQ = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<clock>\d\d:\d\d:\d\d)\s+dnsmasq\[(?P<pid>\d+)\]:\s+(?P<qid>\d+)\s+(?P<client>\S+)\s+(?P<action>\S+)\s+(?P<detail>.*)$")
DNSPROXY = re.compile(r"^(?P<date>\d{4}/\d\d/\d\d)\s+(?P<clock>\d\d:\d\d:\d\d\.\d+)\s+(?P<level>DEBUG|INFO|WARN|ERROR)\s+(?P<message>.*)$")
KEY_VALUE = re.compile(r'([a-zA-Z][\w-]*)=("(?:\\.|[^"\\])*"|\S+)')
DURATION = re.compile(r"^(\d+(?:\.\d+)?)(ns|µs|us|ms|s|m|h)$")

def _fields(message):
    result = {}
    for key, value in KEY_VALUE.findall(message):
        if value.startswith('"'):
            try: value = json.loads(value)
            except ValueError: value = value[1:-1]
        result[key] = value
    return result

def _ms(value):
    if not value: return None
    m = DURATION.fullmatch(str(value))
    if not m: return None
    return float(m[1]) * {"ns": 0.000001, "µs": 0.001, "us": 0.001, "ms": 1, "s": 1000, "m": 60000, "h": 3600000}[m[2]]

def parse(source, line, year=None):
    if source == "dnsmasq":
        m = DNSMASQ.match(line)
        if not m: return None
        d = m.groupdict()
        year = year or dt.datetime.now().year
        try: ts = dt.datetime.strptime(f"{year} {d['mon']} {d['day']} {d['clock']}", "%Y %b %d %H:%M:%S").isoformat()
        except ValueError: return None
        action, detail = d["action"], d["detail"]
        qtype = action[6:-1] if action.startswith("query[") and action.endswith("]") else None
        event = "query" if qtype else action
        domain = detail.split(" from ", 1)[0] if qtype else None
        upstream = None
        result = None
        if event == "forwarded" and " to " in detail:
            domain, upstream = detail.rsplit(" to ", 1)
        elif event in ("reply", "cached", "config") and " is " in detail:
            domain, result = detail.split(" is ", 1)
        return dict(ts=ts, level=None, event=event, query_id=d["qid"], client=d["client"], domain=domain, qtype=qtype, upstream=upstream, protocol=None, duration_ms=None, duration_kind=None, result=result, error=None, fields=json.dumps({"pid": d["pid"], "detail": detail}, ensure_ascii=False))
    if source == "smartdns":
        m=re.match(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+)\] (\S+) query (.*), type (\d+), time (\d+)ms, speed: ([^,]+), result(?: (.*))?$",line)
        if not m:return None
        ts,client,domain,qtype,elapsed,speed,result=m.groups()
        return dict(ts=ts.replace(" ","T").replace(",","."),client=client,domain=domain,qtype=qtype,duration_ms=int(elapsed),result=result or "",fields=json.dumps({"speed":speed}))
    if source == "dnsproxy":
        m = DNSPROXY.match(line)
        if not m: return None
        d = m.groupdict()
        message = d["message"]
        fields = _fields(message)
        event = re.split(r"\s+(?:prefix|addr|upstream|qname|name|req)=", message, maxsplit=1)[0]
        duration_kind = "upstream_exchange" if fields.get("duration") else ("component_elapsed" if fields.get("elapsed") else None)
        return dict(ts=d["date"].replace("/", "-") + "T" + d["clock"], level=d["level"], event=event, query_id=None, client=fields.get("raddr"), domain=fields.get("qname") or fields.get("name"), qtype=fields.get("qtype"), upstream=fields.get("upstream") or fields.get("addr"), protocol=fields.get("proto"), duration_ms=_ms(fields.get("duration") or fields.get("elapsed")), duration_kind=duration_kind, result=fields.get("status"), error=fields.get("err"), fields=json.dumps(fields, ensure_ascii=False))
    raise ValueError("unsupported source")
