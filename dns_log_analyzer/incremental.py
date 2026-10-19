"""Transactional DNS counter deltas; install only after historical backfill."""
def install_dnsmasq_triggers(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS dns_minute_aggregates(
      source TEXT, minute TEXT, dimension TEXT, total INTEGER,
      PRIMARY KEY(source,minute,dimension));
    CREATE TABLE IF NOT EXISTS dns_hourly_aggregates(
      source TEXT,hour TEXT,dimension TEXT,total INTEGER,updated_at TEXT,
      PRIMARY KEY(source,hour,dimension));
    """)
    def metrics(p):
        success=f"({p}.state=\x27answered\x27 AND ({p}.result IS NULL OR {p}.result NOT IN (\x27SERVFAIL\x27,\x27REFUSED\x27,\x27duplicate\x27)))"
        failed=f"coalesce(({p}.result IN (\x27SERVFAIL\x27,\x27REFUSED\x27)),0)"
        duplicate=f"coalesce(({p}.result=\x27duplicate\x27),0)"
        return dict(total="1",success=success,failed=failed,duplicate=duplicate,
          unconfirmed=f"(1-({success})-({failed})-({duplicate}))",
          cache_hits=f"({p}.cache_seen=1 AND {p}.forwarded=0)")
    db.execute("DROP TRIGGER IF EXISTS agg_dnsmasq_delete")
    for action in ("INSERT","UPDATE"):
        parts=[]
        changes=(("NEW",1),) if action=="INSERT" else (("OLD",-1),) if action=="DELETE" else (("OLD",-1),("NEW",1))
        for p,sign in changes:
            for name,expr in metrics(p).items():
                for table,key,bucket in (("dns_minute_aggregates","minute",f"substr({p}.first_seen,1,16)||\x27:00\x27"),
                                         ("dns_hourly_aggregates","hour",f"substr({p}.first_seen,1,13)||\x27:00:00\x27")):
                    cols="source,"+key+",dimension,total"
                    vals=f"\x27dnsmasq\x27,{bucket},\x27{name}\x27,({sign})*({expr})"
                    update="total=total+excluded.total"
                    if key=="hour":
                        cols+=",updated_at"; vals+=",datetime(\x27now\x27)"; update+=",updated_at=excluded.updated_at"
                    parts.append(f"INSERT INTO {table}({cols}) VALUES({vals}) ON CONFLICT(source,{key},dimension) DO UPDATE SET {update};")
        name="agg_dnsmasq_"+action.lower()
        db.execute(f"DROP TRIGGER IF EXISTS {name}")
        db.execute(f"CREATE TRIGGER {name} AFTER {action} ON dnsmasq_requests BEGIN "+" ".join(parts)+" END;")
    db.commit()

def install_dnsproxy_triggers(db):
    """Incrementally maintain exact upstream counters and latency histograms."""
    import json
    bounds = [50,100,150,200,250,300,400,500,700,1000,1500,3000]
    db.executescript("""
    CREATE TABLE IF NOT EXISTS dns_latency_histograms(
      source TEXT NOT NULL,hour TEXT NOT NULL,upstream TEXT NOT NULL,
      bounds_json TEXT NOT NULL,counts_json TEXT NOT NULL,total INTEGER NOT NULL,
      updated_at TEXT NOT NULL,PRIMARY KEY(source,hour,upstream));
    CREATE TABLE IF NOT EXISTS dns_minute_aggregates(
      source TEXT,minute TEXT,dimension TEXT,total INTEGER,
      PRIMARY KEY(source,minute,dimension));
    CREATE TABLE IF NOT EXISTS dns_hourly_aggregates(
      source TEXT,hour TEXT,dimension TEXT,total INTEGER,updated_at TEXT,
      PRIMARY KEY(source,hour,dimension));
    """)
    db.execute("""CREATE TABLE IF NOT EXISTS dns_latency_minute_bins(
      minute TEXT NOT NULL,upstream TEXT NOT NULL,bin INTEGER NOT NULL,total INTEGER NOT NULL,
      PRIMARY KEY(minute,upstream,bin))""")
    # Histogram bins are individually additive in SQL; no historical rescan.
    for action in ("INSERT","UPDATE"):
        changes=(("NEW",1),) if action=="INSERT" else (("OLD",-1),("NEW",1))
        statements=[]
        for row,sign in changes:
            hour=f"substr({row}.first_seen,1,13)||\x27:00:00\x27"
            minute=f"substr({row}.first_seen,1,16)||\x27:00\x27"
            upstream=f"coalesce({row}.upstream,\x27(unknown)\x27)"
            exact=f"(instr({row}.identity,\x27:exact:\x27)>0)"
            for name,metric in (
                ("attempts:",f"{exact}"),
                ("failed:",f"{exact} AND {row}.status=\x27failed\x27")):
                dim=f"\x27{name}\x27||{upstream}"
                expr=f"({sign})*({metric})"
                statements.append(f"""INSERT INTO dns_hourly_aggregates
                  VALUES(\x27dnsproxy\x27,{hour},{dim},{expr},datetime(\x27now\x27))
                  ON CONFLICT(source,hour,dimension)
                  DO UPDATE SET total=total+excluded.total,updated_at=excluded.updated_at;""")
                statements.append(f"""INSERT INTO dns_minute_aggregates
                  VALUES(\x27dnsproxy\x27,{minute},{dim},{expr})
                  ON CONFLICT(source,minute,dimension)
                  DO UPDATE SET total=total+excluded.total;""")
            for i in range(13):
                lower=f"{row}.duration_ms>={bounds[i-1]}" if i else "1"
                upper=f"{row}.duration_ms<{bounds[i]}" if i<12 else "1"
                condition=f"({exact} AND {row}.status=\x27success\x27 AND {row}.duration_ms IS NOT NULL AND {lower} AND {upper})"
                statements.append(f"""INSERT INTO dns_latency_minute_bins
                  VALUES({minute},{upstream},{i},({sign})*({condition}))
                  ON CONFLICT(minute,upstream,bin)
                  DO UPDATE SET total=total+excluded.total;""")
                # Maintain per-bin counters in a normalized table; JSON snapshots can be
                # assembled from these rows without reading detail.
                statements.append(f"""INSERT INTO dns_latency_bins
                  VALUES({hour},{upstream},{i},({sign})*({condition}))
                  ON CONFLICT(hour,upstream,bin)
                  DO UPDATE SET total=total+excluded.total;""")
        name=f"agg_upstream_{action.lower()}"
        db.execute(f"DROP TRIGGER IF EXISTS {name}")
        db.execute(f"CREATE TRIGGER {name} AFTER {action} ON dnsproxy_upstream_attempts BEGIN "+" ".join(statements)+" END;")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS dns_latency_bins(
      hour TEXT NOT NULL,upstream TEXT NOT NULL,bin INTEGER NOT NULL,total INTEGER NOT NULL,
      PRIMARY KEY(hour,upstream,bin));
    CREATE TABLE IF NOT EXISTS dns_latency_minute_bins(
      minute TEXT NOT NULL,upstream TEXT NOT NULL,bin INTEGER NOT NULL,total INTEGER NOT NULL,
      PRIMARY KEY(minute,upstream,bin));
    """)
    db.commit()

def install_event_triggers(db):
    """Maintain packet/cache counts, including duplicate-safe INSERT OR IGNORE."""
    db.executescript("""
    CREATE TABLE IF NOT EXISTS dns_minute_aggregates(
      source TEXT,minute TEXT,dimension TEXT,total INTEGER,
      PRIMARY KEY(source,minute,dimension));
    CREATE TABLE IF NOT EXISTS dns_hourly_aggregates(
      source TEXT,hour TEXT,dimension TEXT,total INTEGER,updated_at TEXT,
      PRIMARY KEY(source,hour,dimension));
    """)
    for table,metric in (("dnsproxy_packet_events","packet_events"),
                         ("dnsproxy_cache_events","cache_events")):
        name="agg_event_"+metric
        db.execute(f"DROP TRIGGER IF EXISTS {name}")
        db.execute(f"""CREATE TRIGGER {name} AFTER INSERT ON {table} BEGIN
          INSERT INTO dns_minute_aggregates VALUES
          (\x27dnsproxy\x27,substr(NEW.ts,1,16)||\x27:00\x27,\x27{metric}\x27,1)
          ON CONFLICT(source,minute,dimension) DO UPDATE SET total=total+1;
          INSERT INTO dns_hourly_aggregates VALUES
          (\x27dnsproxy\x27,substr(NEW.ts,1,13)||\x27:00:00\x27,\x27{metric}\x27,1,datetime(\x27now\x27))
          ON CONFLICT(source,hour,dimension) DO UPDATE SET total=total+1,updated_at=excluded.updated_at;
          END;""")
    db.commit()
