#!/usr/bin/env python3
"""dnsmasq DNS 查询汇总（SQLite 只读）。默认统计今天截至当前。"""
import argparse
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

DEFAULT_DB = "/var/lib/dns-log-analyzer/requests.sqlite3"

def summarize(db, start, end):
    total, duplicate, success, failure = db.execute("""
        SELECT count(*),
          coalesce(sum(CASE WHEN result='duplicate' THEN 1 ELSE 0 END),0),
          coalesce(sum(CASE WHEN state='answered'
            AND (result IS NULL OR result NOT IN ('SERVFAIL','REFUSED','duplicate'))
            THEN 1 ELSE 0 END),0),
          coalesce(sum(CASE WHEN result IN ('SERVFAIL','REFUSED') THEN 1 ELSE 0 END),0)
        FROM dnsmasq_requests WHERE first_seen>=? AND first_seen<?
    """, (start, end)).fetchone()
    unconfirmed = total - duplicate - success - failure
    confirmed = success + failure
    return {
        "total": total, "success": success, "failure": failure,
        "duplicate": duplicate, "unconfirmed": unconfirmed,
        "confirmed_success_rate": success / confirmed * 100 if confirmed else None,
        "overall_success_rate": success / total * 100 if total else None,
    }

def resolve_window(period, days, start, end, now):
    if (start or end) and (period or days):
        raise ValueError("自定义 --start/--end 不可与快捷周期或 --days 同时使用")
    if days is not None and period:
        raise ValueError("--days 不可与快捷周期同时使用")
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if start or end:
        begin = datetime.fromisoformat(start) if start else today
        finish = datetime.fromisoformat(end) if end else now
    elif days is not None:
        if days < 1:
            raise ValueError("--days 必须大于等于 1")
        begin, finish = now - timedelta(days=days), now
    elif period == "yesterday":
        begin, finish = today - timedelta(days=1), today
    elif period == "week":
        begin, finish = today - timedelta(days=today.weekday()), now
    elif period == "month":
        begin, finish = today.replace(day=1), now
    elif period == "last7":
        begin, finish = now - timedelta(days=7), now
    else:
        begin, finish = today, now
    if begin >= finish:
        raise ValueError("开始时间必须早于结束时间")
    return begin.isoformat(timespec="seconds"), finish.isoformat(timespec="seconds")

def main():
    parser = argparse.ArgumentParser(
        prog="dns-summary",
        description="dnsmasq 查询统计：确认成功率与全量完成成功率，保留重复和未确认分类。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""快捷用法：
  dns-summary                  今天 00:00 至现在
  dns-summary today            今天 00:00 至现在
  dns-summary yesterday        昨天全天
  dns-summary week             本周一 00:00 至现在
  dns-summary month            本月 1 日 00:00 至现在
  dns-summary last7            最近连续 7×24 小时
  dns-summary --days 3         最近连续 3×24 小时
  dns-summary --start 2026-10-15T00:00:00 --end 2026-10-16T00:00:00

成功：有效回答（含 NXDOMAIN/NODATA、缓存完成）
失败：SERVFAIL/REFUSED
重复：duplicate，单独统计
未确认：没有最终完成证据，不视为成功或失败
确认成功率 = 成功 / (成功 + 失败)
全量完成成功率 = 成功 / 全部查询
时间使用 local-57 本地时区；--end 为不含端点。"""
    )
    parser.add_argument("period", nargs="?", choices=["today","yesterday","week","month","last7"], help="快捷统计周期")
    parser.add_argument("--days", type=int, metavar="N", help="最近 N×24 小时")
    parser.add_argument("--start", help="自定义开始时间，本地 ISO 格式（含）")
    parser.add_argument("--end", help="自定义结束时间，本地 ISO 格式（不含）")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite 数据库路径")
    args = parser.parse_args()
    try:
        start, end = resolve_window(args.period, args.days, args.start, args.end, datetime.now())
        uri = Path(args.db).resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            result = summarize(db, start, end)
    except (ValueError, sqlite3.Error, OSError) as exc:
        parser.error(str(exc))
    print(f"dnsmasq  {start} <= first_seen < {end}")
    for key, title in (("total","查询总数"),("success","成功"),("failure","明确失败"),("duplicate","重复请求"),("unconfirmed","未确认完成")):
        print(f"{title}: {result[key]:,}")
    for key, title, denominator in (
        ("confirmed_success_rate","确认成功率","成功 + 明确失败"),
        ("overall_success_rate","全量完成成功率","查询总数")
    ):
        value = result[key]
        print(f"{title}: {value:.4f}%  (分母：{denominator})" if value is not None else f"{title}: N/A")

if __name__ == "__main__":
    main()
