"""Linux inotify-driven DNS log ingestion; standard library only.

Directory watches survive copytruncate and pathname replacement.  A periodic
reconciliation also covers inotify queue overflow and missed events.
"""
import argparse
import ctypes
import ctypes.util
import os
import select
import signal
import sqlite3
import struct
import sys
import time
from pathlib import Path

from .requests import ingest, open_db

IN_MODIFY=0x00000002
IN_ATTRIB=0x00000004
IN_CLOSE_WRITE=0x00000008
IN_MOVED_FROM=0x00000040
IN_MOVED_TO=0x00000080
IN_CREATE=0x00000100
IN_DELETE=0x00000200
IN_DELETE_SELF=0x00000400
IN_MOVE_SELF=0x00000800
IN_Q_OVERFLOW=0x00004000
WATCH_MASK=(IN_MODIFY|IN_ATTRIB|IN_CLOSE_WRITE|IN_MOVED_FROM|
            IN_MOVED_TO|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MOVE_SELF)
HEADER=struct.Struct("iIII")


def decode_events(data):
    offset=0
    while offset+HEADER.size<=len(data):
        wd,mask,cookie,length=HEADER.unpack_from(data,offset)
        offset+=HEADER.size
        if offset+length>len(data):
            raise ValueError("truncated inotify event")
        name=data[offset:offset+length].split(b"\0",1)[0]
        offset+=length
        yield wd,mask,os.fsdecode(name)


class Watcher:
    def __init__(self, paths):
        if sys.platform!="linux":
            raise RuntimeError("inotify requires Linux")
        library=ctypes.util.find_library("c")
        self.libc=ctypes.CDLL(library or "libc.so.6",use_errno=True)
        self.libc.inotify_init1.argtypes=[ctypes.c_int]
        self.libc.inotify_init1.restype=ctypes.c_int
        self.libc.inotify_add_watch.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint32]
        self.libc.inotify_add_watch.restype=ctypes.c_int
        self.fd=self.libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
        if self.fd<0:
            raise OSError(ctypes.get_errno(),"inotify_init1 failed")
        self.paths={name:Path(path) for name,path in paths.items()}
        self.dirs={}
        try:
            for directory in {p.parent for p in self.paths.values()}:
                wd=self.libc.inotify_add_watch(self.fd,os.fsencode(directory),WATCH_MASK)
                if wd<0:
                    raise OSError(ctypes.get_errno(),f"inotify watch failed: {directory}")
                self.dirs[wd]=directory
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.fd>=0:
            os.close(self.fd)
            self.fd=-1

    def wait(self,timeout):
        ready,_,_=select.select([self.fd],[],[],timeout)
        if not ready:
            return set(),False
        dirty=set()
        overflow=False
        while True:
            try:
                data=os.read(self.fd,65536)
            except BlockingIOError:
                break
            if not data:
                break
            for wd,mask,name in decode_events(data):
                if mask&IN_Q_OVERFLOW:
                    overflow=True
                directory=self.dirs.get(wd)
                if directory is None:
                    overflow=True
                    continue
                for source,path in self.paths.items():
                    # Include logrotate's .1 and .1.gz archive events.
                    if directory==path.parent and (
                        name==path.name or name in (path.name+".1",path.name+".1.gz")
                    ):
                        dirty.add(source)
                if mask&(IN_DELETE_SELF|IN_MOVE_SELF):
                    overflow=True
        return dirty,overflow


def run(db,paths,interval=30,debounce=0.15,once=False):
    def consume(sources):
        for source in sources:
            try:
                count=ingest(db,source,paths[source])
                if count:
                    print(f"{source}: {count} lines",flush=True)
            except (OSError,sqlite3.Error) as exc:
                print(f"{source}: {type(exc).__name__}: {exc}",file=sys.stderr,flush=True)
    if once:
        consume(paths)
        return
    watcher=Watcher(paths)
    consume(paths)
    stop=False
    def handle_stop(_signum,_frame):
        nonlocal stop
        stop=True
    previous={}
    for sig in (signal.SIGTERM,signal.SIGINT):
        previous[sig]=signal.getsignal(sig)
        signal.signal(sig,handle_stop)
    try:
        while not stop:
            dirty,overflow=watcher.wait(interval)
            if overflow:
                print("inotify overflow or invalidated watch: reconcile all",file=sys.stderr,flush=True)
                dirty=set(paths)
            if dirty:
                # Coalesce bursts, bounded by debounce.
                if debounce:
                    time.sleep(debounce)
                consume(dirty)
            else:
                # Timed wake-up reconciles missing events.
                consume(paths)
    finally:
        watcher.close()
        for sig,handler in previous.items():
            signal.signal(sig,handler)


def main():
    p=argparse.ArgumentParser(description="Event-driven DNS log ingestion")
    p.add_argument("--db",default="./dns-requests.sqlite3")
    p.add_argument("--smartdns",default="/var/log/smartdns/smartdns-audit.log")
    p.add_argument("--dnsproxy",default="/var/log/dnsproxy.log")
    p.add_argument("--reconcile-interval",type=float,default=30)
    p.add_argument("--debounce",type=float,default=0.15)
    p.add_argument("--once",action="store_true")
    a=p.parse_args()
    if a.reconcile_interval<=0 or a.debounce<0:
        p.error("interval must be positive and debounce nonnegative")
    db=open_db(a.db)
    try:
        run(db,{"smartdns":a.smartdns,"dnsproxy":a.dnsproxy},
            interval=a.reconcile_interval,debounce=a.debounce,once=a.once)
    finally:
        db.close()


if __name__=="__main__":
    main()
