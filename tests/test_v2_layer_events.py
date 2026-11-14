import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from scripts import v2_raw_export as raw

class LayerEventTests(unittest.TestCase):
    def test_fanout_decision_and_branch(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fanout.stdout'
            p.write_text(
                '[INFO] plugin/fanout: dns_v2_fanout_upstream '+json.dumps({'ts':'2026-11-14T06:31:34Z','upstream':'127.0.0.1:15370','outcome':'canceled','domain':'example.com.'})+'\n'
                '[INFO] plugin/fanout: dns_v2_fanout '+json.dumps({'ts':'2026-11-14T06:31:34Z','winner':'127.0.0.1:15404','domain':'example.com.'})+'\n'
            )
            with patch.dict(raw.PATHS,{'fanout':p}):
                result=raw.export('fanout',0,0)
            self.assertEqual(len(result['details']),2)
            self.assertEqual(result['details'][0]['event_kind'],'upstream')
            self.assertEqual(result['details'][1]['event_kind'],'decision')
            self.assertNotEqual(result['details'][0]['event_id'],result['details'][1]['event_id'])
    def test_domestic_filter_event(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'domestic.stdout'
            p.write_text('dns_v2_rripfilter '+json.dumps({'ts':'2026-11-14T06:31:34Z','action':'drop','original_ips':['8.8.8.8'],'rejected_ips':['8.8.8.8']})+'\n')
            with patch.dict(raw.PATHS,{'domestic':p}):
                result=raw.export('domestic',0,0)
            self.assertEqual(result['details'][0]['rejected_ips'],['8.8.8.8'])
    def test_overseas_exchange(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'dnsproxy.log'
            p.write_text('2026/11/14 14:24:41.005273 DEBUG upstream exchange completed addr=https://dns.google:443/dns-query proto=tcp qtype=A qname=example.com. id=65370 duration=400.03171ms status=ok\n')
            with patch.dict(raw.PATHS,{'overseas':p}):
                first=raw.export('overseas',0,0)
                self.assertEqual(first['offset'],p.stat().st_size)
                p.write_text(p.read_text()+'2026/11/14 14:24:42.005273 DEBUG upstream exchange completed addr=https://dns.google:443/dns-query proto=tcp qtype=A qname=example.com. id=65370 duration=2ms status=ok\n')
                result=raw.export('overseas',first['inode'],first['offset'])
            self.assertEqual(len(result['details']),1)
            self.assertEqual(result['details'][0]['duration_us'],2000)

if __name__=='__main__':unittest.main()
