import unittest
from scripts.v2_raw_export import parse
class RawExportTests(unittest.TestCase):
    def test_unbound(self):
        row=parse('unbound','[1794630640] unbound[1:0] info: 192.168.0.59 api-normal.doubao.com. A IN NOERROR 0.019373 0 491')
        self.assertEqual(row[3],'api-normal.doubao.com.')
        self.assertEqual(row[6],19373)
    def test_fanout(self):
        row=parse('fanout','[INFO] 2026-11-14T12:30:41.27816708+08:00 127.0.0.1:24949 - 27677 "HTTPS IN worker.clerkprod-cloudflare.net. udp 60 true 1232" NOERROR qr,rd,ra 161 0.005797319s "0"')
        self.assertEqual(row[3],'worker.clerkprod-cloudflare.net.')
        self.assertEqual(row[6],5797)
if __name__=='__main__':unittest.main()
