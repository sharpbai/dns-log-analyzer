import struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from scripts import v2_dnstap_export as tap
def var(n):
    out=[]
    while n>127:out.append((n&127)|128);n>>=7
    return bytes(out+[n])
def f(n,value):
    if isinstance(value,int):return var(n*8)+var(value)
    return var(n*8+2)+var(len(value))+value
def packet():
    name=b'\x04test\x07example\x00'
    return struct.pack('!6H',2345,0x0100,1,0,0,0)+name+struct.pack('!HH',1,1)
def message(kind,ns):
    p=packet()
    inner=(f(1,kind)+f(3,1)+f(4,b'\x7f\x00\x00\x01')+f(5,b'\x7f\x00\x00\x01')+
           f(6,45000)+f(7,53)+f(8 if kind==5 else 12,1794630000)+
           var((9 if kind==5 else 13)*8+5)+struct.pack('<I',ns)+f(10 if kind==5 else 14,p))
    return f(14,inner)+f(15,1)
class DnstapTests(unittest.TestCase):
    def test_match_nanoseconds(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            first=p/'20261114-140000.fstrm'
            frames=[message(5,100000000),message(6,123456000)]
            first.write_bytes(b''.join(struct.pack('!I',len(x))+x for x in frames))
            (p/'20261114-140100.fstrm').write_bytes(b'')
            with patch.object(tap,'BASE',p):
                result=tap.export_file(first.name)
            self.assertEqual(result['matched'],1)
            self.assertEqual(result['ambiguous'],0)
            self.assertEqual(result['events'][0]['duration_us'],23456)
            self.assertEqual(result['events'][0]['client_port'],45000)
            self.assertEqual(result['events'][0]['dns_id'],2345)
            self.assertEqual(result['events'][0]['match_status'],'matched')
if __name__=='__main__':unittest.main()
