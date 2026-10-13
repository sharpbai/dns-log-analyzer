import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from dns_log_analyzer.watch import Watcher,decode_events,HEADER,IN_MODIFY

class WatchTests(unittest.TestCase):
    def test_decode(self):
        payload=HEADER.pack(7,IN_MODIFY,0,8)+b"foo.log\0"
        self.assertEqual(list(decode_events(payload)),[(7,IN_MODIFY,"foo.log")])

    @unittest.skipUnless(os.name=="posix" and __import__("sys").platform=="linux","Linux only")
    def test_modify_and_copytruncate(self):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/"dnsproxy.log"
            log.write_text("initial\n")
            w=Watcher({"dnsproxy":str(log)})
            try:
                with log.open("a") as f:f.write("next\n")
                dirty,overflow=w.wait(2)
                self.assertIn("dnsproxy",dirty)
                self.assertFalse(overflow)
                log.write_text("")
                dirty,_=w.wait(2)
                self.assertIn("dnsproxy",dirty)
            finally:
                w.close()

if __name__=="__main__":
    unittest.main()
