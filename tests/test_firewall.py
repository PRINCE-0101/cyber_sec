import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import HTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from firewall import evaluate, packet, policy, save_policy, simulate
from app import make_handler

ROOT = Path(__file__).resolve().parents[1]

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / 'examples/policy.json').read_text())
        self.p = dict(source='192.168.1.20', destination='198.51.100.10', protocol='TCP', port=443)

    def test_demo_verdicts(self):
        packets = json.loads((ROOT / 'examples/packets.json').read_text())
        self.assertEqual([evaluate(self.config, p)['action'] for p in packets], ['BLOCK','ALLOW','ALLOW','ALLOW','BLOCK','BLOCK'])

    def test_first_match_and_reordering(self):
        self.p['source'] = '203.0.113.66'
        self.assertEqual(evaluate(self.config,self.p)['matched_rule'],'deny-suspicious-host')
        self.config['rules'].reverse()
        self.assertEqual(evaluate(self.config,self.p)['action'],'ALLOW')

    def test_disabled_rule(self):
        self.p['source'] = '203.0.113.66'
        self.config['rules'][0]['enabled'] = False
        self.assertEqual(evaluate(self.config,self.p)['action'],'ALLOW')

    def test_default_allow(self):
        self.assertEqual(evaluate({'default':'ALLOW'}, self.p)['action'],'ALLOW')

    def test_ipv6_and_destination(self):
        cfg={'rules':[{'id':'v6','action':'ALLOW','destination':'2001:db8::/32'}]}
        p=dict(source='2001:db8::1',destination='2001:db8::2',protocol='UDP',port=53)
        self.assertEqual(evaluate(cfg,p)['action'],'ALLOW')
        p['destination']='2001:db9::1'
        self.assertEqual(evaluate(cfg,p)['action'],'BLOCK')

    def test_range_boundaries(self):
        cfg={'rules':[{'id':'range','action':'ALLOW','ports':'8000-8080'}]}
        for p, expected in [(7999,'BLOCK'),(8000,'ALLOW'),(8080,'ALLOW'),(8081,'BLOCK')]:
            with self.subTest(port=p):
                self.assertEqual(evaluate(cfg,{**self.p,'port':p})['action'],expected)

    def test_invalid_packets(self):
        for patch in [{'source':'bad'}, {'port':0},{'port':65536},{'port':True},{'protocol':'HTTP'},{'protocol':'ICMP'},{'destination':'::1'}]:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                packet({**self.p,**patch})

    def test_icmp_does_not_match_port_rule(self):
        result=evaluate({'rules':[{'id':'port','action':'ALLOW','ports':'443'}]}, {**self.p,'protocol':'ICMP','port':None})
        self.assertEqual(result['action'],'BLOCK')

    def test_invalid_rules(self):
        for patch in [{'ports':'90-80'},{'protocol':'ICMP','ports':'22'},{'source':'bad'},{'enabled':'false'},{'action':'DROP'}]:
            with self.subTest(patch=patch),self.assertRaises(ValueError):
                policy({'rules':[{'id':'x','action':'ALLOW',**patch}]})
        with self.assertRaises(ValueError):
            policy({'rules':[{'id':'x','action':'ALLOW'}]*2})

    def test_persistence_and_log(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'policy.json'; logs=Path(d)/'traffic.jsonl'
            save_policy(path,self.config)
            simulate(json.loads(path.read_text()),self.p,logs)
            simulate(self.config,{**self.p,'port':80},logs)
            self.assertEqual([json.loads(x)['action'] for x in logs.read_text().splitlines()],['ALLOW','BLOCK'])
            original=path.read_text()
            with self.assertRaises(ValueError):save_policy(path,{'default':'BAD'})
            self.assertEqual(path.read_text(),original)

class APITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.server=HTTPServer(('127.0.0.1',0),make_handler(self.temp.name))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.base=f'http://127.0.0.1:{self.server.server_port}'
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()
    def request(self,path,data=None,**headers):
        return urlopen(Request(self.base+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json',**headers}),timeout=5)
    def test_dashboard_and_simulate(self):
        with self.request('/') as r:self.assertIn(b'SENTINEL',r.read())
        with self.request('/api/simulate',dict(source='192.0.2.1',destination='198.51.100.1',protocol='TCP',port=443)) as r:self.assertEqual(json.load(r)['action'],'ALLOW')
        with self.request('/api/state') as r:self.assertEqual(len(json.load(r)['logs']),1)
        with self.request('/api/export') as r:self.assertEqual(len(r.read().splitlines()),1)
    def test_reject_cross_origin(self):
        with self.assertRaises(HTTPError) as e:self.request('/api/policy',{'rules':[]},Origin='https://example.com')
        self.assertEqual(e.exception.code,403)
    def test_invalid_input(self):
        with self.assertRaises(HTTPError) as e:self.request('/api/simulate',{'source':'bad'})
        self.assertEqual(e.exception.code,400)
    def test_save_policy(self):
        with self.request('/api/policy',{'default':'ALLOW','rules':[]}) as r:self.assertEqual(r.status,200)
        with self.request('/api/state') as r:self.assertEqual(json.load(r)['policy']['default'],'ALLOW')

if __name__=='__main__':unittest.main()
