#!python3

"""
Takes iftop connection data and displays it as a graph.
"""
import os
import re
import json
from dotenv import load_dotenv
from dataclasses import dataclass
from paramiko import AutoAddPolicy
from paramiko.client import SSHClient
from threading import Thread, Event
from http.server import BaseHTTPRequestHandler, HTTPServer


IFTOP_CMD = "iftop -nNPt -i mstp0"

load_dotenv()
ssh_host = os.getenv("SSH_HOST")
ssh_login = os.getenv("SSH_LOGIN")
ssh_passwd = os.getenv("SSH_PASSWD")

virtual_term_size = {
	"width": 300, "height": 300
}

last_mon_hosts_as_json = "[ ]"

def convert_to_bytes(size_str: str) -> float:
	units = {'B': 1, 'KB': 2**10, 'MB': 2**20, 'GB': 2**30, 'TB': 2**40}
	shift = -2
	if str.isdigit(size_str[shift]):
		shift = -1
	size, unit = size_str[:shift], size_str[shift:].upper()
	return float(size) * units[unit]

@dataclass
class MonHost:
	ip: str
	port: int
	direction: str
	l2s: float
	l10s: float
	l40s: float
	cumm: float

	def __post_init__(self):
		self.l2s = convert_to_bytes(self.l2s)
		self.l10s = convert_to_bytes(self.l10s)
		self.l40s = convert_to_bytes(self.l40s)
		self.cumm = convert_to_bytes(self.cumm)

	def get_dict(self) -> dict[str, str | float]:
		return dict(ip=self.ip, port=self.port, speed=self.l10s, cumm=self.cumm)

@dataclass
class MonHostTuple:
	num: int
	tx: MonHost
	rx: MonHost

def get_ip_port(data: str) -> tuple[str, int]:
	if ":" in data:
		(ip, port) = data.split(":")
	else:
		(ip, port) = data, 0

	port = int(port)
	return (ip, port)

def parse_iftop_results(data: str) -> list[MonHostTuple]:
	lines = data.split("\n")
	num = 0
	results = [ ]
	for s in lines:
		if re.search(pattern="  (=>)|(<=)  ", string=s):
			data = s.split()
			data_len = len(data)
			if data_len == 7:
				num = int(data[0])
				data = data[1:]
				host1 = MonHost(*get_ip_port(data[0]), *data[1:])
			elif data_len == 6:
				host2 = MonHost(*get_ip_port(data[0]), *data[1:])
				if host1:
					host = MonHostTuple(num, host1, host2)
					results.append(host)
				else:
					raise ValueError()
				host1 = None
			else:
				raise ValueError()
	return results

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
	def get_file_ctx(self, file_path: str, mode="r") -> str | bytes:
		with open(file_path, mode) as f:
			return f.read()

	def do_GET(self):
		"""
		Processes GET requests to our HTTP server.
		"""

		path = self.path

		ctx_type = "text/plain"
		msg = "Not found !"
		resp_code = 200
		is_msg_raw = False

		if path == "/":
			ctx_type = "text/html"
			msg = self.get_file_ctx("index.html")
		elif path == "/main.js":
			ctx_type = "text/javascript"
			msg = self.get_file_ctx("main.js")
		elif path == "/favicon.ico":
			ctx_type = "image/vnd.microsoft.icon"
			msg = self.get_file_ctx("favicon.ico", "b+r")
			is_msg_raw = True
		elif path == "/get_data.json":
			msg = last_mon_hosts_as_json
			ctx_type = "application/json"
		else:
			resp_code = 404

		self.send_response(resp_code)
		self.send_header("Content-Type", ctx_type)
		self.send_header("Content-Length", str(len(msg)))
		self.end_headers()
		try:
			if not is_msg_raw:
				msg_raw = msg.encode("utf-8")
			else:
				msg_raw = msg
			self.wfile.write(msg_raw)
		except BrokenPipeError:
			pass # This sometimes happens with rushed clients

class MyHTTPServer(HTTPServer):
	allow_reuse_address = True
	__need_exit: Event

	def __init__(self, need_exit: Event, *args, **kwargs):
		self.__need_exit = need_exit
		return HTTPServer.__init__(self, *args,  **kwargs)

	def service_actions(self):
		"""
		Continuously called every 0.5 seconds from the main
		serve_forever() loop.
		"""
		if self.__need_exit.is_set():
			raise KeyboardInterrupt

		HTTPServer.service_actions(self)

def http_server_thrd(need_exit: Event) -> None:
	host = "127.0.0.1"
	port = 32152
	server_address = (host, port)
	httpd = MyHTTPServer(need_exit, server_address, MyHTTPRequestHandler)
	print(f"Starting http server on http://{host}:{port}")
	try:
		httpd.serve_forever()
	except (KeyboardInterrupt, SystemExit):
		print('Stopping http server')

	# httpd.shutdown() cannot be called here, as there will be a deadloop !
	# Instead I have service_actions() -> raise KeyboardInterrupt
	httpd.server_close()
	print("The http_server_thrd() is ended")

def get_width_by_speed(mh: MonHostTuple) -> int:
	speed = mh.tx.l10s
	if speed < mh.rx.l10s:
		speed = mh.rx.l10s
	result = speed * 10 / 1000000
	if result < 1:
		return 1
	return result

def mon_hosts_to_graph(mon_hosts: list[MonHostTuple]) -> dict[str, list | dict]:
	nodes = { }
	edges = { }
	speeds = { }

	for mh in mon_hosts:
		r1, r2 = mh.tx, mh.rx
		for _ in range(2):
			id = r1.ip
			nodes[id] = dict(id=id, label=f"{id}")
			#tx/rx speed collect for ip
			sp_obj = speeds.get(id)
			if not sp_obj:
				sp_obj = dict(tx=0, rx=0)
				speeds[id] = sp_obj
			sp_obj["tx"] += r1.l10s
			sp_obj["rx"] += r2.l10s
			r1, r2 = r2, r1

		id = f"{mh.tx.ip}:{mh.tx.port}-{mh.rx.ip}:{mh.rx.port}"
		edges[id] = {
			"id": id, "from": mh.tx.ip, "to": mh.rx.ip,
			"length": 500, "width": get_width_by_speed(mh),
			#"label": f"{mh.tx.port}:{mh.rx.port}, tx: {mh.tx.l10s}, rx: {mh.rx.l10s}"
		}

	for node_key, node_obj in nodes.items():
		sp_obj = speeds.get(node_key)
		node_obj["label"] += f"\ntx: {sp_obj['tx']:,.0f}\nrx: {sp_obj['rx']:,.0f}"

	return {
		"nodes": list(nodes.values()),
		"edges": list(edges.values())
	}

try:
	need_exit = Event()
	http_srw_thrd = Thread(target=http_server_thrd, args=(need_exit,))
	http_srw_thrd.start()
	with SSHClient() as ssh_client:
		ssh_client.set_missing_host_key_policy(AutoAddPolicy())
		ssh_client.connect(hostname=ssh_host, username=ssh_login, password=ssh_passwd, port=22110)
		ssh_chan = ssh_client.invoke_shell(term="xterm", **virtual_term_size)
		cmd = IFTOP_CMD
		ssh_chan.send(cmd + "\n")
		data: str = ""
		while True:
			for _ in range(1000):
				raw_data: bytes = ssh_chan.recv(4096)
				data = data + raw_data.decode()
				if data.endswith("===========\r\n\r\n"):
					break
			mon_hosts = parse_iftop_results(data)
			data = ""
			#mon_hosts_as_dict = [ dict(tx=mht.tx.get_dict(), rx=mht.rx.get_dict()) for mht in mon_hosts ]
			mon_hosts_as_graph = mon_hosts_to_graph(mon_hosts)
			mon_hosts_as_json = json.dumps(mon_hosts_as_graph, indent=2)
			#print(mon_hosts_as_json)
			last_mon_hosts_as_json = mon_hosts_as_json
			#time.sleep(1000)

except (KeyboardInterrupt):
	pass

need_exit.set()
http_srw_thrd.join()

print("Main program is done")
