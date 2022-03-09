from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from utils import *
from constants import *
import socket, select, config

class MultithreadingServer(TCPServer, ThreadingMixIn):
	pass

class Socks5Handler(StreamRequestHandler):
	def read_string(self):
		return self.connection.recv(get_int_from_bytes(self.connection.recv(1))).decode("utf8", errors="ignore")

	def auth(self):
		connection = self.connection
		assert connection.recv(1) == get_byte(1) #почему 1 а не 5? а хуй его знает
		username, password = self.read_string(), self.read_string()
		if (username, password) == config.auth:
			connection.send(get_byte(SOCKS_VERSION))
			connection.send(get_byte(0x00))
			return True
		connection.send(get_byte(SOCKS_VERSION))
		connection.send(get_byte(0x01))
		connection.close()
		return False

	def handle(self):
		connection = self.connection
		assert connection.recv(1) == get_byte(SOCKS_VERSION)
		nmethods = get_int_from_bytes(connection.recv(1))
		assert nmethods > 0
		methods = []
		for i in range(nmethods):
			methods.append(get_int_from_bytes(connection.recv(1)))
		if config.auth_method not in methods:
			connection.close()
			return
		connection.send(get_byte(SOCKS_VERSION))
		connection.send(get_byte(config.auth_method))
		if not self.auth(): return
		#=====
		assert connection.recv(1) == get_byte(SOCKS_VERSION) #Версия протокола всегда 5
		assert connection.recv(1) == get_byte(1) #Пока поддерживаем только команду 0x01 (CONNECT)
		assert connection.recv(1) == get_byte(0) #Резервировано
		atype = get_int_from_bytes(connection.recv(1))
		if atype == ATYPE_IPV4:
			hostname = socket.inet_ntoa(connection.recv(4))
		elif atype == ATYPE_DOMAINNAME:
			hostname = connection.recv(get_int_from_bytes(connection.recv(1))).decode("utf8", errors="ignore")
		else: #IPv6 потом...
			connection.close()
			return
		port = get_int_from_bytes(connection.recv(2))
		return
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((hostname, port))
			bind_address = sock.getsockname()[0]
		except Exception:
			connection.close()
			return
		connection.send(bytes([SOCKS_VERSION, 0, 0, 1]))
		connection.send(socket.inet_aton(bind_address))
		connection.send(int.to_bytes(port, 2, "big"))
		while True:
			r = select.select([connection, sock], [], [])[0]
			if connection in r:
				data = connection.recv(4096)
				if sock.send(data) <= 0:
					break
			if sock in r:
				data = sock.recv(4096)
				if connection.send(data) <= 0:
					break
		connection.close()

if __name__ == "__main__":
	server = TCPServer(("", 8080), Socks5Handler)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		server.server_close()