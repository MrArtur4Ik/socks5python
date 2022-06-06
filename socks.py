from socketserver import ThreadingTCPServer, StreamRequestHandler
import socket, select, traceback

SOCKS_VERSION = 0x05
METHOD_NO_AUTH = 0x00
METHOD_USERNAME_PASSWORD = 0x02
ATYPE_IPV4 = 0x01
ATYPE_DOMAINNAME = 0x03
ATYPE_IPV6 = 0x04

# КОНФИГУРАЦИЯ:
port = 2229 #Порт сервера
accounts = [("user", "user")] #Аккаунты
enable_accounts = True #Вкл/выкл аккаунты. Если выключено то сервер не требует логина и пароля.
# =============

auth_method = METHOD_USERNAME_PASSWORD if enable_accounts else METHOD_NO_AUTH

class ServerHandler(StreamRequestHandler):
	def read_string(self):
		return self.connection.recv(int.from_bytes(self.connection.recv(1), "big")).decode("utf8", errors="ignore")

	def auth(self, method):
		if method == METHOD_NO_AUTH:
			return True
		if method == METHOD_USERNAME_PASSWORD:
			connection = self.connection
			b = connection.recv(1)
			if b == b'': return False
			assert b == b'\x01'
			username, password = self.read_string(), self.read_string()
			buf = b''
			if (username, password) in accounts:
				buf += (1).to_bytes(1, "big")
				buf += b'\x00'
				connection.send(buf)
				return True
			buf += (1).to_bytes(1, "big")
			buf += b'\x01'
			connection.send(buf) 
			connection.close()
			return False
		connection.close()
		return False

	def handle(self):
		connection = self.connection
		try:
			assert int.from_bytes(connection.recv(1), "big") == SOCKS_VERSION
			nmethods = int.from_bytes(connection.recv(1), "big")
			assert nmethods > 0
			methods = []
			for i in range(nmethods):
				methods.append(int.from_bytes(connection.recv(1), "big"))
			if auth_method not in methods:
				connection.send(bytes([SOCKS_VERSION, 0xFF]))
				connection.close()
				return
			connection.send(bytes([SOCKS_VERSION, auth_method]))
			if not self.auth(auth_method): return
			b = connection.recv(1)
			if b == b'': return
			assert b == SOCKS_VERSION.to_bytes(1, "big") #Версия протокола всегда 5
			assert connection.recv(1) == b'\x01' #Пока поддерживаем только команду 0x01 (CONNECT)
			assert connection.recv(1) == b'\x00' #Резервировано
			atyp = int.from_bytes(connection.recv(1), "big")
			if atyp == ATYPE_IPV4:
				address = socket.inet_ntoa(connection.recv(4))
			elif atyp == ATYPE_DOMAINNAME:
				address = self.read_string()
			elif atyp == ATYPE_IPV6:
				address = socket.inet_ntop(socket.AF_INET6, connection.recv(16))
			else:
				connection.close()
				return
			port = int.from_bytes(connection.recv(2), "big")
			try:
				if atyp == ATYPE_IPV6:
					sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
				else:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.connect((address, port))
				bind_address = sock.getsockname()[0]
			except Exception:
				connection.close()
				return
			connection.send(bytes([SOCKS_VERSION, 0, 0, atyp if atyp == ATYPE_IPV6 else ATYPE_IPV4]) + \
				(socket.inet_pton(bind_address) if atyp == ATYPE_IPV6 else socket.inet_aton(bind_address)) + \
				int.to_bytes(port, 2, "big"))
			address_string = self.client_address[0] + ":" + str(self.client_address[1])
			print(address_string, "connected.")
			while True:
				r = select.select([connection, sock], [], [])[0]
				if connection in r:
					try: data = connection.recv(4096)
					except ConnectionResetError: break
					if sock.send(data) <= 0:
						break
				if sock in r:
					try: data = sock.recv(4096)
					except ConnectionResetError: break
					if connection.send(data) <= 0:
						break
			print(address_string, "disconnected.")
		except AssertionError:
			pass
		except Exception:
			print(traceback.format_exc())
		connection.close()

if __name__ == "__main__":
	server = ThreadingTCPServer(("", port), ServerHandler)
	try:
		print("Server started on port ", str(port), ".", sep="")
		server.serve_forever()
	except KeyboardInterrupt:
		print("Closing server...")
		server.shutdown()
		server.server_close()