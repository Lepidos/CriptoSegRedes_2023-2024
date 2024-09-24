import sys
import time
import asyncio
import hashlib
from threading import Thread
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

conn_cnt = 0
conn_port = 7777
max_msg_size = 9999

class Client:
	def __init__(self, sckt=None, quit=False):
		self.id = -1
		self.mode = 0
		self.sckt = sckt
		self.msg_cnt = 0
		self.quit = quit


class ServerWorker(object):
	def __init__(self, cnt, addr=None, quit=False):
		self.mode = 0
		self.id = cnt
		self.addr = addr
		self.msg_cnt = 0
		self.quit = quit
		self.servicestr = "Please choose a security mode:\n (1) Integrity;\n (2) Simetric Encryption + Integrity;\n (3) Assimetric Encryption + Integrity + Authenticity;\n"


def process(obj, msg=b""):
	obj.msg_cnt += 1
	return msg.decode()


def process_hash(obj, msg=b""):
	obj.msg_cnt += 1
	txt = msg[:-32].decode()
	return txt


def process_fernet(obj, f, msg):
	obj.msg_cnt += 1
	txt = f.decrypt(msg)
	return txt.decode()


def process_rsa(obj, private_key, public_key, data):
	obj.msg_cnt += 1
	plaintext = private_key.decrypt(data[:-256],
	        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
	        algorithm=hashes.SHA256(),
	        label=None))
	try:
		public_key.verify(data[-256:],data[:-256],
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256())
	except:
		print ("failed to verify signature")
		return
	return plaintext.decode()


async def tcp_read(reader, obj, mod, decipher, encipher): # ALWAYS ON THE SAME MAIN THREAD
	data = await reader.read(max_msg_size)
	md5 = None
	global stop_threads
	global public_encrypt_key
	if mod == 3 and encipher == None:
		encipher = load_pem_public_key(public_encrypt_key)

	while True:
		if not data or data[:1]==b'\n':
			break
		if mod == 0:
			txt = process(obj, data)
			print(txt)
			global mode
			if mode != 1:
				try:
					public_encrypt_key = data
				except:
					pass
			break
		elif mod == 1:
			txt = process_hash(obj, data)
			md5_rcv = data[-32:].decode()
			md5 = hashlib.md5(txt.encode()).hexdigest()
		elif mod == 2:
			txt = process_fernet(obj, decipher, data)
			md5_rcv = data[-32:].decode()
			md5 = hashlib.md5(txt.encode()).hexdigest()
		elif mod == 3:
			txt = process_rsa(obj, decipher, encipher, data)
			md5 = 0
			md5_rcv = 0
		if md5 == md5_rcv:
			print('[%d] : %r' % (obj.id,txt))
		else:
			print('Integrity check failed')
		data = await reader.read(max_msg_size)
	if obj.id == -1 and not obj.quit and mod != 0:
		print("Server closed the connection")
		print("Press enter to quit")
	elif obj.id != -1 and not obj.quit and mod != 0:
		print("Client [%d] exited: Press enter to accept new connections" % obj.id)



def tcp_write(writer, obj): ## ALWAYS ON DIFERENT THREAD
	m = 5
	while m < 0 or m > 4:
		try:
			m = int(input())
		except ValueError:
		        print ("Value between 1 and 3")
	writer.write(str(m).encode())
	print ("selected " + str(m))
	global mode
	mode = m


def tcp_write_hash(writer, obj): ## ALWAYS ON DIFERENT THREAD
	while True:
		txt = input()
		if txt == '':
			writer.write(b'\n')
			obj.quit=True
			break
		else:
			txt = txt.rstrip()
			md5 = hashlib.md5(txt.encode()).hexdigest()
			new_msg = (txt + md5).encode()
			writer.write(new_msg)


def tcp_write_fernet(writer, obj, f): ## ALWAYS ON DIFERENT THREAD
	while True:
		txt = input()
		if txt == '':
			writer.write(b'\n')
			obj.quit=True
			break
		else:
			md5 = hashlib.md5(txt.encode()).hexdigest()
			txt = f.encrypt(txt.encode())
			new_msg = b"".join([txt, md5.encode()])
			writer.write(new_msg)


def tcp_write_rsa(writer, obj, public_key, private_key): ## ALWAYS ON DIFERENT THREAD
	while True:
		txt = input()
		if txt == '':
			writer.write(b'\n')
			obj.quit=True
			break
		else:
			ciphertext = public_key.encrypt(txt.encode(),
			        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
			        algorithm=hashes.SHA256(),label=None)
			        )
			signature = private_key.sign(ciphertext,
				padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH),
				hashes.SHA256())
			new_msg = b"".join([ciphertext, signature])
			writer.write(new_msg)


def tcp_write_thread(writer, obj, mod, cipher, decipher):
	if mod == 0:
		t0 = Thread(target = tcp_write, args=[writer, obj])
		t0.start()
		return t0

	elif mod == 1:
		t1 = Thread(target = tcp_write_hash, args=[writer, obj])
	elif mod == 2:
		t1 = Thread(target = tcp_write_fernet, args=[writer, obj, cipher])
	elif mod == 3:
		t1 = Thread(target = tcp_write_rsa, args=[writer, obj, cipher, decipher])
	else:
		return None
	print('Input message to send (empty to finish)')
	t1.start()
	return t1


def rsa_method(writer, reader, obj):
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	private_pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)
	decipher = serialization.load_pem_private_key(
		private_pem,password=None,backend=default_backend())
	public_key = private_key.public_key()
	public_pem = public_key.public_bytes(
	        encoding=serialization.Encoding.PEM,
	        format=serialization.PublicFormat.SubjectPublicKeyInfo)
	writer.write(public_pem)
	decipher = private_key
	return decipher


async def start_tcp_server(reader, writer):
	global conn_cnt
	quit = 0
	conn_cnt +=1
	addr = writer.get_extra_info('peername')
	srvwrk = ServerWorker(conn_cnt, addr, quit)
	# write security mode options
	writer.write(srvwrk.servicestr.encode())
	# read security mode decision
	m = await reader.read(max_msg_size)
	m = int(m.decode())
	encipher = None
	decipher = None
	print ("Client [%d] selected mode %d" % (conn_cnt, m) )
	if m == 2:
#		print("Sever waiting for key")
		key = await reader.read(max_msg_size)
		encipher = decipher = Fernet(key)
	if m == 3:
#		print("Sever waiting for key")
		data = await reader.read(max_msg_size)
		encipher = load_pem_public_key(data)
		decipher = rsa_method(writer, reader, srvwrk)

	# start writer thread
	t1 = tcp_write_thread(writer, srvwrk, m, encipher, decipher)
	print("Server reading socket")
	coro = asyncio.to_thread(await tcp_read(reader, srvwrk, m, decipher, encipher))
	task = asyncio.create_task(coro)
	# reader ended on empty msg
	writer.write(b'\n')
	await writer.drain()
	writer.close()
	t1.join()
	task.cancel()


def run_client(reader, writer, client, loop):
	print("CLIENT RUNNING")
	encipher = None
	decipher = None
	t0 = tcp_write_thread(writer, client, 0, None, None)
	loop = asyncio.get_event_loop()
	# READ FIRST MSG (MODE SELECTION MENU)
	loop.run_until_complete(tcp_read(reader, client, 0, None, None))
	t0.join()
	if mode == 2:
		key = Fernet.generate_key()
		encipher = decipher = Fernet(key)
		writer.write(key)
		print("Client generating key and sending")
	elif mode == 3: ## RSA
		decipher = rsa_method(writer, reader, client)
		loop.run_until_complete(tcp_read(reader, client, 0, decipher, None))
		encipher = load_pem_public_key(public_encrypt_key)

	t1 = tcp_write_thread(writer, client, mode, encipher, decipher)
	print("Client reading socket")
	loop.run_until_complete(tcp_read(reader, client, mode, decipher, None))
	t1.join()
	writer.write(b'\n')
	writer.close()


def run_server(loop):
	coro = asyncio.start_server(start_tcp_server, '127.0.0.1', conn_port) #this bloc>
	server = loop.run_until_complete(coro)
	print("SEVER RUNNING")
	print('Serving on {}'.format(server.sockets[0].getsockname()))
	print('  (type ^C to finish)')
	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass
	# Close the server
	server.close()
	loop.run_until_complete(server.wait_closed())
	loop.close()
	print('\nFINISHED!')


async def start_tcp_client():
	try:
		reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
	except:
		return None, None, None
	addr = writer.get_extra_info('peername')
	client = Client(addr)
	return reader, writer, client


def run():
	loop = asyncio.get_event_loop()
	reader, writer, client = loop.run_until_complete(start_tcp_client())
	if reader != None:
		run_client(reader, writer, client, loop)
	else:
		run_server(loop)

public_encrypt_key = None
stop_threads = False
mode = 0
run()
