import sys
import socket
import struct


ports: list[int] = [int(port) for port in sys.argv[1].split(":")]


IP: str = "!BBHHHBBH4s4s"
TCP: str = "!HHLLBBHHH"


class DataFragment:
    ip_header_start: int = 0
    ip_header_finish: int = 20

    tcp_header_start: int = 20
    tcp_header_finish: int = 40

    tcp_data: int = 40


class Protocols:
    tcp: int = 6


def sniff_packet(sock: socket.socket):
    while True:
        data, _ = sock.recvfrom(8096)

        ip_header: list[int] = struct.unpack(
            IP, data[DataFragment.ip_header_start : DataFragment.ip_header_finish]
        )

        src_ip: int = socket.inet_ntoa(ip_header[8])
        dst_ip: int = socket.inet_ntoa(ip_header[9])

        protocol: int = ip_header[6]

        if protocol == 6:
            tcp_header: list[int] = struct.unpack(
                TCP,
                data[DataFragment.tcp_header_start : DataFragment.tcp_header_finish],
            )

            port: int = tcp_header[0]
            tcp_data: bytes = data[DataFragment.tcp_data :]

            if port in ports:
                print(port, "-" * 10, tcp_data, src_ip, dst_ip)


if __name__ == "__main__":
    sock: socket.socket = socket.socket(
        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
    )

    print("Listening to ", ports)
    sniff_packet(sock)
