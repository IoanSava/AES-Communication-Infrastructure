import os
import socket
import sys

from Crypto.Cipher import AES

Kp = b'secret_key_16bit'


def socket_create():
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as msg:
        print('Socket creation error: ' + str(msg))
        exit(2)


def socket_bind(host, port, sock):
    try:
        server_address = (host, port)
        sock.bind(server_address)
        sock.listen(5)
        return sock
    except socket.error as msg:
        print("Socket binding error: " + str(msg) + "\n" + "Retrying...")
        socket_bind(host, port, sock)


def communication(connection):
    K = os.urandom(16)

    # send encrypted key to A
    aes = AES.new(Kp, AES.MODE_ECB)
    print('Send encrypted key')
    connection.send(aes.encrypt(K))


def socket_accept(sock):
    print("Waiting a connection")
    (connection, address) = sock.accept()
    print("Connection has been established | IP: " +
          address[0] + " | Port: " + str(address[1]))

    communication(connection)

    connection.close()
    print("Connection closed")


def main():
    try:
        host = sys.argv[1]
        port = int(sys.argv[2])
        sock = socket_create()
        sock = socket_bind(host, port, sock)
        socket_accept(sock)
    except IndexError:
        print('Parameters format: python KM.py host port')


if __name__ == '__main__':
    main()
