import os
import socket
import sys

from Crypto.Cipher import AES

K3 = b'secret_key_16bit'


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
    K1 = os.urandom(16)  # ECB
    K2 = os.urandom(16)  # CFB
    mode_of_operation = connection.recv(3).decode('UTF-8')

    # send encrypted key to A
    aes = AES.new(K3, AES.MODE_ECB)
    if mode_of_operation == 'ecb':
        print('Send encrypted key for ECB')
        connection.send(aes.encrypt(K1))
    else:
        print('Send encrypted key for CFB')
        connection.send(aes.encrypt(K2))


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
