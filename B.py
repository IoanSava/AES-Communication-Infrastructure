import socket
import sys
import util

from Crypto.Cipher import AES

K3 = b'secret_key_16bit'
IV = b'initial_vector_f'
BLOCK_SIZE = 16  # Bytes


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
        sock.listen(1)
        return sock
    except socket.error as msg:
        print("Socket binding error: " + str(msg) + "\n" + "Retrying...")
        socket_bind(host, port, sock)


def communication(connection):
    mode_of_operation = connection.recv(3).decode('UTF-8')
    encrypted_key = connection.recv(16)

    aes = AES.new(K3, AES.MODE_ECB)
    key = aes.decrypt(encrypted_key)

    # initiate the communication
    connection.send('s'.encode())

    aes = AES.new(key, AES.MODE_ECB)
    if mode_of_operation == 'ecb':
        while True:
            decrypted_block = aes.decrypt(connection.recv(BLOCK_SIZE)).decode()
            print(util.unpad(decrypted_block, BLOCK_SIZE), end='')
            if util.unpad(decrypted_block, BLOCK_SIZE) != decrypted_block:
                print()
                break
    else:
        cfb_cipher = IV
        while True:
            next_cipher = connection.recv(BLOCK_SIZE)
            decrypted_block = util.byte_xor(aes.encrypt(cfb_cipher), next_cipher).decode()
            cfb_cipher = next_cipher
            print(util.unpad(decrypted_block, BLOCK_SIZE), end='')
            if util.unpad(decrypted_block, BLOCK_SIZE) != decrypted_block:
                print()
                break


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
        print('Parameters format: python B.py host port')


if __name__ == '__main__':
    main()
