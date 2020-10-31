import socket
import sys
from sources import util

from Crypto.Cipher import AES

K3 = b'secret_key_16bit'
IV = b'initial_vector_f'
BLOCK_SIZE = 16  # Bytes


def connect_to_node(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    address = (host, port)
    sock.connect(address)
    return sock


def choose_mode_of_operation():
    print('Choose mode of operation (ECB/CFB): ', end='')
    mode_of_operation = input()
    while mode_of_operation not in ('ecb', 'cfb'):
        print('Invalid mode of operation. Choose between ECB and CFB: ', end='')
        mode_of_operation = input()

    return mode_of_operation


def communication(server_sock, b_sock):
    mode_of_operation = choose_mode_of_operation()
    b_sock.send(mode_of_operation.encode())
    server_sock.send(mode_of_operation.encode())

    encrypted_key = server_sock.recv(16)
    b_sock.send(encrypted_key)

    aes = AES.new(K3, AES.MODE_ECB)
    key = aes.decrypt(encrypted_key)

    # waiting for B to initiate communication
    b_sock.recv(1)
    print('B initialized communication')

    end_of_file = False
    file = open(sys.argv[5], 'r')
    aes = AES.new(key, AES.MODE_ECB)
    cfb_cipher = IV
    while not end_of_file:
        current_block = file.read(BLOCK_SIZE)

        if len(current_block) < BLOCK_SIZE:
            if len(current_block) == 0:
                break
            end_of_file = True
            current_block = util.pad(current_block, BLOCK_SIZE)

        print('Sending ', current_block)

        if mode_of_operation == 'ecb':
            b_sock.send(aes.encrypt(current_block.encode()))
        else:
            cfb_cipher = util.byte_xor(aes.encrypt(cfb_cipher), current_block.encode())
            b_sock.send(cfb_cipher)


def main():
    try:
        server_host = sys.argv[1]
        server_port = int(sys.argv[2])
        server_sock = connect_to_node(server_host, server_port)

        b_host = sys.argv[3]
        b_port = int(sys.argv[4])
        b_sock = connect_to_node(b_host, b_port)

        communication(server_sock, b_sock)

        server_sock.close()
        b_sock.close()
    except IndexError:
        print('Parameters format: python A.py server_host server_port b_host b_port filename')


if __name__ == '__main__':
    main()
