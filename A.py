import socket
import sys

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


def pad(block):
    padding_length = BLOCK_SIZE - (len(block) % BLOCK_SIZE)
    return block + padding_length * chr(padding_length)


def byte_xor(byte1, byte2):
    parts = []
    for b1, b2 in zip(byte1, byte2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)


def communication(server_sock, B_sock):
    mode_of_operation = choose_mode_of_operation()
    B_sock.send(mode_of_operation.encode())
    server_sock.send(mode_of_operation.encode())

    encrypted_key = server_sock.recv(16)
    B_sock.send(encrypted_key)

    aes = AES.new(K3, AES.MODE_ECB)
    key = aes.decrypt(encrypted_key)

    # waiting for B to initiate communication
    B_sock.recv(1)
    print('B initialized communication')

    end_of_file = False
    file = open(sys.argv[5], 'r')
    aes = AES.new(key, AES.MODE_ECB)
    cfb_cipher = IV
    while not end_of_file:
        current_block = file.read(BLOCK_SIZE)

        if len(current_block) < BLOCK_SIZE:
            end_of_file = True
            current_block = pad(current_block)

        if mode_of_operation == 'ecb':
            B_sock.send(aes.encrypt(current_block.encode()))
        else:
            cfb_cipher = byte_xor(aes.encrypt(cfb_cipher), current_block.encode())
            B_sock.send(cfb_cipher)


def main():
    try:
        server_host = sys.argv[1]
        server_port = int(sys.argv[2])
        server_sock = connect_to_node(server_host, server_port)

        B_host = sys.argv[3]
        B_port = int(sys.argv[4])
        B_sock = connect_to_node(B_host, B_port)

        communication(server_sock, B_sock)

        server_sock.close()
        B_sock.close()
    except IndexError:
        print('Parameters format: python A.py server_host server_port B_host B_port')


if __name__ == '__main__':
    main()
