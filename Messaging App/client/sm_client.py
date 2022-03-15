#!/usr/bin/env python3

from sys import *
from socket import *
from threading import *
from queue import *
from sqlite3 import *
import os
from time import *
import json
import binascii
import getpass

import config

from ClientSendThread import ClientSendThread
from ClientRecvThread import ClientRecvThread

from cryptography.hazmat.primitives import hashes

#----- Client Parameters -----
SERVER_HOST = '127.0.0.1'                    #bind to public IP
SERVER_PORT = 50007                          #TCP Port that the server runs at
sock = socket(AF_INET, SOCK_STREAM)          #connection object to the server for client-to-client interactions
client_username = None                       #logged in client's username - to pass to client's child threads

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
    return


def register_attempt():
    clear_screen()
    first_name = input("First name: ")
    last_name = input("Last name: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    try:
        # start pass encryption
        reg_digest = hashes.Hash(hashes.SHA256())
        # generate random 16 byte salt
        salt = os.urandom(16)
        # calc hash from password
        reg_digest.update(password.encode('utf-8'))
        hash_pass = reg_digest.finalize()
        # append salt to hash
        hash_pass += salt
        salt = None
        # parse encrypted_pass to str format and send to server
        hash_pass_bytes = binascii.hexlify(hash_pass)
        hash_pass_str = hash_pass_bytes.decode()

        #send formatted registration data to server
        regist_req = (json.dumps({
            'command':'register', 
            'first':first_name,
            'last':last_name,
            'username':username, 
            'password':hash_pass_str
        })).encode()

        sock.send(regist_req)

        #receive response from server
        server_resp = json.loads(sock.recv(1024).decode())
        print("Server response type: " + str(server_resp['response']))

        if(server_resp['response'] == 'SUCCESS'):
            print(server_resp['message'])
            return 1

        elif(server_resp['response'] == 'FAILURE'):
            print("Registration attempt failed!")
            return 0

    except:
        print("Something went wrong...")
        return 0


def login_attempt():
    clear_screen()
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    try:
        #send formatted login data to server
        login_req = (json.dumps({
            'command':'login', 
            'username':username, 
            'password':password
        })).encode()

        sock.send(login_req)

        #receive response from server
        server_resp = json.loads(sock.recv(1024).decode())
        print("Server response type: " + str(server_resp['response']))

        if(server_resp['response'] == 'SUCCESS'):
            print("Log in attempt was successful.")
            global client_username
            client_username = username
            sleep(1)
            return 1

        elif(server_resp['response'] == 'FAILURE'):
            print("Log in attempt failed!")
            return 0

    except:
        print("Something went wrong...")
        return 0


def display_login_options():
    #display welcome message & user login menu options
    print("")
    print("----- Welcome to Python CLI Secure Messaging! -----")
    print("OPTIONS:")
    print("--login          Log in to an existing user account.")
    print("--register       Create a new user account.")
    print("--exit           Gracefully exit Python CLI Secure Messaging.")
    print("")


def login_or_register():
    #offer client login options
    sleep(1)
    clear_screen()
    display_login_options()

    #user option loop
    while True:

        try:
            #get user's option selection
            option = input(">> ")

            if not option:
                continue

            #handle options
            if(option == "--options"):
                clear_screen()
                display_login_options()
                continue

            #handle login
            if(option == "--login"):
                result = login_attempt()

                if(result):
                    clear_screen()
                    print("Logged in as " + client_username)
                    break

            #handle account registration
            elif(option == "--register"):
                result = register_attempt()
                
                if(result):
                    clear_screen()
                    print("Account registration successful.")
                    continue

            #handle program exit
            elif(option == "--exit"):
                close_server_conn()
                return 0

            else:
                print("Please pass a valid command.")
                continue

        #terminate the client on keyboard interrupt
        except KeyboardInterrupt:
            close_server_conn()
            return 0

    return 1


def close_server_conn():
    #notify the server that connection should be terminated
    sock.shutdown(SHUT_RDWR)
    sock.close()
    print("Connection was closed. Program is exiting gracefully.")
    return


def start_client():

    #create socket connection
    sock.connect((SERVER_HOST, SERVER_PORT))

    #receive connection message from server
    recv_msg = sock.recv(1024).decode()
    print(recv_msg)

    #--- Login Menu ---
    while True:

        #initial login/registration handling
        if(not login_or_register()):
            break

        #user has logged in: create 2 threads - one for sending, one for receiving
        send_thread = ClientSendThread(sock, (SERVER_HOST, SERVER_PORT), client_username)
        recv_thread = ClientRecvThread(sock, (SERVER_HOST, SERVER_PORT), client_username)

        #set threads to daemons for auto cleanup on program exit
        send_thread.daemon = True
        recv_thread.daemon = True
        
        send_thread.start()
        recv_thread.start()

        #delay loop to check for connection closing
        while True:
            try:
                send_thread.join()
                recv_thread.join()

                #return to login menu scope
                print("Logging out of " + client_username)

                # clear config files for next user
                config.shared_event.clear()
                config.connections = {}
                config.connected_username = None
                config.username = None
                break

            #exit program - daemon threads are cleaned up automatically
            except (BaseException, KeyboardInterrupt) as e:
                print("Gracefully closing the client program.")
                return

    return


if __name__ == "__main__":
    start_client()