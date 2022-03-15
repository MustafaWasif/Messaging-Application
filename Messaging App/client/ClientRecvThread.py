#!/usr/bin/env python3

import binascii
from sys import *
import os
from time import *
from socket import *
from threading import *
from queue import *
import json

import config
from encryption import User
import binascii

# Image conversion
from PIL import Image
import io
import base64

#colored output
from termcolor import colored, cprint

'''
Basic ClientRecvThread class for the client-side to continually listen to the server.
'''

class ClientRecvThread(Thread):
    def __init__(self, socket, address, username):    #Inherit from Thread class
        '''
        Initializes a ClientRecvThread instance as a subclass of threading.Thread.
        This thread continually listens for responses from the server. Once
        initialized, the thread begins execution inside self.run(), which
        is called by the main thread (parent).

        Attributes
        ----------
        self.sock: socket.socket
            The server's socket connection object.

        self.addr: socket.AF_INET
            The server's IPv4 address that they are connected from. 

        self.username: str
            The username of the logged-in client account.

        self.enc_user: encryption.User
            An instance of encryption.User class that handles both X3DH key exchange,
            and AES-GCM message encryption/decryption.

        Returns
        ----------
        None
        '''
        Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.username = username
        self.enc_user = None

        if(not config.username):
            self.enc_user = User(username)
            config.username = self.enc_user
        else:
            self.enc_user = config.username


    def locked_print(self, message_str):
        '''
        Print function to handle the shared resource of stdout file descriptor.
        The Lock object is instantiated once and shared in the config file among
        both client threads. This lock must be acquired by a running thread before
        that thread can print any content to the screen. Once work is complete,
        the lock is released and can be acquired by any other thread.

        Solves the Producer/Consumer resource contention problem.

        Parameters
        ----------
        message_str: str
            The desired message to be printed to the console.

        Returns
        ----------
        None
        '''
        try:
            config.lock.acquire()
            print(message_str)
            config.lock.release()
            return

        except:
            #print("Error acquiring the lock for printing!")
            return

    
    def clear_screen(self):
        '''
        Function to clear the screen (stdout) for a running client. Checks
        whether the machine is running Windows or Linux, and then clears
        the screen appropriately.

        Parameters
        ----------
        None

        Returns
        ----------
        None
        '''
        os.system('cls' if os.name == 'nt' else 'clear')
        return

    
    def join_chat(self, other_username):
        '''
        RecvThread initialization for entering a real-time chat with another user.
        The user can now input any text, and that text becomes sent as a message
        to the connected client. Quitting the chat involves the '--quit' command,
        which notifies both clients that the chat has closed.

        Parameters
        ----------
        other_username: str
            The other client's username also connected to the chat.

        Returns
        ----------
        None
        '''
        #initial chat welcoming
        welcome_msg = "Now chatting with " + str(other_username) + "."
        color_msg = colored(welcome_msg, 'yellow')
        self.locked_print(color_msg)
        self.locked_print("")

        #allow the SendThread to enter the chat
        config.shared_event.set()
        config.shared_event.clear()

        #listen to the chat and handle incoming messages
        while True:
            try:
                data = b''
                part = b''

                while True:
                    part = self.sock.recv(1024)
                    data += part

                    if len(part) < 1024:
                        break
                
                message_data = data

                #chat connection was closed - stop listening
                if not(message_data):
                    return

                #parse the message into a dictionary
                message_json = json.loads(message_data)

                #print out the formatted message in blue to the client console
                if(message_json['command'] == 'message-recv'):
                    
                    # convert str message to hex, then to a bytes type
                    enc_msg_hex = message_json['message'].encode('utf-8')
                    enc_msg_bytes = binascii.unhexlify(enc_msg_hex)

                    # decrypt the AESGCM-encrypted message
                    decrypted_msg = self.enc_user.decrypt_msg(other_username, enc_msg_bytes, False)

                    #handle image messages
                    if(message_json['image_name'] != "false"):
                        encoded_img_string = decrypted_msg.encode('utf-8')
                        # convert img str to base64 bytes
                        img_bytes = binascii.unhexlify(encoded_img_string)
                        f = base64.b64decode(img_bytes)

                        # convert b64 to .png
                        pilimage = Image.open(io.BytesIO(f))
                        img_path = message_json['image_name']
                        img_name = img_path.split('\\')[-1].strip('\"')
                        img_dir = img_path.strip(img_name + '\\\"')
                        
                        # save image
                        try:
                            # get current dir path
                            cur_dir = os.getcwd()   
                            
                            # get pic directory - assuming cur_dir is the root of project folder
                            pic_dir = cur_dir + "\\python\\client\\pictures\\" + self.username + "\\" + other_username
                            
                            # check if dir already exists
                            if os.path.isdir(pic_dir) is True: 
                                continue
                            else:
                                try:
                                    # recursive function to create dirs needed for leaf dir
                                    os.makedirs(pic_dir)
                                except Exception as e:
                                    print(e)
                                    print("ERROR - Could not create directories!")
                            
                            img_dir = pic_dir + "\\"

                            pilimage = pilimage.save(img_dir + img_name)
                            
                            self.locked_print('\033[94m' + "Image Received: " + img_name + "  Saved: " + img_dir + img_name + '\033[0m')

                        except Exception as e:
                            print(e)
                            print("ERROR - Could not save image!")
                            return


                    #handle regular messages
                    else:
                        message_str = str(other_username) + ": " + str(decrypted_msg)
                        self.locked_print('\033[94m' + message_str + '\033[0m')

                #server-sent notification that the chat was closed
                elif(message_json['command'] == 'exit-chat'):
                    self.locked_print('\033[1m' + message_json['message'] + '\033[0m')

                    #reset the shared connected_username variable
                    config.connected_username = None

                    #release the blocked sender thread
                    config.shared_event.set()
                    config.shared_event.clear()
                    return


            #exit chat on any exception
            except Exception as e:
                self.locked_print(str(e))
                return


    def confirm_chat_opened(self, confirm_msg, recv_username):
        '''
        ClientA's RecvThread handling to confirm that the other user
        accepted the chat. The chat scope is initiated here, and ClientA's
        RecvThread is unblocked to allow entry into the chat.

        Parameters
        ----------
        confirm_msg: str
            A chat confirmation message to be displayed on ClientA's screen.

        recv_username: str
            The username of the other client being connected with.

        Returns
        ----------
        None
        '''
        self.clear_screen()
        self.locked_print(confirm_msg)
        sleep(1)

        #set the event such that the sender thread can continue
        config.shared_event.set()
        config.shared_event.clear()

        #listen to the new chat
        #receiver-side user chat scenario
        self.join_chat(recv_username)
        return

    
    def accept_chat_req(self, send_username):
        '''
        ClientB's RecvThread handling to send a confirmation to the server
        that ClientB accepts the chat request. The RecvThread actually performs
        a single send() here, to notify the server. The chat scope is entered
        from here.

        Parameters
        ----------
        send_username: str
            The username of the other client who initiated the chat request.

        Returns
        ----------
        None
        '''
        #ask user if connection should be established
        config.connected_username = send_username
        self.locked_print("Would you like to chat with " + send_username + "? Answer Y/N")
        
        #wait on SendThread to accept the request
        config.shared_event.wait()

        #create formatted response string for the server
        resp_to_connect = (json.dumps({
            'command':'accept-chat-req',
            'response':'SUCCESS', 
            'send_username': send_username, 
            'recv_username':self.username,
            'message':'The other client accepted the chat request.'
        })).encode()
        self.sock.send(resp_to_connect)

        #listen to the new chat
        #receiver-side user chat scenario
        self.clear_screen()
        self.locked_print("You accepted to join the chat.")
        sleep(1)
        self.join_chat(send_username)
        return


    def format_message_history(self, other_username, message_list):
        '''
        Formats the conversation history (list of messages) that is
        received from the server upon a '--history' request from the
        SendThread. Message history is formatted as 'You:' for own
        sent messages, and '<user>:' for messages received from the
        other client.

        Parameters
        ----------
        other_username: str
            The username of the other client involved in the message history.

        message_list: list
            The list of message tuples (unformatted) that are received from the server.
            This list represents a conversation history that this client had with another.

        Returns
        ----------
        None
        '''
        #format each message list and print to client screen
        self.clear_screen()
        self.locked_print("")
        self.locked_print("--- Conversation history with " + str(other_username) + ": ---")

        # flag to open pic_dir
        flag = False
        

        for row in message_list:
            try:
                #decrypt the sent messages from the server, then format and print to screen
                encr_message = str(row[3])
                enc_msg_hex = encr_message.encode('utf-8')
                enc_msg_bytes = binascii.unhexlify(enc_msg_hex)

                #own messages to the other client (outgoing)
                if(str(row[1]) == self.username):
                    decrypted_msg = self.enc_user.decrypt_msg(other_username, enc_msg_bytes, True)
                    message = decrypted_msg

                    if row[4] == "false":    # no image attached
                        self.locked_print("You: " + message)
                    else:
                        # get img path, name, and directory
                        img_path = row[4]
                        img_name = img_path.split('\\')[-1].strip('\"')
                        img_dir = img_path.strip(img_name + '\\\"')

                        # print image name and from where
                        msg = "Image Sent: " + img_name + " from: " + img_dir
                        self.locked_print("You: " + msg)


                #own messages from the other client (incoming)
                elif(str(row[1]) == other_username):
                    decrypted_msg = self.enc_user.decrypt_msg(other_username, enc_msg_bytes, False)
                    message = decrypted_msg
                    message_str = other_username + ": "

                    if row[4] == "false":    # no image attached
                        self.locked_print('\033[94m' + message_str + message + '\033[0m')
                    else:
                        img_path = row[4]
                        img_name = img_path.split('\\')[-1].strip('\"')
                        img_dir = img_path.strip(img_name + '\\\"')

                        self.locked_print('\033[94m' + message_str + "Image Received: " + img_name + '\033[0m')
                        flag = True

            except Exception as e:
                self.locked_print(e)
                return
        
        # open image directory
        if flag is True:
            # get current dir path
            cur_dir = os.getcwd()   
            
            # get pic directory - assuming cur_dir is the root of project folder
            pic_dir = cur_dir + "\\python\\client\\pictures\\" + self.username + "\\" + other_username

            # pop directory window
            try:
                os.startfile(pic_dir)
            except Exception as e:
                print(e)
                print("ERROR - Directory doesn't exist!")
                return

            # reset pic_dir and flag - not sure if needed, just for safety
            pic_dir = ""
            flag = False

        self.locked_print("")
        return


    def listen(self):
        '''
        The main program loop of the ClientRecvThread. Continually listens for data from
        the server over the TCP socket connection, and handles server responses appropriately.

        Should this function return, this RecvThread is terminated.

        Parameters
        ----------
        None

        Returns
        ----------
        None
        '''
        running = True
        while running:
            try:
                # receiving serialized data in chunks
                data = b''
                part = b''

                while True:
                    part = self.sock.recv(1024)
                    data += part

                    if len(part) < 1024:
                        break
                
                server_data = data
                server_data = server_data.decode()

                #server closed the connection - terminate the threads
                if not(server_data):
                    return

                #parse the server's message into a dictionary
                server_resp = json.loads(server_data)

                #Enter Chat Part 2 - receive chat request from a sender client
                if(server_resp['command'] == 'req-chat-from'):
                    self.clear_screen()
                    self.accept_chat_req(server_resp['send_username'])

                #Enter Chat Part 6 - receive 'new chat' response from a receiver client
                elif(server_resp['command'] == 'chat-confirmed'):
                    self.confirm_chat_opened(server_resp['message'], server_resp['recv_username'])

                #handle receiving conversation history from the server
                elif(server_resp['command'] == 'history'):
                    #destringify the message list back into a list - apply literal_eval again
                    message_list = server_resp['message_list']
                    if message_list:
                        self.format_message_history(server_resp['other_username'], message_list)
                    else:
                        self.locked_print("")
                        self.locked_print("There is no message history with " + server_resp['other_username'] + " to be displayed.")

                    #release the SendThread to ask for input again
                    config.shared_event.set()
                    config.shared_event.clear()

                #handle deleting conversation history with a specific client from the server
                elif(server_resp['command'] == 'delete-history'):
                    self.locked_print(server_resp['message'])

                    config.shared_event.set()
                    config.shared_event.clear()

                #handle deleting ALL conversation histories - required at the end of every session
                elif(server_resp['command'] == 'delete-all-histories'):
                    self.locked_print(server_resp['message'])
                    
                    config.shared_event.set()
                    config.shared_event.clear()
                    
                    return

                #handle your account deletion - terminates the session
                elif(server_resp['command'] == 'delete-account'):
                    self.locked_print(server_resp['message'])

                    config.shared_event.set()
                    config.shared_event.clear()
                    return
                
            #exit on any exception type
            except Exception as e:
                self.locked_print(e)
                return

        return


    def run(self):
        '''
        threading.Thread function override to instantiate objects and determine the flow of the
        thread's execution. When this function returns, the thread terminates.

        Parameters
        ----------
        None

        Returns
        ----------
        None
        '''  
        self.listen()
        return
