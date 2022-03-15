#!usr/bin/env python3

import os
import sys

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.exceptions import InvalidSignature, InvalidTag
from python.server.DatabaseConnection import DatabaseConn

MAX_ONE_TIME_PREKEY = 100   # Num of one-time prekeys stored in server

# HKDF Specs - See https://signal.org/docs/specifications/x3dh/#cryptographic-notation
HKDF_F = b'\0xff' * 32
HKDF_LEN = 32
HKDF_SALT = b'\0' * HKDF_LEN
server = DatabaseConn()

class User():
    def __init__(self, username):
        '''
        Initializes a User object and generates keys pair. Public keys are sent 
        to the server, secret keys are kept in the object.
        
        Attributes
        ----------
        self.username: str
            Client's username.

        self.key_bundles: dictionary
            Client's "contacts". Holds "contacts" public keys

        self.secret_IK: x25519.X25519PrivateKey
            Client's secrete identity key.

        self.public_IK: x25519.X25519PublicKey
            Client's public identity key.

        self.secret_ED: ed25519.Ed25519PrivateKey
            Client's secrete Edwards key, used for signing keys.

        self.public_ED: ed25519.Ed25519PublicKey
            Client's secrete Edwards key, used for verifying signatures.
        
        self.secret_SPK: x25519.X25519PrivateKey
            Client's secrete signed prekey.

        self.public_SPK: x25519.X25519PublicKey
            Client's public signed prekey.

        self.Signature: bytes
            Output from signing public SPK with secret ED.
        
        self.secret_OTPK: list of tuples (x25519.X25519PrivateKey, x25519.X25519PublicKey)
            List holding 100 tuples (secret_OTPK, public_OTPK)

        self.public_OTPK: list of x25519.X25519PublicKey
            List holding 100 public One-time prekeys

        self.AESGCM: list of bytes
            List holding AESGCM encryption keys. Used to decrypt Client's own 
            message when viewing history.

        Returns
        ----------
        None
        '''
        self.username = username
        self.key_bundles = {}   # Stores "recent" contacts' key bundles

        self.secret_IK = x25519.X25519PrivateKey.generate()
        self.public_IK = self.secret_IK.public_key()
        
        self.secret_ED = ed25519.Ed25519PrivateKey.generate()
        self.public_ED = self.secret_ED.public_key()
        
        self.secret_SPK = x25519.X25519PrivateKey.generate()
        self.public_SPK = self.secret_SPK.public_key()

        self.Signature = self.secret_ED.sign(self.get_bytes(self.public_SPK, False))
        
        self.secret_OTPK = []
        self.public_OTPK = []

        self.AESGCM = []

        # generates OneTime Prekeys and sends to the server.
        self.generate_OTPK()
        
        # bundles public IK, EK, SPK, Signature and sends to the server.
        self.publish_key_bundle()


    def generate_OTPK(self):
        '''
        Generates 100 OneTimePrekeys pairs and sends public keys to the server.

        Parameters
        ----------
        None

        Returns
        ----------
        None
        '''
        for i in range(MAX_ONE_TIME_PREKEY):
            secret_key = x25519.X25519PrivateKey.generate()
            public_key = secret_key.public_key()

            self.secret_OTPK.append((secret_key, public_key))
            self.public_OTPK.append(public_key)

            # Convert Public OTPK into bytes and send to server
            OTPK_bytes = self.get_bytes(public_key, False)
            server.create_OTPK_table()
            server.insert_OTKP(self.username, OTPK_bytes)
        return

    def publish_key_bundle(self):
        '''
        Send public keys to the server.

        Parameters
        ----------
        None

        Returns
        ----------
        None
        '''
        server.create_KeyBundle_table()

        server.insert_KeyBundle(
            self.username,
            self.get_bytes(self.public_IK, False),
            self.get_bytes(self.public_ED, False),
            self.get_bytes(self.public_SPK, False),
            self.Signature
        )


    def encrypt_msg(self, receiver, message):
        '''
        Generates a shared key using the X3DH protocol, and encrypts
        the message using AES-GCM.

        Parameters
        ----------
        receiver: str
            Receiver username.
        
        message: str
            Message to be encrypted.

        Returns
        ----------
        encrypted_msg: bytes
            Encrypted message.
        '''
        # Get receiver's key bundle
            # get_key_bundle will add receiver to self.key_bundles[receiver]
            # access data via self.key_bundles[receiver][X], data = Object, not bytes
        self.has_key_bundle(receiver)

        recv_key_bundle = self.key_bundles[receiver]

        # Verify Signed Prekeys
        try:
            SPK_bytes = self.get_bytes(recv_key_bundle['SPK'], False)
            recv_key_bundle['ED'].verify(recv_key_bundle['Signature'], SPK_bytes)
        except InvalidSignature as err:
            return err

        # Calculate key material
        key_material = self.X3DH(receiver)

        # Calculate shared key
        shared_key = self.calc_sk(key_material)

        # Generate key combination - recv_IK + sender_EK + recv_OTPK
        key_combination = self.gen_key_combination(receiver)

        # Convert message to bytes
        message_bytes = message.encode('utf-8')
    
        # Sign msg and key combination
        signature = self.secret_ED.sign(key_combination + message_bytes)

        # Build payload
        sender_IK_bytes = self.get_bytes(self.public_IK, False)
        recv_IK_bytes = self.get_bytes(recv_key_bundle['IK'], False)

        payload = signature + sender_IK_bytes + recv_IK_bytes + message_bytes

        # Encrypt payload
        AESGCM_KEY = AESGCM(shared_key)
        self.AESGCM.append((receiver, AESGCM_KEY))
        nonce = os.urandom(12)
        ciphertext = AESGCM_KEY.encrypt(nonce=nonce, data=payload, associated_data=None)
        tag = ciphertext[-16:]

        # Build final msg to be sent
        encrypted_msg = key_combination + nonce + tag + ciphertext

        # Done using OTPK
        self.key_bundles[receiver]['OTPK'] = None

        return encrypted_msg


    def calc_sk(self, key_material) -> bytes:
        '''
        Derives a shared key from a key material; uses SHA-256.

        Parameters
        ----------
        key_meterial: bytes
            Key material from X3DH.

        Returns
        ----------
        shared_key: bytes
            Shared key from HKDF.
        '''
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=HKDF_LEN,
            salt=HKDF_SALT,
            info=None,
        )
        shared_key = hkdf.derive(key_material)

        return shared_key

    def gen_key_combination(self, receiver) -> bytes:
        '''
        Calculates key combination, which is sender_IK + sender_EK + recv_OTPK
        
        Parameters
        ----------
        receiver: str
            User to be establish shared key connection.

        Returns
        ----------
        key_combination: bytes
            The result of sender_IK + sender_EK + recv_OTPK.
        '''
        recv_key_bundle = self.key_bundles[receiver]

        sender_IK_bytes = self.get_bytes(self.public_IK, False)
        # recv_IK_bytes = self.get_bytes(recv_key_bundle['IK'], False)
        sender_EK_bytes = self.get_bytes(recv_key_bundle['public_EK'], False)
        recv_OTPK_bytes = self.get_bytes(recv_key_bundle['OTPK'], False)

        key_combination = sender_IK_bytes + sender_EK_bytes + recv_OTPK_bytes

        return key_combination
    

    def X3DH(self, receiver) -> bytes:
        '''
        Applies Extended Triple Diffie-Hellman and returns key meterial

        Parameters
        ----------
        receiver: str
            User to be establish shared key connection.

        Returns
        ----------
        key_material: bytes
            DH exchange results.
        '''
        recv_key_bundle = self.key_bundles[receiver]
        
        # verify prekey signature
        try:
            SPK_bytes = self.get_bytes(recv_key_bundle['SPK'], False)
            recv_key_bundle['ED'].verify(recv_key_bundle['Signature'], SPK_bytes)
        except InvalidSignature as err:
            return err

        # generate Ephemeral Keys
        secret_key = x25519.X25519PrivateKey.generate()
        public_key = secret_key.public_key()

        self.key_bundles[receiver]['secret_EK'] = secret_key
        self.key_bundles[receiver]['public_EK'] = public_key

        # calculate key material
        DH1 = self.secret_IK.exchange(recv_key_bundle['SPK'])
        DH2 = recv_key_bundle['secret_EK'].exchange(recv_key_bundle['IK'])
        DH3 = recv_key_bundle['secret_EK'].exchange(recv_key_bundle['SPK'])
        DH4 = recv_key_bundle['secret_EK'].exchange(recv_key_bundle['OTPK'])

        key_material = HKDF_F + DH1 + DH2 + DH3 + DH4

        # DELETE secret_EK + DH results after calculating key material
        self.key_bundles[receiver]['secret_EK'] = None
        DH1 = None
        DH2 = None
        DH3 = None
        DH4 = None

        return key_material


    def decrypt_msg(self, sender, encrypted_msg, is_own_msg):
        '''
        Calculates a shared key using the first 124 bytes of the encrypted_msg, 
        then tries to decrypt message using the calculated shared key.

        Parameters
        ----------
        sender: str
            Sender's username

        encrypted_msg: bytes
            Message to be decrypted

        is_own_msg: boolean
            Flag to determine if encrypted_msg is the User's own message.

        Returns
        ----------
        message: str
            Decrypted message.
        '''
        # Indexes to find information in encrypted msg
        IK_FIN = 32
        EK_FIN = 64
        OTPK_FIN = 96
        NONCE_FIN = OTPK_FIN + 12
        TAG_FIN = NONCE_FIN + 16

        if is_own_msg:
            # decrypt own message
            NONCE_START = OTPK_FIN
            nonce = encrypted_msg[NONCE_START: NONCE_FIN]
            tag = encrypted_msg[NONCE_FIN: TAG_FIN]
            ciphertext = encrypted_msg[TAG_FIN:]
            payload = None

            for i in range(len(self.AESGCM)):
                if(self.AESGCM[i][0] == sender):
                    try:
                        AESGCM_KEY = self.AESGCM[i][1]
                        payload = AESGCM_KEY.decrypt(nonce, ciphertext, None)
                    except InvalidTag as e:
                        continue
                    msg_contents = payload[128:]
                    decrypted_msg = msg_contents.decode()
                    return decrypted_msg

            print("ERROR - Can't find AESGCM Key")
            return

        else:
            # Retrive sender's key bundle from server
            sender_key_bundle = None

            self.has_key_bundle(sender)
            
            sender_key_bundle = self.key_bundles[sender]
            
            # Retrive sender's key bundle from msg
            msg_public_IK = encrypted_msg[:IK_FIN]
            msg_public_EK = encrypted_msg[IK_FIN: EK_FIN]
            msg_public_OTPK = encrypted_msg[EK_FIN:OTPK_FIN]
            msg_nonce = encrypted_msg[OTPK_FIN: NONCE_FIN]
            msg_tag = encrypted_msg[NONCE_FIN: TAG_FIN]
            msg_ciphertext = encrypted_msg[TAG_FIN:]
        
            # Find msg secret OTPK pair from public OTPK
            secret_OTPK = None
            for i in range(len(self.secret_OTPK)):
                tmp_public_OTPK = self.get_bytes(self.secret_OTPK[i][1], False)
                if(msg_public_OTPK == tmp_public_OTPK):
                    secret_OTPK = self.secret_OTPK[i][0]
                    break
            
            if secret_OTPK is None:
                print("ERROR - Cannot find private OneTimePrekey used!")
                return

            # Calculate key material - applying reverse X3DH
            sender_IK = self.get_pub_key(msg_public_IK, False)
            sender_EK = self.get_pub_key(msg_public_EK, False)

            DH1 = self.secret_SPK.exchange(sender_IK)
            DH2 = self.secret_IK.exchange(sender_EK)
            DH3 = self.secret_SPK.exchange(sender_EK)
            DH4 = secret_OTPK.exchange(sender_EK)

            key_material = HKDF_F + DH1 + DH2 + DH3 + DH4

            DH1 = None
            DH2 = None
            DH3 = None
            DH4 = None

            # Calculate shared_key using reverse X3DH key meterial
            shared_key = self.calc_sk(key_material)

            # Decrypt msg
            AESGCM_KEY = AESGCM(shared_key)
            payload = AESGCM_KEY.decrypt(msg_nonce, msg_ciphertext, None)

            # Check if decrypted has correct size
            if(len(payload) < 128):
                print("ERROR - Could not decrypt message")
                return

            # Deconstruct payload and extract info
            msg_signature = payload[:64]
            msg_ad = payload[64:128]
            msg_contents = payload[128:]
            
            # Check if encrypted msg AD matches server AD;  AD = sender_IK + recv_IK
            sender_IK_bytes = self.get_bytes(sender_key_bundle['IK'], False)
            recv_IK_bytes = self.get_bytes(self.public_IK, False)

            if(msg_ad != sender_IK_bytes + recv_IK_bytes):
                print("ERROR - Identity Keys don't match!")
                return

            # Verify signature and ensure key msg and key comb is intact
            key_combination = msg_public_IK + msg_public_EK + msg_public_OTPK

            try:
                sender_key_bundle['ED'].verify(msg_signature, key_combination + msg_contents)
            except InvalidSignature as err:
                return err
            # msg is decrypted + intact

            # Decode message - currently in bytes
            decrypted_msg = msg_contents.decode()

            return decrypted_msg


    def has_key_bundle(self, receiver):
        '''
        Checks if user1 has user2 key_bundle; adds user2 key_bundle to user1.
        
        Parameters
        ----------
        receiver: str
            Receiver's username.

        Returns
        ----------
        None
        '''
        # TODO - Ensure server key_bundle is up to date
        #      - Ensure sender updates receiver's key_bundle

        if receiver in self.key_bundles:
            if self.key_bundles[receiver]['OTPK'] == None:

                recv_OTPK = server.get_OTPK(recv_username=receiver)
                self.key_bundles[receiver]['OTPK'] = self.get_pub_key(recv_OTPK['OneTimePrekey'], False)

                server.delete_OTPK(receiver, recv_OTPK['OneTimePrekey'])

                if(server.get_count_OTPK(receiver) == 0):
                    self.generate_OTPK()
                return
            return

        else:
            recv_key_bundle = server.get_KeyBundle(recv_username=receiver)
            recv_OTPK = server.get_OTPK(recv_username=receiver)
        
            server.delete_OTPK(receiver, recv_OTPK['OneTimePrekey'])

            # print(receiver, server.get_count_OTPK(receiver))

            # Check count of OPTK; send more OTPK if 0
            if(server.get_count_OTPK(receiver) == 0):
                self.generate_OTPK()

            self.key_bundles[receiver] = {
                'IK': self.get_pub_key(recv_key_bundle['IdentityKey'], False),
                'ED': self.get_pub_key(recv_key_bundle['EdwardsKey'], True),
                'SPK': self.get_pub_key(recv_key_bundle['SignedPrekey'], False),
                'Signature': recv_key_bundle['Signature'],
                'OTPK': self.get_pub_key(recv_OTPK['OneTimePrekey'], False)
            }
            return


    def get_sec_key(self, secret_byte, is_Edwards):
        '''
        Converts bytes to a secret key object
        
        Parameters
        ----------
        secret_byte: bytes
            Bytes to be converted into a secret key
        
        is_Edwards: boolean
            Determines the format of converted secret key

        Returns
        ----------
        sec_key: x25519.X25519PrivateKey or ed25519.Ed25519PrivateKey
            Secret key in x25519 or ed25519 format.
        '''
        if is_Edwards is True:
            sec_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_byte)
            return sec_key

        sec_key = x25519.X25519PrivateKey.from_private_bytes(secret_byte)
        return sec_key


    def get_pub_key(self, public_byte, is_Edwards):
        '''
        Converts bytes to a public key object
        
        Parameters
        ----------
        public_byte: bytes
            Bytes to be converted into a public key
        
        is_Edwards: boolean
            Determines the format of converted public key

        Returns
        ----------
        pub_key: x25519.X25519PublicKey or ed25519.Ed25519PublicKey
            Secret key in x25519 or ed25519 format.
        '''
        if is_Edwards is True:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_byte)
            return pub_key

        pub_key = x25519.X25519PublicKey.from_public_bytes(public_byte)
        return pub_key


    def get_bytes(self, key, is_secret) -> bytes:
        '''
        Converts a key object into bytes.
        
        Parameters
        ----------
        key: x25519 or ed25519
            x25519 or ed25519 key object to be converted to bytes.
        
        is_secret: boolean
            Distinguishes which convertion method to use. True if key is secret, 
            false otherwise.

        Returns
        ----------
        key_bytes: bytes
            Bytes from given key object.
        '''
        if is_secret is True:
            key_bytes = key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            return key_bytes
        else: # key is public
            key_bytes = key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return key_bytes