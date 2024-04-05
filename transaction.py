import base64
import binascii
import json
from collections import OrderedDict

import Crypto
import Crypto.Random
import requests
from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from flask import Flask, jsonify, render_template, request


class Transaction:
    def __init__(
        self,
        sender_address,
        receiver_address,
        type_of_transaction,
        amount,
        message,
        nonce,
    ):
        self.sender_address = sender_address
        self.receiver_address = receiver_address
        self.amount = amount
        self.type_of_transaction = type_of_transaction
        self.message = message
        self.nonce = nonce
        self.signature = None
        self.transaction_id = self.calculate_transaction_id()

    def calculate_transaction_id(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return SHA256.new(block_string.encode()).hexdigest()

    def sign_transaction(self, private_key):
        message = self.transaction_id.encode()
        key = RSA.importKey(base64.b64decode(private_key))
        h = SHA256.new(message)
        signer = PKCS1_v1_5.new(key)
        self.signature =  base64.b64encode(signer.sign(h)).decode()
    """
    def calculate_fee(self):
        if self.type_of_transaction == "coins":
            return self.amount * 0.03
        else:
            return 0
    """
