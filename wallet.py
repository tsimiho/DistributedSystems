import base64
import binascii
import hashlib
import json
from time import time
from tokenize import generate_tokens
from urllib.parse import urlparse
from uuid import uuid4

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class Wallet:
    def __init__(self):
        self.private_key, self.public_key = self.generate_wallet()
        self.transactions = []

    def to_dict(self):
        return {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "transactions": [
                transaction.to_dict() for transaction in self.transactions
            ],
        }

    def generate_wallet(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return base64.b64encode(private_key).decode("ascii"), base64.b64encode(
            public_key
        ).decode("ascii")
