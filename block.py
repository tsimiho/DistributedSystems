import json
import time
from collections import OrderedDict

from Crypto.Hash import SHA256

import blockchain


class Block:
    def __init__(self, index, previous_hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = time.time()
        self.transactions = []
        self.nonce = 0
        self.validator = None
        self.current_hash = None

    def to_dict(self):
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "validator": self.validator,
            "current_hash": self.current_hash,
            "transactions": [
                transaction.to_dict() for transaction in self.transactions
            ],
        }

    def myHash(self):
        block_dict = self.to_dict()
        del block_dict['current_hash']
        block_string = json.dumps(
            block_dict, sort_keys=True
        )
        return SHA256.new(block_string.encode()).hexdigest()

    def add_transaction(self, transaction):
        self.transactions.append(transaction)
        if len(self.transactions) == self.capacity:
            print("block full")
            return "mine"

        return "not full"
