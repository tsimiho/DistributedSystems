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
        self.listOfTransactions = []
        self.nonce = 0
        self.validator = None
        self.current_hash = self.myHash()
        self.capacity = 2

    def myHash(self):
        block_string = json.dumps(
            self.__dict__, sort_keys=True
        )  # might need to adjust to only include serializable attributes
        return SHA256.new(block_string.encode()).hexdigest()

    def add_transaction(self, transaction):
        self.listOfTransactions.append(transaction)
        if len(self.listOfTransactions) == self.capacity:
            print("block full")
            return "mine"

        return "not full"
