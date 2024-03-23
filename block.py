import json
import time
from collections import OrderedDict

from Crypto.Hash import SHA256

import blockchain


class Block:
    def __init__(self, index, validator, previous_hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = time.time()
        self.transactions = []
        self.nonce = 0
        self.validator = validator
        self.current_hash = self.myHash()

    def myHash(self):
        block_string = json.dumps(
            self.__dict__, sort_keys=True
        )  # might need to adjust to only include serializable attributes
        return SHA256.new(block_string.encode()).hexdigest()

    def add_transaction(self, transaction):
        self.listOfTransactions.append(transaction)
        self.hash = self.calculate_hash()
