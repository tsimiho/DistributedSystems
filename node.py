import base64
import hashlib
import json
import random
import threading
from collections import deque
from copy import deepcopy
from threading import Lock, Thread

import requests
from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import blockchain
from block import Block
from transaction import Transaction
from wallet import Wallet


class Node:
    def __init__(
        self,
        id=None,
        number_of_nodes=None,
        blockchain=None,
        ip_address=None,
        port=None,
        capacity=None,
    ):
        self.id = id
        self.chain = blockchain
        self.current_id_count = 0
        # self.wallet = Wallet()
        self.ring = {}
        self.soft_state = {}
        self.nonce = 0
        self.stake = 1
        self.balance = 0
        self.current_block = None
        self.number_of_nodes = number_of_nodes
        self.transactions = None
        self.ip_address = ip_address
        self.port = port
        self.capacity = capacity

    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.ip_address,
            'port': self.port,
            'public_key': self.wallet.public_key,
            'balance' : self.balance,
            'stake' : self.stake
        }

    def create_new_block(self):
        if len(self.chain.blocks) == 0:
            # Here, the genesis block is created.
            new_idx = 0
            previous_hash = 1
            self.current_block = Block(new_idx, previous_hash)
        else:
            # They will be updated in mining.
            self.current_block = Block(None, None)

        return self.current_block

    def create_transaction(
        self, sender_address, receiver_address, type_of_transaction, amount, message
    ):
        self.nonce += 1
        transaction = Transaction(
            sender_address,
            receiver_address,
            type_of_transaction,
            amount,
            message,
            self.nonce,
        )
        signature = transaction.sign_transaction(self.wallet.private_key)
        print("Create transaction")
        self.broadcast_transaction(transaction)

        return True

    def verify_signature(self, transaction):
        key = RSA.importKey(base64.b64decode(transaction.sender_address))
        h = transaction.calculate_transaction_id()
        verifier = PKCS1_v1_5.new(key)
        return verifier.verify(h, base64.b64decode(transaction.signature))

    def validate_transaction(self, transaction):
        verify = self.verify_signature(transaction)
        if verify == False:
            return False

        if transaction.type_of_transaction == "coins":
            balance_needed = 1.03 * transaction.amount
        elif transaction.type_of_transaction == "message":
            balance_needed = len(transaction.message)
        else:
            print("Wrong type of transaction.")
            return False

        sender = self.soft_state[transaction.sender_address]
        if balance_needed > sender.balance - sender.stake:
            return False
        else:
            #sender.balance -= balance_needed
            self.soft_state[sender.public_key]['balance'] -= balance_needed

            self.transactions.append(transaction)
            if len(self.transactions) == self.capacity:
                self.mine_block()
                #self.transactions = []

    def lottery(self, hash):
        seed = int(hashlib.sha256(hash.encode()).hexdigest(), 16)
        random.seed(seed)
        tickets = []
        for _, node in self.ring.items():
            tickets.extend([node.public_key] * node.stake)
        if not tickets:
            return None
        selected_validator_pubkey = random.choice(tickets)
        return selected_validator_pubkey

    def mine_block(self):
        print("Mine block")
        prev_hash = self.chain.blocks[-1].current_hash
        validator_key = self.lottery(prev_hash)
        print(validator_key)
        if self.wallet.public_key == validator_key:
            for i in range(self.capacity):
                self.add_transaction_to_block(self.transactions[i])
            self.current_block.validator = validator_key
            self.chain.add_block_to_chain(self.current_block)
            self.ring = self.soft_state
            self.broadcast_block(self.current_block)
            index = len(self.chain.blocks)
            current_hash = self.current_block.current_hash
            block = Block(index, current_hash)
            self.transactions = self.transactions[self.capacity:]
            self.current_block = block  
        

    # function to check if the validator is the correct and if the previous block has is correct
    def validate_block(self, block):
        if (block.validator == self.lottery(self.chain.blocks[-1].current_hash)) and (
            block.previous_hash == self.chain.blocks[-1].current_hash
        ):
            self.chain.add_block_to_chain(self.current_block)
            for t in block.transactions:
                for tt in self.transactions:
                    if (t.equals(tt)):
                        self.transactions.remove(tt)
                if t.type_of_transaction == 'coins':
                    if (1.03 * t.amount <= self.ring[t.sender_address].balance - self.ring[t.sender_address].stake):
                        self.ring[t.sender_address].balance -= 1.03 * t.amount
                        self.ring[t.receiver_address].balance += t.amount
                        self.ring[block.vaidator].balance += 0.03 * t.amount
                    else:
                        return False
                elif t.type_of_transaction == 'message':
                    if (len(t.message) <= self.ring[t.sender_address].balance - self.ring[t.sender_address].stake):
                        self.ring[t.sender_address].balance -= len(t.message)
                        self.ring[block.vaidator].balance += len(t.message)
                    else:
                        return False
                elif t.type_of_transaction == 'stake':
                    if (t.amount <= self.ring[t.sender_address].balance):
                        self.ring[t.sender_address].stake = t.amount
                    else:
                        return False                    
                else:
                    return False
            index = len(self.chain.blocks)
            current_hash = block.current_hash
            self.current_block = Block(index, current_hash)
            return True
        else:
            return False

    def validate_chain(self, chain):
        for i in range(1, len(chain.blocks)):
            block = chain.blocks[i]
            prev_block = chain.blocks[i - 1]
            if not self.validate_block(block, prev_block):
                return False
        return True

    def set_stake(self, amount):
        return self.create_transaction(self.wallet.public_key, 0, "stake", amount, None)

    def register_node_to_ring(self, node):
        self.ring[node.public_key] = node
        self.soft_state[node.public_key] = node
        if len(self.ring.items()) > 1:
            self.create_transaction(
                self.wallet.public_key, node.public_key, "coins", 1000, None
            )

        if len(self.ring.items()) == self.number_of_nodes:
            self.broadcast_ring()

    # NOT READY YET
    # Method to add transaction in block, updates wallet transaction for each node and checks if the block is ready to be mined
    def add_transaction_to_block(self, transaction):
        # Add the transaction in node's wallet, if it is the recepient or the sender
        if (transaction.receiver_address == self.wallet.public_key) or (
            transaction.sender_address == self.wallet.public_key
        ):
            self.wallet.transactions.append(transaction)
            #self.nonce += 1
        # print(self.ring)
        # Update the balance of the recipient and the sender.
        for _, node in self.ring.items():
            print(transaction.type_of_transaction)
            if node.wallet.public_key == transaction.sender_address:
                print("Here")
                if transaction.type_of_transaction == "message":
                    print("It's a message")
                    self.balance -= len(transaction.message)
                else:
                    self.balance -= transaction.amount
            if node.wallet.public_key == transaction.receiver_address:
                self.balance += transaction.amount

        # If the chain contains only the genesis block, a new block
        # is created. In other cases, the block is created after mining.
        if self.current_block is None:
            self.current_block = self.create_new_block()

        #self.current_block.total += transaction.amount

    def broadcast_transaction(self, transaction):
        print("broadcast_transaction")
        lock = Lock()

        def thread_target(node, responses):
            if node.wallet.public_key != self.wallet.public_key:
                url = f"http://{node.ip_address}:{node.port}/broadcast_transaction"
                try:
                    res = requests.post(
                        url, json={"transaction": json.dumps(transaction.__dict__)}
                    )
                    with lock:
                        responses.append(res.status_code == 200)
                except Exception as e:
                    print(f"Failed to broadcast transaction: {e}")

        threads = []
        responses = []
        for _, node in self.ring.items():
            thread = Thread(target=thread_target, args=(node, responses))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if all(responses):
            self.add_transaction_to_block(transaction)

    def broadcast_block(self, block):
        print("broadcast_block")
        def thread_target(node, responses):
            if node.wallet.public_key != self.wallet.public_key:
                url = f"http://{node.ip_address}:{node.port}/broadcast_block"
                try:
                    res = requests.post(url, json={"block": json.dumps(block.__dict__)})
                    responses.append(res.status_code == 200)
                except Exception as e:
                    print(f"Failed to broadcast block: {e}")

        threads = []
        responses = []
        for _, node in self.ring.items():
            thread = Thread(target=thread_target, args=(node, responses))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if all(responses):
            pass  # Maybe we need to add the block to the chain here

    def broadcast_ring(self):
        print("broadcast_ring")
        def thread_target(node, responses):
            if node.wallet.public_key != self.wallet.public_key:
                url = f"http://{node.ip_address}:{node.port}/broadcast_ring"
                try:
                    res = requests.post(
                        url, json={"ring": json.dumps(self.ring.__dict__)}
                    )
                    responses.append(res.status_code == 200)
                except Exception as e:
                    print(f"Failed to broadcast block: {e}")

        threads = []
        responses = []
        for _, node in self.ring.items():
            thread = Thread(target=thread_target, args=(node, responses))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

