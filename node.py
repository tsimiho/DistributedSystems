import base64
import hashlib
import json
import random
from collections import deque
from copy import deepcopy
from threading import Lock, Thread

from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import blockchain
from block import Block
from transaction import Transaction
from wallet import Wallet


class Node:
    def __init__(self, id, number_of_nodes, blockchain):
        self.NBC = 0
        self.id = id
        self.chain = blockchain
        self.current_id_count = 0
        self.wallet = Wallet()
        self.ring = []
        self.nonce = 0
        self.stake = 0
        self.current_block = None
        self.number_of_nodes = number_of_nodes
        self.blocks_to_confirm = deque()
        self.filter_lock = Lock()
        self.chain_lock = Lock()
        self.block_lock = Lock()
        self.transactions = []

    def create_new_block(self):
        if len(self.chain.blocks) == 0:
            # Here, the genesis block is created.
            new_idx = 0
            previous_hash = 1
            self.current_block = Block(new_idx, previous_hash)
        else:
            # They will be updated in mining.
            self.current_block = Block(None, None)
        self.chain.add_block_to_chain(self.current_block)

        return self.current_block

    def create_transaction(
        self, sender_address, receiver_address, type_of_transaction, amount, message
    ):
        transaction = Transaction(
            sender_address,
            receiver_address,
            type_of_transaction,
            amount,
            message,
            self.nonce,
        )
        signature = transaction.sign_transaction(self.wallet.private_key)
        self.broadcast_transaction(transaction, signature)

        return True

    def sign_transaction(self, transaction):
        signer = PKCS1_v1_5.new(
            RSA.importKey(base64.b64decode(self.wallet.private_key))
        )
        h = SHA256.new(json.dumps(transaction.to_dict(), sort_keys=True).encode())
        signature = signer.sign(h)
        return base64.b64encode(signature).decode()

    def broadcast_transaction(self, transaction, signature):
        # data = transaction.to_dict()
        # data["signature"] = signature.decode()
        return self.add_transaction_to_block(transaction)

    def verify_signature(self, transaction):
        key = RSA.importKey(base64.b64decode(transaction.sender_address))
        h = transaction.calculate_transaction_id()
        verifier = PKCS1_v1_5.new(key)
        return verifier.verify(h, base64.b64decode(transaction.signature))

    def validate_transaction(self, transaction):
        dict = transaction.to_dict()
        verify = self.verify_signature(transaction)
        if verify == False:
            return False

        if dict["type"] == "coins":
            coins_needed = dict["amount"] + transaction.caclulate_fee()
        elif dict["type"] == "message":
            coins_needed = len(dict["message"])
        else:
            print("Wrong type of transaction.")
            return False

        # todo: staking

    def lottery(self, hash):
        seed = int(hashlib.sha256(hash.encode()).hexdigest(), 16)
        random.seed(seed)
        tickets = []
        for node_info in self.ring:
            tickets.extend([node_info["pubkey"]] * node_info["stake"])
        if not tickets:
            return None
        selected_validator_pubkey = random.choice(tickets)
        return selected_validator_pubkey

    def mine_block(self):
        prev_hash = self.chain.blocks[-1].current_hash
        validator_key = self.lottery(prev_hash)
        if self.wallet.public_key == validator_key:
            index = len(self.blockchain.blocks)
            block = Block(index, prev_hash)
            self.transactions = []
            self.chain.add_block_to_chain(block)
            if self.validate_block(block):
                self.broadcast_block(block, self.chain.blocks[-2])

    def validate_block(self, block, prev_block):
        if (block.validator != self.lottery(prev_block.current_hash)) or (
            block.previous_hash != prev_block.current_hash
        ):
            return False
        return True

    def validate_chain(self, chain):
        for i in range(1, len(chain.blocks)):
            block = chain.blocks[i]
            prev_block = chain.blocks[i - 1]
            if not self.validate_block(block, prev_block):
                return False
        return True

    def stake(self, amount):
        pass

    def register_node_to_ring(self, ip_addr, pubkey, port, node_id, stake, balance):
        node_info = {
            "ip_addr": ip_addr,
            "pubkey": pubkey,
            "port": port,
            "id": node_id,
            "stake": stake,
            "balance": 0,
        }
        self.node[pubkey] = node_info
        if len(self.node_ring.items()) > 1:
            self.create_transaction(self.wallet.public_key, pubkey, "coins", 1000)

        if len(self.node_ring.items()) == self.number_of_nodes:
            self.broadcast_ring()

    def broadcast_ring(self):
        pass

    # Method to add transaction in block, updates wallet transaction for each node and checks if the block is ready to be mined
    def add_transaction_to_block(self, transaction):
        # Add the transaction in node's wallet, if it is the recepient or the sender
        if (transaction.receiver_address == self.wallet.public_key) or (
            transaction.sender_address == self.wallet.public_key
        ):
            self.wallet.transactions.append(transaction)

        # Update the balance of the recipient and the sender.
        for node in self.ring:
            if node["public_key"] == transaction.sender_address:
                node["balance"] -= transaction.amount
            if node["public_key"] == transaction.receiver_address:
                node["balance"] += transaction.amount

        # If the chain contains only the genesis block, a new block
        # is created. In other cases, the block is created after mining.
        if self.current_block is None:
            self.current_block = self.create_new_block()

        self.block_lock.acquire()
        if self.current_block.add_transaction(transaction) == "mine":
            # Mining procedure includes:
            # - add the current block in the queue of unconfirmed blocks.
            # - wait until the thread gets the lock.
            # - check that the queue is not empty.
            # - mine the first block of the queue.
            # - if mining succeeds, broadcast the mined block.
            # - if mining fails, put the block back in the queue and wait
            #   for the lock.

            # Update previous hash and index in case of insertions in the chain
            self.blocks_to_confirm.append(deepcopy(self.current_block))
            self.current_block = self.create_new_block()
            self.block_lock.release()
            while True:
                with self.filter_lock:
                    if self.blocks_to_confirm:
                        mined_block = self.blocks_to_confirm.popleft()
                        mining_result = self.mine_block(mined_block)
                        if mining_result:
                            break
                        else:
                            self.blocks_to_confirm.appendleft(mined_block)
                    else:
                        return
            self.broadcast_block(mined_block)
        else:
            self.block_lock.release()
        # if enough transactions  mine
        if len(self.transactions) == self.capacity:
            self.mint_block()
            self.transactions = []

    def broadcast_block(self):
        pass

    def validate_proof(self, difficulty="MINING_DIFFICULTY"):
        pass

    def resolve_conflicts(self):
        # resolve correct chain
        pass
