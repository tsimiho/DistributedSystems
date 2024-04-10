import base64
import time
import hashlib
import pickle
import random
from threading import Lock, Thread

import requests
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from block import Block
from blockchain import Blockchain
from transaction import Transaction
from wallet import Wallet


class Node:
    def __init__(
        self,
        id=None,
        number_of_nodes=None,
        ip_address=None,
        port=None,
        capacity=10,
        stake=10,
    ):
        self.id = id
        self.chain = Blockchain()
        self.current_id_count = 0
        self.wallet = Wallet()
        self.ring = {}
        self.soft_state = {}
        self.nonce = 0
        self.stake = stake
        self.balance = 0
        self.current_block = Block(None, None)
        self.current_block.create_hash()
        self.current_block.index = len(self.chain.blocks)
        if self.chain.blocks != []:
            self.current_block.previous_hash = self.chain.blocks[-1].current_hash
        self.number_of_nodes = number_of_nodes
        self.transactions = []
        self.ip_address = ip_address
        self.port = port
        self.capacity = capacity
        self.to_mine = True
        self.transactions_lock = Lock()
        self.soft_state_lock = Lock()
        self.ring_lock = Lock()
        self.block_lock = Lock()
        self.chain_lock = Lock()
        self.mine_lock = Lock()
        self.throughput_individual = {}
        self.block_time = {}
        self.node_start_time = None
        self.node_finish_time = None

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip_address,
            "port": self.port,
            "public_key": self.wallet.public_key,
            "balance": self.balance,
            "stake": self.stake,
        }

    def create_new_block(self):
        if len(self.chain.blocks) == 0:
            # print("Create new block")
            new_idx = 0
            previous_hash = 1
            # self.block_lock.acquire()
            self.current_block = Block(new_idx, previous_hash)
            self.current_block.create_hash()
            # self.block_lock.release()
            # print("Created block")
        else:
            new_idx = len(self.chain.blocks)
            previous_hash = self.chain.blocks[-1].current_hash
            # self.block_lock.acquire()
            self.current_block = Block(new_idx, previous_hash)
            self.current_block.create_hash()
            # self.block_lock.release()
        return self.current_block

    def create_transaction(
        self, sender_address, receiver_address, type_of_transaction, amount, message
    ):
        self.nonce += 1
        self.throughput_individual[str(self.nonce)] = time.time()
        transaction = Transaction(
            sender_address,
            receiver_address,
            type_of_transaction,
            amount,
            message,
            self.nonce,
        )
        transaction.sign_transaction(self.wallet.private_key)
        self.broadcast_transaction(transaction)
        self.validate_transaction(transaction.to_dict())

        return True

    def verify_signature(self, transaction):
        key = RSA.importKey(base64.b64decode(transaction["sender_address"]))
        message = transaction["transaction_id"].encode()
        h = SHA.new(message)
        verifier = PKCS1_v1_5.new(key)
        decoded_signature = base64.b64decode(transaction["signature"])
        return verifier.verify(h, decoded_signature)

    def validate_transaction(self, transaction):
        verify = self.verify_signature(transaction)

        if not verify:
            return False

        # self.soft_state_lock.acquire()
        if transaction["type_of_transaction"] == "coins":
            # print(self.soft_state[transaction["sender_address"]]["balance"])
            if (
                1.03 * transaction["amount"]
                <= self.soft_state[transaction["sender_address"]]["balance"]
                - self.soft_state[transaction["sender_address"]]["stake"]
            ):
                self.soft_state[transaction["sender_address"]]["balance"] -= (
                    1.03 * transaction["amount"]
                )
                self.soft_state[transaction["receiver_address"]]["balance"] += (
                    transaction["amount"]
                )
            else:
                # print(f"error 1: {transaction}")
                return False
        elif transaction["type_of_transaction"] == "message":
            if (
                len(transaction["message"])
                <= self.soft_state[transaction["sender_address"]]["balance"]
                - self.soft_state[transaction["sender_address"]]["stake"]
            ):
                self.soft_state[transaction["sender_address"]]["balance"] -= len(
                    transaction["message"]
                )
            else:
                # print("error 2")
                return False
        elif transaction["type_of_transaction"] == "stake":
            if (
                transaction["amount"]
                <= self.soft_state[transaction["sender_address"]]["balance"]
            ):
                self.soft_state[transaction["sender_address"]]["stake"] = transaction[
                    "amount"
                ]
            else:
                # print("error 3")
                return False
        # self.soft_state_lock.release()

        self.node_finish_time = time.time()
        # self.transactions_lock.acquire()
        self.transactions.append(transaction)
        # self.transactions_lock.release()
        # print(f"Here: {len(self.transactions)}, {self.capacity}")
        if len(self.transactions) >= self.capacity and self.to_mine:
            # self.mine_lock.acquire()
            self.to_mine = False
            # self.mine_lock.release()
            # print(f"Capacity reached by node {self.id}")
            self.mine_block()

    def lottery(self, hash):
        seed = int(hashlib.sha256(hash.encode()).hexdigest(), 16)
        random.seed(seed)
        tickets = []
        for _, node in self.ring.items():
            tickets.extend([node["public_key"]] * node["stake"])
        if not tickets:
            return None
        selected_validator_pubkey = random.choice(tickets)
        return selected_validator_pubkey

    def mine_block(self):
        # print("Mine block")
        prev_hash = self.chain.blocks[-1].current_hash
        validator_key = self.lottery(prev_hash)
        # print(
        #     f"Node chosen for validation of block: {self.soft_state[validator_key]['id']}"
        # )
        if self.wallet.public_key == validator_key:
            # self.block_lock.acquire()
            for i in range(self.capacity):
                self.add_transaction_to_block(self.transactions[i])
            self.current_block.validator = validator_key
            # self.block_lock.release()
            self.broadcast_block(self.current_block)
            self.validate_block(self.current_block.to_dict())

    def validate_block(self, block):
        if (
            block["validator"] == self.lottery(self.chain.blocks[-1].current_hash)
        ) and (block["previous_hash"] == self.chain.blocks[-1].current_hash):
            for t in block["transactions"]:
                # self.transactions_lock.acquire()
                for tt in self.transactions:
                    if t["transaction_id"] == tt["transaction_id"]:
                        # print("Removed transaction from list")
                        self.transactions.remove(tt)
                # self.transactions_lock.release()
                # self.ring_lock.acquire()
                if t["type_of_transaction"] == "coins":
                    if (
                        1.03 * t["amount"]
                        <= self.ring[t["sender_address"]]["balance"]
                        - self.ring[t["sender_address"]]["stake"]
                    ):
                        self.ring[t["sender_address"]]["balance"] -= 1.03 * t["amount"]
                        self.ring[t["receiver_address"]]["balance"] += t["amount"]
                        self.ring[block["validator"]]["balance"] += 0.03 * t["amount"]
                    else:
                        return False
                elif t["type_of_transaction"] == "message":
                    if (
                        len(t["message"])
                        <= self.ring[t["sender_address"]]["balance"]
                        - self.ring[t["sender_address"]]["stake"]
                    ):
                        self.ring[t["sender_address"]]["balance"] -= len(t["message"])
                        self.ring[block["validator"]]["balance"] += len(t["message"])
                    else:
                        return False
                elif t["type_of_transaction"] == "stake":
                    if t["amount"] <= self.ring[t["sender_address"]]["balance"]:
                        self.ring[t["sender_address"]]["stake"] = t["amount"]
                    else:
                        return False
                else:
                    return False
                # self.ring_lock.release()

            # print(f"{self.id} validated the block")
            b = Block(block["index"], block["previous_hash"])
            b.transactions = block["transactions"]
            b.current_hash = block["current_hash"]
            b.nonce = block["nonce"]
            b.timestamp = block["timestamp"]
            b.validator = block["validator"]
            # self.chain_lock.acquire()
            self.chain.add_block_to_chain(b)
            # self.chain_lock.release()
            ct = time.time()
            for t in block["transactions"]:
                if t["sender_address"] == self.wallet.public_key:
                    t_time = self.throughput_individual[str(t["nonce"])]
                    self.throughput_individual[str(t["nonce"])] = ct - t_time
            self.create_new_block()
            # self.soft_state_lock.acquire()
            self.soft_state = self.ring.copy()
            # self.soft_state_lock.release()
            if len(self.transactions) >= self.capacity:
                self.mine_block()
            # self.mine_lock.acquire()
            self.to_mine = True
            # self.mine_lock.release()
            return True
        else:
            # if block["validator"] != self.lottery(self.chain.blocks[-1].current_hash):
            #     print("------------------------------------ Wrong validator")
            #     print(
            #         block["validator"], self.lottery(self.chain.blocks[-1].current_hash)
            #     )
            #     print("------------------------------------ Wrong validator")
            #
            # if block["previous_hash"] != self.chain.blocks[-1].current_hash:
            #     hashes = [block.current_hash for block in self.chain.blocks]
            #     print(
            #         "------------------------------------ Wrong hash",
            #         "\n",
            #         block["previous_hash"],
            #         "\n",
            #         hashes,
            #         "\n",
            #         "------------------------------------ Wrong hash",
            #     )
            return False

    def validate_chain(self, chain):
        return True

    def set_stake(self, amount):
        return self.create_transaction(self.wallet.public_key, 0, "stake", amount, None)

    def register_node_to_ring(self, node):
        self.ring[node["public_key"]] = node
        self.soft_state[node["public_key"]] = node

    def add_transaction_to_block(self, transaction):
        self.current_block.add_transaction(transaction)

    def broadcast_transaction(self, transaction):
        # print(f"{self.id}: broadcast_transaction")

        lock = Lock()

        def thread_target(node, responses):
            if node["public_key"] != self.wallet.public_key:
                url = f"http://{node['ip']}:{node['port']}/receive_transaction"
                try:
                    res = requests.post(
                        url, json={"transaction": transaction.to_dict()}
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
            pass

    def broadcast_block(self, block):
        # print(f"{self.id}: broadcast_block")

        def thread_target(node, responses):
            if node["public_key"] != self.wallet.public_key:
                url = f"http://{node['ip']}:{node['port']}/receive_block"
                try:
                    res = requests.post(url, json={"block": block.to_dict()})
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
            pass

    def broadcast_ring(self):
        # print("broadcast_ring")

        def thread_target(node, responses):
            if node["public_key"] != self.wallet.public_key:
                url = f"http://{node['ip']}:{node['port']}/receive_ring"
                try:
                    res = requests.post(url, json={"ring": self.ring.copy()})
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

    def broadcast_chain(self):
        # print("broadcast_chain")

        def thread_target(node, responses):
            if node["public_key"] != self.wallet.public_key:
                url = f"http://{node['ip']}:{node['port']}/receive_chain"
                try:
                    res = requests.post(url, data=pickle.dumps(self.chain))
                    responses.append(res.status_code == 200)
                except Exception as e:
                    print(f"Failed to broadcast chain: {e}")

        threads = []
        responses = []
        for _, node in self.ring.items():
            thread = Thread(target=thread_target, args=(node, responses))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def start_proccess(self):
        # print("Starting proccess")

        def thread_target(node, responses):
            url = f"http://{node['ip']}:{node['port']}/start_proccess"
            try:
                res = requests.post(url)
                responses.append(res.status_code == 200)
            except Exception as e:
                print(f"Failed to start proccess: {e}")

        threads = []
        responses = []
        for _, node in self.ring.items():
            thread = Thread(target=thread_target, args=(node, responses))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
