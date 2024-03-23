import base64
import json

from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import block
import blockchain
import transaction
import wallet


class node:
    def __init__(self, id, number_of_nodes):
        self.NBC = 0
        self.id = id
        self.chain = blockchain.Blockchain()
        self.current_id_count = 0
        self.wallet = None
        self.ring = []
        self.nonce = 0
        self.stake = 0
        self.number_of_nodes = number_of_nodes

    def create_new_block(self):
        new_block = block.Block(self.chain.get_latest_block().hash)
        self.chain.add_block(new_block)
        return new_block

    def generate_wallet(self):
        self.wallet = wallet.Wallet()

    def create_transaction(
        self, sender_address, receiver_address, type_of_transaction, amount, message
    ):
        transaction = transaction.Transaction(
            sender_address,
            receiver_address,
            type_of_transaction,
            amount,
            message,
            self.nonce,
        )
        signature = transaction.sign_transaction(self.wallet.private_key)
        self.broadcast_transaction(transaction, signature)
        if len(self.transactions) == self.capacity:
            self.mint_block()
            self.transactions = []
        return transaction

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
        pass

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

    def mint_block(self):
        pass

    def validate_block(self):
        pass

    def validate_chain(self, chain):
        # check for the longer chain accroose all nodes
        pass

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

    def add_transaction_to_block(self):
        pass
        # if enough transactions  mine

    def broadcast_block(self):
        pass

    def validate_proof(self, difficulty="MINING_DIFFICULTY"):
        pass

    def resolve_conflicts(self):
        # resolve correct chain
        pass
