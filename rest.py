import json
from argparse import ArgumentParser, ArgumentTypeError
from threading import Lock, Thread

import requests
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

import block
import blockchain
import transaction
import wallet
from node import Node

total_nodes = 5
app = Flask(__name__)
CORS(app)
node = Node()


# .......................................................................................
# Endpoint to register a new node in the network
# used only by the starting node and executes the register_node_to_ring function
@app.route("/add_node", methods=["POST"])
def add_node():
    # Get the arguments
    register_node = request.json.get("register_node")
    print(register_node)
    node_id = len(node.ring)
    register_node.id = node_id

    # Add node in the list of registered nodes.
    node.register_node_to_ring(register_node)

    # When all nodes are registered, the bootstrap node sends them:
    # - the current chain
    # - the ring
    # - the first transaction
    if node_id == total_nodes - 1:
        for _, ring_node in node.ring.items():
            if ring_node.id != node.id:
                # node.share_chain(ring_node)
                # node.share_ring(ring_node)
                node.create_transaction(
                    sender_address=node.wallet.public_key,
                    receiver_address=ring_node.public_key,
                    type_of_transaction="coins",
                    amount=1000,
                    message="",
                )

    return jsonify({"id": node_id})


@app.route("/broadcast_transaction", methods=["POST"])
def broadcast_transaction_endpoint():
    new_transaction = request.form.get("transaction")
    node.validate_transaction(new_transaction)
    return jsonify({"message": "Transaction received"}), 200


@app.route("/broadcast_block", methods=["POST"])
def broadcast_block_endpoint():
    new_block = request.form.get("block")
    if node.validate_block(new_block):
        return jsonify({"message": "Block added"}), 200
    else: 
        return jsonify({"message": "Block could not be added"}), 401

@app.route("/broadcast_ring", methods=["POST"])
def broadcast_ring_endpoint():
    new_ring = request.form.get("ring")
    node.ring = new_ring
    return jsonify({"message": "Ring received"}), 200


##############################################################################################
# Starting page
@app.route("/", methods=["GET"])
def start_page():
    button_blocks = '<form action="/blocks/get" method="get"><button type="submit">View Blocks</button></form>'
    button_create_trans = '<form action="/transaction" method="get"><button type="submit">Create Transaction</button></form>'
    return "Blockchain Application" + button_blocks + button_create_trans


# get all blocks in the blockchain
@app.route("/blocks/get", methods=["GET"])
def get_blocks():
    blocks = blockchain.blocks
    blocks_json = []
    for block in blocks:
        block_dict = {
            "index": block.index,
            "previous_hash": block.previous_hash,
            "timestamp": block.timestamp,
            "transactions": [vars(tx) for tx in block.transactions],
            "nonce": block.nonce,
            "validator": block.validator,
            "current_hash": block.current_hash,
            "capacity": block.capacity,
        }
        blocks_json.append(block_dict)
    response = {"blocks": blocks_json}
    return jsonify(response), 200


# page to create transaction
@app.route("/transaction/", methods=["GET"])
def transaction_page():
    return render_template("transaction_form.html")


# endpoint to create transaction
@app.route("/transaction/create_transaction", methods=["POST"])
def create_transaction():
    # Get input arguments:
    # id of the sender node
    # id of the receiver node
    # the amount of BCCs to send
    # the message to send
    # # the type of transaction
    # sender_public_key = int(request.form.get("sender"))
    receiver_public_key = str(request.form.get("receiver"))
    if request.form.get("amount") == "":
        amount = 0
    else:
        amount = int(request.form.get("amount"))
    message = str(request.form.get("message"))
    type_of_transaction = str(request.form.get("type"))
    print("Type of transaction", type_of_transaction)
    if node.create_transaction(
        node.wallet.public_key,
        receiver_public_key,
        type_of_transaction,
        amount,
        message,
    ):
        return (
            jsonify(
                {
                    "message": "The transaction was successful.",
                    "balance": node.balance,
                    "sender_public_key": node.wallet.public_key,
                }
            ),
            200,
        )
    else:
        return (
            jsonify({"message": "Not enough BCCs.", "balance": node.balance}),
            400,
        )
    # return str(sender_public_key) + str(receiver_public_key) + str(type_of_transaction) + str(amount) + str(message)


# get all transactions in specific block
@app.route("/blocks/transactions/get", methods=["GET"])
def get_transactions():
    blocks = blockchain.blocks
    response = {"blocks": blocks}
    return jsonify(response), 200


# run it once fore every node
if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument(
        "-p",
        "--port",
        default=5000,
        type=int,
        help="port to listen on",
    )
    parser.add_argument(
        "-b",
        "--bootstrap",
        default=True,
        help="is it the bootstrap node",
    )
    args = parser.parse_args()
    port = args.port
    b = args.bootstrap
    if isinstance(b, bool):
        bootstrap_node = b
    elif b.lower() in ("yes", "true", "t", "y", "1"):
        bootstrap_node = True
    elif b.lower() in ("no", "false", "f", "n", "0"):
        bootstrap_node = False
    else:
        raise ArgumentTypeError("Boolean value expected.")
    # node_id = args.id

    if bootstrap_node:
        blockchain = blockchain.Blockchain()
        print("Created blockchain")
        # maybe we should create a function that adds the starting node to the ring or check if "id0" then add node to ring
        node.chain = blockchain
        node.id = "id0"
        node.number_of_nodes = 1
        node.ip_address = "127.0.0.1"
        node.port = port

        # Listen in the specified port
        app.run(host="127.0.0.1", port=port)

        # create genesis block
        genesis = node.create_new_block()

        # add first transaction to genesis block
        # Adds the first and only transaction in the genesis block.
        first_transaction = transaction.Transaction(
            sender_address="0",
            receiver_address=node.wallet.public_key,
            type_of_transaction="coins",
            amount=1000 * total_nodes,
            message="",
            nonce=0,
        )
        genesis.current_hash = genesis.myHash()
        genesis.transactions.append(first_transaction)
        node.wallet.transactions.append(first_transaction)

        # Add the genesis block in the chain.
        node.chain.add_block_to_chain(genesis)
        node.current_block = None

    else:
        node.ip_address = "127.0.0.1"
        node.port = port
        print(json.dumps(node.__dict__))

        def thread_target():
            url = f"http://127.0.0.1:{node.port}/add_node"
            try:
                res = requests.post(url, json={"register_node": node.__dict__})
                if res.status_code == 200:
                    print("Node initialized")

                node.id = res.json()["id"]
            except Exception as e:
                print(f"Failed to broadcast transaction: {e}")

        thread = Thread(target=thread_target, args=())
        thread.start()
        app.run(host="127.0.0.1", port=port)
