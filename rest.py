import pickle
from argparse import ArgumentParser, ArgumentTypeError
from threading import Thread
import time

import requests
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

import blockchain
import transaction
from node import Node

total_nodes = 5

app = Flask(__name__)
CORS(app)
node = Node()


@app.route("/add_node", methods=["POST"])
def add_node():
    register_node = request.json.get("register_node")
    node_id = len(node.ring)
    register_node["id"] = node_id

    node.register_node_to_ring(register_node)

    if node_id == total_nodes - 1:
        node.broadcast_ring()
        node.broadcast_chain()

        for _, ring_node in node.ring.items():
            if ring_node["id"] != node.id:
                node.create_transaction(
                    sender_address=node.wallet.public_key,
                    receiver_address=ring_node["public_key"],
                    type_of_transaction="coins",
                    amount=1000,
                    message="",
                )
        print(
            f"{node.ring[node.wallet.public_key]['id']} has {node.ring[node.wallet.public_key]['balance']}"
        )
    return {"id": node_id}


def start():
    file_path = f"input/trans{node.id}.txt"
    id_dict = {}
    for _, n in node.ring.items():
        id_dict[str(n["id"])] = n["public_key"]

    counter = 0
    with open(file_path, "r") as file:
        for line in file:
            parts = line.split(" ", 1)
            id_num = int(parts[0][2:])
            message = parts[1].strip()
            if id_num <= len(id_dict.items()) - 1:
                node.create_transaction(
                    node.wallet.public_key,
                    id_dict[str(id_num)],
                    "message",
                    None,
                    message,
                )
            counter += 1
            if counter == 20:
                return


# Endpoint to start the proccess of reading from the input file
@app.route("/start_proccess", methods=["POST"])
def start_proccess_endpoint():
    start()
    return jsonify({"message": "Proccess started"}), 200


@app.route("/receive_transaction", methods=["POST"])
def receive_transaction_endpoint():
    new_transaction = request.json.get("transaction")
    node.validate_transaction(new_transaction)
    return jsonify({"message": "Transaction received"}), 200


@app.route("/receive_block", methods=["POST"])
def receive_block_endpoint():
    print(f"{node.id} received block")
    new_block = request.json.get("block")
    if node.validate_block(new_block):
        return jsonify({"message": "Block added"}), 200
    else:
        print(
            f"{node.id} failed to validate block. Chain length: {len(node.chain.blocks)}"
        )
        return jsonify({"message": "Block could not be added"}), 401


@app.route("/receive_ring", methods=["POST"])
def receive_ring_endpoint():
    new_ring = request.json.get("ring")
    node.ring = new_ring
    node.soft_state = new_ring
    return jsonify({"message": "Ring received"}), 200


@app.route("/receive_chain", methods=["POST"])
def receive_chain_endpoint():
    new_chain = pickle.loads(request.get_data())
    # TODO: validate chain
    node.chain = new_chain
    print(f"Node {node.id} received chain: {node.chain}")
    node.current_block.previous_hash = node.chain.blocks[-1].current_hash
    return jsonify({"message": "Chain received"}), 200


@app.route("/cli", methods=["POST"])
def cli():
    info = request.json.get("info")

    id_dict = {}
    for _, n in node.ring.items():
        id_dict[str(n["id"])] = n["public_key"]

    if info["action"] == "transaction_coins":
        node.create_transaction(
            node.wallet.public_key,
            id_dict[info["recipient_address"]],
            "coins",
            info["amount"],
            None,
        )
    elif info["action"] == "transaction_message":
        node.create_transaction(
            node.wallet.public_key,
            id_dict[info["recipient_address"]],
            "message",
            None,
            info["amount"],
        )
    elif info["action"] == "stake":
        node.set_stake(info["amount"])
    elif info["action"] == "view":
        last_block = node.chain.blocks[-1]
        formatted_transactions = "\n".join(
            [f"{str(t.to_dict())}" for t in last_block.transactions]
        )
        res = f"""
        Validator: {last_block.validator}
        Transactions: 
        {formatted_transactions}
        """
        return jsonify({"message": res}), 200
    elif info["action"] == "balance":
        last_block = node.balance
        res = str(node.balance)
        return jsonify({"message": res}), 200
    else:
        return jsonify({"message": "Invalid CLI request"}), 200

    return jsonify({"message": "CLI request received"}), 200


# ##############################################################################################
# # Starting page
# @app.route("/", methods=["GET"])
# def start_page():
#     button_blocks = '<form action="/blocks/get" method="get"><button type="submit">View Blocks</button></form>'
#     button_create_trans = '<form action="/transaction" method="get"><button type="submit">Create Transaction</button></form>'
#     return "Blockchain Application" + button_blocks + button_create_trans
#
#
# # get all blocks in the blockchain
# @app.route("/blocks/get", methods=["GET"])
# def get_blocks():
#     # blocks = blockchain.blocks
#     # blocks_json = []
#     # for block in blocks:
#     #     block_dict = {
#     #         "index": block.index,
#     #         "previous_hash": block.previous_hash,
#     #         "timestamp": block.timestamp,
#     #         "transactions": [vars(tx) for tx in block.transactions],
#     #         "nonce": block.nonce,
#     #         "validator": block.validator,
#     #         "current_hash": block.current_hash,
#     #         "capacity": block.capacity,
#     #     }
#     # blocks_json.append(block_dict)
#     blocks_json = node.chain.to_dict()
#     response = {"blocks": blocks_json}
#     return jsonify(response), 200
#
#
# # page to create transaction
# @app.route("/transaction/", methods=["GET"])
# def transaction_page():
#     return render_template("transaction_form.html")
#
#
# # endpoint to create transaction
# @app.route("/transaction/create_transaction", methods=["POST"])
# def create_transaction():
#     # Get input arguments:
#     # id of the sender node
#     # id of the receiver node
#     # the amount of BCCs to send
#     # the message to send
#     # # the type of transaction
#     # sender_public_key = int(request.form.get("sender"))
#     receiver_public_key = str(request.form.get("receiver"))
#     if request.form.get("amount") == "":
#         amount = 0
#     else:
#         amount = int(request.form.get("amount"))
#     message = str(request.form.get("message"))
#     type_of_transaction = str(request.form.get("type"))
#     print("Type of transaction", type_of_transaction)
#     if node.create_transaction(
#         node.wallet.public_key,
#         receiver_public_key,
#         type_of_transaction,
#         amount,
#         message,
#     ):
#         return (
#             jsonify(
#                 {
#                     "message": "The transaction was successful.",
#                     "balance": node.balance,
#                     "sender_public_key": node.wallet.public_key,
#                 }
#             ),
#             200,
#         )
#     else:
#         return (
#             jsonify({"message": "Not enough BCCs.", "balance": node.balance}),
#             400,
#         )
#
#
# # get all transactions in specific block
# @app.route("/blocks/transactions/get", methods=["GET"])
# def get_transactions():
#     blocks = blockchain.blocks
#     response = {"blocks": blocks}
#     return jsonify(response), 200


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
    parser.add_argument(
        "-s",
        "--stake",
        default=10,
        help="stake",
    )
    parser.add_argument(
        "-c",
        "--capacity",
        default=10,
        help="capacity",
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

    if bootstrap_node:
        blockchain = blockchain.Blockchain()
        print("Created blockchain")
        node.chain = blockchain
        node.id = 0
        node.number_of_nodes = total_nodes
        node.ip_address = "127.0.0.1"
        node.port = port
        node.balance = 1000 * total_nodes
        node.stake = args.stake
        node.capacity = args.capacity

        node.ring[node.wallet.public_key] = node.to_dict()
        node.soft_state[node.wallet.public_key] = node.to_dict()

        genesis = node.create_new_block()

        first_transaction = transaction.Transaction(
            sender_address="0",
            receiver_address=node.wallet.public_key,
            type_of_transaction="coins",
            amount=1000 * total_nodes,
            message="",
            nonce=0,
        )

        genesis.transactions.append(first_transaction)
        node.wallet.transactions.append(first_transaction)

        node.chain.add_block_to_chain(genesis)

        app.run(host="127.0.0.1", port=port)

    else:
        node.ip_address = "127.0.0.1"
        node.port = port
        node.stake = args.stake
        node.capacity = args.capacity

        def thread_target():
            url = f"http://127.0.0.1:5000/add_node"
            try:
                res = requests.post(url, json={"register_node": node.to_dict()})
                if res.status_code == 200:
                    print("Node initialized")

                node.id = res.json()["id"]
                time.sleep(5)
                if node.id == total_nodes - 1:
                    node.start_proccess()
                    start()
            except Exception as e:
                print(f"Failed : {e}")

        thread = Thread(target=thread_target, args=())
        thread.start()
        app.run(host=node.ip_address, port=port)
