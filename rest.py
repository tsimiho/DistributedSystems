import requests
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

import block
import blockchain
import transaction
import wallet
from node import Node

### JUST A BASIC EXAMPLE OF A REST API WITH FLASK


app = Flask(__name__)
CORS(app)
blockchain = blockchain.Blockchain()

# Create an instance of the node class
# Define the node object of the current node.
my_node = Node(0, 0, blockchain)
# Define the number of nodes in the network.
# .......................................................................................


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
            "listOfTransactions": [vars(tx) for tx in block.listOfTransactions],
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
    # the amount of NBCs to send
    # the message to send
    # # the type of transaction
    # sender_public_key = int(request.form.get("sender"))
    receiver_public_key = str(request.form.get("receiver"))
    if request.form.get("amount") == '':
        amount = 0
    else:
        amount = int(request.form.get("amount"))
    message = str(request.form.get("message"))
    type_of_transaction = int(request.form.get("type"))
    print("Type of transaction", type_of_transaction)
    if my_node.create_transaction(
        my_node.wallet.public_key, receiver_public_key, type_of_transaction, amount, message
    ):
        return (
            jsonify(
                {
                    "message": "The transaction was successful.",
                    "balance": my_node.wallet.get_balance(),
                    "sender_public_key": my_node.wallet.public_key
                }
            ),
            200,
        )
    else:
        return (
            jsonify(
                {"message": "Not enough NBCs.", "balance": my_node.wallet.get_balance()}
            ),
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
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument(
        "-p", "--port", default=5000, type=int, help="port to listen on"
    )
    args = parser.parse_args()
    port = args.port

    app.run(host="127.0.0.1", port=port)
