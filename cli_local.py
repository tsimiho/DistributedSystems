import argparse
import requests


def send_request(info, sender_address):
    url = f"http://127.0.0.1:{5000+int(sender_address)}/cli"
    try:
        res = requests.post(url, json={"info": info})
        if res.status_code == 200:
            message = res.json()["message"]
            print(message)
        else:
            print(f"Something went wrong: {res.status_code}")
    except Exception as e:
        print(f"Failed : {e}")


def transfer(args):
    if args.message.isdigit():
        info = {
            "action": "transaction_coins",
            "amount": int(args.message),
            "recipient_address": args.recipient_address,
        }
    else:
        info = {
            "action": "transaction_message",
            "amount": args.message,
            "recipient_address": args.recipient_address,
        }
    send_request(info, args.sender_address)


def stake(args):
    info = {"action": "stake", "amount": args.amount}
    send_request(info, args.sender_address)


def view(args):
    info = {"action": "view"}
    send_request(info, args.sender_address)


def balance(args):
    info = {"action": "balance"}
    send_request(info, args.sender_address)


def help_command(args):
    help = """
    - t <recipient_address> <amount>: transaction of <amount> coins from the sender's to the <recipient_address>'s wallet
    - t <recipient_address> <message>: transaction of <message> to the <recipient_address>'s wallet
    - stake <amount>: set the node stake to <amount>
    - view: print the validator and the transactions of the last validated block in the chain
    - balance: print the balance of the node's wallet
    """
    print(help)


def main():
    parser = argparse.ArgumentParser(description="CLI client")
    subparsers = parser.add_subparsers(help="commands")

    parser_t = subparsers.add_parser("t", help="Transfer coins or send a message")
    parser_t.add_argument("sender_address", type=str, help="Sender address")
    parser_t.add_argument("recipient_address", type=str, help="Recipient address")
    parser_t.add_argument(
        "message", type=str, help="Amount to transfer or message to send"
    )
    parser_t.set_defaults(func=transfer)

    parser_stake = subparsers.add_parser("stake", help="Stake coins")
    parser_stake.add_argument("sender_address", type=str, help="Sender address")
    parser_stake.add_argument("amount", type=int, help="Amount of coins to stake")
    parser_stake.set_defaults(func=stake)

    parser_view = subparsers.add_parser("view", help="View the ledger")
    parser_view.add_argument("sender_address", type=str, help="Sender address")
    parser_view.set_defaults(func=view)

    parser_balance = subparsers.add_parser("balance", help="Check balance")
    parser_balance.add_argument("sender_address", type=str, help="Sender address")
    parser_balance.set_defaults(func=balance)

    parser_help = subparsers.add_parser("help", help="Display help")
    parser_help.set_defaults(func=help_command)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
