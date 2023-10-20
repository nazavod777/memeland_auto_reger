import eth_account.signers.local
from eth_account import Account


def generate_eth_account() -> eth_account.signers.local.LocalAccount:
    account: eth_account.signers.local.LocalAccount = Account.create()

    return account


def get_account(private_key: str) -> eth_account.signers.local.LocalAccount:
    account: eth_account.signers.local.LocalAccount = Account.from_key(private_key)

    return account
