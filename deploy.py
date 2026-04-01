"""
deploy.py
One-time script to:
  1. Install the Solidity compiler (solc 0.8.20) via py-solc-x
  2. Compile FileStorageContract.sol
  3. Deploy the compiled contract to local Ganache
  4. Save the ABI to contract_abi.json
  5. Save the deployed address to contract_address.txt

Run this ONCE before starting app.py:
    python deploy.py

Prerequisites:
    - Ganache must be running: ganache  (in a separate terminal)
    - pip install web3 py-solc-x
"""

import json
import os
import sys

from web3 import Web3

GANACHE_URL    = os.environ.get("GANACHE_URL", "http://127.0.0.1:8545")
CONTRACT_FILE  = os.path.join("contracts", "FileStorageContract.sol")
ABI_FILE       = "contract_abi.json"
ADDRESS_FILE   = "contract_address.txt"


def print_banner():
    print("=" * 60)
    print("  SecureVault — Ethereum Smart Contract Deployer")
    print("  Local Ganache Network — Free, No Real ETH")
    print("=" * 60)


def check_ganache(w3: Web3) -> None:
    """Verify Ganache is running and accessible."""
    print(f"\n[1/5] Connecting to Ganache at {GANACHE_URL}...")
    if not w3.is_connected():
        print("\n❌ ERROR: Cannot connect to Ganache.")
        print("\nTo fix this:")
        print("  1. Open a NEW terminal window")
        print("  2. Run:  ganache")
        print("  3. Come back to this terminal")
        print("  4. Run:  python deploy.py")
        sys.exit(1)

    account = w3.eth.accounts[0]
    balance = w3.from_wei(w3.eth.get_balance(account), "ether")
    print(f"   ✅ Connected!")
    print(f"   Account: {account}")
    print(f"   Balance: {balance} ETH (test ETH, not real)")
    print(f"   Network ID: {w3.net.version}")


def install_compiler() -> None:
    """Download and install the Solidity compiler if not present."""
    print("\n[2/5] Checking Solidity compiler (solc 0.8.20)...")
    try:
        from solcx import install_solc, get_installed_solc_versions
        installed = get_installed_solc_versions()
        if "0.8.20" not in [str(v) for v in installed]:
            print("   Downloading solc 0.8.20 (one-time, ~50 MB)...")
            install_solc("0.8.20")
            print("   ✅ Compiler installed.")
        else:
            print("   ✅ Compiler already installed.")
    except ImportError:
        print("❌ ERROR: py-solc-x not installed.")
        print("   Run: pip install py-solc-x")
        sys.exit(1)


def compile_contract() -> tuple[list, str]:
    """Compile the Solidity contract and return (ABI, bytecode)."""
    print("\n[3/5] Compiling FileStorageContract.sol...")

    from solcx import compile_standard, set_solc_version
    set_solc_version("0.8.20")

    if not os.path.exists(CONTRACT_FILE):
        print(f"❌ ERROR: {CONTRACT_FILE} not found.")
        print("   Make sure contracts/FileStorageContract.sol exists.")
        sys.exit(1)

    with open(CONTRACT_FILE) as f:
        source = f.read()

    compiled = compile_standard(
        {
            "language": "Solidity",
            "sources": {
                "FileStorageContract.sol": {
                    "content": source
                }
            },
            "settings": {
                "outputSelection": {
                    "*": {
                        "*": [
                            "abi",
                            "metadata",
                            "evm.bytecode",
                            "evm.bytecode.sourceMap",
                        ]
                    }
                }
            },
        },
        solc_version = "0.8.20",
    )

    contract_data = compiled["contracts"]["FileStorageContract.sol"]["FileStorageContract"]
    abi           = contract_data["abi"]
    bytecode      = contract_data["evm"]["bytecode"]["object"]

    print(f"   ✅ Compiled successfully.")
    print(f"   ABI functions: {len([x for x in abi if x.get('type') == 'function'])}")
    print(f"   ABI events:    {len([x for x in abi if x.get('type') == 'event'])}")
    print(f"   Bytecode size: {len(bytecode) // 2} bytes")

    return abi, bytecode


def deploy_contract(w3: Web3, abi: list, bytecode: str) -> str:
    """Deploy the compiled contract to Ganache. Returns deployed address."""
    print("\n[4/5] Deploying contract to Ganache...")

    account  = w3.eth.accounts[0]
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    # Estimate gas needed
    gas_estimate = Contract.constructor().estimate_gas({"from": account})
    print(f"   Gas estimate: {gas_estimate}")

    # Deploy
    tx_hash = Contract.constructor().transact({
        "from": account,
        "gas":  gas_estimate + 50000,   # add buffer
    })

    print(f"   Transaction sent: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    address = receipt["contractAddress"]

    gas_used = receipt["gasUsed"]
    block_no = receipt["blockNumber"]

    print(f"   ✅ Contract deployed!")
    print(f"   Address:      {address}")
    print(f"   Block number: {block_no}")
    print(f"   Gas used:     {gas_used} (FREE on Ganache)")
    print(f"   TX hash:      {tx_hash.hex()}")

    return address


def save_deployment(abi: list, address: str) -> None:
    """Save ABI and address to files for ethereum.py to load."""
    print("\n[5/5] Saving deployment info...")

    with open(ABI_FILE, "w") as f:
        json.dump(abi, f, indent=2)
    print(f"   ✅ ABI saved to {ABI_FILE}")

    with open(ADDRESS_FILE, "w") as f:
        f.write(address)
    print(f"   ✅ Address saved to {ADDRESS_FILE}")


def verify_deployment(w3: Web3, abi: list, address: str) -> None:
    """Quick sanity check — call getContractInfo() on deployed contract."""
    print("\n── Verifying deployment ──────────────────────────────")
    contract = w3.eth.contract(
        address = Web3.to_checksum_address(address),
        abi     = abi,
    )
    info = contract.functions.getContractInfo().call()
    print(f"   Owner:           {info[0]}")
    print(f"   Total files:     {info[1]}")
    print(f"   Max files:       {info[2]}")
    print(f"   Max file size:   {info[3] // (1024*1024)} MB")
    print(f"   Expiry:          {info[4]} days")
    print("\n✅ Contract is live and responding correctly!")


def main():
    print_banner()

    # Connect to Ganache
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    check_ganache(w3)

    # Install Solidity compiler
    install_compiler()

    # Compile Solidity contract
    abi, bytecode = compile_contract()

    # Deploy to Ganache
    address = deploy_contract(w3, abi, bytecode)

    # Save ABI + address
    save_deployment(abi, address)

    # Verify it works
    verify_deployment(w3, abi, address)

    print("\n" + "=" * 60)
    print("  🎉  Deployment complete!")
    print("=" * 60)
    print("\nNext step → start the Flask app:")
    print("    python app.py")
    print("\nThen open: http://127.0.0.1:5000")
    print("=" * 60)


if __name__ == "__main__":
    main()
