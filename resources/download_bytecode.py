import argparse
from os import path
from web3 import Web3

def main():
    parser = argparse.ArgumentParser(description="Download smart contract bytecode.")
    parser.add_argument("contract_address", help="The Ethereum contract address")
    parser.add_argument("target_dir", help="Directory to save the bytecode")
    args = parser.parse_args()

    # Connect to Ethereum node
    w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/92bf4da1e6dd4f5aa6dfc804624f73e2"))

    if not w3.is_connected():
        raise ConnectionError("Web3 provider is not connected.")

    # Normalize contract address
    address = w3.to_checksum_address(args.contract_address)

    # Fetch bytecode
    bytecode = w3.eth.get_code(address).hex()
    
    target_file = path.join(args.target_dir, "contract.hex")

    # Save to file
    with open(target_file, "w") as f:
        f.write(bytecode)

    print(f"Bytecode saved to {target_file}")

if __name__ == "__main__":
    main()