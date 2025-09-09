import requests
from web3 import Web3
from collections import defaultdict
import csv
import os
import importlib.util

# Load Credentials (credentials.py)
credentials_path = "/home/fbioribeiro/thesis-tool/config/credentials.py"

spec = importlib.util.spec_from_file_location("credentials", credentials_path)
credentials = importlib.util.module_from_spec(spec)
spec.loader.exec_module(credentials)

ETHEREUM_PROVIDER = Web3.HTTPProvider(credentials.INESC_ETH_NODE_URL, request_kwargs={'timeout': 60})

# --- Functions ---
def get_contracts_in_tx(tx_hash):
    """Fetch all addresses touched by a transaction using QuickNode traces."""
    traces = ETHEREUM_PROVIDER.make_request("trace_transaction", [tx_hash])

    if 'error' in traces:
        raise Exception(f"Trace API error: {traces['error']}")
    
    addresses = set()

    for t in traces['result']:
        action = t.get('action', {})
        trace_type = t.get('type')

        # Collect contract calls
        if trace_type == 'call' and 'to' in action:
            addresses.add(action['to'].lower())

    return list(addresses)

def get_contract_creators(addresses, batch_size=5):
    """Fetch contract creators from Etherscan, batching requests with slicing."""
    batches = [addresses[i:i + batch_size] for i in range(0, len(addresses), batch_size)]
    all_results = []

    for batch in batches:
        joined = ",".join(batch)
        params = {
            "chainid": 1,
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": joined,
            "apikey": credentials.ETHERSCAN_API_KEY
        }

        resp = requests.get(credentials.ETHERSCAN_URL, params=params)
        resp.raise_for_status()
        data = resp.json()
        result = data.get("result", [])

        if isinstance(result, list):
            all_results.extend(result)
        else:
            print(f"Warning: Unexpected response for batch {batch}: {result}")

    return all_results

def group_by_creator(creator_info):
    """Group contracts by creator."""
    grouped = defaultdict(list)
    for entry in creator_info:
        creator = entry.get("contractCreator", "").lower()
        contract = entry.get("contractAddress", "").lower()
        grouped[creator].append(contract)
    return grouped

def download_contract_bytecode(contract_address, folder_path, exploited_project):
    """Download contract bytecode via Ethereum RPC (QuickNode)."""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [contract_address, "latest"],
        "id": 1
    }

    resp = requests.post(credentials.QUICKNODE_URL, json=payload)
    resp.raise_for_status()
    data = resp.json()
    bytecode = data.get("result", "")

    if bytecode and bytecode != "0x":
        os.makedirs(folder_path, exist_ok=True)
        file_path = os.path.join(folder_path, f"{contract_address}.hex")
        with open(file_path, "w") as f:
            f.write(bytecode)
        return True
    
    return False

# --- MAIN ---
with open("./dataset/incident.csv", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row["platform"] == "ETH" and row["transaction"]:
            print(f"Processing transaction: {row['transaction']} from project {row['exploited_project']}")
            tx_hash = row["transaction"]

            # Get all addresses touched by the transaction via QuickNode
            all_addresses = get_contracts_in_tx(tx_hash)

            if not all_addresses:
                print("No addresses found in transaction trace.")
                continue

            # Get creators from Etherscan (filters out EOAs automatically)
            creator_info = get_contract_creators(all_addresses)
            if not creator_info:
                print("No contracts found via Etherscan for these addresses.")
                continue

            # Group contracts by creator
            grouped = group_by_creator(creator_info)

            # Output
            for creator, contracts in grouped.items():
                print(f"Creator {creator} deployed these contracts:")
                for contract in contracts:
                    print(f"   {contract}")

            # Create project folder
            project_folder = f"./dataset/{row['exploited_project']}"
            os.makedirs(project_folder, exist_ok=True)

            downloaded_contracts = set()

            # Choose group and download contracts
            chosen_creator = input("Enter the creator address to download contracts: ")
            if chosen_creator in grouped:
                contracts_to_download = grouped[chosen_creator]
                print(f"Downloading contracts for creator {chosen_creator}:")

                for contract in contracts_to_download:
                    success = download_contract_bytecode(contract, project_folder, row["exploited_project"])
                    if success:
                        downloaded_contracts.add(contract)
                        print(f"   {contract} downloaded successfully.")
                    else:
                        print(f"   {contract} has no bytecode or download failed.")

                # Write the downloaded contracts to file (comma-separated, single line)
                contract_set_file = os.path.join(project_folder, "contract_set.txt")
                with open(contract_set_file, "w") as f:
                    f.write(",".join(downloaded_contracts))
            else:
                print(f"Creator {chosen_creator} not found.")