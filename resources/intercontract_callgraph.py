import argparse
import os
import re
import networkx as nx
import matplotlib.pyplot as pyplot
import csv
import json
from collections import defaultdict
import subprocess
import random
from dataclasses import dataclass
import copy

# Global Variables
contract_set = set()  # Set of contract names to analyze

# Per contract call graphs
per_contract_call_graphs = dict()
per_contract_reverse_call_graphs = dict()

# Inter-contract call graphs
intercontract_call_graph = defaultdict(set)
intercontract_reverse_call_graph = defaultdict(set)

# Data structures to hold parsed data
tac_codes = dict() # contract.tac
function_sets = dict() # Function.csv
public_functions = dict() # PublicFunction.csv
external_calls = dict() # CallToSignatureHex.csv

tac_blocks = dict() # TAC_Block.csv
in_functions = dict() # InFunction.csv

partial_flows_oracle_to_external_call = dict() # PartialFlowOracleToExternalCall.csv
partial_flows_call_data_load_to_external_call = dict() # PartialFlowCallDataLoadToExternalCall.csv
partial_flows_call_data_load_to_sink = dict() # PartialFlowCallDataLoadToSink.csv

# Complete flows
complete_flows = list()  # Complete flows (both intra- and inter-contract)

# Flow classes

@dataclass
class Flow:
    flow_type: str       # e.g., "CompleteFlowOracleToSink", "PartialFlowOracleToExternalCall", "PartialFlowCallDataLoadToExternalCall", "PartialFlowCallDataLoadToSink"
    contract_name: str   # e.g., "ContractName"
    from_stmt: str       # e.g., "0x123"
    to_stmt: str         # e.g., "0xabc"


@dataclass
class CompleteFlow:
    flow_type: str      # always "[Intra/Inter]FlowOracleToSink"
    flows: list         # list of flow paths (each is a list of Flow steps)



def adjust_brightness(hex_color, factor):
    """
    Lighten or darken a hex color.
    factor > 1.0 → lighter
    factor < 1.0 → darker
    """
    hex_color = hex_color.lstrip("#")
    rgb = [int(hex_color[i:i+2], 16) for i in (0, 2, 4)]
    adjusted = [min(255, int(c * factor)) for c in rgb]
    return "#{:02x}{:02x}{:02x}".format(*adjusted)

def export_to_graphviz_pdf():
    dot_file = f"/home/fbioribeiro/thesis-tool/greed/resources/intercontract_callgraph.dot"
    pdf_file = f"/home/fbioribeiro/thesis-tool/greed/resources/intercontract_callgraph.pdf"

    # Step 1: Assign random colors to each contract
    def random_color():
        return "#%06x" % random.randint(0x444444, 0xFFFFFF)  # readable color range

    contract_colors = {contract: random_color() for contract in contract_set}

    # Step 2: Write DOT file
    with open(dot_file, "w") as f:
        f.write("digraph InterContractCallGraph {\n")
        f.write("  rankdir=LR;\n")
        f.write("  node [shape=box fontname=\"Arial\"];\n")

        added_nodes = set()

        for caller, callees in intercontract_call_graph.items():
            # Add caller node with color if not already added
            if caller not in added_nodes:
                contract, function_entry_block = caller.split("::")

                color = contract_colors[contract]
                penwidth = "3.5" if function_entry_block in public_functions[contract].keys() else "1"

                f.write(f"  \"{caller}\" [style=filled, fillcolor=\"{color}\", penwidth=\"{penwidth}\"];\n")
                added_nodes.add(caller)

            for callee in callees:
                # Add callee node with color if not already added
                if callee not in added_nodes:
                    contract, function_entry_block = callee.split("::")

                    color = contract_colors[contract]
                    penwidth = "3.5" if function_entry_block in public_functions[contract].keys() else "1"
                    f.write(f"  \"{callee}\" [style=filled, fillcolor=\"{color}\", penwidth=\"{penwidth}\"];\n")

                    added_nodes.add(callee)

                # Add the edge
                f.write(f"  \"{caller}\" -> \"{callee}\";\n")

        f.write("}\n")

    # Step 3: Call GraphViz to export to PDF
    try:
        subprocess.run(["dot", "-Tpdf", dot_file, "-o", pdf_file], check=True)
        print(f"Graph exported to: {pdf_file}")
    except subprocess.CalledProcessError as e:
        print("Error while generating PDF with dot:", e)

def export_call_graphs_to_json():
    """
    Exports the call graph and reverse call graph to JSON files.
    """

    call_graph_serializable = {k: list(v) for k, v in intercontract_call_graph.items()}
    reverse_call_graph_serializable = {k: list(v) for k, v in intercontract_reverse_call_graph.items()}

    # Export call graph
    with open("/home/fbioribeiro/thesis-tool/greed/resources/call_graph.json", "w") as f:
        json.dump(call_graph_serializable, f, indent=4)

    # Export reverse call graph
    with open("/home/fbioribeiro/thesis-tool/greed/resources/reverse_call_graph.json", "w") as f:
        json.dump(reverse_call_graph_serializable, f, indent=4)

def build_call_graphs(tac_code, function_set, contract_name):
    """
    Parses TAC IR and builds:
      - call_graph: caller -> [callees]
      - reverse_call_graph: callee -> [callers]
    
    Only considers CALLPRIVATE with known targets in function_set.
    """
    call_graph = defaultdict(set)
    reverse_call_graph = defaultdict(set)
    current_func = None

    for line in tac_code.splitlines():
        # Detect block/function headers
        block_match = re.match(r"    Begin block (\S+)", line)
        if block_match:
            block_addr = block_match.group(1)
            if block_addr in function_set:
                current_func = block_addr

        # Detect internal calls (CALLPRIVATE) and extract destination
        if "CALLPRIVATE" in line and current_func:
            target_match = re.search(r"CALLPRIVATE v\S+\((0x[0-9a-f]+)\)", line)
            if target_match:
                called_addr = target_match.group(1)
                if called_addr in function_set:
                    # Add both directions
                    call_graph[f"{contract_name}::{current_func}"].add(f"{contract_name}::{called_addr}")
                    reverse_call_graph[f"{contract_name}::{called_addr}"].add(f"{contract_name}::{current_func}")

    return call_graph, reverse_call_graph

def load_files():

    for contract_name in contract_set:
        print(f"Loading files for contract: {contract_name}")
        ### Load the contract TAC
        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/contract.tac", "r") as tac_file:
            tac_code = tac_file.read()

        tac_codes[contract_name] = tac_code
        
        ### Load the contract functions
        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/Function.csv", newline='') as csvfile:
            reader = csv.reader(csvfile)

            rows = [row[0] for row in reader]
            function_list = rows[1:] # Skip the function selector
            function_set = set(function_list)

        function_sets[contract_name] = function_set

        ### Load the public functions
        entry_block_to_function = dict()

        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/PublicFunction.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 2:
                    entry_block, function_name = row
                    entry_block_to_function[entry_block] = function_name
        
        public_functions[contract_name] = entry_block_to_function

        ### Load the external calls
        statement_to_externalcall_function = dict()

        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/CallToSignatureHex.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 2:
                    statement, externalcall_function = row
                    statement_to_externalcall_function[statement] = externalcall_function

        external_calls[contract_name] = statement_to_externalcall_function

        ### Load the TAC_Block's
        statement_to_block = dict()

        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/TAC_Block.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 2:
                    statement, block = row
                    statement_to_block[statement] = block

        tac_blocks[contract_name] = statement_to_block

        ### Load the InFunction's
        block_to_function_entry_block = dict()

        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/InFunction.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 2:
                    block, function_entry_block = row
                    block_to_function_entry_block[block] = function_entry_block

        in_functions[contract_name] = block_to_function_entry_block

        ### Load the Complete flows Oracle -> Sink
        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/CompleteFlowOracleToSink.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 2:
                    oracle_stmt, sink_stmt = row
                    complete_flows.append(CompleteFlow("IntraFlowOracleToSink", [Flow("CompleteFlowOracleToSink", contract_name, oracle_stmt, sink_stmt)]))

        ### Load the Partial flows Oracle -> External Call
        flows_oracle_to_external_call = list()

        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/PartialFlowOracleToExternalCall.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 3:
                    oracle_stmt, external_stmt, external_sig = row
                    flows_oracle_to_external_call.append((oracle_stmt, external_stmt, external_sig))
        
        partial_flows_oracle_to_external_call[contract_name] = flows_oracle_to_external_call

        ### Load the Partial flows Calldataload -> External Call
        flows_call_data_load_to_external_call = list()
        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/PartialFlowCallDataLoadToExternalCall.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 3:
                    calldataload_stmt, external_stmt, external_sig = row
                    flows_call_data_load_to_external_call.append((calldataload_stmt, external_stmt, external_sig))

        partial_flows_call_data_load_to_external_call[contract_name] = flows_call_data_load_to_external_call

        ### Load the Partial flows Calldataload -> Sink
        flows_call_data_load_to_sink = list()
        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/PartialFlowCallDataLoadToSink.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 2:
                    calldataload_stmt, sink_stmt = row
                    flows_call_data_load_to_sink.append((calldataload_stmt, sink_stmt))
        
        partial_flows_call_data_load_to_sink[contract_name] = flows_call_data_load_to_sink
        
def compose_function_name(contract_name, function_entry_block):
    """
    Composes a function name from the contract name and the function entry block.
    """
    return f"{contract_name}::{function_entry_block}"

def recurse_partial_flow_calldataload_to_sink(contract_name, flows):
    list_of_flows_lists = list()

    for flow in partial_flows_call_data_load_to_sink[contract_name]:
        calldataload_stmt, sink_stmt = flow
        print(f"Checking partial flow calldataload->sink: CDL statement: {calldataload_stmt}, Sink statement: {sink_stmt}")

        flows_copy = [copy.deepcopy(f) for f in flows]
        f1 = Flow("PartialFlowCallDataLoadToSink", contract_name, calldataload_stmt, sink_stmt)
        flows_copy.append(f1)

        list_of_flows_lists.append(flows_copy)

    return list_of_flows_lists

def recurse_partial_flow_calldataload_to_external_call(contract_name, flows):
    list_of_flows_lists = list()

    for flow in partial_flows_call_data_load_to_external_call[contract_name]:
        calldataload_stmt, external_stmt, external_sig = flow
        print(f"Checking partial flow calldataload->external call: CDL statement: {calldataload_stmt}, External statement: {external_stmt}, External signature: {external_sig}")

        external_call_block = tac_blocks[contract_name][external_stmt] # Statement -> Block
        external_call_function_entry_block = in_functions[contract_name][external_call_block] # Block -> Function entry block
        print(f"External call function entry block: {external_call_function_entry_block}")

        f1 = Flow("PartialFlowCallDataLoadToExternalCall", contract_name, calldataload_stmt, external_stmt)
        flows.append(f1)

        # Check if any callee belongs to another contract
        for callee in intercontract_call_graph[compose_function_name(contract_name, external_call_function_entry_block)]:
            print(f"Checking callee: {callee}")
            callee_contract_name, callee_entry_block = callee.split("::")

            if callee_contract_name != contract_name and external_sig == public_functions[callee_contract_name][callee_entry_block]:
                print(f"Inter-contract edge found. External call in {compose_function_name(contract_name, external_call_function_entry_block)} calls function in another contract: {callee}")
                
                # Recurse with copies of the flows list
                flows_copy_1 = [copy.deepcopy(f) for f in flows]
                flows_copy_2 = [copy.deepcopy(f) for f in flows]

                list_of_flows_lists_1 = recurse_partial_flow_calldataload_to_sink(callee_contract_name, flows_copy_1)

                list_of_flows_lists_2 = recurse_partial_flow_calldataload_to_external_call(callee_contract_name, flows_copy_2)

                list_of_flows_lists.extend(list_of_flows_lists_1)
                list_of_flows_lists.extend(list_of_flows_lists_2)

    return list_of_flows_lists

def check_partial_flows(contract_name):

    for flow in partial_flows_oracle_to_external_call[contract_name]:
        
        oracle_stmt, external_stmt, external_sig = flow
        print(f"Checking partial flow: Oracle statement: {oracle_stmt}, External statement: {external_stmt}, External signature: {external_sig}")

        flows = list()
        f1 = Flow("PartialFlowOracleToExternalCall", contract_name, oracle_stmt, external_stmt)
        flows.append(f1)

        oracle_block = tac_blocks[contract_name][oracle_stmt] # Statement -> Block
        oracle_function_entry_block = in_functions[contract_name][oracle_block] # Block -> Function entry block
        print(f"Oracle function entry block: {oracle_function_entry_block}")

        external_call_block = tac_blocks[contract_name][external_stmt] # Statement -> Block
        external_call_function_entry_block = in_functions[contract_name][external_call_block] # Block -> Function entry block
        print(f"External call function entry block: {external_call_function_entry_block}")

        # TODO: NEED TO CHECK BOTH CALLDATALOAD -> SINK AND CALLDATALOAD -> EXTERNAL CALL
        # TODO: NEED TO FIND A WAY TO SPLIT IF MULTIPLE ARE FOUND
        # TODO: BEST WAY IS PROBABLY ONE FUNCTION FOR EACH TYPE OF PARTIAL FLOW FROM THE ABOVE TO ANALYZE THE
        # TODO: SOME SORT OF RECURSION THAT GOES ON ADDING FLOWS TO THE LIST AND RETURNS IT IN THE END OF THE RECURSION
        # TODO: AT THE END ONLY ADD TO COMPLETE FLOWS IF THE LAST FLOW ENDS IN A SINK

        # Check if any callee belongs to another contract
        for callee in intercontract_call_graph[compose_function_name(contract_name, external_call_function_entry_block)]:
            print(f"Checking callee: {callee}")
            callee_contract_name, callee_entry_block = callee.split("::")

            if callee_contract_name != contract_name and external_sig == public_functions[callee_contract_name][callee_entry_block]:
                print(f"Inter-contract edge found. External call in {compose_function_name(contract_name, external_call_function_entry_block)} calls function {external_sig} in another contract: {callee}")
                
                # Recurse with copies of the flows list
                flows_copy_1 = [copy.deepcopy(f) for f in flows]
                flows_copy_2 = [copy.deepcopy(f) for f in flows]

                list_of_flows_lists_1 = recurse_partial_flow_calldataload_to_sink(callee_contract_name, flows_copy_1)

                list_of_flows_lists_2 = recurse_partial_flow_calldataload_to_external_call(callee_contract_name, flows_copy_2)

        for flows_list in list_of_flows_lists_1 + list_of_flows_lists_2:

            # Only add to complete flows if the (last partial) flow ends in a sink
            # NOTE: In theory, only partial flows that end in a sink will be added to the returned list of lists in the recursion,
            # NOTE: so these flows should already always end in a sink
            if flows_list[-1].flow_type == "PartialFlowCallDataLoadToSink":
                complete_flows.append(CompleteFlow("InterFlowOracleToSink", flows_list))

def print_complete_flows():
    for i, cf in enumerate(complete_flows):
        print(f"\n=== CompleteFlow #{i} ===")
        print(f"Flow type: {cf.flow_type}")
        print(f"  Flow has {len(cf.flows)} steps:")
        for j, partial_flow in enumerate(cf.flows):
            print(f"    Step #{j} - {partial_flow.flow_type} | Contract: {partial_flow.contract_name}, From: {partial_flow.from_stmt}, To: {partial_flow.to_stmt}")


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("contracts_str", type=str, help="Comma-separated list of the names of the contracts to analyze.")
    return parser.parse_args()

def main():
    args = get_args()

    global contract_set
    contract_set = set(args.contracts_str.split(','))
    print("Contracts to analyze:", contract_set)
    print()

    load_files()

    # Build per contract call graphs
    for contract_name in contract_set:

        call_graph, reverse_call_graph = build_call_graphs(tac_codes[contract_name], function_sets[contract_name], contract_name)

        # Update inter-contract call graphs
        for caller, callees in call_graph.items():
            intercontract_call_graph[caller].update(callees)
        for callee, callers in reverse_call_graph.items():
            intercontract_reverse_call_graph[callee].update(callers)

    # Parse external calls and public functions to link the per contract call graphs
    for contract_name in contract_set:
        
        for statement, externalcall_function in external_calls[contract_name].items():
            # Check if the external call is to a public function in another contract
            for other_contract_name in contract_set:
                if other_contract_name != contract_name:

                    for entry_block, function_name in public_functions[other_contract_name].items():
                        if externalcall_function == function_name:
                            print(f"Linking external call {statement} in {contract_name} to public function {function_name} in {other_contract_name}")
                            block = tac_blocks[contract_name][statement] # Statement -> Block
                            function_entry_block = in_functions[contract_name][block] # Block -> Function entry block

                            intercontract_call_graph[f"{contract_name}::{function_entry_block}"].add(f"{other_contract_name}::{entry_block}")
                            intercontract_reverse_call_graph[f"{other_contract_name}::{entry_block}"].add(f"{contract_name}::{function_entry_block}")
                        
    # Export the inter-contract call graph to a PDF
    export_to_graphviz_pdf()

    # Export call graphs to JSON files
    export_call_graphs_to_json()

    print("Inter-contract call graph created and exported succesfully.")

    # Analyze candidate flows using the inter-contract call graph
    for contract_name in contract_set:
        print(f"Analyzing candidate flows for {contract_name}...")

        # TODO: Is there a way to check if the calldataload is indeed from the function that we are analyzing?
        # TODO: Can this approach incur in loops? In theory, I guess not?
        check_partial_flows(contract_name)
        
    print_complete_flows()


if __name__ == "__main__":
    main()