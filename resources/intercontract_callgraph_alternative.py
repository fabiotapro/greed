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
from dataclasses import dataclass, asdict
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

all_public_functions = set() # Set of all public functions across all contracts

partial_flows_oracle_to_external_call = dict() # PartialFlowOracleToExternalCall.csv
partial_flows_external_call_to_external_call = dict() # PartialFlowExternalCallToExternalCall.csv
partial_flows_call_data_load_to_external_call = dict() # PartialFlowCallDataLoadToExternalCall.csv
partial_flows_call_data_load_to_sink = dict() # PartialFlowCallDataLoadToSink.csv
partial_flows_external_call_to_sink = dict() # PartialFlowExternalCallToSink.csv

# Complete flows
complete_flows = list()  # Complete flows (both intra- and inter-contract)

# Flow classes

@dataclass
class Flow:
    flow_type: str         # e.g., "CompleteFlowOracleToSink", "PartialFlowOracleToExternalCall", "PartialFlowCallDataLoadToExternalCall", "PartialFlowCallDataLoadToSink"
    contract_name: str     # e.g., "ContractName"
    from_stmt: str         # e.g., "0x123"
    to_stmt: str           # e.g., "0xabc"
    calldataload_var: str  # e.g., "v1ab" or None
    output_var: str        # e.g., "v1ab"


@dataclass
class CompleteFlow:
    flow_type: str      # always "[Intra/Inter]FlowOracleToSink"
    flows: list         # list of flow paths (each is a list of Flow steps)


def export_to_graphviz_pdf():
    """
    Exports the call graph to DOT and PDF with Graphviz.
    """
    dot_file = f"/home/fbioribeiro/thesis-tool/greed/resources/intercontract_callgraph.dot"
    pdf_file = f"/home/fbioribeiro/thesis-tool/greed/resources/intercontract_callgraph.pdf"
    png_file = f"/home/fbioribeiro/thesis-tool/greed/resources/intercontract_callgraph.png"
    svg_file = f"/home/fbioribeiro/thesis-tool/greed/resources/intercontract_callgraph.svg"

    # Assign random colors to each contract
    def random_color():
        return "#%06x" % random.randint(0x444444, 0xFFFFFF)  # readable color range

    contract_colors = {contract: random_color() for contract in contract_set}

    # Write DOT file
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

    # Export to PDF
    try:
        subprocess.run(["dot", "-Tpdf", dot_file, "-o", pdf_file], check=True)
        print(f"Graph exported to: {pdf_file}")
    except subprocess.CalledProcessError as e:
        print("Error while generating PDF with dot:", e)

    # Export to PNG
    try:
        subprocess.run(["dot", "-Tpng", dot_file, "-o", png_file], check=True)
        print(f"Graph exported to: {png_file}")
    except subprocess.CalledProcessError as e:
        print("Error while generating PNG with dot:", e)

    # Export to SVG
    try:
        subprocess.run(["dot", "-Tsvg", dot_file, "-o", svg_file], check=True)
        print(f"Graph exported to: {svg_file}")
    except subprocess.CalledProcessError as e:
        print("Error while generating SVG with dot:", e)

def export_call_graphs_to_json():
    """
    Exports the call graph and reverse call graph to JSON files.
    Exports the per contract reverse call graphs to a separate JSON file.
    """

    # Convert to JSON-safe structure (dict -> dict -> list)
    json_ready_per_contract_reverse_call_graphs = {
        contract_name: {
            caller: list(callees)  # convert set -> list
            for caller, callees in reverse_call_graph.items()
        }
        for contract_name, reverse_call_graph in per_contract_reverse_call_graphs.items()
    }

    call_graph_serializable = {k: list(v) for k, v in intercontract_call_graph.items()}
    reverse_call_graph_serializable = {k: list(v) for k, v in intercontract_reverse_call_graph.items()}

    # Export per contract reverse call graphs
    with open("/home/fbioribeiro/thesis-tool/greed/resources/per_contract_reverse_call_graphs.json", "w") as f:
        json.dump(json_ready_per_contract_reverse_call_graphs, f, indent=2)

    # Export call graph
    with open("/home/fbioribeiro/thesis-tool/greed/resources/call_graph.json", "w") as f:
        json.dump(call_graph_serializable, f, indent=4)

    # Export reverse call graph
    with open("/home/fbioribeiro/thesis-tool/greed/resources/reverse_call_graph.json", "w") as f:
        json.dump(reverse_call_graph_serializable, f, indent=4)

def export_complete_flows_to_json():
    """
    Exports the complete flows to a JSON file.
    """
    with open("/home/fbioribeiro/thesis-tool/greed/resources/complete_flows.json", "w") as f:
        json.dump([asdict(cf) for cf in complete_flows], f, indent=2)

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

def get_reachable_callers(target_function_block):
    """
    Given a per-contract reverse call graph and a target function block,
    recursively finds all function blocks that can reach the target.
    """
    reverse_call_graph = per_contract_reverse_call_graphs[target_function_block.split('::')[0]]
    reachable_callers = set()

    def recurse(func):
        if func in reachable_callers:
            return  # Avoid cycles
        reachable_callers.add(func)
        for caller in reverse_call_graph.get(func, []):
            recurse(caller)

    recurse(target_function_block)
    #reachable_callers.discard(target_function_block)  # do we want to exclude the target itself ? not for now, i think
    return reachable_callers

def load_files():
    """
    Loads the necessary files, from the Gigahorse analysis, for each contract.
    """

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

        # ### Load the Complete flows Oracle -> Sink
        # with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/CompleteFlowOracleToSink.csv", newline='') as csvfile:
        #     reader = csv.reader(csvfile, delimiter='\t')
        #     for row in reader:
        #         if len(row) == 3:
        #             oracle_stmt, sink_stmt, amount_var = row
        #             complete_flows.append(CompleteFlow("IntraFlowOracleToSink", [Flow("CompleteFlowOracleToSink", contract_name, oracle_stmt, sink_stmt, None, amount_var)]))

        # ### Load the Partial flows Oracle -> External Call
        # flows_oracle_to_external_call = list()

        # with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/PartialFlowOracleToExternalCall.csv", newline='') as csvfile:
        #     reader = csv.reader(csvfile, delimiter='\t')
        #     for row in reader:
        #         if len(row) == 4:
        #             oracle_stmt, external_stmt, external_sig, taintedVar = row
        #             flows_oracle_to_external_call.append((oracle_stmt, external_stmt, external_sig, taintedVar))

        # partial_flows_oracle_to_external_call[contract_name] = flows_oracle_to_external_call

        ### Load the Partial flows External Call -> External Call
        flows_externalcall_to_externalcall = list()

        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/PartialFlowExternalCallToExternalCall.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 5:
                    firstCallStmt, firstSigHash, secondCallStmt, secondSigHash, taintedVar = row
                    flows_externalcall_to_externalcall.append((firstCallStmt, firstSigHash, secondCallStmt, secondSigHash, taintedVar))

        partial_flows_external_call_to_external_call[contract_name] = flows_externalcall_to_externalcall

        ### Load the Partial flows Calldataload -> External Call
        flows_call_data_load_to_external_call = list()
        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/PartialFlowCallDataLoadToExternalCall.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 5:
                    calldataload_stmt, calldataload_var, external_stmt, external_sig, taintedVar = row
                    flows_call_data_load_to_external_call.append((calldataload_stmt, calldataload_var, external_stmt, external_sig, taintedVar))

        partial_flows_call_data_load_to_external_call[contract_name] = flows_call_data_load_to_external_call

        ### Load the Partial flows Calldataload -> Sink
        flows_call_data_load_to_sink = list()
        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/PartialFlowCallDataLoadToSink.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 4:
                    calldataload_stmt, calldataload_var, sink_stmt, amount_var = row
                    flows_call_data_load_to_sink.append((calldataload_stmt, calldataload_var, sink_stmt, amount_var))

        partial_flows_call_data_load_to_sink[contract_name] = flows_call_data_load_to_sink

        ### Load the Partial flows External Call -> Sink
        flows_externalcall_to_sink = list()

        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/PartialFlowExternalCallToSink.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 4:
                    callStmt, sigHash, sinkStmt, amount_var = row
                    flows_externalcall_to_sink.append((callStmt, sigHash, sinkStmt, amount_var))

        partial_flows_external_call_to_sink[contract_name] = flows_externalcall_to_sink

def compose_function_name(contract_name, function_entry_block):
    """
    Composes a function name from the contract name and the function entry block.
    """
    return f"{contract_name}::{function_entry_block}"

def recurse_partial_flow_calldataload_to_sink(contract_name, function_entry_block, flows):
    """
    Checks partial flows from calldataload to sink for a given contract.
    """
    list_of_flows_lists = list()

    for flow in partial_flows_call_data_load_to_sink[contract_name]:
        calldataload_stmt, calldataload_var, sink_stmt, amount_var = flow

        # Check if the calldataload statement is in the same function as the function entry block called
        if function_entry_block == in_functions[contract_name][tac_blocks[contract_name][calldataload_stmt]]:

            flows_copy = [copy.deepcopy(f) for f in flows]
            f1 = Flow("PartialFlowCallDataLoadToSink", contract_name, calldataload_stmt, sink_stmt, calldataload_var, amount_var)
            flows_copy.append(f1)

            list_of_flows_lists.append(flows_copy)

    return list_of_flows_lists

def recurse_partial_flow_calldataload_to_external_call(contract_name, function_entry_block, flows):
    """
    Recursively checks partial flows from calldataload to external calls for a given contract.
    """
    list_of_flows_lists = list()

    for flow in partial_flows_call_data_load_to_external_call[contract_name]:
        calldataload_stmt, calldataload_var, external_stmt, external_sig, taintedVar = flow

        # Check if the calldataload statement is in the same function as the function entry block called
        if function_entry_block == in_functions[contract_name][tac_blocks[contract_name][calldataload_stmt]]:

            external_call_block = tac_blocks[contract_name][external_stmt] # Statement -> Block
            external_call_function_entry_block = in_functions[contract_name][external_call_block] # Block -> Function entry block
            
            flows_copy = [copy.deepcopy(f) for f in flows]
            f1 = Flow("PartialFlowCallDataLoadToExternalCall", contract_name, calldataload_stmt, external_stmt, calldataload_var, taintedVar)
            flows_copy.append(f1)

            # Check if any callee belongs to another contract
            for callee in intercontract_call_graph[compose_function_name(contract_name, external_call_function_entry_block)]:
                callee_contract_name, callee_entry_block = callee.split("::")

                if callee_contract_name != contract_name and external_sig == public_functions[callee_contract_name][callee_entry_block]:
                    
                    # Recurse with copies of the flows list
                    flows_copy_1 = [copy.deepcopy(f) for f in flows_copy]
                    flows_copy_2 = [copy.deepcopy(f) for f in flows_copy]

                    list_of_flows_lists_1 = recurse_partial_flow_calldataload_to_sink(callee_contract_name, callee_entry_block, flows_copy_1)

                    list_of_flows_lists_2 = recurse_partial_flow_calldataload_to_external_call(callee_contract_name, callee_entry_block, flows_copy_2)

                    list_of_flows_lists.extend(list_of_flows_lists_1)
                    list_of_flows_lists.extend(list_of_flows_lists_2)

    return list_of_flows_lists

def recurse_and_look_for_oracle_call(contract_name, function_entry_block):
    """
    Recursively checks if there is an oracle call after an external call that will lead to a sink.
    """

    # Check if there is a call outside of this set of contracts
    for external_call in external_calls[contract_name].items():
        external_call_statement, externalcall_function = external_call

        external_call_block = tac_blocks[contract_name][external_call_statement] # Statement -> Block
        external_call_function_entry_block = in_functions[contract_name][external_call_block] # Block -> Function entry block

        if externalcall_function not in all_public_functions and \
        (contract_name + "::" + function_entry_block) in get_reachable_callers(contract_name + "::" + external_call_function_entry_block):
            return True

    # Recurse on partial flows from calldataload to external call
    for flow in partial_flows_call_data_load_to_external_call[contract_name]:
            calldataload_stmt, calldataload_var, external_stmt, external_sig, taintedVar = flow

            # Check if the calldataload statement is in the same function as the function entry block called
            if function_entry_block == in_functions[contract_name][tac_blocks[contract_name][calldataload_stmt]]:

                external_call_block = tac_blocks[contract_name][external_stmt] # Statement -> Block
                external_call_function_entry_block = in_functions[contract_name][external_call_block] # Block -> Function entry block

                # Check if any callee belongs to another contract
                for callee in intercontract_call_graph[compose_function_name(contract_name, external_call_function_entry_block)]:
                    callee_contract_name, callee_entry_block = callee.split("::")

                    if callee_contract_name != contract_name and external_sig == public_functions[callee_contract_name][callee_entry_block]:
                        if recurse_and_look_for_oracle_call(callee_contract_name, callee_entry_block):
                            return True

    return False


def check_partial_flows(contract_name):
    """
    Checks the partial flows from Oracle to External Call and recurses different partial flows from other contracts to find complete flows ending in sinks.
    """
    list_of_flows_lists = list()

    # Check complete flows External Call (Oracle) -> Sink
    for flow in partial_flows_external_call_to_sink[contract_name]:
        callStmt, sigHash, sinkStmt, amount_var = flow
        
        if sigHash not in all_public_functions and callStmt != sinkStmt:
            complete_flows.append(CompleteFlow("IntraFlowOracleToSink", [Flow("PartialFlowExternalCall(Oracle)ToSink", contract_name, callStmt, sinkStmt, None, amount_var)]))

    # Check flows that start with Oracle -> External Call
    for flow in partial_flows_external_call_to_external_call[contract_name]:
        firstCallStmt, firstSigHash, secondCallStmt, secondSigHash, taintedVar = flow

        if firstSigHash not in all_public_functions and secondSigHash in all_public_functions:

            flows = list()
            f1 = Flow("PartialFlowExternalCall(Oracle)ToExternalCall", contract_name, firstCallStmt, secondCallStmt, None, taintedVar)
            flows.append(f1)

            external_call_block = tac_blocks[contract_name][secondCallStmt] # Statement -> Block
            external_call_function_entry_block = in_functions[contract_name][external_call_block] # Block -> Function entry block

            # Check if any callee of the external call belongs to another contract
            for callee in intercontract_call_graph[compose_function_name(contract_name, external_call_function_entry_block)]:
                callee_contract_name, callee_entry_block = callee.split("::")

                if callee_contract_name != contract_name and secondSigHash == public_functions[callee_contract_name][callee_entry_block]:

                    # Recurse with copies of the flows list
                    flows_copy_1 = [copy.deepcopy(f) for f in flows]
                    flows_copy_2 = [copy.deepcopy(f) for f in flows]

                    list_of_flows_lists_1 = recurse_partial_flow_calldataload_to_sink(callee_contract_name, callee_entry_block, flows_copy_1)

                    list_of_flows_lists_2 = recurse_partial_flow_calldataload_to_external_call(callee_contract_name, callee_entry_block, flows_copy_2)

                    list_of_flows_lists.extend(list_of_flows_lists_1)
                    list_of_flows_lists.extend(list_of_flows_lists_2)

    # Check flows that start in External Calls (may receive a manipulated value) and end in sinks
    for flow in partial_flows_external_call_to_sink[contract_name]:
        callStmt, sigHash, sinkStmt, amount_var = flow

        flows = list()
        f1 = Flow("PartialFlowExternalCallToSink", contract_name, callStmt, sinkStmt, None, amount_var)
        flows.append(f1)
        
        if sigHash in all_public_functions:
            external_call_block = tac_blocks[contract_name][callStmt] # Statement -> Block
            external_call_function_entry_block = in_functions[contract_name][external_call_block] # Block -> Function entry block

            # Check if any callee of the external call belongs to another contract
            for callee in intercontract_call_graph[compose_function_name(contract_name, external_call_function_entry_block)]:
                callee_contract_name, callee_entry_block = callee.split("::")

                if callee_contract_name != contract_name and sigHash == public_functions[callee_contract_name][callee_entry_block]:
                    
                    try:
                        if recurse_and_look_for_oracle_call(callee_contract_name, callee_entry_block):
                            list_of_flows_lists.extend([flows])
                    except Exception as e:
                        print(f"Error while recursing for oracle. Ignoring possible flow. Error: {e}")

    # Save all Complete Flows
    for flows_list in list_of_flows_lists:

        # Only add to complete flows if the (last partial) flow ends in a sink
        # NOTE: In theory, only partial flows that end in a sink will be added to the returned list of lists in the recursion,
        # NOTE: so these flows should already always end in a sink
        #if flows_list[-1].flow_type == "PartialFlowCallDataLoadToSink":
        complete_flows.append(CompleteFlow("InterFlowOracleToSink", flows_list))

def print_complete_flows():
    """
    Prints the complete flows in a readable format for debug.
    """
    for i, cf in enumerate(complete_flows):
        print(f"\n=== CompleteFlow #{i} ===")
        print(f"Flow type: {cf.flow_type}")
        print(f"  Flow has {len(cf.flows)} steps:")
        for j, partial_flow in enumerate(cf.flows):
            print(f"    Step #{j} - {partial_flow.flow_type} | Contract: {partial_flow.contract_name}, From: {partial_flow.from_stmt}, To: {partial_flow.to_stmt}, Output Var: {partial_flow.output_var}")


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("project_folder_path", type=str, help="Path to the project folder")
    return parser.parse_args()

def main():
    args = get_args()

    project_folder = args.project_folder_path
    contract_set_file = os.path.join(project_folder, "contract_set.txt")

    with open(contract_set_file, "r") as f:
        contract_string = f.read().strip()

    global contract_set
    contract_set = set(contract_string.split(','))
    print("Contracts to analyze:", contract_set)
    print()

    load_files()
    print("File loading complete.")
    print()

    # Populate all_public_functions
    for contract_name in contract_set:
        for entry_block, function_name in public_functions[contract_name].items():
            all_public_functions.add(function_name)

    print("All public functions:", all_public_functions)
    print("External calls outside of this set will be treated as potential oracles/sources.")

    # Build per contract call graphs
    for contract_name in contract_set:

        call_graph, reverse_call_graph = build_call_graphs(tac_codes[contract_name], function_sets[contract_name], contract_name)

        # Update per contract call graphs
        per_contract_call_graphs[contract_name] = call_graph
        per_contract_reverse_call_graphs[contract_name] = reverse_call_graph

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
                            block = tac_blocks[contract_name][statement] # Statement -> Block
                            function_entry_block = in_functions[contract_name][block] # Block -> Function entry block

                            intercontract_call_graph[f"{contract_name}::{function_entry_block}"].add(f"{other_contract_name}::{entry_block}")
                            intercontract_reverse_call_graph[f"{other_contract_name}::{entry_block}"].add(f"{contract_name}::{function_entry_block}")
                        
    # Export the inter-contract call graph to a PDF
    export_to_graphviz_pdf()

    # Export call graphs to JSON files
    export_call_graphs_to_json()

    print("Inter-contract call graph created and exported succesfully.")
    print()

    # Analyze inter-contract flows using the inter-contract call graph
    for contract_name in contract_set:
        print(f"Analyzing potential inter-contract flows for {contract_name}...")

        # TODO: Is there a way to check if the calldataload is indeed from the function that we are analyzing?
        # TODO: Can this approach incur in loops? In theory, I guess not?
        check_partial_flows(contract_name)

    print("Inter-contract flows analysis complete.")
    print()

    print_complete_flows()
    print()

    export_complete_flows_to_json()
    print("Complete flows exported succesfully to JSON.")
    print()

if __name__ == "__main__":
    main()