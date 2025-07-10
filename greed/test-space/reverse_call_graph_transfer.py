import argparse
import os
import re
import networkx as nx
import matplotlib.pyplot as pyplot
import csv

def parse_tac_ir(tac_code, function_set):
    """
    Parses the TAC IR code and builds a reverse call graph: callee -> [callers].
    """
    function_callers = {}
    transfer_callers = set()
    current_func = None

    for line in tac_code.splitlines():
        block_match = re.match(r"    Begin block (\S+)", line)
        if block_match:
            block_addr = block_match.group(1)
            if block_addr in function_set:
                current_func = block_addr

        if "CALLPRIVATE" in line and current_func:
            target_match = re.search(r"CALLPRIVATE v\S+\((0x[0-9a-f]+)\)", line)
            if target_match:
                called_addr = target_match.group(1)
                function_callers.setdefault(called_addr, [])
                function_callers[called_addr].append(current_func)

        if current_func and "0xa9059cbb" in line:
            transfer_callers.add(current_func)

    return function_callers, transfer_callers

def get_relevant_functions(function_callers, transfer_callers):
    """
    Recursively finds all function callers for the transfer callers.
    """
    relevant_functions = set()

    def recurse(func):
        if func in relevant_functions:
            return  # Avoid revisiting
        relevant_functions.add(func)
        callers = function_callers.get(func, [])
        for caller in callers:
            recurse(caller)

    for function in transfer_callers:
        recurse(function)

    return relevant_functions

def show_call_graph(call_graph):
    """
    Shows the call graph. Assumes input is callee -> [callers].
    """

    # Create a directed graph using networkx
    G = nx.DiGraph()

    # Since we have callee -> [callers], we reverse it to draw: caller -> callee
    for callee, callers in call_graph.items():
        for caller in callers:
            G.add_edge(caller, callee)

    # Draw the graph
    pyplot.figure(figsize=(10, 8))
    nx.draw(
        G,
        with_labels=True,
        node_color='lightblue',
        font_weight='bold',
        node_size=1200,
        font_size=9,
        arrowsize=15
    )
    pyplot.title("Call Graph (Caller → Callee)")
    pyplot.show()

def load_files(contract_tac_path, function_csv_path):

    # Load the contract TAC
    with open(contract_tac_path, "r") as tac_file:
        tac_code = tac_file.read();
    
    # Load the contract functions
    with open(function_csv_path, newline='') as csvfile:
        reader = csv.reader(csvfile)

        rows = [row[0] for row in reader]
        function_list = rows[1:] # Skip the function selector
        function_set = set(function_list)

    return function_set, tac_code

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("folder_path", type=str, help="Path to the Gigahorse's output folder.")
    return parser.parse_args()

def main(folder_path):

    contract_tac_path = os.path.join(folder_path, "contract.tac")
    function_csv_path = os.path.join(folder_path, "Function.csv")

    function_set, tac_code = load_files(contract_tac_path, function_csv_path)

    function_callers, transfer_callers = parse_tac_ir(tac_code, function_set)
    print(f"Function callers: {function_callers}")
    print(f"Transfer callers: {transfer_callers}")

    show_call_graph(function_callers)

    # Recursively find all function callers for the transfer callers
    # This obtains all the 'relevant' functions to symbolically execute
    relevant_functions = get_relevant_functions(function_callers, transfer_callers)

    print(f"Relevant functions: {relevant_functions}")
    
    return relevant_functions

if __name__ == "__main__":
    args = get_args()

    main(args.folder_path)