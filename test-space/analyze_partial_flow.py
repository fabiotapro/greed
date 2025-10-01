#!/usr/bin/env python3
import argparse
import logging
import json
import csv
from collections import defaultdict


import IPython

from web3 import Web3

from greed import Project
from greed.state import SymbolicEVMState
from greed import options
from greed.exploration_techniques import DirectedSearch, Prioritizer
from greed.solver.yices2 import YicesTermBV, YicesTermBVS
from greed.solver.shortcuts import *
from greed.utils.extra import gen_exec_id
from greed.utils.files import load_csv_map, load_csv_multimap
from greed.sim_manager import SimulationManager

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("greed")

# Global variables
#complete_flows = None
per_contract_reverse_call_graphs = defaultdict()  # Maps contract name to its reverse call graph

public_functions = dict() # PublicFunction.csv
tac_blocks = dict()  # Maps contract name to a dictionary of statement to TAC block
in_functions = dict()  # Maps contract name to a dictionary of block to function entry block

all_public_functions = set() # Set of all public functions across all contracts


def prune_irrelevant_functions(state: SymbolicEVMState) -> bool:
    """
    Prune the states that reach "irrelevant" functions until the "from" statement of the flow under analysis.
    """

    tac_block_function = load_csv_map(f"{state.project.tac_parser.target_dir}/InFunction.csv")
    tac_statement_block = load_csv_map(f"{state.project.tac_parser.target_dir}/TAC_Block.csv")

    # Skip function selector or if already checked
    if (tac_block_function[state.curr_stmt.block_id] != '0x0' and not state.pruning_already_checked):

        # First update both prev and curr function entry blocks
        if tac_block_function[state.curr_stmt.block_id] != state.curr_function_entry_block:
            state.prev_function_entry_block = state.curr_function_entry_block
            state.curr_function_entry_block = tac_block_function[state.curr_stmt.block_id]

        curr_function_block = state.project.contract_name + "::" + tac_block_function[state.curr_stmt.block_id]

        # # TEST CONDITION
        # print(f"From stmt: {state.project.from_stmt} || Block ID: {tac_block_function[state.curr_stmt.block_id]} || Curr stmt: {state.curr_stmt.id}")
        # if (state.curr_stmt.id == state.project.from_stmt):
        #     print("ORACLE (from_stmt) FUNCTION FOUND, ABORT PRUNING!")
        #     state.project.prune_status = False
        #     return False

        if not (curr_function_block in state.project.relevant_functions):
            print(f"Current function entry block is not from a relevant function. Pruning state {state.uuid}")
            print(f"Number of states pruned: {SimulationManager.pruned_count + 1}")
            state.pruning_already_checked = True
            return True
        else:
            print(f"Current block IS from a relevant function. CONTINUING state {state.uuid}")
            state.pruning_already_checked = True

    return False

def find_to_stmt(state: SymbolicEVMState) -> bool:
    """
    Find the target "to_stmt" in the state.
    """
    if state.curr_stmt.id == state.project.to_stmt and state.has_crossed_from_stmt:
        print(f"Found target statement {state.curr_stmt.id} in state {state.uuid}. Has crossed from_stmt? {state.has_crossed_from_stmt}")
        return True
    return False

def load_files():
    """
    Loads the necessary files, from the Gigahorse analysis, for each contract.
    """
    
    ### Load the per_contract_reverse_call_graphs
    with open("/home/fbioribeiro/thesis-tool/greed/resources/per_contract_reverse_call_graphs.json", "r") as f:
        raw_data = json.load(f)

    # Convert inner dicts to defaultdict(set)
    global per_contract_reverse_call_graphs
    per_contract_reverse_call_graphs = {
        contract: defaultdict(set, {
            func: set(callers)
            for func, callers in func_map.items()
        })
        for contract, func_map in raw_data.items()
    }

    for contract_name in contract_set:
        
        ### Load the public functions
        entry_block_to_function = dict()

        with open("/home/fbioribeiro/thesis-tool/greed/gigahorse-toolchain/.temp/" + contract_name + "/out/PublicFunction.csv", newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            for row in reader:
                if len(row) == 2:
                    entry_block, function_name = row
                    entry_block_to_function[entry_block] = function_name
        
        public_functions[contract_name] = entry_block_to_function

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

def to_greed_variable_format(var):
    """
    Converts a variable name to the format used in Greed's TAC statements.
    Example: "0x123V0xabc" -> "v122Vabc"
    """
    if var is not None:
        return 'v' + var.replace('0x', '')
    else:
        return None

def traverse_term(term, depth=0):
    indent = "  " * depth
    # Check if this is a BV before calling is_concrete
    if isinstance(term, YicesTermBV):
        concrete = is_concrete(term)
    else:
        concrete = False

    print(f"{indent}- {term} | concrete={concrete} | type={type(term)}")

    # Recurse over children if present
    if hasattr(term, "children") and term.children:
        for child in term.children:
            traverse_term(child, depth + 1)

def count_oracle_vars(term):
    """
    Recursively traverse a YicesTerm AST and count symbolic variables 
    that came from oracle reads (marked with 'ORACLE' in their name).
    """
    count = 0

    seen_oracles = set() # Identified by the oracle's statements

    # Check if this term is a symbolic variable (leaf)
    if isinstance(term, YicesTermBVS):
        if "ORACLE" in term.name:
            oracle_stmt = term.name.split("_")[7]
            selector = term.name.split("_")[10]
            
            # Oracle verification (check if indeed from outside the protocol and unique)
            if selector not in all_public_functions and oracle_stmt not in seen_oracles:
                count += 1
                seen_oracles.add(oracle_stmt)

    # Recurse into children
    if hasattr(term, 'children') and term.children:
        for child in term.children:
            count += count_oracle_vars(child)

    return count


def main(args):

    global contract_set
    contract_string = args.contract_string.strip()
    contract_set = set(contract_string.split(','))

    contract_name = args.target.strip("/").split("/")[-1]
    print("split: ", contract_name)
    from_stmt = args.from_stmt
    to_stmt = args.to_stmt
    amount_var = args.amount_var

    load_files()

    # Populate all_public_functions
    for contract in contract_set:
        for entry_block, function_name in public_functions[contract].items():
            all_public_functions.add(function_name)

    # # DEBUG: MANUAL
    # contract_name = "3_0x5ad"
    # from_stmt = "0x1313"
    # to_stmt = "0x1c15"
    # amount_var = "v123Vabc"
        
    print("Contract name:" + contract_name)
    print("From statement:" + from_stmt)
    from_block = contract_name + "::" + in_functions[contract_name][tac_blocks[contract_name][from_stmt]]
    reachable_callers = get_reachable_callers(from_block)

    print(f"Reachable callers for {from_block}: ")
    print(reachable_callers)

    p = Project(target_dir=args.target, contract_name=contract_name, relevant_functions=reachable_callers, from_stmt=from_stmt, to_stmt=to_stmt)
    xid = gen_exec_id()

    options.SOLVER_TIMEOUT = 60
    options.MAX_CALLDATA_SIZE = 1024
    options.GREEDY_SHA = True
    options.MAX_SHA_SIZE = 512
    options.OPTIMISTIC_CALL_RESULTS = True
    options.DEFAULT_EXTCODESIZE = True
    # options.STATE_INSPECT = True

    init_ctx = {
        "CALLDATASIZE": options.MAX_CALLDATA_SIZE,
        "CALLER": "0xaaA4a5495988E18c036436953AC87aadEa074550",
        "ORIGIN": "0xaaA4a5495988E18c036436953AC87aadEa074550",
        "ADDRESS": args.address or "0x42"
    }

    w3 = Web3(Web3.HTTPProvider(options.WEB3_PROVIDER))
    if w3.is_connected():
        block_number = w3.eth.block_number
        block_info = w3.eth.get_block(block_number)
        init_ctx["NUMBER"] = block_number
        init_ctx["DIFFICULTY"] = block_info["totalDifficulty"]
        init_ctx["TIMESTAMP"] = block_info["timestamp"]

    entry_state = p.factory.entry_state(xid=xid, init_ctx=init_ctx, partial_concrete_storage=args.partial_concrete_storage)
    simgr = p.factory.simgr(entry_state=entry_state)

    ####################################################################################################################
    # from greed.exploration_techniques.other import MstoreConcretizer
    # concretizer = MstoreConcretizer()
    # concretizer.setup(simgr)
    # simgr.use_technique(concretizer)

    # def print_calldata(simgr, state):
    #     calldata_size = state.MAX_CALLDATA_SIZE
    #     calldata = state.solver.eval_memory(state.calldata, BVV(calldata_size, 256))
    #     log.info(f'CALLDATA: {calldata}')

    # simgr.one_active.inspect.stop_at_stmt("STATICCALL", func=print_calldata)

    ####################################################################################################################
    # SETUP PRIORITIZATION
    if args.find is not None:
        target_stmt = None
        target_stmt_id = None

        if args.find in p.statement_at:
            target_stmt_id = args.find
            target_stmt = p.factory.statement(target_stmt_id)
        else:
            print('Please specify a valid target statement.')
            exit(1)

        directed_search = DirectedSearch(target_stmt)
        simgr.use_technique(directed_search)

        prioritizer = Prioritizer(scoring_function=lambda s: -s.globals['directed_search_distance'])
        simgr.use_technique(prioritizer)

        for found in  simgr.findall(find=lambda s: s.curr_stmt.id == target_stmt_id):
            log.info(f'Found {found}')
            calldata_size = found.MAX_CALLDATA_SIZE
            calldata = found.solver.eval_memory(found.calldata, BVV(calldata_size, 256))
            log.info(f'CALLDATA: {calldata}')
            break
        else:
            log.fatal('No paths found')
            exit()

    ####################################################################################################################
    else:
        simgr.run(find=find_to_stmt, prune=prune_irrelevant_functions)
        print(f"FINISHED!")
        
        # Amount constraint
        for state in simgr.stashes['found']:
            amount_var_formatted = to_greed_variable_format(amount_var)
            if amount_var is not None and amount_var_formatted in state.registers:
                amount_val = state.registers[amount_var_formatted]
                print(f"State {state.uuid} | Amount variable {amount_var_formatted} | Value: {amount_val}")

                # Debug: traverse the term and print AST
                #traverse_term(amount_val)

                # First rule -> Only one oracle?
                print("Nr. of oracle vars:", count_oracle_vars(amount_val))
                if count_oracle_vars(amount_val) <= 1:
                    print("Amount constraint rule not met (<= 1 oracle var).")
                    # exit(2)

                # Second rule -> Try to give bigger values and check satisfiablity
                # TODO: implement second rule function

        # exit(0)

    if args.debug:
        IPython.embed()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("target", type=str, action="store", help="Path to Gigahorse output folder")
    parser.add_argument("contract_string", type=str, help="Contract set string (e.g., \"contractA,contractB\")")
    parser.add_argument("from_stmt", type=str, help="From statement (e.g., \"0x1234\")")
    parser.add_argument("to_stmt", type=str, help="To statement (e.g., \"0x5678\")")
    parser.add_argument("calldataload_var", type=str, help="Calldata load variable (e.g., \"v123Vabc\")")
    parser.add_argument("amount_var", type=str, help="Amount variable (e.g., \"v123Vabc\")")
    parser.add_argument("--address", type=str, action="store", help="Address of the contract")
    parser.add_argument("--find", type=str, action="store", help="Target code address")
    parser.add_argument("--partial-concrete-storage", dest="partial_concrete_storage", action="store_true", help="Enable partial concrete storage")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    print(f"Target: {args.target}")
    print(f"Contract String: {args.contract_string}")
    print(f"From Statement: {args.from_stmt}")
    print(f"To Statement: {args.to_stmt}")
    print(f"Amount Variable: {args.amount_var}")

    # setup logging
    if args.debug:
        log.setLevel("DEBUG")
    else:
        log.setLevel("INFO")

    try:
        main(args)
    except KeyboardInterrupt:
        pass