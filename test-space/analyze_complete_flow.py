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
from greed.solver.shortcuts import *
from greed.utils.extra import gen_exec_id
from greed.utils.files import load_csv_map, load_csv_multimap
from greed.sim_manager import SimulationManager

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("greed")

# Global variables
complete_flows = None
per_contract_reverse_call_graphs = defaultdict()  # Maps contract name to its reverse call graph

tac_blocks = dict()  # Maps contract name to a dictionary of statement to TAC block
in_functions = dict()  # Maps contract name to a dictionary of block to function entry block


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
    if state.curr_stmt.id == state.project.to_stmt:
        print(f"Found target statement {state.curr_stmt.id} in state {state.uuid}")
        return True
    return False

def load_files():
    """
    Loads the necessary files, from the Gigahorse analysis, for each contract.
    """

    ### Load the complete flows
    with open("/home/fbioribeiro/thesis-tool/greed/resources/complete_flows.json", "r") as f:
        global complete_flows
        complete_flows = json.load(f)

    
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


def main(args):

    load_files()

    contract_name = None
    from_stmt = None
    to_stmt = None

    # Traverse the complete flows (for now we only analyze the first one)
    for complete_flow in complete_flows:
        if complete_flow["flow_type"] == "IntraFlowOracleToSink":
            flow = complete_flow["flows"][0]
            contract_name = flow["contract_name"]
            from_stmt = flow["from_stmt"]
            to_stmt = flow["to_stmt"]
        
    print("Contract name:" + contract_name)
    print("From statement:" + from_stmt)
    from_block = contract_name + "::" + in_functions[contract_name][tac_blocks[contract_name][from_stmt]]
    reachable_callers = get_reachable_callers(from_block)

    print(f"Reachable callers for {from_block}: ")
    print(reachable_callers)

    # TODO: look at state, project, etc. to continue to perform selective symbolic execution
    # until the "from_stmt" and then test how to proceed until the "to_stmt"

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
        simgr.run(prune=prune_irrelevant_functions)

    if args.debug:
        IPython.embed()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("target", type=str, action="store", help="Path to Gigahorse output folder")
    parser.add_argument("contracts_str", type=str, action="store", help="Comma-separated list of the names of the contracts to analyze")
    parser.add_argument("--address", type=str, action="store", help="Address of the contract")
    parser.add_argument("--find", type=str, action="store", help="Target code address")
    parser.add_argument("--partial-concrete-storage", dest="partial_concrete_storage", action="store_true", help="Enable partial concrete storage")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    global contract_set
    contract_set = set(args.contracts_str.split(','))

    # setup logging
    if args.debug:
        log.setLevel("DEBUG")
    else:
        log.setLevel("INFO")

    try:
        main(args)
    except KeyboardInterrupt:
        pass