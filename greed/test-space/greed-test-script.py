import web3
import logging 

from greed import Project, options
from greed.exploration_techniques import ExplorationTechnique, DirectedSearch, HeartBeat, Prioritizer, DFS
from greed.utils.extra import gen_exec_id
from greed.solver.shortcuts import *

import matplotlib.pyplot as plt
import networkx as nx


LOGGING_FORMAT = "%(levelname)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("example")
log.setLevel(logging.INFO)

def config_greed():
    options.GREEDY_SHA = True
    options.LAZY_SOLVES = False
    options.STATE_INSPECT = True
    options.MAX_SHA_SIZE = 300
    options.OPTIMISTIC_CALL_RESULTS = True
    options.DEFAULT_EXTCODESIZE = True
    options.DEFAULT_CREATE2_RESULT_ADDRESS = True
    options.DEFAULT_CREATE_RESULT_ADDRESS = True
    options.MATH_CONCRETIZE_SYMBOLIC_EXP_EXP = True
    options.MATH_CONCRETIZE_SYMBOLIC_EXP_BASE = True

def main():

    config_greed()

    # 4 bytes of the mint() function
    # 0 --> 3
    calldata = "0x40c10f19"
    block_ref = 12878195

    # Create the greed project
    proj = Project(target_dir="./test-contracts/test_high")

    # Dump the callgraph
    proj.dump_callgraph(filename="callgraph.dot")

    relevant_paths_pcs = ["0x17e0", "0x4bad"]

    # Let's set the CALLER to my account
    init_ctx = {}

    xid = gen_exec_id()

    # Create the entry state
    entry_state = proj.factory.entry_state(
                                        xid=xid,
                                        init_ctx=init_ctx,
                                        max_calldatasize=68,
                                        partial_concrete_storage=False
                                        )

    # Setting up the simulation manager
    simgr = proj.factory.simgr(entry_state=entry_state)

    heartbeat = HeartBeat(beat_interval=100, show_op=True)
    simgr.use_technique(heartbeat)

    print(f"  Symbolically executing...")

    while True:
        try:
            simgr.run()
        except Exception as e:
            print(e)
            continue

        print("Simulation ended!!!")
        print(simgr.deadended[0])
        print(simgr.deadended[1])
        print(simgr.deadended[2])
        print(simgr.deadended[3])
        break

        '''
        if len(simgr.deadended) == 1:
            print(f"   ✅ Found state for {stop_stmt.__internal_name__} at {stop_stmt.id}!")
            state = simgr.one_found

            # Fix the shas!
            if len(state.sha_observed) > 0:
                shas = state.sha_resolver.fix_shas()
                if shas != None:
                    print(f'Fixed {len(shas)} shas in the state!')
                else:
                    print('Could not fix shas solutions, state is unsat')
                    assert(False)

            # Get a solution for the CALLDATA
            calldata_sol = state.solver.eval_memory(state.calldata, length=BVV(68,256), raw=True)
            
            # Get a solution for CALLVALUE (i.e., how much we paid for a penguin)
            # (Note: Yices2 does not expose a min() function, but you can find the minimum value
            # by using a bisection search)
            callvalue = state.solver.eval(state.ctx['CALLVALUE'])

            print(f"   📥 Calldata: {hex(bv_unsigned_value(calldata_sol))}")
            print(f"   💸 Callvalue: {callvalue}")
            
            break

        elif len(simgr.found) == 0:
            print(f"   ❌ No state found for {stop_stmt.__internal_name__} at {stop_stmt.id}!")
            break

'''

if __name__ == "__main__":
    main()