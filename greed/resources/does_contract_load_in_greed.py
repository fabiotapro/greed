#!/usr/bin/env python3

import argparse
import logging
import traceback

from greed import Project

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("greed")


def main(args):
    p = Project(target_dir=args.target)

    entry_state = p.factory.entry_state(xid=1)
    simgr = p.factory.simgr(entry_state=entry_state)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("target", type=str, action="store", help="Path to Gigahorse output folder")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    # setup logging
    if args.debug:
        log.setLevel("DEBUG")
    else:
        log.setLevel("INFO")

    try:
        main(args)
    except:
        traceback.print_exc()
        exit(1)

    exit(0)
