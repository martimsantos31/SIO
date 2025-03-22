import sys
import os

import argparse
import logging
import json
from dotenv import load_dotenv


dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path)

logging.basicConfig(format="%(levelname)s\t- %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser("~"), ".sio")
    state_file = os.path.join(state_dir, "state.json")

    logger.debug("State folder: " + state_dir)
    logger.debug("State file: " + state_file)

    if os.path.exists(state_file):
        logger.debug("Loading state")
        with open(state_file, "r") as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state


def parse_env(state):
    if "REP_ADDRESS" in os.environ:
        state["REP_ADDRESS"] = os.getenv("REP_ADDRESS")
        logger.debug("Setting REP_ADDRESS from Environment to: " + state["REP_ADDRESS"])

    if "REP_PUB_KEY" in os.environ:
        rep_pub_key = os.getenv("REP_PUB_KEY")
        logger.debug(f"Loading REP_PUB_KEY from: {rep_pub_key}")
        if rep_pub_key is not None and rep_pub_key != "" and rep_pub_key != "None":
            rep_pub_key = os.path.join(os.path.dirname(__file__), rep_pub_key)
            if os.path.exists(rep_pub_key):
                with open(rep_pub_key, "r") as f:
                    state["REP_PUB_KEY"] = f.read()
                    logger.debug(f"Loaded REP_PUB_KEY content: {state['REP_PUB_KEY']}")
            else:
                logger.error(f"REP_PUB_KEY file does not exist at path: {rep_pub_key}")
                sys.exit(-1)
        else:
            logger.error("REP_PUB_KEY is empty or invalid.")
            sys.exit(-1)

    return state


def parse_args(auth_type="none"):
    state = load_state()
    state = parse_env(state)
    parser = argparse.ArgumentParser()

    # Add these arguments
    parser.add_argument("-k", "--key", nargs=1, help="Path to the key file")
    parser.add_argument("-r", "--repo", nargs=1, help="Repository address")
    parser.add_argument(
        "-v", "--verbose", help="Increase verbosity", action="store_true"
    )
    parser.add_argument("-c", "--command", help="Command to execute")
    parser.add_argument(
        "-s", "--username", help="Creator of the document", default=None
    )
    parser.add_argument("-d", "--date", help="Date of the document", default=None)
    parser.add_argument("arg0", nargs="?", default=None)
    parser.add_argument("arg1", nargs="?", default=None)
    parser.add_argument("arg2", nargs="?", default=None)
    parser.add_argument("arg3", nargs="?", default=None)
    parser.add_argument("arg4", nargs="?", default=None)
    parser.add_argument("arg5", nargs="?", default=None)

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info("Setting log level to DEBUG")

    if auth_type != "none":
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f"Session file not found: {args.key[0]}")
            sys.exit(-1)

    if args.key:
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f"Key file not found or invalid: {args.key[0]}")
            sys.exit(-1)

        with open(args.key[0], "r") as f:
            state["REP_PUB_KEY"] = f.read()
            logger.info("Overriding REP_PUB_KEY from command line")

    if args.repo:
        state["REP_ADDRESS"] = args.repo[0]
        logger.info("Overriding REP_ADDRESS from command line")

    if "REP_ADDRESS" not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if "REP_PUB_KEY" not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)

    """ Do something """
    logger.debug("Arguments: " + str(args))

    if args.command:
        logger.info("Command: " + args.command)

    return state, {
        "arg0": args.arg0,
        "arg1": args.arg1,
        "arg2": args.arg2,
        "arg3": args.arg3,
        "arg4": args.arg4,
        "arg5": args.arg5,
        "username": args.username,
        "date": args.date,
    }


def save(state):
    state_dir = os.path.join(os.path.expanduser("~"), ".sio")
    state_file = os.path.join(state_dir, "state.json")

    if not os.path.exists(state_dir):
        logger.debug("Creating state folder")
        os.mkdir(state_dir)

    with open(state_file, "w") as f:
        f.write(json.dumps(state, indent=4))
