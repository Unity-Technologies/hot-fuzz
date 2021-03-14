#!/usr/bin/env python3

import argparse
import json
import os
import sys

from fuzz import request
from fuzz.config.config import Config
from fuzz.fuzzer import Fuzzer


class Client:
    def __init__(self):
        self.config = Config()

        self.parser = argparse.ArgumentParser(
            description="Hot Fuzz: A fuzzing utility that sends HTTP requests of mutated json data models"
        )
        self.parser.add_argument(
            "-m",
            "--model-path",
            metavar="path",
            type=str,
            nargs="?",
            help="The path of the data model file relative to this directory (required)",
            required=True,
        )
        self.parser.add_argument(
            "-d",
            "--domain",
            metavar="domain",
            type=str,
            nargs="?",
            help="The domain name in the data model that describes transport protocol, hostname, etc. (required)",
            required=True,
        )
        self.parser.add_argument(
            "-i",
            metavar="n",
            type=int,
            nargs="?",
            dest="iterations",
            help="Number of iterations per endpoint (defaults to infinite)",
        )
        self.parser.add_argument(
            "-t",
            "--timeout",
            metavar="s",
            type=float,
            nargs="?",
            help="The default maximum time (seconds) to wait for a response per request if not defined in "
            "the data model, defaults to " + str(request.DEFAULT_TIMEOUT),
            default=request.DEFAULT_TIMEOUT,
        )
        self.parser.add_argument(
            "-s",
            metavar="n",
            type=int,
            nargs="?",
            dest="state",
            help="Fuzzer initial state. Used to resume fuzzing sessions or a replay specific case",
            default=0,
        )
        self.parser.add_argument(
            "-g",
            "--gtimeout",
            action="store_true",
            help="Global timeout. If set, all timeout values in the data model will be overridden",
        )
        self.parser.add_argument(
            "-c",
            "--constants",
            metavar="obj",
            type=str,
            nargs="?",
            help="A JSON string where keys are strings to replace and values are the replacement (optional)",
        )
        self.parser.add_argument(
            "-C",
            "--constants-file",
            metavar="path",
            type=str,
            nargs="?",
            help="Relative path to a json file containing placeholder keys and constant values (optional). "
            "If the --constants argument is also used, they will be combined with input from the "
            "constants file. In this case, matching constants will be overwritten by those supplied "
            "with the --constants argument.",
        )
        self.parser.add_argument(
            "-u",
            "--uri",
            metavar="URI",
            type=str,
            nargs="?",
            help="A specific endpoint that the fuzzer will target (defaults to all in the data model)",
        )
        self.parser.add_argument(
            "--method",
            metavar=("list"),
            type=str,
            nargs="+",
            default=None,
            help="An whitespace-separated list of request methods (see RFC7231 section 4.3). If empty, all "
            "methods in the data model are used for the specified uri.",
        )
        self.parser.add_argument(
            "-l",
            "--loglevel",
            metavar=("0,1,2,3"),
            type=int,
            nargs="?",
            choices=self.config.logging_levels.keys(),
            help="The log verbosity level: warning=3, info=2, debug=1, trace=0",
        )
        self.parser.add_argument(
            "--statefile",
            metavar="path",
            type=str,
            nargs="?",
            help="A relative file path that contains a list of states. See test/example_states.txt for details.",
        )
        self.parser.add_argument(
            "--printcurl",
            action="store_true",
            help="The request to print a curl query command only.",
        )

        self.constants = {}
        self.parsed_args = None
        self.fuzzer_results = []
        self.model_file_path = ""
        self.states = []

    def _validate_printcurl_args(self):
        if self.parsed_args.printcurl:
            if not self.parsed_args.uri:
                print("-u argument (uri) is required")
                sys.exit(1)
            if not self.parsed_args.method:
                print("--method argument is required")
                sys.exit(1)

    def _set_logging_level(self):
        if self.parsed_args.loglevel is not None:
            self.config.root_logger.setLevel(
                self.config.logging_levels[self.parsed_args.loglevel]
            )
        else:
            self.config.root_logger.setLevel(self.config.logging_levels[3])

    @staticmethod
    def _get_cmd_string():
        cmd = ""
        for token in sys.argv:
            try:
                if isinstance(json.loads(token), (dict, list)):
                    cmd += " '{0}'".format(token)
                else:
                    cmd += " " + token
            except (json.decoder.JSONDecodeError, TypeError):
                cmd += " " + token
        return cmd

    def _set_constants(self):
        cli_constants = (
            json.loads(self.parsed_args.constants) if self.parsed_args.constants else {}
        )
        if self.parsed_args.constants_file:
            with open(self.parsed_args.constants_file, "r") as file:
                constants_from_file = json.loads(file.read())
                self.constants = (
                    {**constants_from_file, **cli_constants}
                    if constants_from_file
                    else cli_constants
                )
        else:
            self.constants = cli_constants

    def parse_cli_args(self):
        self.parsed_args = self.parser.parse_args()

        self._validate_printcurl_args()
        self._set_logging_level()
        self._set_constants()

        self.states = (
            Fuzzer.get_states_from_file(self.parsed_args.statefile)
            if self.parsed_args.statefile
            else []
        )
        self.model_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), self.parsed_args.model_path
        )

    def run_fuzzer(self):
        fuzzer = Fuzzer(
            self.parsed_args.model_path,
            self.parsed_args.domain,
            self.parsed_args.gtimeout,
            self.parsed_args.state,
            self.parsed_args.timeout,
            self.constants,
            self.parsed_args.uri,
            self.parsed_args.method,
            self.config,
        )

        self.config.root_logger.log(self.config.note_log_level, self._get_cmd_string())

        if self.parsed_args.printcurl:
            print(" ---> Printing curl:\n" + fuzzer.get_curl_query_string())
        else:
            if self.states:
                self.fuzzer_results = fuzzer.fuzz_requests_by_state_list(self.states)
                fuzzer.log_last_state_used(fuzzer.state)
            else:
                self.fuzzer_results = fuzzer.fuzz_requests_by_incremental_state(
                    self.parsed_args.iterations
                )


def main():
    client = Client()
    client.parse_cli_args()
    client.run_fuzzer()


if __name__ == "__main__":
    main()
