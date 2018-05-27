import unittest
import sys
import os
import json
import xmlrunner
import coverage

from cli import Client
from fuzz.config.config import Config


test_config = Config()

if os.path.exists(test_config.cli_coverage_file):
    os.remove(test_config.cli_coverage_file)

cov = coverage.Coverage(data_file=test_config.cli_coverage_file,
                        source=["cli",
                                "test.test_cli",
                                "fuzz.config.config"])
cov.start()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.client = Client()
        self.argparse_args = ["-m", os.path.join("."), "-d", "test"]

    def _validate_printcurl_args(self):
        # pylint: disable=protected-access
        def evaluate_args(additional_args):
            self.client.parsed_args = self.client.parser.parse_args(self.argparse_args + additional_args)
            try:
                self.client._validate_printcurl_args()
                self.fail("should raise SystemExit")
            except SystemExit as ex:
                self.assertEqual(ex.code, 1)

        evaluate_args(["--printcurl"])
        evaluate_args(["--printcurl", "--method", "POST"])
        evaluate_args(["--printcurl", "--uri", "/test"])

        self.client.parsed_args = self.client.parser.parse_args(self.argparse_args + ["--printcurl", "--uri", "/test", "--method", "POST"])
        self.client._validate_printcurl_args()

    def _set_logging_level(self):
        # pylint: disable=protected-access
        def evaluate_log_level_arg(level):
            self.client.parsed_args = self.client.parser.parse_args(self.argparse_args + ["-l", str(level)])
            self.client._set_logging_level()
            msg = "should be log level {0} when level was set to {1}".format(self.client.config.logging_levels[level], str(level))
            self.assertEqual(self.client.config.root_logger.level, self.client.config.logging_levels[level], msg)

            self.client.parsed_args = self.client.parser.parse_args(self.argparse_args + ["--loglevel", str(level)])
            self.client._set_logging_level()
            msg = "should be log level {0} when level was set to {1}".format(self.client.config.logging_levels[level], str(level))
            self.assertEqual(self.client.config.root_logger.level, self.client.config.logging_levels[level], msg)

        for i in range(0, len(self.client.config.logging_levels)):
            evaluate_log_level_arg(i)

    def _get_cmd_string(self):
        # pylint: disable=protected-access
        args = ["./cli.py"] + self.argparse_args
        sys.argv = args
        self.assertEqual(self.client._get_cmd_string().strip(" "), " ".join(sys.argv).strip(" "),
                         "should reproduce command line input as a string")

        jsonargs = ["-c", '{"my": "test", "json": "arg"}']
        sys.argv = args + jsonargs
        actual = self.client._get_cmd_string().strip(" ")
        expected = " ".join(args + [jsonargs[0]]) + " '{0}'".format(jsonargs[1])
        self.assertEqual(actual, expected, "should reproduce input with json arg surrounded with quotes")

    def _set_constants(self):
        # pylint: disable=protected-access
        jsonfile = self.client.config.example_json_file
        jsonfile_args = ["-C", jsonfile]
        args = self.argparse_args + jsonfile_args
        self.client.parsed_args = self.client.parser.parse_args(args)
        self.client._set_constants()
        with open(jsonfile, "r") as file:
            jsonfile_constants = json.loads(file.read())
        self.assertEqual(self.client.constants, jsonfile_constants, "should load constants from " + jsonfile)

        jsonstring_args = ["-c", '{"{otherPlaceholder}":5}']
        args += jsonstring_args
        self.client.parsed_args = self.client.parser.parse_args(args)
        self.client._set_constants()
        constants = self.client.constants
        constants.update(json.loads(jsonstring_args[1]))
        self.assertEqual(self.client.constants, constants,
                         "should combine constants from " + jsonfile + " with args from " + str(jsonstring_args))

        jsonstring_args = ["-c", '{"{otherPlaceholder}":5, "{placeholder}":"test"}']
        args = self.argparse_args + jsonfile_args + jsonstring_args
        self.client.parsed_args = self.client.parser.parse_args(args)
        self.client._set_constants()
        constants = self.client.constants
        constants.update(json.loads(jsonstring_args[1]))
        self.assertEqual(self.client.constants, constants,
                         "should overwrite constants from " + jsonfile + " with args from " + str(jsonstring_args))

    def parse_cli_args(self):
        model_file = self.client.config.example_json_file
        cmdline_args = ["./cli.py", "-d", "test", "-m", model_file]
        sys.argv = cmdline_args
        self.client.parse_cli_args()
        self.assertEqual(self.client.states, [], "should have empty state list since no state file was provided")
        with open(self.client.model_file_path, "r"):
            pass

        state_file = self.client.config.example_states_file
        sys.argv = cmdline_args + ["--statefile", state_file]
        self.client.parse_cli_args()
        expected_states = [234, 812, 1, 999909, 234, 22222893428923498, 9]
        self.assertEqual(self.client.states.sort(), expected_states.sort())

    def run_fuzzer(self):
        model_file = self.client.config.example_json_file
        state_file = self.client.config.example_states_file
        cmdline_args = ["./cli.py", "-d", "local", "-m", model_file, "-u", "/json", "--method", "POST"]
        sys.argv = cmdline_args + ["--statefile", state_file]
        self.client.parse_cli_args()
        self.client.run_fuzzer()
        expected_nstates = 7
        self.assertEqual(len(self.client.fuzzer_results),
                         expected_nstates,
                         "should execute " + str(expected_nstates) + " iterations (each state in the state file)")

        sys.argv = cmdline_args + ["-i", str(expected_nstates)]
        self.client.parse_cli_args()
        self.client.run_fuzzer()
        self.assertEqual(len(self.client.fuzzer_results),
                         expected_nstates,
                         "should execute " + str(expected_nstates) + " iterations")


Suite = unittest.TestSuite()
Suite.addTests([CliTests("_validate_printcurl_args"),
                CliTests("_set_logging_level"),
                CliTests("_get_cmd_string"),
                CliTests("_set_constants"),
                CliTests("parse_cli_args"),
                CliTests("run_fuzzer")])

test_runner = xmlrunner.XMLTestRunner(output="results", verbosity=int(os.environ.get("VERBOSE", 2)))

result = not test_runner.run(Suite).wasSuccessful()
cov.stop()
cov.save()

try:
    cov.combine(data_paths=[test_config.cli_coverage_file,
                            test_config.fuzzer_coverage_file], strict=True)
except coverage.CoverageException:
    pass  # ignore the exception, but don't combine if not all files exist to prevent xml report failure
cov.xml_report(outfile=test_config.coverage_xml_file)

sys.exit(result)
