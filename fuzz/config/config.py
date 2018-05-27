import os
from pathlib import Path
import locale
import logging
import configparser


class Config:
    # pylint: disable=too-many-instance-attributes, too-few-public-methods

    def __init__(self):
        self._pwd = str(Path(os.path.dirname(os.path.abspath(__file__))).parents[1])
        self.parser = configparser.ConfigParser()
        self.parser.read(os.path.join(self._pwd, "fuzz", "config", "config.ini"))

        locale.setlocale(locale.LC_ALL, "en_US.UTF-8")

        self.log_formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
        self.trace_log_level = 9
        logging.addLevelName(self.trace_log_level, "TRACE")
        self.note_log_level = 51
        logging.addLevelName(self.note_log_level, "NOTE")
        self.logging_levels = {0: self.trace_log_level,
                               1: logging.DEBUG,
                               2: logging.INFO,
                               3: logging.WARNING}
        self.root_logger = logging.getLogger()
        self.root_logger.propagate = False

        self.fuzz_db_array = open(os.path.join(self._pwd, self.parser.get("DEFAULT", "fuzz_db")), "r").read().splitlines()
        self.results_dir = os.path.join(self._pwd, self.parser.get("DEFAULT", "results_dir"))
        self.default_placeholder_pattern = self.parser.get("DEFAULT", "placeholder_pattern")
        self.max_iterations_in_memory = self.parser.getint("DEFAULT", "max_iterrations_in_memory")
        self.model_reload_interval_seconds = self.parser.getint("DEFAULT", "model_reload_interval_seconds")
        self.curl_data_file_path = self.parser.get("DEFAULT", "curl_config")
        self.expectations_path = os.path.join(self._pwd, self.parser.get("DEFAULT", "default_expectations"))
        self.maximum_url_size_in_bytes = self.parser.getint("DEFAULT", "maximumUrlSizeInBytes")
        self.drop_header_chance = self.parser.getfloat("DEFAULT", "drop_header_chance")

        self.slack_client_token = self.parser.get("DEFAULT", "slack_client_token")
        self.slack_channel = self.parser.get("DEFAULT", "slack_channel")
        self.slack_errors_per_hour = self.parser.getint("DEFAULT", "slack_errors_per_hour")
        self.slack_status_update_interval_seconds = self.parser.getint("DEFAULT", "slack_status_update_interval_seconds")

        self.example_json_file = self.parser.get("test", "example_json_file")
        self.example_expectations_file = self.parser.get("test", "example_json_expectation_file")
        self.example_states_file = self.parser.get("test", "example_states_file")

        self.cli_coverage_file = self.parser.get("test", "cli_coverage_file")
        self.fuzzer_coverage_file = self.parser.get("test", "fuzzer_coverage_file")
        self.coverage_xml_file = self.parser.get("test", "coverage_xml_file")
