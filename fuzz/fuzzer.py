import sys
import signal
import json
import logging
import itertools
import traceback
import os
import re
import copy
from collections import OrderedDict
from time import strftime
from time import time
from time import localtime
import slackclient

from fuzz import mutator
from fuzz import request
from fuzz.config.config import Config


class Fuzzer:  # pylint: disable=too-many-instance-attributes

    def log_last_state_used(self, state):
        self.config.root_logger.log(self.config.note_log_level, "Last state used: {0}".format(state))

    def _send_slack_message(self, message):
        return self.slacker.api_call("chat.postMessage", channel=self.config.slack_channel, text=message)

    def exit_handler(self, signum, frame):
        self.config.root_logger.log(self.config.note_log_level, "Exited with signal: {0}".format(signum))
        if signum != 0:
            self.config.root_logger.log(logging.ERROR, traceback.extract_stack(frame))
        self.log_last_state_used(self.state)
        self._send_slack_message("fuzzer stopped")
        sys.exit(signum)

    def _connect_slack_client(self):
        self.slacker = slackclient.SlackClient(self.config.slack_client_token)
        resp = self._send_slack_message("fuzzer started with log " + self.log_file_name)
        if not resp["ok"]:
            self.config.root_logger.log(logging.ERROR,
                                        "failed to connect slack client to channel " + self.config.slack_channel +
                                        " with token " + self.config.slack_client_token)

    def __init__(self, schema_file_path, domain, global_timeout=False, state=0, timeout=None, constants=None,
                 uri=None, methods=None, config_obj=None):
        """
        :param schema_file_path: string file handle for the schema
        :param domain: domain name
        :param global_timeout: if set to true, the timeout value will override all timeouts defined in the data model
        :param state: the starting state number
        :param timeout: amount of seconds (float) that the request api will wait for the first byte of a response
        :param constants: dict of constants used for injecting into model placeholders
        :param uri: string of a specific uri to choose from the model
        :param methods: list of http methods to select from when iterating over each endpoint
        """

        # pylint: disable=too-many-arguments
        # pylint: disable=too-many-statements

        self.constants = constants
        self.schema_file_path = schema_file_path
        self.domain = domain
        self.timeout = timeout if timeout is not None and timeout > 0 else None
        self.global_timeout = global_timeout
        self.state = state
        self.starting_state = state
        self.model_obj = self.load_model()
        self.uri = uri if uri else None
        self.config = config_obj if config_obj else Config()
        self.model_reload_rate = self.config.model_reload_interval_seconds
        self.time_since_last_model_check = 0.0

        if not os.path.exists(self.config.results_dir):
            os.makedirs(self.config.results_dir)

        if methods is None:
            self.methods = request.METHODS
        elif isinstance(methods, list):
            self.methods = []
            for m in methods:
                if m not in request.METHODS:
                    raise RuntimeError("method {0} is not a valid HTTP method".format(str(m)))
                self.methods.append(m.upper())
        elif isinstance(methods, str) and methods in request.METHODS:
            self.methods = [methods]
        else:
            raise RuntimeError("method {0} is not a valid HTTP method".format(str(methods)))

        name = "-" + os.path.splitext(os.path.basename(self.schema_file_path))[0]
        name += re.sub("[{}]", "", self.uri).replace("/", "-") if self.uri else "_all_uris"
        name += "_all_methods" if self.methods == request.METHODS else "_" + "_".join(self.methods)
        self.log_file_name = os.path.join(self.config.results_dir, "{0}{1}.log".format(strftime("%Y%m%d%H%M%S"), name))
        file_handler = logging.FileHandler(self.log_file_name)
        file_handler.setFormatter(self.config.log_formatter)
        self.config.root_logger.addHandler(file_handler)

        try:
            with open(self.config.expectations_path, 'r') as file:
                self.default_expectations = json.loads(file.read(), object_pairs_hook=OrderedDict)
        except FileNotFoundError:
            self.config.root_logger.error("Expectation file " + self.config.expectations_path +
                                          " was unable to open. Default expectations were not set.")
            self.default_expectations = {}

        self.mutator = mutator.Mutator(self.config.fuzz_db_array, state)

        signal.signal(signal.SIGABRT, self.exit_handler)
        signal.signal(signal.SIGFPE, self.exit_handler)
        signal.signal(signal.SIGILL, self.exit_handler)
        signal.signal(signal.SIGINT, self.exit_handler)
        signal.signal(signal.SIGSEGV, self.exit_handler)
        signal.signal(signal.SIGTERM, self.exit_handler)

        self.slacker = None
        self._connect_slack_client()
        self.slack_errors = 0
        self.last_hour = localtime().tm_hour
        self.last_slack_status_update = time()

    @staticmethod
    def evaluate_expectations(expectations_obj, result):
        """
        Determine if the data contained in result meets the requirements provided in expectations_obj.
        :param expectations_obj: A list of code to be evaluated to determine if result is acceptable
        :param result: A result object provided by send_payload
        :return: boolean: True if the result meets the expectation
        """
        # pylint: disable=unused-argument, exec-used
        # result and expectation are actually used in the exec call

        expectation = False  # pylint: disable=unused-variable
        vlocals = locals()

        if expectations_obj:
            for k in expectations_obj.keys():
                for e in expectations_obj[k]:
                    exec(e, globals(), vlocals)

        return vlocals["expectation"]

    @staticmethod
    def inject_constants(model_obj, constants):
        """
        Replace placeholders in the model with values in constants.
        :param model_obj: data model subset
        :param constants: dictionary of placeholders (keys) and replacements (values) for placeholders
        :return: updated model_obj
        """
        if not constants:
            return model_obj
        json_str = json.dumps(model_obj)
        for k in constants.keys():
            if constants[k] is True:
                constants[k] = "true"
            elif constants[k] is False:
                constants[k] = "false"
            json_str = json_str.replace(k, str(constants[k]))
        return json.loads(json_str, object_pairs_hook=OrderedDict)

    def mutate_payload(self, endpoint_obj):
        """
        Mutate the payload
        :param endpoint_obj: an entry in the endpoints list of the data model
        :return: mutated payload dictionary
        """
        payload = OrderedDict()

        payload["uri"] = self.mutator.mutate(endpoint_obj["uri"], True, self.config.default_placeholder_pattern)

        if endpoint_obj["input"].get("body"):
            payload["body"] = self.mutator.mutate(endpoint_obj["input"]["body"],
                                                  pattern=self.config.default_placeholder_pattern)
        else:
            payload["body"] = None

        if endpoint_obj["input"].get("query"):
            payload["query"] = self.mutator.mutate(endpoint_obj["input"]["query"],
                                                   pattern=self.config.default_placeholder_pattern)
        else:
            payload["query"] = None

        payload["headers"] = self.mutate_headers(endpoint_obj.get("headers", {}),
                                                 self.config.default_placeholder_pattern)
        payload["headers"]["X-Hot-Fuzz-State"] = str(self.state)

        return payload

    def send_payload(self, payload, method, timeout, delay=0):
        """
        Send the payload
        :param payload: a mutated payload
        :param method: request method
        :param timeout: amount of seconds (float) that the request api will wait for the first byte of a response
        :param delay: delay in seconds before the payload is sent
        :return: request result dictionary
        """
        return request.send_request(self.model_obj["domains"][self.domain], payload["uri"],
                                    method, timeout, delay, payload["headers"],
                                    payload["body"], payload["query"])

    def load_model(self):
        """
        Load the data model from the schema, then inject constants into the model.
        :return: data model with injected constants
        """
        with open(self.schema_file_path, 'r') as model_file:
            return json.loads(model_file.read(), object_pairs_hook=OrderedDict)

    def get_curl_query_string(self):
        """
        Construct a mutated request payload and print it as a curl command with a curl config file.
        :return: A curl command line string
        """
        if not self.uri:
            raise RuntimeError("uri must be a non-empty string")

        method = self.methods[0]
        endpoints = Fuzzer.get_endpoints(self.model_obj["endpoints"], self.uri, [method])

        if not endpoints:
            raise RuntimeError("failed to locate uri '{0}' with method '{1}' in model".format(self.uri, method))

        endpoint_obj = self.inject_constants(endpoints[0], self.constants)
        payload = self.mutate_payload(endpoint_obj)

        return request.construct_curl_query(self.config.curl_data_file_path, self.model_obj["domains"][self.domain],
                                            payload["uri"], method, payload["headers"],
                                            payload["body"], payload["query"])

    def change_state(self, new_state):
        self.state = new_state
        self.mutator.change_state(self.state)

    @staticmethod
    def get_endpoints(endpoints_list, uri=None, methods=None):
        """
        Get all endpoint definitions for a uri
        :param endpoints_list: the endpoints value of a model
        :param uri: endpoint uri
        :param methods: list of http request methods
        :return:
        """
        if not uri:
            return endpoints_list

        endpoints = []
        for _, endpoint in enumerate(endpoints_list):
            if uri == endpoint.get("uri", "") and\
                    (methods is None or set(endpoint.get("methods", request.METHODS)).intersection(methods) != set()):
                endpoints.append(endpoint)

        return endpoints

    def get_expectations(self, endpoint_obj):
        """
        Get the most granular expectations available for the endpoint.
        :param endpoint_obj: an entry in the endpoints list of the data model
        :return: a list of code used in evaluate_expectations()
        """
        expectations = OrderedDict({})
        if endpoint_obj.get("expectations", False):
            expectations["local"] = endpoint_obj["expectations"]
        elif self.model_obj.get("expectations", False):
            expectations["global"] = self.model_obj["expectations"]
        else:
            expectations = self.default_expectations
        return expectations

    def iterate_endpoints(self):
        """
        Send a newly mutated payload for each uri/method permutation. Logs information for each request.
        :return: dict containing number of iterations (values) for each uri (keys)
        """
        results = []

        for endpoint_obj in Fuzzer.get_endpoints(self.model_obj["endpoints"], self.uri):
            my_timeout = self.timeout
            if not self.global_timeout:
                my_timeout = endpoint_obj.get("timeout", my_timeout)

            requests_per_second = endpoint_obj.get("requestsPerSecond", self.model_obj.get("requestsPerSecond"))
            request_delay = request.get_request_delay(requests_per_second)

            my_methods = list(set(endpoint_obj.get("methods", self.methods)).intersection(self.methods))
            my_methods = [my_methods] if isinstance(my_methods, str) else my_methods

            for method in my_methods:
                if method not in endpoint_obj.get("methods", request.METHODS):
                    break

                injected_endpoint_obj = Fuzzer.inject_constants(endpoint_obj, self.constants)
                mutated_payload = self.mutate_payload(injected_endpoint_obj)

                result = self.send_payload(mutated_payload, method, my_timeout, request_delay)
                results.append(result)

                summary = "state={0} method={1} uri={2} code={3} reason='{4}'"\
                    .format(result["headers"]["X-Hot-Fuzz-State"], method, endpoint_obj["uri"],
                            result.get("httpcode"), result.get("reason"))

                expectations_obj = self.get_expectations(endpoint_obj)

                if Fuzzer.evaluate_expectations(expectations_obj, result) is False:
                    self.config.root_logger.warning(summary)
                    self.config.root_logger.debug(request.dump_result(result))

                    # reset the counted slack errors every hour
                    if self.last_hour != localtime().tm_hour:
                        self.slack_errors = 0
                        self.last_hour = localtime().tm_hour

                    # print the error to slack if it does not exceed the throttle
                    if self.slack_errors < self.config.slack_errors_per_hour:
                        self._send_slack_message(summary)
                        self.slack_errors += 1
                else:
                    self.config.root_logger.info(summary)
                    self.config.root_logger.log(self.config.trace_log_level, request.dump_result(result))
                    if time() - self.last_slack_status_update > self.config.slack_status_update_interval_seconds:
                        self._send_slack_message("current state is " + str(self.state))
                        self.last_slack_status_update = time()

                self.config.root_logger.log(self.config.trace_log_level, "payload: " + json.dumps(mutated_payload))
                if my_timeout is not None:
                    self.config.root_logger.log(self.config.trace_log_level,
                                                "timeout={0}s delay={1}s".format(my_timeout, request_delay))
                else:
                    self.config.root_logger.log(self.config.trace_log_level,
                                                "delay={0}s".format(request_delay))

        return results

    def _check_for_model_update(self):
        """
        If the check interval is reached, check for changes in the current model loaded in memory with a new instance
        loaded from the same schema on the disk. If a change is found, reset the fuzzer state to its starting state,
        update the loaded model, log the event, then reset the check interval.
        :return:
        """
        if self.model_reload_rate > self.time_since_last_model_check:
            return

        model = self.load_model()
        if model != self.model_obj:
            self.model_obj = model
            self.config.root_logger.log(self.config.note_log_level, "at state " + str(self.state) +
                                        " a new data model instance was loaded after detecting a change in " +
                                        self.schema_file_path)
            self.config.root_logger.log(self.config.note_log_level, "state has been reset to " + str(self.starting_state))
            self.change_state(self.starting_state)

        self.time_since_last_model_check = 0.0

    def fuzz_requests_by_incremental_state(self, n_times=None):
        """
        Send a request n_times for each uri/method permutation.
        :param n_times: number of requests, this method will run indefinitely if n_times is None
        :return: dict containing the first number of iterations (values) for each uri (keys)
        """
        maxval = self.config.max_iterations_in_memory
        results = []

        r = itertools.count()
        if n_times and n_times > 0:
            r = range(n_times)

        for _ in r:
            self._check_for_model_update()
            start = time()
            my_results = self.iterate_endpoints()
            if len(results) < maxval and n_times:
                results.extend(my_results)
                if len(results) > maxval:
                    results = results[:maxval]
            self.change_state(self.state + 1)
            self.time_since_last_model_check += time() - start

        return results

    def fuzz_requests_by_state_list(self, states):
        """
        Functionally similar to fuzz_requests_by_incremental_state but instead applies for a list of states.
        :param states: list of state numbers
        :return: dict containing the first number of iterations (values) for each uri (keys)
        """
        maxval = self.config.max_iterations_in_memory
        results = []

        for state in states:
            self.change_state(state)
            my_results = self.iterate_endpoints()
            if len(results) < maxval:
                results.extend(my_results)
                if len(results) > maxval:
                    results = results[:maxval]

        return results

    @staticmethod
    def get_states_from_file(file_handle):
        """
        Get a list of fuzzer states from a text file.
        :param file_handle: relative path to the state file
        :return: list of states read from the file
        """
        states = []
        with open(file_handle, 'r') as state_file:
            for state in state_file.read().split("\n"):
                if state != "":
                    states.append(int(state))
            return states

    def mutate_headers(self, headers, pattern=None):
        """
        Mutate or drop HTTP headers
        :param headers: headers dictionary
        :param pattern: a string regex
        :return: mutated headers
        """
        if headers is None:
            return headers

        mutated_headers = copy.deepcopy(headers)
        headers_to_pop = []

        for (key, value) in mutated_headers.items():
            if pattern and re.search(pattern, value):
                if self.mutator.chance(self.config.drop_header_chance):
                    headers_to_pop.append(key)
                else:
                    mutated_headers[key] = self.mutator.safe_decode(self.mutator.mutate_regex(value, pattern).encode())

        if headers_to_pop:
            for header in headers_to_pop:
                mutated_headers.pop(header, None)

        return mutated_headers
