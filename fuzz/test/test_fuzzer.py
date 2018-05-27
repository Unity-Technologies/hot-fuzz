# pylint: disable=too-many-lines
import sys
import unittest
import re
import os
import json
import threading
import copy
import urllib
from urllib.parse import urlparse
import logging
import time
from collections import OrderedDict

import xmlrunner
import coverage
import fuzz.test.mockserver

from fuzz import mutator
from fuzz import request
from fuzz.fuzzer import Fuzzer
from fuzz.config.config import Config

root_logger = logging.getLogger()
root_logger.propagate = False
root_logger.setLevel(logging.INFO)

Mutator = mutator.Mutator

test_config = Config()

if os.path.exists(test_config.fuzzer_coverage_file):
    os.remove(test_config.fuzzer_coverage_file)

cov = coverage.Coverage(data_file=test_config.fuzzer_coverage_file,
                        source=["fuzz.fuzzer",
                                "fuzz.mutator",
                                "fuzz.request",
                                "fuzz.test.test_fuzzer",
                                "fuzz.config.config"])
cov.start()

# pylint: disable=too-many-public-methods


class MutatorTests(unittest.TestCase):
    def setUp(self):
        with open(test_config.example_json_file, 'r') as model_file:
            self.model = json.loads(model_file.read(), object_pairs_hook=OrderedDict)
        self.n_times = 10000
        self.tolerance = 0.015
        self.mutator = Mutator(test_config.fuzz_db_array)
        self.sample = "abcdef0123456789öåä!#€%&/()=?©@£$∞§|[]≈±´~^¨*abcdef0123456789öåä!#€%&/()=?©@£$∞§|[]≈±´~^¨*"

    def chance(self):
        expected_probability = 0.1
        result = {True: 0, False: 0}
        for _ in range(self.n_times):
            r = self.mutator.chance(expected_probability)
            result[r] += 1
            self.mutator.change_state(_ + 1)
        diff = abs(result[True] / self.n_times - expected_probability)
        self.assertGreaterEqual(self.tolerance, diff,
                                "{0} exceeded tolerance of {1} for probability {2}".format(diff, self.tolerance,
                                                                                           expected_probability))

    def chance_identity(self):
        list1 = []
        list2 = []
        probability = 0.5
        for _ in range(self.n_times):
            list1.append(self.mutator.chance(probability))
            list2.append(self.mutator.chance(probability))
        self.assertEqual(list1, list2,
                         "both lists should contain the same output since the mutator state never changed")

    def roll_dice(self):
        result = [0, 0, 0, 0, 0, 0]  # total hits for each die face
        faces = len(result)
        expected_probability = 1 / faces
        for _ in range(self.n_times):
            r = self.mutator.roll_dice(1, faces)
            result[r - 1] += 1
            self.mutator.change_state(_ + 1)
        for n in range(faces):
            diff = abs(result[n] / self.n_times - expected_probability)
            self.assertGreaterEqual(self.tolerance, diff,
                                    "{0} exceeded tolerance of {1} for probability {2}".format(diff, self.tolerance,
                                                                                               expected_probability))

    def roll_dice_identity(self):
        list1 = []
        list2 = []
        minimum = 0
        maximum = 10
        for _ in range(self.n_times):
            list1.append(self.mutator.roll_dice(minimum, maximum))
            list2.append(self.mutator.roll_dice(minimum, maximum))
        self.assertEqual(list1, list2,
                         "both lists should contain the same output since the mutator state never changed")

    def juggle_type(self):
        result = {
            str: 0,
            bool: 0,
            int: 0,
            list: 0,
            dict: 0,
            type(None): 0
        }
        expected_probability = 1 / len(result)
        for _ in range(self.n_times):
            value = self.mutator.juggle_type(0)
            result[type(value)] += 1
            self.mutator.change_state(_ + 1)
        for key, _ in result.items():
            diff = abs(result[key] / self.n_times - expected_probability)
            self.assertGreaterEqual(self.tolerance, diff,
                                    "{0} exceeded tolerance of {1} for probability {2}".format(diff, self.tolerance,
                                                                                               expected_probability))

    def mutate_radamsa_state_change(self):
        n_times = 100
        previous_value = None
        for n in range(n_times):
            self.mutator.change_state(n)
            value = self.mutator.mutate_radamsa(self.sample)
            self.assertNotEqual(previous_value, value,
                                "mutator output should differ if the state changes, last state was " + str(
                                    self.mutator.state))
            previous_value = value

    def mutate_radamsa_state_static(self):
        n_times = 100
        for _ in range(n_times):
            self.mutator.change_state(0)
            value = self.mutator.mutate_radamsa(self.sample)
            self.assertEqual(self.mutator.mutate_radamsa(self.sample), value,
                             "mutator output should remain the same if state != -1 and remains constant")

    def mutate_radamsa_nondeterministic(self):
        self.mutator.mutate_radamsa(self.sample)

    def mutate_radamsa_encoding_change(self):
        defaultEncodingMutation = self.mutator.mutate_radamsa(self.sample)
        self.assertEqual(self.mutator.mutate_radamsa(self.sample), defaultEncodingMutation, "should be equal output for same state and encoding")
        self.mutator.byte_encoding = "utf-16"
        asciiEncodingMutation = self.mutator.mutate_radamsa(self.sample)
        self.assertNotEqual(defaultEncodingMutation, asciiEncodingMutation, "should have different output for same state and different encoding")

    def mutate_val_state_static(self):
        n_times = 100
        for _ in range(n_times):
            self.mutator.change_state(0)
            value = self.mutator.mutate_val(self.sample)
            self.assertEqual(self.mutator.mutate_val(self.sample), value,
                             "mutator output should remain the same if state != -1 and remains constant")

    def mutate_val_nondeterministic(self):
        self.mutator.mutate_val(self.sample)

    def list_obj_iterable(self):
        dictionary = {1: 0}
        self.assertEqual(self.mutator.list_obj_iterable(dictionary), dictionary, "should no-op if input is a dict")
        lst = [1, 1]
        self.assertEqual(self.mutator.list_obj_iterable([1, 1]), range(len(lst)),
                         "iteration range should be the length of the list")
        string = "11"
        self.assertEqual(self.mutator.list_obj_iterable(string), range(len(string)),
                         "iteration range should be the length of the string")

    def walk_and_mutate(self):
        obj = {"1": {"2": {"3": [0, 1]}}}
        self.assertNotEqual(self.mutator.walk_and_mutate(obj, False, None), obj, "dict should mutate")

        lst = [0, 1, 2]
        self.assertNotEqual(self.mutator.walk_and_mutate(lst, False, None), lst, "list should mutate")

    def walk_and_mutate_strict(self):
        placeholder_str = "{placeholder}"
        plain_str = " text outside of placeholder"
        obj = {"1": placeholder_str + plain_str}
        mutated_obj = copy.deepcopy(obj)
        self.mutator.walk_and_mutate(mutated_obj, True, test_config.default_placeholder_pattern)
        self.assertNotEqual(mutated_obj, obj, "dict should mutate")
        self.assertIn(plain_str, mutated_obj["1"], "string mutation should only apply for pattern in strict mode")
        self.assertNotIn(placeholder_str, mutated_obj["1"], "string mutation not apply for plain text in strict mode")

        mutated_obj = copy.deepcopy(obj)
        self.mutator.walk_and_mutate(mutated_obj, False, test_config.default_placeholder_pattern)
        self.assertNotEqual(mutated_obj, obj, "dict should mutate")
        self.assertIn(plain_str, mutated_obj["1"], "string mutation should only apply for pattern in non-strict mode")
        self.assertNotIn(placeholder_str, mutated_obj["1"],
                         "string mutation not apply for plain text in non-strict mode")

        mutated_obj = copy.deepcopy(obj)
        self.mutator.walk_and_mutate(mutated_obj, False, "asdf")
        self.assertNotEqual(mutated_obj, obj, "dict should mutate")
        self.assertNotIn(plain_str, mutated_obj["1"],
                         "string mutation should apply for entire string if pattern is not matched in non-strict mode")
        self.assertNotIn(placeholder_str, mutated_obj["1"],
                         "string mutation should apply for entire string if pattern is not matched in non-strict mode")

        mutated_obj = copy.deepcopy(obj)
        self.mutator.walk_and_mutate(mutated_obj, True, None)
        self.assertEqual(mutated_obj, obj, "dict should not mutate if in strict mode but no pattern")

    def mutate(self):
        state = self.mutator.state
        self.assertIsNone(self.mutator.mutate(None), "empty objects should not mutate")
        self.assertEqual(state, self.mutator.state, "mutator state should not change")

        obj = {"type": "asdfa{adsf}"}
        self.assertNotEqual(self.mutator.mutate(obj), obj, "objects should mutate")
        self.assertEqual(state, self.mutator.state, "mutator state should not change")
        self.assertEqual(self.mutator.mutate(obj), self.mutator.mutate(obj),
                         "output should be identical since state has not changed")

        obj = "/some/shoopy/uri"
        self.assertNotEqual(self.mutator.mutate(obj), obj, "strings should mutate")
        self.assertEqual(state, self.mutator.state, "mutator state should not change")
        self.assertEqual(self.mutator.mutate(obj), self.mutator.mutate(obj),
                         "output should be identical since state has not changed")

    def mutate_strict(self):
        base = "asdf/"
        placeholder = "{test}"
        obj = {"string": base + placeholder}
        mutated = self.mutator.mutate(obj, True, test_config.default_placeholder_pattern)
        self.assertNotEqual(mutated, obj, "object should mutate if in strict mode and has pattern")

        mutated = self.mutator.mutate(obj, True)
        self.assertEqual(mutated, obj, "object shouldn't mutate if in strict mode and no pattern")

        mutated = self.mutator.mutate(obj, True, "ffff")
        self.assertEqual(mutated, obj, "object shouldn't mutate if pattern not found in field and in strict mode")

        mutated = self.mutator.mutate(obj, pattern="ffff")
        self.assertNotEqual(mutated, obj, "object should mutate if not in strict mode")

        obj = "/some/nuby/uri/" + placeholder
        mutated = self.mutator.mutate(obj, True, test_config.default_placeholder_pattern)
        self.assertNotEqual(mutated, obj, "string should mutate if in strict mode and has pattern")

        mutated = self.mutator.mutate(obj, True)
        self.assertEqual(mutated, obj, "string shouldn't mutate if in strict mode and no pattern")

        mutated = self.mutator.mutate(obj, True, "ffff")
        self.assertEqual(mutated, obj, "string shouldn't mutate if pattern not found in field and in strict mode")

        mutated = self.mutator.mutate(obj, pattern="ffff")
        self.assertNotEqual(mutated, obj, "object should mutate if not in strict mode")

    def mutate_regex_str(self):
        uri = "/my/{sherby}/{uri}"
        mutatedObj = self.mutator.mutate_regex(uri, test_config.default_placeholder_pattern)
        self.assertNotEqual(uri, mutatedObj, "uri should mutate")
        self.assertIsNotNone(re.search(test_config.default_placeholder_pattern, uri), "uri should not contain placeholders")

        myPlaceholder = "asdf"
        mutatedObj = self.mutator.mutate_regex(uri, myPlaceholder)
        self.assertEqual(uri, mutatedObj, "uri should not mutate")
        self.assertIsNone(re.search(myPlaceholder, uri), "uri should contain placeholders")

    def mutate_regex_obj(self):
        uri = "/json"
        obj = Fuzzer.get_endpoints(self.model["endpoints"], uri)[0]["input"]["body"]
        staticValue = "stuff "
        dynamicValue = "{placeholder}"
        self.assertIsNotNone(re.search(test_config.default_placeholder_pattern, obj["dynamicField"]),
                             "obj should contain placeholder")
        self.assertIn(staticValue + dynamicValue, obj["dynamicField"], "field should contain string")
        mutatedObj = self.mutator.mutate(obj, pattern=test_config.default_placeholder_pattern)
        self.assertNotEqual(obj, mutatedObj, "obj should mutate")
        self.assertIsNone(re.search(test_config.default_placeholder_pattern, mutatedObj["dynamicField"]),
                          "mutatedObj should not contain placeholder")
        self.assertIn(staticValue, mutatedObj["dynamicField"],
                      "mutatedObj field should not fuzz the part of the string which is not a placeholder")

    def change_state(self):
        self.mutator.change_state(0)
        self.assertEqual(self.mutator.state, 0, "should be state=0 after setting the state to 0")

        rand_state = self.mutator.own_rand.getstate()
        first = self.mutator.own_rand.randint(0, sys.maxsize)
        self.assertNotEqual(rand_state, self.mutator.own_rand.getstate(), "the internal random state should change")
        self.assertNotEqual(first, self.mutator.own_rand.randint(0, sys.maxsize), "should change after initial seed")

        self.mutator.change_state(0)
        self.assertEqual(rand_state, self.mutator.own_rand.getstate(),
                         "the internal random state should match the initial state")
        self.assertEqual(first, self.mutator.own_rand.randint(0, sys.maxsize),
                         "should be the same output if the seed is the same")

    def safe_decode(self):
        emoji = "🙂"
        self.assertEqual(self.mutator.safe_decode(emoji.encode()), emoji.encode().decode(self.mutator.byte_encoding),
                         "should properly decode '{0}' using {1} encoding"
                         .format(emoji, self.mutator.byte_encoding))
        self.mutator.byte_encoding = "ascii"
        self.assertEqual(self.mutator.safe_decode(emoji.encode()), str(emoji.encode()),
                         "should stringify '{0}' bytes because it cannot decode using {1} byte encoding"
                         .format(emoji, self.mutator.byte_encoding))


Suite = unittest.TestSuite()
Suite.addTests([MutatorTests("chance"),
                MutatorTests("chance_identity"),
                MutatorTests("roll_dice"),
                MutatorTests("roll_dice_identity"),
                MutatorTests("juggle_type"),
                MutatorTests("mutate_radamsa_state_change"),
                MutatorTests("mutate_radamsa_state_static"),
                MutatorTests("mutate_radamsa_encoding_change"),
                MutatorTests("mutate_radamsa_nondeterministic"),
                MutatorTests("mutate_val_state_static"),
                MutatorTests("mutate_val_nondeterministic"),
                MutatorTests("list_obj_iterable"),
                MutatorTests("walk_and_mutate"),
                MutatorTests("walk_and_mutate_strict"),
                MutatorTests("mutate"),
                MutatorTests("mutate_strict"),
                MutatorTests("mutate_regex_str"),
                MutatorTests("mutate_regex_obj"),
                MutatorTests("change_state"),
                MutatorTests("safe_decode")])


class RequestTests(unittest.TestCase):
    def setUp(self):
        with open(test_config.example_json_file, 'r') as model_file:
            self.model = json.loads(model_file.read(), object_pairs_hook=OrderedDict)
        self.critical_headers = ["authorization", "content-type", "x-hot-fuzz-state"]

    def send_request(self):
        uri = "/json"
        method = "GET"
        endpoint = Fuzzer.get_endpoints(self.model["endpoints"], uri)[0]
        r = None
        retries = 10
        for _ in range(0, retries):
            r = request.send_request(self.model["domains"]["local"], endpoint["uri"], method,
                                     body_obj=endpoint["input"]["body"])
            if r.get("httpcode") == 200:
                break

        self.assertEqual(r.get("httpcode"), 200, "all {0} retries failed: {1}".format(str(retries), r["reason"]))

    def send_request_timeout(self):
        uri = "/sleepabit"
        method = "GET"
        endpoint = Fuzzer.get_endpoints(self.model["endpoints"], uri)[0]
        r = request.send_request(self.model["domains"]["local"], endpoint["uri"], method, timeout=0.1,
                                 query_obj=endpoint["input"]["query"])
        error = "ReadTimeoutError"
        self.assertIn(error, r["reason"], "expected to find {0} in the failure reason: {1}".format(error, r["reason"]))

    def send_request_body_and_query(self):
        uri = "/poorly/designed/endpoint"
        method = "GET"
        endpoint = Fuzzer.get_endpoints(self.model["endpoints"], uri)[0]
        r = request.send_request(self.model["domains"]["local"], endpoint["uri"], method, timeout=0.1,
                                 body_obj=endpoint["input"]["body"], query_obj=endpoint["input"]["query"])
        self.assertEqual(r["body"],
                         endpoint["input"]["body"],
                         "expected response to contain request body")
        self.assertEqual(r["url"],
                         request.get_encoded_url(self.model["domains"]["local"], endpoint["uri"],
                                                 endpoint["input"]["query"]),
                         "expected response to contain url-encoded query")

    def _expect_tokens(self, qobj, qstring):
        n_expected = len(qobj) + len(qobj["list"]) - 2
        n_actual = len([m.start() for m in re.finditer("[^?&]&", qstring)])
        self.assertEqual(n_expected, n_actual,
                         "expected {0} '&'s but found {1} for string {2}".format(str(n_expected), str(n_actual),
                                                                                 qstring))

        n_expected = len(qobj) + len(qobj["list"]) - 1
        n_actual = len([m.start() for m in re.finditer("[^?=&]=", qstring)])
        self.assertEqual(n_expected, n_actual,
                         "expected {0} '='s but found {1} for string {2}".format(str(n_expected), str(n_actual),
                                                                                 qstring))

        n_expected = len(qobj["list"])
        n_actual = len([m.start() for m in re.finditer(r"\[\]=", qstring)])
        self.assertEqual(n_expected, n_actual,
                         "expected {0} '[]='s but found {1} for string {2}".format(str(n_expected), str(n_actual),
                                                                                   qstring))

        self.assertEqual("?", qstring[0], "first character of {0} should be '?'".format(qstring))
        self.assertNotEqual("&", qstring[len(qstring) - 1], "last character of {0} should not be '&'".format(qstring))

    def _check_url(self, domain_obj, uri, input_obj):
        url = request.get_encoded_url(domain_obj, uri, input_obj.get("query"))
        parsed_url = urlparse(url)
        self.assertEqual(parsed_url.scheme, domain_obj["protocol"], "protocol should match")
        self.assertEqual(parsed_url.netloc, domain_obj["host"], "host should match")
        self.assertEqual(parsed_url.path, uri, "uri should match")
        if "query" in input_obj:
            self.assertEqual(parsed_url.query, urllib.parse.quote(parsed_url.query, safe="/*-._[]&%="),
                             "query syntax should match")

    def get_encoded_url(self):
        endpoint_obj = Fuzzer.get_endpoints(self.model["endpoints"], "/query/string")[0]
        domain_obj = self.model["domains"]["example"]
        self._check_url(domain_obj, endpoint_obj["uri"], endpoint_obj["input"])
        url = request.get_encoded_url(domain_obj, endpoint_obj["uri"], endpoint_obj["input"]["query"])
        self.assertIn("false", url, "should have a lower-case bool/string")
        self.assertNotIn("False", url, "should not have an upper-case bool/string")

        endpoint_obj = Fuzzer.get_endpoints(self.model["endpoints"], "/complex/qstring")[0]
        self._check_url(domain_obj, endpoint_obj["uri"], endpoint_obj["input"])

        endpoint_obj = Fuzzer.get_endpoints(self.model["endpoints"], "/poorly/designed/endpoint")[0]
        self._check_url(domain_obj, endpoint_obj["uri"], endpoint_obj["input"])

    def get_endpoints(self):
        self.assertEqual(Fuzzer.get_endpoints(self.model["endpoints"]), self.model["endpoints"],
                         "should return same object if no criteria was specified")

        uri = "/multiple"
        nExpected = 3
        endpoints = Fuzzer.get_endpoints(self.model["endpoints"], uri)
        self.assertEqual(len(endpoints), nExpected, "should have {0} endpoint definitions for {1}".format(nExpected, uri))

        methods = ["PUT", "PATCH"]
        nExpected = 1
        endpoints = Fuzzer.get_endpoints(self.model["endpoints"], uri, methods)
        self.assertEqual(len(endpoints), nExpected, "should have {0} endpoint definition for {1} which has methods {2}".format(nExpected, uri, methods))

    def get_endpoints_uri(self):
        uri = "/multiple"
        endpoints = Fuzzer.get_endpoints(self.model["endpoints"], uri=uri)
        n_expected = 3
        self.assertEqual(len(endpoints), n_expected, "should have {0} {1} endpoints".format(str(n_expected), uri))

        uri = "asdfasdf"
        endpoints = Fuzzer.get_endpoints(self.model["endpoints"], uri=uri)
        n_expected = 0
        self.assertEqual(len(endpoints), n_expected, "should have {0} {1} endpoints".format(str(n_expected), uri))

    def dump_result(self):
        result = {"result": "abc", "stuff": 123}
        self.assertNotIn("result", request.dump_result(result))
        self.assertIn("stuff", request.dump_result(result))

        result = {"stuff": 123}
        self.assertNotIn("result", request.dump_result(result))
        self.assertIn("stuff", request.dump_result(result))

        result = {}
        self.assertEqual("{}", request.dump_result(result))

    def construct_curl_query(self):
        curl_data_file_path = test_config.curl_data_file_path
        uri = "/poorly/designed/endpoint"
        method = "GET"
        endpoint = Fuzzer.get_endpoints(self.model["endpoints"], uri)[0]
        domain_obj = self.model["domains"]["local"]

        actual_query = request.construct_curl_query(curl_data_file_path, domain_obj,
                                                    uri, method,
                                                    endpoint["headers"], endpoint["input"]["body"],
                                                    endpoint["input"]["query"])

        expected_query = "curl -g -K {0}".format(curl_data_file_path)

        self.assertEqual(expected_query, actual_query, "should construct a valid curl query")

    def get_request_delay(self):
        requests_per_second = 0.5
        actual_request_delay = request.get_request_delay(requests_per_second)
        expected_request_delay = 2

        self.assertEqual(expected_request_delay, actual_request_delay, "Request delay is incorrect")

    def delay_request(self):
        endpoint = Fuzzer.get_endpoints(self.model["endpoints"], "/delayabit")[0]

        request_delay = request.get_request_delay(endpoint["requestsPerSecond"])
        now = time.time()
        response = request.send_request(self.model["domains"]["local"], endpoint["uri"],
                                        "GET", delay=request_delay)
        request_time = time.time() - now
        expected_delay = 0.4
        self.assertEqual(expected_delay, response["delay"], "Delay should be represented in the response object")
        tolerance = 0.005
        self.assertGreaterEqual(round(request_time - expected_delay, 3), round(response["time"] - tolerance, 3),
                                "Request time should be equal to the time between building the request to receiving"
                                " the response, minus the delay time +/- " + str(tolerance))
        self.assertLessEqual(round(request_time - expected_delay, 3), round(response["time"] + tolerance, 3),
                             "Request time should be equal to the time between building the request to receiving"
                             " the response, minus the delay time +/- " + str(tolerance))

    def get_header_size_in_bytes(self):
        header = {"Accept": "application/json"}
        expected_size = 28
        self.assertEqual(request.get_header_size_in_bytes(header), expected_size, "should have size {0}".format(expected_size))

    def send_request_result_size(self):
        method = "GET"
        uri = "/poorly/designed/endpoint"
        endpoint = Fuzzer.get_endpoints(self.model["endpoints"], uri, methods=[method])[0]
        headers = endpoint["headers"]
        body = endpoint["input"]["body"]
        query = endpoint["input"]["query"]
        result = request.send_request(self.model["domains"]["example"], uri, method, headers_obj=headers,
                                      body_obj=body, query_obj=query)
        expected_url_size = 63
        self.assertEqual(len(result["url"]), expected_url_size)
        expected_body_size = 35
        self.assertEqual(len(json.dumps(result["body"])), expected_body_size)
        expected_header_size = 58
        self.assertEqual(request.get_header_size_in_bytes(result["headers"]), expected_header_size)
        expected_size = expected_url_size + expected_body_size + expected_header_size
        self.assertEqual(result["size"], expected_size, "should have size {0}".format(expected_size))

    def truncate_object(self):
        obj = {"a": "a", "b": "bb"}
        expectedObj = {"a": "", "b": ""}
        n_bytes = 3
        self.assertDictEqual(request.truncate_object(obj, n_bytes), expectedObj,
                             "should remove {0} bytes from object values".format(n_bytes))

        obj = {"a": "a", "b": 10}
        expectedObj = {"a": "", "b": 10}
        self.assertDictEqual(request.truncate_object(obj, n_bytes), expectedObj,
                             "should remove {0} bytes from object values and ignore non-string values".format(n_bytes))

        obj = expectedObj
        self.assertDictEqual(request.truncate_object(obj, n_bytes, is_header=True), expectedObj,
                             "should not change object if it has already been truncated by same amount of bytes")

    def truncate_header_object(self):
        obj = {self.critical_headers[0]: "Bearer my.token", "X-Debug": "abcdefg"}
        expectedObj = {self.critical_headers[0]: "Bearer my.token", "X-Debug": ""}
        n_bytes = 30
        self.assertDictEqual(request.truncate_object(obj, n_bytes, is_header=True), expectedObj,
                             "should remove {0} bytes from object values that are not in {1}".format(n_bytes, self.critical_headers))

        obj = {self.critical_headers[0]: "Bearer my.token"}
        expectedObj = obj
        n_bytes = 30
        self.assertDictEqual(request.truncate_object(obj, n_bytes, is_header=True), expectedObj,
                             "shouldn't truncate {0} field if the value is not longer than {1}".format(self.critical_headers[0], n_bytes))

        n_bytes = 30
        obj = {self.critical_headers[0]: "".join("a" for c in range(n_bytes * 2))}
        expectedObj = {self.critical_headers[0]: "".join("a" for c in range(n_bytes))}
        self.assertDictEqual(request.truncate_object(obj, n_bytes, is_header=True), expectedObj,
                             "should truncate {0} field if the value is longer than {1}".format(self.critical_headers[0], n_bytes))

    def sanitize_headers(self):
        obj = {self.critical_headers[0]: "Bearer my.token", "X-Debug": " aaaa\nbb b\x02 "}
        expectedObj = {self.critical_headers[0]: "Bearer my.token", "X-Debug": "aaaabb b"}
        self.assertDictEqual(request.sanitize_headers(obj), expectedObj,
                             "should not have control characters, newlines, or leading/trailing whitespace")

        obj = expectedObj
        self.assertDictEqual(request.sanitize_headers(obj), expectedObj,
                             "should not change headers if they are already sanitized")

        obj = {"X-Debug": "".join("a" for i in range(request.MAX_REQUEST_SEGMENT_SIZE))}
        size = request.get_header_size_in_bytes(obj)
        expectedSize = len(obj["X-Debug"]) - int(size / request.TRUNCATION_RESIZE_FACTOR)
        expectedObj = {"X-Debug": "".join("a" for i in range(expectedSize))}
        self.assertDictEqual(request.sanitize_headers(obj), expectedObj,
                             "should have truncated field with byte length of {0}".format(expectedSize))

    def sanitize_url(self):
        domain_obj = self.model["domains"]["local"]
        uri = "/i/have/the/best/uri/EVAR"
        size = request.MAX_REQUEST_SEGMENT_SIZE
        query_obj = {"a": "".join("b" for i in range(size))}
        expected_url = request.get_encoded_url(domain_obj, uri, query_obj)[:request.MAX_REQUEST_SEGMENT_SIZE]
        self.assertEqual(request.sanitize_url(domain_obj, uri, query_obj), expected_url,
                         "should be equal after truncating to length {0}".format(len(expected_url)))

    def sanitize(self):
        domain_obj = self.model["domains"]["local"]
        uri = "/i/have/the/best/uri/EVAR"
        headers_obj = {self.critical_headers[0]: "Bearer my.token", "X-Debug": " aaaa\nbb b\x02 "}
        size = request.MAX_REQUEST_SEGMENT_SIZE
        query_obj = {"a": "".join("a" for i in range(size))}

        url, sanitized_headers_obj = request.sanitize(domain_obj, uri, query_obj, headers_obj)
        url_size = len(url)
        headers_size = request.get_header_size_in_bytes(sanitized_headers_obj)

        self.assertEqual(sanitized_headers_obj, request.sanitize_headers(headers_obj),
                         "headers should be sanitized")
        self.assertEqual(url, request.sanitize_url(domain_obj, uri, query_obj, url_size),
                         "url should be sanitized")
        self.assertLessEqual(url_size + headers_size, request.MAX_REQUEST_SEGMENT_SIZE,
                             "combined size of sanitized url and headers should be at most {0}".format(request.MAX_REQUEST_SEGMENT_SIZE))

    def sanitize_url_length_limit(self):
        domain_obj = self.model["domains"]["local"]
        base_url = "http://localhost:8080"
        max_length = test_config.maximum_url_size_in_bytes
        addedLength = max_length - len(base_url + "/")
        uri = "/" + "".join("a" for i in range(addedLength))
        url, _ = request.sanitize(domain_obj, uri)
        self.assertEqual(len(url), max_length, "URL should be maximum length")

        uri = "/" + "".join("a" for i in range(addedLength + 1))
        url, _ = request.sanitize(domain_obj, uri)
        self.assertEqual(len(url), max_length, "URL should be truncated to maximum length")

        uri = "/" + "".join("a" for i in range(addedLength - 1))
        url, _ = request.sanitize(domain_obj, uri)
        self.assertEqual(len(url), max_length - 1, "URL should be one less than maximum length")


Suite.addTests([RequestTests("send_request"),
                RequestTests("send_request_timeout"),
                RequestTests("send_request_body_and_query"),
                RequestTests("get_encoded_url"),
                RequestTests("get_endpoints"),
                RequestTests("get_endpoints_uri"),
                RequestTests("dump_result"),
                RequestTests("construct_curl_query"),
                RequestTests("get_request_delay"),
                RequestTests("delay_request"),
                RequestTests("get_header_size_in_bytes"),
                RequestTests("send_request_result_size"),
                RequestTests("truncate_object"),
                RequestTests("truncate_header_object"),
                RequestTests("sanitize_headers"),
                RequestTests("sanitize_url"),
                RequestTests("sanitize"),
                RequestTests("sanitize_url_length_limit")])


class FuzzerTests(unittest.TestCase):
    # pylint: disable=too-many-public-methods
    def setUp(self):
        self.domain = "local"
        self.fuzzer = Fuzzer(test_config.example_json_file, self.domain)
        self.default_expectations = {"default": ["code = int(result.get('httpcode', 0))",
                                                 "expectation = (code >= 400 and code < 500) or " +
                                                 "('error' in result.get('response', '').lower() and code < 400)"]}

    def init_methods(self):
        fuzzy = Fuzzer(test_config.example_json_file, self.domain)
        expected_methods = request.METHODS
        self.assertEqual(fuzzy.methods, expected_methods, "should contain all methods if none were initialized")

        try:
            Fuzzer(test_config.example_json_file, self.domain, methods=["GET", "NOT_A_METHOD"])
            self.fail("should throw RuntimeError because of invalid HTTP method")
        except RuntimeError:
            pass

        try:
            Fuzzer(test_config.example_json_file, self.domain, methods="GET, NOT_A_METHOD")
            self.fail("should throw RuntimeError because of invalid HTTP method")
        except RuntimeError:
            pass

        try:
            Fuzzer(test_config.example_json_file, self.domain, methods=0)
            self.fail("should throw RuntimeError because of invalid HTTP method")
        except RuntimeError:
            pass

        method = "GET"
        fuzzy = Fuzzer(test_config.example_json_file, self.domain, methods=method)
        expected_methods = [method]
        self.assertEqual(fuzzy.methods, expected_methods, "should allow string of one HTTP method")

        expected_methods = ["PUT", "PATCH"]
        fuzzy = Fuzzer(test_config.example_json_file, self.domain, methods=expected_methods)
        self.assertEqual(fuzzy.methods, expected_methods)

    def init_expectations(self):
        e = self.fuzzer.default_expectations
        self.assertTrue(e is not None and e != {}, "default expectations should have loaded from " + test_config.example_json_file)

    def init_mutator(self):
        self.assertIsNotNone(self.fuzzer.mutator, "should have loaded mutator object")

    def init_logger(self):
        expected_file_name = "_all_uris_all_methods"
        self.assertIn(expected_file_name, self.fuzzer.log_file_name)

        methods = ["GET", "POST"]
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, methods=methods)
        expected_file_name = "_all_uris_" + "_".join(methods)
        self.assertIn(expected_file_name, fuzzer.log_file_name)

        uri = "/json"
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, methods=methods, uri=uri)
        expected_file_name = "-json_" + "_".join(methods)
        self.assertIn(expected_file_name, fuzzer.log_file_name)

    def log_last_state_used(self):
        self.fuzzer.log_last_state_used(0)

    def evaluate_endpoint_expectation(self):
        with open(test_config.example_json_file, 'r') as model_file:
            model = json.loads(model_file.read())

        endpoint = next((l for l in model["endpoints"] if l["uri"] == "/sleepabit"), None)
        result = {
            "httpcode": 200,
            "time": 2
        }

        expectations = OrderedDict({})
        self.assertFalse(Fuzzer.evaluate_expectations(expectations, result),
                         "should be false if expectation obj is empty")

        if endpoint.get("expectations", False):
            expectations["local"] = endpoint["expectations"]
        else:
            expectations = self.default_expectations

        self.assertTrue(Fuzzer.evaluate_expectations(expectations, result), "result should be expected")

        result = {
            "httpcode": 500,
            "time": 2
        }
        self.assertFalse(Fuzzer.evaluate_expectations(expectations, result),
                         "result should not be expected because the httpcode does not match")

        result = {
            "httpcode": 200,
            "time": 0.1
        }
        self.assertFalse(Fuzzer.evaluate_expectations(expectations, result),
                         "result should not be expected because the time is incorrect")

        result = {
            "time": 2
        }
        self.assertFalse(Fuzzer.evaluate_expectations(expectations, result),
                         "result should not be expected because the httpcode is missing")

        expectations = OrderedDict([("default1", ["expectation = True"]),
                                    ("default2", ["expectation = False"])])
        self.assertFalse(Fuzzer.evaluate_expectations(expectations, result),
                         "should be false because default2 overrides default1")

    def get_expectations(self):
        endpoint = next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/sleepabit"), None)
        expectations = self.fuzzer.get_expectations(endpoint)
        self.assertEqual(len(expectations), 1, "should only find 1 key in expectation obj")
        self.assertIn("local", expectations.keys(), "should choose the local expectation definition")

        endpoint = next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/complex/qstring"), None)
        self.fuzzer.default_expectations = {"default": ["expectation = True"]}
        expectations = self.fuzzer.get_expectations(endpoint)
        self.assertEqual(len(expectations), 1, "should only find 1 key in expectation obj")
        self.assertIn("default", expectations.keys(), "should choose the default expectation definition")

        fuzzer = Fuzzer(test_config.example_expectations_file, self.domain)
        endpoint = next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/json"), None)
        expectations = fuzzer.get_expectations(endpoint)
        self.assertEqual(len(expectations), 1, "should only find 1 key in expectation obj")
        self.assertIn("global", expectations.keys(), "should choose the global expectation definition")

    def inject_constants(self):
        token = "{time}"
        constants = {token: "newvalue"}
        self.assertIn(token, json.dumps(self.fuzzer.model_obj))
        self.assertNotIn(token, json.dumps(Fuzzer.inject_constants(self.fuzzer.model_obj, constants)),
                         "'{0}' should have been replaced by '{1}'".format(token, constants[token]))
        self.assertIn(constants[token], json.dumps(Fuzzer.inject_constants(self.fuzzer.model_obj, constants)),
                      "'{0}' should have replaced '{1}'".format(constants[token], token))

        constants = {token: True}
        self.assertIn("true", json.dumps(Fuzzer.inject_constants(self.fuzzer.model_obj, constants)),
                      "'{0}' should have replaced '{1}'".format("true", token))

        constants = {token: 534897}
        self.assertIn(str(constants[token]), json.dumps(Fuzzer.inject_constants(self.fuzzer.model_obj, constants)),
                      "'{0}' should have replaced '{1}'".format(str(constants[token]), token))

    def mutate_payload_body(self):
        payload = self.fuzzer.mutate_payload(next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/json"), None))
        self.assertIsNotNone(payload.get("body"), "payload should have a body")

    def mutate_payload_query(self):
        payload = self.fuzzer.mutate_payload(next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/query/string"), None))
        self.assertIsNone(payload.get("body"), "payload with only query string should have an empty body")

    def mutate_payload_body_and_query(self):
        payload = self.fuzzer.mutate_payload(next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/poorly/designed/endpoint"), None))
        self.assertIsNotNone(payload.get("body"), "payload should have a body")
        self.assertIsNotNone(payload.get("query"), "payload should have query input")

    def mutate_payload_headers(self):
        payload = self.fuzzer.mutate_payload(next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/json"), None))
        self.assertIsNotNone(payload.get("headers"), "payload should have headers")
        self.assertIsNotNone(payload["headers"].get("Content-Type"), "should have Content-Type header")
        self.assertEqual(payload["headers"]["Content-Type"], "application/x-www-form-urlencoded; charset=UTF-8",
                         "Content-Type header should not be mutated because it does not have a placeholder")
        self.assertIsNotNone(payload["headers"]["Authorization"], "should have Authorization header")
        self.assertIn("Bearer ", payload["headers"]["Authorization"],
                      "Authorization header should have intact non-placeholder string")
        self.assertNotIn("{token}", payload["headers"]["Authorization"],
                         "Authorization header should have mutated token placeholder")

    def mutate_payload_header_state(self):
        payload = self.fuzzer.mutate_payload(next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/watch"), None))
        self.assertIsNotNone(payload.get("headers"), "payload should have headers")
        self.assertIsNotNone(payload["headers"].get("X-Hot-Fuzz-State"), "payload should have X-Hot-Fuzz-State header")
        self.assertEqual(payload["headers"]["X-Hot-Fuzz-State"], str(self.fuzzer.state),
                         "X-Hot-Fuzz-State header should have mutator state")
        self.fuzzer.state += 1
        payload = self.fuzzer.mutate_payload(next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/watch"), None))
        self.assertEqual(payload["headers"]["X-Hot-Fuzz-State"], str(self.fuzzer.state),
                         "X-Hot-Fuzz-State header should have mutator state after mutator state was incremented")

    def mutate_payload_uri(self):
        payload = self.fuzzer.mutate_payload(next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/{someId}"), None))
        self.assertIsNotNone(payload.get("uri"), "payload should have a uri")
        self.assertNotEqual("/{someId}", payload["uri"], "uri with placeholder should mutate")
        payload = self.fuzzer.mutate_payload(next((l for l in self.fuzzer.model_obj["endpoints"] if l["uri"] == "/json"), None))
        self.assertIsNotNone(payload.get("uri"), "payload should have a uri")
        self.assertEqual("/json", payload["uri"], "uri without placeholder should not mutate")

    @staticmethod
    def _get_n_expected_results(endpoints, n_iterations, uri=None, methods=None):
        nresults = 0
        for e in endpoints:
            if e["uri"] == uri or uri is None:
                nmethods = len(
                    list(set(e.get("methods", request.METHODS)).intersection(methods)) if methods else e.get("methods",
                                                                                                             request.METHODS))
                nresults += nmethods * n_iterations
        return nresults

    def iterate_endpoints_uri(self):
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=5, uri="/multiple")
        n_times = 1
        expected_n_results = self._get_n_expected_results(fuzzer.model_obj["endpoints"], n_times, fuzzer.uri)

        results = fuzzer.iterate_endpoints()
        self.assertEqual(len(results), expected_n_results,
                         "should only iterate {0} times over {1} endpoint with all methods".format(
                             str(expected_n_results), fuzzer.uri))

        for i in results:
            self.assertIn(fuzzer.uri, i["url"], "expected iteration {0} to contain {1}".format(json.dumps(i), fuzzer.uri))

    def iterate_endpoints_methods(self):
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=5, methods=["GET", "POST"])
        n_times = 1
        expected_n_results = self._get_n_expected_results(fuzzer.model_obj["endpoints"], n_times, methods=fuzzer.methods)

        results = fuzzer.iterate_endpoints()
        self.assertEqual(len(results), expected_n_results,
                         "should only iterate {0} times over all endpoints with methods {1}".format(str(expected_n_results), str(fuzzer.methods)))

        for i in results:
            self.assertIn(i["method"], fuzzer.methods,
                          "expected iteration {0} to contain one of methods {1}".format(json.dumps(i), str(fuzzer.methods)))

    def iterate_endpoints_uri_methods(self):
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=5, methods=["GET", "POST"], uri="/multiple")
        n_times = 1
        expected_n_results = self._get_n_expected_results(fuzzer.model_obj["endpoints"], n_times, fuzzer.uri, fuzzer.methods)

        results = fuzzer.iterate_endpoints()
        self.assertEqual(len(results), expected_n_results,
                         "should only iterate {0} times over all endpoints with methods {1}".format(
                             str(expected_n_results), str(fuzzer.methods)))

        for i in results:
            self.assertIn(i["method"], fuzzer.methods,
                          "expected iteration {0} to contain one of methods {1}".format(json.dumps(i), str(fuzzer.methods)))

        placeholder = "{otherId}"
        original_uri = "/" + placeholder
        expected_constant = "shoop"
        expected_uri = "/" + expected_constant
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, constants={placeholder: expected_constant}, uri=original_uri)
        results = fuzzer.iterate_endpoints()
        self.assertIn(expected_uri, json.dumps(results),
                      "should find a request with uri {0} that was changed to {1} after injecting {2} "
                      "as a constant".format(original_uri, expected_uri, expected_constant))

        placeholder = "{something_that_doesnt_exist}"
        original_uri = "/" + placeholder
        expected_uri = "/" + expected_constant
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, constants={placeholder: expected_constant}, uri=original_uri)
        results = fuzzer.iterate_endpoints()
        self.assertNotIn(expected_uri, json.dumps(results),
                         "should not find a request with uri {0} that was changed to {1} after injecting {2} "
                         "as a constant".format(original_uri, expected_uri, expected_constant))

    def iterate_endpoints_all(self):
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=5)
        n_times = 1
        expected_n_results = self._get_n_expected_results(fuzzer.model_obj["endpoints"], n_times)

        results = fuzzer.iterate_endpoints()
        self.assertEqual(len(results), expected_n_results,
                         "should only iterate {0} times over all endpoints and methods".format(str(expected_n_results)))

    def slack_error_throttle(self):
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=5, uri="/query/string")
        expected_errors = fuzzer.slack_errors + 1
        fuzzer.last_hour = time.localtime().tm_hour
        fuzzer.iterate_endpoints()
        self.assertEqual(fuzzer.slack_errors, expected_errors, "should increment by 1")

        fuzzer.slack_errors = test_config.slack_errors_per_hour
        expected_errors = fuzzer.slack_errors
        fuzzer.last_hour = time.localtime().tm_hour
        fuzzer.iterate_endpoints()
        self.assertEqual(fuzzer.slack_errors, expected_errors, "should match because errors per hour limit was reached")

        fuzzer.last_hour += 1
        fuzzer.iterate_endpoints()
        expected_errors = 1
        self.assertEqual(fuzzer.slack_errors, expected_errors, "should reset to 0 and increment to 1 because hour changed")

    def slack_status_update(self):
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=5, uri="/sleepabit")
        last_update_time = 0
        fuzzer.last_slack_status_update = last_update_time
        fuzzer.iterate_endpoints()
        self.assertNotEqual(fuzzer.last_slack_status_update, last_update_time,
                            "should change because the update interval was exceeded")

        last_update_time = fuzzer.last_slack_status_update
        fuzzer.iterate_endpoints()
        self.assertEqual(fuzzer.last_slack_status_update, last_update_time,
                         "should be the same because the update interval was not yet exceeded")

    def iterate_endpoints_log_summary_uri(self):
        method = "GET"
        uri = "/{someId}"
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=0.1, methods=[method], uri=uri)

        def check_result(message):
            result = fuzzer.iterate_endpoints()[0]
            # reason is not part of the assertion because it is not easy to assert
            expected_summary = "state={0} method={1} uri={2} code={3}" \
                .format(result["headers"]["X-Hot-Fuzz-State"], method, uri, result.get("httpcode"))
            with open(fuzzer.log_file_name, 'r') as file:
                log_content = file.read()
            self.assertIn(expected_summary, log_content, message)

        check_result("should contain summary for request")

        constants = {"{someId}": "some_constant"}
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=0.1, methods=[method],
                        uri=uri, constants=constants)

        check_result("summary for request should have a url which is logged without the injected constant")

    def _check_for_model_update(self):
        # pylint: disable=protected-access
        model = self.fuzzer.model_obj
        self.fuzzer._check_for_model_update()
        self.assertEqual(model, self.fuzzer.model_obj,
                         "should not change since elapsed time ({0}s) has not exceeded reload interval ({1}s)"
                         .format(self.fuzzer.time_since_last_model_check, self.fuzzer.model_reload_rate))

        self.fuzzer.time_since_last_model_check = self.fuzzer.model_reload_rate + 1
        self.fuzzer._check_for_model_update()
        self.assertEqual(self.fuzzer.time_since_last_model_check, 0.0,
                         "should reset to 0.0 after exceeding reload interval")
        self.assertEqual(model, self.fuzzer.model_obj,
                         "should not change since file was not changed")

        self.fuzzer.time_since_last_model_check = self.fuzzer.model_reload_rate + 1
        model = {"random": "new", "model": 0}
        self.fuzzer.model_obj = model  # this simulates a change in the schema
        self.fuzzer._check_for_model_update()
        self.assertNotEqual(self.fuzzer.model_obj, model,
                            "should change because the model in memory differs from what was loaded from the schema file")

    def fuzz_requests_by_incremental_state(self):
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=5, uri="/any/method", methods=["GET"])
        n_times = 5
        expected_fuzzer_state = n_times

        fuzzer.fuzz_requests_by_incremental_state(n_times)
        self.assertEqual(fuzzer.state, expected_fuzzer_state)

    def fuzz_requests_by_state_list(self):
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=5, uri="/any/method", methods=["GET"])
        states = [5, 2345, 3409, 222, 6]

        results = fuzzer.fuzz_requests_by_state_list(states)
        for result in results:
            self.assertIn(int(result["headers"]["X-Hot-Fuzz-State"]), states, "fuzzer should have iterated this state")

    def _run_parallel_fuzzers(self, n_iterations, fuzzer_1_state=0, fuzzer_2_state=0):

        fuzzer1 = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=5, state=fuzzer_1_state, constants={"{time}": "1m1s"}, uri="/json", methods=["POST"])
        fuzzer2 = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=5, state=fuzzer_2_state, constants={"{time}": "1m1s"}, uri="/json", methods=["POST"])
        results1 = fuzzer1.fuzz_requests_by_incremental_state(n_iterations)
        results2 = fuzzer2.fuzz_requests_by_incremental_state(n_iterations)

        # reason and time value will always be different and aren't worth diffing
        for n in range(n_iterations):
            if results1[n].get("reason"):
                del results1[n]["reason"]
            if results1[n].get("time"):
                del results1[n]["time"]

            if results2[n].get("reason"):
                del results2[n]["reason"]
            if results2[n].get("time"):
                del results2[n]["time"]

        return results1, results2

    def identical_output(self):
        n_times = 10
        results1, results2 = self._run_parallel_fuzzers(n_times)

        for i in range(n_times):
            str1 = json.dumps(results1[i])
            str2 = json.dumps(results2[i])
            self.assertEqual(str1, str2, "fuzzers with same initial state should produce identical output")

    def different_output(self):
        n_times = 10
        results1, results2 = self._run_parallel_fuzzers(n_times, fuzzer_1_state=1, fuzzer_2_state=2)

        for i in range(n_times):
            str1 = json.dumps(results1[i])
            str2 = json.dumps(results2[i])
            self.assertNotEqual(str1, str2,
                                "fuzzers with different initial state should produce different request bodies")

    def state_iteration(self):
        n_times = 1
        state = 0
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=0.1, state=state)
        results = fuzzer.fuzz_requests_by_incremental_state(n_times)

        for r in results:
            self.assertEqual(int(r["headers"]["X-Hot-Fuzz-State"]), state,
                             "state for each endpoint should be {0} for the first iteration".format(str(state)))

        state += 1
        results = fuzzer.fuzz_requests_by_incremental_state(n_times)
        for r in results:
            self.assertEqual(int(r["headers"]["X-Hot-Fuzz-State"]), state,
                             "state for each endpoint should be {0} for the second iteration".format(str(state)))

        results = fuzzer.fuzz_requests_by_incremental_state(n_times)
        for r in results:
            self.assertNotEqual(int(r["headers"]["X-Hot-Fuzz-State"]), state,
                                "state for each endpoint should be {0} for the third iteration".format(str(state + 1)))

    def get_states_from_file(self):
        expected_states = [234, 812, 1, 999909, 234, 22222893428923498, 9]
        states = Fuzzer.get_states_from_file(test_config.example_states_file)
        self.assertEqual(states, expected_states, "states should have loaded from " + test_config.example_states_file)

    def send_delayed_request_local(self):
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=0.1, uri="/delayabit", methods=["GET"])
        results = fuzzer.fuzz_requests_by_incremental_state(1)
        expected_requests_per_second = 2.5
        expected_delay = request.get_request_delay(expected_requests_per_second)
        self.assertEqual(results[0]["delay"], expected_delay,
                         "local request rate defined in endpoint should have delay of {0}".format(expected_delay))

    def send_delayed_request_global(self):
        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=0.1, uri="/delayabit", methods=["GET"])
        fuzzer.model_obj["requestsPerSecond"] = 10.1
        results = fuzzer.fuzz_requests_by_incremental_state(1)
        expected_requests_per_second = 2.5
        expected_delay = request.get_request_delay(expected_requests_per_second)
        self.assertEqual(results[0]["delay"], expected_delay,
                         "local request rate should override global definition with delay of {0}".format(expected_delay))

        fuzzer = Fuzzer(test_config.example_json_file, self.domain, global_timeout=True, timeout=0.1, uri="/poorly/designed/endpoint", methods=["GET"])
        results = fuzzer.fuzz_requests_by_incremental_state(1)
        expected_delay = request.get_request_delay(fuzzer.model_obj["requestsPerSecond"])
        self.assertEqual(results[0]["delay"], expected_delay,
                         "global definition should have delay of {0}".format(expected_delay))

    def get_curl_query_string(self):
        try:
            self.fuzzer.methods = ["GET"]
            self.fuzzer.get_curl_query_string()
            self.fail("should raise RuntimeError since uri is empty")
        except RuntimeError:
            pass
        try:
            self.fuzzer.uri = "/json"
            self.fuzzer.get_curl_query_string()
            self.fail("should raise RuntimeError since method could not be found with uri in model")
        except RuntimeError:
            pass
        self.fuzzer.methods = ["POST"]
        self.fuzzer.get_curl_query_string()

    def get_curl_query_string_constants(self):
        curl_file = test_config.curl_data_file_path
        self.fuzzer.methods = ["GET"]
        placeholder = "{someId}"
        self.fuzzer.uri = "/" + placeholder
        self.fuzzer.constants = {placeholder: "berb"}
        expectedUri = "/" + self.fuzzer.constants[placeholder]
        self.fuzzer.get_curl_query_string()

        with open(curl_file, 'r') as file:
            self.assertIn(expectedUri, file.read(), "should contain uri which was not fuzzed due to constant injection")

        self.fuzzer.constants = None
        expectedUri = self.fuzzer.uri
        self.fuzzer.get_curl_query_string()

        with open(curl_file, 'r') as file:
            self.assertNotIn(expectedUri, file.read(),
                             "should not contain uri because it was fuzzed without constant injection")

    def get_model_with_constants(self):
        self.fuzzer.schema_file_path = ""
        try:
            self.fuzzer.load_model()
            self.fail("should throw error because the file path for the model was invalid")
        except FileNotFoundError:
            pass

        self.fuzzer.schema_file_path = test_config.example_json_file
        self.fuzzer.load_model()  # testing the constant injection feature is done in inject_constants

    def mutate_headers(self):
        with open(test_config.example_json_file, 'r') as model_file:
            model = json.loads(model_file.read())

        header_to_drop = "Authorization"
        endpoint = Fuzzer.get_endpoints(model["endpoints"], "/json")[0]

        mutated_headers = self.fuzzer.mutate_headers(endpoint["headers"], test_config.default_placeholder_pattern)

        self.assertTrue(header_to_drop in mutated_headers, "Authorization header should exist")

        header_drop_state = 1
        self.fuzzer.change_state(header_drop_state)
        mutated_headers = self.fuzzer.mutate_headers(endpoint["headers"], test_config.default_placeholder_pattern)

        self.assertTrue(header_to_drop not in mutated_headers, "Authorization header should be dropped")


Suite.addTests([FuzzerTests("init_methods"),
                FuzzerTests("init_expectations"),
                FuzzerTests("init_mutator"),
                FuzzerTests("init_logger"),
                FuzzerTests("log_last_state_used"),
                FuzzerTests("evaluate_endpoint_expectation"),
                FuzzerTests("get_expectations"),
                FuzzerTests("inject_constants"),
                FuzzerTests("mutate_payload_body"),
                FuzzerTests("mutate_payload_query"),
                FuzzerTests("mutate_payload_body_and_query"),
                FuzzerTests("mutate_payload_headers"),
                FuzzerTests("mutate_payload_header_state"),
                FuzzerTests("mutate_payload_uri"),
                FuzzerTests("iterate_endpoints_uri"),
                FuzzerTests("iterate_endpoints_methods"),
                FuzzerTests("iterate_endpoints_uri_methods"),
                FuzzerTests("iterate_endpoints_all"),
                FuzzerTests("slack_error_throttle"),
                FuzzerTests("slack_status_update"),
                FuzzerTests("iterate_endpoints_log_summary_uri"),
                FuzzerTests("_check_for_model_update"),
                FuzzerTests("fuzz_requests_by_incremental_state"),
                FuzzerTests("fuzz_requests_by_state_list"),
                FuzzerTests("identical_output"),
                FuzzerTests("different_output"),
                FuzzerTests("state_iteration"),
                FuzzerTests("get_states_from_file"),
                FuzzerTests("send_delayed_request_local"),
                FuzzerTests("send_delayed_request_global"),
                FuzzerTests("get_curl_query_string"),
                FuzzerTests("get_curl_query_string_constants"),
                FuzzerTests("get_model_with_constants"),
                FuzzerTests("mutate_headers")])

threading.Thread(target=fuzz.test.mockserver.run_mock_server, daemon=True).start()

mutator_test_runner = xmlrunner.XMLTestRunner(output="results", verbosity=int(os.environ.get("VERBOSE", 2)))

res = not mutator_test_runner.run(Suite).wasSuccessful()
cov.stop()
cov.save()

try:
    cov.combine(data_paths=[test_config.cli_coverage_file,
                            test_config.fuzzer_coverage_file], strict=True)
except coverage.CoverageException:
    pass  # ignore the exception, but don't combine if not all files exist to prevent xml report failure
cov.xml_report(outfile=test_config.coverage_xml_file)

sys.exit(res)
