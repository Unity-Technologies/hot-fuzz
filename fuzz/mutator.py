import os
import random
import copy
import re
from pathlib import Path
import configparser
from subprocess import Popen, PIPE, STDOUT

_pwd = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = str(Path(_pwd).parents[0])

CONFIG = configparser.ConfigParser()
CONFIG.read(os.path.join(_pwd, "config", "config.ini"))

_radamsa_bin_env = os.environ.get("RADAMSA_BIN")
_radamsa_bin_config = os.path.join(PROJECT_DIR, CONFIG.get("DEFAULT", "radamsa_bin"))

RADAMSA_BIN = _radamsa_bin_env if _radamsa_bin_env is not None else _radamsa_bin_config


class Mutator:

    def __init__(self, fuzzdb_array, state=0, byte_encoding="unicode_escape"):
        self.own_rand = random.Random()
        self.change_state(state)
        self.fuzzdb_array = fuzzdb_array
        self.byte_encoding = byte_encoding

    def change_state(self, new_state):
        self.state = new_state
        self.own_rand.seed(self.state)

    def chance(self, probability):
        """Returns True x% of the time"""
        self.change_state(self.state)
        return self.own_rand.random() < probability

    def roll_dice(self, minimum, maximum):
        self.change_state(self.state)
        return self.own_rand.randint(minimum, maximum)

    def safe_decode(self, input_bytes):
        """
        Attempt to decode the input using byte_encoding. Return the value as a string if not possible.
        """
        try:
            output = input_bytes.decode(self.byte_encoding)
        except (UnicodeDecodeError, OverflowError):
            output = str(input_bytes)  # Leave it as it is

        return output

    def mutate_radamsa(self, value):
        """
        Mutate the value and encode the mutator output using byte_encoding.
        :param value: seed value for the mutator
        :param byte_encoding: name of the byte encoding method defined in the python encodings library
        :return:
        """
        value = str(value)
        if self.state == -1:
            radamsa_process = Popen([RADAMSA_BIN], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        else:
            radamsa_process = Popen([RADAMSA_BIN, "-s", str(self.state)], stdout=PIPE, stdin=PIPE, stderr=STDOUT)

        radamsa_output = radamsa_process.communicate(input=value.encode(self.byte_encoding))[0]

        return self.safe_decode(radamsa_output)

    def juggle_type(self, value):  # pylint: disable=too-many-return-statements, inconsistent-return-statements

        roll = self.roll_dice(1, 6)

        if roll == 1:  # String
            return str(value)

        if roll == 2:  # Boolean
            return self.chance(0.5)

        if roll == 3:  # Number
            try:
                return int(value)
            except ValueError:
                if self.chance(0.5):
                    return 1
                return 0

        if roll == 4:  # Array
            return [value]

        if roll == 5:  # Object
            return {str(value): value}

        if roll == 6:  # NoneType / null
            return None

    def pick_from_fuzzdb(self):
        roll = self.roll_dice(0, len(self.fuzzdb_array) - 1)

        return self.fuzzdb_array[roll]

    def mutate_val(self, value):
        roll = self.roll_dice(1, 3)

        if roll == 1:
            mutated_val = self.mutate_radamsa(value)
        elif roll == 2:
            mutated_val = self.juggle_type(value)
        elif roll == 3:
            mutated_val = self.pick_from_fuzzdb()

        return mutated_val

    @staticmethod
    def list_obj_iterable(obj):
        if isinstance(obj, dict):
            return obj
        return range(len(obj))

    def mutate_regex(self, string, pattern):
        """
        Discards tokens matching the pattern and replaces them with mutations seeded by the preceding string value
        This works as long as the tokens in string are not sequential
        """
        tokens = re.split(pattern, string)
        mutated = ""
        for index, token in enumerate(tokens):
            mutated += token
            if index < len(tokens) - 1:
                mutated += str(self.mutate_val(token))
        return mutated

    def walk_and_mutate(self, obj, strict, pattern):
        for key in self.list_obj_iterable(obj):
            if isinstance(obj[key], (dict, list)):  # Not a single val, dig deeper
                self.walk_and_mutate(obj[key], strict, pattern)
            elif isinstance(obj[key], str) and pattern and re.search(pattern, obj[key]):
                obj[key] = self.mutate_regex(obj[key], pattern)
            elif not strict:
                obj[key] = self.mutate_val(obj[key])

    def mutate(self, obj, strict=False, pattern=None):
        """
        Main entry point
        :obj: Data structure to mutate, can be any type
        :strict: If true, values that are of type string will only be mutated where a substring matches the pattern
        :pattern: A string regex
        """

        if not obj:
            return obj
        elif isinstance(obj, str):
            if pattern and re.search(pattern, obj):
                obj = self.mutate_regex(obj, pattern)
            elif not strict:
                obj = self.mutate_val(obj)

            return obj
        else:
            obj_to_mutate = copy.deepcopy(obj)
            self.walk_and_mutate(obj_to_mutate, strict, pattern)
            return obj_to_mutate
