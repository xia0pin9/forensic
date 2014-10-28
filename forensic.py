# import volatility.utils as utils
import os
import sys
import importlib

import volatility.conf as conf
import volatility.debug as debug

from conf_d import Configuration
from volinfo import VolInfo
from importlib import import_module


class Forensic(VolInfo):
    """Apply Heuristic Rules on Volatility extracted results"""

    def __init__(self, config=conf.ConfObject(), deb=debug, *args):
        self._config = config
        self._config.add_option('HEURISPATH', short_option='r', 
                                default="rules/heuristics.conf",
                                help='Heuristic rules path',
                                action='store', type='str')
        VolInfo.__init__(self, self._config, deb)
        self.heuris = Configuration(name="heuris", 
                                    path=self._config.HEURISPATH,
                                    section_parser=self.ssplit).raw()
        self._results = {}
        self.check_heuris()
        # self.show_results()

    def ssplit(self, config):
        for key in config:
            if ", " in config[key]:
                config[key] = config[key].split(", ")
            if not isinstance(config[key], list):
                if config[key].isdigit():
                    config[key] = int(config[key])
        return config

    def check_heuris(self):
        heurisrules = {} 

        # Prepare resources information
        if self._config.ENABLEDB:
            pslist = [x for x in self._db[self._dbname]['processes'].find()]
        else:
            pslist = self._processes

        # Prepare heuris rule lists that need to be checked
        rules_to_check = self.heuris['heuris']['check']
        if rules_to_check == '*':
            for rulename in self.heuris['sections']:
                category, name = rulename.split('/')
                if category not in heurisrules:
                    heurisrules[category] = {}
                heurisrules[category][name] = self.heuris['sections'][rulename]
        elif rules_to_check.endswith('*'):
            target_category = rules_to_check.split('/')[0]
            heurisrules[target_category] = {}
            for rulename in self.heuris['sections']:
                if rulename.startswith(target_category):
                    category, name = rulename.split('/')
                    heurisrules[category][name] = self.heuris['sections'][rulename]
        else:
            for rulename in self.heuris['sections']:
                if rulename == rules_to_check:
                    category, name = rulename.split('/')
                    heurisrules[category] = {}
                    heurisrules[category][name] = self.heuris['sections'][rulename]

        # Go through the heuristic rules
        for category in heurisrules:
            print("Analysing {0} related heuristic rule".format(category))
            self._results[category] = []
            for rulename in heurisrules[category]:
                modname = "handles." + category + "." + rulename
                module = import_module(modname) 
                funcname = getattr(module, rulename)
                message = self.heuris['heuris'][category+'/'+rulename].replace("\"", "")
                results = funcname(pslist, heurisrules[category][rulename], message)
                if results:
                    for result in results:
                        print(result[2])
                        # self._results[category].append(result)

    def show_results(self):
        print("Heuristic Analysis Result:")
        for category in self._results:
            for result in self._results[category]:
                print(result[2])


def main():
    forensic = Forensic(config=conf.ConfObject())

if __name__ == "__main__":
    main()
