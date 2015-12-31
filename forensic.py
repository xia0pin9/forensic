# import volatility.utils as utils
import os
import sys
import importlib
import subprocess

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
        # self.check_heuris()
        # self.show_results()
        # self.edit_heuris()
        self.start_shell()

    def ssplit(self, config):
        for key in config:
            if "\"" in config[key]:
                config[key] = config[key].split("\"", "")
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
            print("Analyzing {0} related heuristic rules:".format(category))
            self._results[category] = []
            for rulename in heurisrules[category]:
                modname = "handles." + category + "." + rulename
                try:
                    module = import_module(modname) 
                    funcname = getattr(module, rulename)
                except ImportError:
                    print("No module named {0}".format(modname))
                except AttributeError:
                    print("Module {0} has no attribute {1}".format(module, rulename))
                else:
                    message = self.heuris['heuris'][category+'/'+rulename].replace("\"", "")
                    results = funcname(pslist, heurisrules[category][rulename], self._config, message)
                    if results:
                        for result in results:
                            print(rulename, result)
                            # self._results[category].append(result)

    def show_results(self):
        print("Heuristic Analysis Result:")
        for category in self._results:
            for result in self._results[category]:
                print(result[2])

    def start_shell(self):
        def sh(self):
            """Opens current heuris.conf in default text editor"""
            cpath = self._config.HEURISPATH
            if sys.platform.startswith('darwin'):
                subprocess.call(('open', cpath))
                # subprocess.call(['nano', cpath])
            elif os.name == 'nt':
                os.startfile(cpath)
            elif os.name == 'posix':
                subprocess.call(('xdg-open', cpath))

        shell_funcs = {'sh':sh}     # TODO: list available commands

        def hh(cmd = None):
            import pydoc
            from inspect import getargspec, formatargspec
            if not cmd:
                print "\nAvailable commands:"
                for f in sorted(shell_funcs):
                    doc = pydoc.getdoc(shell_funcs[f])
                    synop, _full = pydoc.splitdoc(doc)
                    print "\t{0:20} : {1}".format(f + formatargspec(*getargspec(shell_funcs[f])), synop)
                print "\nFor help on a specific command, type 'hh(<command>)'"
            elif type(cmd) == str:
                try:
                    doc = pydoc.getdoc(shell_funcs[cmd])
                except KeyError:
                    print "No such command: {0}".format(cmd)
                    return
                print doc
            else:
                doc = pydoc.getdoc(cmd)
                print doc

        banner = "Welcome to volshell! \n\t Current memory image is: {0}\n".format(self._config.LOCATION)
        print (banner)

        # Attempt IPython (both old and new) with tab completion
        try:
            import IPython
            try:
                IPython.embed()
            except AttributeError:
                shell = IPython.Shell.IPShellEmbed([], banner = banner)
                shell()
        except (AttributeError, ImportError):
            import code, inspect
            frame = inspect.currentframe()
            try:
                import rlcompleter, readline
                readline.parse_and_bind("tab: complete")
            except ImportError:
                pass
            namespace = frame.f_globals.copy()
            namespace.update(frame.f_locals)
            code.interact(banner = banner, local = namespace)

def main():
    forensic = Forensic(config=conf.ConfObject())

if __name__ == "__main__":
    main()
