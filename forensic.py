# import volatility.utils as utils
import volatility.conf as conf

from conf_d import Configuration
from volinfo import VolInfo


class Forensic(VolInfo):
    """Apply Heuristic Rules on Volatility extracted results"""

    def __init__(self, config, *args):
        self._config = config
        self._config.add_option('HEURISPATH', short_option='p', 
                                default="./resources/heuristics.conf",
                                help='Heuristic rules path',
                                action='store', type='str')
        VolInfo.__init__(self, self._config)
        self.heuris = Configuration(name="heuris", 
                                    path=self._config.HEURISPATH,
                                    section_parser=self.ssplit).raw()
        self._results = []
        self.check_heuris()
        self.show_results()

    def ssplit(self, config):
        for key in config:
            if ", " in config[key]:
                config[key] = config[key].split(", ")
            if not isinstance(config[key], list):
                if config[key].isdigit():
                    config[key] = int(config[key])
        return config

    def levenshtein(self, s1, s2):
        if len(s1) < len(s2):
            return self.levenshtein(s2, s1)
        # len(s1) >= len(s2)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # j+1 instead of j since previous_row and
                # current_row are one character longer
                insertions = previous_row[j + 1] + 1                 
                deletions = current_row[j] + 1       # than s2
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def check_occurrence(self, pslist, heurisrule, message):
        """
        Check 
        :param pslist:
        :param heurisrule:
        :param message:
        :return:
        """
        results = []
        for rule in heurisrule:
            real_count = 0
            expected_count = heurisrule[rule]
            for process in pslist:
                if process['name'] == rule:
                    real_count += 1
                if real_count > expected_count:
                    msg = message.format(rule, expected_count)
                    results.append((rule, msg))
        return results

    def check_relation(self, pslist, heurisrule, message):
        """
        Check process relationship against specified heuristic rule
        :param pslist:
        :param heurisrule:
        :param message:
        :return:
        """
        results = []
        for rule in heurisrule:
            pid = -1
            parentid = -1
            for process in pslist:
                if str(process['name']) == rule:
                    pid = str(process['pid'])
                    parentid = int(process['ppid'])
        
                    for process in pslist:
                        if process['pid'] == parentid:
                            if str(process['name']) != heurisrule[rule]:
                                msg = message.format(rule, process['name'])
                                results.append((rule, pid, msg))
        return results

    def check_similarity(self, pslist, heurisrule, message):
        """
        Check the process similarity against whitelist in heurisrtic rule
        :param pslist:
        :param heurisrule:
        :param message:
        :return: heuristic rule check result for process similarity
        """
        results = []
        for rule in heurisrule['whitelist']:
            for process in pslist:
                pname = process['name']
                if pname in heurisrule['whitelist']:
                    continue
                distance = self.levenshtein(pname, rule)
                if 1 <= distance <= 2:
                    msg = message.format(pname, rule)
                    results.append((pname, str(process['pid']), msg))
        return results

    def check_owner(self, pslist, heurisrule, message):
        pass

    def check_heuris(self):
        pslist = [x for x in self._db[self._dbname]['processes'].find()]
        heurisrules = {} 
        heurisresults = [] 
        if self.heuris['heuris']['check'] == 'all':
            for rulename in self.heuris['sections']:
                heurisrules[rulename] = self.heuris['sections'][rulename]
        else:
            for rulename in self.heuris['sections']:
                if rulename == self.heuris['heuris']['check']:
                    heurisrules[rulename] = self.heuris['sections'][rulename]

        for rulename in heurisrules:
            print("Analysing processes related heuristic rule: %s" % rulename)
            funcname = getattr(self, 'check_' + rulename)
            message = self.heuris['heuris'][rulename].replace("\"", "")
            results = funcname(pslist, heurisrules[rulename], message)
            if results:
                for result in results:
                    heurisresults.append(result)
        for process in heurisresults:
            self._results.append(process)

    def show_results(self):
        print("Heuristic Analysis Result:")
        for process in self._results:
            print(process)


def main():
    forensic = Forensic(config=conf.ConfObject())

if __name__ == "__main__":
    main()
