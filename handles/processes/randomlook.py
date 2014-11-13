import re

def randomlook(pslist, heurisrule, config, message):
    results = []
    pattern = re.compile(heurisrule['pattern'])
    for process in pslist:
        if pattern.search(process['name']):
            name = process['name'] + "(pid=" + str(process['pid']) + ")"
            msg = message.format(name)
            results.append(msg)
    return results
