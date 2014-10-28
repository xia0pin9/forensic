# _*_ coding: utf-8 -*-

def occurrence(pslist, heurisrule, message):
    """
    Check
    :param pslist:
    :param heurisrule:
    :param message:
    :return:
    """
    results = []
    for pname in heurisrule:
        real_count = 0
        expected_count = heurisrule[pname]
        for process in pslist:
            if process['name'] == pname:
                real_count += 1
        if real_count > expected_count:
            name = pname + "(pid=" + pid + ")"
            msg = message.format(name, expected_count, real_count)
            results.append((pname, msg))
    return results
