# _*_ coding: utf-8 -*-

def occurrence(pslist, heurisrule, config, message):
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
        firstpid = -1
        for process in pslist:
            if process['name'].lower() == pname:
                real_count += 1
                firstpid = str(process['pid'])
        if real_count > expected_count:
            name = pname + "(pid=" + firstpid + ")"
            msg = message.format(name, expected_count, real_count)
            results.append(msg)
    return results
