# _*_ coding: utf-8 -*-

def relation(pslist, heurisrule, message):
    """
    Check process relationship against specified heuristic rule
    :param pslist:
    :param heurisrule:
    :param message:
    :return:
    """
    results = []
    for pname in heurisrule:
        pid = -1
        parentid = -1
        for process in pslist:
            if str(process['name']) == pname:
                pid = str(process['pid'])
                parentid = int(process['ppid'])

                for process in pslist:
                    if process['pid'] == parentid:
                        if str(process['name']) != heurisrule[pname]:
                            name = pname + "(pid=" + pid + ")" 
                            msg = message.format(name, heurisrule[pname], process['name'])
                            results.append((pname, pid, msg))
    return results
