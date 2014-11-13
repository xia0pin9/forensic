# _*_ coding: utf-8 -*-

def similarity(pslist, heurisrule, config, message):
    """
    Check the process similarity against whitelist in heurisrtic rule
    :param pslist:
    :param heurisrule:
    :param message:
    :return: heuristic rule check result for process similarity
    """
    results = []
    for targetprocess in heurisrule['whitelist']:
        for process in pslist:
            pname = process['name']
            if pname in heurisrule['whitelist']:
                continue
            distance = levenshtein(pname, targetprocess)
            if 1 <= distance <= 2:
                name = pname + "(pid=" +  str(process['pid']) + ")"
                msg = message.format(name, targetprocess)
                results.append(msg)
    return results

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
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
