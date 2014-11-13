def session_index(pslist, heurisrule, config, message):
    results = []
    if config.PROFILE.startswith("vista"):
        for targetprocess in heurisrule:
            expectedsession = heurisrule[targetprocess]
            for process in pslist:
                if process['name'] == targetprocess and process['sessionid'] != expectedsession:
                    name = targetprocess + "(pid=" + str(process['pid']) + ")"
                    msg = message.format(name, process('sessionid'))
    return results
