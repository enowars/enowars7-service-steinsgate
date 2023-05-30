import re
from urllib.parse import urlparse

mapType = {
    "upstream": urlparse,
    "write_timeout": int,
    "read_timeout": int,
    "read_buffer_size": int,
    "write_buffer_size": int,
    "connect_timeout": int,
    "deny": dict,
    "path": [re.compile, re.I],
    "if_match_code": str,
    "if_match_body": str
}

proxy_config = {
    "denyRules": []
}

def parseConfig(configfile):
    try:
        lastKey = ""
        ruleCount = 0
        fp = open(configfile, "r")
        cfgLines = fp.readlines()
        fp.close()
        for k in cfgLines:
            ln = k.strip()
            key, value = ln.split("=")
            valueParsed = ""
            if key in mapType:
                if mapType[key] != dict:
                    if type(mapType[key]) == list:
                        valueParsed = mapType[key][0](value, mapType[key][1])
                    else:
                        valueParsed = mapType[key](value)
            else:
                valueParsed = value
            if key == "deny" and value == "begin":
                lastKey = key + str(ruleCount)
                proxy_config["denyRules"].append({})
                continue
            if key == "deny" and value == "end":
                lastKey = ""
                ruleCount += 1
                continue
            if lastKey == "":
                proxy_config[key] = valueParsed
            else:
                proxy_config["denyRules"][-1][key] = valueParsed
    except Exception as e:
        print("Config file in wrong format:", e)


