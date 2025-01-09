
import io
import csv
import ipaddress


def stripComment(line):
    p = line.find("#")
    if p != -1:
        return line[:p]
    return line.strip()


def emptyToNone(s):
    if len(s) == 0:
        return None
    return s


def parseGeofeed(line):
    line = stripComment(line)
    if len(line) == 0:
        return None
    items = list(csv.reader([line]))[0]  # avoid "" in the csv
    if len(items) != 5:
        return None
    try:
        if not ipaddress.ip_network(items[0]).is_global:
            return None
    except:
        return None
    return items
    # items = [emptyToNone(item) for item in items]
    # return {
    #     "prefix": items[0],
    #     "country": items[1],
    #     "region": items[2],
    #     "city": items[3],
    #     "code": items[4]
    # }
