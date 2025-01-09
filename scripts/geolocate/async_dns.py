#!/usr/bin/python
#
# Created by Peter Krumins (peter@catonmat.net, @pkrumins on twitter)
# www.catonmat.net -- good coders code, great coders reuse
#
# Asynchronous DNS Resolution in Python.
#
# Read more about how this code works in my post:
# www.catonmat.net/blog/asynchronous-dns-resolution
#

import adns, time
from datetime import datetime
import socket


class AsyncResolver(object):

    def __init__(self, IPs, intensity=100):
        """
        hosts: a list of hosts to resolve
        intensity: how many hosts to resolve at once
        """
        hosts = []
        self.intensity = intensity
        self.adns = adns.init()

        # process IP addresses into rDNS hosts
        for IP in IPs:
            bytes = IP.split(".")
            bytes.reverse()
            revIP = ".".join(bytes)
            d = dict()
            d["ip"] = IP
            d["host"] = revIP + ".in-addr.arpa"
            hosts.append(d)
        self.hosts = hosts

    def resolve(self):
        """ Resolves hosts and returns a dictionary of { 'host': 'ip' }. """
        resolved_hosts = []
        active_queries = {}
        ip_queue = self.hosts[:]

        def collect_results():
            try:
                for query in self.adns.completed():
                    answer = query.check()
                    ip = active_queries[query]
                    del active_queries[query]
                    if answer[0] == 0:
                        host = answer[3][0].decode("utf-8")
                        d = dict()
                        d["ip"] = ip["ip"]
                        d["host"] = host
                        d["timestamp"] = str(datetime.utcnow())
                        resolved_hosts.append(d)
                    elif answer[0] == 101:  # CNAME
                        try:
                            query = self.adns.submit(answer[1], adns.rr.PTR)
                            active_queries[query] = ip
                        # CNAME response has no data, so IP could not be resolved
                        except:
                            d = dict()
                            d["ip"] = ip["ip"]
                            d["host"] = None
                            d["timestamp"] = str(datetime.utcnow())
                            resolved_hosts.append(d)
                    else:
                        d = dict()
                        d["ip"] = ip["ip"]
                        d["host"] = None
                        d["timestamp"] = str(datetime.utcnow())
                        resolved_hosts.append(d)
            except:
                pass

        def finished_resolving():
            return len(resolved_hosts) == len(self.hosts)

        while not finished_resolving():
            while ip_queue and len(active_queries) < self.intensity:
                ip = ip_queue.pop()
                query = self.adns.submit(ip["host"], adns.rr.PTR)
                active_queries[query] = ip
            time.sleep(0.01)
            collect_results()

        return resolved_hosts


if __name__ == "__main__":
    host_format = "www.host%d.com"
    number_of_hosts = 20000

    hosts = [host_format % i for i in range(number_of_hosts)]
    hosts = ["4.31.77.189"]

    ar = AsyncResolver(hosts, intensity=500)
    resolved_hosts = ar.resolve()
    print(resolved_hosts)
