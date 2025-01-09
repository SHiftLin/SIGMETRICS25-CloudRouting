import time
import json
import pyasn
import pytricia


class IpAsnOrg:
    def __init__(self, dirt="../../data", enable_org=False):
        start = time.time()
        self.dirt = dirt
        self.enable_org = enable_org
        self.__initPyASN()
        self.__initIXP()
        self.__initProviderFeeds()
        if self.enable_org:
            self.__initASNOrg()
        end = time.time()
        print("IpAsnOrg init finished in %.2fs" % (end-start))

    def __initPyASN(self):
        self.asndb = pyasn.pyasn(f"{self.dirt}/ipasn_20240901.dat")

    def __initIXP(self):
        self.ixp_ip_asn = {}
        with open(f"{self.dirt}/caida/ix-asns_202310.jsonl") as fin:
            for line in fin:
                data = json.loads(line)
                for ip in data["ipv4"]+data["ipv6"]:
                    self.ixp_ip_asn[ip] = data["asn"]

    def __initProviderFeeds(self):
        self.pyt_ispfeeds = pytricia.PyTricia(128)

        with open(f"{self.dirt}/ip_ranges/aws-ip-ranges.json", "r") as fin:
            data = json.loads(fin.read())
            for item in data["prefixes"]:
                self.pyt_ispfeeds[item["ip_prefix"]] = 16509  # AWS

        with open(f"{self.dirt}/ip_ranges/azure-ip-ranges.json", "r") as fin:
            data = json.loads(fin.read())
            for item in data["values"]:
                for prefix in item["properties"]["addressPrefixes"]:
                    self.pyt_ispfeeds[prefix] = 8075  # Azure

        with open(f"{self.dirt}/ip_ranges/gcp-ip-ranges.json", "r") as fin:
            data = json.loads(fin.read())
            for item in data["prefixes"]:
                if "ipv4Prefix" in item:
                    self.pyt_ispfeeds[item["ipv4Prefix"]] = 16509  # GCP
                if "ipv6Prefix" in item:
                    self.pyt_ispfeeds[item["ipv6Prefix"]] = 16509  # GCP

        # We do not include IP ranges from
        # https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
        # https://www.gstatic.com/ipranges/goog.json
        # Because these IP ranges can be resolved by pyasn

    def __initASNOrg(self):
        self.asn_org = {}
        with open(f"{self.dirt}/as_rank/asns.jsonl") as fin:
            for line in fin:
                data = json.loads(line)
                asn = int(data["asn"])
                try:
                    org = data["organization"]["orgName"]
                except:
                    continue
                if len(org) > 0:
                    self.asn_org[asn] = org

    def byPyASN(self, ip):
        asn = self.asndb.lookup(ip)[0]  # (asn, prefix) or (None, None)
        if asn is not None:
            return {"asn": asn, "method": "pyasn"}
        return None

    def byIXP(self, ip):
        if ip in self.ixp_ip_asn:
            return {"asn": self.ixp_ip_asn[ip], "method": "ixp"}
        return None

    def byProviderFeeds(self, ip):
        if ip in self.pyt_ispfeeds:
            return {"asn": self.pyt_ispfeeds[ip], "method": "ispfeed"}
        return None

    def lookup(self, ip):
        res = None
        while True:
            res = self.byPyASN(ip)
            if res is not None:
                break
            res = self.byIXP(ip)
            if res is not None:
                break
            res = self.byProviderFeeds(ip)
            if res is not None:
                break
            break
        if self.enable_org and res is not None:
            res["org"] = None
            if res["asn"] in self.asn_org:
                res["org"] = self.asn_org[res["asn"]]
        return res


if __name__ == "__main__":
    ipasn = IpAsnOrg(dirt="../data", enable_org=True)
    print(ipasn.lookup("206.108.115.47"))  # AMS-IX Chicago AS 8075 - Microsoft
    print(ipasn.lookup("20.35.240.0"))  # AS 8070 - Microsoft
    print(ipasn.lookup("8.35.192.0"))  # AS 396982 - Google
    print(ipasn.lookup("34.0.0.0"))  # AS 19527 - Google
    print(ipasn.lookup("91.210.16.168"))  # NIX.CZ AS 15169 - Google
