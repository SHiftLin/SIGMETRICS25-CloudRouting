import os
import re
import csv
import time
import json
import ipaddress
import requests
import pickle

import tldextract
import pytricia
import googlemaps
import ipinfo

from .geofeed_parser import parseGeofeed
from .async_dns import AsyncResolver
from .redis_cache import RedisCache


class GeoLocate:
    def __init__(self, dirt="../../data", google_api_key=None, ipinfo_token=None, dbv=0):
        start = time.time()
        self.cnt = 0
        self.dirt = dirt
        self.dbv = dbv
        self.gmaps = googlemaps.Client(key=google_api_key)
        self.ipinfo_handler = ipinfo.getHandler(ipinfo_token)
        self.__initCache()
        self.__initGeoCode()
        self.__initLocal()
        self.__initGeoFeeds()
        self.__initProviderFeeds()
        self.__initPeeringDB()
        self.__initRDNS()
        self.__check_data()
        end = time.time()
        print("GeoLocate init finished in %.2fs" % (end - start))
        print(
            f"Using redis db version {dbv}. (0 for 20240304, 2 for 20240815)")

    def __initCache(self):
        self.loc_cache = RedisCache("loc", db=self.dbv)
        self.gmap_geo_cache = RedisCache("gmap_geo", db=self.dbv)
        self.gmap_rgeo_cache = RedisCache("gmap_rgeo", db=self.dbv)
        self.rDNS_cache = RedisCache("rdns", db=self.dbv)
        self.ripe_cache = RedisCache("ripe", db=self.dbv)
        self.ipinfo_cache = RedisCache("ipinfo", db=self.dbv)

    def dumpCache(self):
        print("dumpCache is deprecated")

    def __readFromPkl(self, pkl_name, readFunc):  # Not used yet
        pkl_name = f"{self.dirt}/geolocate_cache/" + pkl_name
        if os.path.isfile(pkl_name):
            with open(pkl_name, "rb") as fin:
                results = pickle.load(fin)
                return results
        results = readFunc()
        with open(pkl_name, "wb") as fout:
            pickle.dump(results, fout)
        return results

    def __check_data(self):
        if len(self.pyt_geofeeds) != 208309:
            print("Warning: pyt_geofeeds length is not equal to preset."
                  "Check whether the cache is corrupted")
            return False
        return True

    def __initLocal(self):
        self.local_ip = {}
        with open(f"{self.dirt}/geolocate_local.csv", "r", encoding="utf-8") as fin:
            reader = csv.reader(fin)
            for ip, asn, lat, lng, place, country, tag in reader:
                self.local_ip[ip] = (lat, lng, place, country)

    def __initGeoCode(self):
        self.iata_loc = {}
        with open(f"{self.dirt}/iata-icao.csv", "r", encoding="utf-8") as fin:
            reader = csv.DictReader(fin)
            for row in reader:
                self.iata_loc[row["iata"].lower()] = row
        # print("iata_loc:", len(self.iata_loc))

        self.clli_loc = {}
        with open(f"{self.dirt}/clli-lat-lon.230606.txt", "r", encoding="utf-8") as fin:
            for line in fin:
                row = line.split('\t')
                row[0] = row[0].replace(' ', '')[:6]
                self.clli_loc[row[0].lower()] = (float(row[1]), float(row[2]))
        # print("clli_loc:", len(self.clli_loc))

    def __initGeoFeeds(self):
        # PyTricia cannot be pickled
        self.pyt_geofeeds = pytricia.PyTricia(128)
        cachename = f"{self.dirt}/geolocate_cache/cache_geofeed.csv"
        if os.path.isfile(cachename):
            with open(cachename, "r", encoding="utf-8") as fin:
                reader = csv.reader(fin)
                for row in reader:
                    self.pyt_geofeeds[row[0]] = row
        else:
            fout = open(cachename, "w", encoding="utf-8")
            writer = csv.writer(fout, lineterminator="\n")
            for filename in ["ripedb_geofeed.csv", "geofeed-finder.csv", "opengeofeed.csv"]:
                with open(f"{self.dirt}/geofeeds/{filename}", "r", encoding="utf-8") as fin:
                    for line in fin:
                        row = parseGeofeed(line)
                        if row is not None:
                            self.pyt_geofeeds[row[0]] = row
                            writer.writerow(row)
            fout.close()
        # print("pyt_geofeed:", len(self.pyt_geofeeds))

    def __initProviderFeeds(self):
        self.pyt_ispfeeds = pytricia.PyTricia(128)
        with open(f"{self.dirt}/ip_ranges/aws-ip-ranges.json", "r", encoding="utf-8") as fin:
            data = json.loads(fin.read())
            for item in data["prefixes"]:
                self.pyt_ispfeeds[item["ip_prefix"]
                                  ] = item["network_border_group"]
        # print("pyt_ispfeeds:", len(self.pyt_ispfeeds))

    def __initPeeringDB(self):
        self.ixs = {}
        self.ixlans = {}
        self.pyt_pdb = pytricia.PyTricia(128)
        with open(f"{self.dirt}/peeringDB/peeringDB_ix.json", "r", encoding="utf-8") as fin:
            data = json.loads(fin.read())["data"]
            for ix in data:
                self.ixs[ix["id"]] = ix
        # print("ixs:", len(self.ixs))

        with open(f"{self.dirt}/peeringDB/peeringDB_ixlan.json", "r", encoding="utf-8") as fin:
            data = json.loads(fin.read())["data"]
            for ixlan in data:
                self.ixlans[ixlan["id"]] = ixlan
        # print("ixlans:", len(self.ixlans))

        with open(f"{self.dirt}/peeringDB/peeringDB_ixpfx.json", "r", encoding="utf-8") as fin:
            data = json.loads(fin.read())["data"]
            for pfx in data:
                if pfx["ixlan_id"] in self.ixlans:
                    self.pyt_pdb[pfx["prefix"]
                                 ] = self.ixlans[pfx["ixlan_id"]]["ix_id"]

        with open(f"{self.dirt}/peeringDB/peeringDB_netixlan.json", "r", encoding="utf-8") as fin:
            data = json.loads(fin.read())["data"]
            for ixlan in data:
                if ixlan["ipaddr4"] is not None:
                    self.pyt_pdb[ixlan["ipaddr4"]] = ixlan["ix_id"]
        # print("pyt_pdb:", len(self.pyt_pdb))

    def __initRDNS(self):
        self.hoiho = {}
        with open(f"{self.dirt}/202103-midar-iff.geo-re.json", "r", encoding="utf-8") as fin:
            for line in fin:
                data = json.loads(line)
                self.hoiho[data["domain"]] = data
        # print("hoiho:", len(self.hoiho))

    def gmapGeocode(self, addr):
        addr = addr.lower()
        res = self.gmap_geo_cache.get(addr)
        if res is None:
            res = self.gmaps.geocode(addr)
            self.gmap_geo_cache.add(addr, res)
        try:
            return res[0]["geometry"]["location"]
        except:
            return None

    def gmapReverseGeocode(self, lat, lng):
        coord_str = "%.5f,%.5f" % (lat, lng)
        res = self.gmap_rgeo_cache.get(coord_str)
        if res is None:
            res = self.gmaps.reverse_geocode((lat, lng))
            self.gmap_rgeo_cache.add(coord_str, res)
        if len(res) > 0:
            items = res[0]["address_components"]
            addr1 = None
            addr2 = None
            country = None
            for item in items:
                if "administrative_area_level_1" in item["types"]:
                    addr1 = item["long_name"]
                if "administrative_area_level_2" in item["types"]:
                    addr2 = item["long_name"]
                if "country" in item["types"]:
                    country = item["short_name"]
            if country is None:
                return (None, None)
            if addr2 is not None:
                return (addr2, country)
            return (addr1, country)
        return (None, None)

    def byLocal(self, ip):
        if ip in self.local_ip:
            loc = self.local_ip[ip]
            return {"place": loc[2],
                    "country": loc[3],
                    "lat": float(loc[0]),
                    "lng": float(loc[1]),
                    "method": "local"}
        return None

    def byGeoFeeds(self, ip):
        if ip in self.pyt_geofeeds:
            items = self.pyt_geofeeds[ip]
            country = items[1]
            place = items[3]
            if len(place) == 0:
                place = items[2]
            if len(place) > 0 and len(country) > 0:
                loc = self.gmapGeocode(f"{place},{country}")
                if loc is not None:
                    return {
                        "place": place,
                        "country": country,
                        "lat": float(loc["lat"]),
                        "lng": float(loc["lng"]),
                        "method": "geofeed"
                    }
        return None

    def byProviderFeeds(self, ip):
        if ip in self.pyt_ispfeeds:
            items = self.pyt_ispfeeds[ip].split("-")
            if len(items) == 5:
                loc = self.iata_loc[items[3]]
                return {
                    "place": loc["region_name"],
                    "country": loc["country_code"],
                    "lat": float(loc["latitude"]),
                    "lng": float(loc["longitude"]),
                    "method": "ispfeed"
                }
        return None

    def byPeeringDB(self, ip):
        if ip in self.pyt_pdb:
            ix = self.ixs[self.pyt_pdb[ip]]
            city = ix["city"]
            if city.find(', ') != -1:  # May include multiple cities, just take the first one
                city = city.split(', ')[0]
            country = ix["country"]
            loc = self.gmapGeocode(f"{city},{country}")
            if loc is not None:
                return {
                    "place": city,
                    "country": country,
                    "lat": loc["lat"],
                    "lng": loc["lng"],
                    "method": "peeringDB"
                }
        return None

    #  May use RIPE IP map rDNS engine instead
    def byHoiho(self, host):
        domain = tldextract.extract(host).registered_domain
        if domain not in self.hoiho:
            return None
        for regex in self.hoiho[domain]["re"]:
            res = re.match(regex, host)
            if res is None:
                continue
            code = res.group(1).lower()
            for hint in self.hoiho[domain]["geohints"]:
                if code == hint["code"]:
                    if hint["type"] == "clli":
                        code = code[:6]
                        if code in self.clli_loc:
                            loc = self.clli_loc[code]
                            (city, country) = self.gmapReverseGeocode(
                                loc[0], loc[1])
                            return {
                                "place": city,
                                "country": country,
                                "lat": loc[0],
                                "lng": loc[1],
                                "method": "hoiho"
                            }
                    else:
                        try:
                            city = hint["location"]["place"]
                            country = hint["location"]["cc"]
                        except Exception as e:
                            if "lat" in hint and "lng" in hint:
                                (city, country) = self.gmapReverseGeocode(
                                    float(hint["lat"]), float(hint["lng"]))
                            else:
                                continue
                        try:
                            lat = float(hint["lat"])
                            lng = float(hint["lng"])
                        except Exception as e:
                            loc = self.gmapGeocode(f"{city},{country}")
                            lat = loc["lat"]
                            lng = loc["lng"]
                        return {
                            "place": city,
                            "country": country,
                            "lat": lat,
                            "lng": lng,
                            "method": "hoiho"
                        }
        return None

    # May use RIPE IP map rDNS engine instead
    def byRDNS(self, ip):
        res = self.rDNS_cache.get(ip)
        if res is None:
            ar = AsyncResolver([ip])
            res = ar.resolve()[0]
            self.rDNS_cache.add(ip, res)
        host = res["host"]
        if host is not None:
            return self.byHoiho(host)
        return None

    def byRipeIPMap(self, ip):
        res = self.ripe_cache.get(ip)
        if res is None:
            response = requests.get(
                # f"https://ipmap-api.ripe.net/v1/locate/{ip}?engines=single-radius,latency")
                f"https://ipmap-api.ripe.net/v1/locate/{ip}")
            if response.status_code == 200:
                res = response.json()
                self.ripe_cache.add(ip, res)
        if res is not None and "locations" in res:
            for loc in res["locations"]:
                try:
                    # if loc["contributions"]["latency"]["minRtt"] < 5:
                    return {
                        "place": loc["cityName"],
                        "country": loc["countryCodeAlpha2"],
                        "lat": loc["latitude"],
                        "lng": loc["longitude"],
                        "method": "ripe IP Map"
                    }
                except Exception as e:
                    pass
        return None

    def byIPInfo(self, ip):
        res = self.ipinfo_cache.get(ip)
        if res is None:
            try:
                res = self.ipinfo_handler.getDetails(ip, timeout=60).details
                self.ipinfo_cache.add(ip, res)
            except Exception as e:
                print(e)
                pass
        try:
            return {
                "place": res["city"],
                "country": res["country"],
                "lat": float(res["latitude"]),
                "lng": float(res["longitude"]),
                "method": "ipinfo"
            }
        except Exception as e:
            pass
        return None

    def geoLocate(self, ip, cache_only=False):
        if not ipaddress.ip_address(ip).is_global:
            return None

        self.cnt += 1

        res = self.byLocal(ip)
        if res is not None:
            return res

        res = self.loc_cache.get(ip)
        if res is not None or cache_only:
            return res

        while True:
            res = self.byGeoFeeds(ip)
            if res is not None:
                break
            res = self.byProviderFeeds(ip)
            if res is not None:
                break
            res = self.byPeeringDB(ip)
            if res is not None:
                break
            res = self.byRDNS(ip)
            if res is not None:
                break
            res = self.byRipeIPMap(ip)
            if res is not None:
                break
            res = self.byIPInfo(ip)
            break

        if res is not None:
            self.loc_cache.add(ip, res)
        return res


if __name__ == "__main__":
    geoloc = GeoLocate(
        dirt="../data",
        google_api_key="YOUR_API_KEY",
        ipinfo_token="YOUR_TOKEN")
    print(geoloc.geoLocate("38.122.231.170"))
    print(geoloc.geoLocate("85.112.122.5"))
    print(geoloc.geoLocate("157.167.19.12"))
    print(geoloc.geoLocate("142.4.161.216"))
    print(geoloc.geoLocate("80.249.210.217"))
    print(geoloc.geoLocate("94.237.0.76"))
    print(geoloc.geoLocate("75.2.54.174"))
    print(geoloc.geoLocate("44.212.67.241"))
    print(geoloc.geoLocate("192.88.99.255"))
    print(geoloc.geoLocate("104.44.47.231"))
    print(geoloc.geoLocate("202.1.205.246"))
    print(geoloc.geoLocate("54.94.206.42"))
    print(geoloc.geoLocate("15.197.187.232"))
    print(geoloc.geoLocate("220.128.12.161"))
