import sys
import json
import csv
import ipaddress
import argparse

import pytricia

import utils
from geolocate import ip_asn_org


parser = argparse.ArgumentParser()
parser.add_argument('-c', '--cloud', metavar='cloud',
                    type=str, help="AWS, Azure, Google")
parser.add_argument('-t', '--table_tag', metavar='table_tag',
                    type=str, help="20240304 or 20240901", required=True)
parser.add_argument('-s', '--start_time', metavar='start_time',
                    type=str, help="eg. 2024-04-07 10:00:00-04:00", required=True)
parser.add_argument('-r', '--repeat', action='store_true')
args = parser.parse_args()
print(' '.join(sys.argv), args)

ipasn = ip_asn_org.IpAsnOrg(dirt=f"{utils.data_dir}")


def is_close(hop1, hop2):
    rtt1 = min(hop1["rtts"])
    rtt2 = min(hop2["rtts"])
    return 0 <= rtt2 - rtt1 and rtt2 - rtt1 <= 2


def check_border(hop, borders):
    if borders[0] is not None and hop["ip"] == borders[0]["ip"]:
        return 0
    if borders[1] is not None and hop["ip"] == borders[1]["ip"]:
        return 1
    return None


def check_colocated(separated, dist_km, pen_rtts, pop_rtts):
    colocated = False
    if separated:
        try:
            if dist_km < 50 and abs(min(pen_rtts) - min(pop_rtts)) < 2:
                colocated = True
        except Exception as e:
            pass
    else:
        if dist_km is not None and dist_km < 50:
            colocated = True
    return colocated


def locate_traceroute(traces, cloud_asns, cloud_pop_list, with_timestamp=False):
    global probe_loc
    stats = {
        "geo_violate_event": 0,
        "colocate_event": 0
    }
    rows = []
    for msm_id, prb_id, timestamp, hops, ip_from in traces:
        borders = [None, None]
        prev = None
        hops = [{"id": -1, "ip": ip_from,
                 "ttl": 0, "rtts": [0, 0, 0]}] + hops
        for hop in hops:
            hop_ip = hop["ip"]  # ensure vm ip is correctly mapped to asn
            hop["asn"] = ipasn.lookup(hop_ip)
            if hop["asn"] is not None:
                method = hop["asn"]["method"]
                hop["asn"] = hop["asn"]["asn"]
                if hop["asn"] in cloud_asns:  # `hop_ip in cloud_ixp_ips` included in ipasn.lookup
                    ixp_pop = (method == "ixp")
                    borders[0] = prev
                    borders[1] = hop
                    break  # hop["asn"] should not be used later
            prev = hop

        if borders[1] is None:
            continue

        separated = False
        if (borders[0] is None) or (borders[0]["id"] + 1 != borders[1]["id"]):
            separated = True

        prb_loc = probe_loc[prb_id] if prb_id in probe_loc else None
        prev = None
        prev_res = None
        for hop in hops:
            if hop["ip"] == ip_from:
                if prb_loc is not None:
                    res = {"place": prb_loc[1], "country": prb_loc[2],
                           "lat": prb_loc[0][0], "lng": prb_loc[0][1],
                           "method": "ripe IP Map"}
                else:
                    res = None
            else:
                res = utils.geoloc.geoLocate(hop["ip"])

            idx = check_border(hop, borders)
            if idx == 1 and res is None and prev_res is not None and is_close(prev, hop):
                res = prev_res
                stats["colocate_event"] += 1
            if (res is not None) and (prb_loc is not None):
                if utils.check_light_speed_violation((res["lat"], res["lng"]), prb_loc[0], min(hop["rtts"])):
                    res = None
                    stats["geo_violate_event"] += 1

            if idx is not None:
                borders[idx]["loc"] = res
            prev_res = res
            prev = hop

        locs = [None, None]
        pop_listed = False
        for i in range(0, 2):
            if borders[i] is not None and borders[i]["loc"] is not None:
                loc = borders[i]["loc"]
                locs[i] = (loc["lat"], loc["lng"])
                if i == 1 and utils.in_pop_positions((loc["place"], loc["country"]), loc["lat"], loc["lng"], cloud_pop_list) is not None:
                    pop_listed = True

        dist_km = None
        if (locs[0] is not None) and (locs[1] is not None):
            dist_km = utils.geodist.geodist(locs[0], locs[1])

        row = [msm_id, prb_id]
        if with_timestamp:
            row.append(timestamp)
        if borders[0] is not None:
            row.extend([borders[0]["ip"], borders[0]["asn"],
                        borders[0]["ttl"], borders[0]["rtts"]])
        else:
            row.extend([None, None, None, None])
        row.extend([borders[1]["ip"], borders[1]["asn"], borders[1]["ttl"], borders[1]["rtts"],
                    ixp_pop, pop_listed, dist_km, separated])
        colocated = False
        if (borders[0] is not None) and (borders[1] is not None):
            colocated = check_colocated(
                separated, dist_km, borders[0]["rtts"], borders[1]["rtts"])
        row.append(colocated)
        rows.append(row)
    print(stats)
    return rows


def locate_traceroute_out(trouts, cloud_asns, cloud_pop_list):
    global probe_loc
    stats = {
        "geo_violate_event": 0,
        "colocate_event": 0,
    }
    rows = []
    for tid, prb_id, vm_ip, dst_ip, hops in trouts:
        vm_loc = utils.geoloc.geoLocate(vm_ip)
        if vm_loc is None or vm_loc["method"] != "local":
            print("Cannot geolocate VM IP %s. Need to fix geolocate_local.csv." %
                  vm_ip, file=sys.stderr)
            exit()

        hops = [{"id": -1, "ip": vm_ip,
                 "ttl": 0, "rtts": [0, 0, 0]}] + hops
        for hop in hops:
            # ensure vm ip is correctly mapped to asn
            asn = ipasn.lookup(hop["ip"])
            if asn is not None:
                hop["asn"] = asn["asn"]
                hop["asn_method"] = asn["method"]
            else:
                hop["asn"] = None
                hop["asn_method"] = None

        borders = [None, None]
        prev = None
        for hop in hops:
            if hop["asn"] not in cloud_asns:  # `hop_ip in cloud_ixp_ips` included in ipasn.lookup
                borders[0] = prev
                borders[1] = hop
                break
            prev = hop

        if borders[1] is None:
            continue

        ixp_pop = None
        if borders[0] is not None:
            ixp_pop = (borders[0]["asn_method"] == "ixp")

        separated = False
        if (borders[0] is None) or (borders[0]["id"] + 1 != borders[1]["id"]):
            separated = True

        prb_loc = probe_loc[prb_id] if prb_id in probe_loc else None
        prev = None
        prev_res = None
        for hop in hops:
            if hop["ip"] == vm_ip:
                res = vm_loc
            elif hop["ip"] == dst_ip:
                if prb_loc is not None:
                    res = {"place": prb_loc[1], "country": prb_loc[2],
                           "lat": prb_loc[0][0], "lng": prb_loc[0][1],
                           "method": "ripe IP Map"}
                else:
                    res = None
            else:
                res = utils.geoloc.geoLocate(hop["ip"])

            idx = check_border(hop, borders)
            if idx == 1 and res is None and prev_res is not None and is_close(prev, hop):
                res = prev_res
                stats["colocate_event"] += 1
            if (res is not None) and (prb_loc is not None):
                if utils.check_light_speed_violation((res["lat"], res["lng"]), (vm_loc["lat"], vm_loc["lng"]), min(hop["rtts"])):
                    res = None
                    stats["geo_violate_event"] += 1

            if idx is not None:
                borders[idx]["loc"] = res
            prev_res = res
            prev = hop

        locs = [None, None]
        for i in range(0, 2):
            if borders[i] is not None and borders[i]["loc"] is not None:
                loc = borders[i]["loc"]
                locs[i] = (loc["lat"], loc["lng"])

        pop_listed = None
        if locs[0] is not None:
            pop_listed = (utils.in_pop_positions(
                (borders[0]["loc"]["place"], borders[0]["loc"]["country"]), locs[0][0], locs[0][1], cloud_pop_list) is not None)

        dist_km = None
        if (locs[0] is not None) and (locs[1] is not None):
            dist_km = utils.geodist.geodist(locs[0], locs[1])

        row = [tid]
        if borders[0] is not None:
            row.extend([borders[0]["ip"], borders[0]["asn"],
                        borders[0]["ttl"], borders[0]["rtts"]])
        else:
            row.extend([None, None, None, None])
        row.extend([borders[1]["ip"], borders[1]["asn"], borders[1]["ttl"], borders[1]["rtts"],
                    ixp_pop, separated, pop_listed, dist_km])
        colocated = False
        if (borders[0] is not None) and (borders[1] is not None):
            colocated = check_colocated(
                separated, dist_km, borders[1]["rtts"], borders[0]["rtts"])
        row.append(colocated)
        rows.append(row)
    print(stats)
    return rows


probe_loc = utils.get_probes_coordinates_city_asn(
    "probe20240801" if args.table_tag == "20240901" else "probe20231130")
cloud_region_loc = utils.get_cloud_region_loc()

if __name__ == "__main__":
    # update_border()
    # update_border_out()
    # exit()

    # for cloud in ["AWS", "Azure", "Google"]:
    if args.cloud is None:
        clouds = ["AWS", "Azure", "Google"]
    else:
        clouds = [args.cloud]
    for cloud in clouds:
        pop_list = utils.get_pops(cloud)
        cloud_asns = utils.get_cloud_asns(cloud)

        print(cloud, len(pop_list), len(cloud_asns))

        # asn_city
        # traces = utils.db.query(f"ripe_asn_city_trs", "msm_id,prb_id,timestamp,sanitized_hops,ip_from",
        #                         f"cloud='{cloud}'")
        # rows = locate_traceroute(traces, cloud_asns, pop_list)
        # utils.db.insert("tr_borders_asn_city", rows)
        # continue

        if not args.repeat:
            # traceroute in
            traces = utils.db.query(f"sanitized_tr_{args.table_tag} as st, ripe_cloud as rc",
                                    "st.msm_id, st.prb_id, st.timestamp, st.sanitized_hops, rc.ip_from",
                                    "st.msm_id=rc.msm_id and st.prb_id=rc.prb_id" +
                                    f" and st.cloud='{cloud}' and st.timestamp>='{args.start_time}'")
            rows = locate_traceroute(traces, cloud_asns, pop_list)
            utils.db.insert(f"tr_borders_{args.table_tag}", rows)

            # traceroute out
            trouts = utils.db.query(f"sanitized_trout_{args.table_tag}",
                                    "trout_id,prb_id,src_ip_pub,dst_ip,sanitized_hops",
                                    f"cloud='{cloud}' and src_ip_pub is not NULL and timestamp>='{args.start_time}'")
            rows = locate_traceroute_out(trouts, cloud_asns, pop_list)
            utils.db.insert(f"trout_borders_{args.table_tag}", rows)
        else:
            # repeat traceroute in
            traces = utils.db.query(f"repeat_sanitized_tr_{args.table_tag} as rst, repeat_ripe_cloud as rrc",
                                    "rst.msm_id, rst.prb_id, rst.timestamp, sanitized_hops, rrc.ip_from",
                                    "rst.msm_id=rrc.msm_id and rst.prb_id=rrc.prb_id and rst.timestamp=rrc.timestamp" +
                                    f" and rst.cloud='{cloud}' and rst.timestamp>='{args.start_time}'")
            rows = locate_traceroute(
                traces, cloud_asns, pop_list, with_timestamp=True)
            utils.db.insert(f"repeat_tr_borders_{args.table_tag}", rows)

            # repeat traceroute out
            trouts = utils.db.query(f"repeat_sanitized_trout_{args.table_tag}",
                                    "trout_id,prb_id,src_ip_pub,dst_ip,sanitized_hops",
                                    f"cloud='{cloud}' and src_ip_pub is not NULL and timestamp>='{args.start_time}'")
            rows = locate_traceroute_out(trouts, cloud_asns, pop_list)
            utils.db.insert(f"repeat_trout_borders_{args.table_tag}", rows)
