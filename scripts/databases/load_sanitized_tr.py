import sys
import json
import database
import ipaddress
import utils
import argparse
from datetime import datetime
from utils import geodist
from geolocate import ip_asn_org

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--cloud', metavar='cloud',
                    type=str, help="AWS, Azure, Google")
parser.add_argument('-s', '--start_time', metavar='start_time',
                    type=str, help="eg. 2024-04-07 10:00:00-04:00", required=True)
parser.add_argument('-t', '--table_tag', metavar='table_tag',
                    type=str, help="20240304 or 20240901", required=True)
parser.add_argument('-l', '--locate_pop_done', action='store_true')
args = parser.parse_args()
print(' '.join(sys.argv), args)

# We put this function here instead of utils to align the sanitization with the table in db,
# because in the future we may change sanitization


def sanitize_tr_hops_20240304(traceroute):  # ripe atlas format:
    if "result" not in traceroute:
        return []
    hops = []
    ip_rtts = {}
    for i, hop in enumerate(traceroute["result"]):
        # hop_rtts is already sorted by the number of IP appearances in a hop
        hop_rtts = utils.get_hop_rtts(hop)
        for (ip, rtts) in hop_rtts:
            if ip not in ip_rtts:
                ip_rtts[ip] = []
            # an IP may appear at different hop (usually adjacent), merge the rtts
            ip_rtts[ip].extend(rtts)
        if len(hop_rtts) > 0:
            # Only use the IP with the most appearance if multiple IPs appears in a hop
            hops.append({
                "id": i,
                "ttl": hop["hop"],
                "ip": hop_rtts[0][0]
            })
    # Add rtts after ip_rtts goes through all hops
    for hop in hops:
        hop["rtts"] = ip_rtts[hop["ip"]]
    return hops


def load(clouds, table_tag, start_time):
    ipasn = ip_asn_org.IpAsnOrg(dirt=f"{utils.data_dir}")

    for cloud in clouds:
        traceroutes = utils.db.query(
            "ripe_cloud as rc, ripe_measure_meta as rm",
            "rc.msm_id,rc.prb_id,rc.timestamp,rc.result,btrim(rc.region),btrim(rc.service),rm.target,rc.ip_from",
            f"rc.msm_id=rm.msm_id and rc.msm_type='TRACEROUTE' and rc.cloud='{cloud}' and rc.timestamp>'{start_time}'")
        rows = []
        for msm_id, prb_id, timestamp, result, region, service, target, ip_from in traceroutes:
            sanitized_hops = sanitize_tr_hops_20240304(result)
            reach_dst = False
            if len(sanitized_hops) > 0 and target == sanitized_hops[-1]["ip"]:
                reach_dst = True

            asns = set()
            prb_asn = ipasn.lookup(ip_from)
            if prb_asn is not None:
                asns.add(prb_asn["asn"])
            for hop in sanitized_hops:
                asn = ipasn.lookup(hop["ip"])
                if asn is not None:
                    asns.add(asn["asn"])
                    hop["asn"] = asn["asn"]
                else:
                    hop["asn"] = None

            rows.append([msm_id, prb_id, timestamp, json.dumps(sanitized_hops),
                         reach_dst, cloud, region, service, len(asns)])
        print(cloud, len(rows))
        utils.db.insert(
            f"sanitized_tr_{table_tag} (msm_id,prb_id,timestamp,sanitized_hops,reach_dst,cloud,region,service,asn_len)", rows)

    # # reach_dst is set by SQL
    # set_reach_dst = f'''
    # update {table}
    # set reach_dst= true
    # where (msm_id, prb_id) in
    #     (select msm_id, prb_id
    #     from (select {table}.msm_id,
    #                     prb_id,
    #                     sanitized_hops,
    #                     host(target),
    #                     host(target) =
    #                     (jsonb_path_query_array(sanitized_hops, '$[*].ip') ->> -1) as reach_dst
    #             from {table},
    #                 ripe_measure_meta
    #             where {table}.msm_id = ripe_measure_meta.msm_id) as tab
    #     where tab.reach_dst = true);
    # '''
    # utils.db.execute_raw([set_reach_dst])


def get_dns_ping_rtts(cloud, start_time):
    # length(rm.tag)=34 refers to tag 'ping Azure VMs to compare with DNS'
    # rows = utils.db.query("ripe_cloud as rc,ripe_measure_meta as rm",
    #                       "rc.msm_id, prb_id, rc.cloud, btrim(rc.region), btrim(rc.service), launch_time, rc.msm_type, result",
    #                       "rc.msm_id = rm.msm_id and (rc.msm_type = 'DNS' or rc.msm_type = 'PING')" +
    #                       f" and (length(rm.tag) = 0 or length(rm.tag) = 34) and rc.cloud='{cloud}'")
    rows = utils.db.query("ripe_cloud as rc,ripe_measure_meta as rm",
                          "rc.msm_id, prb_id, rc.cloud, btrim(rc.region), btrim(rc.service), start_time, rc.msm_type, result",
                          "rc.msm_id = rm.msm_id and (rc.msm_type = 'DNS' or rc.msm_type = 'PING')" +
                          f" and length(rm.tag) = 0 and rc.cloud='{cloud}' and start_time>='{start_time}'")
    ping_rtts = {}
    dns_rtts = {}
    for msm_id, prb_id, cloud, region, service, start_time, msm_type, result in rows:
        # if msm_type == 'PING' and cloud == 'Azure':
        #     epoch = '24021403'
        # if msm_type == 'DNS' and cloud == 'AWS':
        #     epoch = '24092400'
        # epoch = utils.get_epoch_label(start_time)
        trace = (prb_id, (cloud, region, service), epoch)
        if msm_type == 'PING':
            utils.dict_init(ping_rtts, [trace], [])
            for item in result["result"]:
                if "rtt" in item:
                    ping_rtts[trace].append(item["rtt"])
        elif msm_type == 'DNS':
            utils.dict_init(dns_rtts, [trace], [])
            if "result" in result:
                dns_rtts[trace].append(result["result"]["rt"])
    return ping_rtts, dns_rtts

    # Google aisa-south1 is missing due configuration errors
    # '''
    # update sanitized_tr_20240304
    # set ping_rtts=tr_rtts
    # where cloud = 'Google'
    # and region = 'asia-south1';
    # '''


def update_rtts(clouds, table_tag, start_time):
    for cloud in clouds:
        ping_rtts, dns_rtts = get_dns_ping_rtts(cloud, start_time)
        print(cloud, len(ping_rtts), len(dns_rtts))

        # utils.db.execute_raw(
        #     [f"UPDATE {table} SET ping_rtts=NULL, dns_rtts=NULL, tr_rtts=NULL " +
        #      f"WHERE cloud='{cloud}' and timestamp>={start_time}"])
        rows = utils.db.query(f"sanitized_tr_{table_tag} as st,ripe_measure_meta as rm",
                              "st.msm_id,st.prb_id,st.cloud,btrim(st.region),btrim(st.service),rm.start_time, sanitized_hops -> -1 -> 'rtts', reach_dst",
                              f"st.msm_id=rm.msm_id and st.cloud='{cloud}' and rm.start_time>='{start_time}'")
        sqls = []
        for msm_id, prb_id, _, region, service, start_time, tr_rtts, reach_dst in rows:
            epoch = utils.get_epoch_label(start_time)
            trace = (prb_id, (cloud, region, service), epoch)
            # if cloud == 'Azure':
            #     ping_rtt = ping_rtts.get(
            #         (prb_id, (cloud, region, service), 24021403))
            # else:
            ping_rtt = ping_rtts.get(trace)
            dns_rtt = dns_rtts.get(trace)
            tr_rtt = tr_rtts if reach_dst else None

            rtts = [ping_rtt, dns_rtt, tr_rtt]
            for rtt_list in rtts:
                if rtt_list is not None:
                    rtt_list.sort()  # simplify future minimum operation in sql

            sql = f"UPDATE sanitized_tr_{table_tag} SET ping_rtts=%s, dns_rtts=%s, tr_rtts=%s" + \
                f" WHERE msm_id={msm_id} and prb_id={prb_id}"
            sqls.append((sql, rtts))

        print(cloud, len(sqls))
        utils.db.execute_raw(sqls)


def update_ingressASN(cloud, table_tag):
    utils.db.execute_raw(
        [f"UPDATE sanitized_tr_{table_tag} SET ingress_asn=NULL WHERE cloud='{cloud}'"])
    sql = f'''
    update sanitized_tr_{table_tag} as st
    set ingress_asn=tb.pen_asn
    from tr_borders_{table_tag} as tb
            left join ip_geo_{table_tag} on tb.pop = ip_geo_{table_tag}.ip
    where st.cloud='{cloud}'
    and st.msm_id = tb.msm_id
    and st.prb_id = tb.prb_id
    and ((ip_geo_{table_tag}.geo_method != 'local' and (not separated or colocated))
        or (ip_geo_{table_tag}.geo_method = 'local' and colocated))
    '''
    utils.db.execute_raw([sql])
    # # Need to run load_ip_geo.py, and set reach_dst and create tr_as_path_2024xxxx in table.sql
    # for cloud in ["AWS", "Azure", "Google"]:
    #     print(cloud)
    #     utils.db.execute_raw(
    #         [f"UPDATE sanitized_tr_20240304 SET ingress_asn=NULL WHERE cloud='{cloud}'"])
    #     cloud_asns = set(utils.get_cloud_asns(cloud))
    #     rows = utils.db.query("tr_as_path_20240412,ripe_measure_meta",
    #                           "ripe_measure_meta.msm_id, prb_id, json_agg(json_build_object('id', id, 'asn', asn))",
    #                           f"tr_as_path_20240412.msm_id = ripe_measure_meta.msm_id and cloud='{cloud}'",
    #                           "group by ripe_measure_meta.msm_id, prb_id")
    #     sqls = []
    #     for msm_id, prb_id, as_path in rows:
    #         as_path.sort(key=lambda x: x["id"])
    #         i = 0
    #         while i < len(as_path):
    #             hop = as_path[i]
    #             if hop["asn"] in cloud_asns:
    #                 break
    #             i += 1

    #         if 0 < i and i < len(as_path):
    #             if as_path[i - 1]["id"] + 1 == as_path[i]["id"]:
    #                 ingress_asn = as_path[i - 1]["asn"]
    #                 sql = f"UPDATE sanitized_tr_20240304 SET ingress_asn={ingress_asn} " +\
    #                     f"WHERE msm_id={msm_id} and prb_id={prb_id}"
    #                 sqls.append(sql)
    #                 if msm_id == 70167514 and prb_id == 32232:
    #                     print(i, as_path, cloud_asns)
    #     utils.db.execute_raw(sqls)


def update_dist(cloud, table_tag):
    utils.db.execute_raw(
        [f"UPDATE sanitized_tr_{table_tag} SET dist_e2e_km=NULL, dist_pop_km=NULL, in_efficiency=NULL, ex_efficiency=NULL, all_efficiency=NULL WHERE cloud='{cloud}'"])
    probe_loc = utils.get_probes_coordinates(
        "probe20240801" if table_tag == "20240901" else "probe20231130")
    cloud_region_loc = utils.get_cloud_region_loc()
    rtt_col = 'tr_rtts'
    if cloud == 'AWS':
        rtt_col = 'dns_rtts'
    trs = utils.db.query(  # use left join instead of join
        f" sanitized_tr_{table_tag} as st left join (tr_borders_{table_tag} join ip_geo_{table_tag} on tr_borders_{table_tag}.pop = ip_geo_{table_tag}.ip) as tb" +
        " on st.msm_id = tb.msm_id and st.prb_id = tb.prb_id",
        f"st.msm_id, st.prb_id, {rtt_col}, tb.pop_rtts, tb.lat, tb.lng, st.cloud, btrim(st.region)",
        f"cloud='{cloud}'")
    print(len(trs))

    sqls = []
    for msm_id, prb_id, e2e_rtts, pop_rtts, pop_lat, pop_lng, cloud, region in trs:
        prb_coord = probe_loc.get(prb_id)
        vm_coord = utils.dict_get(cloud_region_loc, [cloud, region])

        dist_e2e = None
        eff_e2e = None
        if prb_coord is not None and vm_coord is not None:
            dist_e2e = geodist.geodist(prb_coord, vm_coord)
            if e2e_rtts is not None and len(e2e_rtts) > 0:
                rtt_e2e = min(e2e_rtts)
                if rtt_e2e != 0:
                    eff_e2e = dist_e2e / rtt_e2e

        dist_ex = None
        eff_ex = None
        if prb_coord is not None and pop_lat is not None:
            dist_ex = geodist.geodist(prb_coord, (pop_lat, pop_lng))
            rtt_ex = min(pop_rtts)
            if rtt_ex != 0:  # TODO: Need to consider the colocation
                eff_ex = dist_ex / rtt_ex

        dist_in = None
        eff_in = None
        if pop_lat is not None and vm_coord is not None:
            dist_in = geodist.geodist((pop_lat, pop_lng), vm_coord)
            if e2e_rtts is not None and len(e2e_rtts) > 0:
                rtt_in = min(e2e_rtts) - min(pop_rtts)
                if rtt_in != 0:  # TODO: Need to consider the fluctuation and negative values
                    eff_in = dist_in / rtt_in

        dist_pop = None
        if dist_ex is not None and dist_in is not None:
            dist_pop = dist_ex + dist_in

        sqls.append((f"UPDATE sanitized_tr_{table_tag}" +
                    " SET dist_e2e_km=%s, dist_pop_km=%s, in_efficiency=%s, ex_efficiency=%s, all_efficiency=%s" +
                     f" WHERE msm_id={msm_id} and prb_id={prb_id}", (dist_e2e, dist_pop, eff_in, eff_ex, eff_e2e)))

    print(cloud, len(sqls))
    utils.db.execute_raw(sqls)


class Encoder:
    def __init__(self, tag):
        # start with a large constant to partition raw_id and trout_id to avoid errors in the future
        self.tag = tag
        self.__total_tid = 1100000000
        self.__id_encoder = {}
        self.__updated_ids = []
        self.trouts_raw = {}

        # DO NOT separate into different clouds for encoder
        rows = utils.db.query(
            f"traceroute_out_{self.tag}", "trout_raw_id,trout_id,prb_id, cloud,btrim(region),btrim(service),src_ip_pub,dst_ip,timestamp", "true",
            "order by cloud,region,service,dst_ip,timestamp, trout_raw_id")
        for raw_id, trout_id, prb_id, cloud, region, service, src_ip_pub, dst_ip, dt in rows:
            self.trouts_raw[raw_id] = [
                trout_id, prb_id, cloud, region, service, src_ip_pub, dst_ip, dt]
            if trout_id is not None:
                key = Encoder.__encode(cloud, region, service, dst_ip, dt)
                self.__id_encoder[key] = trout_id
                self.__total_tid = max(self.__total_tid, trout_id)

    def __encode(cloud, region, service, dst_ip, dt: datetime):
        dt_str = utils.get_epoch_label(dt)
        key = "%s_%s_%s_%s_%s" % (cloud, region, service, dst_ip, dt_str)
        return key

    def get_trout_id(self, raw_id):
        trout_id, _, cloud, region, service, _, dst_ip, dt = self.trouts_raw[raw_id]
        if trout_id is not None:
            return trout_id

        key = Encoder.__encode(cloud, region, service, dst_ip, dt)
        if key not in self.__id_encoder:
            self.__total_tid += 1
            self.__id_encoder[key] = self.__total_tid
        trout_id = self.__id_encoder[key]

        self.trouts_raw[raw_id][0] = trout_id
        self.__updated_ids.append([trout_id, raw_id])
        return trout_id

    def save_trout_id(self):
        print("# of added ids:", len(self.__updated_ids))
        if len(self.__updated_ids) > 0:
            utils.db.update(f"traceroute_out_{self.tag}", "trout_id",
                            "trout_raw_id", self.__updated_ids)


def load_out(cloud, table_tag, start_time):
    ipasn = ip_asn_org.IpAsnOrg(dirt=f"{utils.data_dir}")

    encoder = Encoder(table_tag)
    rows = utils.db.query(f"traceroute_out_{table_tag}",
                          "trout_raw_id, trout_id, result",
                          f"cloud='{cloud}' and timestamp>='{start_time}'")
    trouts = {}
    for raw_id, trout_id, result in rows:
        tid = encoder.get_trout_id(raw_id)
        if trout_id is not None and tid != trout_id:
            print("CRITICAL ERROR, tr_out_id diffs (%d, %d) for trout_raw_id (%d)" %
                  (out_id, tid, raw_id))
            exit()
        utils.dict_init(trouts, [tid], [])
        trouts[tid].append((raw_id, result))
    encoder.save_trout_id()

    records = []
    for tid, results in trouts.items():
        hops = {}
        _, prb_id, cloud, region, service, src_ip_pub, dst_ip, timestamp = encoder.trouts_raw[
            results[0][0]]
        # print(cloud, tid, len(results))
        for raw_id, result in results:
            if "hops" not in result:
                continue
            for data in result["hops"]:
                icmp_type = data["icmp_type"]
                icmp_code = data["icmp_code"]
                if (icmp_type, icmp_code) not in [(3, 1), (3, 3), (3, 10), (11, 0)]:
                    continue
                ttl = data["probe_ttl"]
                hop = {  # convert the ripe format
                    "ttl": data["reply_ttl"],
                    "from": data["addr"],
                    "rtt": data["rtt"],
                    "size": data["reply_size"]
                }
                if "icmpext" in data:
                    hop["icmpext"] = data["icmpext"]
                utils.dict_init(hops, [ttl], {"hop": ttl, "result": []})
                hops[ttl]["result"].append(hop)

        if len(hops) > 0:
            # convert the ripe format
            for ttl in range(1, max(hops.keys()) + 1):  # make hop.id to be hop.ttl-1
                utils.dict_init(hops, [ttl], {"hop": ttl, "result": []})
            hops = sorted(list(hops.values()), key=lambda x: x["hop"])
        else:
            hops = []

        sanitized_hops = sanitize_tr_hops_20240304({"result": hops})

        asns = set()
        prb_asn = ipasn.lookup(src_ip_pub)
        if prb_asn is not None:
            asns.add(prb_asn["asn"])
        for hop in sanitized_hops:
            asn = ipasn.lookup(hop["ip"])
            if asn is not None:
                asns.add(asn["asn"])
                hop["asn"] = asn["asn"]
            else:
                hop["asn"] = None
        reach_dst = False
        if len(sanitized_hops) > 0:
            reach_dst = (sanitized_hops[-1]["ip"] == dst_ip)
        record = [tid, timestamp, cloud, region, service, src_ip_pub, dst_ip, prb_id, json.dumps(sanitized_hops),
                  reach_dst, None, None, None, None, None, None, len(asns)]
        records.append(record)
    print(len(records))
    utils.db.insert(f"sanitized_trout_{table_tag}", records)


def update_egressASN(cloud, table_tag):
    # Set by sql
    sql = f'''
    update sanitized_trout_{table_tag} as st
    set egress_asn=tb.pen_asn
    from trout_borders_{table_tag} as tb
    where cloud='{cloud}' and st.trout_id = tb.trout_id
        and (not separated or colocated)
    '''
    utils.db.execute_raw([sql])


def update_dist_out(cloud, table_tag):
    utils.db.execute_raw(
        [f"UPDATE sanitized_trout_{table_tag} SET dist_e2e_km=NULL, dist_pop_km=NULL, in_efficiency=NULL, ex_efficiency=NULL, all_efficiency=NULL WHERE cloud='{cloud}'"])
    probe_loc = utils.get_probes_coordinates(
        "probe20240801" if table_tag == "20240901" else "probe20231130")
    cloud_region_loc = utils.get_cloud_region_loc()
    trs = utils.db.query(  # use left join instead of join
        f" sanitized_trout_{table_tag} as st left join (trout_borders_{table_tag} join ip_geo_{table_tag} on trout_borders_{table_tag}.pop = ip_geo_{table_tag}.ip) as tb" +
        " on st.trout_id = tb.trout_id",
        "st.trout_id, st.prb_id, sanitized_hops->-1->'rtts', reach_dst, tb.pop_rtts, tb.lat, tb.lng, st.cloud, btrim(st.region)",
        f"cloud='{cloud}'")
    print(len(trs))

    sqls = []
    for trout_id, prb_id, rtts, reach_dst, pop_rtts, pop_lat, pop_lng, cloud, region in trs:
        prb_coord = probe_loc.get(prb_id)
        vm_coord = utils.dict_get(cloud_region_loc, [cloud, region])

        dist_e2e = None
        eff_e2e = None
        if prb_coord is not None and vm_coord is not None:
            dist_e2e = geodist.geodist(prb_coord, vm_coord)
            if reach_dst:
                rtt_e2e = min(rtts)
                if rtt_e2e != 0:
                    eff_e2e = dist_e2e / rtt_e2e

        dist_ex = None
        eff_ex = None
        if prb_coord is not None and pop_lat is not None:
            dist_ex = geodist.geodist((pop_lat, pop_lng), prb_coord)
            if reach_dst:
                rtt_ex = min(rtts) - min(pop_rtts)
                if rtt_ex != 0:  # TODO: Need to consider the colocation
                    eff_ex = dist_ex / rtt_ex

        dist_in = None
        eff_in = None
        if pop_lat is not None and vm_coord is not None:
            dist_in = geodist.geodist(vm_coord, (pop_lat, pop_lng))
            rtt_in = min(pop_rtts)
            if rtt_in != 0:  # TODO: Need to consider the fluctuation and negative values
                eff_in = dist_in / rtt_in

        dist_pop = None
        if dist_ex is not None and dist_in is not None:
            dist_pop = dist_ex + dist_in

        sqls.append((f"UPDATE sanitized_trout_{table_tag}" +
                    " SET dist_e2e_km=%s, dist_pop_km=%s, in_efficiency=%s, ex_efficiency=%s, all_efficiency=%s" +
                     f" WHERE trout_id={trout_id}", (dist_e2e, dist_pop, eff_in, eff_ex, eff_e2e)))

    print(len(sqls))
    utils.db.execute_raw(sqls)


def load_tr_pop():
    sqls = []
    for cloud in ["AWS", "Azure", "Google"]:
        traceroutes = utils.db.query(
            "ripe_tr_pop", "msm_id,prb_id,dst_ip,result", f"cloud='{cloud}'")
        for msm_id, prb_id, dst_ip, result in traceroutes:
            sanitized_hops = sanitize_tr_hops_20240304(result)
            reach_dst = False
            if len(sanitized_hops) > 0:
                reach_dst = (sanitized_hops[-1]["ip"] == dst_ip)
            sqls.append(("UPDATE ripe_tr_pop SET sanitized_hops=%s, reach_dst=%s" +
                        f" WHERE msm_id={msm_id} and prb_id={prb_id}", (json.dumps(sanitized_hops), reach_dst)))
    utils.db.execute_raw(sqls)


def add_asn_to_sanitized_tr():
    ip_asn = {}
    # Use old asn info
    for ip, asn in utils.db.query("ip_geo_20240304", "ip,asn", "asn is not null"):
        ip_asn[ip] = asn

    rows = utils.db.query("sanitized_tr_20240304",
                          "msm_id,prb_id,sanitized_hops")
    sqls = []
    for msm_id, prb_id, sanitized_hops in rows:
        for hop in sanitized_hops:
            asn = ip_asn.get(hop["ip"])
            if asn is not None:
                hop["asn"] = asn
            else:
                hop["asn"] = None
        sqls.append((f"UPDATE sanitized_tr_20240304 SET sanitized_hops=%s WHERE msm_id=%s and prb_id=%s",
                    (json.dumps(sanitized_hops), msm_id, prb_id)))
    print(len(sqls))
    utils.db.execute_raw(sqls)

    rows = utils.db.query("sanitized_trout_20240304",
                          "trout_id,sanitized_hops")
    params = []
    for trout_id, sanitized_hops in rows:
        for hop in sanitized_hops:
            asn = ip_asn.get(hop["ip"])
            if asn is not None:
                hop["asn"] = asn
            else:
                hop["asn"] = None
        params.append((json.dumps(sanitized_hops), trout_id))
    print(len(params))
    utils.db.update("sanitized_trout_20240304",
                    "sanitized_hops", "trout_id", params)


if __name__ == "__main__":
    # update_rtts([args.cloud], args.table_tag, args.start_time)
    # update_dist(args.cloud, args.table_tag)
    if not args.locate_pop_done:
        load([args.cloud], args.table_tag, args.start_time)
        update_rtts([args.cloud], args.table_tag, args.start_time)
        load_out(args.cloud, args.table_tag, args.start_time)
    else:
        update_ingressASN(args.cloud, args.table_tag)
        update_dist(args.cloud, args.table_tag)
        update_egressASN(args.cloud, args.table_tag)
        update_dist_out(args.cloud, args.table_tag)
    # load_tr_pop()
    # add_asn_to_sanitized_tr()
    pass
