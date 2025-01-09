import requests
import time

API_KEY = "YOUR_API_KEY"

headers = {"Authorization": "Api-Key " + API_KEY}

res = requests.get("https://www.peeringdb.com/api/fac", headers=headers)
with open("../../data/peeringDB/peeringDB_fac.json", "w") as fout:
    fout.write(res.text)
time.sleep(1)

res = requests.get("https://www.peeringdb.com/api/carrier", headers=headers)
with open("../../data/peeringDB/peeringDB_carrier.json", "w") as fout:
    fout.write(res.text)
time.sleep(1)

res = requests.get("https://www.peeringdb.com/api/carrierfac", headers=headers)
with open("../../data/peeringDB/peeringDB_carrierfac.json", "w") as fout:
    fout.write(res.text)
time.sleep(1)

res = requests.get("https://www.peeringdb.com/api/ix", headers=headers)
with open("../../data/peeringDB/peeringDB_ix.json", "w") as fout:
    fout.write(res.text)
time.sleep(1)

res = requests.get("https://www.peeringdb.com/api/ixfac", headers=headers)
with open("../../data/peeringDB/peeringDB_ixfac.json", "w") as fout:
    fout.write(res.text)
time.sleep(1)

res = requests.get("https://www.peeringdb.com/api/ixlan", headers=headers)
with open("../../data/peeringDB/peeringDB_ixlan.json", "w") as fout:
    fout.write(res.text)
time.sleep(1)

res = requests.get("https://www.peeringdb.com/api/ixpfx", headers=headers)
with open("../../data/peeringDB/peeringDB_ixpfx.json", "w") as fout:
    fout.write(res.text)
time.sleep(1)

res = requests.get("https://www.peeringdb.com/api/net", headers=headers)
with open("../../data/peeringDB/peeringDB_net.json", "w") as fout:
    fout.write(res.text)
time.sleep(1)

res = requests.get("https://www.peeringdb.com/api/netfac", headers=headers)
with open("../../data/peeringDB/peeringDB_netfac.json", "w") as fout:
    fout.write(res.text)
time.sleep(1)

res = requests.get("https://www.peeringdb.com/api/netixlan", headers=headers)
with open("../../data/peeringDB/peeringDB_netixlan.json", "w") as fout:
    fout.write(res.text)
time.sleep(1)
