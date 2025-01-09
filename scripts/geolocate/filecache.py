import os
import json


class FileCache:
    def __init__(self,  name="filecache", dirt="../../data",):
        self.name = name
        self.dirt = dirt
        self.filename = f"cache_{name}.json"
        self.cache = {}

        self.load_cache()

    def load_cache(self):
        fp = f"{self.dirt}/{self.filename}"
        try:
            with open(fp, "r", encoding="utf-8") as fin:
                for line in fin:
                    data = json.loads(line)
                    self.cache[data["key"]] = data["value"]
            return None
        except Exception as e:
            return e

    def dump_cache(self):
        fp = f"{self.dirt}/{self.filename}"
        with open(fp, "w", encoding="utf-8") as fout:
            for key in self.cache:
                jstr = json.dumps(
                    {"key": key, "value": self.cache[key]}, ensure_ascii=False)
                fout.write(jstr+"\n")

    def add(self, key, value):
        res = None
        if key in self.cache:
            res = self.cache[key]
        self.cache[key] = value
        return res

    def get(self, key):
        if key in self.cache:
            return self.cache[key]
        return None

    def remove(self, key):
        return self.cache.pop(key, None)
