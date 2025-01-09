import os
import json
import redis


class RedisCache:
    def __init__(self, name="cache", db=0,
                 encoder=json.dumps, decoder=json.loads):
        self.name = name
        self.__conn = redis.Redis(host="localhost", port=6379, username="lsh",
                                  password="password", decode_responses=True, db=db)
        self.__encoder = encoder
        self.__decoder = decoder

    def __gen_key(self, key):
        return self.name + ":" + key

    def add(self, key: str, value: dict):
        key = self.__gen_key(key)
        value = self.__encoder(value)
        res = self.__conn.set(key, value, get=True)
        if res is not None:
            res = self.__decoder(res)
        return res

    def get(self, key: str) -> dict:
        key = self.__gen_key(key)
        res = self.__conn.get(key)
        if res is not None:
            res = self.__decoder(res)
        return res

    def remove(self, key) -> int:
        key = self.__gen_key(key)
        return self.__conn.delete(key)

    def scan(self, key):
        key = self.__gen_key(key)
        res = []
        for full_key in self.__conn.scan_iter(key):
            res.append(full_key.replace(self.name + ":", ''))
        return res
