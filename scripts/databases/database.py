import psycopg2


class Database:
    def __init__(self, params: str = "dbname=cira user=lsh password=danyang-03.postgres.lsh"):
        self.__conn = psycopg2.connect(params)

    def query_raw(self, sql):
        with self.__conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()

    def execute_raw(self, sqls: list):
        with self.__conn.cursor() as cur:
            for sql in sqls:
                if type(sql) == tuple or type(sql) == list:
                    cmd, params = sql
                    cur.execute(cmd, params)
                else:
                    cur.execute(sql)
        self.__conn.commit()

    def query(self, table: str, cols: str = "*", where: str = "true", additional=""):
        sql = f"SELECT {cols} FROM {table} WHERE {where} {additional}"
        return self.query_raw(sql)

    def update(self, table: str, column: str, wherekey: str, rows: list):
        sql = f"UPDATE {table} SET {column}=%s WHERE {wherekey}=%s"
        with self.__conn.cursor() as cur:
            cur.executemany(sql, rows)
        self.__conn.commit()

    def insert(self, table: str, rows: list):
        if len(rows) == 0:
            return

        placeholders = '(' + ','.join(["%s"] * len(rows[0])) + ')'
        sql = f"INSERT INTO {table} VALUES {placeholders} ON CONFLICT DO NOTHING"
        with self.__conn.cursor() as cur:
            cur.executemany(sql, rows)
        self.__conn.commit()

    def delete(self, table: str, where: str):
        sql = f"DELETE FROM {table} WHERE {where}"
        self.execute_raw([sql])


if __name__ == "__main__":
    import time
    import datetime

    # tz = datetime.datetime.now().astimezone()
    # print(tz)  # 2024-02-21 14:41:41.259346-05:00

    db = Database()
    # db.delete("ripe_measure_meta", "tag='pytest'")
    # db.insert("ripe_measure_meta", [
    #     [1, tz, "PING", "1.5.3.4", "ping test", "pytest", True],
    #     [2, tz, "DNS", "192.168.3.4", "dns test", "pytest", True]
    # ])

    # print(db.query("ripe_measure_meta", where="tag='pytest'"))

    # db.update("probe20231130", "continent",
    #           "country_code", [["NA", "US"], ["AS", "CN"]])
