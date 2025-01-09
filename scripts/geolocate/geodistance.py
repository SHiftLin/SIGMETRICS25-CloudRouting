from geopy.distance import geodesic


class GeoDistance:
    def __init__(self):
        self.__cache = {}

    def geodist(self, loc1, loc2):
        if (loc1, loc2) in self.__cache:
            return self.__cache[(loc1, loc2)]
        if (loc2, loc1) in self.__cache:
            return self.__cache[(loc2, loc1)]
        self.__cache[(loc1, loc2)] = geodesic(loc1, loc2).km
        return self.__cache[(loc1, loc2)]


geodist = GeoDistance()

if __name__ == "__main__":
    # prb_id=169 and region='us-east4'
    print(geodist.geodist((55.6315, 13.7005), (53.55, 9.99)))
    print(geodist.geodist((55.6315, 13.7005), (59.33, 18.07)))
