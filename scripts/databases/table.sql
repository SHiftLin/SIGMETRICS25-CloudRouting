CREATE TYPE msmtype AS ENUM ('PING','TRACEROUTE','DNS','TLS','HTTP','NTP');
CREATE TYPE cloud AS ENUM ('Google', 'Azure', 'AWS');

CREATE TABLE ripe_measure_meta
(
    msm_id      int primary key,
    launch_time timestamptz NOT NULL, -- Launch time by our Python script, not RIPE Atlas creation_time
    create_time timestamptz NOT NULL, -- Actual RIPE Atlas creation time
    start_time  timestamptz NOT NULL,
    stop_time   timestamptz NOT NULL,
    msm_type    msmtype     NOT NULL,
    target      inet        NOT NULL,
    description char(128),
    cloud       cloud,
    region      char(32),
    service     char(32),
    tag         char(64),
    test        bool        NOT NULL  -- whether the measurement is just for test
);
create index ripe_measure_meta_cloud_region_index on ripe_measure_meta (cloud, region);
create index ripe_measure_meta_service_index on ripe_measure_meta (service);


CREATE TABLE probe20231130
(
    prb_id       int primary key,
    connected    bool,
    public       bool,
    address_v4   inet,
    address_v6   inet,
    prefix_v4    cidr,
    prefix_v6    cidr,
    asn_v4       int,
    asn_v6       int,
    city         varchar(128),
    country      varchar(64),
    country_code char(4),
    lat          float8,
    lng          float8,
    description  text,
    is_anchor    bool,
    type         char(8),
    tags         varchar(128)[]
);

CREATE TABLE ripe_cloud
(
    msm_id    int,
    prb_id    int,
    timestamp timestamptz NOT NULL,
    msm_type  msmtype     NOT NULL,
    fw        int,                  -- probe's firmware version
    ip_from   inet        NOT NULL, -- IP address of the probe as known by controller
    proto     char(8)     NOT NULL,
    cloud     cloud,                -- copy cloud,region,service from meta table here to avoid join every time
    region    char(32),
    service   char(32),
    result    jsonb,
    PRIMARY KEY (msm_id, prb_id),
    FOREIGN KEY (msm_id) REFERENCES ripe_measure_meta (msm_id)
--     FOREIGN KEY (prb_id) REFERENCES probe20231130 (prb_id)
);
create index ripe_cloud_cloud_region_index on ripe_cloud (cloud, region);
create index ripe_cloud_service_index on ripe_cloud (service);

CREATE TABLE cloud_ping_pop_20240304
(
    launch_time timestamptz NOT NULL,
    cloud       cloud       NOT NULL,
    region      char(32)    NOT NULL,
    service     char(32)    NOT NULL,
    dst_ip      inet        NOT NULL,
    rtts        float8[],
    PRIMARY KEY (cloud, region, service, dst_ip, launch_time)
);
create index cloud_ping_pen_ip_index on cloud_ping_pop_20240304 (dst_ip);


CREATE TABLE cloud_ping_pop_20240901
(
    start_time timestamptz NOT NULL,
    cloud      cloud       NOT NULL,
    region     char(32)    NOT NULL,
    service    char(32)    NOT NULL,
    dst_ip     inet        NOT NULL,
    rtts       float8[],
    PRIMARY KEY (cloud, region, service, dst_ip, start_time)
);
create index cloud_ping_pop_20240901_ip_index on cloud_ping_pop_20240901 (dst_ip);


CREATE TABLE asn
(
    asn           bigint primary key,
    asn_name      char(256),
    org           char(256),
    rank          int,
    clique_member bool,
    country_code  char(4)
);

create table cloud_asns as
(select 'AWS'::cloud as cloud, asn
 from asn
 where lower(org) like '%amazon%')
union
(select 'Azure'::cloud as cloud, asn
 from asn
 where lower(org) like '%microsoft%')
union
(select 'Google'::cloud as cloud, asn
 from asn
 where lower(org) like '%google%')
order by cloud, asn;

alter table cloud_asns
    add constraint cloud_asns_pk
        primary key (asn);
create index cloud_asns_cloud_index
    on public.cloud_asns (cloud);


CREATE TABLE tr_borders_20240304
(
    msm_id     int NOT NULL,
    prb_id     int NOT NULL,
    pen        inet, -- the last non-cloud hop
    pen_asn    int,
    pen_ttl    int,
    pen_rtts   float8[],
    pop        inet, -- the first cloud hop
    pop_asn    int,
    pop_ttl    int,
    pop_rtts   float8[],
    ixp_pop    bool,
    listed_pop bool, -- the pop is listed on the cloud's website
    dist_km    float8,
    separated  bool, -- separated by one or more wildcards in the traceroute
    colocated  bool,
    PRIMARY KEY (msm_id, prb_id),
    FOREIGN KEY (msm_id, prb_id) REFERENCES ripe_cloud (msm_id, prb_id),
    FOREIGN KEY (msm_id) REFERENCES ripe_measure_meta (msm_id),
    FOREIGN KEY (prb_id) REFERENCES probe20231130 (prb_id)
);

CREATE TABLE tr_borders_20240901
(
    msm_id     int NOT NULL,
    prb_id     int NOT NULL,
    pen        inet, -- the last non-cloud hop
    pen_asn    int,
    pen_ttl    int,
    pen_rtts   float8[],
    pop        inet, -- the first cloud hop
    pop_asn    int,
    pop_ttl    int,
    pop_rtts   float8[],
    ixp_pop    bool,
    listed_pop bool, -- the pop is listed on the cloud's website
    dist_km    float8,
    separated  bool, -- separated by one or more wildcards in the traceroute
    colocated  bool,
    PRIMARY KEY (msm_id, prb_id),
    FOREIGN KEY (msm_id, prb_id) REFERENCES ripe_cloud (msm_id, prb_id),
    FOREIGN KEY (msm_id) REFERENCES ripe_measure_meta (msm_id),
    FOREIGN KEY (prb_id) REFERENCES probe20240801 (prb_id)
);


CREATE TABLE sanitized_tr_20240304
(
    msm_id         int NOT NULL,
    prb_id         int NOT NULL,
    cloud          cloud,
    region         char(32),
    service        char(32),
    sanitized_hops jsonb,
    asn_len        integer,
    reach_dst      bool default false,
    ingress_asn    int,
    in_efficiency  float8,
    ex_efficiency  float8,
    all_efficiency float8,
    dist_e2e_km    float8,   -- distance from probe to vm
    dist_pop_km    float8,   -- distance from probe to pop to vm
    ping_rtts      float8[], -- sorted
    dns_rtts       float8[], -- sorted
    tr_rtts        float8[], -- sorted
    PRIMARY KEY (msm_id, prb_id),
    FOREIGN KEY (msm_id, prb_id) REFERENCES ripe_cloud (msm_id, prb_id),
    FOREIGN KEY (msm_id) REFERENCES ripe_measure_meta (msm_id),
    FOREIGN KEY (prb_id) REFERENCES probe20231130 (prb_id)
);
create index sanitized_tr_20240304_cloud_region on sanitized_tr_20240304 (cloud, region);
create index sanitized_tr_20240304_service on sanitized_tr_20240304 (service);



CREATE TABLE sanitized_tr_20240901
(
    msm_id         int NOT NULL,
    prb_id         int NOT NULL,
    timestamp      timestamptz,
    cloud          cloud,
    region         char(32),
    service        char(32),
    sanitized_hops jsonb,
    asn_len        integer,
    reach_dst      bool default false,
    ingress_asn    int,
    in_efficiency  float8,
    ex_efficiency  float8,
    all_efficiency float8,
    dist_e2e_km    float8,   -- distance from probe to vm
    dist_pop_km    float8,   -- distance from probe to pop to vm
    ping_rtts      float8[], -- sorted
    dns_rtts       float8[], -- sorted
    tr_rtts        float8[], -- sorted
    PRIMARY KEY (msm_id, prb_id),
    FOREIGN KEY (msm_id, prb_id) REFERENCES ripe_cloud (msm_id, prb_id),
    FOREIGN KEY (msm_id) REFERENCES ripe_measure_meta (msm_id),
    FOREIGN KEY (prb_id) REFERENCES probe20240801 (prb_id)
);
create index sanitized_tr_20240901_cloud_region on sanitized_tr_20240901 (cloud, region);
create index sanitized_tr_20240901_service on sanitized_tr_20240901 (service);


create table probe_ping_dst_20240427
(
    prb_id int  not null,
    dst_ip inet not null,
    cloud  cloud,
    PRIMARY KEY (prb_id, dst_ip, cloud),
    FOREIGN KEY (prb_id) REFERENCES probe20231130 (prb_id)
);
create index probe_ping_dst_20240427_cloud_index on probe_ping_dst_20240427 (cloud);


create table probe_ping_dst_20240901
(
    prb_id int  not null,
    dst_ip inet not null,
    cloud  cloud,
    PRIMARY KEY (prb_id, dst_ip, cloud),
    FOREIGN KEY (prb_id) REFERENCES probe20240801 (prb_id)
);
create index probe_ping_dst_20240901_cloud_index on probe_ping_dst_20240901 (cloud);



CREATE TABLE ripe_ping_pop_20240304
(
    msm_id    int         NOT NULL,
    prb_id    int         NOT NULL,
    timestamp timestamptz NOT NULL,
    fw        int,                  -- probe's firmware version
    ip_from   inet        NOT NULL, -- IP address of the probe as known by controller
    proto     char(8)     NOT NULL,
    dst_ip    inet,
    rtts      float8[],
    tr_cloud  cloud,
    result    jsonb,
    PRIMARY KEY (msm_id, prb_id),
    FOREIGN KEY (msm_id) REFERENCES ripe_measure_meta (msm_id),
    FOREIGN KEY (prb_id) REFERENCES probe20231130 (prb_id)
);
create index ripe_ping_pop_prb_id_dst_ip on ripe_ping_pop_20240304 (prb_id, dst_ip);


CREATE TABLE ripe_ping_pop_20240901
(
    msm_id    int         NOT NULL,
    prb_id    int         NOT NULL,
    timestamp timestamptz NOT NULL,
    fw        int,                  -- probe's firmware version
    ip_from   inet        NOT NULL, -- IP address of the probe as known by controller
    proto     char(8)     NOT NULL,
    dst_ip    inet,
    rtts      float8[],
    tr_cloud  cloud,
    result    jsonb,
    PRIMARY KEY (msm_id, prb_id),
    FOREIGN KEY (msm_id) REFERENCES ripe_measure_meta (msm_id),
    FOREIGN KEY (prb_id) REFERENCES probe20240801 (prb_id)
);
create index ripe_ping_pop_20240901_prb_id_dst_ip on ripe_ping_pop_20240901 (prb_id, dst_ip);
