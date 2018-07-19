# Purpose

This app sniff memcached binary traffic in order filter certains kind of informations (keys, commands, ttls, errors)
It also offer the possibility to forward store commands to an other memcached instance (still in binary format)

# How to build

- docker build -t memcache_sniffer .
- docker run --rm -ti -v (pwd):/data memcache_sniffer cp memcache_sniffer /data
- sudo setcap cap_net_raw,cap_net_admin=eip ./memcache_sniffer
