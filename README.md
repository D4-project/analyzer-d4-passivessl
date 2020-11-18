analyzer-d4-passivessl fetch a redis feed of certificate and TLS sessions and massage the dataset to be usable by lookup-d4-passivessl service.

# Dependencies
```bash
go get github.com/gomodule/redigo/redis
go get github.com/lib/pq
sudo apt install postgresql-plpython3-[your psql version]
```

# Config

```bash
analyzer-d4-passivessl - Passive SSL analyzer:

 Fetch data from sensor-d4-tls-fingerprinting and push it into d4-passivessl-server

Usage:

 analyzer-d4-passivessl -c  config_directory

Configuration:

 The configuration settings are stored in files in the configuration directory
 specified with the -c command line switch.

Files in the configuration directory:

 redis - empty if not used.
       | host:port/db
 redis_queue - type and uuid of the redis queue
          | type:uuid 
 postgres - postgres database
          | user:password@host:port/db
 certfolder - absolute path to the folder containing certificates
          | /.... 
```
