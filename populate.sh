#!/bin/bash
# Set PGPASSWORD first
# export PGPASSWORD=postgres
psql -hlocalhost -p5432 -Upostgres -f passivesslCreate.sql
psql -hlocalhost -p5432 -Upostgres -d p2 -f passivessl.sql
