#!/bin/bash
# Set PGPASSWORD first
psql -hlocalhost -p5432 -Upostgres -d p2 -f passivessl.sql
