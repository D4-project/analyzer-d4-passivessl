#!/bin/bash
psql -hlocalhost -p5432 -Upostgres -d passive_ssl -f passivessl.sql
