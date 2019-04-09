-- Database generated with pgModeler (PostgreSQL Database Modeler).
-- pgModeler  version: 0.9.1-beta
-- PostgreSQL version: 10.0
-- Project Site: pgmodeler.com.br
-- Model Author: ---


-- Database creation must be done outside an multicommand file.
-- These commands were put in this file only for convenience.
-- -- object: new_database | type: DATABASE --
-- -- DROP DATABASE IF EXISTS new_database;
-- CREATE DATABASE new_database
-- ;
-- -- ddl-end --
-- 

-- object: ltree | type: EXTENSION --
-- DROP EXTENSION IF EXISTS ltree CASCADE;
CREATE EXTENSION ltree
      WITH SCHEMA public;
-- ddl-end --

-- object: hstore | type: EXTENSION --
-- DROP EXTENSION IF EXISTS hstore CASCADE;
CREATE EXTENSION hstore
      WITH SCHEMA public;
-- ddl-end --

-- object: public.public_key | type: TABLE --
-- DROP TABLE IF EXISTS public.public_key CASCADE;
CREATE TABLE public.public_key(
	hash bytea NOT NULL,
	type text NOT NULL,
	modulus text,
	exponent int4,
	modulus_size int4,
	"P" numeric,
	"Q" numeric,
	"G" numeric,
	"Y" numeric,
	"X" numeric,
	"N" numeric,
	"B" numeric,
	bitsize int4,
	curve_name varchar(256),
	"Gx" numeric,
	"Gy" numeric,
	CONSTRAINT public_key_pk PRIMARY KEY (hash)

);
-- ddl-end --
ALTER TABLE public.public_key OWNER TO postgres;
-- ddl-end --

-- object: public.certificate | type: TABLE --
-- DROP TABLE IF EXISTS public.certificate CASCADE;
CREATE TABLE public.certificate(
	file_path varchar(4096) NOT NULL,
	issuer text,
	cert_chain public.ltree,
	subject text,
	hash bytea NOT NULL,
	"is_CA" bool NOT NULL DEFAULT false,
	is_valid_chain bool NOT NULL DEFAULT false,
	"notBefore" time,
	"notAfter" time,
	CONSTRAINT certificate_pk PRIMARY KEY (hash)

);
-- ddl-end --
ALTER TABLE public.certificate OWNER TO postgres;
-- ddl-end --

-- object: public.many_certificate_has_many_public_key | type: TABLE --
-- DROP TABLE IF EXISTS public.many_certificate_has_many_public_key CASCADE;
CREATE TABLE public.many_certificate_has_many_public_key(
	hash_certificate bytea NOT NULL,
	hash_public_key bytea NOT NULL,
	CONSTRAINT many_certificate_has_many_public_key_pk PRIMARY KEY (hash_certificate,hash_public_key)

);
-- ddl-end --

-- object: certificate_fk | type: CONSTRAINT --
-- ALTER TABLE public.many_certificate_has_many_public_key DROP CONSTRAINT IF EXISTS certificate_fk CASCADE;
ALTER TABLE public.many_certificate_has_many_public_key ADD CONSTRAINT certificate_fk FOREIGN KEY (hash_certificate)
REFERENCES public.certificate (hash) MATCH FULL
ON DELETE RESTRICT ON UPDATE CASCADE;
-- ddl-end --

-- object: public_key_fk | type: CONSTRAINT --
-- ALTER TABLE public.many_certificate_has_many_public_key DROP CONSTRAINT IF EXISTS public_key_fk CASCADE;
ALTER TABLE public.many_certificate_has_many_public_key ADD CONSTRAINT public_key_fk FOREIGN KEY (hash_public_key)
REFERENCES public.public_key (hash) MATCH FULL
ON DELETE RESTRICT ON UPDATE CASCADE;
-- ddl-end --

-- object: public."sessionRecord" | type: TABLE --
-- DROP TABLE IF EXISTS public."sessionRecord" CASCADE;
CREATE TABLE public."sessionRecord"(
	id bigserial NOT NULL,
	dst_ip inet NOT NULL,
	src_ip inet NOT NULL,
	dst_port int4 NOT NULL,
	src_port int4 NOT NULL,
	hash_ja3 bytea,
	"timestamp" time(0) with time zone,
	CONSTRAINT "sessionRecord_pk" PRIMARY KEY (id)

);
-- ddl-end --
ALTER TABLE public."sessionRecord" OWNER TO postgres;
-- ddl-end --

-- object: public.ja3 | type: TABLE --
-- DROP TABLE IF EXISTS public.ja3 CASCADE;
CREATE TABLE public.ja3(
	hash bytea NOT NULL,
	raw text,
	type smallint NOT NULL,
	CONSTRAINT j3a_pk PRIMARY KEY (hash)

);
-- ddl-end --
ALTER TABLE public.ja3 OWNER TO postgres;
-- ddl-end --

-- object: ja3_fk | type: CONSTRAINT --
-- ALTER TABLE public."sessionRecord" DROP CONSTRAINT IF EXISTS ja3_fk CASCADE;
ALTER TABLE public."sessionRecord" ADD CONSTRAINT ja3_fk FOREIGN KEY (hash_ja3)
REFERENCES public.ja3 (hash) MATCH FULL
ON DELETE SET NULL ON UPDATE CASCADE;
-- ddl-end --

-- object: public."many_sessionRecord_has_many_certificate" | type: TABLE --
-- DROP TABLE IF EXISTS public."many_sessionRecord_has_many_certificate" CASCADE;
CREATE TABLE public."many_sessionRecord_has_many_certificate"(
	"id_sessionRecord" bigint NOT NULL,
	hash_certificate bytea NOT NULL,
	CONSTRAINT "many_sessionRecord_has_many_certificate_pk" PRIMARY KEY ("id_sessionRecord",hash_certificate)

);
-- ddl-end --

-- object: "sessionRecord_fk" | type: CONSTRAINT --
-- ALTER TABLE public."many_sessionRecord_has_many_certificate" DROP CONSTRAINT IF EXISTS "sessionRecord_fk" CASCADE;
ALTER TABLE public."many_sessionRecord_has_many_certificate" ADD CONSTRAINT "sessionRecord_fk" FOREIGN KEY ("id_sessionRecord")
REFERENCES public."sessionRecord" (id) MATCH FULL
ON DELETE RESTRICT ON UPDATE CASCADE;
-- ddl-end --

-- object: certificate_fk | type: CONSTRAINT --
-- ALTER TABLE public."many_sessionRecord_has_many_certificate" DROP CONSTRAINT IF EXISTS certificate_fk CASCADE;
ALTER TABLE public."many_sessionRecord_has_many_certificate" ADD CONSTRAINT certificate_fk FOREIGN KEY (hash_certificate)
REFERENCES public.certificate (hash) MATCH FULL
ON DELETE RESTRICT ON UPDATE CASCADE;
-- ddl-end --

-- object: public.fuzzy_hash | type: TABLE --
-- DROP TABLE IF EXISTS public.fuzzy_hash CASCADE;
CREATE TABLE public.fuzzy_hash(
	id bigserial NOT NULL,
	type text NOT NULL,
	value public.hstore NOT NULL,
	hash_ja3 bytea,
	CONSTRAINT fuzzy_hash_pk PRIMARY KEY (id)

);
-- ddl-end --
ALTER TABLE public.fuzzy_hash OWNER TO postgres;
-- ddl-end --

-- object: public.software | type: TABLE --
-- DROP TABLE IF EXISTS public.software CASCADE;
CREATE TABLE public.software(
	id serial NOT NULL,
	name text NOT NULL,
	version text,
	CONSTRAINT software_pk PRIMARY KEY (id)

);
-- ddl-end --
ALTER TABLE public.software OWNER TO postgres;
-- ddl-end --

-- object: public.annotation | type: TABLE --
-- DROP TABLE IF EXISTS public.annotation CASCADE;
CREATE TABLE public.annotation(
	id serial NOT NULL,
	hash_ja3 bytea,
	confidence smallint,
	id_software integer,
	CONSTRAINT annotation_pk PRIMARY KEY (id)

);
-- ddl-end --
ALTER TABLE public.annotation OWNER TO postgres;
-- ddl-end --

-- object: ja3_fk | type: CONSTRAINT --
-- ALTER TABLE public.annotation DROP CONSTRAINT IF EXISTS ja3_fk CASCADE;
ALTER TABLE public.annotation ADD CONSTRAINT ja3_fk FOREIGN KEY (hash_ja3)
REFERENCES public.ja3 (hash) MATCH FULL
ON DELETE SET NULL ON UPDATE CASCADE;
-- ddl-end --

-- object: software_fk | type: CONSTRAINT --
-- ALTER TABLE public.annotation DROP CONSTRAINT IF EXISTS software_fk CASCADE;
ALTER TABLE public.annotation ADD CONSTRAINT software_fk FOREIGN KEY (id_software)
REFERENCES public.software (id) MATCH FULL
ON DELETE SET NULL ON UPDATE CASCADE;
-- ddl-end --

-- object: ja3_trie | type: INDEX --
-- DROP INDEX IF EXISTS public.ja3_trie CASCADE;
CREATE INDEX  CONCURRENTLY ja3_trie ON public.ja3
	USING spgist
	(
	  raw
	);
-- ddl-end --

-- object: hash_index | type: INDEX --
-- DROP INDEX IF EXISTS public.hash_index CASCADE;
CREATE INDEX hash_index ON public.certificate
	USING btree
	(
	  hash
	);
-- ddl-end --

-- object: pk_index | type: INDEX --
-- DROP INDEX IF EXISTS public.pk_index CASCADE;
CREATE INDEX pk_index ON public.public_key
	USING btree
	(
	  hash
	);
-- ddl-end --

-- object: dst_index | type: INDEX --
-- DROP INDEX IF EXISTS public.dst_index CASCADE;
CREATE INDEX dst_index ON public."sessionRecord"
	USING btree
	(
	  dst_ip
	);
-- ddl-end --

-- object: path_index | type: INDEX --
-- DROP INDEX IF EXISTS public.path_index CASCADE;
CREATE INDEX path_index ON public.certificate
	USING gist
	(
	  cert_chain
	)
	WITH (BUFFERING = ON);
-- ddl-end --

-- object: ja3_fk | type: CONSTRAINT --
-- ALTER TABLE public.fuzzy_hash DROP CONSTRAINT IF EXISTS ja3_fk CASCADE;
ALTER TABLE public.fuzzy_hash ADD CONSTRAINT ja3_fk FOREIGN KEY (hash_ja3)
REFERENCES public.ja3 (hash) MATCH FULL
ON DELETE SET NULL ON UPDATE CASCADE;
-- ddl-end --


