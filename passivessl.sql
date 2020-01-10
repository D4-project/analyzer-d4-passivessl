-- Database generated with pgModeler (PostgreSQL Database Modeler).
-- pgModeler  version: 0.9.1
-- PostgreSQL version: 10.0
-- Project Site: pgmodeler.io
-- Model Author: ---

SET check_function_bodies = false;
-- ddl-end --

-- Database creation must be done outside a multicommand file.
-- These commands were put in this file only as a convenience.
-- -- object: passive_ssl | type: DATABASE --
-- -- DROP DATABASE IF EXISTS passive_ssl;
-- CREATE DATABASE passive_ssl
-- 	ENCODING = 'UTF8'
-- 	LC_COLLATE = 'en_US.UTF-8'
-- 	LC_CTYPE = 'en_US.UTF-8'
-- 	TABLESPACE = pg_default
-- 	OWNER = postgres;
-- -- ddl-end --
-- 

-- object: ltree | type: EXTENSION --
-- DROP EXTENSION IF EXISTS ltree CASCADE;
CREATE EXTENSION ltree
      WITH SCHEMA public
      VERSION '1.1';
-- ddl-end --
COMMENT ON EXTENSION ltree IS 'data type for hierarchical tree-like structures';
-- ddl-end --

-- object: hstore | type: EXTENSION --
-- DROP EXTENSION IF EXISTS hstore CASCADE;
CREATE EXTENSION hstore
      WITH SCHEMA public
      VERSION '1.4';
-- ddl-end --
COMMENT ON EXTENSION hstore IS 'data type for storing sets of (key, value) pairs';
-- ddl-end --

-- object: public.public_key | type: TABLE --
-- DROP TABLE IF EXISTS public.public_key CASCADE;
CREATE TABLE public.public_key(
	hash bytea NOT NULL,
	type text NOT NULL,
	modulus text,
	exponent integer,
	modulus_size integer,
	"P" numeric,
	"Q" numeric,
	"G" numeric,
	"Y" numeric,
	"X" numeric,
	"N" numeric,
	"B" numeric,
	bitsize integer,
	curve_name character varying(256),
	"Gx" numeric,
	"Gy" numeric,
	private bytea,
	CONSTRAINT public_key_pk PRIMARY KEY (hash)

);
-- ddl-end --
ALTER TABLE public.public_key OWNER TO postgres;
-- ddl-end --

-- object: public.certificate | type: TABLE --
-- DROP TABLE IF EXISTS public.certificate CASCADE;
CREATE TABLE public.certificate(
	mounted_path character varying(4096) NOT NULL,
	issuer text,
	cert_chain ltree,
	subject text,
	hash bytea NOT NULL,
	"is_CA" boolean NOT NULL DEFAULT false,
	is_valid_chain boolean NOT NULL DEFAULT false,
	"notBefore" time,
	"notAfter" time,
	"is_SS" boolean NOT NULL DEFAULT false,
	"Signature" bytea,
	"SignatureAlgorithm" text,
	"Version" integer,
	"DNSnames" text[],
	emails text[],
	"IPaddresses" inet[],
	"URIs" text[],
	"PermittedDNS" text[],
	"ExcludedDNS" text[],
	"PermittedIPRanges" cidr[],
	"ExcludedIPRanges" cidr[],
	"PermittedEmailAddresses" text[],
	"ExcludedEmailAddresses" text[],
	"PermittedURIDomains" text[],
	"ExcludedURIDomains" text[],
	fs_type smallint DEFAULT 0,
	atrest_path character varying(4096) NOT NULL,
	CONSTRAINT certificate_pk PRIMARY KEY (hash)

);
-- ddl-end --
COMMENT ON COLUMN public.certificate.mounted_path IS 'Where to access the file when mounted (check fs_type to know the state)';
-- ddl-end --
COMMENT ON COLUMN public.certificate.fs_type IS 'How to access the raw certificate:
0 - mount point
1 - tar.gz
2 - squashfs';
-- ddl-end --
COMMENT ON COLUMN public.certificate.atrest_path IS 'Where to access the file when unmounted (check fs_type to know how to mount)';
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
ALTER TABLE public.many_certificate_has_many_public_key OWNER TO postgres;
-- ddl-end --

-- object: public."sessionRecord_id_seq" | type: SEQUENCE --
-- DROP SEQUENCE IF EXISTS public."sessionRecord_id_seq" CASCADE;
CREATE SEQUENCE public."sessionRecord_id_seq"
	INCREMENT BY 1
	MINVALUE 1
	MAXVALUE 9223372036854775807
	START WITH 1
	CACHE 1
	NO CYCLE
	OWNED BY NONE;
-- ddl-end --
ALTER SEQUENCE public."sessionRecord_id_seq" OWNER TO postgres;
-- ddl-end --

-- object: public."sessionRecord" | type: TABLE --
-- DROP TABLE IF EXISTS public."sessionRecord" CASCADE;
CREATE TABLE public."sessionRecord"(
	id bigint NOT NULL DEFAULT nextval('public."sessionRecord_id_seq"'::regclass),
	dst_ip inet NOT NULL,
	src_ip inet NOT NULL,
	dst_port integer NOT NULL,
	src_port integer NOT NULL,
	hash_ja3 bytea NOT NULL,
	"timestamp" timestamp(0) with time zone,
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
	type character varying(16) NOT NULL,
	CONSTRAINT j3a_pk PRIMARY KEY (hash)

);
-- ddl-end --
ALTER TABLE public.ja3 OWNER TO postgres;
-- ddl-end --

-- object: public."many_sessionRecord_has_many_certificate" | type: TABLE --
-- DROP TABLE IF EXISTS public."many_sessionRecord_has_many_certificate" CASCADE;
CREATE TABLE public."many_sessionRecord_has_many_certificate"(
	"id_sessionRecord" bigint NOT NULL,
	hash_certificate bytea NOT NULL,
	CONSTRAINT "many_sessionRecord_has_many_certificate_pk" PRIMARY KEY ("id_sessionRecord",hash_certificate)

);
-- ddl-end --
ALTER TABLE public."many_sessionRecord_has_many_certificate" OWNER TO postgres;
-- ddl-end --

-- object: public.fuzzy_hash_id_seq | type: SEQUENCE --
-- DROP SEQUENCE IF EXISTS public.fuzzy_hash_id_seq CASCADE;
CREATE SEQUENCE public.fuzzy_hash_id_seq
	INCREMENT BY 1
	MINVALUE 1
	MAXVALUE 9223372036854775807
	START WITH 1
	CACHE 1
	NO CYCLE
	OWNED BY NONE;
-- ddl-end --
ALTER SEQUENCE public.fuzzy_hash_id_seq OWNER TO postgres;
-- ddl-end --

-- object: public.fuzzy_hash | type: TABLE --
-- DROP TABLE IF EXISTS public.fuzzy_hash CASCADE;
CREATE TABLE public.fuzzy_hash(
	id bigint NOT NULL DEFAULT nextval('public.fuzzy_hash_id_seq'::regclass),
	type text NOT NULL,
	value text NOT NULL,
	"id_sessionRecord" bigint,
	CONSTRAINT fuzzy_hash_pk PRIMARY KEY (id)

);
-- ddl-end --
ALTER TABLE public.fuzzy_hash OWNER TO postgres;
-- ddl-end --

-- object: public.software_id_seq | type: SEQUENCE --
-- DROP SEQUENCE IF EXISTS public.software_id_seq CASCADE;
CREATE SEQUENCE public.software_id_seq
	INCREMENT BY 1
	MINVALUE 1
	MAXVALUE 2147483647
	START WITH 1
	CACHE 1
	NO CYCLE
	OWNED BY NONE;
-- ddl-end --
ALTER SEQUENCE public.software_id_seq OWNER TO postgres;
-- ddl-end --

-- object: public.software | type: TABLE --
-- DROP TABLE IF EXISTS public.software CASCADE;
CREATE TABLE public.software(
	id integer NOT NULL DEFAULT nextval('public.software_id_seq'::regclass),
	name text NOT NULL,
	version text,
	CONSTRAINT software_pk PRIMARY KEY (id)

);
-- ddl-end --
ALTER TABLE public.software OWNER TO postgres;
-- ddl-end --

-- object: public.annotation_id_seq | type: SEQUENCE --
-- DROP SEQUENCE IF EXISTS public.annotation_id_seq CASCADE;
CREATE SEQUENCE public.annotation_id_seq
	INCREMENT BY 1
	MINVALUE 1
	MAXVALUE 2147483647
	START WITH 1
	CACHE 1
	NO CYCLE
	OWNED BY NONE;
-- ddl-end --
ALTER SEQUENCE public.annotation_id_seq OWNER TO postgres;
-- ddl-end --

-- object: public.annotation | type: TABLE --
-- DROP TABLE IF EXISTS public.annotation CASCADE;
CREATE TABLE public.annotation(
	id integer NOT NULL DEFAULT nextval('public.annotation_id_seq'::regclass),
	hash_ja3 bytea,
	confidence smallint,
	id_software integer,
	CONSTRAINT annotation_pk PRIMARY KEY (id)

);
-- ddl-end --
ALTER TABLE public.annotation OWNER TO postgres;
-- ddl-end --

-- object: ja3_trie | type: INDEX --
-- DROP INDEX IF EXISTS public.ja3_trie CASCADE;
CREATE INDEX ja3_trie ON public.ja3
	USING spgist
	(
	  raw
	)
	WITH (FILLFACTOR = 90);
-- ddl-end --

-- object: hash_index | type: INDEX --
-- DROP INDEX IF EXISTS public.hash_index CASCADE;
CREATE INDEX hash_index ON public.certificate
	USING btree
	(
	  hash
	)
	WITH (FILLFACTOR = 90);
-- ddl-end --

-- object: pk_index | type: INDEX --
-- DROP INDEX IF EXISTS public.pk_index CASCADE;
CREATE INDEX pk_index ON public.public_key
	USING btree
	(
	  hash
	)
	WITH (FILLFACTOR = 90);
-- ddl-end --

-- object: dst_index | type: INDEX --
-- DROP INDEX IF EXISTS public.dst_index CASCADE;
CREATE INDEX dst_index ON public."sessionRecord"
	USING btree
	(
	  dst_ip
	)
	WITH (FILLFACTOR = 90);
-- ddl-end --

-- object: path_index | type: INDEX --
-- DROP INDEX IF EXISTS public.path_index CASCADE;
CREATE INDEX path_index ON public.certificate
	USING gist
	(
	  cert_chain
	)
	WITH (FILLFACTOR = 90);
-- ddl-end --

-- object: pg_catalog.plpython3_validator | type: FUNCTION --
-- DROP FUNCTION IF EXISTS pg_catalog.plpython3_validator(oid) CASCADE;
CREATE FUNCTION pg_catalog.plpython3_validator ( _param1 oid)
	RETURNS void
	LANGUAGE c
	VOLATILE 
	STRICT
	SECURITY INVOKER
	COST 1
	AS '$libdir/plpython3', 'plpython3_validator';
-- ddl-end --
ALTER FUNCTION pg_catalog.plpython3_validator(oid) OWNER TO postgres;
-- ddl-end --

-- object: pg_catalog.plpython3_call_handler | type: FUNCTION --
-- DROP FUNCTION IF EXISTS pg_catalog.plpython3_call_handler() CASCADE;
CREATE FUNCTION pg_catalog.plpython3_call_handler ()
	RETURNS language_handler
	LANGUAGE c
	VOLATILE 
	CALLED ON NULL INPUT
	SECURITY INVOKER
	COST 1
	AS '$libdir/plpython3', 'plpython3_call_handler';
-- ddl-end --
ALTER FUNCTION pg_catalog.plpython3_call_handler() OWNER TO postgres;
-- ddl-end --

-- object: pg_catalog.plpython3_inline_handler | type: FUNCTION --
-- DROP FUNCTION IF EXISTS pg_catalog.plpython3_inline_handler(internal) CASCADE;
CREATE FUNCTION pg_catalog.plpython3_inline_handler ( _param1 internal)
	RETURNS void
	LANGUAGE c
	VOLATILE 
	STRICT
	SECURITY INVOKER
	COST 1
	AS '$libdir/plpython3', 'plpython3_inline_handler';
-- ddl-end --
ALTER FUNCTION pg_catalog.plpython3_inline_handler(internal) OWNER TO postgres;
-- ddl-end --

-- object: plpython3u | type: LANGUAGE --
-- DROP LANGUAGE IF EXISTS plpython3u CASCADE;
CREATE  LANGUAGE plpython3u
	HANDLER pg_catalog.plpython3_call_handler
	VALIDATOR pg_catalog.plpython3_validator
	INLINE pg_catalog.plpython3_inline_handler;
-- ddl-end --
ALTER LANGUAGE plpython3u OWNER TO postgres;
-- ddl-end --

-- object: public.tlshc | type: FUNCTION --
-- DROP FUNCTION IF EXISTS public.tlshc(text,text) CASCADE;
CREATE FUNCTION public.tlshc ( a text,  b text)
	RETURNS integer
	LANGUAGE plpython3u
	VOLATILE 
	CALLED ON NULL INPUT
	SECURITY INVOKER
	COST 1
	AS $$

import tlsh
return tlsh.diff(a, b)

$$;
-- ddl-end --
ALTER FUNCTION public.tlshc(text,text) OWNER TO postgres;
-- ddl-end --

-- object: public.tlsht | type: FUNCTION --
-- DROP FUNCTION IF EXISTS public.tlsht(text,text,integer,integer) CASCADE;
CREATE FUNCTION public.tlsht ( filter text,  hash text,  threshold integer,  maxrows integer)
	RETURNS SETOF public.fuzzy_hash
	LANGUAGE plpython3u
	IMMUTABLE LEAKPROOF
	STRICT
	SECURITY INVOKER
	COST 1
	ROWS 1000
	AS $$

import tlsh
plan = plpy.prepare("SELECT * FROM fuzzy_hash WHERE type <> $1", ["text"])
rv = plan.execute(["filter"], maxrows)
r = []
for x in rv:
    if tlsh.diff(x["value"], hash) < threshold:
        r.append(x)
return r

$$;
-- ddl-end --
ALTER FUNCTION public.tlsht(text,text,integer,integer) OWNER TO postgres;
-- ddl-end --

-- object: pg_catalog.plpython3_validator_cp | type: FUNCTION --
-- DROP FUNCTION IF EXISTS pg_catalog.plpython3_validator_cp(oid) CASCADE;
CREATE FUNCTION pg_catalog.plpython3_validator_cp ( _param1 oid)
	RETURNS void
	LANGUAGE c
	VOLATILE 
	STRICT
	SECURITY INVOKER
	COST 1
	AS '$libdir/plpython3', 'plpython3_validator';
-- ddl-end --
ALTER FUNCTION pg_catalog.plpython3_validator_cp(oid) OWNER TO postgres;
-- ddl-end --

-- object: pg_catalog.plpython3_call_handler_cp | type: FUNCTION --
-- DROP FUNCTION IF EXISTS pg_catalog.plpython3_call_handler_cp() CASCADE;
CREATE FUNCTION pg_catalog.plpython3_call_handler_cp ()
	RETURNS language_handler
	LANGUAGE c
	VOLATILE 
	CALLED ON NULL INPUT
	SECURITY INVOKER
	COST 1
	AS '$libdir/plpython3', 'plpython3_call_handler';
-- ddl-end --
ALTER FUNCTION pg_catalog.plpython3_call_handler_cp() OWNER TO postgres;
-- ddl-end --

-- object: pg_catalog.plpython3_inline_handler_cp | type: FUNCTION --
-- DROP FUNCTION IF EXISTS pg_catalog.plpython3_inline_handler_cp(internal) CASCADE;
CREATE FUNCTION pg_catalog.plpython3_inline_handler_cp ( _param1 internal)
	RETURNS void
	LANGUAGE c
	VOLATILE 
	STRICT
	SECURITY INVOKER
	COST 1
	AS '$libdir/plpython3', 'plpython3_inline_handler';
-- ddl-end --
ALTER FUNCTION pg_catalog.plpython3_inline_handler_cp(internal) OWNER TO postgres;
-- ddl-end --

-- object: plpython3u_cp | type: LANGUAGE --
-- DROP LANGUAGE IF EXISTS plpython3u_cp CASCADE;
CREATE  LANGUAGE plpython3u_cp
	HANDLER pg_catalog.plpython3_call_handler
	VALIDATOR pg_catalog.plpython3_validator
	INLINE pg_catalog.plpython3_inline_handler;
-- ddl-end --
ALTER LANGUAGE plpython3u_cp OWNER TO postgres;
-- ddl-end --

-- object: public.zgrep | type: FUNCTION --
-- DROP FUNCTION IF EXISTS public.zgrep(text,text) CASCADE;
CREATE FUNCTION public.zgrep ( a text,  b text)
	RETURNS integer
	LANGUAGE plpython3u_cp
	VOLATILE 
	CALLED ON NULL INPUT
	SECURITY INVOKER
	COST 1
	AS $$

import tlsh
return tlsh.diff(a, b)

$$;
-- ddl-end --
ALTER FUNCTION public.zgrep(text,text) OWNER TO postgres;
-- ddl-end --

-- object: p_index | type: INDEX --
-- DROP INDEX IF EXISTS public.p_index CASCADE;
CREATE INDEX  CONCURRENTLY p_index ON public.public_key
	USING btree
	(
	  "P"
	);
-- ddl-end --

-- object: certificate_fk | type: CONSTRAINT --
-- ALTER TABLE public.many_certificate_has_many_public_key DROP CONSTRAINT IF EXISTS certificate_fk CASCADE;
ALTER TABLE public.many_certificate_has_many_public_key ADD CONSTRAINT certificate_fk FOREIGN KEY (hash_certificate)
REFERENCES public.certificate (hash) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: public_key_fk | type: CONSTRAINT --
-- ALTER TABLE public.many_certificate_has_many_public_key DROP CONSTRAINT IF EXISTS public_key_fk CASCADE;
ALTER TABLE public.many_certificate_has_many_public_key ADD CONSTRAINT public_key_fk FOREIGN KEY (hash_public_key)
REFERENCES public.public_key (hash) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: ja3_fk | type: CONSTRAINT --
-- ALTER TABLE public."sessionRecord" DROP CONSTRAINT IF EXISTS ja3_fk CASCADE;
ALTER TABLE public."sessionRecord" ADD CONSTRAINT ja3_fk FOREIGN KEY (hash_ja3)
REFERENCES public.ja3 (hash) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: "sessionRecord_fk" | type: CONSTRAINT --
-- ALTER TABLE public."many_sessionRecord_has_many_certificate" DROP CONSTRAINT IF EXISTS "sessionRecord_fk" CASCADE;
ALTER TABLE public."many_sessionRecord_has_many_certificate" ADD CONSTRAINT "sessionRecord_fk" FOREIGN KEY ("id_sessionRecord")
REFERENCES public."sessionRecord" (id) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: certificate_fk | type: CONSTRAINT --
-- ALTER TABLE public."many_sessionRecord_has_many_certificate" DROP CONSTRAINT IF EXISTS certificate_fk CASCADE;
ALTER TABLE public."many_sessionRecord_has_many_certificate" ADD CONSTRAINT certificate_fk FOREIGN KEY (hash_certificate)
REFERENCES public.certificate (hash) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: "sessionRecord_fk" | type: CONSTRAINT --
-- ALTER TABLE public.fuzzy_hash DROP CONSTRAINT IF EXISTS "sessionRecord_fk" CASCADE;
ALTER TABLE public.fuzzy_hash ADD CONSTRAINT "sessionRecord_fk" FOREIGN KEY ("id_sessionRecord")
REFERENCES public."sessionRecord" (id) MATCH FULL
ON DELETE SET NULL ON UPDATE CASCADE;
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


