package main

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/gomodule/redigo/redis"
	_ "github.com/lib/pq"
)

type certMapElm struct {
	CertHash string
	chain    chain
	*x509.Certificate
}

type sessionRecord struct {
	ServerIP     string
	ServerPort   string
	ClientIP     string
	ClientPort   string
	TLSH         string
	Timestamp    time.Time
	JA3          string
	JA3Digest    string
	JA3S         string
	JA3SDigest   string
	Certificates []certMapElm
}

type chain struct {
	isValid bool
	s       string
}

var db *sql.DB
var cr redis.Conn

var connectRedis = false
var connectDB = true

func main() {
	if connectDB {
		initDB()
		defer db.Close()
	}

	var jsonPath string

	if connectRedis {
		initRedis()
		//defer cr.Close()
		// pop redis queue
		for {
			err := errors.New("")
			jsonPath, err = redis.String(cr.Do("LPOP", "analyzer:ja3-jl:0894517855f047d2a77b4473d3a9cc5b"))
			if err != nil {
				log.Fatal("Queue processed")
			}
		}

	} else {
		jsonPath = "./test.json"

		// read corresponding json file
		dat, err := ioutil.ReadFile(jsonPath)
		if err != nil {
			log.Fatal(err)
		}
		// Unmarshal JSON file
		s := sessionRecord{}
		_ = json.Unmarshal([]byte(dat), &s)

		// Insert Session
		ids, err := insertSession(&s)
		if err != nil {
			log.Fatal(fmt.Sprintf("Insert Sessions into DB failed: %q", err))
		}
		// Attempt to roughly build a chain of trust
		session := buildChain(&s)

		// Insert Certificates
		idc, err := insertCertificates(session)
		if err != nil {
			log.Fatal(fmt.Sprintf("Insert Certificate into DB failed: %q", err))
		}
		// Launch go routine to create the relationship between certificates and sessions
		err = linkSessionCert(ids, idc)
		if err != nil {
			log.Fatal(fmt.Sprintf("Could not link Certs and Session into DB failed: %q", err))
		}
		// Launch go routine to create public keys
	}
}

// linkSessionCert creates the link between a session and its certificates
func linkSessionCert(ids int64, idc []string) error {
	for _, i := range idc {
		q := `INSERT INTO "many_sessionRecord_has_many_certificate" ("id_sessionRecord", "hash_certificate") VALUES ($1, $2)`
		_, err := db.Query(q, ids, i)
		if err != nil {
			return err
		}
	}
	return nil
}

// buildChain attempts to rearrange certificate as a chain of trust from a sessionRecord (that
// contains a slice of certificate). If the chain of trust is build successfully
// it marked as valid, If not root is found or if the chain is broken, it
// does not touch the original slice and mark the chain as invalid.
func buildChain(s *sessionRecord) (*sessionRecord) {
	certChain := make([]certMapElm, 0)

	// First we find the leaf
	for _, c := range s.Certificates {
		fmt.Println(c.Certificate.Issuer.String())
		fmt.Println(c.Certificate.Subject.String())
		fmt.Println(c.Certificate.Subject.String() == c.Certificate.Issuer.String())
		if !c.Certificate.IsCA {
			certChain = append(certChain, c)
		}
	}
	// Find the parent of each certificate
	for _, _ = range s.Certificates {
		for i, _ := range s.Certificates {
			if s.Certificates[i].Certificate.Subject.String() == certChain[len(certChain)-1].Issuer.String() {
				certChain = append(certChain, s.Certificates[i])
			}
		}
	}
	// Write the new chain
	if len(certChain) == len(s.Certificates) {
		cstr := make([]string, 0)
		for i := len(certChain) - 1; i >= 0; i-- {
			certChain[i].chain.isValid = true
			cstr = append(cstr, certChain[i].CertHash)
			certChain[i].chain.s = strings.Join(cstr, ".")
		}
		tmp := s
		tmp.Certificates = certChain
		return tmp
	}
	return s
}

func insertCertificate(c certMapElm) (string, error) {
	q := `INSERT INTO "certificate" (hash, "is_CA", issuer, subject, cert_chain, is_valid_chain, file_path) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING hash`
	var hash string
	err := db.QueryRow(q, c.CertHash, c.Certificate.IsCA, c.Certificate.Issuer.String(), c.Certificate.Subject.String(), c.chain.s, c.chain.isValid, getFullPath(c.CertHash)).Scan(&hash)
	if err != nil {
		return "", err
	}
	return hash, nil
}

// getFullPath takes a certificate's hash and return the full path to
// its location on disk
func getFullPath(h string) (string) {
	return "TODO PATH"
}

func insertCertificates(s *sessionRecord) ([]string, error) {
	var inserted []string
	for _, certificate := range s.Certificates {
		idc, err := insertCertificate(certificate)
		if err != nil {
			return inserted, err
		}
		inserted = append(inserted, idc)
	}
	return inserted, nil
}

func insertSession(s *sessionRecord) (int64, error) {
	q := `INSERT INTO "sessionRecord" (dst_ip, src_ip, dst_port, src_port, timestamp) VALUES ($1, $2, $3, $4, $5) RETURNING id`
	var id int64
	err := db.QueryRow(q, s.ServerIP, s.ClientIP, s.ServerPort, s.ClientPort, s.Timestamp).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func initRedis() {
	err := errors.New("")
	cr, err = redis.Dial("tcp", ":6380", redis.DialDatabase(2))
	if err != nil {
		panic(err)
	}
}

func initDB() {
	connStr := "user=postgres password=postgres dbname=new_database"
	err := errors.New("")
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
}

// String returns a string that describes a TLSSession
func (t *sessionRecord) String() string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("---------------SESSION START-------------------\n"))
	buf.WriteString(fmt.Sprintf("Time: %v\n", t.Timestamp))
	buf.WriteString(fmt.Sprintf("Client: %v:%v\n", t.ClientIP, t.ClientPort))
	buf.WriteString(fmt.Sprintf("Server: %v:%v\n", t.ServerIP, t.ServerPort))
	buf.WriteString(fmt.Sprintf("TLSH: %q\n", t.TLSH))
	buf.WriteString(fmt.Sprintf("ja3: %q\n", t.JA3))
	buf.WriteString(fmt.Sprintf("ja3 Digest: %q\n", t.JA3Digest))
	buf.WriteString(fmt.Sprintf("ja3s: %q\n", t.JA3S))
	buf.WriteString(fmt.Sprintf("ja3s Digest: %q\n", t.JA3SDigest))
	for _, certMe := range t.Certificates {
		buf.WriteString(fmt.Sprintf("Certificate Issuer: %q\n", certMe.Certificate.Issuer))
		buf.WriteString(fmt.Sprintf("Certificate Subject: %q\n", certMe.Certificate.Subject))
		buf.WriteString(fmt.Sprintf("Certificate is CA: %t\n", certMe.Certificate.IsCA))
		buf.WriteString(fmt.Sprintf("Certificate SHA256: %q\n", certMe.CertHash))
	}
	buf.WriteString(fmt.Sprintf("---------------SESSION  END--------------------\n"))
	return buf.String()
}
