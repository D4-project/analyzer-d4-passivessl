package main

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/lib/pq"
	"io/ioutil"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/gomodule/redigo/redis"
)

type BigNumber big.Int

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
	isSS    bool
	s       string
}

var db *sql.DB
//var db *sqlx.DB
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
		var path []string
		path = append(path, "./sessions")
		path = append(path, "")
		files, err := ioutil.ReadDir(path[0])
		if err != nil {
			log.Fatal(err)
		}

		for _, f := range files {

			path[1] = f.Name()
			jsonPath = strings.Join(path, "/")

			// read corresponding json file
			dat, err := ioutil.ReadFile(jsonPath)
			if err != nil {
				log.Fatal(err)
			}
			// Unmarshal JSON file
			s := sessionRecord{}
			_ = json.Unmarshal([]byte(dat), &s)

			if len(s.Certificates) > 0 {
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
				// Create the relationship between certificates and sessions
				err = linkSessionCerts(ids, idc)
				if err != nil {
					log.Fatal(fmt.Sprintf("Could not link Certs and Session into DB: %q", err))
				}

				// Create ja3* records
				err = insertJA3(session)
				if err != nil {
					log.Fatal(fmt.Sprintf("Could not insert JA3 into DB: %q", err))
				}
			}
		}
	}
}

func insertJA3(s *sessionRecord) error {
	q := `INSERT INTO "ja3" (hash, raw, type) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`
	_, err := db.Exec(q, s.JA3Digest, s.JA3, "ja3")
	if err != nil {
		return err
	}
	q = `INSERT INTO "ja3" (hash, raw, type) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`
	_, err = db.Exec(q, s.JA3SDigest, s.JA3S, "ja3s")
	if err != nil {
		return err
	}
	return nil
}

// insertPublicKeys insert each public key of each certificate of a session
func insertPublicKey(c x509.Certificate) (string, error) {
	pub, err := x509.ParsePKIXPublicKey(c.RawSubjectPublicKeyInfo)
	hash := fmt.Sprintf("%x", sha256.Sum256(c.RawSubjectPublicKeyInfo))
	if err != nil {
		return hash, nil
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		q := `INSERT INTO "public_key" (hash, type, modulus, exponent, modulus_size) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`
		_, err := db.Exec(q, hash, "RSA", (*BigNumber)(pub.N), pub.E, pub.Size())
		if err != nil {
			return hash, err
		}
	case *dsa.PublicKey:
		q := `INSERT INTO "public_key" (hash, type, "G", "P", "Q", "Y") VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`
		_, err := db.Exec(q, hash, "DSA", (*BigNumber)(pub.Parameters.G), (*BigNumber)(pub.Parameters.P), (*BigNumber)(pub.Parameters.Q), (*BigNumber)(pub.Y))
		if err != nil {
			return hash, err
		}
	case *ecdsa.PublicKey:
		q := `INSERT INTO "public_key" (hash, type, "Y", "X", "P", "N", "B", "bitsize", "Gx", "Gy", "curve_name") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING`
		_, err := db.Exec(q, hash, "ECDSA", (*BigNumber)(pub.Y), (*BigNumber)(pub.X), (*BigNumber)(pub.Curve.Params().P), (*BigNumber)(pub.Curve.Params().N), (*BigNumber)(pub.Curve.Params().B), pub.Curve.Params().BitSize, (*BigNumber)(pub.Curve.Params().Gx), (*BigNumber)(pub.Curve.Params().Gy), pub.Params().Name)
		if err != nil {
			return hash, err
		}
	default:
		return hash, fmt.Errorf("PKIx: could not determine the type of key %g", pub)
	}
	return hash, nil
}

func (bn *BigNumber) Value() (driver.Value, error) {
	return driver.Value((*big.Int)(bn).Text(10)), nil
}

// linkSessionCerts creates the link between a session and its certificates
func linkSessionCerts(ids int64, idc []string) error {
	for _, i := range idc {
		q := `INSERT INTO "many_sessionRecord_has_many_certificate" ("id_sessionRecord", "hash_certificate") VALUES ($1, $2) ON CONFLICT DO NOTHING `
		_, err := db.Exec(q, ids, i)
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
func buildChain(s *sessionRecord) *sessionRecord {
	certChain := make([]certMapElm, 0)
	// First find if there are any duplicates certificate
	dedup := unique(s.Certificates)
	deduplen := len(dedup)

	if deduplen > 1 {
		// Then we find the leaf
		removed := 0
		for i, c := range dedup {
			if !c.Certificate.IsCA {
				certChain = append(certChain, c)
				// Remove this element from the list
				dedup = append(dedup[:i-removed], dedup[i+1-removed:]...)
				removed++
			}
		}

		cursor := len(certChain)
		// Find the parent of each certificate
		for i := 0; i < cursor; i++ {
			p, success, isSS := findParent(dedup, certChain[i])
			// if we found a root, no need to go any further
			if isSS {
				p.chain.isSS = true
				certChain = append(certChain, p)
				break
			}
			if success {
				p.chain.isSS = false
				certChain = append(certChain, p)
			}
			cursor = len(certChain)
		}

		// Write the new chain if it's valid
		if len(certChain) >= deduplen-1 {
			cstr := make([]string, 0)
			for i := len(certChain) - 1; i >= 0; i-- {
				certChain[i].chain.isValid = true
				if !certChain[i].chain.isSS {
					cstr = append(cstr, certChain[i].CertHash)
					certChain[i].chain.s = strings.Join(cstr, ".")
				}
			}
			tmp := s
			tmp.Certificates = certChain
			return tmp
		}
		// Only one cert in the chain
	} else {
		s.Certificates[0].chain = chain{true, s.Certificates[0].Certificate.Issuer.String() == s.Certificates[0].Certificate.Subject.String(), s.Certificates[0].CertHash}
	}

	return s
}

func findParent(dedup []certMapElm, c certMapElm) (certMapElm, bool, bool) {
	// A Root or SSC signs itself
	if c.Certificate.Subject.String() == c.Certificate.Issuer.String() {
		return c, true, true
	}

	// A leaf or a node has a parent
	for _, candidate := range dedup {
		if candidate.Certificate.Subject.String() == c.Certificate.Issuer.String() {
			return candidate, true, false
		}
	}

	return c, false, false
}

func unique(s []certMapElm) []certMapElm {
	keys := make(map[string]bool)
	var list []certMapElm
	for _, entry := range s {
		if _, value := keys[entry.CertHash]; !value {
			keys[entry.CertHash] = true
			list = append(list, entry)
		}
	}
	return list
}

func insertCertificate(c certMapElm) (string, error) {
	q := `INSERT INTO "certificate" (hash, "is_CA", "is_SS", issuer, subject, cert_chain, is_valid_chain, file_path) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`
	_, err := db.Exec(q, c.CertHash, c.Certificate.IsCA, c.chain.isSS, c.Certificate.Issuer.String(), c.Certificate.Subject.String(), c.chain.s, c.chain.isValid, getFullPath(c.CertHash))
	if err != nil {
		return c.CertHash, err
	}
	key, err := insertPublicKey(*c.Certificate)
	if err != nil {
		return c.CertHash, err
	}
	fmt.Println(c.CertHash)
	fmt.Println(key)
	q = `INSERT INTO "many_certificate_has_many_public_key" ("hash_certificate", "hash_public_key") VALUES ($1, $2) ON CONFLICT DO NOTHING `
	_, err = db.Exec(q, c.CertHash, key)
	if err != nil {
		return c.CertHash, err
	}
	return c.CertHash, nil
}

// getFullPath takes a certificate's hash and return the full path to
// its location on disk
func getFullPath(h string) string {
	return "TODO PATH"
}

func insertCertificates(s *sessionRecord) ([]string, error) {
	var inserted []string
	for _, certificate := range s.Certificates {
		tmp, err := insertCertificate(certificate)
		inserted = append(inserted, tmp)
		if err != nil {
			return inserted, err
		}
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
		log.Fatalln(err)
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
