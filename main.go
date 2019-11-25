package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gallypette/certificate-transparency-go/x509"

	"github.com/gomodule/redigo/redis"
	_ "github.com/lib/pq"
)

type (
	conf struct {
		redisHost    string
		redisPort    string
		redisDB      int
		redisQueue   string
		postgresUser string
		postgresPWD  string
		postgresHost string
		postgresPort string
		postgresDB   string
		certPath     string
		format       string
		recursive    bool
		tarball      bool
	}

	bigNumber big.Int

	certMapElm struct {
		CertHash string
		chain    chain
		*x509.Certificate
	}

	sessionRecord struct {
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

	chain struct {
		isValid bool
		isSS    bool
		s       string
	}
)

var (
	db        *sql.DB
	confdir   = flag.String("c", "conf.sample", "configuration directory")
	recursive = flag.Bool("r", false, "should it open the directory recursively")
	tarball   = flag.Bool("t", false, "is it a tar archive")
	format    = flag.String("f", "json", "certificate file format [json, crt, der]")
	pull      = flag.Bool("p", true, "pull from redis?")
	cr        redis.Conn
)

func main() {
	// Control Chan
	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt, os.Kill)

	// Usage and flags
	flag.Usage = func() {
		fmt.Printf("analyzer-d4-passivessl - Passive SSL analyzer:\n\n")
		fmt.Printf(" Fetch data from sensor-d4-tls-fingerprinting and push it into d4-passivessl-server\n")
		fmt.Printf("\n")
		fmt.Printf("Usage:\n\n analyzer-d4-passivessl -c  config_directory\n")
		fmt.Printf("\n")
		fmt.Printf("Configuration:\n\n")
		fmt.Printf(" The configuration settings are stored in files in the configuration directory\n")
		fmt.Printf(" specified with the -c command line switch.\n\n")
		fmt.Printf("Files in the configuration directory:\n")
		fmt.Printf("\n")
		fmt.Printf(" redis - empty if not used.\n")
		fmt.Printf("       | host:port/db\n")
		fmt.Printf(" redis_queue - type and uuid of the redis queue\n")
		fmt.Printf("          | type:uuid \n")
		fmt.Printf(" postgres - postgres database\n")
		fmt.Printf("          | user:password@host:port/db\n")
		fmt.Printf(" certfolder - absolute path to the folder containing certificates\n")
		fmt.Printf("          | /.... \n")
		fmt.Printf("\n")
		flag.PrintDefaults()
	}

	// Config
	c := conf{}
	flag.Parse()
	if flag.NFlag() == 0 || *confdir == "" {
		flag.Usage()
		os.Exit(1)
	} else {
		*confdir = strings.TrimSuffix(*confdir, "/")
		*confdir = strings.TrimSuffix(*confdir, "\\")
	}

	// Parse DB Config
	tmp := readConfFile(*confdir, "postgres")
	ss := strings.Split(string(tmp), "/")
	if len(ss) <= 1 {
		log.Fatal("Missing Database in Postgres config: should be user:pwd@host:port/database_name")
	}
	c.postgresDB = ss[1]
	sssat := strings.Split(ss[0], "@")
	if len(ss) <= 1 {
		log.Fatal("Malformed postgres config: should be user:pwd@host:port/database_name")
	}
	sssu := strings.Split(sssat[0], ":")
	if len(ss) <= 1 {
		log.Fatal("Malformed postgres config: should be user:pwd@host:port/database_name")
	}
	c.postgresUser = sssu[0]
	c.postgresPWD = sssu[1]
	ret, ssh := isNet(sssat[1])
	if !ret {
		sssh := strings.Split(string(ssh), ":")
		c.postgresHost = sssh[0]
		c.postgresPort = sssh[1]
	}

	// Parse Certificate Folder
	if !*pull {
		c.certPath = string(readConfFile(*confdir, "certfolder"))
	}
	c.recursive = *recursive
	c.tarball = *tarball
	c.format = *format

	// DB
	initDB(c.postgresUser, c.postgresPWD, c.postgresHost, c.postgresPort, c.postgresDB)
	defer db.Close()

	var jsonPath string

	if *pull { // Redis
		// Parse Redis Config
		tmp := readConfFile(*confdir, "redis")
		ss := strings.Split(string(tmp), "/")
		if len(ss) <= 1 {
			log.Fatal("Missing Database in Redis config: should be host:port/database_name")
		}
		c.redisDB, _ = strconv.Atoi(ss[1])
		var ret bool
		ret, ss[0] = isNet(ss[0])
		if !ret {
			sss := strings.Split(string(ss[0]), ":")
			c.redisHost = sss[0]
			c.redisPort = sss[1]
		}
		c.redisQueue = string(readConfFile(*confdir, "redis_queue"))
		initRedis(c.redisHost, c.redisPort, c.redisDB)
		defer cr.Close()
		// pop redis queue
		for {
			err := errors.New("")
			jsonPath, err = redis.String(cr.Do("LPOP", "analyzer:ja3-jl:"+c.redisQueue))
			err = filepath.Walk(jsonPath,
				func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if !info.IsDir() {
						fd, err := os.Open(path)
						if err != nil {
							log.Fatal(err)
						}
						bf := bufio.NewReader(fd)
						fmt.Println(path)
						processFile(bf, path, c.format)
						// Exit Signal Handle
						select {
						case <-s:
							fmt.Println("Exiting...")
							os.Exit(0)
						default:
						}
					}
					return nil
				})
			if err != nil {
				log.Fatal(err)
			}
		}
	} else { // Files
		if c.recursive {
			err := filepath.Walk(c.certPath,
				func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if !info.IsDir() {
						fd, err := os.Open(path)
						if err != nil {
							log.Fatal(err)
						}
						bf := bufio.NewReader(fd)
						fmt.Println(path)
						processFile(bf, path, c.format)
					}
					return nil
				})
			if err != nil {
				log.Println(err)
			}
		} else if c.tarball {
			fd, err := os.Stat(c.certPath)
			if err != nil {
				log.Fatal(err)
			}
			switch mode := fd.Mode(); {
			case mode.IsDir():
				log.Fatal("With -t=true flag, you need to input a tarball")
			case mode.IsRegular():
				processTar(c.certPath, jsonPath, c.format)
				break
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
				fd, err := os.Open(jsonPath)
				if err != nil {
					log.Fatal(err)
				}
				bf := bufio.NewReader(fd)
				processFile(bf, jsonPath, c.format)

				// Exit Signal Handle
				select {
				case <-s:
					fmt.Println("Exiting...")
					os.Exit(0)
				}
			}
		}

	}
}

func processTar(fp string, p string, f string) error {
	fd, err := os.Open(fp)
	if err != nil {
		log.Fatal(err)
	}
	bf := bufio.NewReader(fd)
	gzr, err := gzip.NewReader(bf)
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		switch {
		// if no more files are found return
		case err == io.EOF:
			return nil
		// return any other error
		case err != nil:
			return err
		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			processFile(tr, fp, f)
		}
	}
}

func processFile(r io.Reader, fp string, f string) {
	switch f {
	case "json":
		processJSON(r, fp)
		break
	case "der":
		processDER(r, fp)
		break
	case "crt":
		processCRT(r, fp)
		break
	}
}

func processDER(r io.Reader, p string) bool {
	// read corresponding der file
	dat, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(dat)
	if err != nil {
		// Not stopping on Non Fatal Errors
		switch err := err.(type) {
		case x509.NonFatalErrors:
			// Stopping on Unknown PK Algo
			if cert.PublicKeyAlgorithm == 0 {
				fmt.Println("Unknown Public Key Algorithm, skipping key (most likely GOST R 14)")
				break
			}
			goto I
		default:
			fmt.Println("failed to parse certificate: " + err.Error())
			return false
		}
	}

I:
	// Cert elem
	h := sha1.New()
	h.Write(cert.Raw)
	c := certMapElm{Certificate: cert, CertHash: fmt.Sprintf("%x", h.Sum(nil))}
	// Insert Certificate
	err = insertLeafCertificate(p, c)
	if err != nil {
		// Not stopping on failed insertion
		log.Println(fmt.Sprintf("Insert Certificate into DB failed: %q", err))
	}

	return true
}

func insertLeafCertificate(fp string, c certMapElm) error {
	key, err := insertPublicKey(*c.Certificate)
	if err != nil {
		// Not stopping on Non Fatal Errors
		switch err := err.(type) {
		case x509.NonFatalErrors:
			goto J
		default:
			fmt.Println("failed to Insert Key: " + err.Error())
			return err
		}
	}
J:
	// q := `INSERT INTO "certificate" (hash, "is_CA", "is_SS", issuer, subject, cert_chain, is_valid_chain, file_path) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`
	q := `INSERT INTO "certificate" (hash, "is_CA", "is_SS", issuer, subject, cert_chain, is_valid_chain, file_path) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (hash) DO UPDATE SET file_path = excluded.file_path`
	_, err = db.Exec(q, c.CertHash, c.Certificate.IsCA, false, c.Certificate.Issuer.String(), c.Certificate.Subject.String(), nil, false, fp)
	fmt.Println(fp)
	if err != nil {
		return err
	}
	//fmt.Println(c.CertHash)
	//fmt.Println(key)
	q = `INSERT INTO "many_certificate_has_many_public_key" ("hash_certificate", "hash_public_key") VALUES ($1, $2) ON CONFLICT DO NOTHING `
	_, err = db.Exec(q, c.CertHash, key)
	if err != nil {
		fmt.Println(c.CertHash)
		return err
	}
	return nil
}

func processCRT(r io.Reader, fp string) bool {

	return true
}

func processJSON(r io.Reader, fp string) bool {
	// read corresponding json file
	dat, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	// Unmarshal JSON file
	s := sessionRecord{}
	_ = json.Unmarshal([]byte(dat), &s)

	if isValid(&s) {
		// Create ja3* records
		err = insertJA3(&s)
		if err != nil {
			log.Fatal(fmt.Sprintf("Could not insert JA3 into DB: %q", err))
		}
		// Insert Session
		ids, err := insertSession(&s)
		if err != nil {
			log.Fatal(fmt.Sprintf("Insert Sessions into DB failed: %q", err))
		}
		err = insertFuzzyHash(&s, ids)
		if err != nil {
			log.Fatal(fmt.Sprintf("Insert Fuzzy Hash into DB failed: %q", err))
		}
		// Attempt to roughly build a chain of trust
		session := buildChain(&s)

		// Insert Certificates
		idc, err := insertCertificates(fp, session)
		if err != nil {
			log.Fatal(fmt.Sprintf("Insert Certificate into DB failed: %q", err))
		}
		// Create the relationship between certificates and sessions
		err = linkSessionCerts(ids, idc)
		if err != nil {
			log.Fatal(fmt.Sprintf("Could not link Certs and Session into DB: %q", err))
		}
	}
	return true
}

func isValid(s *sessionRecord) bool {
	// Relationships
	if len(s.Certificates) < 1 || s.JA3Digest == "" || s.JA3 == "" {
		return false
	}
	// Basic informations
	if s.ClientPort == "" || s.ServerPort == "" || s.ServerIP == "" || s.ClientIP == "" {
		return false
	}
	return true
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

func insertFuzzyHash(s *sessionRecord, ids int64) error {
	q := `INSERT INTO "fuzzy_hash" (type, value, "id_sessionRecord") VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`
	_, err := db.Exec(q, "TLSH", s.TLSH, ids)
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
		return hash, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		q := `INSERT INTO "public_key" (hash, type, modulus, exponent, modulus_size) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`
		_, err := db.Exec(q, hash, "RSA", (*bigNumber)(pub.N), pub.E, pub.Size())
		if err != nil {
			return hash, err
		}
		//  else {
		// Adds the moduli into Redis for analysis
		// cr.Send("HMSET", hash, "moduli", (*BigNumber)(pub.N))
		//cr.Send("LPUSH", "albums", "1")
		// }
	case *dsa.PublicKey:
		q := `INSERT INTO "public_key" (hash, type, "G", "P", "Q", "Y") VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`
		_, err := db.Exec(q, hash, "DSA", (*bigNumber)(pub.Parameters.G), (*bigNumber)(pub.Parameters.P), (*bigNumber)(pub.Parameters.Q), (*bigNumber)(pub.Y))
		if err != nil {
			return hash, err
		}
	case *ecdsa.PublicKey:
		q := `INSERT INTO "public_key" (hash, type, "Y", "X", "P", "N", "B", "bitsize", "Gx", "Gy", "curve_name") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING`
		_, err := db.Exec(q, hash, "ECDSA", (*bigNumber)(pub.Y), (*bigNumber)(pub.X), (*bigNumber)(pub.Curve.Params().P), (*bigNumber)(pub.Curve.Params().N), (*bigNumber)(pub.Curve.Params().B), pub.Curve.Params().BitSize, (*bigNumber)(pub.Curve.Params().Gx), (*bigNumber)(pub.Curve.Params().Gy), pub.Params().Name)
		if err != nil {
			return hash, err
		}
	default:
		return hash, fmt.Errorf("PKIx: could not determine the type of key %g", pub)
	}
	return hash, nil
}

func (bn *bigNumber) Value() (driver.Value, error) {
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

func insertCertificate(fp string, c certMapElm) (string, error) {
	q := `INSERT INTO "certificate" (hash, "is_CA", "is_SS", issuer, subject, cert_chain, is_valid_chain, file_path) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`
	_, err := db.Exec(q, c.CertHash, c.Certificate.IsCA, c.chain.isSS, c.Certificate.Issuer.String(), c.Certificate.Subject.String(), c.chain.s, c.chain.isValid, getFullPath(fp, c.CertHash))
	if err != nil {
		return c.CertHash, err
	}
	key, err := insertPublicKey(*c.Certificate)
	if err != nil {
		return c.CertHash, err
	}
	//fmt.Println(c.CertHash)
	//fmt.Println(key)
	q = `INSERT INTO "many_certificate_has_many_public_key" ("hash_certificate", "hash_public_key") VALUES ($1, $2) ON CONFLICT DO NOTHING `
	_, err = db.Exec(q, c.CertHash, key)
	if err != nil {
		return c.CertHash, err
	}
	return c.CertHash, nil
}

// getFullPath takes a certificate's hash and return the full path to
// its location on disk
func getFullPath(c string, h string) string {
	return c + h
}

func insertCertificates(fp string, s *sessionRecord) ([]string, error) {
	var inserted []string
	for _, certificate := range s.Certificates {
		tmp, err := insertCertificate(fp, certificate)
		inserted = append(inserted, tmp)
		if err != nil {
			return inserted, err
		}
	}
	return inserted, nil
}

func insertSession(s *sessionRecord) (int64, error) {
	q := `INSERT INTO "sessionRecord" (dst_ip, src_ip, dst_port, src_port, timestamp, hash_ja3) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`
	var id int64
	err := db.QueryRow(q, s.ServerIP, s.ClientIP, s.ServerPort, s.ClientPort, s.Timestamp, s.JA3Digest).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func initRedis(host string, port string, d int) {
	err := errors.New("")
	cr, err = redis.Dial("tcp", host+":"+port, redis.DialDatabase(d))
	if err != nil {
		panic(err)
	}
}

func initDB(u string, pa string, h string, po string, d string) {
	connStr := "host=" + h + " port=" + po + " user=" + u + " password=" + pa + " dbname=" + d
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

func isNet(host string) (bool, string) {
	// DNS regex
	validDNS := regexp.MustCompile(`^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z
 ]{2,3})$`)
	// Check ipv6
	if strings.HasPrefix(host, "[") {
		// Parse an IP-Literal in RFC 3986 and RFC 6874.
		// E.g., "[fe80::1]:80".
		i := strings.LastIndex(host, "]")
		if i < 0 {
			log.Fatal("Unmatched [ in destination config")
			return false, ""
		}
		if !validPort(host[i+1:]) {
			log.Fatal("No valid port specified")
			return false, ""
		}
		// trim brackets
		if net.ParseIP(strings.Trim(host[:i+1], "[]")) != nil {
			log.Fatal(fmt.Sprintf("Server IP: %s, Server Port: %s\n", host[:i+1], host[i+1:]))
			return true, host
		}
	} else {
		// Ipv4 or DNS name
		ss := strings.Split(string(host), ":")
		if len(ss) > 1 {
			if !validPort(":" + ss[1]) {
				log.Fatal("No valid port specified")
				return false, ""
			}
			if net.ParseIP(ss[0]) != nil {
				log.Fatal(fmt.Sprintf("Server IP: %s, Server Port: %s\n", ss[0], ss[1]))
				return true, host
			} else if validDNS.MatchString(ss[0]) {
				log.Fatal(fmt.Sprintf("DNS: %s, Server Port: %s\n", ss[0], ss[1]))
				return true, host
			}
		}
	}
	return false, host
}

// Reusing code from net.url
// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
func validPort(port string) bool {
	if port == "" {
		return false
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func readConfFile(p string, fileName string) []byte {
	f, err := os.OpenFile("./"+p+"/"+fileName, os.O_RDWR|os.O_CREATE, 0666)
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}
	data := make([]byte, 100)
	count, err := f.Read(data)
	if err != nil {
		if err != io.EOF {
			log.Fatal(err)
		}
	}
	if count == 0 {
		log.Fatal(fileName + " is empty.")
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	// trim \n if present
	return bytes.TrimSuffix(data[:count], []byte("\n"))
}
