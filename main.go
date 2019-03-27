package main

// APACHE 2.0
import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/gomodule/redigo/redis"
	_ "github.com/lib/pq"
)

func main() {
	// connect to redis
	c, err := redis.Dial("tcp", ":6380", redis.DialDatabase(2))
	defer c.Close()
	if err != nil {
		panic(err)
	}

	// connect to db
	connStr := "user=postgres password=postgres dbname=passivessl"
	db, err := sql.Open("postgres", connStr)
	defer db.Close()
	if err != nil {
		panic(err)
	}

	// pop redis queue
	for {
		jsonPath, err := redis.String(c.Do("LPOP", "analyzer:ja3-jl:0894517855f047d2a77b4473d3a9cc5b"))
		if err != nil {
			log.Fatal("Queue processed")
		}
		// read corresponding json file
		dat, err := ioutil.ReadFile(jsonPath)
		if err != nil {
			log.Fatal(err)
		}

		q := `INSERT INTO sessions (data) VALUES ($1) RETURNING id`
		id := 0
		err = db.QueryRow(q, dat).Scan(&id)
		if err != nil {
			panic(err)
		}
		fmt.Println("New record ID is:", id)
	}
}
