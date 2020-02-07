package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gomodule/redigo/redis"
)

var cache redis.Conn
var db *sql.DB

func main() {
	initCache()
	initDB()
	http.Handle("/signup", rootHandler(Signup))
	http.Handle("/signin", rootHandler(Signin))
	http.Handle("/signout", rootHandler(Signout))
	http.Handle("/welcome", rootHandler(Welcome))
	err := http.ListenAndServe(":8001", nil)
	if err != nil {
		fmt.Println(err)
		log.Fatal("ListenAndServe: ", err)
	}
}

func initDB() {
	var err error
	db, err = sql.Open("postgres", "postgres://db_user:db_pass@localhost/db_name")
	if err != nil {
		panic(err)
	}
}

func initCache() {
	conn, err := redis.DialURL("redis://localhost")
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	cache = conn
}

type rootHandler func(http.ResponseWriter, *http.Request) error

// rootHandler implements http.Handler interface.
func (fn rootHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := fn(w, r)
	if err == nil {
		return
	}
	log.Printf("%v", err)

	ClientResponse, ok := err.(ClientResponse)
	if !ok {
		w.WriteHeader(500)
		return
	}

	body, err := ClientResponse.ResponseBody()
	if err != nil {
		log.Printf("%v", err)
		w.WriteHeader(500)
		return
	}
	status, headers := ClientResponse.ResponseHeaders()
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	w.Write(body)
}
