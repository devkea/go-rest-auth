package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	uuid "github.com/nu7hatch/gouuid"
)

//Credentials structure
type Credentials struct {
	Password string `json:"password" db:"password"`
	Username string `json:"username" db:"username"`
	Email    string `json:"email" db:"email"`
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

//Signup function
func Signup(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return ResponseHTTP(nil, 405, "Method not allowed.")
	}
	creds := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		log.Printf("An error accured: %v", err)
		return ResponseHTTP(err, http.StatusBadRequest, "Bad request.")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)

	if _, err = db.Query("insert into users values (DEFAULT, $1, $2, $3)", creds.Username, creds.Email, string(hashedPassword)); err != nil {
		log.Printf("An error accured: %v", err)
		return ResponseHTTP(err, http.StatusConflict, "The username or email already exists.")
	}
	return ResponseHTTP(err, http.StatusOK, "You have successfully signed up.")
}

//Signin function
func Signin(w http.ResponseWriter, r *http.Request) error {
	c, _ := r.Cookie("session_token")
	if c != nil {
		return ResponseHTTP(nil, http.StatusOK, "You are already signed in.")
	}
	if r.Method != http.MethodPost {
		return ResponseHTTP(nil, http.StatusMethodNotAllowed, "Method not allowed.")
	}
	creds := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		log.Printf("An error accured: %v", err)
		return ResponseHTTP(err, http.StatusBadRequest, "Bad request.")
	}

	result := db.QueryRow("select password from users where username=$1", creds.Username)
	storedCreds := &Credentials{}
	err = result.Scan(&storedCreds.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("An error accured: %v", err)
			return ResponseHTTP(err, http.StatusOK, "Username/Password incorrect.")
		}
		log.Printf("An error accured: %v", err)
		return ResponseHTTP(err, http.StatusInternalServerError, "Internal server error.")
	}

	if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password)); err != nil {
		log.Printf("An error accured: %v", storedCreds.Password)
		return ResponseHTTP(err, http.StatusOK, "Username/Password incorrect.")
	}

	ss, err := SetSession("", creds.Username)
	if err != nil {
		log.Printf("An error accured: %v", err)
		return ResponseHTTP(err, http.StatusInternalServerError, "Internal server error.")
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   ss,
		Expires: time.Now().Add(3600 * 24 * 30 * time.Second),
	})
	return ResponseHTTP(err, http.StatusOK, "You have successfully signed in.")
}

//Signout function
func Signout(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return ResponseHTTP(nil, http.StatusMethodNotAllowed, "Method not allowed.")
	}
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			log.Printf("An error accured: %v", err)
			return ResponseHTTP(err, http.StatusUnauthorized, "Unauthorized.")
		}
		return ResponseHTTP(err, http.StatusBadRequest, "Bad request.")
	}
	sessionToken := c.Value
	_, err = UnsetSession(sessionToken)
	if err != nil {
		log.Printf("An error accured: %v", err)
		return ResponseHTTP(err, http.StatusBadRequest, "Bad request.")
	}
	return ResponseHTTP(err, http.StatusOK, "You are logged out.")
}

//Welcome function
func Welcome(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			log.Printf("An error accured: %v", err)
			return ResponseHTTP(err, http.StatusUnauthorized, "Unauthorized.")
		}
		return ResponseHTTP(err, http.StatusBadRequest, "Bad request.")
	}
	sessionToken := c.Value
	ss, err := SetSession(sessionToken, "")
	if err != nil {
		log.Printf("An error accured: %v", err)
		return ResponseHTTP(err, http.StatusInternalServerError, "Internal server error.")
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   ss,
		Expires: time.Now().Add(3600 * 24 * 30 * time.Second),
	})
	return ResponseHTTP(err, http.StatusOK, "ok")
}

//SetSession function
func SetSession(st, un string) (string, error) {
	if st != "" {
		response, err := cache.Do("GET", st)
		if err != nil {
			return "", err
		}
		_, err = cache.Do("SETEX", st, 3600*24*30, response)
		if err != nil {
			return "", err
		}
	}
	gst, err := uuid.NewV4()
	_, err = cache.Do("SETEX", st, 3600*24*30, un)
	if err != nil {
		return "", err
	}
	return gst.String(), nil
}

//UnsetSession function
func UnsetSession(st string) (int, error) {
	_, err := cache.Do("GET", st)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	_, err = cache.Do("DEL", st)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusUnauthorized, nil
}
