package main

import (
	"encoding/json"
	"fmt"
)

//ClientResponse interface
type ClientResponse interface {
	Error() string
	ResponseBody() ([]byte, error)
	ResponseHeaders() (int, map[string]string)
}

//HTTPResponse interface
type HTTPResponse struct {
	Cause  error  `json:"-"`
	Detail string `json:"response"`
	Status int    `json:"-"`
}

func (e *HTTPResponse) Error() string {
	if e.Cause == nil {
		return e.Detail
	}
	return e.Detail + " : " + e.Cause.Error()
}

//ResponseBody function
func (e *HTTPResponse) ResponseBody() ([]byte, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("Error while parsing response body: %v", err)
	}
	return body, nil
}

//ResponseHeaders function
func (e *HTTPResponse) ResponseHeaders() (int, map[string]string) {
	return e.Status, map[string]string{
		"Content-Type": "application/json; charset=utf-8",
	}
}

//ResponseHTTP function
func ResponseHTTP(err error, status int, detail string) error {
	return &HTTPResponse{
		Cause:  err,
		Detail: detail,
		Status: status,
	}
}
