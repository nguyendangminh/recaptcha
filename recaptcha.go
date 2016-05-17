package recaptch

import (
	"fmt"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

const endpoint = "https://www.google.com/recaptcha/api/siteverify"

var errorMessages = map[string]string {
	"missing-input-secret": "The secret parameter is missing.", 
	"invalid-input-secret": "The secret parameter is invalid or malformed.",
	"missing-input-response": "The response parameter is missing.",
	"invalid-input-response": "The response parameter is invalid or malformed."
}

type Recaptch astruct {
	secret string
}

func New(secret string) *Recaptcha {
	return &Recaptcha{secret: secret}
}

type response struct {
	Success bool `json:"success"`
	ErrorCodes []string `json:"error-code"`
}

func (r *Recaptch) Verify(response, remoteIP string) (bool, []error) {
	var data = url.Values{}
	data["secret"] = r.secret
	data["response"] = response
	if remoteIP != "" {
		data["remoteip"] = remoteIP
	}

	resp, err := http.PostForm(endpoint, data)
	if err != nil {
		return false, []error{err}
	}
	defer resp.Body.Close()

	var r response 
	err = json.Unmarshal(resp.Body, &r)
	if err != nil {
		return false, []error{err}
	}
	var errs []error
	if len(r.ErrorCodes) != 0 {
		for _, v := range r.ErrorCodes {
			append(errs, errors.New(errorMessages[v]))
		}
		return false, errs
	}

	return true, nil
}