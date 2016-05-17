package recaptch

import (
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
	"invalid-input-response": "The response parameter is invalid or malformed.",
}

type Recaptcha struct {
	secret string
}

func New(secret string) *Recaptcha {
	return &Recaptcha{secret: secret}
}

type Response struct {
	Success bool `json:"success"`
	ErrorCodes []string `json:"error-code"`
}

func (r *Recaptcha) Verify(response, remoteIP string) (bool, []error) {
	var data = url.Values{}
	data.Set("secret", r.secret)
	data.Set("response", response)
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}

	resp, err := http.PostForm(endpoint, data)
	if err != nil {
		return false, []error{err}
	}
	defer resp.Body.Close()

	var res Response 
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return false, []error{err}
	}
	var errs []error
	if len(res.ErrorCodes) != 0 {
		for _, v := range res.ErrorCodes {
			errs = append(errs, errors.New(errorMessages[v]))
		}
		return false, errs
	}

	return true, nil
}