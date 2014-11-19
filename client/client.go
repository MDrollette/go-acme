package client

import (
	"net/http"
	"net/url"
)

const (
	defaultServerURL = "https://127.0.0.1:8888/acme"
)

type Client struct {
	client  *http.Client
	BaseURL *url.URL
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	baseURL, _ := url.Parse(defaultServerURL)

	return &Client{
		client:  httpClient,
		BaseURL: baseURL,
	}
}
