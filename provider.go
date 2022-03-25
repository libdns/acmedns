package acmedns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/libdns/libdns"
)

var acmePrefix = "_acme-challenge."

type DomainConfig struct {
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Subdomain  string `json:"subdomain,omitempty"`
	FullDomain string `json:"fulldomain,omitempty"`
	ServerURL  string `json:"server_url,omitempty"`
}

// Provider.Configs defines a map from domain string to
// DomainConfig. It uses the same structure as ACME-DNS client
// JSON storage file (https://github.com/acme-dns/acme-dns-client).

// Provider must be set up in one of two ways:
//
// 1) Set Configs field. Configs field defines a map from domains
// to different ACME-DNS accounts.
//
// 2) Set fields Username, Password, Subdomain, ServerURL.
// If these fields are set, one account will be used for
// AppendRecords for all zones and record names.
type Provider struct {
	// Provider.Configs defines a map from domain string to
	// DomainConfig. It uses the same structure as ACME-DNS client
	// JSON storage file (https://github.com/acme-dns/acme-dns-client).
	Configs map[string]DomainConfig `json:"config,omitempty"`

	// ACME-DNS account username as returned by ACME-DNS API /register endpoint.
	Username string `json:"username,omitempty"`
	// ACME-DNS account password as returned by ACME-DNS API /register endpoint.
	Password string `json:"password,omitempty"`
	// ACME-DNS account subdomain as returned by ACME-DNS API /register endpoint.
	Subdomain string `json:"subdomain,omitempty"`
	// ACME-DNS API base URL. For example, https://auth.acme-dns.io
	ServerURL string `json:"server_url,omitempty"`
}

type account struct {
	Username  string
	Password  string
	Subdomain string
	ServerURL string
}

func (p *Provider) selectAccount(zone string, name string) (*account, error) {
	if p.Configs != nil {
		domain := name + "." + zone
		if domain[len(domain)-1:] == "." {
			domain = domain[:len(domain)-1]
		}
		if domain[:len(acmePrefix)] == acmePrefix {
			domain = domain[len(acmePrefix):]
		}
		config, found := p.Configs[domain]
		if !found {
			return nil, fmt.Errorf("Config for domain %s not found", domain)
		}
		acc := account{
			Username:  config.Username,
			Password:  config.Password,
			Subdomain: config.Subdomain,
			ServerURL: config.ServerURL,
		}
		return &acc, nil
	}

	if p.Username == "" {
		return nil, fmt.Errorf("Username cannot be empty")
	}
	if p.Password == "" {
		return nil, fmt.Errorf("Password cannot be empty")
	}
	if p.Subdomain == "" {
		return nil, fmt.Errorf("Subdomain cannot be empty")
	}
	if p.ServerURL == "" {
		return nil, fmt.Errorf("ServerURL cannot be empty")
	}

	acc := account{
		Username:  p.Username,
		Password:  p.Password,
		Subdomain: p.Subdomain,
		ServerURL: p.ServerURL,
	}
	return &acc, nil
}

func updateTxtValue(acc account, value string) error {
	body, err := json.Marshal(
		map[string]string{
			"subdomain": acc.Subdomain,
			"txt":       value,
		},
	)
	if err != nil {
		return fmt.Errorf("Error while marshalling JSON: %w", err)
	}
	req, err := http.NewRequest("POST", acc.ServerURL+"/update", bytes.NewBuffer(body))
	req.Header.Set("X-Api-User", acc.Username)
	req.Header.Set("X-Api-Key", acc.Password)
	client := &http.Client{Timeout: time.Second * 30}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error while reading response: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Updating ACME-DNS record resulted in response code %d", resp.StatusCode)
	}
	return nil
}

// Implements libdns.RecordAppender.
//
// The only operation Joohoi's ACME-DNS API supports is a rolling update
// of two TXT records.
//
// If Provider Configs field is not nil, zone and record names are used to
// select relevant credentials from Provider.Configs.
//
// If Configs is nil and Provider is set up with non-nil Username,
// Password, Subdomain and ServerURL fields, these credentials
// will be used to update ACME-DNS account TXT records regardless
// of what zone and record names are passed.
//
// Only TXT records are supported. ID, TTL and Priority fields
// of libdns.Record are ignored.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	appendedRecords := []libdns.Record{}
	for _, record := range recs {
		if record.Type != "TXT" {
			return appendedRecords, fmt.Errorf("joohoi_acme_dns provider only supports adding TXT records")
		}
		acc, err := p.selectAccount(zone, record.Name)
		if err != nil {
			return appendedRecords, err
		}
		err = updateTxtValue(*acc, record.Value)
		if err != nil {
			return appendedRecords, err
		}
		appendedRecords = append(appendedRecords, libdns.Record{Type: "TXT", Name: record.Name, Value: record.Value})

	}
	return appendedRecords, nil
}

// Implements libdns.RecordDeleter.
//
// DeleteRecords does nothing at all - ACME-DNS does not support record deletion.
// However, older records are automatically deleted as newer records are added
// (a rolling update of two records).
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

// Interface guards.
var (
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
