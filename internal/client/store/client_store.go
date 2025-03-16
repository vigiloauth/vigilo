package client

import "github.com/vigiloauth/vigilo/internal/client"

type ClientStore interface {
	CreateClient(client *client.Client) error
	GetClient(clientID string) *client.Client
	DeleteClient(clientID string) error
	UpdateClient(client *client.Client) error
}
