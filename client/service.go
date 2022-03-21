package client

type Service interface {
	Name() string
	Start() error
	Stop() error
}
