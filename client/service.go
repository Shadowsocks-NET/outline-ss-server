package client

// Service defines the management interface for client services.
type Service interface {
	// String returns the service's name.
	// This method may be called on a nil pointer.
	String() string

	// Start starts the service.
	Start() error

	// Stop stops the service.
	Stop() error
}
