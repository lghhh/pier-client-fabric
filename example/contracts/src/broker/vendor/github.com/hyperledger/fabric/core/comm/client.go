/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/third_party/github.com/tjfoc/gmsm/sm2"
	"github.com/hyperledger/fabric/third_party/github.com/tjfoc/gmtls"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type GRPCClient struct {
	// TLS configuration used by the grpc.ClientConn
	tlsConfig interface{}
	// Options for setting up new connections
	dialOpts []grpc.DialOption
	// Duration for which to block while established a new connection
	timeout time.Duration
	// Maximum message size the client can receive
	maxRecvMsgSize int
	// Maximum message size the client can send
	maxSendMsgSize int
}

// NewGRPCClient creates a new implementation of GRPCClient given an address
// and client configuration
func NewGRPCClient(config ClientConfig) (*GRPCClient, error) {
	client := &GRPCClient{}

	// parse secure options
	err := client.parseSecureOptions(config.SecOpts)
	if err != nil {
		return client, err
	}

	// keepalive options
	var kap keepalive.ClientParameters
	if config.KaOpts != nil {
		kap = keepalive.ClientParameters{
			Time:    config.KaOpts.ClientInterval,
			Timeout: config.KaOpts.ClientTimeout}
	} else {
		// use defaults
		kap = keepalive.ClientParameters{
			Time:    DefaultKeepaliveOptions.ClientInterval,
			Timeout: DefaultKeepaliveOptions.ClientTimeout}
	}
	kap.PermitWithoutStream = true
	// set keepalive
	client.dialOpts = append(client.dialOpts, grpc.WithKeepaliveParams(kap))
	// Unless asynchronous connect is set, make connection establishment blocking.
	if !config.AsyncConnect {
		client.dialOpts = append(client.dialOpts, grpc.WithBlock())
		client.dialOpts = append(client.dialOpts, grpc.FailOnNonTempDialError(true))
	}
	client.timeout = config.Timeout
	// set send/recv message size to package defaults
	client.maxRecvMsgSize = MaxRecvMsgSize
	client.maxSendMsgSize = MaxSendMsgSize

	return client, nil
}

func (client *GRPCClient) parseSecureOptions(opts *SecureOptions) error {

	if opts == nil || !opts.UseTLS {
		return nil
	}
	if factory.GetDefault().GetProviderName() == "SW" {
		client.tlsConfig = &tls.Config{
			VerifyPeerCertificate: opts.VerifyCertificate,
			MinVersion:            tls.VersionTLS12} // TLS 1.2 only
		if len(opts.ServerRootCAs) > 0 {
			client.tlsConfig.(*tls.Config).RootCAs = x509.NewCertPool()
			for _, certBytes := range opts.ServerRootCAs {
				err := AddPemToCertPool(certBytes, client.tlsConfig.(*tls.Config).RootCAs)
				if err != nil {
					commLogger.Debugf("error adding root certificate: %v", err)
					return errors.WithMessage(err,
						"error adding root certificate")
				}
			}
		}
		if opts.RequireClientCert {
			// make sure we have both Key and Certificate
			if opts.Key != nil &&
				opts.Certificate != nil {
				cert, err := tls.X509KeyPair(opts.Certificate,
					opts.Key)
				if err != nil {
					return errors.WithMessage(err, "failed to "+
						"load client certificate")
				}
				client.tlsConfig.(*tls.Config).Certificates = append(
					client.tlsConfig.(*tls.Config).Certificates, cert)
			} else {
				return errors.New("both Key and Certificate " +
					"are required when using mutual TLS")
			}
		}

		if opts.TimeShift > 0 {
			client.tlsConfig.(*tls.Config).Time = func() time.Time {
				return time.Now().Add((-1) * opts.TimeShift)
			}
		}
	} else {
		client.tlsConfig = &gmtls.Config{
			VerifyPeerCertificate: opts.VerifyGMCertificate,
			MinVersion:            tls.VersionTLS12} // TLS 1.2 only
		if len(opts.ServerRootCAs) > 0 {
			client.tlsConfig.(*gmtls.Config).RootCAs = sm2.NewCertPool()
			for _, certBytes := range opts.ServerRootCAs {
				err := AddPemToCertPool(certBytes, client.tlsConfig.(*gmtls.Config).RootCAs)
				if err != nil {
					commLogger.Debugf("error adding root certificate: %v", err)
					return errors.WithMessage(err,
						"error adding root certificate")
				}
			}
		}
		if opts.RequireClientCert {
			// make sure we have both Key and Certificate
			if opts.Key != nil &&
				opts.Certificate != nil {
				cert, err := gmtls.X509KeyPair(opts.Certificate,
					opts.Key)
				if err != nil {
					return errors.WithMessage(err, "failed to "+
						"load client certificate")
				}
				client.tlsConfig.(*gmtls.Config).Certificates = append(
					client.tlsConfig.(*gmtls.Config).Certificates, cert)
			} else {
				return errors.New("both Key and Certificate " +
					"are required when using mutual TLS")
			}
		}

		if opts.TimeShift > 0 {
			client.tlsConfig.(*gmtls.Config).Time = func() time.Time {
				return time.Now().Add((-1) * opts.TimeShift)
			}
		}
	}

	return nil
}

// Certificate returns the tls.Certificate used to make TLS connections
// when client certificates are required by the server
func (client *GRPCClient) Certificate() interface{} {
	if factory.GetDefault().GetProviderName() == "SW" {
		cert := tls.Certificate{}
		if client.tlsConfig != nil && len(client.tlsConfig.(*tls.Config).Certificates) > 0 {
			cert = client.tlsConfig.(*tls.Config).Certificates[0]
		}
		return cert
	} else {
		cert := gmtls.Certificate{}
		if client.tlsConfig != nil && len(client.tlsConfig.(*gmtls.Config).Certificates) > 0 {
			cert = client.tlsConfig.(*gmtls.Config).Certificates[0]
		}
		return cert
	}
}

// TLSEnabled is a flag indicating whether to use TLS for client
// connections
func (client *GRPCClient) TLSEnabled() bool {
	return client.tlsConfig != nil
}

// MutualTLSRequired is a flag indicating whether the client
// must send a certificate when making TLS connections
func (client *GRPCClient) MutualTLSRequired() bool {
	if factory.GetDefault().GetProviderName() == "SW" {
		return client.tlsConfig != nil &&
			len(client.tlsConfig.(*tls.Config).Certificates) > 0
	} else {
		return client.tlsConfig != nil &&
			len(client.tlsConfig.(*gmtls.Config).Certificates) > 0
	}
}

// SetMaxRecvMsgSize sets the maximum message size the client can receive
func (client *GRPCClient) SetMaxRecvMsgSize(size int) {
	client.maxRecvMsgSize = size
}

// SetMaxSendMsgSize sets the maximum message size the client can send
func (client *GRPCClient) SetMaxSendMsgSize(size int) {
	client.maxSendMsgSize = size
}

// SetServerRootCAs sets the list of authorities used to verify server
// certificates based on a list of PEM-encoded X509 certificate authorities
func (client *GRPCClient) SetServerRootCAs(serverRoots [][]byte) error {

	// NOTE: if no serverRoots are specified, the current cert pool will be
	// replaced with an empty one
	if factory.GetDefault().GetProviderName() == "SW" {
		certPool := x509.NewCertPool()
		for _, root := range serverRoots {
			err := AddPemToCertPool(root, certPool)
			if err != nil {
				return errors.WithMessage(err, "error adding root certificate")
			}
		}
		client.tlsConfig.(*tls.Config).RootCAs = certPool
	} else {
		certPool := sm2.NewCertPool()
		for _, root := range serverRoots {
			err := AddPemToCertPool(root, certPool)
			if err != nil {
				return errors.WithMessage(err, "error adding root certificate")
			}
		}
		client.tlsConfig.(*gmtls.Config).RootCAs = certPool
	}
	return nil
}

// TLSOption changes the given TLS config
type TLSOption func(tlsConfig *tls.Config)

// GMTLSOption changes the given TLS config
type GMTLSOption func(tlsConfig *gmtls.Config)

// NewConnection returns a grpc.ClientConn for the target address and
// overrides the server name used to verify the hostname on the
// certificate returned by a server when using TLS
func (client *GRPCClient) NewConnection(address string, serverNameOverride string, tlsOptions ...interface{}) (
	*grpc.ClientConn, error) {

	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, client.dialOpts...)

	// set transport credentials and max send/recv message sizes
	// immediately before creating a connection in order to allow
	// SetServerRootCAs / SetMaxRecvMsgSize / SetMaxSendMsgSize
	//  to take effect on a per connection basis
	if factory.GetDefault().GetProviderName() == "SW" {
		if client.tlsConfig != nil {
			client.tlsConfig.(*tls.Config).ServerName = serverNameOverride
			dialOpts = append(dialOpts,
				grpc.WithTransportCredentials(
					&DynamicClientCredentials{TLSConfig: client.tlsConfig, TLSOptions: tlsOptions}))
		} else {
			dialOpts = append(dialOpts, grpc.WithInsecure())
		}
	} else {
		if client.tlsConfig != nil {
			client.tlsConfig.(*gmtls.Config).ServerName = serverNameOverride
			dialOpts = append(dialOpts,
				grpc.WithTransportCredentials(
					&DynamicClientCredentials{TLSConfig: client.tlsConfig, TLSOptions: tlsOptions}))
		} else {
			dialOpts = append(dialOpts, grpc.WithInsecure())
		}
	}
	dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(
		grpc.MaxCallRecvMsgSize(client.maxRecvMsgSize),
		grpc.MaxCallSendMsgSize(client.maxSendMsgSize)))

	ctx, cancel := context.WithTimeout(context.Background(), client.timeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, address, dialOpts...)
	if err != nil {
		return nil, errors.WithMessage(errors.WithStack(err),
			"failed to create new connection")
	}
	return conn, nil
}
