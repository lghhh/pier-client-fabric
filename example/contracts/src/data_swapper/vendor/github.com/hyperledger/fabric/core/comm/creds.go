/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"

	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/third_party/github.com/tjfoc/gmsm/sm2"
	"github.com/hyperledger/fabric/third_party/github.com/tjfoc/gmtls"
	"github.com/hyperledger/fabric/third_party/github.com/tjfoc/gmtls/gmcredentials"
	"google.golang.org/grpc/credentials"
)

var (
	ClientHandshakeNotImplError = errors.New("core/comm: Client handshakes" +
		"are not implemented with serverCreds")
	OverrrideHostnameNotSupportedError = errors.New(
		"core/comm: OverrideServerName is " +
			"not supported")
	ServerHandshakeNotImplementedError = errors.New("core/comm: server handshakes are not implemented with clientCreds")

	MissingServerConfigError = errors.New(
		"core/comm: `serverConfig` cannot be nil")
	// alpnProtoStr are the specified application level protocols for gRPC.
	alpnProtoStr = []string{"h2"}
)

// NewServerTransportCredentials returns a new initialized
// grpc/credentials.TransportCredentials
func NewServerTransportCredentials(
	serverConfig *TLSConfig,
	logger *flogging.FabricLogger) credentials.TransportCredentials {

	if factory.GetDefault().GetProviderName() == "SW" {
		// NOTE: unlike the default grpc/credentials implementation, we do not
		// clone the tls.Config which allows us to update it dynamically
		serverConfig.config.(*tls.Config).NextProtos = alpnProtoStr
		// override TLS version and ensure it is 1.2
		serverConfig.config.(*tls.Config).MinVersion = tls.VersionTLS12
		serverConfig.config.(*tls.Config).MaxVersion = tls.VersionTLS12
	} else {
		// NOTE: unlike the default grpc/credentials implementation, we do not
		// clone the tls.Config which allows us to update it dynamically
		serverConfig.config.(*gmtls.Config).NextProtos = alpnProtoStr
		// override TLS version and ensure it is 1.2
		serverConfig.config.(*gmtls.Config).MinVersion = gmtls.VersionTLS12
		serverConfig.config.(*gmtls.Config).MaxVersion = gmtls.VersionTLS12
	}
	return &serverCreds{
		serverConfig: serverConfig,
		logger:       logger}
}

// serverCreds is an implementation of grpc/credentials.TransportCredentials.
type serverCreds struct {
	serverConfig *TLSConfig
	logger       *flogging.FabricLogger
}

type TLSConfig struct {
	config interface{}
	lock   sync.RWMutex
}

func NewTLSConfig(config interface{}) *TLSConfig {
	return &TLSConfig{
		config: config,
	}
}

func (t *TLSConfig) Config() interface{} {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if t.config != nil {
		if factory.GetDefault().GetProviderName() == "SW" {
			return *t.config.(*tls.Config).Clone()
		} else {
			return *t.config.(*gmtls.Config).Clone()
		}
	}

	return tls.Config{}
}

func (t *TLSConfig) AddClientRootCA(cert interface{}) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if factory.GetDefault().GetProviderName() == "SW" {
		t.config.(*tls.Config).ClientCAs.AddCert(cert.(*x509.Certificate))
	} else {
		t.config.(*gmtls.Config).ClientCAs.AddCert(cert.(*sm2.Certificate))
	}
}

func (t *TLSConfig) SetClientCAs(certPool interface{}) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if factory.GetDefault().GetProviderName() == "SW" {
		t.config.(*tls.Config).ClientCAs = certPool.(*x509.CertPool)
	} else {
		t.config.(*gmtls.Config).ClientCAs = certPool.(*sm2.CertPool)
	}
}

// ClientHandShake is not implemented for `serverCreds`.
func (sc *serverCreds) ClientHandshake(context.Context,
	string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ClientHandshakeNotImplError
}

// ServerHandshake does the authentication handshake for servers.
func (sc *serverCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	serverConfig := sc.serverConfig.Config()

	if factory.GetDefault().GetProviderName() == "SW" {
		config := serverConfig.(tls.Config)
		conn := tls.Server(rawConn, &config)
		if err := conn.Handshake(); err != nil {
			if sc.logger != nil {
				sc.logger.With("remote address",
					conn.RemoteAddr().String()).Errorf("TLS handshake failed with error %s", err)
			}
			return nil, nil, err
		}
		return conn, credentials.TLSInfo{State: conn.ConnectionState()}, nil
	} else {
		config := serverConfig.(gmtls.Config)
		conn := gmtls.Server(rawConn, &config)
		if err := conn.Handshake(); err != nil {
			if sc.logger != nil {
				sc.logger.With("remote address",
					conn.RemoteAddr().String()).Errorf("TLS handshake failed with error %s", err)
			}
			return nil, nil, err
		}
		return conn, gmcredentials.TLSInfo{State: conn.ConnectionState()}, nil
	}
}

// Info provides the ProtocolInfo of this TransportCredentials.
func (sc *serverCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
	}
}

// Clone makes a copy of this TransportCredentials.
func (sc *serverCreds) Clone() credentials.TransportCredentials {
	config := sc.serverConfig.Config()
	serverConfig := NewTLSConfig(&config)
	creds := NewServerTransportCredentials(serverConfig, sc.logger)
	return creds
}

// OverrideServerName overrides the server name used to verify the hostname
// on the returned certificates from the server.
func (sc *serverCreds) OverrideServerName(string) error {
	return OverrrideHostnameNotSupportedError
}

type DynamicClientCredentials struct {
	TLSConfig  interface{}
	TLSOptions []interface{}
}

func (dtc *DynamicClientCredentials) latestConfig() interface{} {
	if factory.GetDefault().GetProviderName() == "SW" {
		tlsConfigCopy := dtc.TLSConfig.(*tls.Config).Clone()
		for _, tlsOption := range dtc.TLSOptions {
			tlsOption.(func(*tls.Config))(tlsConfigCopy)
		}
		return tlsConfigCopy
	} else {
		tlsConfigCopy := dtc.TLSConfig.(*gmtls.Config).Clone()
		for _, tlsOption := range dtc.TLSOptions {
			tlsOption.(func(*gmtls.Config))(tlsConfigCopy)
		}
		return tlsConfigCopy
	}
}

func (dtc *DynamicClientCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if factory.GetDefault().GetProviderName() == "SW" {
		return credentials.NewTLS(dtc.latestConfig().(*tls.Config)).ClientHandshake(ctx, authority, rawConn)
	} else {
		return gmcredentials.NewTLS(dtc.latestConfig().(*gmtls.Config)).ClientHandshake(ctx, authority, rawConn)
	}
}

func (dtc *DynamicClientCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ServerHandshakeNotImplementedError
}

func (dtc *DynamicClientCredentials) Info() credentials.ProtocolInfo {
	if factory.GetDefault().GetProviderName() == "SW" {
		return credentials.NewTLS(dtc.latestConfig().(*tls.Config)).Info()
	} else {
		return gmcredentials.NewTLS(dtc.latestConfig().(*gmtls.Config)).Info()
	}
}

func (dtc *DynamicClientCredentials) Clone() credentials.TransportCredentials {
	if factory.GetDefault().GetProviderName() == "SW" {
		return credentials.NewTLS(dtc.latestConfig().(*tls.Config))
	} else {
		return gmcredentials.NewTLS(dtc.latestConfig().(*gmtls.Config))
	}
}

func (dtc *DynamicClientCredentials) OverrideServerName(name string) error {
	if factory.GetDefault().GetProviderName() == "SW" {
		dtc.TLSConfig.(*tls.Config).ServerName = name
	} else {
		dtc.TLSConfig.(*gmtls.Config).ServerName = name
	}
	return nil
}
