package manet

import (
	"context"
	"crypto/tls"
	"fmt"
	ma "github.com/multiformats/go-multiaddr"
	"net"
)

func (d *Dialer) DialTLS(remote ma.Multiaddr,tlsConf *tls.Config) (Conn, error) {
	return d.DialTLSContext(context.Background(), remote,tlsConf)
}

// DialContext allows to provide a custom context to Dial().
func (d *Dialer) DialTLSContext(ctx context.Context, remote ma.Multiaddr,tlsConf *tls.Config) (Conn, error) {
	// if a LocalAddr is specified, use it on the embedded dialer.
	if d.LocalAddr != nil {
		// convert our multiaddr to net.Addr friendly
		naddr, err := ToNetAddr(d.LocalAddr)
		if err != nil {
			return nil, err
		}

		// set the dialer's LocalAddr as naddr
		d.Dialer.LocalAddr = naddr
	}

	// get the net.Dial friendly arguments from the remote addr
	rnet, rnaddr, err := DialArgs(remote)
	if err != nil {
		return nil, err
	}

	// ok, Dial!
	var nconn net.Conn
	switch rnet {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "unix":
		nconn, err = tls.DialWithDialer(&d.Dialer,rnet,rnaddr,tlsConf)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unrecognized network: %s", rnet)
	}

	// get local address (pre-specified or assigned within net.Conn)
	local := d.LocalAddr
	// This block helps us avoid parsing addresses in transports (such as unix
	// sockets) that don't have local addresses when dialing out.
	if local == nil && nconn.LocalAddr().String() != "" {
		local, err = FromNetAddr(nconn.LocalAddr())
		if err != nil {
			return nil, err
		}
	}
	return wrap(nconn, local, remote), nil
}

// Dial connects to a remote address. It uses an underlying net.Conn,
// then wraps it in a Conn object (with local and remote Multiaddrs).
func DialTLS(remote ma.Multiaddr,tlsConf *tls.Config) (Conn, error) {
	return (&Dialer{}).DialTLS(remote,tlsConf)
}