package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	twin "github.com/condercx/twin-go"
)

type Twin struct {
	*Base
	option *TwinOption
	client *twin.Client
	mu     sync.Mutex
}

type TwinOption struct {
	BasicOption
	Name           string   `proxy:"name"`
	Server         string   `proxy:"server"`
	Port           int      `proxy:"port,omitempty"`
	Password       string   `proxy:"password,omitempty"`
	TLSMode        string   `proxy:"tls,omitempty"`
	SNI            string   `proxy:"sni,omitempty"`
	SkipCertVerify bool     `proxy:"skip-cert-verify,omitempty"`
	ConnCount      int      `proxy:"conns,omitempty"`
	IPs            []string `proxy:"ips,omitempty"`
}

func NewTwin(option TwinOption) (*Twin, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Twin{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Twin,
			ProviderName: option.ProviderName,
			UDP:          true,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

func (t *Twin) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err := t.ensureConn(ctx); err != nil {
		return nil, err
	}

	target := net.JoinHostPort(metadata.String(), strconv.Itoa(int(metadata.DstPort)))
	stream, err := t.client.DialTCP(ctx, target)
	if err != nil {
		log.Debugln("Twin proxy [%s]: dial error %v, reconnecting", t.Base.Name(), err)
		t.mu.Lock()
		t.client = nil
		t.mu.Unlock()
		return nil, fmt.Errorf("twin dial tcp: %w", err)
	}

	return NewConn(&twinNetConn{ReadWriteCloser: stream}, t), nil
}

func (t *Twin) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err := t.ensureConn(ctx); err != nil {
		return nil, err
	}

	pc, err := t.client.ListenPacket()
	if err != nil {
		return nil, err
	}
	return newPacketConn(N.NewThreadSafePacketConn(pc), t), nil
}

func (t *Twin) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		t.client.Close()
		t.client = nil
	}
	return nil
}

func (t *Twin) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

func (t *Twin) ensureConn(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client != nil {
		return nil
	}

	serverAddr := t.option.Server
	serverPort := t.option.Port
	if serverPort == 0 {
		serverPort = 443
	}

	tlsMode := twin.TLSModeWSS
	if t.option.TLSMode != "" {
		tlsMode = twin.TLSMode(strings.ToLower(t.option.TLSMode))
	}

	sni := t.option.SNI
	if sni == "" {
		sni = serverAddr
	}

	connCount := t.option.ConnCount
	if connCount <= 0 {
		connCount = 3
	}

	cfg := twin.ClientConfig{
		ServerAddr:   serverAddr,
		ServerPort:   serverPort,
		Password:     t.option.Password,
		TLSMode:      tlsMode,
		SNI:          sni,
		Insecure:     t.option.SkipCertVerify,
		ConnCount:    connCount,
		ProxyIPs:     t.option.IPs,
	}

	client, err := twin.NewClient(&cfg)
	if err != nil {
		return fmt.Errorf("twin create client: %w", err)
	}

	t.client = client

	log.Debugln("Twin proxy [%s] connected to %s (tls=%s, conns=%d)", t.Base.Name(), cfg.ServerURL(), tlsMode, connCount)
	return nil
}

type twinNetConn struct {
	io.ReadWriteCloser
}

func (c *twinNetConn) LocalAddr() net.Addr              { return nil }
func (c *twinNetConn) RemoteAddr() net.Addr             { return nil }
func (c *twinNetConn) SetDeadline(t time.Time) error    { return nil }
func (c *twinNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *twinNetConn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*twinNetConn)(nil)
