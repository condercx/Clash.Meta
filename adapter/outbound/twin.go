package outbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	twin "github.com/condercx/twin-go"

	"github.com/metacubex/quic-go"
	qtls "github.com/metacubex/tls"
)

type Twin struct {
	*Base
	option    *TwinOption
	client    *twin.Client
	quicConn  *quic.Conn
	packetConn net.PacketConn
	mu        sync.Mutex
	connected bool
}

type TwinOption struct {
	BasicOption
	Name           string   `proxy:"name"`
	Server         string   `proxy:"server"`
	Port           int      `proxy:"port,omitempty"`
	Password       string   `proxy:"password,omitempty"`
	SNI            string   `proxy:"sni,omitempty"`
	SkipCertVerify bool     `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string   `proxy:"fingerprint,omitempty"`
	Certificate    string   `proxy:"certificate,omitempty"`
	PrivateKey     string   `proxy:"private-key,omitempty"`
	ALPN           []string `proxy:"alpn,omitempty"`
	Up             string   `proxy:"up,omitempty"`
	Down           string   `proxy:"down,omitempty"`
	SideChannel    bool     `proxy:"side-channel,omitempty"`
	SideStrategy   string   `proxy:"side-strategy,omitempty"`

	InitialStreamReceiveWindow     uint64 `proxy:"initial-stream-receive-window,omitempty"`
	MaxStreamReceiveWindow         uint64 `proxy:"max-stream-receive-window,omitempty"`
	InitialConnectionReceiveWindow uint64 `proxy:"initial-connection-receive-window,omitempty"`
	MaxConnectionReceiveWindow     uint64 `proxy:"max-connection-receive-window,omitempty"`
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
		return nil, fmt.Errorf("twin dial tcp: %w", err)
	}

	return NewConn(&twinNetConn{ReadWriteCloser: stream}, t), nil
}

func (t *Twin) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	return nil, C.ErrNotSupport
}

func (t *Twin) Close() error {
	if t.quicConn != nil {
		_ = t.quicConn.CloseWithError(0, "proxy removed")
	}
	if t.packetConn != nil {
		_ = t.packetConn.Close()
	}
	if t.client != nil {
		_ = t.client.Close()
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
	if t.connected {
		return nil
	}

	addr := net.JoinHostPort(t.option.Server, strconv.Itoa(t.option.Port))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve addr: %w", err)
	}

	serverName := t.option.Server
	if t.option.SNI != "" {
		serverName = t.option.SNI
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &qtls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: t.option.SkipCertVerify,
			MinVersion:         qtls.VersionTLS13,
		},
		Fingerprint: t.option.Fingerprint,
		Certificate: t.option.Certificate,
		PrivateKey:  t.option.PrivateKey,
	})
	if err != nil {
		return err
	}

	if len(t.option.ALPN) > 0 {
		tlsConfig.NextProtos = t.option.ALPN
	} else {
		tlsConfig.NextProtos = []string{"twin"}
	}

	tc := twin.DefaultConfig()
	tc.ServerAddr = t.option.Server
	tc.ServerPort = t.option.Port
	tc.Password = t.option.Password
	tc.SNI = serverName
	tc.SkipCert = t.option.SkipCertVerify
	tc.SideChannel = t.option.SideChannel

	if t.option.Up != "" {
		tc.UpBPS = StringToBps(t.option.Up)
	}
	if t.option.Down != "" {
		tc.DownBPS = StringToBps(t.option.Down)
	}
	if t.option.SideStrategy != "" {
		if s, err := twin.ParseSideStrategy(t.option.SideStrategy); err == nil {
			tc.SideStrategy = s
		}
	}
	if t.option.InitialStreamReceiveWindow > 0 {
		tc.InitialStreamReceiveWindow = t.option.InitialStreamReceiveWindow
	}
	if t.option.MaxStreamReceiveWindow > 0 {
		tc.MaxStreamReceiveWindow = t.option.MaxStreamReceiveWindow
	}
	if t.option.InitialConnectionReceiveWindow > 0 {
		tc.InitialConnectionReceiveWindow = t.option.InitialConnectionReceiveWindow
	}
	if t.option.MaxConnectionReceiveWindow > 0 {
		tc.MaxConnectionReceiveWindow = t.option.MaxConnectionReceiveWindow
	}

	quicCfg := twin.NewQUICConfig(&tc)

	ip, _ := netip.AddrFromSlice(udpAddr.IP)
	serverAddrPort := netip.AddrPortFrom(ip, uint16(udpAddr.Port))

	packetConn, err := t.dialer.ListenPacket(ctx, "udp", "", serverAddrPort)
	if err != nil {
		return fmt.Errorf("listen udp via dialer: %w", err)
	}

	quicConn, err := quic.Dial(ctx, packetConn, udpAddr, tlsConfig, quicCfg)
	if err != nil {
		packetConn.Close()
		return fmt.Errorf("quic dial: %w", err)
	}

	client := twin.NewClient(&tc)
	if err := client.SetConn(quicConn); err != nil {
		quicConn.CloseWithError(0, "")
		packetConn.Close()
		return fmt.Errorf("twin auth: %w", err)
	}

	t.client = client
	t.quicConn = quicConn
	t.packetConn = packetConn
	t.connected = true

	log.Debugln("Twin proxy [%s] connected to %s", t.Base.Name(), addr)
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