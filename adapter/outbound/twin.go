package outbound

import (
	"context"
	"fmt"
	"net/netip"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	twin "github.com/condercx/twin-go"

	"github.com/condercx/twin-go/obfs"

	"github.com/metacubex/quic-go"
	qtls "github.com/metacubex/tls"
)

type Twin struct {
	*Base
	option     *TwinOption
	client     *twin.Client
	quicConn   *quic.Conn
	packetConn net.PacketConn
	mu         sync.Mutex
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
		log.Debugln("Twin proxy [%s]: dial error %v, reconnecting", t.Base.Name(), err)
		t.mu.Lock()
		t.cleanupLocked()
		t.mu.Unlock()
		return nil, fmt.Errorf("twin dial tcp: %w", err)
	}

	return NewConn(&twinNetConn{ReadWriteCloser: stream}, t), nil
}

func (t *Twin) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err := t.ensureConn(ctx); err != nil {
		return nil, err
	}

	pc := &twinPacketConn{
		client:  t.client,
		ctx:     ctx,
		inbound: make(chan udpPacket, 256),
		sessions: make(map[string]*twin.UDPSession),
		closeCh: make(chan struct{}),
	}
	return newPacketConn(N.NewThreadSafePacketConn(pc), t), nil
}

func (t *Twin) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cleanupLocked()
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

	if t.client != nil && t.client.IsClosed() {
		log.Debugln("Twin proxy [%s]: connection closed, reconnecting", t.Base.Name())
		t.cleanupLocked()
	}

	if t.client != nil {
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

	obfsKey := twin.DeriveObfsKey(tc.Password)
	obfsPacketConn := obfs.NewObfsPacketConn(packetConn, obfsKey)

	quicConn, err := quic.Dial(ctx, obfsPacketConn, udpAddr, tlsConfig, quicCfg)
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

	log.Debugln("Twin proxy [%s] connected to %s", t.Base.Name(), addr)
	return nil
}

func (t *Twin) cleanupLocked() {
	if t.quicConn != nil {
		t.quicConn.CloseWithError(0, "reconnect")
	}
	if t.packetConn != nil {
		t.packetConn.Close()
	}
	if t.client != nil {
		t.client.Close()
	}
	t.client = nil
	t.quicConn = nil
	t.packetConn = nil
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

type udpPacket struct {
	addr string
	data []byte
}

type twinPacketConn struct {
	client  *twin.Client
	ctx     context.Context

	mu       sync.Mutex
	sessions map[string]*twin.UDPSession
	closed   bool

	inbound chan udpPacket
	closeCh chan struct{}
	wg      sync.WaitGroup
}

func (pc *twinPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	addrStr := addr.String()

	pc.mu.Lock()
	sess, ok := pc.sessions[addrStr]
	pc.mu.Unlock()

	if !ok {
		ctx, cancel := context.WithTimeout(pc.ctx, 10*time.Second)
		defer cancel()

		newSess, err := pc.client.NewUDPSession(ctx)
		if err != nil {
			return 0, fmt.Errorf("open udp session: %w", err)
		}

		pc.mu.Lock()
		if pc.closed {
			pc.mu.Unlock()
			newSess.Close()
			return 0, net.ErrClosed
		}
		if existing, ok := pc.sessions[addrStr]; ok {
			pc.mu.Unlock()
			newSess.Close()
			sess = existing
		} else {
			pc.sessions[addrStr] = newSess
			pc.mu.Unlock()
			sess = newSess
			pc.wg.Add(1)
			go pc.udpReadLoop(newSess, addrStr)
		}
	}

	host, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		return 0, err
	}
	port, _ := strconv.Atoi(portStr)
	if err := sess.WriteTo(p, host, uint16(port)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (pc *twinPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-pc.closeCh:
		return 0, nil, net.ErrClosed
	case pkt, ok := <-pc.inbound:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt.data)
		udpAddr, _ := net.ResolveUDPAddr("udp", pkt.addr)
		return n, udpAddr, nil
	}
}

func (pc *twinPacketConn) udpReadLoop(sess *twin.UDPSession, addrStr string) {
	defer pc.wg.Done()
	defer func() {
		pc.mu.Lock()
		delete(pc.sessions, addrStr)
		pc.mu.Unlock()
	}()

	for {
		data, host, port, err := sess.ReadFrom()
		if err != nil {
			return
		}
		replyAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))

		select {
		case pc.inbound <- udpPacket{addr: replyAddr, data: data}:
		default:
		}
	}
}

func (pc *twinPacketConn) Close() error {
	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return nil
	}
	pc.closed = true
	sessions := pc.sessions
	pc.sessions = make(map[string]*twin.UDPSession)
	close(pc.closeCh)
	pc.mu.Unlock()

	for _, sess := range sessions {
		sess.Close()
	}

	pc.wg.Wait()
	return nil
}

func (pc *twinPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (pc *twinPacketConn) SetDeadline(t time.Time) error      { return nil }
func (pc *twinPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (pc *twinPacketConn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.PacketConn = (*twinPacketConn)(nil)
