package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	greetLimit = 5 * time.Second
	dialLimit  = 10 * time.Second
)

// Forbidden reports whether ip is in a class no device may connect to. The
// proxy shares the network of the host, so these addresses would reach the
// host itself. The net.IP methods also match IPv4-mapped forms, and IsMulticast
// covers every scope, interface-local included. Server.refused adds the
// addresses that depend on the host.
func Forbidden(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified()
}

// Dial opens the upstream connection. The result is a *net.TCPConn, which the
// relay half-closes, with the default TCP keep-alive.
func Dial(ctx context.Context, d Dest) (net.Conn, error) {
	dialer := net.Dialer{Timeout: dialLimit}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(d.IP.String(), strconv.Itoa(d.Port)))
}

// HostInterface is one network interface of the host.
type HostInterface struct {
	Name  string
	Addrs []*net.IPNet
}

// hostInterfaces lists the interfaces the proxy sees, which are the host's
// because it shares its network.
func hostInterfaces() ([]HostInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]HostInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		h := HostInterface{Name: iface.Name}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				h.Addrs = append(h.Addrs, n)
			}
		}
		out = append(out, h)
	}
	return out, nil
}

// localNets is what the interfaces of the host put out of reach: its own
// addresses, on any interface, and the whole subnet of each Docker bridge. The
// containers there expect only the host's own traffic, and EveBox has no login
// of its own. Other subnets, such as the LAN, stay reachable.
type localNets struct {
	hosts   []net.IP
	bridges []*net.IPNet
}

func newLocalNets(ifaces []HostInterface) *localNets {
	l := &localNets{}
	for _, iface := range ifaces {
		bridge := strings.HasPrefix(iface.Name, "docker") || strings.HasPrefix(iface.Name, "br-")
		for _, a := range iface.Addrs {
			l.hosts = append(l.hosts, a.IP)
			if bridge {
				l.bridges = append(l.bridges, a)
			}
		}
	}
	return l
}

// contains also matches IPv4-mapped forms: Equal and Contains both normalise.
func (l *localNets) contains(ip net.IP) bool {
	for _, h := range l.hosts {
		if h.Equal(ip) {
			return true
		}
	}
	for _, n := range l.bridges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Server owns the SOCKS listener and the connections it accepted. Apply is
// the only way to change it, so the control file decides what is open.
type Server struct {
	Engine     *Engine
	PrivateDir string
	StateDir   string
	Resolve    func(ctx context.Context, host string) ([]net.IP, error)
	GreetLimit time.Duration // zero means 5 seconds
	Interfaces func() ([]HostInterface, error)

	local atomic.Pointer[localNets] // nil until the first list, and Apply opens no port before that

	mu         sync.Mutex
	cfg        Config
	ln         net.Listener // nil while the port is closed
	port       int
	caGen      int
	conns      map[string]map[uint64]context.CancelFunc // by device, then by connection
	nextConn   uint64
	state      string // the last line logged by Apply
	listFailed bool   // the current failure to list interfaces is already logged
}

// NewServer returns a Server with the port closed. The CA is loaded into e.CA
// the first time the feature is enabled.
func NewServer(e *Engine, privateDir, stateDir string) *Server {
	return &Server{
		Engine:     e,
		PrivateDir: privateDir,
		StateDir:   stateDir,
		Resolve: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		},
		Interfaces: hostInterfaces,
		conns:      make(map[string]map[uint64]context.CancelFunc),
	}
}

// Apply brings the server in line with cfg. It runs on every poll, so it only
// touches the listener and the connections when cfg asks for something new,
// and a CA or listen failure is simply tried again by the next call.
func (s *Server) Apply(cfg Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	s.Engine.Bypass.SetOwn(cfg.Bypass)
	s.Engine.Bypass.Apply(cfg.AutoRemove)
	s.readInterfaces()

	state := "off"
	open := false
	if cfg.Enabled {
		state = "on, SOCKS off"
		open = cfg.Socks
		// Before the listener: Handle needs a CA for every connection.
		if err := s.loadCA(cfg.CAGeneration); err != nil {
			state = fmt.Sprintf("on, port closed, CA failed: %v", err)
			open = false
		}
		// Without a list, the Docker networks would be open to every device.
		if open && s.local.Load() == nil {
			state = "on, port closed, no interface list"
			open = false
		}
	}
	if s.ln != nil && (!open || cfg.SocksPort != s.port) {
		s.ln.Close()
		s.ln = nil
	}
	if open {
		state = fmt.Sprintf("on, SOCKS on port %d, devices %v", cfg.SocksPort, cfg.Devices)
		if err := s.listen(cfg.SocksPort); err != nil {
			state = fmt.Sprintf("on, port closed: %v", err)
		}
	}
	for device, group := range s.conns {
		if !open || !cfg.Allowed(net.ParseIP(device)) {
			for _, cancel := range group {
				cancel()
			}
		}
	}
	if state != s.state {
		s.state = state
		log.Printf("proxy %s", state)
	}
}

// readInterfaces refreshes the local networks, so a Docker network created
// later is covered by the next poll. A failure keeps the last good list.
func (s *Server) readInterfaces() {
	ifaces, err := s.Interfaces()
	if err != nil {
		if !s.listFailed {
			log.Printf("interface list: %v", err)
			s.listFailed = true
		}
		return
	}
	s.listFailed = false
	s.local.Store(newLocalNets(ifaces))
}

// loadCA stores the CA of this generation, unless it is already there.
func (s *Server) loadCA(generation int) error {
	if s.Engine.CA.Load() != nil && generation == s.caGen {
		return nil
	}
	ca, err := LoadCA(s.PrivateDir, s.StateDir, generation)
	if err != nil {
		return err
	}
	s.Engine.CA.Store(ca)
	s.caGen = generation
	log.Printf("CA generation %d loaded", generation)
	return nil
}

// listen opens the port, unless it is already open.
func (s *Server) listen(port int) error {
	if s.ln != nil {
		return nil
	}
	if port == 0 {
		return errors.New("no SOCKS port set") // 0 would pick a random port
	}
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	s.ln, s.port = ln, port
	go s.accept(ln)
	return nil
}

// accept serves ln until Apply closes it.
func (s *Server) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			// Out of file descriptors, most likely. The port stays open.
			log.Printf("accept: %v", err)
			time.Sleep(time.Second)
			continue
		}
		var device net.IP
		if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			device = a.IP
		}
		ctx, done, ok := s.admit(ln, device)
		if !ok {
			c.Close()
			continue
		}
		go func() {
			defer done()
			s.serve(ctx, c, device)
		}()
	}
}

// admit registers a connection from device and returns its context and the
// function that ends it, or false if the connection must be closed. It holds
// the lock of Apply, so a connection either meets the current configuration
// here or is seen by the next Apply. It is never missed by both.
func (s *Server) admit(ln net.Listener, device net.IP) (context.Context, func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != ln {
		return nil, nil, false
	}
	if !s.cfg.Allowed(device) {
		s.Engine.Stats.Refused()
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	key, id := device.String(), s.nextConn
	s.nextConn++
	if s.conns[key] == nil {
		s.conns[key] = make(map[uint64]context.CancelFunc)
	}
	s.conns[key][id] = cancel
	return ctx, func() {
		cancel()
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.conns[key], id)
		if len(s.conns[key]) == 0 {
			delete(s.conns, key)
		}
	}, true
}

// serve runs the SOCKS handshake of one connection and hands it to the engine.
func (s *Server) serve(ctx context.Context, c net.Conn, device net.IP) {
	defer c.Close()
	// Handle does the same, but it has not started during Greet and lookup.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()

	limit := s.GreetLimit
	if limit == 0 {
		limit = greetLimit
	}
	c.SetDeadline(time.Now().Add(limit))
	d, err := Greet(c)
	if err != nil {
		return
	}
	c.SetDeadline(time.Time{})

	if d.IP == nil {
		ip, err := s.lookup(ctx, d.Host)
		if err != nil {
			Reply(c, ReplyUnreachable)
			return
		}
		d = Dest{IP: ip, Port: d.Port}
	}
	if s.refused(d.IP) {
		Reply(c, ReplyNotAllowed)
		return
	}
	s.Engine.Handle(ctx, c, device, d, func(ok bool) {
		if ok {
			Reply(c, ReplyOK)
		} else {
			Reply(c, ReplyUnreachable)
		}
	})
}

// refused reports whether a device may not connect to ip.
func (s *Server) refused(ip net.IP) bool {
	return Forbidden(ip) || s.local.Load().contains(ip)
}

// lookup returns the first IPv4 address of host, else the first IPv6.
func (s *Server) lookup(ctx context.Context, host string) (net.IP, error) {
	ips, err := s.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, nil
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("no addresses")
	}
	return ips[0], nil
}
