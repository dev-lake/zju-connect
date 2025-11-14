package mobile

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"golang.org/x/crypto/pkcs12"
	"inet.af/netaddr"
)

var conf configs.Config

type ProxyStatus string

const (
	StatusIdle     ProxyStatus = "idle"
	StatusStarting ProxyStatus = "starting"
	StatusRunning  ProxyStatus = "running"
	StatusStopping ProxyStatus = "stopping"
	StatusStopped  ProxyStatus = "stopped"
)

var (
	statusMu     sync.RWMutex
	currentState = StatusIdle

	stopMu        sync.Mutex
	stopCh        chan struct{}
	stopRequested bool
)

func setStatus(state ProxyStatus) {
	statusMu.Lock()
	currentState = state
	statusMu.Unlock()
}

func GetProxyStatus() string {
	statusMu.RLock()
	defer statusMu.RUnlock()
	return string(currentState)
}

func prepareStopSignal() (chan struct{}, bool) {
	stopMu.Lock()
	defer stopMu.Unlock()
	if stopCh != nil {
		return nil, false
	}
	stopRequested = false
	stopCh = make(chan struct{})
	return stopCh, true
}

func releaseStopSignal(ch chan struct{}) {
	stopMu.Lock()
	if stopCh == ch {
		stopCh = nil
		stopRequested = false
	}
	stopMu.Unlock()
}

func StopProxy() {
	stopMu.Lock()
	ch := stopCh
	if ch == nil || stopRequested {
		stopMu.Unlock()
		return
	}
	stopRequested = true
	stopMu.Unlock()

	setStatus(StatusStopping)
	close(ch)
}

const zjuConnectVersion = "0.9.0"

func initConf() {
	conf = *defaultConf()
}

func StartProxy(server string, port int, user string, pass string) {
	log.Init()

	stopSignal, ok := prepareStopSignal()
	if !ok {
		log.Println("Proxy already running, StartProxy call ignored")
		return
	}
	defer func() {
		setStatus(StatusStopped)
		releaseStopSignal(stopSignal)
	}()

	setStatus(StatusStarting)

	initConf()
	conf.ServerAddress = server
	conf.ServerPort = port
	conf.Username = user
	conf.Password = pass

	log.Println("Start ZJU Connect v" + zjuConnectVersion)
	if conf.DebugDump {
		log.EnableDebug()
	}

	if errs := hook_func.ExecInitialFunc(context.Background(), conf); errs != nil {
		for _, err := range errs {
			log.Printf("Initial ZJU-Connect failed: %s", err)
		}
		return
	}

	tlsCert := tls.Certificate{}
	if conf.CertFile != "" {
		p12Data, err := os.ReadFile(conf.CertFile)
		if err != nil {
			log.Printf("Read certificate file error: %s", err)
			return
		}

		key, cert, err := pkcs12.Decode(p12Data, conf.CertPassword)
		if err != nil {
			log.Printf("Decode certificate file error: %s", err)
			return
		}

		tlsCert = tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key.(crypto.PrivateKey),
			Leaf:        cert,
		}
	}

	vpnClient := client.NewEasyConnectClient(
		conf.ServerAddress+":"+fmt.Sprintf("%d", conf.ServerPort),
		conf.Username,
		conf.Password,
		conf.TOTPSecret,
		tlsCert,
		conf.TwfID,
		!conf.DisableMultiLine,
		!conf.DisableServerConfig,
		!conf.SkipDomainResource,
	)
	err := vpnClient.Setup()
	if err != nil {
		log.Printf("EasyConnect client setup error: %s", err)
		return
	}

	log.Printf("EasyConnect client started")

	ipResources, err := vpnClient.IPResources()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No IP resources")
	}

	ipSet, err := vpnClient.IPSet()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No IP set")
	}

	domainResources, err := vpnClient.DomainResources()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No domain resources")
	}

	dnsResource, err := vpnClient.DNSResource()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No DNS resource")
	}

	if !conf.DisableZJUConfig {
		if domainResources != nil {
			domainResources["zju.edu.cn"] = client.DomainResource{
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}
		} else {
			domainResources = map[string]client.DomainResource{
				"zju.edu.cn": {
					PortMin:  1,
					PortMax:  65535,
					Protocol: "all",
				},
			}
		}

		if ipResources != nil {
			ipResources = append([]client.IPResource{{
				IPMin:    net.ParseIP("10.0.0.0"),
				IPMax:    net.ParseIP("10.255.255.255"),
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}}, ipResources...)
		} else {
			ipResources = []client.IPResource{{
				IPMin:    net.ParseIP("10.0.0.0"),
				IPMax:    net.ParseIP("10.255.255.255"),
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}}
		}

		ipSetBuilder := netaddr.IPSetBuilder{}
		if ipSet != nil {
			ipSetBuilder.AddSet(ipSet)
		}
		ipSetBuilder.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/8"))
		ipSet, _ = ipSetBuilder.IPSet()
	}

	for _, customProxyDomain := range conf.CustomProxyDomain {
		if domainResources != nil {
			domainResources[customProxyDomain] = client.DomainResource{
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}
		} else {
			domainResources = map[string]client.DomainResource{
				customProxyDomain: {
					PortMin:  1,
					PortMax:  65535,
					Protocol: "all",
				},
			}
		}
	}

	var vpnStack stack.Stack
	if conf.TUNMode {
		// vpnTUNStack, err := tun.NewStack(vpnClient, conf.DNSHijack, ipResources)
		// if err != nil {
		// 	log.Fatalf("Tun stack setup error, make sure you are root user : %s", err)
		// }

		// if conf.AddRoute && ipSet != nil {
		// 	for _, prefix := range ipSet.Prefixes() {
		// 		log.Printf("Add route to %s", prefix.String())
		// 		_ = vpnTUNStack.AddRoute(prefix.String())
		// 	}
		// } else if !conf.AddRoute && !conf.DisableZJUConfig {
		// 	log.Println("Add route to 10.0.0.0/8")
		// 	_ = vpnTUNStack.AddRoute("10.0.0.0/8")
		// }

		// vpnStack = vpnTUNStack
	} else {
		vpnStack, err = gvisor.NewStack(vpnClient)
		if err != nil {
			log.Printf("gVisor stack setup error: %s", err)
			return
		}
	}

	useZJUDNS := !conf.DisableZJUDNS
	zjuDNSServer := conf.ZJUDNSServer
	if useZJUDNS && zjuDNSServer == "auto" {
		zjuDNSServer, err = vpnClient.DNSServer()
		if err != nil {
			useZJUDNS = false
			zjuDNSServer = "10.10.0.21"
			log.Println("No DNS server provided by server. Disable ZJU DNS")
		} else {
			log.Printf("Use DNS server %s provided by server", zjuDNSServer)
		}
	}

	vpnResolver := resolve.NewResolver(
		vpnStack,
		zjuDNSServer,
		conf.SecondaryDNSServer,
		conf.DNSTTL,
		domainResources,
		dnsResource,
		useZJUDNS,
	)

	for _, customDns := range conf.CustomDNSList {
		ipAddr := net.ParseIP(customDns.IP)
		if ipAddr == nil {
			log.Printf("Custom DNS for host name %s is invalid, SKIP", customDns.HostName)
		}
		vpnResolver.SetPermanentDNS(customDns.HostName, ipAddr)
		log.Printf("Add custom DNS: %s -> %s\n", customDns.HostName, customDns.IP)
	}
	localResolver := service.NewDnsServer(vpnResolver, []string{zjuDNSServer, conf.SecondaryDNSServer})
	vpnStack.SetupResolve(localResolver)

	go vpnStack.Run()

	vpnDialer := dial.NewDialer(vpnStack, vpnResolver, ipResources, conf.ProxyAll, conf.DialDirectProxy)

	if conf.DNSServerBind != "" {
		go service.ServeDNS(conf.DNSServerBind, localResolver)
	}
	if conf.TUNMode {
		clientIP, _ := vpnClient.IP()
		go service.ServeDNS(clientIP.String()+":53", localResolver)
	}

	if conf.SocksBind != "" {
		go service.ServeSocks5(conf.SocksBind, vpnDialer, vpnResolver, conf.SocksUser, conf.SocksPasswd)
	}

	if conf.HTTPBind != "" {
		go service.ServeHTTP(conf.HTTPBind, vpnDialer)
	}

	if conf.ShadowsocksURL != "" {
		go service.ServeShadowsocks(vpnDialer, conf.ShadowsocksURL)
	}

	for _, portForwarding := range conf.PortForwardingList {
		if portForwarding.NetworkType == "tcp" {
			go service.ServeTCPForwarding(vpnStack, portForwarding.BindAddress, portForwarding.RemoteAddress)
		} else if portForwarding.NetworkType == "udp" {
			go service.ServeUDPForwarding(vpnStack, portForwarding.BindAddress, portForwarding.RemoteAddress)
		} else {
			log.Printf("Port forwarding: unknown network type %s. Aborting", portForwarding.NetworkType)
		}
	}

	if !conf.DisableKeepAlive {
		if !useZJUDNS {
			log.Println("Keep alive is disabled because ZJU DNS is disabled")
		} else {
			go service.KeepAlive(vpnResolver)
		}
	}

	setStatus(StatusRunning)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	select {
	case <-quit:
		setStatus(StatusStopping)
	case <-stopSignal:
		// stop requested via StopProxy
	}
	signal.Stop(quit)
	log.Println("Shutdown ZJU-Connect ......")
	if errs := hook_func.ExecTerminalFunc(context.Background()); errs != nil {
		for _, err := range errs {
			log.Printf("Shutdown ZJU-Connect failed: %s", err)
		}
	} else {
		log.Println("Shutdown ZJU-Connect success, Bye~")
	}
}

func defaultConf() *configs.Config {
	return &configs.Config{
		DisableKeepAlive: true,
		DisableZJUConfig: true,
		DisableZJUDNS:    true,
		DNSTTL:           3600,
		HTTPBind:         "127.0.0.1:1080",
		SocksBind:        "127.0.0.1:1081",
	}
}
