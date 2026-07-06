package claimer

import (
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Kqzz/MCsniperGO/pkg/mc"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"

	"github.com/Kqzz/MCsniperGO/log"
)

var workerCount = 100

func SetWorkerCount(n int) {
	if n > 0 {
		workerCount = n
	}
}

func GetWorkerCount() int {
	return workerCount
}

type Event struct {
	Level   string    `json:"level"`
	Message string    `json:"message"`
	Time    time.Time `json:"time"`
}

var (
	eventMu       sync.RWMutex
	eventHandlers []func(Event)
)

func OnEvent(fn func(Event)) {
	eventMu.Lock()
	eventHandlers = append(eventHandlers, fn)
	eventMu.Unlock()
}

func emitEvent(level, message string) {
	eventMu.RLock()
	handlers := eventHandlers
	eventMu.RUnlock()
	if len(handlers) == 0 {
		return
	}
	ev := Event{Level: level, Message: message, Time: time.Now()}
	for _, fn := range handlers {
		fn(ev)
	}
}

type Claim struct {
	Username  string
	Running   bool
	DropRange mc.DropRange
	Accounts  []*mc.MCaccount
	Proxies   []string
}

func (c *Claim) Start() {
	c.Running = true
	go c.runClaim()
}

func (c *Claim) Stop() {
	c.Running = false
}

type ClaimAttempt struct {
	Claim   *Claim
	Name    string
	Bearer  string
	AccType mc.AccType
	AccNum  int
	Proxy   string
}

func preWarmDNS(hosts []string) {
	for _, host := range hosts {
		net.LookupHost(host)
	}
}

func testProxy(proxy string) bool {
	client := &fasthttp.Client{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	if strings.HasPrefix(proxy, "socks5://") {
		client.Dial = fasthttpproxy.FasthttpSocksDialer(proxy)
	} else if proxy != "" {
		client.Dial = fasthttpproxy.FasthttpHTTPDialer(proxy)
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://api.minecraftservices.com/entitlements/mcitems")
	err := client.Do(req, resp)
	return err == nil && resp.StatusCode() < 500
}

func filterWorkingProxies(proxies []string) []string {
	if len(proxies) == 0 {
		return []string{""}
	}

	working := []string{}
	for _, p := range proxies {
		if testProxy(p) {
			working = append(working, p)
		}
	}

	if len(working) == 0 {
		log.Log("warn", "no working proxies found, using direct connection")
		return []string{""}
	}

	log.Log("success", "%d/%d proxies working", len(working), len(proxies))
	return working
}

func newWorkerClient(proxy string) *fasthttp.Client {
	client := &fasthttp.Client{
		Dial: (&fasthttp.TCPDialer{
			Concurrency:      4096,
			DNSCacheDuration: time.Hour,
		}).Dial,
		NoDefaultUserAgentHeader: true,
		MaxConnsPerHost:          512,
		ReadTimeout:              15 * time.Second,
		WriteTimeout:             15 * time.Second,
	}
	if strings.HasPrefix(proxy, "socks5://") {
		client.Dial = fasthttpproxy.FasthttpSocksDialer(proxy)
	} else if proxy != "" {
		client.Dial = fasthttpproxy.FasthttpHTTPDialer(proxy)
	}
	return client
}

func requestGenerator(
	workChan chan ClaimAttempt,
	killChan chan bool,
	bearers []string,
	name string,
	accType mc.AccType,
	endTime time.Time,
	proxies []string,
	delay int,
) {
	noEnd := endTime.IsZero()
	if len(bearers) == 0 {
		return
	}

	sleepTime := delay

	if endTime.IsZero() {
		nMax := int(math.Min(float64(len(bearers)), float64(len(proxies))))
		day := int((time.Hour * 24).Milliseconds())
		sleepTime = int(day / 40 / nMax)
	} else if delay == -1 {
		nMax := int(math.Min(float64(len(bearers)), float64(len(proxies))))
		day := int((time.Hour * 24).Milliseconds())
		shortInterval := int(math.Min(30000, float64(time.Until(endTime).Milliseconds())))
		longInterval := int(math.Min(float64(day), float64(time.Until(endTime).Milliseconds())))
		var deltaShort int
		if accType == mc.Ms {
			deltaShort = shortInterval / 3 / nMax
		} else {
			deltaShort = shortInterval / 2 / nMax
		}
		deltaLong := longInterval / 40 / nMax
		sleepTime = int(math.Max(float64(deltaShort), float64(deltaLong)))
	}
	loopCount := 2
	if accType == mc.Ms {
		loopCount = 3
	}
	i := 0
	prox := 0
	for noEnd || time.Now().Before(endTime) {
		for y := 0; y < loopCount; y++ {
			if i >= len(bearers) {
				i = 0
			}

			if prox >= len(proxies) {
				prox = 0
			}

			select {
			case workChan <- ClaimAttempt{
				Name:    name,
				Bearer:  bearers[i],
				AccType: accType,
				Proxy:   proxies[prox],
				AccNum:  i + 1,
			}:
			case <-killChan:
				return
			}
			time.Sleep(time.Millisecond * time.Duration(sleepTime))
			prox++
		}
		i++
	}

}

func claimName(claim ClaimAttempt, client *fasthttp.Client) {
	acc := mc.MCaccount{
		Bearer: claim.Bearer,
		Type:   claim.AccType,
	}

	status := 0
	var err error = nil
	var fail mc.FailType = mc.DUPLICATE

	before := time.Now()
	if claim.AccType == mc.Ms {
		status, fail, err = acc.ChangeUsername(claim.Name, client)
	} else {
		status, fail, err = acc.CreateProfile(claim.Name, client)
	}
	after := time.Now()

	if err != nil {
		msg := log.Sprintf("err: %v #%d", err, claim.AccNum)
		log.Log("err", "%v #%d", err, claim.AccNum)
		emitEvent("err", msg)
		return
	}

	Stats.Total++

	msg := log.Sprintf("[%v] %v %vms %v %v #%d | %s", claim.Name, after.Format("15:04:05.999"), after.Sub(before).Milliseconds(), status, acc.Type, claim.AccNum, string(fail))
	log.Log("info", "[%v] %v %vms %v %v #%d | %s", claim.Name, after.Format("15:04:05.999"), after.Sub(before).Milliseconds(), log.PrettyStatus(status), acc.Type, claim.AccNum, string(fail))
	emitEvent("info", msg)

	if status == 200 {
		successMsg := log.Sprintf("CLAIMED %v on %v acc, %v", claim.Name, acc.Type, acc.Bearer[len(acc.Bearer)/2:])
		log.Log("success", "Claimed %v on %v acc, %v", claim.Name, acc.Type, acc.Bearer[len(acc.Bearer)/2:])
		log.Log("success", "Join https://discord.gg/2BZseKW for more!")
		emitEvent("success", successMsg)
		Stats.Success++
		claim.Claim.Running = false
	}

	switch fail {
	case mc.DUPLICATE:
		Stats.Duplicate++
	case mc.NOT_ALLOWED:
		Stats.NotAllowed++
	case mc.TOO_MANY_REQUESTS:
		Stats.TooManyRequests++
	}

}

func worker(claimChan chan ClaimAttempt, killChan chan bool, proxy string) {
	client := newWorkerClient(proxy)
	for {
		select {
		case claim := <-claimChan:
			claimName(claim, client)
		case <-killChan:
			return
		}
	}
}

func (s *Claim) runClaim() {
	workChan := make(chan ClaimAttempt, workerCount*2)
	killChan := make(chan bool)
	s.Running = true

	go func() {

		doChecks := true
		_, statusCode, err := mc.UsernameToUuid(s.Username)

		if err != nil {
			log.Log("err", "failed to get uuid of %v for availability checking: %v", s.Username, err)
		}

		if statusCode != 404 {
			doChecks = false
		}

		for i := 0; true; i++ {
			if i%30 == 0 && doChecks {
				i = 0
				_, statusCode, err = mc.UsernameToUuid(s.Username)

				if err != nil {
					log.Log("err", "failed to get uuid of %v for availability checking: %v", s.Username, err)
				}

				if statusCode == 200 {
					msg := log.Sprintf("username %v is taken now", s.Username)
					log.Log("err", "username %v is taken now", s.Username)
					emitEvent("err", msg)
					s.Running = false
					close(killChan)
					return
				}
			}

			if !s.Running {
				log.Log("info", "Stopped claim of %v", s.Username)
				close(killChan)
				return
			}
			time.Sleep(time.Second * 2)
		}
	}()

	gcs := []string{}
	mss := []string{}

	for _, acc := range s.Accounts {
		if acc.Type == mc.Ms {
			mss = append(mss, acc.Bearer)
		} else {
			gcs = append(gcs, acc.Bearer)
		}
	}

	preWarmDNS([]string{"api.minecraftservices.com", "api.mojang.com"})

	workingProxies := filterWorkingProxies(s.Proxies)

	proxySet := make(map[string]bool)
	for _, p := range workingProxies {
		proxySet[p] = true
	}
	uniqueProxies := make([]string, 0, len(proxySet))
	for p := range proxySet {
		uniqueProxies = append(uniqueProxies, p)
	}

	workersPerProxy := workerCount / len(uniqueProxies)
	if workersPerProxy < 1 {
		workersPerProxy = 1
	}
	for _, proxy := range uniqueProxies {
		for j := 0; j < workersPerProxy; j++ {
			go worker(workChan, killChan, proxy)
		}
	}

	msg := log.Sprintf("using %v accounts, %v/%v proxies working, %v workers", len(s.Accounts), len(uniqueProxies), len(s.Proxies), workersPerProxy*len(uniqueProxies))
	log.Log("info", "using %v accounts", len(s.Accounts))
	log.Log("info", "using %v/%v working proxies", len(uniqueProxies), len(s.Proxies))
	emitEvent("info", msg)

	time.Sleep(time.Until(s.DropRange.Start))

	go requestGenerator(workChan, killChan, gcs, s.Username, mc.MsPr, s.DropRange.End, workingProxies, -1)
	go requestGenerator(workChan, killChan, mss, s.Username, mc.Ms, s.DropRange.End, workingProxies, -1)

	if s.DropRange.End.IsZero() {
		select {}
	}

	for time.Now().Before(s.DropRange.End) {
		time.Sleep(10 * time.Second)
	}
	s.Running = false
	_, ok := (<-killChan)
	if ok {
		close(killChan)
	}

}
