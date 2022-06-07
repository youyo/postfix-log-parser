package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/tabalt/pidfile"
	postfixlog "github.com/yo000/postfix-log-parser"
)

func init() {}

type (
	PostfixLogParser struct {
		Time           *time.Time `json:"time"`
		Hostname       string     `json:"hostname"`
		Process        string     `json:"process"`
		QueueId        string     `json:"queue_id"`
		ClientHostname string     `json:"client_hostname"`
		ClinetIp       string     `json:"client_ip"`
		SaslMethod     string     `json:"sasl_method"`
		SaslUsername   string     `json:"sasl_username"`
		MessageId      string     `json:"message_id"`
		From           string     `json:"from"`
		Size           string     `json:"size"`
		NRcpt          string     `json:"nrcpt"`
		Messages       []Message  `json:"messages"`
	}

	Message struct {
		Time     *time.Time `json:"time"`
		To       string     `json:"to"`
		Status   string     `json:"status"`
		Message  string     `json:"message"`
		BounceId string     `json:"bounce_id"`
	}

	PostfixLogParserFlat struct {
		Time           *time.Time `json:"time"`
		Hostname       string     `json:"hostname"`
		Process        string     `json:"process"`
		QueueId        string     `json:"queue_id"`
		ClientHostname string     `json:"client_hostname"`
		ClinetIp       string     `json:"client_ip"`
		SaslMethod     string     `json:"sasl_method"`
		SaslUsername   string     `json:"sasl_username"`
		MessageId      string     `json:"message_id"`
		From           string     `json:"from"`
		Size           string     `json:"size"`
		NRcpt          string     `json:"nrcpt"`
		TimeSent       *time.Time `json:"time_sent"`
		To             string     `json:"to"`
		Status         string     `json:"status"`
		Message        string     `json:"message"`
		BounceId       string     `json:"bounce_id"`
	}
)

var (
	File   os.File
	Writer *bufio.Writer

	Version = "1.2.7"

	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "postfixlogparser_build_info",
		Help: "Constant 1 value labeled by version and goversion from which postfix-log-parser was built",
	}, []string{"version", "goversion"})
	StartTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "postfixlogparser_time_start_seconds",
		Help: "Process start time in UNIX timestamp (seconds)",
	})
	LineReadCnt = promauto.NewCounter(prometheus.CounterOpts{
		Name: "postfixlogparser_line_read_count",
		Help: "Number of lines read",
	})
	LineIncorrectCnt = promauto.NewCounter(prometheus.CounterOpts{
		Name: "postfixlogparser_line_incorrect_count",
		Help: "Number of lines with incorrect format",
	})
	LineOutCnt = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "postfixlogparser_line_out_count",
		Help: "Number of lines written to ouput",
	}, []string{"host"})
	MsgInCnt = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "postfixlogparser_msg_in_count",
		Help: "Number of mails accepted by smtpd",
	}, []string{"host"})
	MsgSentCnt = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "postfixlogparser_msg_sent_count",
		Help: "Number of mails sent",
	}, []string{"host"})
	MsgDeferredCnt = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "postfixlogparser_msg_deferred_count",
		Help: "Number of mails deferred",
	}, []string{"host"})
	MsgBouncedCnt = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "postfixlogparser_msg_bounced_count",
		Help: "Number of mails bounced",
	}, []string{"host"})
	MsgRejectedCnt = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "postfixlogparser_msg_rejected_count",
		Help: "Number of mails rejected",
	}, []string{"host"})
	MsgHoldCnt = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "postfixlogparser_msg_hold_count",
		Help: "Number of mails hold",
	}, []string{"host"})

	rootCmd = &cobra.Command{
		Use:   "postfix-log-parser",
		Short: "Postfix Log Parser v" + Version + ". Parse postfix log, and output json format",
		//Long: ``,
		Run: func(cmd *cobra.Command, args []string) {
			processLogs(cmd, args)
		},
	}

	gFlatten             bool
	gOutputFile          string
	gPidFilePath         string
	gSyslogListenAddress string
	gPromListenAddress   string
	gPromMetricPath      string
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		rootCmd.SetOutput(os.Stderr)
		rootCmd.Println(err)
		os.Exit(1)
	}
}

func PlpToFlat(plp *PostfixLogParser) []PostfixLogParserFlat {
	var plpf = make([]PostfixLogParserFlat, len(plp.Messages))

	for i := range plp.Messages {
		plpf[i] = PostfixLogParserFlat{
			Time:           plp.Time,
			Hostname:       plp.Hostname,
			Process:        plp.Process,
			QueueId:        plp.QueueId,
			ClientHostname: plp.ClientHostname,
			ClinetIp:       plp.ClinetIp,
			SaslMethod:     plp.SaslMethod,
			SaslUsername:   plp.SaslUsername,
			MessageId:      plp.MessageId,
			From:           plp.From,
			Size:           plp.Size,
			NRcpt:          plp.NRcpt,
			TimeSent:       plp.Messages[i].Time,
			To:             plp.Messages[i].To,
			Status:         plp.Messages[i].Status,
			Message:        plp.Messages[i].Message,
			BounceId:       plp.Messages[i].BounceId,
		}
	}

	return plpf
}

func NewWriter(file string) (*bufio.Writer, *os.File, error) {
	if len(file) > 0 {
		var f *os.File
		var err error
		if _, err = os.Stat(file); err == nil {
			f, err = os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0640)
		} else if os.IsNotExist(err) {
			f, err = os.OpenFile(file, os.O_CREATE|os.O_WRONLY, 0640)
		}
		if err != nil {
			return nil, nil, err
		}
		Writer = bufio.NewWriter(f)
		return Writer, f, nil
	} else {
		Writer = bufio.NewWriter(os.Stdout)
		return Writer, nil, nil
	}
}

func writeOut(msg string, filename string) error {
	_, err := fmt.Fprintln(Writer, msg)
	Writer.Flush()
	if err != nil {
		return err
	}

	var tmpPlp PostfixLogParser
	json.Unmarshal([]byte(msg), &tmpPlp)
	LineOutCnt.WithLabelValues(tmpPlp.Hostname).Inc()

	return nil
}

// Every 24H, remove sent, milter-rejected and deferred that entered queue more than 5 days ago
func periodicallyCleanMQueue(mqueue map[string]*PostfixLogParser) {
	var ok int

	for range time.Tick(time.Hour * 24) {
		for _, inmail := range mqueue {
			ok = 0
			// Check all mails were sent (multiple destinations mails)
			//  or rejected
			for _, outmail := range inmail.Messages {
				if outmail.Status == "sent" || outmail.Status == "milter-reject" {
					ok += 1
				} else if outmail.Status == "deferred" {
					if inmail.Time.Add(time.Hour * 5 * 24).Before(time.Now()) {
						ok += 1
					}
				}
			}
			if ok == len(inmail.Messages) {
				delete(mqueue, inmail.MessageId)
			}
		}
	}
}

func initConfig() {}

func init() {

	rootCmd.Version = Version

	rootCmd.Flags().BoolVarP(&gFlatten, "gFlatten", "f", false, "Flatten output for using with syslog")
	rootCmd.Flags().StringVarP(&gOutputFile, "out", "o", "", "Output to file, append if exists")
	rootCmd.Flags().StringVarP(&gPidFilePath, "pidfile", "p", "", "pid file path")
	rootCmd.Flags().StringVarP(&gSyslogListenAddress, "syslog.listen-address", "s", "do-not-listen", "Address to listen on for syslog incoming messages. Default is to parse stdin")
	rootCmd.Flags().StringVarP(&gPromListenAddress, "prom.listen-address", "l", "do-not-listen", "Address to listen on for prometheus metrics")
	rootCmd.Flags().StringVarP(&gPromMetricPath, "prom.telemetry-path", "m", "/metrics", "Path under which to expose metrics.")

	cobra.OnInitialize(initConfig)
}

func processLogs(cmd *cobra.Command, args []string) {
	var scanner *bufio.Scanner
	var listener net.Listener
	var mtx sync.Mutex
	var useStdin bool

	// Nope, breaks stdout output interpretation by jq
	//fmt.Printf("postfix-log-parser v%s\n", Version)
	BuildInfo.WithLabelValues(Version, runtime.Version()).Set(1)
	StartTime.Set(float64(time.Now().Unix()))

	// Prometheus exporter
	if gPromListenAddress != "do-not-listen" {
		go func() {
			http.Handle(gPromMetricPath, promhttp.Handler())
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`
				<html>
				<head><title>Postfix-log-parser Exporter</title></head>
				<body>
				<h1>Postfix-log-parser Exporter</h1>
				<p><a href='` + gPromMetricPath + `'>Metrics</a></p>
				</body>
				</html>`))
			})
			log.Fatal(http.ListenAndServe(gPromListenAddress, nil))
		}()
	}

	// Create PID file
	if len(gPidFilePath) > 0 {
		if pid, err := pidfile.Create(gPidFilePath); err != nil {
			log.Fatal(err)
		} else {
			defer pid.Clear()
		}
	}

	// create queue
	m := make(map[string]*PostfixLogParser)

	// initialize
	p := postfixlog.NewPostfixLog()

	// Get a writer, file or stdout
	_, File, err := NewWriter(gOutputFile)
	if err != nil {
		cmd.SetOutput(os.Stderr)
		cmd.Println(err)
		os.Exit(1)
	}

	// Manage output file rotation when receiving SIGUSR1
	if len(gOutputFile) > 0 {
		sig := make(chan os.Signal)
		signal.Notify(sig, syscall.SIGUSR1)
		go func() {
			for {
				<-sig
				mtx.Lock()
				fmt.Println("SIGUSR1 received, recreating output file")
				File.Close()
				_, File, err = NewWriter(gOutputFile)
				if err != nil {
					mtx.Unlock()
					cmd.SetOutput(os.Stderr)
					cmd.Println(err)
					os.Exit(1)
				}
				mtx.Unlock()
			}
		}()
	}

	// Cleaner thread
	go periodicallyCleanMQueue(m)

	// Initialize Stdin input
	if true == strings.EqualFold(gSyslogListenAddress, "do-not-listen") {
		useStdin = true
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		listener, err = net.Listen("tcp", gSyslogListenAddress)
		if err != nil {
			log.Fatal(fmt.Sprintf("Error listening on %s: %v\n", gSyslogListenAddress, err))
		}
	}

	for {
		// If input is made via TCP Conn, we need to read from a connected net.Conn
		if useStdin == false {
			if scanner == nil {
				// We support _only one_ concurent connection to the service
				connClt, err := listener.Accept()
				if err != nil {
					log.Printf("Error accepting: %v", err)
					// Loop
					continue
				}
				// Read will fail if no data after "duration"
				connClt.SetReadDeadline(time.Now().Add(time.Duration(3600) * time.Second))
				scanner = bufio.NewScanner(connClt)
			}
		}

		if false == scanner.Scan() {
			// After Scan returns false, the Err method will return any error that occurred during scanning, except that if it was io.EOF, Err will return nil
			if err := scanner.Err(); err != nil {
				log.Printf("Error reading data: %v\n", err.Error())
				continue
			}
			if useStdin == false {
				// close connection so we can Accept() again, then loop
				scanner = nil
				continue
			} else {
				// stdin is dead, abort mission!
				return
			}
		}
		LineReadCnt.Inc()

		// parse log
		logFormat, err := p.Parse(scanner.Bytes())
		if err != nil {
			// Incorrect line, just skip it
			if err.Error() == "Error: Line do not match regex" {
				LineIncorrectCnt.Inc()
				continue
			}
			cmd.SetOutput(os.Stderr)
			cmd.Println(err)
			os.Exit(1)
		}

		/*
			Oct 10 04:02:02 mail.example.com postfix/smtpd[22941]: DFBEFDBF00C5: client=example.net[127.0.0.1], sasl_method=PLAIN, sasl_username=user@example.com
		*/
		if logFormat.ClientHostname != "" && !strings.HasPrefix(logFormat.Messages, "milter-reject:") {
			m[logFormat.QueueId] = &PostfixLogParser{
				Time:           logFormat.Time,
				Hostname:       logFormat.Hostname,
				Process:        logFormat.Process,
				QueueId:        logFormat.QueueId,
				ClientHostname: logFormat.ClientHostname,
				ClinetIp:       logFormat.ClinetIp,
				SaslMethod:     logFormat.SaslMethod,
				SaslUsername:   logFormat.SaslUsername,
			}
		}

		/*
			Oct 10 04:02:02 mail.example.com postfix/cleanup[22923]: DFBEFDBF00C5: message-id=<20181009190202.81363306015D@example.com>
		*/
		if logFormat.MessageId != "" {
			if plp, ok := m[logFormat.QueueId]; ok {
				plp.MessageId = logFormat.MessageId
			}
		}

		/*
			Oct 10 04:02:03 mail.example.com postfix/qmgr[18719]: DFBEFDBF00C5: from=<root@example.com>, size=3578, nrcpt=1 (queue active)
		*/
		if logFormat.From != "" {
			if plp, ok := m[logFormat.QueueId]; ok {
				plp.From = logFormat.From
				plp.Size = logFormat.Size
				plp.NRcpt = logFormat.NRcpt
			}
			nrcpt, _ := strconv.ParseFloat(logFormat.NRcpt, 64)
			MsgInCnt.WithLabelValues(logFormat.Hostname).Add(nrcpt)
		}

		/*
			Oct 10 04:02:08 mail.example.com postfix/smtp[22928]: DFBEFDBF00C5: to=<test@example-to.com>, relay=mail.example-to.com[192.168.0.10]:25, delay=5.3, delays=0.26/0/0.31/4.7, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as C598F1B0002D)
		*/
		if logFormat.To != "" {
			if plp, ok := m[logFormat.QueueId]; ok {
				message := Message{
					Time:     logFormat.Time,
					To:       logFormat.To,
					Status:   logFormat.Status,
					Message:  logFormat.Messages,
					BounceId: "",
				}

				/* When a message is deferred, it won't be written out until it is either sent, expired, or generates a non delivery notification.
				    We want to know instantly when a message is deferred, so we handle this case by emiting output for this message, and not appending this occurence
					to the list of Messages
				*/
				if logFormat.Status == "deferred" {
					MsgDeferredCnt.WithLabelValues(plp.Hostname).Inc()
					tmpplp := PostfixLogParser{
						Time:           plp.Time,
						Hostname:       plp.Hostname,
						Process:        plp.Process,
						QueueId:        plp.QueueId,
						ClientHostname: plp.ClientHostname,
						ClinetIp:       plp.ClinetIp,
						SaslMethod:     plp.SaslMethod,
						SaslUsername:   plp.SaslUsername,
						MessageId:      plp.MessageId,
						From:           plp.From,
						Size:           plp.Size,
						NRcpt:          plp.NRcpt,
					}
					tmpplp.Messages = append(tmpplp.Messages, message)

					var jsonBytes []byte
					if gFlatten {
						jsonBytes, err = json.Marshal(PlpToFlat(&tmpplp)[0])
					} else {
						jsonBytes, err = json.Marshal(tmpplp)
					}
					if err != nil {
						log.Fatal(err)
					}
					mtx.Lock()
					err = writeOut(string(jsonBytes), gOutputFile)
					mtx.Unlock()
					if err != nil {
						log.Fatal(err)
					}
					tmpplp.Messages = nil
					// cannot use nil as type PostfixLogParser in assignment
					//tmpplp = nil
				} else {
					plp.Messages = append(plp.Messages, message)
				}
			}
		}

		/*
			2021-02-05T17:25:03+01:00 mail.example.com postfix/bounce[39258]: 006B056E6: sender non-delivery notification: 642E456E9
		*/
		if logFormat.BounceId != "" {
			if plp, ok := m[logFormat.QueueId]; ok {
				// Get the matching Message by Status=bounced
				for i, msg := range plp.Messages {
					// Need to manage more than one bounce for the same queue_id. This is flawy as we just rely on order to match
					if msg.Status == "bounced" && len(msg.BounceId) == 0 {
						message := Message{
							Time:     msg.Time,
							To:       msg.To,
							Status:   msg.Status,
							Message:  msg.Message,
							BounceId: logFormat.BounceId,
						}
						// Delete old message, put new at the end
						copy(plp.Messages[i:], plp.Messages[i+1:])
						plp.Messages[len(plp.Messages)-1] = message
						break
					}
				}
			}
		}
		/*
			Oct 10 04:02:08 mail.example.com postfix/qmgr[18719]: DFBEFDBF00C5: removed
				or
			2021-02-05T14:17:51+01:00 smtp.server.com postfix/cleanup[38982]: D8C136A3A: milter-reject: END-OF-MESSAGE from unknown[1.2.3.4]: 4.7.1 Greylisting in action, try again later; from=<sender1@sender.com> to=<dest1@example.com> proto=ESMTP helo=<mail.sender.com>
		*/
		// "removed" message is end of logs. then flush.
		if logFormat.Messages == "removed" || strings.HasPrefix(logFormat.Status, "milter-") {
			if plp, ok := m[logFormat.QueueId]; ok {
				for _, plpf := range PlpToFlat(plp) {
					switch plpf.Status {
					case "sent":
						MsgSentCnt.WithLabelValues(plpf.Hostname).Inc()
					case "milter-reject":
						MsgRejectedCnt.WithLabelValues(plpf.Hostname).Inc()
					case "milter-hold":
						MsgHoldCnt.WithLabelValues(plpf.Hostname).Inc()
					case "bounced":
						MsgBouncedCnt.WithLabelValues(plpf.Hostname).Inc()
					}

					if gFlatten {
						jsonBytes, err := json.Marshal(plpf)
						if err != nil {
							log.Fatal(err)
						}
						mtx.Lock()
						err = writeOut(string(jsonBytes), gOutputFile)
						mtx.Unlock()
						if err != nil {
							log.Fatal(err)
						}
					}
				}

				if !gFlatten {
					jsonBytes, err := json.Marshal(plp)
					if err != nil {
						log.Fatal(err)
					}
					mtx.Lock()
					err = writeOut(string(jsonBytes), gOutputFile)
					mtx.Unlock()
					if err != nil {
						log.Fatal(err)
					}
				}
			}
		}
	}
	if File != nil {
		mtx.Lock()
		File.Close()
		mtx.Unlock()
	}
}
