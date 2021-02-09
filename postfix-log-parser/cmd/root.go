package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

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

var File os.File
var Writer *bufio.Writer

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
	if err != nil {
		return err
	}
	return nil
}

func NewCmdRoot() *cobra.Command {
	var flatten bool
	var outputFile string
	var pidfilepath string
	var mtx sync.Mutex

	cmd := &cobra.Command{
		Use:   "postfix-log-parser",
		Short: "Parse postfix log, and output json format",
		//Long: ``,
		Run: func(cmd *cobra.Command, args []string) {

			if len(pidfilepath) > 0 {
				if pid, err := pidfile.Create(pidfilepath); err != nil {
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
			Writer, File, err := NewWriter(outputFile)
			if err != nil {
				cmd.SetOutput(os.Stderr)
				cmd.Println(err)
				os.Exit(1)
			}

			// Manage output file rotation when receiving SIGUSR1
			if len(outputFile) > 0 {
				sig := make(chan os.Signal)
				signal.Notify(sig, syscall.SIGUSR1)
				go func() {
					for {
						<-sig
						mtx.Lock()
						fmt.Println("SIGUSR1 received, recreating output file")
						//Writer.Flush()	// Done by File.CLose()
						File.Close()
						Writer, File, err = NewWriter(outputFile)
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

			// input stdin
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {

				// parse log
				logFormat, err := p.Parse(scanner.Bytes())
				if err != nil {
					// Incorrect line, just skip it
					if err.Error() == "Error: Line do not match regex" {
						continue
					}
					cmd.SetOutput(os.Stderr)
					cmd.Println(err)
					os.Exit(1)
				}

				/*
					Oct 10 04:02:02 mail.example.com postfix/smtpd[22941]: DFBEFDBF00C5: client=example.net[127.0.0.1], sasl_method=PLAIN, sasl_username=user@example.com
				*/
				if logFormat.ClientHostname != "" {
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
							if flatten {
								jsonBytes, err = json.Marshal(PlpToFlat(&tmpplp))
							} else {
								jsonBytes, err = json.Marshal(tmpplp)
							}
							if err != nil {
								log.Fatal(err)
							}
							mtx.Lock()
							err = writeOut(string(jsonBytes), outputFile)
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
				if logFormat.Messages == "removed" || logFormat.Status == "milter-reject" {
					if plp, ok := m[logFormat.QueueId]; ok {
						if flatten {
							// Flatten the structure, then print each message
							for _, plpf := range PlpToFlat(plp) {
								jsonBytes, err := json.Marshal(plpf)
								if err != nil {
									log.Fatal(err)
								}
								mtx.Lock()
								err = writeOut(string(jsonBytes), outputFile)
								mtx.Unlock()
								if err != nil {
									log.Fatal(err)
								}
							}
						} else {
							jsonBytes, err := json.Marshal(plp)
							if err != nil {
								log.Fatal(err)
							}
							mtx.Lock()
							err = writeOut(string(jsonBytes), outputFile)
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
		},
	}

	cmd.Flags().BoolVarP(&flatten, "flatten", "f", false, "Flatten output for using with syslog")
	cmd.Flags().StringVarP(&outputFile, "out", "o", "", "Output to file, append if exists")
	cmd.Flags().StringVarP(&pidfilepath, "pidfile", "p", "", "pid file path")

	cobra.OnInitialize(initConfig)
	return cmd
}
