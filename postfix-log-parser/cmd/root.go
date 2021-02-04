package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"
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
		MessageId      string     `json:"message_id"`
		From           string     `json:"from"`
		Messages       []Message  `json:"messages"`
	}

	Message struct {
		Time    *time.Time `json:"time"`
		To      string     `json:"to"`
		Status  string     `json:"status"`
		Message string     `json:"message"`
	}

	PostfixLogParserFlat struct {
		Time           *time.Time `json:"timestamp"`
		Hostname       string     `json:"hostname"`
		Process        string     `json:"process"`
		QueueId        string     `json:"queue_id"`
		ClientHostname string     `json:"client_hostname"`
		ClinetIp       string     `json:"client_ip"`
		MessageId      string     `json:"message_id"`
		From           string     `json:"from"`
		TimeSent       *time.Time `json:"time_sent"`
		To             string     `json:"to"`
		Status         string     `json:"status"`
		Message        string     `json:"message"`
	}
)

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
			MessageId:      plp.MessageId,
			From:           plp.From,
			TimeSent:       plp.Messages[i].Time,
			To:             plp.Messages[i].To,
			Status:         plp.Messages[i].Status,
			Message:        plp.Messages[i].Message,
		}
	}

	return plpf
}

func NewCmdRoot() *cobra.Command {
	var flatten bool
	var outputFile string
	var wtr *bufio.Writer

	cmd := &cobra.Command{
		Use:   "postfix-log-parser",
		Short: "Parse postfix log, and output json format",
		//Long: ``,
		Run: func(cmd *cobra.Command, args []string) {

			// create queue
			m := make(map[string]*PostfixLogParser)

			// initialize
			p := postfixlog.NewPostfixLog()

			// writer, either file or stdout
			if len(outputFile) > 0 {
				var f *os.File
				var err error
				if _, err = os.Stat(outputFile); err == nil {
					f, err = os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0640)
				} else if os.IsNotExist(err) {
					f, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY, 0640)
				}
				if err != nil {
					cmd.SetOutput(os.Stderr)
					cmd.Println(err)
					os.Exit(1)
				}
				wtr = bufio.NewWriter(f)
				defer f.Close()
			} else {
				wtr = bufio.NewWriter(os.Stdout)
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
					Oct 10 04:02:02 mail.example.com postfix/smtpd[22941]: DFBEFDBF00C5: client=example.net[127.0.0.1]
				*/
				if logFormat.ClientHostname != "" {
					m[logFormat.QueueId] = &PostfixLogParser{
						Time:           logFormat.Time,
						Hostname:       logFormat.Hostname,
						Process:        logFormat.Process,
						QueueId:        logFormat.QueueId,
						ClientHostname: logFormat.ClientHostname,
						ClinetIp:       logFormat.ClinetIp,
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
					}
				}

				/*
					Oct 10 04:02:08 mail.example.com postfix/smtp[22928]: DFBEFDBF00C5: to=<test@example-to.com>, relay=mail.example-to.com[192.168.0.10]:25, delay=5.3, delays=0.26/0/0.31/4.7, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as C598F1B0002D)
				*/
				if logFormat.To != "" {
					if plp, ok := m[logFormat.QueueId]; ok {
						message := Message{
							Time:    logFormat.Time,
							To:      logFormat.To,
							Status:  logFormat.Status,
							Message: logFormat.Messages,
						}

						plp.Messages = append(plp.Messages, message)
					}
				}

				/*
					Oct 10 04:02:08 mail.example.com postfix/qmgr[18719]: DFBEFDBF00C5: removed
				*/
				// "removed" message is end of logs. then flush.
				if logFormat.Messages == "removed" {
					if plp, ok := m[logFormat.QueueId]; ok {
						if flatten {
							// Flatten the structure, then print each message
							for _, plpf := range PlpToFlat(plp) {
								jsonBytes, err := json.Marshal(plpf)
								if err != nil {
									log.Fatal(err)
								}
								fmt.Fprintln(wtr, string(jsonBytes))
								wtr.Flush()
							}
						} else {
							jsonBytes, err := json.Marshal(plp)
							if err != nil {
								log.Fatal(err)
							}
							fmt.Fprintln(wtr, string(jsonBytes))
							wtr.Flush()
						}
					}
				}

			}
		},
	}

	cmd.Flags().BoolVarP(&flatten, "flatten", "f", false, "Flatten output for using with syslog")
	cmd.Flags().StringVarP(&outputFile, "out", "o", "", "Output to file, append if exists")

	cobra.OnInitialize(initConfig)
	return cmd
}
