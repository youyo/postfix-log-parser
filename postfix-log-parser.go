package postfixlog

import (
	"errors"
	"regexp"
	"time"
)

const (
	SyslogPri                  = `(?:<\d{1,3}>)?`
	TimeFormat                 = "Jan  2 15:04:05"
	TimeFormatISO8601          = "2006-01-02T15:04:05.999999-07:00"
	TimeRegexpFormat           = `([A-Za-z]{3}\s*[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}|^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:[+-][0-2]\d:[0-5]\d|Z))`
	HostRegexpFormat           = `([0-9A-Za-z\-\.]*)`
	ProcessRegexpFormat        = `(postfix.*(?:\/[a-z]*)+\[[0-9]{1,5}\])?`
	QueueIdRegexpFormat        = `([0-9A-Z]*)`
	ClientRegexpFormat         = `(?:client=(.+)\[(.+)\](?:, sasl_method=(.+), sasl_username=(.+))?)?`
	MessageIdRegexpFormat      = `(?:message-id=<(.+)>)?`
	FromRegexpFormat           = `(?:from=<(.+@.+)>(?:, size=(\d+), nrcpt=(\d+))?)?`
	ToRegexpFormat             = `(?:to=<(.+@.+)>.*status=([a-z]+))?`
	SenderNDNRegexpFormat      = `(?:sender non-delivery notification: ([0-9A-Z]*))?`
	MilterRegexpFormat         = `(?:(milter-.*): .* from (.+)\[(.+)\]: .*from=<(.+@.+)?> to=<(.+@.+)> .*)?`
	AuthentFailedRegexpFormat  = `(?:warning: (.+)\[(.+)\]: SASL (.*) authentication failed: (.*))?`
	PostfixRejectRegexpFormat  = `(?:reject: RCPT from (.+)\[(.+)\]: [0-9]{3} [0-9\.]{5} [^;]*; from=<(.+@.+)?> to=<(.+@[^>]+)>.*$)?`
	MessageDetailsRegexpFormat = `(` + ClientRegexpFormat + MessageIdRegexpFormat + FromRegexpFormat + ToRegexpFormat + SenderNDNRegexpFormat + MilterRegexpFormat + AuthentFailedRegexpFormat + PostfixRejectRegexpFormat + `.*)`
	RegexpFormat               = SyslogPri + TimeRegexpFormat + ` ` + HostRegexpFormat + ` ` + ProcessRegexpFormat + `:? ` + QueueIdRegexpFormat + `(?:\: )?` + MessageDetailsRegexpFormat
)

type (
	PostfixLog struct {
		LogFormat LogFormat
		Regexp    *regexp.Regexp
	}

	LogFormat struct {
		Time           *time.Time `json:"time"`
		Hostname       string     `json:"hostname"`
		Process        string     `json:"process"`
		QueueId        string     `json:"queue_id"`
		Messages       string     `json:"messages"`
		ClientHostname string     `json:"client_hostname"`
		ClinetIp       string     `json:"client_ip"`
		SaslMethod     string     `json:"sasl_method"`
		SaslUsername   string     `json:"sasl_username"`
		MessageId      string     `json:"message_id"`
		From           string     `json:"from"`
		Size           string     `json:"size"`
		NRcpt          string     `json:"nrcpt"`
		To             string     `json:"to"`
		Status         string     `json:"status"`
		BounceId       string     `json:"bounce_id"`
	}
)

func NewPostfixLog() *PostfixLog {
	return &PostfixLog{
		Regexp: regexp.MustCompile(RegexpFormat),
	}
}

func (p *PostfixLog) Parse(text []byte) (LogFormat, error) {
	re := p.Regexp.Copy()
	group := re.FindSubmatch(text)
	if len(group) == 0 {
		err := errors.New("Error: Line do not match regex")
		return LogFormat{}, err
	}
	var t time.Time
	t, err := time.ParseInLocation(TimeFormat, string(group[1]), time.Local)
	if err != nil {
		t, err = time.ParseInLocation(TimeFormatISO8601, string(group[1]), time.Local)
		if err != nil {
			return LogFormat{}, err
		}
	}

	logFormat := LogFormat{
		Time:         &t,
		Hostname:     string(group[2]),
		Process:      string(group[3]),
		QueueId:      string(group[4]),
		Messages:     string(group[5]),
		SaslMethod:   string(group[8]),
		SaslUsername: string(group[9]),
		MessageId:    string(group[10]),
		Size:         string(group[12]),
		NRcpt:        string(group[13]),
		BounceId:     string(group[16]),
	}

	// Milter reject|hold put values far in the group
	if len(group[17]) > 0 {
		logFormat.Status = string(group[17])
		logFormat.ClientHostname = string(group[18])
		logFormat.ClinetIp = string(group[19])
		logFormat.From = string(group[20])
		logFormat.To = string(group[21])
	// Authentication failure
	} else if len(group[22]) > 0 {
		logFormat.ClientHostname = string(group[22])
		logFormat.ClinetIp = string(group[23])
		logFormat.SaslMethod = string(group[24])
		logFormat.Status = "auth-failed"
	// postfix-reject
	} else if len(group[26]) > 0 {
		logFormat.ClientHostname = string(group[26])
		logFormat.ClinetIp = string(group[27])
		logFormat.From = string(group[28])
		logFormat.To = string(group[29])
		logFormat.Status = "postfix-reject"
	} else {
		logFormat.Status = string(group[15])
		logFormat.ClientHostname = string(group[6])
		logFormat.ClinetIp = string(group[7])
		logFormat.From = string(group[11])
		logFormat.To = string(group[14])
	}

	return logFormat, nil
}
