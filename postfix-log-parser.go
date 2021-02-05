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
	MessageDetailsRegexpFormat = `((?:client=(.+)\[(.+)\](?:, sasl_method=(.+), sasl_username=(.+))?)?(?:message-id=<(.+)>)?(?:from=<(.+@.+)>(?:, size=(\d+), nrcpt=(\d+))?)?(?:to=<(.+@.+)>.*status=([a-z]+))?.*)`
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
		Time:           &t,
		Hostname:       string(group[2]),
		Process:        string(group[3]),
		QueueId:        string(group[4]),
		Messages:       string(group[5]),
		ClientHostname: string(group[6]),
		ClinetIp:       string(group[7]),
		SaslMethod:     string(group[8]),
		SaslUsername:   string(group[9]),
		MessageId:      string(group[10]),
		From:           string(group[11]),
		Size:           string(group[12]),
		NRcpt:          string(group[13]),
		To:             string(group[14]),
		Status:         string(group[15]),
	}

	return logFormat, nil
}
