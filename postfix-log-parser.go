package postfixlog

import (
	"regexp"
	"time"
)

const (
	TimeFormat                 = "Jan  2 15:04:05"
	TimeRegexpFormat           = `([A-Za-z]{3}\s*[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2})`
	HostRegexpFormat           = `([0-9A-Za-z\.]*)`
	ProcessRegexpFormat        = `(postfix/[a-z]*\[[0-9]{1,5}\])?`
	QueueIdRegexpFormat        = `([0-9A-Z]*)`
	MessageDetailsRegexpFormat = `((?:client=(.+)\[(.+)\])?(?:message-id=<(.+)>)?(?:from=<(.+@.+)>)?(?:to=<(.+@.+)>.*status=([a-z]+))?.*)`
	RegexpFormat               = TimeRegexpFormat + ` ` + HostRegexpFormat + ` ` + ProcessRegexpFormat + `: ` + QueueIdRegexpFormat + `(?:\: )?` + MessageDetailsRegexpFormat
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
		MessageId      string     `json:"message_id"`
		From           string     `json:"from"`
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
	t, err := time.ParseInLocation(TimeFormat, string(group[1]), time.Local)
	if err != nil {
		return LogFormat{}, err
	}

	logFormat := LogFormat{
		Time:           &t,
		Hostname:       string(group[2]),
		Process:        string(group[3]),
		QueueId:        string(group[4]),
		Messages:       string(group[5]),
		ClientHostname: string(group[6]),
		ClinetIp:       string(group[7]),
		MessageId:      string(group[8]),
		From:           string(group[9]),
		To:             string(group[10]),
		Status:         string(group[11]),
	}

	return logFormat, nil
}
