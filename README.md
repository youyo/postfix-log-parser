# postfix-log-parser

Parse postfix log, and output json format

## Install

Place a `postfix-log-parser` command to your PATH and set an executable flag.  
Download the latest release from github. https://github.com/youyo/postfix-log-parser/releases/latest

## Usage

Input postfix logs as os stdin.

``` console
# cat /var/log/maillog | ./postfix-log-parser | jq
{
  "time": "0000-10-10T15:59:29+09:00",
  "hostname": "mail",
  "process": "postfix/smtpd[1827]",
  "queue_id": "3D74ADB7400B",
  "client_hostname": "example.com",
  "client_ip": "127.0.0.1",
  "message_id": "f93388828093534f92d85ffe21b2a719@example.info",
  "from": "test2@example.info",
  "messages": [
    {
      "time": "0000-10-10T15:59:30+09:00",
      "to": "test@example.to",
      "status": "sent",
      "message": "to=<test@example.to>, relay=example.to[192.168.0.20]:25, delay=1.7, delays=0.02/0/1.7/0.06, dsn=2.0.0, status=sent (250 [Sniper] OK 1539154772 snipe-queue 10549)"
    },
    {
      "time": "0000-10-10T15:59:30+09:00",
      "to": "test2@example.to",
      "status": "sent",
      "message": "to=<test2@example.to>, relay=example.to[192.168.0.20]:25, delay=1.7, delays=0.02/0/1.7/0.06, dsn=2.0.0, status=sent (250 [Sniper] OK 1539154772 snipe-queue 10549)"
    }
  ]
}
.
.
.
```

Use -f flag to flatten json structure:

``` console
# cat /var/log/maillog | ./postfix-log-parser -f | jq
{
  "time": "0000-10-10T15:59:29+09:00",
  "hostname": "mail",
  "process": "postfix/smtpd[1827]",
  "queue_id": "3D74ADB7400B",
  "client_hostname": "example.com",
  "client_ip": "127.0.0.1",
  "message_id": "f93388828093534f92d85ffe21b2a719@example.info",
  "from": "test2@example.info",
  "time_sent": "0000-10-10T15:59:30+09:00",
  "to": "test@example.to",
  "status": "sent",
  "message": "to=<test@example.to>, relay=example.to[192.168.0.20]:25, delay=1.7, delays=0.02/0/1.7/0.06, dsn=2.0.0, status=sent (250 [Sniper] OK 1539154772 snipe-queue 10549)"
}
{
  "time": "0000-10-10T15:59:29+09:00",
  "hostname": "mail",
  "process": "postfix/smtpd[1827]",
  "queue_id": "3D74ADB7400B",
  "client_hostname": "example.com",
  "client_ip": "127.0.0.1",
  "message_id": "f93388828093534f92d85ffe21b2a719@example.info",
  "from": "test2@example.info",
  "time_sent": "0000-10-10T15:59:30+09:00",
  "to": "test2@example.to",
  "status": "sent",
  "message": "to=<test2@example.to>, relay=example.to[192.168.0.20]:25, delay=1.7, delays=0.02/0/1.7/0.06, dsn=2.0.0, status=sent (250 [Sniper] OK 1539154772 snipe-queue 10549)"
}
.
.
.
```

Use "-o filename.json" to write output to file.

## Piping rsyslog to postfix-log-parser

You can feed syslog to postfix-log-parser by using "omprog" rsyslog module, with template "RSYSLOG_FileFormat" :
``` console
module(load="omprog")
[...]
mail.info                                                       /var/log/maillog
& action(
    type="omprog"
    binary="/usr/local/bin/postfix-log-parser -f -o /var/log/maillog.json"
    template="RSYSLOG_FileFormat")

& stop

```


## Library usage

```
$ go get github.com/youyo/postfix-log-parser
```

``` main.go
package main

import (
	"github.com/k0kubun/pp"
	postfixlog "github.com/youyo/postfix-log-parser"
)

func main() {
	textByte := []byte("Oct 10 04:02:08 mail.example.com postfix/smtp[22928]: DFBEFDBF00C5: to=<test@example-to.com>, relay=mail.example-to.com[192.168.0.10]:25, delay=5.3, delays=0.26/0/0.31/4.7, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as C598F1B0002D)")

	p := postfixlog.NewPostfixLog()
	logFormat, _ := p.Parse(textByte)
	pp.Println(logFormat)
}
```

```
$ go run main.go
postfixlog.LogFormat{
  Time:           &0-10-10 04:02:08 Local,
  Hostname:       "mail.example.com",
  Process:        "postfix/smtp[22928]",
  QueueId:        "DFBEFDBF00C5",
  Messages:       "to=<test@example-to.com>, relay=mail.example-to.com[192.168.0.10]:25, delay=5.3, delays=0.26/0/0.31/4.7, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as C598F1B0002D)",
  ClientHostname: "",
  ClinetIp:       "",
  MessageId:      "",
  From:           "",
  To:             "test@example-to.com",
  Status:         "sent",
}
```
