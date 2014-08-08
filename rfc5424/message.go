package rfc5424

import (
  message "github.com/scalingdata/syslogparser/message"
  "time"
)

type Rfc5424Message struct {
  rawMsg *[]byte
  ts time.Time
  pid string
  facility message.Facility
  severity message.Severity
  hostname string
  message string
  appName string
  version int
  msgId string
  structuredData string
}

func (self Rfc5424Message) RawMessage() *[]byte {
  return self.rawMsg
}

func (self Rfc5424Message) TimeStamp() time.Time {
  return self.ts
}

func (self Rfc5424Message) Pid() string {
  return self.pid
}

func (self Rfc5424Message) Facility() message.Facility {
  return self.facility
}

func (self Rfc5424Message) Severity() message.Severity {
  return self.severity
}

func (self Rfc5424Message) Hostname() string {
  return self.hostname
}

func (self Rfc5424Message) Message() string {
  return self.message
}

func (self Rfc5424Message) Process() string {
  return self.appName
}

