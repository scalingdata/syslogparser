package rfc3164

import (
  message "github.com/jeromer/syslogparser/message"
  "time"
)

type Rfc3164Message struct {
  rawMsg []byte
  ts time.Time
  pid string
  facility message.Facility
  severity message.Severity
  process string
  hostname string
  message string
}

func (self Rfc3164Message) RawMessage() []byte { 
  return self.rawMsg 
}

func (self Rfc3164Message) TimeStamp() time.Time { 
  return self.ts
}

func (self Rfc3164Message) Pid() string { 
  return self.pid 
}

func (self Rfc3164Message) Facility() message.Facility { 
  return self.facility 
}

func (self Rfc3164Message) Severity() message.Severity { 
  return self.severity 
}

func (self Rfc3164Message) Process() string { 
  return self.process 
}

func (self Rfc3164Message) Hostname() string { 
  return self.hostname 
}

func (self Rfc3164Message) Message() string { 
  return self.message 
}

