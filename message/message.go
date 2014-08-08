package message

import (
  "time"
)

type IMessage interface {
  RawMessage() *[]byte
  TimeStamp() time.Time
  /* Common sense says that the pid should be an int, but in practice that would require
     taking the string the syslogparser module gives, converting it to an int, and 
     then converting it into a string as that's how it's stored in the attributes map.
     tl/dr - using int would result in string->int->string conversion on each message. */
  Pid() string
  Facility() Facility
  Severity() Severity
  Process() string
  Hostname() string
  Message() string
}


type UnparsableMessage struct {
  rawMsg *[]byte
  ts time.Time
}
func NewUnparsableMessage(rawMsg *[]byte) *UnparsableMessage {
  return &UnparsableMessage{rawMsg, time.Now().UTC()}
}
// SD-248: default values to should conform to RFC
func (self *UnparsableMessage) RawMessage() *[]byte { return self.rawMsg }
func (self *UnparsableMessage) TimeStamp() time.Time { return self.ts }
func (self *UnparsableMessage) Pid() string { return "" }
func (self *UnparsableMessage) Facility() Facility { return FacilityUnknown }
func (self *UnparsableMessage) Severity() Severity { return SeverityUnknown }
func (self *UnparsableMessage) Process() string { return "" }
func (self *UnparsableMessage) Hostname() string { return "" }
func (self *UnparsableMessage) Message() string { return ""}
