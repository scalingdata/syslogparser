package rfc3164

import (
  . "github.com/scalingdata/check"
  "time"
  "testing"
  message "github.com/scalingdata/syslogparser/message"
)

// Hooks up gocheck into the gotest runner.
func TestMessage(t *testing.T) { TestingT(t) }

var sampleRfc3164Log = []byte("<94>Jun 06 20:07:15 webtest-mark simlogging[17155]: This is a log.info() message")

type Rfc3164MessageTestSuite struct {
}

var _ = Suite(&Rfc3164MessageTestSuite{})

func (s *Rfc3164MessageTestSuite) TestMessageFromRfc3164(c *C) {
  parser := NewParser(&sampleRfc3164Log)
  err := parser.Parse()
  if nil != err {
    c.Fatal(err)
  }
  var msg message.IMessage = parser.Message()
  c.Assert(string(sampleRfc3164Log), Equals, string(*msg.RawMessage()))
  c.Assert("webtest-mark", Equals, msg.Hostname())
  c.Assert("This is a log.info() message", Equals, msg.Message())
  c.Assert(true, Equals, time.Unix(1402085235, 0).Equal(msg.TimeStamp()))
  c.Assert("simlogging", Equals, msg.Process())
  c.Assert(message.Info, Equals, msg.Severity())
  c.Assert(message.Ftp, Equals, msg.Facility())
  c.Assert("", Equals, msg.Pid())
}

func (s *Rfc3164MessageTestSuite) TestMessageCantParseMessage(c *C) {
  badMsg := []byte("FOO BAR BAZ")
  parser := NewParser(&badMsg)
  err := parser.Parse()
  if nil == err {
    c.Fatal("Parsing was expected to fail, but did not")
  }
  var msg message.IMessage = parser.Message()
  c.Assert(string(badMsg), Equals, string(*msg.RawMessage()))
  c.Assert("", Equals, msg.Hostname())
  c.Assert("", Equals, msg.Message())
  c.Assert(nil, Not(Equals), msg.TimeStamp())
  c.Assert("", Equals, msg.Process())
  c.Assert(message.SeverityUnknown, Equals, msg.Severity())
  c.Assert(message.FacilityUnknown, Equals, msg.Facility())
  c.Assert("", Equals, msg.Pid())
}

