package rfc5424

import (
  . "github.com/go-check/check"
  "time"
  "testing"
  message "github.com/jeromer/syslogparser/message"
)

var sampleRfc5424Log []byte = []byte(`<94>1 2014-06-06T20:07:15.000000+00:00 webtest-mark simlogging 23456 ID47 [exampleSDID@32473 iut="9" eventSource="rawr" eventID="123"] This is a log.info() message in a fancy format`)

// Hooks up gocheck into the gotest runner.
func TestMessage(t *testing.T) { TestingT(t) }

type Rfc5424MessageTestSuite struct {
}

var _ = Suite(&Rfc5424MessageTestSuite{})

func (s *Rfc5424MessageTestSuite) TestMessageFromRfc5424(c *C) {
  parser := NewParser(sampleRfc5424Log)
  err := parser.Parse()
  if nil != err {
    c.Fatal(err)
  }
  var msg message.IMessage = parser.Message()
  c.Assert(string(sampleRfc5424Log), Equals, string(msg.RawMessage()))
  c.Assert("webtest-mark", Equals, msg.Hostname())
  c.Assert("This is a log.info() message in a fancy format", Equals, msg.Message())
  c.Assert(true, Equals, time.Unix(1402085235, 0).Equal(msg.TimeStamp()))
  c.Assert("simlogging", Equals, msg.Process())
  c.Assert(message.Info, Equals, msg.Severity())
  c.Assert(message.Ftp, Equals, msg.Facility())
  c.Assert("23456", Equals, msg.Pid())
}

func (s *Rfc5424MessageTestSuite) TestMessageCantParseMessage(c *C) {
  badMsg := []byte("FOO BAR BAZ")
  parser := NewParser(badMsg)
  err := parser.Parse()
  if nil == err {
    c.Fatal("Parsing was expected to fail, but did not")
  }
  var msg message.IMessage = parser.Message()
  c.Assert(string(badMsg), Equals, string(msg.RawMessage()))
  c.Assert("", Equals, msg.Hostname())
  c.Assert("", Equals, msg.Message())
  c.Assert(nil, Not(Equals), msg.TimeStamp())
  c.Assert("", Equals, msg.Process())
  c.Assert(message.SeverityUnknown, Equals, msg.Severity())
  c.Assert(message.FacilityUnknown, Equals, msg.Facility())
  c.Assert("", Equals, msg.Pid())
}
