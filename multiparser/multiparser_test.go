package multiparser

import (
  . "github.com/go-check/check"
  "strings"
  syslogmsg "github.com/jeromer/syslogparser/message"
  "testing"
  "time"
)

// Hooks up gocheck into the gotest runner.
func TestMutliParser(t *testing.T) { TestingT(t) }
type MultiParserTestSuite struct {}
var _ = Suite(&MultiParserTestSuite{})

var rfc3164ValidMsg []byte = []byte("<94>Jun 06 20:07:15 webtest-mark simlogging[17155]: This is a log.info() message")

func (s *MultiParserTestSuite) TestRfc3164Message(c *C) {
  parser := NewRfcParser(rfc3164ValidMsg)
  err := parser.Parse()
  if nil != err {
    c.Fatal(err)
  }
  msg := parser.Message()
  if nil == msg {
    c.Fatal("No log parts returned")
  }
  expectedTime := time.Unix(1402085235, 0)
  actualTime := msg.TimeStamp()
  c.Assert(true, Equals, expectedTime.Equal(actualTime))
  c.Assert("webtest-mark", Equals, msg.Hostname())
  c.Assert("This is a log.info() message", Equals, msg.Message())
  c.Assert("simlogging", Equals, msg.Process())
  c.Assert(syslogmsg.Ftp, Equals, msg.Facility())
  c.Assert(syslogmsg.Info, Equals, msg.Severity())
  c.Assert(string(rfc3164ValidMsg), Equals, string(msg.RawMessage()))
}

var rfc5424ValidMsg []byte = []byte(strings.TrimSpace(`<94>1 2014-06-06T20:07:15.000000+00:00 webtest-mark simlogging - ID47 [exampleSDID@32473 iut="9" eventSource="rawr" eventID="123"] This is a log.info() message in a fancy format`))

func (s *MultiParserTestSuite) TestRfc5424Message(c *C) {
  parser := NewRfcParser(rfc5424ValidMsg)
  err := parser.Parse()
  if nil != err {
    c.Fatal(err)
  }
  msg := parser.Message()
  if nil == msg {
    c.Fatal("No log parts returned")
  }
  expectedTime := time.Unix(1402085235, 0)
  actualTime := msg.TimeStamp()
  c.Assert(true, Equals, expectedTime.Equal(actualTime))
  c.Assert("webtest-mark", Equals, msg.Hostname())
  c.Assert(syslogmsg.Ftp, Equals, msg.Facility())
  c.Assert(syslogmsg.Info, Equals, msg.Severity())

  c.Assert("This is a log.info() message in a fancy format", Equals, msg.Message())
  c.Assert("simlogging", Equals, msg.Process())
  c.Assert(string(rfc5424ValidMsg), Equals, string(msg.RawMessage()))
}

func (s *MultiParserTestSuite) TestInvalidMessage(c *C) {
  parser := NewRfcParser([]byte("FOO BAR BAXLKDFLKSJDLFKJ"))
  err := parser.Parse()
  if nil != err {
    c.Fatal(err)
  }
  msg := parser.Message()
  if nil == msg {
    c.Fatal("No message returned")
  }
}
