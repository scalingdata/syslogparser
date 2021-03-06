package rfc3164

import (
  . "github.com/scalingdata/check"
  "time"
  "testing"
  message "github.com/scalingdata/syslogparser/message"
)

// Hooks up gocheck into the gotest runner.
func TestMessage(t *testing.T) { TestingT(t) }

var (
  sampleRfc3164Log = []byte("<94>Jun 06 20:07:15 webtest-mark simlogging[17155]: This is a log.info() message")
  testDate = func() time.Time { return time.Date(2015, 6, 6, 0, 0, 0, 0, time.Now().Location()) } 
)

type Rfc3164MessageTestSuite struct {
  originalLocale *time.Location
}

var _ = Suite(&Rfc3164MessageTestSuite{})

func (s *Rfc3164MessageTestSuite) SetUpTest(c *C) {
  s.originalLocale = time.Local
  time.Local = time.UTC
}

func (s *Rfc3164MessageTestSuite) TearDownTest(c *C) {
  time.Local = s.originalLocale
}

func (s *Rfc3164MessageTestSuite) TestMessageFromRfc3164(c *C) {
  parser := NewParser(&sampleRfc3164Log)
  parser.TimeFunction = testDate
  err := parser.Parse()
  if nil != err {
    c.Fatal(err)
  }
  var msg message.IMessage = parser.Message()
  c.Assert(string(sampleRfc3164Log), Equals, string(*msg.RawMessage()))
  c.Assert("webtest-mark", Equals, msg.Hostname())
  c.Assert("This is a log.info() message", Equals, msg.Message())
  c.Assert(time.Date(2015, 6, 6, 20, 7, 15, 0, time.Now().Location()), Equals, msg.TimeStamp())
  c.Assert("simlogging", Equals, msg.Process())
  c.Assert(message.Info, Equals, msg.Severity())
  c.Assert(message.Ftp, Equals, msg.Facility())
  c.Assert("17155", Equals, msg.Pid())
}

func (s *Rfc3164MessageTestSuite) TestMessageCantParseMessage(c *C) {
  badMsg := []byte("FOO BAR BAZ")
  parser := NewParser(&badMsg)
  parser.TimeFunction = testDate
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

/* Test recieving a mesaage from slightly in the past, over a year boundary */
func (s *Rfc3164MessageTestSuite) TestMessageFromDecemberInJanuary(c *C) {
  log := []byte("<94>Dec 29 20:07:15 webtest-mark simlogging[17155]: This is a log.info() message")
  testDecDate := func() time.Time { return time.Date(2015, 1, 2, 0, 0, 0, 0, time.Now().Location()) } 

  parser := NewParser(&log)
  parser.TimeFunction = testDecDate
  err := parser.Parse()
  if nil != err {
    c.Fatal(err)
  }
  var msg message.IMessage = parser.Message()
  c.Assert(time.Date(2014, 12, 29, 20, 7, 15, 0, time.Now().Location()), Equals, msg.TimeStamp())
}

/* Test recieving a message from slightly in the future, over a year boundary */
func (s *Rfc3164MessageTestSuite) TestMessageFromJanuaryInDecember(c *C) {
  log := []byte("<94>Jan 01 20:07:15 webtest-mark simlogging[17155]: This is a log.info() message")
  testJanDate := func() time.Time { return time.Date(2015, 12, 29, 0, 0, 0, 0, time.Now().Location()) } 

  parser := NewParser(&log)
  parser.TimeFunction = testJanDate
  err := parser.Parse()
  if nil != err {
    c.Fatal(err)
  }
  var msg message.IMessage = parser.Message()
  c.Assert(time.Date(2016, 1, 1, 20, 7, 15, 0, time.Now().Location()), Equals, msg.TimeStamp())
}
