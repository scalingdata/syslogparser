package rfc3164

import (
  "bytes"
  "github.com/scalingdata/syslogparser"
  "strings"
  . "github.com/scalingdata/check"
  "testing"
  "time"
)

// Hooks up gocheck into the gotest runner.
func Test(t *testing.T) { TestingT(t) }

type Rfc3164TestSuite struct {
}

var (
  _ = Suite(&Rfc3164TestSuite{})

  // XXX : corresponds to the length of the last tried timestamp format
  // XXX : Jan  2 15:04:05
  lastTriedTimestampLen = 15
)

func (s *Rfc3164TestSuite) TestParser_Valid(c *C) {
  buff := []byte("<34>Oct 11 22:14:15 mymachine very.large.syslog.message.tag[17155]: 'su root' failed for lonvick on /dev/pts/8")

  p := NewParser(&buff)
  expectedP := &Parser{
    buff:   buff,
    cursor: 0,
    l:      len(buff),
  }

  c.Assert(p, DeepEquals, expectedP)

  err := p.Parse()
  c.Assert(err, IsNil)

  now := time.Now()

  obtained := p.Dump()
  expected := syslogparser.LogParts{
    "timestamp": time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC),
    "hostname":  "mymachine",
    "tag":       "very.large.syslog.message.tag",
    "content":   "'su root' failed for lonvick on /dev/pts/8",
    "priority":  34,
    "facility":  4,
    "severity":  2,
    "proc_id": "17155",
  }

  c.Assert(obtained, DeepEquals, expected)
}

func (s *Rfc3164TestSuite) TestParseHeader_Valid(c *C) {
  buff := []byte("Oct 11 22:14:15 mymachine ")
  now := time.Now()
  hdr := header{
    timestamp: time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC),
    hostname:  "mymachine",
  }

  s.assertRfc3164Header(c, hdr, buff, 25, nil)
}

func (s *Rfc3164TestSuite) TestParseHeader_InvalidTimestamp(c *C) {
  buff := []byte("Oct 34 32:72:82 mymachine ")
  hdr := header{}

  s.assertRfc3164Header(c, hdr, buff, lastTriedTimestampLen+1, syslogparser.ErrTimestampUnknownFormat)
}

func (s *Rfc3164TestSuite) TestParsemessage_Valid(c *C) {
  content := "foo bar baz blah quux"
  buff := []byte("sometag[1234]: " + content)
  hdr := rfc3164message{
    tag:     "sometag",
    content: content,
    procId: "1234",
  }

  s.assertRfc3164message(c, hdr, buff, len(buff), syslogparser.ErrEOL)
}

func (s *Rfc3164TestSuite) TestParseTimestamp_Invalid(c *C) {
  buff := []byte("Oct 34 32:72:82")
  ts := new(time.Time)

  s.assertTimestamp(c, *ts, buff, lastTriedTimestampLen, syslogparser.ErrTimestampUnknownFormat)
}

func (s *Rfc3164TestSuite) TestParseTimestamp_TrailingSpace(c *C) {
  // XXX : no year specified. Assumed current year
  // XXX : no timezone specified. Assume UTC
  buff := []byte("Oct 11 22:14:15 ")

  now := time.Now()
  ts := time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC)

  s.assertTimestamp(c, ts, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTimestamp_OneDigitForMonths(c *C) {
  // XXX : no year specified. Assumed current year
  // XXX : no timezone specified. Assume UTC
  buff := []byte("Oct  1 22:14:15")

  now := time.Now()
  ts := time.Date(now.Year(), time.October, 1, 22, 14, 15, 0, time.UTC)

  s.assertTimestamp(c, ts, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTimestamp_Valid(c *C) {
  // XXX : no year specified. Assumed current year
  // XXX : no timezone specified. Assume UTC
  buff := []byte("Oct 11 22:14:15")

  now := time.Now()
  ts := time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC)

  s.assertTimestamp(c, ts, buff, len(buff), nil)
}

func (s *Rfc3164TestSuite) TestParseTag_Pid(c *C) {
  buff := []byte("apache2[10]:")
  tag := "apache2"
  s.assertTag(c, tag, buff, len(buff) - 5, nil)
}

func (s *Rfc3164TestSuite) TestParseTag_TrailingNoPid(c *C) {
  buff := []byte("apache2: ")
  tag := "apache2"
  s.assertTag(c, tag, buff, len(buff) - 2, nil)
}

func (s *Rfc3164TestSuite) TestParseContent_Valid(c *C) {
  buff := []byte(" foo bar baz quux ")
  content := string(bytes.Trim(buff, " "))

  p := NewParser(&buff)
  pid, obtained, err := p.parseContent()
  c.Assert(err, Equals, syslogparser.ErrEOL)
  c.Assert(obtained, Equals, content)
  c.Assert(pid, Equals, "")
  c.Assert(p.cursor, Equals, len(buff))
}

func (s *Rfc3164TestSuite) TestParseContent_ValidWithPid(c *C) {
  buff := []byte("[17155]:  foo bar baz quux ")
  content := string(strings.Trim(" foo bar baz quux ", " "))

  p := NewParser(&buff)
  pid, obtained, err := p.parseContent()
  c.Assert(err, Equals, syslogparser.ErrEOL)
  c.Assert(obtained, Equals, content)
  c.Assert(pid, Equals, "17155")
  c.Assert(p.cursor, Equals, len(buff))
}

func (s *Rfc3164TestSuite) TestParseContent_NoClosingPid(c *C) {
  buff := []byte("[17155234234")
  content := string(buff)

  p := NewParser(&buff)
  pid, obtained, err := p.parseContent()
  c.Assert(err, Equals, syslogparser.ErrEOL)
  c.Assert(obtained, Equals, content)
  c.Assert(pid, Equals, "")
}

func (s *Rfc3164TestSuite) TestParseContent_NoMessage(c *C) {
  buff := []byte("")
  p := NewParser(&buff)
  pid, obtained, err := p.parseContent()
  c.Assert(err, Equals, syslogparser.ErrEOL)
  c.Assert(obtained, Equals, "")
  c.Assert(pid, Equals, "")
}

func (s *Rfc3164TestSuite) TestParseContent_VariousSeps(c *C) {
  for _, msg := range []string{"[10]somestuff", "[10]:somestuff", "[10] somestuff", "[10]: somestuff"} {
    bytes := []byte(msg)
    p := NewParser(&bytes)
    pid, obtained, err := p.parseContent()
    c.Assert(err, Equals, syslogparser.ErrEOL)
    c.Assert(obtained, Equals, "somestuff")
    c.Assert(pid, Equals, "10")
  }
}

func (s *Rfc3164TestSuite) TestParseContent_PidExtraOpenBracket(c *C) {
  buff := []byte("[10[12]")
  p := NewParser(&buff)
  pid, obtained, err := p.parseContent()
  c.Assert(err, Equals, syslogparser.ErrEOL)
  c.Assert(obtained, Equals, "[10[12]")
  c.Assert(pid, Equals, "")
}

func (s *Rfc3164TestSuite) TestParseContent_PidMultipleEntries(c *C) {
  buff := []byte("[10][12] some message")
  p := NewParser(&buff)
  pid, obtained, err := p.parseContent()
  c.Assert(err, Equals, syslogparser.ErrEOL)
  c.Assert(obtained, Equals, "[12] some message")
  c.Assert(pid, Equals, "10")
}

func (s *Rfc3164TestSuite) TestParseContent_NoPidOrMsgButSep(c *C) {
  buff := []byte(":")
  p := NewParser(&buff)
  pid, obtained, err := p.parseContent()
  c.Assert(err, Equals, syslogparser.ErrEOL)
  c.Assert(obtained, Equals, "")
  c.Assert(pid, Equals, "")
}

func (s *Rfc3164TestSuite) BenchmarkParseTimestamp(c *C) {
  buff := []byte("Oct 11 22:14:15")

  p := NewParser(&buff)

  for i := 0; i < c.N; i++ {
    _, err := p.parseTimestamp()
    if err != nil {
      panic(err)
    }

    p.cursor = 0
  }
}

func (s *Rfc3164TestSuite) BenchmarkParseHostname(c *C) {
  buff := []byte("gimli.local")

  p := NewParser(&buff)

  for i := 0; i < c.N; i++ {
    _, err := p.parseHostname()
    if err != nil {
      panic(err)
    }

    p.cursor = 0
  }
}

func (s *Rfc3164TestSuite) BenchmarkParseTag(c *C) {
  buff := []byte("apache2[10]:")

  p := NewParser(&buff)

  for i := 0; i < c.N; i++ {
    _, err := p.parseTag()
    if err != nil {
      panic(err)
    }

    p.cursor = 0
  }
}

func (s *Rfc3164TestSuite) BenchmarkParseHeader(c *C) {
  buff := []byte("Oct 11 22:14:15 mymachine ")

  p := NewParser(&buff)

  for i := 0; i < c.N; i++ {
    _, err := p.parseHeader()
    if err != nil {
      panic(err)
    }

    p.cursor = 0
  }
}

func (s *Rfc3164TestSuite) BenchmarkParsemessage(c *C) {
  buff := []byte("sometag[123]: foo bar baz blah quux")

  p := NewParser(&buff)

  for i := 0; i < c.N; i++ {
    _, err := p.parsemessage()
    if err != syslogparser.ErrEOL {
      panic(err)
    }

    p.cursor = 0
  }
}

func (s *Rfc3164TestSuite) assertTimestamp(c *C, ts time.Time, b []byte, expC int, e error) {
  p := NewParser(&b)
  obtained, err := p.parseTimestamp()
  c.Assert(obtained, Equals, ts)
  c.Assert(p.cursor, Equals, expC)
  c.Assert(err, Equals, e)
}

func (s *Rfc3164TestSuite) assertTag(c *C, tag string, b []byte, expC int, e error) {
  p := NewParser(&b)
  obtainedTag, err := p.parseTag()
  c.Assert(obtainedTag, Equals, tag)
  c.Assert(p.cursor, Equals, expC)
  c.Assert(err, Equals, e)
}

func (s *Rfc3164TestSuite) assertRfc3164Header(c *C, hdr header, b []byte, expC int, e error) {
  p := NewParser(&b)
  obtained, err := p.parseHeader()
  c.Assert(err, Equals, e)
  c.Assert(obtained, Equals, hdr)
  c.Assert(p.cursor, Equals, expC)
}

func (s *Rfc3164TestSuite) assertRfc3164message(c *C, msg rfc3164message, b []byte, expC int, e error) {
  p := NewParser(&b)
  obtained, err := p.parsemessage()
  c.Assert(err, Equals, e)
  c.Assert(obtained, Equals, msg)
  c.Assert(p.cursor, Equals, expC)
}
