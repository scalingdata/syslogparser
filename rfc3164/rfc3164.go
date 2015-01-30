package rfc3164

import (
  "bytes"
  "github.com/scalingdata/syslogparser"
  message "github.com/scalingdata/syslogparser/message"
  "time"
)

type Parser struct {
  buff     []byte
  cursor   int
  l        int
  priority syslogparser.Priority
  version  int
  header   header
  message  rfc3164message
  parseSuccessful bool
}

type header struct {
  timestamp time.Time
  hostname  string
}

type rfc3164message struct {
  tag     string
  procId  string
  content string
}

func NewParser(buff *[]byte) *Parser {
  return &Parser{
    buff:   *buff,
    cursor: 0,
    l:      len(*buff),
    parseSuccessful: false,
  }
}

func (p *Parser) Parse() error {
  pri, err := p.parsePriority()
  if err != nil {
    return err
  }

  hdr, err := p.parseHeader()
  if err != nil {
    return err
  }

  p.cursor++

  msg, err := p.parsemessage()
  if err != syslogparser.ErrEOL {
    return err
  }

  p.priority = pri
  p.version = syslogparser.NO_VERSION
  p.header = hdr
  p.message = msg

  p.parseSuccessful = true
  return nil
}

func (p *Parser) Dump() syslogparser.LogParts {
  return syslogparser.LogParts{
    "timestamp": p.header.timestamp,
    "hostname":  p.header.hostname,
    "tag":       p.message.tag,
    "content":   p.message.content,
    "priority":  p.priority.P,
    "facility":  p.priority.F.Value,
    "severity":  p.priority.S.Value,
    "proc_id":   p.message.procId,
  }
}

func (p *Parser) Message() message.IMessage {
  if ! p.parseSuccessful {
    return message.NewUnparsableMessage(&p.buff)
  } else {
    return &Rfc3164Message{
      rawMsg: &p.buff,
      ts: p.header.timestamp,
      pid: p.message.procId,
      facility: message.Facility(p.priority.F.Value),
      severity: message.Severity(p.priority.S.Value),
      process: p.message.tag,
      hostname: p.header.hostname,
      message: p.message.content,
    }
  }
}

func (p *Parser) parsePriority() (syslogparser.Priority, error) {
  return syslogparser.ParsePriority(p.buff, &p.cursor, p.l)
}

func (p *Parser) parseHeader() (header, error) {
  hdr := header{}
  var err error

  ts, err := p.parseTimestamp()
  if err != nil {
    return hdr, err
  }

  hostname, err := p.parseHostname()
  if err != nil {
    return hdr, err
  }

  hdr.timestamp = ts
  hdr.hostname = hostname

  return hdr, nil
}

func (p *Parser) parsemessage() (rfc3164message, error) {
  msg := rfc3164message{}
  var err error

  tag, err := p.parseTag()
  if err != nil {
    return msg, err
  }
  msg.tag = tag

  pid, content, err := p.parseContent()
  if err != syslogparser.ErrEOL {
    return msg, err
  }
  msg.procId = pid
  msg.content = content

  return msg, err
}

// https://tools.ietf.org/html/rfc3164#section-4.1.2
func (p *Parser) parseTimestamp() (time.Time, error) {
  var ts time.Time
  var err error
  var tsFmtLen int
  var sub []byte

  tsFmts := []string{
    "Jan 02 15:04:05",
    "Jan  2 15:04:05",
  }

  found := false
  for _, tsFmt := range tsFmts {
    tsFmtLen = len(tsFmt)

    if p.cursor+tsFmtLen > p.l {
      continue
    }

    sub = p.buff[p.cursor : tsFmtLen+p.cursor]
    ts, err = time.ParseInLocation(tsFmt, string(sub), time.Local)
    if err == nil {
      ts = ts.UTC()
      found = true
      break
    }
  }

  if !found {
    p.cursor = tsFmtLen

    // XXX : If the timestamp is invalid we try to push the cursor one byte
    // XXX : further, in case it is a space
    if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') {
      p.cursor++
    }

    return ts, syslogparser.ErrTimestampUnknownFormat
  }

  fixTimestampIfNeeded(&ts)

  p.cursor += tsFmtLen

  if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') {
    p.cursor++
  }

  return ts, nil
}

func (p *Parser) parseHostname() (string, error) {
  return syslogparser.ParseHostname(p.buff, &p.cursor, p.l)
}

// http://tools.ietf.org/html/rfc3164#section-4.1.3
func (p *Parser) parseTag() (string, error) {
  i := 0;
  for i < (p.l - p.cursor) {
    curChar := p.buff[p.cursor + i]
    if (curChar >= '0' && curChar <= '9') ||
      (curChar >= 'a' && curChar <= 'z') ||
      (curChar >= 'A' && curChar <= 'Z') ||
      /* Allow non-compliant tags with "-" and "_" */
       curChar == '-' || curChar == '_' ||
      /* Note that the spec says to stop on *any* non-alphanumeric, but the original
         author of this lib specifically allowed '.' chars so we're retaining this
         divergance from the specification until we find a reason not to. */
      (curChar == '.') { 
      i++
    } else {
      tag := p.buff[p.cursor:p.cursor+i]
      p.cursor = p.cursor+i
      return string(tag), nil
    }
  }
  tag := p.buff[p.cursor:p.cursor+i]
  p.cursor = p.cursor+i
  return string(tag), nil
}

func (p *Parser) parseContent() (string, string, error) {
  if p.cursor >= p.l {
    return "", "", syslogparser.ErrEOL
  }

  pid, err := p.parsePid()
  if nil != err {
    return "", "", err
  }

  /* Trim any padding that might appear after the pid */
  curChar := p.buff[p.cursor]
  for (':' == curChar || ' ' == curChar) &&  (p.cursor < p.l) {
    p.cursor++
    if p.cursor < p.l {
      curChar = p.buff[p.cursor]
    }
  }

  content := bytes.Trim(p.buff[p.cursor:p.l], " ")
  p.cursor = p.l

  return pid, string(content), syslogparser.ErrEOL
}

func (p *Parser) parsePid() (string, error) {
  if '[' != p.buff[p.cursor] {
    return "", nil
  } else {
    /* Walk past our initial '[' char until we find a non-numeric
       value or we hit the end of the buffer. */
    i := p.cursor + 1;
    curChar := p.buff[i]; 
    for (curChar >= '0' && curChar <= '9') && i < p.l {
      i++
      if i < p.l {
        curChar = p.buff[i]
      }
    }
    if i >= p.l {
      /* We got to the end of the buffer, and no closing bracket found */
      return "", nil
    } else if ']' == p.buff[i] {
      /* Found closing bracket, pull out the pid */
      pid := p.buff[p.cursor+1:i]
      p.cursor = i+1
      return string(pid), nil
    } else {
      /* We found a non-numeric value that wasn't the ']', not a pid */
      return "", nil
    }
  }
}

func fixTimestampIfNeeded(ts *time.Time) {
  now := time.Now()
  y := ts.Year()

  if ts.Year() == 0 {
    y = now.Year()
  }

  newTs := time.Date(y, ts.Month(), ts.Day(), ts.Hour(), ts.Minute(),
    ts.Second(), ts.Nanosecond(), ts.Location())

  *ts = newTs
}
