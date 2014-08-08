package multiparser

import (
  "fmt"
  log "code.google.com/p/log4go"
  "github.com/jeromer/syslogparser"
  message "github.com/jeromer/syslogparser/message"
  "reflect"
  "github.com/jeromer/syslogparser/rfc3164"
  "github.com/jeromer/syslogparser/rfc5424"
  "strings"
)

type MultiParserError struct {
	ErrorString string
  ParseErrors []error
}
func (self MultiParserError) Error() string {
  var errorMsgs []string
  for _,e := range self.ParseErrors {
    errorMsgs = append(errorMsgs, e.Error())
  }
  return fmt.Sprintf("%v: %v", self.ErrorString, strings.Join(errorMsgs, ", "))
}

type Parser struct {
  rawMsg []byte
  parsers []syslogparser.LogParser
  // rfc3164Parser *rfc3164.Parser
  // rfc5424Parser *rfc5424.Parser
  successfulParser syslogparser.LogParser
  failureMsg message.IMessage
}

func (self *Parser) Parse() error {
  var parseErrors []error

  for _,p := range self.parsers {
    err := p.Parse()
    if nil != err {
      log.Debug("Unable to parse message using %s due to '%s'", reflect.TypeOf(p), err)
      parseErrors = append(parseErrors, err)
    } else {
      self.successfulParser = p
      return nil
    }
  }

  self.failureMsg = message.NewUnparsableMessage(self.rawMsg)

  log.Debug("Unable to debug message, using empty LogParts for data")
  return nil
}

func (self *Parser) Dump() syslogparser.LogParts {
  if nil != self.successfulParser {
    return self.successfulParser.Dump()
  } else {
    return nil
  }
}

func (self *Parser) Message() message.IMessage {
  if nil != self.successfulParser {
    return self.successfulParser.Message() 
  } else {
    return self.failureMsg
  }
}

/* Create a Parser that uses all known RFC defined formats */
func NewRfcParser(rawMsg []byte) syslogparser.LogParser {
  parserSet := []syslogparser.LogParser{rfc3164.NewParser(rawMsg), rfc5424.NewParser(rawMsg)}
  return &Parser{
    rawMsg: rawMsg,
    parsers: parserSet,
  }
}
