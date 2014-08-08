package message

import (
  "strconv"
)

type Severity int

const (
  SeverityUnknown Severity = -1
  Emergency Severity = 0
  Alert Severity = 1
  Critical Severity = 2
  Error Severity = 3
  Warning Severity = 4
  Notice Severity = 5
  Info Severity = 6
  Debug Severity = 7
)
func (self Severity) String() string {
  return strconv.Itoa(int(self))
}
