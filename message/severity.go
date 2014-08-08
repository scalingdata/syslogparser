package message

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
  return severityNames[int(self)]
}

/* SD-247: reach a consensus on textual representation for each message type 
   (these are copy/pasted from the rfc. */
var severityNames = map[int]string{
  -1: "Unknown",
  0: "Emergency",
  1: "Alert",
  2: "Critical",
  3: "Error",
  4: "Warning",
  5: "Notice",
  6: "Info",
  7: "Debug",
}
