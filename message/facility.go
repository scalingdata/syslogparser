package message

type Facility int

const (
  FacilityUnknown Facility = -1
  Kernel Facility = 0
  User Facility = 1
  Mail Facility = 2
  Sysdaemon Facility = 3
  Secauth Facility = 4
  Syslogd Facility = 5
  Lineprinter Facility = 6
  Netnews Facility = 7
  Uucp Facility = 8
  Clock Facility = 9
  Secauth2 Facility = 10
  Ftp Facility = 11
  Ntp Facility = 12
  Logaudit Facility = 13
  Logalert Facility = 14
  Clock2 Facility = 15
  Local0 Facility = 16
  Local1 Facility = 17
  Local2 Facility = 18
  Local3 Facility = 19
  Local4 Facility = 20
  Local5 Facility = 21
  Local6 Facility = 22
  Local7 Facility = 23
)

func (self Facility) String() string {
  return facilityNames[int(self)]
}

/* SD-247: reach a consensus on textual representation for each message type 
   (these are copy/pasted from the rfc. */
var facilityNames = map[int]string{
  -1: "Unknown",
  0: "kernel messages",
  1: "user-level messages",
  2: "mail system",
  3: "system daemons",
  4: "security/authorization messages",
  5: "messages generated internally by syslogd",
  6: "line printer subsystem",
  7: "network news subsystem",
  8: "UUCP subsystem",
  9: "clock daemon",
  10: "security/authorization messages (note 1)",
  11: "FTP daemon",
  12: "NTP subsystem",
  13: "log audit (note 1)",
  14: "log alert (note 1)",
  15: "clock daemon (note 2)",
  16: "local use 0  (local0)",
  17: "local use 1  (local1)",
  18: "local use 2  (local2)",
  19: "local use 3  (local3)",
  20: "local use 4  (local4)",
  21: "local use 5  (local5)",
  22: "local use 6  (local6)",
  23: "local use 7  (local7)",
}
