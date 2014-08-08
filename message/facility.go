package message

import (
  "strconv"
)

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
  return strconv.Itoa(int(self))
}
