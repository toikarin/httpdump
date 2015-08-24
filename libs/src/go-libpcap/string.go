package pcap

import (
	"fmt"
	"strconv"
)

func binarystr(i int64) string {
	return strconv.FormatInt(i, 2)
}

func (p FileHeader) String() string {
	return fmt.Sprintf(`[FileHeader:
  Version:        %d.%d
  ThisZone:       %d
  Sigfigs:        %d
  SnapLength:     %d
  Network:        %d
]`, p.VersionMajor(), p.VersionMinor(), p.ThisZone(), p.Sigfigs(), p.SnapLength(), p.Network())
}

func (p PacketHeader) String() string {
	return fmt.Sprintf(`[PacketHeader:
  Timestamp:      %s
  OriginalLength: %d
  IncludeLength:  %d
]`, p.Timestamp(), p.OriginalLength(), p.IncludeLength())
}
