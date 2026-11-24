package scanner

import (
	"fmt"
	"strconv"
)

var sizeUnits = [...]string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}

// humanSize formats a byte count in base-2 units with at most one decimal
// ("512 B", "1.5 KiB", "100 MiB"). The decimal is truncated, not rounded
// (1127 gives "1.1 KiB"). A negative count is printed as plain bytes.
func humanSize(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10) + " B"
	}
	// rem holds the value in 1/1024 of the chosen unit and stays below 2^20, so rem*10 cannot overflow.
	unit := 0
	rem := n
	for rem >= 1024*1024 && unit < len(sizeUnits)-1 {
		rem >>= 10
		unit++
	}
	tenths := (rem * 10) >> 10
	whole, frac := tenths/10, tenths%10
	s := strconv.FormatInt(whole, 10)
	if frac != 0 {
		s += "." + strconv.FormatInt(frac, 10)
	}
	return s + " " + sizeUnits[unit]
}

func tooBigError(size, limit int64) error {
	s, l := humanSize(size), humanSize(limit)
	// Rounded sizes can print equal while the file is over the limit by a few bytes.
	if s == l {
		s, l = strconv.FormatInt(size, 10)+" B", strconv.FormatInt(limit, 10)+" B"
	}
	return fmt.Errorf("%w: size %s exceeds max_file_size %s", errFileTooBig, s, l)
}
