package version

import "fmt"

var (
	Version = "0.1.0"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("%s (%s, %s)", Version, Commit, Date)
}
