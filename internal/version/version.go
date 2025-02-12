package version

import "runtime/debug"

var version = "(devel)"

func init() {
	if version != "(devel)" {
		return
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	version = bi.Main.Version
}

func Version() string {
	return version
}
