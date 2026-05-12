package config

import "os"

func writeFileBytes(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
