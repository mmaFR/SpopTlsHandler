package SpopTlsHandler

import (
	"errors"
	"fmt"
	"io"
	"os"
)

func loadBytesFromFile(filePath string) ([]byte, error) {
	var err error
	var fd *os.File
	var bytes []byte

	if fd, err = os.Open(filePath); err != nil {
		return nil, err
	}

	if bytes, err = io.ReadAll(fd); err != nil {
		return nil, err
	}
	if err = fd.Close(); err != nil {
		return nil, err
	}
	return bytes, nil
}
func dumpBytesToFile(filePath string, bytes []byte) error {
	var err error
	var l int
	var fd *os.File

	if fd, err = os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_SYNC|os.O_EXCL, 0600); err != nil {
		return err
	}

	l, err = fd.Write(bytes)
	if err != nil {
		return err
	}
	if l != len(bytes) {
		return errors.New(fmt.Sprintf("Only %d bytes were written out of %d", l, len(bytes)))
	}

	if err = fd.Close(); err != nil {
		return err
	}
	return nil
}
