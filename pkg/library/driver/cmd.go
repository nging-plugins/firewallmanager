package driver

import (
	"io"
	"os/exec"

	"github.com/admpub/packer"
)

func RunCmd(path string, args []string, stdout io.Writer) error {
	cmd := exec.Cmd{
		Path:   path,
		Args:   args,
		Stdout: stdout,
		Stderr: packer.Stderr,
	}

	if err := cmd.Run(); err != nil {
		switch e := err.(type) {
		case *exec.ExitError:
			return e
		default:
			return err
		}
	}
	return nil
}
