package process

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
)

type ProcessConn struct {
	baseTube
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	logger *slog.Logger
}

func NewProcess(logger *slog.Logger, args []string, env map[string]string) (*ProcessConn, error) {
	cmd := exec.Command(args[0], args[1:]...)

	for k, v := range env {
		cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", k, v))
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	p := &ProcessConn{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		logger: logger,
	}

	p.reader = bufio.NewReader(stdout)
	p.writer = stdin
	p.closer = stdin

	Log(LogInfo, "Process", fmt.Sprintf("Started process with PID %d", cmd.Process.Pid))

	return p, nil
}

func (p *ProcessConn) GetPID() int {
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return -1
}

func (p *ProcessConn) Kill() error {
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Kill()
	}
	return nil
}

func (p *ProcessConn) Wait() error {
	if p.cmd != nil {
		return p.cmd.Wait()
	}
	return nil
}
