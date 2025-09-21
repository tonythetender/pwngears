package process

import (
	"log"
	"log/slog"
	"os"

	"github.com/tonythetender/pwngears"
)

type ProcessConnWithLogger struct {
	*ProcessConn
	failOnError bool
}

func (p *ProcessConnWithLogger) logAndFatal(msg string, args ...any) {
	p.ProcessConn.logger.Error(msg, args...)
	if p.failOnError {
		log.Fatal()
	}
}

func Process(path string, args ...string) *ProcessConnWithLogger {
	logger, err := pwngears.NewDefaultLogger("INFO")
	if err != nil {
		log.Fatalf("error generating the default logger: %v", err)
	}
	var p *ProcessConn
	if len(args) == 0 {
		p, err = NewProcess(logger, []string{path}, nil)
	} else {
		allArgs := append([]string{path}, args...)
		p, err = NewProcess(logger, allArgs, nil)
	}
	if err != nil {
		wd, _ := os.Getwd()
		logger.Error("Could not establish connection to the given URL",
			slog.String("error", err.Error()),
			slog.String("working-directory", wd),
			slog.String("executable-path", path))
	}

	return &ProcessConnWithLogger{
		ProcessConn: p,
		failOnError: true,
	}
}

func ProcessWithLogger(logger *slog.Logger, path string, args ...string) *ProcessConnWithLogger {
	var p *ProcessConn
	var err error
	if len(args) == 0 {
		p, err = NewProcess(logger, []string{path}, nil)
	} else {
		allArgs := append([]string{path}, args...)
		p, err = NewProcess(logger, allArgs, nil)
	}
	if err != nil {
		wd, _ := os.Getwd()
		logger.Error("Could not establish connection to the given URL",
			slog.String("error", err.Error()),
			slog.String("working-directory", wd),
			slog.String("executable-path", path))
	}

	return &ProcessConnWithLogger{
		ProcessConn: p,
		failOnError: true,
	}
}

func (p *ProcessConnWithLogger) SetFailOnError(fail bool) {
	p.failOnError = fail
}

func (p *ProcessConnWithLogger) GetPID() int {
	return p.ProcessConn.GetPID()
}

func (p *ProcessConnWithLogger) Kill() {
	err := p.ProcessConn.Kill()
	if err != nil {
		p.logAndFatal("Could not send kill signal",
			slog.String("error", err.Error()))
		return
	}
	return
}

func (p *ProcessConnWithLogger) Wait() {
	err := p.ProcessConn.Wait()
	if err != nil {
		p.logAndFatal("Could not wait for command to exit",
			slog.String("error", err.Error()))
	}
	return
}

func (p *ProcessConnWithLogger) Send(data any) {
	err := p.ProcessConn.Send(data)
	if err != nil {
		p.logAndFatal("Could not send data to process",
			"error", err.Error())
	}
	return
}

type RemoteConnWithLogger struct {
	*RemoteConn
	failOnError bool
}

func Remote(host string, port int, opts ...RemoteOption) *RemoteConnWithLogger {
	logger, err := pwngears.NewDefaultLogger("INFO")
	if err != nil {
		log.Fatalf("error generating the default logger: %v", err)
	}
	remote, err := NewRemote(host, port, opts...)
	if err != nil {
		logger.Error("Could not establish connection to the given URL",
			slog.String("error", err.Error()))
		return nil
	}
	return &RemoteConnWithLogger{
		RemoteConn:  remote,
		failOnError: true,
	}
}

func (r *RemoteConnWithLogger) GetPID() int {
	return r.RemoteConn.GetPID()
}
