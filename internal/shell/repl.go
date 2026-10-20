package shell

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Handler is called for each command line submitted by the user.
// It returns the output string to print and a boolean indicating whether to exit.
type Handler func(line string) (output string, exit bool)

type REPL struct {
	prompt  string
	handler Handler
	history []string
	in      *os.File
	out     *os.File
	isRaw   bool
	oldState *term.State
}

func New(prompt string, handler Handler) *REPL {
	return &REPL{
		prompt:  prompt,
		handler: handler,
		in:      os.Stdin,
		out:     os.Stdout,
	}
}

func (r *REPL) SetPrompt(p string) {
	r.prompt = p
}

// Run enters the interactive loop. It uses raw terminal mode when stdin is a
// terminal (better Ctrl+C handling), and falls back to line-buffered reads
// when stdin is a pipe.
func (r *REPL) Run() {
	if term.IsTerminal(int(r.in.Fd())) {
		r.runRaw()
	} else {
		r.runBuffered()
	}
}

func (r *REPL) runBuffered() {
	sc := bufio.NewScanner(r.in)
	for {
		fmt.Fprint(r.out, r.prompt)
		if !sc.Scan() {
			if err := sc.Err(); err != nil && err != io.EOF {
				fmt.Fprintf(r.out, "\nerror: %v\n", err)
			}
			return
		}
		line := strings.TrimRight(sc.Text(), "\r\n")
		if line == "" {
			continue
		}
		r.history = append(r.history, line)
		out, exit := r.handler(line)
		if out != "" {
			fmt.Fprintln(r.out, out)
		}
		if exit {
			return
		}
	}
}

func (r *REPL) runRaw() {
	oldState, err := term.MakeRaw(int(r.in.Fd()))
	if err != nil {
		r.runBuffered()
		return
	}
	defer term.Restore(int(r.in.Fd()), oldState)

	t := term.NewTerminal(r.in, r.prompt)

	for {
		t.SetPrompt(r.prompt)
		line, err := t.ReadLine()
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(r.out, "\nerror: %v\n", err)
			}
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		r.history = append(r.history, line)
		out, exit := r.handler(line)
		if out != "" {
			fmt.Fprintln(t, out)
		}
		if exit {
			return
		}
	}
}

func (r *REPL) History() []string {
	return r.history
}
