package parser

import (
	"fmt"
	"regexp"

	"logbanner/internal/config"
)

// Parser turns one raw log line from a source into an Event. A line
// that carries no recognisable structure returns an error; the caller
// counts it as unparsable and moves on.
type Parser interface {
	Parse(source, line string) (Event, error)
}

// New returns the parser for a format name: one of the built-in
// formats (nginx, apache, ssh, json) or a custom format from the
// agent config.
func New(format string, custom []config.CustomFormat) (Parser, error) {
	switch format {
	case "nginx", "apache":
		return combinedParser{}, nil
	case "ssh":
		return sshParser{}, nil
	case "json":
		return jsonParser{}, nil
	}
	for _, f := range custom {
		if f.Name == format {
			re, err := regexp.Compile(f.Regex)
			if err != nil {
				return nil, fmt.Errorf("custom format %q: invalid regex: %w", f.Name, err)
			}
			return customParser{format: f, re: re}, nil
		}
	}
	return nil, fmt.Errorf("unknown log format %q", format)
}
