package revoker

import "strings"

const separator = ";"

type errorList struct {
	errors []error
}

func (e *errorList) append(newError error) {
	if e.errors == nil {
		e.errors = []error{}
	}
	e.errors = append(e.errors, newError)
}

func (e *errorList) Error() string {
	var messages []string
	for _, recordedError := range e.errors {
		messages = append(messages, recordedError.Error())
	}
	return strings.Join(messages, separator)
}

func (e *errorList) IsNil() bool {
	return e.errors == nil || len(e.errors) == 0
}
