package errors

type ErrorCode int

const (
	InternalError ErrorCode = iota
)

type Error struct {
	Reason string
	Code   ErrorCode
}

func (e *Error) Error() string {
	return e.Reason
}

func New(reason string, code ErrorCode) *Error {
	return &Error{
		Reason: reason,
		Code:   code,
	}
}
