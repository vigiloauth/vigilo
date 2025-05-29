package container

import "sync"

// LazyInit is a generic type that provides lazy initialization for a value of type T.
// It ensures that the initialization function (initFunc) is executed only once,
// regardless of how many times the value is accessed.
//
// Fields:
//   - once: A sync.Once instance used to guarantee that the initialization function
//     is executed only once.
//   - value: The lazily initialized value of type T.
//   - initFunc: A function that initializes and returns the value of type T.
//
// Usage:
// LazyInit can be used to defer the computation or initialization of a value
// until it is actually needed, while ensuring thread-safe access.
type LazyInit[T any] struct {
	once     sync.Once
	value    T
	initFunc func() T
}

// Get retrieves the value of the LazyInit instance, initializing it if necessary.
// The initialization is performed only once using the provided initFunc.
// Subsequent calls to Get will return the already initialized value.
//
// Returns:
//   - T: The initialized value of the LazyInit instance.
func (l *LazyInit[T]) Get() T {
	l.once.Do(func() {
		l.value = l.initFunc()
	})

	return l.value
}
