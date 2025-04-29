package utils

// KeysToSlice converts the keys of a map to slice.
//
// Parameters:
//   - input map[K]V: The map to extract the keys from.
//
// Returns:
//   - []K: A slice containing the keys from the input map.
func KeysToSlice[K comparable, V any](input map[K]V) []K {
	keys := make([]K, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}

	return keys
}
