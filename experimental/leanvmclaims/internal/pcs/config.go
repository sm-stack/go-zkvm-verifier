package pcs

import "errors"

// Mixed trees use plain commitments. The pinned supported profiles are generated
// from Rust Config::for_rate, including all query/grinding soundness parameters.
type config struct {
	initialK                                int
	levelKs, rates, queries, grinding, oods []int
}

func configFor(logN, rate int) (config, error) {
	c, ok := profiles[[2]int{logN, rate}]
	if !ok {
		return config{}, errors.New("leanvmclaims: unsupported PCS size or rate")
	}
	return c, nil
}
