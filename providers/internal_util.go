package providers

import (
	"net/url"
)

// hasQueryParams check if URL has query parameters
func hasQueryParams(endpoint string) bool {
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return false
	}

	return len(endpointURL.RawQuery) != 0
}
