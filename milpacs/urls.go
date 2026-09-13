package milpacs

import (
	"strings"

	"github.com/spf13/viper"
)

func forumBaseURL() string {
	baseURL := viper.GetString("FORUM_BASE_URL")
	if baseURL == "" {
		baseURL = "https://7cav.us"
	}

	return strings.TrimRight(baseURL, "/")
}
