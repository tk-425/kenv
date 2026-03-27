package vault

import (
	"fmt"
	"strings"
)

type UnknownPlaceholdersError struct {
	Unknown []string
}

func (e *UnknownPlaceholdersError) Error() string {
	return fmt.Sprintf("unknown placeholder(s): %s", strings.Join(e.Unknown, ", "))
}

func ResolvePlaceholders(v Vault, placeholders []string) (map[string]string, error) {
	resolved := make(map[string]string)
	if len(placeholders) == 0 {
		return resolved, nil
	}

	byPlaceholder := make(map[string]string, len(v.Credentials))
	for _, credential := range v.Credentials {
		byPlaceholder[credential.Placeholder] = credential.Secret
	}

	unknown := make([]string, 0)
	seenUnknown := make(map[string]struct{})
	for _, placeholder := range placeholders {
		if secret, exists := byPlaceholder[placeholder]; exists {
			resolved[placeholder] = secret
			continue
		}

		if _, seen := seenUnknown[placeholder]; seen {
			continue
		}

		seenUnknown[placeholder] = struct{}{}
		unknown = append(unknown, placeholder)
	}

	if len(unknown) > 0 {
		return nil, &UnknownPlaceholdersError{Unknown: unknown}
	}

	return resolved, nil
}
