package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	t.Parallel()

	type tc struct {
		name      string
		headerVal string
		wantKey   string
		wantErr   bool
		expectErr error // optional: exact error to match (by string)
	}

	cases := []tc{
		{
			name:      "no header",
			headerVal: "",
			wantErr:   true,
			expectErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name:      "wrong scheme",
			headerVal: "Bearer abc123",
			wantErr:   true,
			expectErr: errors.New("malformed authorization header"),
		},
		{
			name:      "missing token",
			headerVal: "ApiKey",
			wantErr:   true,
			expectErr: errors.New("malformed authorization header"),
		},
		{
			name:      "valid header",
			headerVal: "ApiKey abc123",
			wantKey:   "abc123",
			wantErr:   false,
		},
		{
			name:      "extra parts are ignored after token",
			headerVal: "ApiKey abc123 extra junk",
			wantKey:   "abc123",
			wantErr:   false,
		},
	}

	for _, c := range cases {
		c := c // capture
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			h := http.Header{}
			if c.headerVal != "" {
				h.Set("Authorization", c.headerVal)
			}

			got, err := auth.GetAPIKey(h)

			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (key=%q)", got)
				}
				if c.expectErr != nil && err.Error() != c.expectErr.Error() {
					t.Fatalf("unexpected error.\n  got:  %v\n  want: %v", err, c.expectErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.wantKey {
				t.Fatalf("wrong key. got %q, want %q", got, c.wantKey)
			}
		})
	}
}
