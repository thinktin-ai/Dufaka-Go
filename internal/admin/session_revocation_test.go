package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminSessionRevokedAfterPasswordChangeOrDeletion(t *testing.T) {
	for _, change := range []string{"UPDATE admin_users SET password='replaced-hash' WHERE username='owner'", "DELETE FROM admin_users WHERE username='owner'", "ALTER TABLE admin_users RENAME TO unavailable_admin_users"} {
		t.Run(change, func(t *testing.T) {
			g := newLoginRig(t, 0)
			login := g.try(t, "198.51.100.14:1", "owner", "right-pw")
			if login.Code != http.StatusFound {
				t.Fatal(login.Code)
			}
			cookies := login.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatal("expected a session")
			}
			called := 0
			handler := g.s.authed(func(w http.ResponseWriter, r *http.Request, u session) { called++; w.WriteHeader(http.StatusOK) })
			request := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", "/admin/goods", nil)
				r.AddCookie(cookies[0])
				w := httptest.NewRecorder()
				handler(w, r)
				return w
			}
			if request().Code != http.StatusOK {
				t.Fatal("fresh session rejected")
			}
			if _, err := g.pool.Exec(context.Background(), change); err != nil {
				t.Fatal(err)
			}
			got := request()
			if got.Code == http.StatusOK || called != 1 {
				t.Fatalf("stale session authorized: code=%d calls=%d", got.Code, called)
			}
			want := http.StatusFound
			if change[0:5] == "ALTER" {
				want = http.StatusServiceUnavailable
			}
			if got.Code != want {
				t.Fatalf("status=%d, want=%d", got.Code, want)
			}
			if want == http.StatusFound && got.Header().Get("Location") != "/admin/login" {
				t.Fatal("missing login redirect")
			}
		})
	}
}
