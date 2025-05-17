package main

import (
	// "context"
	"net/http"
	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/tbordvik/torcms/templates"
	"github.com/tbordvik/torcms/data"
	// "modernc.org/sqlite"
	"time"
)

func main() {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.Timeout(60 * time.Second))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		user := data.User{Username: "admin", Perm: data.Permission{Name: "admin"}}
		templates.Index(user).Render(r.Context(), w)
		// templ.Handler(templates.Index(user)).ServeHTTP(w, r)
	})

	r.Mount("/admin", adminRouter())

	http.ListenAndServe(":3333", r)
	
}

func adminRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(AdminOnly)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		user := data.User{Username: "admin", Perm: data.Permission{Name: "admin"}}
		templ.Handler(templates.AdminIndex(user)).ServeHTTP(w, r)
	})

	return r
}

func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		perm, ok := ctx.Value("acl.permission").(data.Permission)
		if !ok || !perm.IsAdmin() {
			http.Error(w, http.StatusText(403), 403)
			return
		}
		next.ServeHTTP(w, r)
	})
}
