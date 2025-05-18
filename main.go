package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// Site represents a tenant/site
type Site struct {
	ID      int
	Name    string
	Domain  string
	Content string
}

// Page represents a page within a site
type Page struct {
	ID       int
	SiteID   int
	Title    string
	Slug     string
	Elements []Element
}

// Element represents a content element
type Element struct {
	ID       int
	PageID   int
	Type     string
	Content  map[string]string
	Position int
}

// User represents an authenticated user
type User struct {
	ID       int
	Username string
	Role     string
}

// SiteRepository handles database operations
type SiteRepository struct {
	db    *sql.DB
	store *sessions.CookieStore
}

// NewSiteRepository initializes the repository
func NewSiteRepository(db *sql.DB, store *sessions.CookieStore) *SiteRepository {
	return &SiteRepository{db: db, store: store}
}

// GetSiteByDomain retrieves a site
func (r *SiteRepository) GetSiteByDomain(domain string) (*Site, error) {
	var site Site
	err := r.db.QueryRow("SELECT id, name, domain, content FROM sites WHERE domain = ?", domain).Scan(
		&site.ID, &site.Name, &site.Domain, &site.Content,
	)
	if err != nil {
		return nil, err
	}
	return &site, nil
}

// CreateSite creates a new site
func (r *SiteRepository) CreateSite(name, domain, content string, userID int) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec("INSERT INTO sites (name, domain, content) VALUES (?, ?, ?)", name, domain, content)
	if err != nil {
		return err
	}
	siteID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO user_sites (user_id, site_id) VALUES (?, ?)", userID, siteID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// GetPageBySlug retrieves a page
func (r *SiteRepository) GetPageBySlug(siteID int, slug string) (*Page, error) {
	var page Page
	err := r.db.QueryRow("SELECT id, site_id, title, slug FROM pages WHERE site_id = ? AND slug = ?", siteID, slug).Scan(
		&page.ID, &page.SiteID, &page.Title, &page.Slug,
	)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query("SELECT id, page_id, type, content, position FROM elements WHERE page_id = ? ORDER BY position", page.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var e Element
		var contentStr string
		if err := rows.Scan(&e.ID, &e.PageID, &e.Type, &contentStr, &e.Position); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(contentStr), &e.Content); err != nil {
			return nil, err
		}
		page.Elements = append(page.Elements, e)
	}
	return &page, nil
}

// CreatePage creates a new page
func (r *SiteRepository) CreatePage(siteID int, title, slug string) error {
	_, err := r.db.Exec("INSERT INTO pages (site_id, title, slug) VALUES (?, ?, ?)", siteID, title, slug)
	return err
}

// CreateElement adds a new element
func (r *SiteRepository) CreateElement(pageID int, elementType string, content map[string]string, position int) error {
	contentJSON, err := json.Marshal(content)
	if err != nil {
		return err
	}
	_, err = r.db.Exec("INSERT INTO elements (page_id, type, content, position) VALUES (?, ?, ?, ?)",
		pageID, elementType, string(contentJSON), position)
	return err
}

// RegisterUser creates a new user
func (r *SiteRepository) RegisterUser(username, password, role string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = r.db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", username, hashedPassword, role)
	return err
}

// AuthenticateUser verifies user credentials
func (r *SiteRepository) AuthenticateUser(username, password string) (*User, error) {
	var user User
	var hashedPassword string
	err := r.db.QueryRow("SELECT id, username, password, role FROM users WHERE username = ?", username).Scan(
		&user.ID, &user.Username, &hashedPassword, &user.Role,
	)
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return nil, err
	}
	return &user, nil
}

// HasSiteAccess checks if a user has access to a site
func (r *SiteRepository) HasSiteAccess(userID, siteID int) bool {
	var count int
	r.db.QueryRow("SELECT COUNT(*) FROM user_sites WHERE user_id = ? AND site_id = ?", userID, siteID).Scan(&count)
	return count > 0
}

// Middleware
func TenantMiddleware(repo *SiteRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := strings.Split(r.Host, ":")[0]
			site, err := repo.GetSiteByDomain(host)
			if err != nil {
				http.Error(w, "Site not found", http.StatusNotFound)
				return
			}
			ctx := r.Context()
			ctx = context.WithValue(ctx, "site", site)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AuthMiddleware(repo *SiteRepository, requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := repo.store.Get(r, "session")
			userID, ok := session.Values["user_id"].(int)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			var user User
			err := repo.db.QueryRow("SELECT id, username, role FROM users WHERE id = ?", userID).Scan(
				&user.ID, &user.Username, &user.Role,
			)
			if err != nil || (requiredRole != "" && user.Role != requiredRole) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			site := r.Context().Value("site").(*Site)
			if !repo.HasSiteAccess(user.ID, site.ID) {
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}
			ctx := r.Context()
			ctx = context.WithValue(ctx, "user", &user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Handlers
func HomeHandler(repo *SiteRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		site := r.Context().Value("site").(*Site)
		page, err := repo.GetPageBySlug(site.ID, "home")
		if err != nil {
			http.Error(w, "Page not found", http.StatusNotFound)
			return
		}
		session, _ := repo.store.Get(r, "session")
		userID, _ := session.Values["user_id"]
		component := pageTemplate(site.Name, page, userID != nil)
		templ.Handler(component).ServeHTTP(w, r)
	}
}

func PageHandler(repo *SiteRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		site := r.Context().Value("site").(*Site)
		slug := chi.URLParam(r, "slug")
		page, err := repo.GetPageBySlug(site.ID, slug)
		if err != nil {
			http.Error(w, "Page not found", http.StatusNotFound)
			return
		}
		session, _ := repo.store.Get(r, "session")
		userID, _ := session.Values["user_id"]
		component := pageTemplate(site.Name, page, userID != nil)
		templ.Handler(component).ServeHTTP(w, r)
	}
}

func LoginHandler(repo *SiteRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			templ.Handler(loginTemplate("")).ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			templ.Handler(loginTemplate("Invalid form")).ServeHTTP(w, r)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		user, err := repo.AuthenticateUser(username, password)
		if err != nil {
			templ.Handler(loginTemplate("Invalid credentials")).ServeHTTP(w, r)
			return
		}
		session, _ := repo.store.Get(r, "session")
		session.Values["user_id"] = user.ID
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func RegisterHandler(repo *SiteRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			templ.Handler(registerTemplate("")).ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			templ.Handler(registerTemplate("Invalid form")).ServeHTTP(w, r)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		role := r.FormValue("role")
		if role != "admin" && role != "content-creator" {
			templ.Handler(registerTemplate("Invalid role")).ServeHTTP(w, r)
			return
		}
		if err := repo.RegisterUser(username, password, role); err != nil {
			templ.Handler(registerTemplate("Username taken")).ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func LogoutHandler(repo *SiteRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := repo.store.Get(r, "session")
		session.Values["user_id"] = nil
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func AdminCreateSiteHandler(repo *SiteRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if r.Method == http.MethodGet {
			templ.Handler(adminCreateSiteTemplate("")).ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			templ.Handler(adminCreateSiteTemplate("Invalid form")).ServeHTTP(w, r)
			return
		}
		name := r.FormValue("name")
		domain := r.FormValue("domain")
		content := r.FormValue("content")
		if name == "" || domain == "" {
			templ.Handler(adminCreateSiteTemplate("Name and domain required")).ServeHTTP(w, r)
			return
		}
		if err := repo.CreateSite(name, domain, content, user.ID); err != nil {
			templ.Handler(adminCreateSiteTemplate("Failed to create site")).ServeHTTP(w, r)
			return
		}
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func AdminCreatePageHandler(repo *SiteRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		site := r.Context().Value("site").(*Site)
		if r.Method == http.MethodGet {
			templ.Handler(adminCreatePageTemplate(site.Name, "")).ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			templ.Handler(adminCreatePageTemplate(site.Name, "Invalid form")).ServeHTTP(w, r)
			return
		}
		title := r.FormValue("title")
		slug := r.FormValue("slug")
		if title == "" || slug == "" {
			templ.Handler(adminCreatePageTemplate(site.Name, "Title and slug required")).ServeHTTP(w, r)
			return
		}
		if err := repo.CreatePage(site.ID, title, slug); err != nil {
			templ.Handler(adminCreatePageTemplate(site.Name, "Failed to create page")).ServeHTTP(w, r)
			return
		}
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func AdminCreateElementHandler(repo *SiteRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		site := r.Context().Value("site").(*Site)
		pageSlug := chi.URLParam(r, "pageSlug")
		page, err := repo.GetPageBySlug(site.ID, pageSlug)
		if err != nil {
			http.Error(w, "Page not found", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet {
			templ.Handler(adminCreateElementTemplate(site.Name, page, "")).ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			templ.Handler(adminCreateElementTemplate(site.Name, page, "Invalid form")).ServeHTTP(w, r)
			return
		}
		elementType := r.FormValue("type")
		position, _ := strconv.Atoi(r.FormValue("position"))
		content := map[string]string{}
		switch elementType {
		case "text":
			content["text"] = r.FormValue("text")
		case "image":
			content["src"] = r.FormValue("src")
			content["alt"] = r.FormValue("alt")
		case "button":
			content["text"] = r.FormValue("text")
			content["url"] = r.FormValue("url")
		default:
			templ.Handler(adminCreateElementTemplate(site.Name, page, "Invalid element type")).ServeHTTP(w, r)
			return
		}
		if err := repo.CreateElement(page.ID, elementType, content, position); err != nil {
			templ.Handler(adminCreateElementTemplate(site.Name, page, "Failed to create element")).ServeHTTP(w, r)
			return
		}
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func ElementFieldsHandler(repo *SiteRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		elementType := r.URL.Query().Get("type")
		templ.Handler(elementFieldsTemplate(elementType)).ServeHTTP(w, r)
	}
}

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Get session secret key from environment
	sessionKey := os.Getenv("SESSION_SECRET_KEY")
	if sessionKey == "" {
		log.Fatal("SESSION_SECRET_KEY not set in .env file")
	}

	// Database connection
	db, err := sql.Open("sqlite3", "./cms.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Session store
	store := sessions.NewCookieStore([]byte(sessionKey))

	// Initialize repository
	repo := NewSiteRepository(db, store)

	// Set up chi router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(TenantMiddleware(repo))

	// Public routes
	r.Get("/", HomeHandler(repo))
	r.Get("/{slug}", PageHandler(repo))
	r.Get("/login", LoginHandler(repo))
	r.Post("/login", LoginHandler(repo))
	r.Get("/register", RegisterHandler(repo))
	r.Post("/register", RegisterHandler(repo))
	r.Get("/logout", LogoutHandler(repo))

	// Admin routes (admin role only)
	r.Route("/admin", func(r chi.Router) {
		r.Use(AuthMiddleware(repo, "admin"))
		r.Get("/create-site", AdminCreateSiteHandler(repo))
		r.Post("/create-site", AdminCreateSiteHandler(repo))
	})

	// Content routes (admin or content-creator)
	r.Route("/content", func(r chi.Router) {
		r.Use(AuthMiddleware(repo, ""))
		r.Get("/create-page", AdminCreatePageHandler(repo))
		r.Post("/create-page", AdminCreatePageHandler(repo))
		r.Get("/pages/{pageSlug}/create-element", AdminCreateElementHandler(repo))
		r.Post("/pages/{pageSlug}/create-element", AdminCreateElementHandler(repo))
		r.Get("/element-fields", ElementFieldsHandler(repo))
	})

	// Static files
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Start server
	fmt.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}