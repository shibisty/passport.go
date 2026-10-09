// Example application: password login (users in PostgreSQL via orm),
// Google and Facebook login, sessions in Redis (or in memory), JWT for the API.
//
//	DATABASE_URL=postgres://user:pass@localhost:5432/app \
//	JWT_SECRET=$(openssl rand -hex 32) \
//	REDIS_URL=redis://localhost:6379/0 \
//	GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
//	go run .
//
// Table: CREATE TABLE users (id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL,
// name TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ);
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"orm"
	postgres "orm-postgres"
	redis "orm-redis"
	"passport"
	"passport-facebook"
	"passport-google"
	"passport-local"
	"passport-session-redis"
	"passport/jwt"
	"passport/memorystore"
)

// UserRecord is the orm model for the users table.
type UserRecord struct {
	orm.BaseModel
	Email        string `db:"email"`
	Name         string `db:"name"`
	PasswordHash string `db:"password_hash"`
}

func (UserRecord) TableName() string { return "users" }

func main() {
	ctx := context.Background()
	baseURL := env("BASE_URL", "http://localhost:8080")

	db, err := orm.New(ctx, postgres.Driver(must("DATABASE_URL")))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	exec, ok := db.(orm.QueryExecutor)
	if !ok {
		log.Fatalf("driver %s does not support SQL queries", db.Driver())
	}
	users := orm.NewRepository[UserRecord](exec)
	find := func(ctx context.Context, email string) (*User, error) {
		found, err := users.All(ctx, orm.NewQuery("users").Where("email", "=", email).LimitOffset(1, 0))
		if err != nil || len(found) == 0 {
			return nil, err
		}
		u := found[0]
		return &User{ID: u.ID, Email: u.Email, Name: u.Name, PasswordHash: u.PasswordHash}, nil
	}

	tokens, err := jwt.New(must("JWT_SECRET"), "passport-example")
	if err != nil {
		log.Fatal(err) // e.g. the secret is shorter than 32 bytes
	}
	a := passport.New().UseTokenIssuer(tokens).Use(local.New(verifyPassword(find)))

	if url := os.Getenv("REDIS_URL"); url != "" {
		conn, err := orm.New(ctx, redis.Driver(url))
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		kv, ok := conn.(orm.KeyValueStore)
		if !ok {
			log.Fatalf("driver %s is not a key-value store", conn.Driver())
		}
		a.UseSessionStore(redisstore.New(kv).WithPrefix("passport-example:session:"))
	} else {
		log.Println("REDIS_URL not set: sessions are kept in memory and will be lost on restart")
		a.UseSessionStore(memorystore.New())
	}

	var providers []string
	if id := os.Getenv("GOOGLE_CLIENT_ID"); id != "" {
		a.Use(google.New(id, must("GOOGLE_CLIENT_SECRET"), baseURL+"/auth/google/callback"))
		providers = append(providers, "google")
	}
	if id := os.Getenv("FACEBOOK_APP_ID"); id != "" {
		a.Use(facebook.New(id, must("FACEBOOK_APP_SECRET"), baseURL+"/auth/facebook/callback"))
		providers = append(providers, "facebook")
	}

	srv := &http.Server{
		Addr:              env("ADDR", ":8080"),
		Handler:           newMux(a, providers...),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func must(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("environment variable %s is not set", key)
	}
	return v
}
