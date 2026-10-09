//go:build integration

package redisstore_test

import (
	"os"
	"testing"
	"time"

	"orm"
	redis "orm-redis"
	redisstore "passport-session-redis"
	"passport/sessionstoretest"
)

// ORM_TEST_REDIS_DSN=redis://127.0.0.1:6379/15 go test -tags integration ./...
func TestRedis(t *testing.T) {
	dsn := os.Getenv("ORM_TEST_REDIS_DSN")
	if dsn == "" {
		t.Skip("ORM_TEST_REDIS_DSN is not set")
	}
	conn, err := redis.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var kv orm.KeyValueStore = conn
	sessionstoretest.Run(t, redisstore.New(kv).WithPrefix("passporttest:"), time.Second)
}
