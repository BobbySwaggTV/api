package rest_test

// MariaDB-backed auth coverage: the FULL production chain (rest.New —
// sentry → metrics → auth → gzip → clean-path → mux) mounted over the
// REAL datastore against a disposable harness database, so the bearer
// parse, the SHA-256 key_hash lookup and the per-route scope
// gate are all exercised end-to-end. The fake datastore cannot express
// the real no-scope behavior (it models a resolved empty-scope identity
// → 403; the real inner joins produce zero rows → 401), so the
// divergence cases live only here. Skips without TESTDB_ADDR like every
// harness consumer — run via `make test-integration`.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BobbySwaggTV/api/datastores"
	"github.com/BobbySwaggTV/api/rest"
	"github.com/BobbySwaggTV/api/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openMariaDBStack dials a seeded harness database through gorm — the
// exact stack production uses — and mounts rest.New over the real
// datastore. The stub reference cache suffices: the exercised routes
// either never reach a handler or (ranks) never consult it.
func openMariaDBStack(t *testing.T) http.Handler {
	t.Helper()
	_, dsn := testdb.Open(t)

	gormDB, err := gorm.Open(gormmysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err, "dialing harness database through gorm")
	sqlDB, err := gormDB.DB()
	require.NoError(t, err, "unwrapping gorm connection pool")

	// ValidateApiKey fires an async last_used_date bump per resolved
	// key; mirror openHarnessDatastore's idle barrier so the metering
	// write doesn't race pool teardown.
	bumped := make(chan struct{}, 16)
	ds := &datastores.Mysql{
		Db: gormDB,
		OnKeyUsed: func(error) {
			select {
			case bumped <- struct{}{}:
			default:
			}
		},
	}
	t.Cleanup(func() {
		idle := time.NewTimer(150 * time.Millisecond)
		defer idle.Stop()
		for {
			select {
			case <-bumped:
				idle.Reset(150 * time.Millisecond)
			case <-idle.C:
				if err := sqlDB.Close(); err != nil {
					t.Errorf("closing gorm pool: %v", err)
				}
				return
			}
		}
	})

	return rest.New(ds, &stubReferenceCache{})
}

func getWithKey(t *testing.T, h http.Handler, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// The no-scope divergence, pinned at the HTTP seam on the REAL
// datastore: an active key with zero scope mappings produces zero rows
// through the inner joins → nil result → the middleware's generic 401.
// The fake datastore's empty-scope identity would reach requireScope
// and answer 403 — this is current production behavior, documented and
// protected here, not endorsed.
func TestMariaDBStack_ActiveKeyNoScopeMappingsIs401(t *testing.T) {
	h := openMariaDBStack(t)

	rr := getWithKey(t, h, testdb.ScopelessAPIKey, "/api/v1/milpacs/ranks")

	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"real DB resolves a scopeless key to zero rows → generic 401, NOT the fake datastore's empty-scope 403")
	assert.Equal(t, "Unauthorized", strings.TrimSpace(rr.Body.String()))
}

// Same outcome through the other join filter: the key row is active but
// its only scope definition is retired → still zero rows → 401.
func TestMariaDBStack_ActiveKeyOnlyInactiveScopeDefsIs401(t *testing.T) {
	h := openMariaDBStack(t)

	rr := getWithKey(t, h, testdb.InactiveScopeAPIKey, "/api/v1/milpacs/ranks")

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, "Unauthorized", strings.TrimSpace(rr.Body.String()))
}

// The resolvable side of the same tables: the seeded 15meu_ key serves a
// scoped route, the non-"15meu_"-prefixed token authenticates
// identically (the prefix is branding end-to-end, not just at the
// datastore lookup), the revoked key is rejected, and the
// resolved-vs-authorized split holds — a key carrying only "read"
// authenticates fine, then the tickets route's own scope gate denies it
// with 403.
func TestMariaDBStack_RealKeysThroughTheChain(t *testing.T) {
	h := openMariaDBStack(t)

	t.Run("active key serves a scoped route", func(t *testing.T) {
		rr := getWithKey(t, h, testdb.ActiveAPIKey, "/api/v1/milpacs/ranks")
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), `"rankFull"`)
	})

	t.Run("non-15meu prefix authenticates identically", func(t *testing.T) {
		rr := getWithKey(t, h, testdb.MeuPrefixAPIKey, "/api/v1/milpacs/ranks")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("unbranded token authenticates identically", func(t *testing.T) {
		rr := getWithKey(t, h, testdb.UnbrandedAPIKey, "/api/v1/milpacs/ranks")
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("resolved key lacking the route scope is 403", func(t *testing.T) {
		// The meu15 key carries only "read"; /tickets requires
		// "read:tickets". Auth resolved — the per-route gate denies.
		rr := getWithKey(t, h, testdb.MeuPrefixAPIKey, "/api/v1/tickets")
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.JSONEq(t, `{"code":7,"message":"scope required: read:tickets","details":[]}`, rr.Body.String())
	})

	t.Run("revoked key is the generic 401", func(t *testing.T) {
		rr := getWithKey(t, h, testdb.RevokedAPIKey, "/api/v1/milpacs/ranks")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "Unauthorized", strings.TrimSpace(rr.Body.String()))
	})

	t.Run("unknown key is the generic 401", func(t *testing.T) {
		rr := getWithKey(t, h, "15meu_test_never_issued", "/api/v1/milpacs/ranks")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "Unauthorized", strings.TrimSpace(rr.Body.String()))
	})
}
