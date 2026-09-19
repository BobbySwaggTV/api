package datastores_test

// SQL log-safety coverage for ValidateApiKey. Production opens gorm
// with an empty &gorm.Config{} (servers.setupDatasource), so GORM's
// logger.Default is live: Warn level, 200 ms slow threshold,
// ParameterizedQueries off. That logger interpolates BOUND PARAMETERS
// into process logs on SQL errors and slow queries — the path through
// which a raw bearer token could leak when the token was a string
// param. Since the digest moved into Go, the only bound value is a
// []byte, which GORM's ExplainSQL renders as "<binary>".
//
// These tests replicate the production logger shape writing to a
// buffer and drive each branch — error, slow-query, and the verbose
// Info level — asserting the token never appears. Each test also
// asserts the auth SQL itself WAS logged (non-vacuous: a silent
// logger cannot pass), and that "SHA2" is gone from the logged query —
// the database no longer sees the hashing expression at all.

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/BobbySwaggTV/api/datastores"
	"github.com/BobbySwaggTV/api/testdb"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// leakProbeToken is an obviously fake, never-issued token — unique
// enough to grep for in captured logs, and unresolvable so the test
// exercises the query path without a successful-resolution bump
// complicating the teardown.
const leakProbeToken = "cav7_leakprobe_5f8e1d2c9b4a"

// productionLoggerConfig replicates the logger.Config GORM's
// logger.Default carries — the shape production actually runs
// (servers.setupDatasource passes an empty &gorm.Config{}).
var productionLoggerConfig = logger.Config{
	SlowThreshold:             200 * time.Millisecond,
	LogLevel:                  logger.Warn,
	IgnoreRecordNotFoundError: false,
	ParameterizedQueries:      false,
}

// openLoggedHarnessDatastore mirrors openHarnessDatastore but wires a
// GORM logger of the given config into a buffer, returning both. The
// cleanup keeps the same idle barrier so an in-flight last_used_date
// bump cannot write into a closing pool.
func openLoggedHarnessDatastore(t *testing.T, cfg logger.Config) (datastores.Mysql, *bytes.Buffer) {
	t.Helper()
	_, dsn := testdb.Open(t)

	var buf bytes.Buffer
	gormDB, err := gorm.Open(gormmysql.Open(dsn), &gorm.Config{
		Logger: logger.New(log.New(&buf, "\r\n", log.LstdFlags), cfg),
	})
	if err != nil {
		t.Fatalf("dialing harness database through gorm: %v", err)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		t.Fatalf("unwrapping gorm connection pool: %v", err)
	}
	bumped := make(chan struct{}, 16)
	ds := datastores.Mysql{
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
	return ds, &buf
}

// assertNoTokenInLog is the shared verdict for every branch: the log
// must contain the auth SQL (proving the statement was actually
// traced — the check is not vacuous), must NOT contain the token, and
// must not contain the retired in-database hashing expression.
func assertNoTokenInLog(t *testing.T, logged, token string) {
	t.Helper()
	if !strings.Contains(logged, "key_hash") {
		t.Fatalf("expected the auth SQL in the captured log (non-vacuous check), got %q", logged)
	}
	if strings.Contains(logged, token) {
		t.Errorf("raw bearer token %q must not appear in GORM log output: %q", token, logged)
	}
	if strings.Contains(logged, "SHA2") {
		t.Errorf("the query no longer hashes in-database; SHA2 must not appear in logged auth SQL: %q", logged)
	}
}

// The error branch — the exact trace production emits whenever the
// resolving query fails. Breaking the query deterministically (dropping
// the column it filters on) makes GORM log the failed statement at
// Error level with its interpolated parameters.
func TestValidateApiKey_ErrorLogDoesNotLeakToken(t *testing.T) {
	ds, buf := openLoggedHarnessDatastore(t, productionLoggerConfig)

	if err := ds.Db.Exec(`ALTER TABLE xf_15meu_api_key DROP COLUMN key_hash`).Error; err != nil {
		t.Fatalf("dropping key_hash to fault the resolving SELECT: %v", err)
	}

	if _, err := ds.ValidateApiKey(leakProbeToken); err == nil {
		t.Fatal("ValidateApiKey must error once key_hash is gone")
	}

	assertNoTokenInLog(t, buf.String(), leakProbeToken)
}

// The slow-query branch — the same Warn-level trace production emits
// whenever a query exceeds its 200 ms threshold. A 1 ns test threshold
// forces that branch deterministically; it is the identical code path
// (logger.Trace's elapsed > SlowThreshold case), not a different or
// weakened configuration.
func TestValidateApiKey_SlowQueryLogDoesNotLeakToken(t *testing.T) {
	ds, buf := openLoggedHarnessDatastore(t, logger.Config{
		SlowThreshold: time.Nanosecond,
		LogLevel:      logger.Warn,
	})

	if _, err := ds.ValidateApiKey(leakProbeToken); err != nil {
		t.Fatalf("ValidateApiKey(leakProbeToken): %v", err)
	}

	logged := buf.String()
	if !strings.Contains(logged, "SLOW SQL") {
		t.Fatalf("expected a SLOW SQL trace for the auth query, got %q", logged)
	}
	assertNoTokenInLog(t, logged, leakProbeToken)
}

// The verbose branch — Info level logs EVERY statement with its
// params, which is what an operator flips to while debugging. The
// token must not appear there either, and neither must the seeded
// active fixture token (a credential shape all the same). The
// resolving-key call also lets the last_used_date bump UPDATE log —
// its param is key_id, never token material.
func TestValidateApiKey_InfoLogDoesNotLeakToken(t *testing.T) {
	ds, buf := openLoggedHarnessDatastore(t, logger.Config{
		LogLevel: logger.Info,
	})

	if _, err := ds.ValidateApiKey(leakProbeToken); err != nil {
		t.Fatalf("ValidateApiKey(leakProbeToken): %v", err)
	}
	if _, err := ds.ValidateApiKey(testdb.ActiveAPIKey); err != nil {
		t.Fatalf("ValidateApiKey(active): %v", err)
	}

	logged := buf.String()
	assertNoTokenInLog(t, logged, leakProbeToken)
	if strings.Contains(logged, testdb.ActiveAPIKey) {
		t.Errorf("resolved token %q must not appear in GORM log output either: %q", testdb.ActiveAPIKey, logged)
	}
}
