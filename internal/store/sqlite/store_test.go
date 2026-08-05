package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/rin721/certmate/internal/jobs"
)

func TestMigrateCreatesCoreSchemaAndDefaultPolicy(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("迁移必须可重复执行: %v", err)
	}

	wantTables := map[string]bool{
		"certificates": false, "dns_credentials": false, "renewal_policies": false,
		"job_runs": false, "audit_events": false, "system_settings": false,
	}
	rows, err := store.db.QueryContext(ctx, `SELECT name, sql FROM sqlite_schema WHERE type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, schema string
		if err := rows.Scan(&name, &schema); err != nil {
			t.Fatal(err)
		}
		if _, ok := wantTables[name]; ok {
			wantTables[name] = true
		}
		if strings.Contains(strings.ToLower(schema), "admin_password") {
			t.Fatalf("数据库表 %s 不得包含管理员密码字段", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for name, found := range wantTables {
		if !found {
			t.Errorf("缺少表 %s", name)
		}
	}

	policy, err := store.RenewalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Enabled || policy.CronExpression != "0 3 * * *" || policy.Timezone != "Asia/Shanghai" {
		t.Fatalf("默认续签策略异常: %+v", policy)
	}
}

func TestMarkInterruptedJobsOnlyChangesRunningJobs(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	running := &jobs.Run{JobType: "renew", Status: "running"}
	succeeded := &jobs.Run{JobType: "issue", Status: "succeeded"}
	if err := store.CreateJob(ctx, running); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateJob(ctx, succeeded); err != nil {
		t.Fatal(err)
	}
	count, err := store.MarkInterruptedJobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("interrupted count = %d", count)
	}
	var runningStatus, succeededStatus string
	if err := store.db.QueryRowContext(ctx, `SELECT status FROM job_runs WHERE id = ?`, running.ID).Scan(&runningStatus); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT status FROM job_runs WHERE id = ?`, succeeded.ID).Scan(&succeededStatus); err != nil {
		t.Fatal(err)
	}
	if runningStatus != "interrupted" || succeededStatus != "succeeded" {
		t.Fatalf("running=%s succeeded=%s", runningStatus, succeededStatus)
	}
}
