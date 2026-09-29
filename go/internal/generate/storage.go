package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	pgPlaceholder   = regexp.MustCompile(`%\((\w+)\)s`)
	litePlaceholder = regexp.MustCompile(`:(\w+)`)
	columnLine      = regexp.MustCompile(`^\s{4}([a-z][a-z0-9_]*)\s+([A-Z]+(?:\s+PRECISION)?)(.*?)[,;]?\s*$`)
	insertColumns   = regexp.MustCompile(`(?is)INSERT\s+INTO\s+[a-z0-9_.]+\s*\((.*?)\)\s*VALUES`)
)

type sqlColumn struct {
	name     string
	goType   string
	sqlType  string
	nullable bool
}
type sqlQuery struct {
	name, pg, lite string
	args           []string
}

type projectionVocabulary struct {
	projections map[string]bool
	fields      map[string]bool
}

func newProjectionVocabulary() *projectionVocabulary {
	return &projectionVocabulary{
		projections: map[string]bool{},
		fields:      map[string]bool{},
	}
}

func (v *projectionVocabulary) use(projection string, fields ...string) {
	v.projections[projection] = true
	for _, field := range fields {
		v.fields[field] = true
	}
}

func GenerateStorage(storageSourceDir, schemasDir, storageOutDir, fixtureDir, samplesFile, contractsRef string) error {
	// Raw contracts SQL is intentionally not copied into the SDK. The canonical
	// source is transformed directly into deterministic Go source.
	for _, obsolete := range []string{
		"loader.go", "loader_test.go", "protocol.go", "provider.go", "provider_test.go", "save_gen.go", "sql_gen.go", "sql_ddl_gen.go", "sql_queries_gen.go", "operations_gen.go", "sql",
	} {
		if err := os.RemoveAll(filepath.Join(storageOutDir, obsolete)); err != nil {
			return fmt.Errorf("remove obsolete storage output %s: %w", obsolete, err)
		}
	}
	if fixtureDir != "" {
		target := filepath.Join(storageOutDir, "storagetest", "testdata")
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("clean storage fixtures: %w", err)
		}
		if err := copyJSONFiles(fixtureDir, target); err != nil {
			return err
		}
		if samplesFile != "" {
			if err := generateStorageSamples(samplesFile, filepath.Join(target, "samples.json")); err != nil {
				return err
			}
		}
	}
	if err := generateSQL(
		storageSourceDir,
		filepath.Join(storageOutDir, "schema.go"),
		filepath.Join(storageOutDir, "queries.go"),
		contractsRef,
	); err != nil {
		return err
	}
	vocabulary := newProjectionVocabulary()
	if err := generateOperations(
		storageSourceDir,
		schemasDir,
		filepath.Join(storageOutDir, "operations.go"),
		contractsRef,
		vocabulary,
	); err != nil {
		return err
	}
	return generateProjectionIdentifiers(
		filepath.Join(storageOutDir, "projection_identifiers.go"),
		contractsRef,
		vocabulary,
	)
}

func generateSQL(source, ddlOutput, queriesOutput, ref string) error {
	tables := map[string][]sqlColumn{}
	for _, dialect := range []string{"postgres", "sqlite"} {
		entries, err := os.ReadDir(filepath.Join(source, dialect, "schema"))
		if err != nil {
			return fmt.Errorf("read %s schema: %w", dialect, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".sql")
			data, err := os.ReadFile(filepath.Join(source, dialect, "schema", e.Name()))
			if err != nil {
				return err
			}
			cols := parseColumns(string(data))
			if len(cols) == 0 {
				return fmt.Errorf("%s schema %s: no columns parsed", dialect, e.Name())
			}
			if prior, ok := tables[name]; ok {
				if columnSignature(prior) != columnSignature(cols) {
					return fmt.Errorf("schema columns/types differ for %s: postgres [%s], sqlite [%s]", name, columnSignature(prior), columnSignature(cols))
				}
			} else {
				tables[name] = cols
			}
		}
	}
	queries := map[string]*sqlQuery{}
	for _, dialect := range []string{"postgres", "sqlite"} {
		entries, err := os.ReadDir(filepath.Join(source, dialect, "queries"))
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(source, dialect, "queries", e.Name()))
			if err != nil {
				return err
			}
			raw := string(data)
			names, text := rewriteSQL(raw, dialect)
			q := queries[e.Name()]
			if q == nil {
				q = &sqlQuery{name: e.Name()}
				queries[e.Name()] = q
			}
			if q.args != nil && strings.Join(q.args, ",") != strings.Join(names, ",") {
				return fmt.Errorf("query placeholders differ for %s: %v versus %v", e.Name(), q.args, names)
			}
			q.args = names
			if dialect == "postgres" {
				q.pg = text
			} else {
				q.lite = text
			}
			if strings.HasSuffix(e.Name(), ".upsert.sql") {
				table := strings.TrimSuffix(e.Name(), ".upsert.sql")
				cols, ok := tables[table]
				if !ok {
					return fmt.Errorf("query %s has no DDL table", e.Name())
				}
				m := insertColumns.FindStringSubmatch(raw)
				if m == nil {
					return fmt.Errorf("query %s: cannot parse INSERT columns", e.Name())
				}
				inserted := words(m[1])
				ddl := strings.Split(columnNames(cols), ",")
				if strings.Join(inserted, ",") != strings.Join(ddl, ",") {
					return fmt.Errorf("query %s INSERT columns [%s] do not match DDL columns [%s]", e.Name(), strings.Join(inserted, ","), strings.Join(ddl, ","))
				}
				placeholderSet := map[string]bool{}
				for _, n := range names {
					placeholderSet[n] = true
				}
				for _, n := range inserted {
					if n == "id" {
						continue
					}
					if !placeholderSet[n] {
						return fmt.Errorf("query %s column %s has no placeholder", e.Name(), n)
					}
				}
			}
		}
	}
	for name, query := range queries {
		if query.pg == "" {
			return fmt.Errorf("query %s missing postgres dialect", name)
		}
		if query.lite == "" && !postgresOnlyQuery(name) {
			return fmt.Errorf("query %s missing sqlite dialect", name)
		}
	}
	boot := map[string][]string{}
	for _, d := range []string{"postgres", "sqlite"} {
		if d == "postgres" {
			path := filepath.Join(source, d, "namespace.sql")
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read PostgreSQL namespace SQL %s: %w", path, err)
			}
			statements, err := splitStatements(string(data))
			if err != nil {
				return fmt.Errorf("postgres/namespace.sql: %w", err)
			}
			boot[d] = append(boot[d], statements...)
		}
		for _, section := range []string{"schema", "views"} {
			entries, err := os.ReadDir(filepath.Join(source, d, section))
			if err != nil {
				return err
			}
			sort.Slice(entries, func(i, j int) bool {
				left, right := bootstrapRank(section, entries[i].Name()), bootstrapRank(section, entries[j].Name())
				if left != right {
					return left < right
				}
				return entries[i].Name() < entries[j].Name()
			})
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
					continue
				}
				path := filepath.Join(source, d, section, e.Name())
				data, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("read bootstrap SQL %s: %w", path, err)
				}
				ss, err := splitStatements(string(data))
				if err != nil {
					return fmt.Errorf("%s/%s/%s: %w", d, section, e.Name(), err)
				}
				boot[d] = append(boot[d], ss...)
			}
		}
	}
	var ddl strings.Builder
	fmt.Fprintf(&ddl, "// Code generated from traust-contracts %s SQL DDL. DO NOT EDIT.\n\npackage storage\n\n", ref)
	for _, d := range []string{"postgres", "sqlite"} {
		fmt.Fprintf(&ddl, "var bootstrap%s = []string{\n", storagePascal(d))
		for _, s := range boot[d] {
			fmt.Fprintf(&ddl, "\t%q,\n", s)
		}
		ddl.WriteString("}\n\n")
	}
	ddl.WriteString("func generatedBootstrap(d dialect) []string { if d == dialectPostgres { return bootstrapPostgres }; return bootstrapSqlite }\n")
	if err := formatAndWrite(ddlOutput, []byte(ddl.String())); err != nil {
		return err
	}

	var querySource strings.Builder
	fmt.Fprintf(&querySource, "// Code generated from traust-contracts %s SQL queries. DO NOT EDIT.\n\npackage storage\n\nimport (\n\t\"context\"\n\t\"database/sql\"\n)\n\n", ref)
	querySource.WriteString("type queries struct { dialect dialect }\n\n")
	qnames := make([]string, 0, len(queries))
	for n := range queries {
		qnames = append(qnames, n)
	}
	sort.Strings(qnames)
	for _, n := range qnames {
		query := queries[n]
		id := sqlIdent(strings.TrimSuffix(n, ".sql"))
		paramsType := id + "Params"
		fmt.Fprintf(&querySource, "const %sPostgres = %q\nconst %sSQLite = %q\n\n", id, query.pg, id, query.lite)
		fmt.Fprintf(&querySource, "type %s struct {\n", paramsType)
		table := strings.Split(n, ".")[0]
		colmap := map[string]string{}
		for _, c := range tables[table] {
			colmap[c.name] = c.goType
		}
		for _, arg := range query.args {
			typ := colmap[arg]
			if typ == "" {
				if arg == "lock_key" {
					typ = "int64"
				} else {
					typ = "string"
				}
			}
			fmt.Fprintf(&querySource, "\t%s %s\n", sqlIdent(arg), typ)
		}
		querySource.WriteString("}\n")
		fmt.Fprintf(&querySource, "func (q queries) %s(ctx context.Context, conn *sql.Conn, p %s)", id, paramsType)
		switch {
		case isRowQuery(n):
			querySource.WriteString(" *sql.Row")
		case isRowsQuery(n):
			querySource.WriteString(" (*sql.Rows, error)")
		default:
			querySource.WriteString(" error")
		}
		fmt.Fprintf(&querySource, " { statement := %sSQLite; if q.dialect == dialectPostgres { statement = %sPostgres }; ", id, id)
		switch {
		case isRowQuery(n):
			querySource.WriteString("return conn.QueryRowContext(ctx, statement")
		case isRowsQuery(n):
			querySource.WriteString("return conn.QueryContext(ctx, statement")
		default:
			querySource.WriteString("_, err := conn.ExecContext(ctx, statement")
		}
		for _, arg := range query.args {
			fmt.Fprintf(&querySource, ", p.%s", sqlIdent(arg))
		}
		switch {
		case isRowQuery(n), isRowsQuery(n):
			querySource.WriteString(") }\n\n")
		default:
			querySource.WriteString("); return err }\n\n")
		}
	}
	return formatAndWrite(queriesOutput, []byte(querySource.String()))
}

func isRowQuery(name string) bool {
	return strings.HasSuffix(name, ".exists.sql") || strings.HasSuffix(name, ".get.sql")
}

func isRowsQuery(name string) bool { return strings.HasSuffix(name, ".list.sql") }

func postgresOnlyQuery(name string) bool {
	switch name {
	case "artifact.lock.sql", "traust_storage_meta.lock.sql":
		return true
	default:
		return false
	}
}

func parseColumns(s string) []sqlColumn {
	var out []sqlColumn
	for _, l := range strings.Split(s, "\n") {
		m := columnLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		nullable := !strings.Contains(m[3], "NOT NULL") && !strings.Contains(m[3], "PRIMARY KEY")
		typ := "string"
		switch strings.Fields(m[2])[0] {
		case "BIGINT", "INTEGER":
			typ = "int64"
		case "DOUBLE", "REAL":
			typ = "float64"
		case "BYTEA", "BLOB":
			typ = "[]byte"
		}
		if nullable && typ != "[]byte" {
			typ = "*" + typ
		}
		out = append(out, sqlColumn{
			name:     m[1],
			goType:   typ,
			sqlType:  strings.Fields(m[2])[0],
			nullable: nullable,
		})
	}
	return out
}
func columnSignature(c []sqlColumn) string {
	parts := make([]string, len(c))
	for i, column := range c {
		parts[i] = column.name + ":" + column.goType
	}
	return strings.Join(parts, ",")
}
func columnNames(c []sqlColumn) string {
	a := make([]string, len(c))
	for i, x := range c {
		a[i] = x.name
	}
	return strings.Join(a, ",")
}
func words(s string) []string {
	r := regexp.MustCompile(`[a-z][a-z0-9_]*`)
	return r.FindAllString(strings.ToLower(s), -1)
}
func rewriteSQL(s, d string) ([]string, string) {
	re := litePlaceholder
	if d == "postgres" {
		re = pgPlaceholder
	}
	names := []string{}
	idx := map[string]int{}
	out := re.ReplaceAllStringFunc(s, func(x string) string {
		name := re.FindStringSubmatch(x)[1]
		if d == "postgres" {
			if i, ok := idx[name]; ok {
				return fmt.Sprintf("$%d", i)
			}
			names = append(names, name)
			idx[name] = len(names)
			return fmt.Sprintf("$%d", len(names))
		}
		names = append(names, name)
		return "?"
	})
	return names, strings.TrimSpace(out)
}
func bootstrapRank(section, name string) int {
	// Views that other views select FROM must be created first.
	// Alphabetical order is NOT dependency order: current_finding sorts
	// before report_current but selects from it, and PostgreSQL resolves a
	// view's references at CREATE time while SQLite does not -- so the
	// alphabetical order failed only on PostgreSQL. Mirrors VIEW_ORDER in
	// traust-contracts sql.py; the two must stay in step.
	if section == "views" {
		switch name {
		case "binding_current.sql":
			return 0
		case "report_current.sql":
			return 1
		case "ownership_current.sql":
			return 2
		case "current_finding.sql":
			return 3
		case "threat_current.sql":
			return 4
		case "finding_first_seen.sql":
			return 5
		case "finding_timeline.sql":
			return 6
		case "pqc_posture.sql":
			return 7
		case "sla_clock.sql":
			return 8
		case "sla_threshold.sql":
			return 9
		default:
			return 10
		}
	}
	if section != "schema" {
		return 2
	}
	switch name {
	case "artifact_evidence.sql":
		return 0
	case "artifact_binding.sql":
		return 1
	default:
		return 2
	}
}

func splitStatements(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	for _, l := range strings.Split(s, "\n") {
		cur.WriteString(l)
		cur.WriteByte('\n')
		if strings.HasSuffix(strings.TrimSpace(l), ";") {
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		return nil, fmt.Errorf("unterminated SQL")
	}
	return out, nil
}
func sqlIdent(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	for i := range parts {
		if i == 0 {
			parts[i] = strings.ToLower(parts[i])
		} else {
			parts[i] = storagePascal(parts[i])
		}
	}
	return strings.Join(parts, "")
}

func generateStorageSamples(source, target string) error {
	const script = `import json,runpy,sys; data=runpy.run_path(sys.argv[1]); samples={name:json.loads(data["sample"](name)[0]) for name in data["FAMILIES"]}; print(json.dumps(samples,ensure_ascii=False,separators=(",",":"),sort_keys=True))`
	output, err := exec.Command("python3", "-c", script, source).Output()
	if err != nil {
		return fmt.Errorf("generate storage samples from %s: %w", source, err)
	}
	if err = os.WriteFile(target, output, 0o644); err != nil {
		return fmt.Errorf("write storage samples: %w", err)
	}
	return nil
}
func copyJSONFiles(source, target string) error { return copyFiles(source, target, ".json") }
func copyFiles(source, target, suffix string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return fmt.Errorf("read %s: %w", source, err)
	}
	if err = os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), suffix) {
			data, er := os.ReadFile(filepath.Join(source, e.Name()))
			if er != nil {
				return er
			}
			if er = os.WriteFile(filepath.Join(target, e.Name()), data, 0o644); er != nil {
				return er
			}
		}
	}
	return nil
}

type storageProfilesDocument struct {
	Version   int                       `json:"version"`
	Artifacts map[string]storageProfile `json:"artifacts"`
}

type storageProfile struct {
	Class      string   `json:"class"`
	Required   []string `json:"required"`
	Projection string   `json:"projection"`
}

func loadStorageProfiles(storageDir string, schemas map[string]*SchemaFile) (map[string]storageProfile, error) {
	data, err := os.ReadFile(filepath.Join(storageDir, "profiles.json"))
	if err != nil {
		return nil, err
	}
	var document storageProfilesDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode storage profiles: %w", err)
	}
	if document.Version != 1 {
		return nil, fmt.Errorf("unsupported storage profile version %d", document.Version)
	}
	if len(document.Artifacts) != len(schemas) {
		return nil, fmt.Errorf("storage profiles cover %d artifacts; schemas contain %d", len(document.Artifacts), len(schemas))
	}
	classes := map[string]bool{"evidence-only": true, "run-bound": true, "layer-bound": true, "scope-ref": true, "aggregate": true}
	for filename := range schemas {
		name := strings.TrimSuffix(filename, ".schema.json")
		profile, ok := document.Artifacts[name]
		if !ok {
			return nil, fmt.Errorf("storage profile missing artifact %s", name)
		}
		if !classes[profile.Class] {
			return nil, fmt.Errorf("storage profile %s has invalid class %q", name, profile.Class)
		}
		if profile.Projection == "" {
			return nil, fmt.Errorf("storage profile %s has no projection table", name)
		}
		for _, field := range profile.Required {
			if field != "subject_id" && field != "run_id" && field != "layer_id" {
				return nil, fmt.Errorf("storage profile %s requires unknown field %q", name, field)
			}
		}
	}
	for name := range document.Artifacts {
		if schemas[name+".schema.json"] == nil {
			return nil, fmt.Errorf("storage profile has unknown artifact %s", name)
		}
	}
	return document.Artifacts, nil
}

// Families that project one row PER ITEM rather than one row per artifact.
// Their columns come from array items, not from the schema's root properties,
// which is exactly what generateOneRowProjector requires -- so their
// projectors are written by hand.
//
// Keyed on the SCHEMA name, which is why this list has to be checked against
// the schemas that actually exist: contracts renamed threat-register to
// threat-model in 0.24.0 and this entry kept the old name, so the generator
// stopped skipping it and failed with "no root property for projection column
// threat_key" -- a message that describes the symptom and not the rename.
var fanOutSchemas = map[string]bool{
	"layer":           true,
	"triage":          true,
	"vuln-findings":   true,
	"corpus-registry": true,
	"threat-model":    true,
}

var secondaryProjectors = map[string]string{
	"report": "projectReportFindings",
}

func generateOperations(
	storageDir, schemasDir, output, contractsRef string,
	vocabulary *projectionVocabulary,
) error {
	schemas, err := LoadSchemas(schemasDir)
	if err != nil {
		return err
	}
	if err := ResolveRefs(schemas); err != nil {
		return err
	}
	profiles, err := loadStorageProfiles(storageDir, schemas)
	if err != nil {
		return err
	}
	tables, err := loadPostgresTables(storageDir)
	if err != nil {
		return err
	}
	// Tables written by HAND-WRITTEN fan-out projectors. The generated
	// one-row projector never sees them, so their identifiers would not
	// exist without this.
	vocabulary.use("layer_metadata")
	vocabulary.use("layer_event")
	vocabulary.use("subject_ownership")
	// Fan-out table with a hand-written projector, so no generated projector
	// records it -- without this its identifiers are never emitted.
	vocabulary.use(
		"threat",
		"actors",
		"evidence",
		"attack_refs",
		"isolation_dimensions",
		"isolation_boundaries",
	)
	vocabulary.use("finding", "line")
	vocabulary.use("report_finding")
	vocabulary.use("triage_verdict", "rationale", "severity", "vote_breakdown")

	var b strings.Builder
	fmt.Fprintf(&b, "// Code generated from traust-contracts %s. DO NOT EDIT.\n\npackage storage\n\n", contractsRef)
	b.WriteString("import (\n\t\"context\"\n\t\"database/sql\"\n\n\t\"github.com/traust-security/traust-sdk/go/v1/types\"\n)\n\n")
	filenames := sortedSchemaFilenames(schemas)
	for _, filename := range filenames {
		schema := strings.TrimSuffix(filename, ".schema.json")
		goType := schemaStructName(filename)
		operation := storagePascal(schema)
		profile := profiles[schema]
		if profile.Projection != "" && len(tables[profile.Projection]) == 0 {
			return fmt.Errorf("storage profile %s has no projection table %s", schema, profile.Projection)
		}
		fmt.Fprintf(&b, "type Save%sInput struct {\n\tBinding Binding\n\tArtifact types.Artifact[types.%s]\n}\n\n", operation, goType)
		fmt.Fprintf(&b, "func (c *Client) Save%s(ctx context.Context, input Save%sInput) (SaveResult, error) {\n", operation, operation)
		projector := "nil"
		if profile.Projection != "" {
			projector = "c.store.project" + operation
		}
		fmt.Fprintf(&b, "\treturn saveTypedArtifact(ctx, c.store, %q, input.Binding, %s, input.Artifact, %s)\n}\n\n", schema, runtimeProfileLiteral(profile), projector)
		fmt.Fprintf(&b, "func (c *Client) Get%s(ctx context.Context, bindingID string) (types.Artifact[types.%s], error) {\n", operation, goType)
		fmt.Fprintf(&b, "\treturn getTypedArtifact(ctx, c.store, %q, bindingID, types.Parse%sArtifact)\n}\n\n", schema, goType)
		// Families whose projection FANS OUT (one row per item) rather than
		// mapping root properties to columns. generateOneRowProjector cannot
		// express them, so their projectors are written by hand.
		// Families that project one row PER ITEM rather than one row per
		// artifact. They have hand-written projectors because their columns
		// come from array items, not from the schema's root properties --
		// which is exactly what generateOneRowProjector requires.
		if fanOutSchemas[schema] || profile.Projection == "" {
			continue
		}
		if err := generateOneRowProjector(
			&b,
			schemas[filename],
			schema,
			operation,
			goType,
			profile.Projection,
			tables[profile.Projection],
			vocabulary,
		); err != nil {
			// The one-row projector only fails this way when the table is a
			// fan-out: its columns come from array items, so they are not
			// root properties of the schema. That means either a new fan-out
			// family, or a renamed one whose old name is still in
			// fanOutSchemas -- which is what happened when contracts renamed
			// threat-register to threat-model and the raw error named a
			// column instead of the rename.
			return fmt.Errorf(
				"%w\n\nschema %q projects to %q, which looks like a FAN-OUT table. "+
					"If it is, add %q to fanOutSchemas and write its projector by hand; "+
					"if a family was renamed, update the stale entry there",
				err, schema, profile.Projection, schema,
			)
		}
	}
	b.WriteString("func (c *Client) saveNamed(ctx context.Context, name string, payload []byte, binding Binding) (SaveResult, error) {\n\tswitch name {\n")
	for _, filename := range filenames {
		schema := strings.TrimSuffix(filename, ".schema.json")
		goType := schemaStructName(filename)
		operation := storagePascal(schema)
		fmt.Fprintf(&b, "\tcase %q:\n", schema)
		fmt.Fprintf(&b, "\t\tartifact, err := types.Parse%sArtifact(payload)\n", goType)
		b.WriteString("\t\tif err != nil { return SaveResult{}, wrap(OperationSave, PhaseValidate, err) }\n")
		fmt.Fprintf(&b, "\t\treturn c.Save%s(ctx, Save%sInput{Binding: binding, Artifact: artifact})\n", operation, operation)
	}
	b.WriteString("\tdefault:\n\t\treturn SaveResult{}, wrap(OperationSave, PhaseInput, ErrUnknownArtifact)\n\t}\n}\n")
	return formatAndWrite(output, []byte(b.String()))
}

func runtimeProfileLiteral(profile storageProfile) string {
	required := map[string]bool{}
	for _, field := range profile.Required {
		required[field] = true
	}
	return fmt.Sprintf(
		"bindingRequirements{subject: %t, run: %t, layer: %t}",
		required["subject_id"],
		required["run_id"],
		required["layer_id"],
	)
}

func loadPostgresTables(storageDir string) (map[string][]sqlColumn, error) {
	tables := map[string][]sqlColumn{}
	root := filepath.Join(storageDir, "postgres", "schema")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		tables[strings.TrimSuffix(entry.Name(), ".sql")] = parseColumns(string(data))
	}
	return tables, nil
}

func generateOneRowProjector(
	b *strings.Builder,
	schemaFile *SchemaFile,
	schema, operation, goType, table string,
	columns []sqlColumn,
	vocabulary *projectionVocabulary,
) error {
	vocabulary.use(table)
	fmt.Fprintf(
		b,
		"func (s *sqlStore) project%s(ctx context.Context, conn *sql.Conn, state writeState, value types.%s) error {\n",
		operation,
		goType,
	)
	for _, column := range columns {
		if isProjectionMetadata(column.name) {
			continue
		}
		if _, ok := schemaFile.Properties[column.name]; !ok {
			return fmt.Errorf("schema %s has no root property for projection column %s", schema, column.name)
		}
		helper := ""
		switch {
		case column.sqlType == "JSONB" && column.nullable:
			helper = "optionalProjectionJSON"
		case column.sqlType == "JSONB":
			helper = "projectionJSON"
		case schemaFile.Properties[column.name].Const != nil:
			helper = "projectionText"
		default:
			continue
		}
		vocabulary.use(table, column.name)
		local := sqlIdent(column.name)
		fmt.Fprintf(b, "\t%s, err := %s(value.%s)\n", local, helper, toPascalCase(column.name))
		fmt.Fprintf(
			b,
			"\tif err != nil { return projectionError(projection%s, projectionField%s, err) }\n",
			storagePascal(table),
			storagePascal(column.name),
		)
	}
	fmt.Fprintf(
		b,
		"\tif err := s.queries.%s(ctx, conn, %sParams{\n",
		sqlIdent(table+".upsert"),
		sqlIdent(table+".upsert"),
	)
	for _, column := range columns {
		expression := sqlIdent(column.name)
		switch column.name {
		case "binding_id":
			expression = "state.bindingID"
		case "artifact_digest":
			expression = "state.digest"
		default:
			switch column.sqlType {
			case "BIGINT", "INTEGER":
				expression = "int64(value." + toPascalCase(column.name) + ")"
			case "JSONB":
			default:
				property := schemaFile.Properties[column.name]
				if property.Const == nil {
					expression = "value." + toPascalCase(column.name)
					if isEnumProperty(property) {
						// The type generator retypes an enum field to its registry
						// type (enums.*) when one matches and leaves it string
						// otherwise; both conversions accept either form.
						if column.nullable {
							expression = "projectionEnum(" + expression + ")"
						} else {
							expression = "string(" + expression + ")"
						}
					}
				}
			}
		}
		fmt.Fprintf(b, "\t\t%s: %s,\n", sqlIdent(column.name), expression)
	}
	fmt.Fprintf(
		b,
		"\t}); err != nil {\n\t\treturn projectionError(projection%s, projectionFieldRow, err)\n\t}\n",
		storagePascal(table),
	)
	if secondary, ok := secondaryProjectors[schema]; ok {
		fmt.Fprintf(b, "\treturn s.%s(ctx, conn, state, value)\n}\n\n", secondary)
	} else {
		b.WriteString("\treturn nil\n}\n\n")
	}
	return nil
}

func generateProjectionIdentifiers(
	output, contractsRef string,
	vocabulary *projectionVocabulary,
) error {
	projections := make([]string, 0, len(vocabulary.projections))
	for projection := range vocabulary.projections {
		projections = append(projections, projection)
	}
	sort.Strings(projections)
	fields := make([]string, 0, len(vocabulary.fields))
	for field := range vocabulary.fields {
		fields = append(fields, field)
	}
	sort.Strings(fields)

	var b strings.Builder
	fmt.Fprintf(
		&b,
		"// Code generated from traust-contracts %s projection metadata. DO NOT EDIT.\n\npackage storage\n\nconst (\n",
		contractsRef,
	)
	for _, projection := range projections {
		fmt.Fprintf(&b, "\tprojection%s projectionName = %q\n", storagePascal(projection), projection)
	}
	for _, field := range fields {
		fmt.Fprintf(&b, "\tprojectionField%s projectionField = %q\n", storagePascal(field), field)
	}
	b.WriteString(")\n")
	return formatAndWrite(output, []byte(b.String()))
}

func isProjectionMetadata(name string) bool {
	return name == "binding_id" || name == "artifact_digest"
}

func storagePascal(s string) string {
	name := toPascalCase(s)
	name = strings.ReplaceAll(name, "Adr", "ADR")
	name = strings.ReplaceAll(name, "Pqc", "PQC")
	return name
}

// isEnumProperty reports whether a projected root property is a string enum,
// directly or through its resolved $ref.
func isEnumProperty(node *SchemaNode) bool {
	if node == nil {
		return false
	}
	if len(node.Enum) > 0 {
		return true
	}
	return node.ResolvedRef != nil && len(node.ResolvedRef.Enum) > 0
}
