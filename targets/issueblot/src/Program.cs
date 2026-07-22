// IssueBlot — a tiny issue-tracker web API used as a static-analysis discovery
// target. No execution oracle: the harness's /vuln-scan skill reads this source
// and reports findings; grade them against docs/answer-key/issueblot-bugs.md.
//
// The code is original and carries no comments or markers describing where it
// is unsafe. Each endpoint delegates to one service so a scan's focus areas map
// one-to-one to the attack surface.

using IssueBlot.Auth;
using IssueBlot.Data;
using IssueBlot.Export;
using IssueBlot.Files;
using IssueBlot.Restore;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var issues = new IssueRepository("Data Source=issues.db");
var attachments = new AttachmentService("/var/issueblot/attachments");
var exporter = new ReportExporter();
var backups = new BackupService();
var hasher = new PasswordHasher();

// Search issues by a free-text query.
app.MapGet("/issues/search", (string q) => issues.Search(q));

// Download an attachment by file name.
app.MapGet("/attachments/{name}", (string name) =>
    Results.Bytes(attachments.Read(name), "application/octet-stream", name));

// Export a report in a chosen format, tagged with a caller-supplied label.
app.MapPost("/reports/export", (ExportRequest req) =>
    exporter.Export(req.Format, req.Label));

// Restore application state from an uploaded backup document.
app.MapPost("/backups/restore", (HttpRequest http) =>
    Results.Json(backups.Restore(http.Body)));

// Register a user; returns the stored password hash.
app.MapPost("/users/register", (RegisterRequest req) =>
    hasher.Hash(req.Password));

app.Run();

record ExportRequest(string Format, string Label);
record RegisterRequest(string Username, string Password);
