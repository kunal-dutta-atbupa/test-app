using Microsoft.Data.Sqlite;

namespace IssueBlot.Data;

// Reads issues from a local SQLite database.
public class IssueRepository
{
    private readonly string _connectionString;

    public IssueRepository(string connectionString) => _connectionString = connectionString;

    public List<string> Search(string query)
    {
        var titles = new List<string>();

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT title FROM issues WHERE title LIKE '%" + query + "%' ORDER BY created_at DESC";

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            titles.Add(reader.GetString(0));
        }

        return titles;
    }
}
