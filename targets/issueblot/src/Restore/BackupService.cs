using Newtonsoft.Json;

namespace IssueBlot.Restore;

// Restores application objects from an uploaded backup document.
public class BackupService
{
    private static readonly JsonSerializerSettings SerializerSettings = new()
    {
        TypeNameHandling = TypeNameHandling.All,
    };

    public object? Restore(Stream body)
    {
        using var reader = new StreamReader(body);
        var document = reader.ReadToEnd();
        return JsonConvert.DeserializeObject(document, SerializerSettings);
    }
}
