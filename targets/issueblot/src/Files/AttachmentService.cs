namespace IssueBlot.Files;

// Serves attachment files from a configured storage directory.
public class AttachmentService
{
    private readonly string _storageRoot;

    public AttachmentService(string storageRoot) => _storageRoot = storageRoot;

    public byte[] Read(string name)
    {
        var path = Path.Combine(_storageRoot, name);
        return File.ReadAllBytes(path);
    }
}
