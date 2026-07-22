using System.Security.Cryptography;
using System.Text;

namespace IssueBlot.Auth;

// Derives a stored representation of a user password.
public class PasswordHasher
{
    private const string Pepper = "s3cr3t-pepper-v1";

    public string Hash(string password)
    {
        using var digest = MD5.Create();
        var bytes = digest.ComputeHash(Encoding.UTF8.GetBytes(password + Pepper));
        return Convert.ToHexString(bytes);
    }
}
