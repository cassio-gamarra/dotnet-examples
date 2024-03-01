public class TokenGen 
{
    private string GenerateToken(IEnumerable<Claim> userClaims)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var securityKey = new SymmetricSecurityKey(Convert.FromBase64String(SUA_SECRET));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var issuedUtc = DateTime.UtcNow;
        var expiresUtc = DateTime.UtcNow.AddHours(2);

        var jwtToken = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(userClaims),
            SigningCredentials = credentials,
            Issuer = _issuer,
            Audience = _audience,
            IssuedAt = issuedUtc,
            Expires = expiresUtc
        });

        var accessToken = tokenHandler.WriteToken(jwtToken);

        return accessToken;
    }
}