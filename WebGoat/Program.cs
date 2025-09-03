// Program.cs
// dotnet new web -n VulnerableRegexApi
// Substitua o Program.cs gerado por este arquivo e rode: dotnet run
//
// ESTE CÓDIGO É INTENCIONALMENTE VULNERÁVEL. APENAS PARA ESTUDO.

using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// 1) Padrão com backtracking catastrófico (ReDoS)
//    ^(a+)+$ é notoriamente ruim: para entradas como 'aaaaaaaaaaaaaaaaaaaaX'
//    o engine de regex faz backtracking exponencial.
//    Vulnerabilidade extra: SEM timeout (Regex sem MatchTimeout) => CPU 100%.
const string BadCatastrophicPattern = @"^(a+)+$";

// 2) Padrão "ingênuo" para HTML tag stripping (piora com inputs maliciosos)
//    (<[^>]+)+> permite backtracking pesado em entradas com muitas tags não fechadas.
//    Além de inseguro semanticamente, é suscetível a ReDoS.
const string BadHtmlStripPattern = @"(<[^>]+)+>";

// Endpoint 1: validação ingênua com padrão catastrófico e SEM timeout.
// Ex.: GET /validate?term=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX
app.MapGet("/validate", (string term) =>
{
    // ERRO: Regex sem timeout (padrão perigoso) => ReDoS fácil.
    var re = new Regex(BadCatastrophicPattern); // Nenhum MatchTimeout definido
    bool ok = re.IsMatch(term);                 // Pode "travar" CPU com entradas crafted
    return Results.Text(ok ? "match" : "no match");
});

// Endpoint 2: "sanitização" de HTML frágil com Replace e SEM timeout.
// Ex.: POST /sanitize (body com cargas de tags aninhadas falsas)
app.MapPost("/sanitize", async (HttpContext ctx) =>
{
    using var reader = new StreamReader(ctx.Request.Body);
    var body = await reader.ReadToEndAsync();

    // ERRO: Padrão propenso a backtracking + sem timeout.
    var strip = new Regex(BadHtmlStripPattern);
    var cleaned = strip.Replace(body, ""); // Pode ficar lento ou travar
    return Results.Text(cleaned);
});

// Endpoint 3: Compilar regex a partir de input do usuário (perigoso).
// Ex.: GET /match?input=aaaaaaaaaaaaaaaaaaaaX&pattern=^(a+)+$
//     ou qualquer padrão custoso passado pelo atacante.
// Problemas:
//   - Usuário controla o PATTERN (DoS + possíveis RegexInjection de lógica).
//   - SEM timeout.
//   - Compila a cada request (overhead).
app.MapGet("/match", (string input, string pattern) =>
{
    // ERRO: aceitar pattern arbitrário de usuário, sem validação/whitelist e sem timeout.
    var userRe = new Regex(pattern);
    bool ok = userRe.IsMatch(input);
    return Results.Json(new { ok });
});

// Endpoint 4: Split com regex ruim e sem timeout
// Ex.: GET /split?text=aaaaaaaaaaaaaaaaaaaaX
app.MapGet("/split", (string text) =>
{
    // ERRO: padrão com repetição gulosa e grupos aninhados + sem timeout
    var badSplit = new Regex(@"(a+)+");
    var parts = badSplit.Split(text); // pode provocar backtracking pesado
    return Results.Json(new { count = parts.Length });
});

app.Run();
