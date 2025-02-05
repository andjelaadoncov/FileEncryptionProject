using CryptographyWebApp.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;

var builder = WebApplication.CreateBuilder(args);

// Citanje direktorijuma iz konfiguracije
var targetDirectory = builder.Configuration["FileDirectories:Target"];
var outputDirectory = builder.Configuration["FileDirectories:X"];

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddSingleton<CryptoService>();
builder.Services.AddSingleton(sp => new DirectoryWatcherService(
    targetDirectory,
    outputDirectory,
    sp.GetRequiredService<CryptoService>() // This resolves the CryptoService dependency
));
builder.Services.AddSingleton<FileExchangeService>();



var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();
