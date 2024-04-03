using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using System;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Text;

namespace MentoryWebAuthJwtProject
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder();
            string connection = builder.Configuration.GetConnectionString("DefaultConnection");
            builder.Services.AddDbContext<ApplicationContext>(options => options.UseSqlServer(connection));
            builder.Services.AddAuthorization();
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        // указывает, будет ли валидироваться издатель при валидации токена
                        ValidateIssuer = true,
                        // строка, представляющая издателя
                        ValidIssuer = AuthOptions.ISSUER,
                        // будет ли валидироваться потребитель токена
                        ValidateAudience = true,
                        // установка потребителя токена
                        ValidAudience = AuthOptions.AUDIENCE,
                        // будет ли валидироваться время существования
                        ValidateLifetime = true,
                        // установка ключа безопасности
                        IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
                        // валидация ключа безопасности
                        ValidateIssuerSigningKey = true,
                    };
                });
            

            var app = builder.Build();
            app.UseAuthentication();   // добавление middleware аутентификации 
            app.UseAuthorization();   // добавление middleware авторизации 

            
            

            

            app.MapPost("/login", async (string? returnUrl, HttpContext context, ApplicationContext db, PersonFormdata loginInfo) =>
            {
                

                string email = loginInfo.Email;
                string password = Person.GetHash(loginInfo.Password);

                // находим пользователя 
                Person? person = db.People.FirstOrDefault(p => p.Email == email && p.PassHash == password);

                // если пользователь не найден, отправляем статусный код 401
                if (person is null) return Results.Unauthorized();

                var claims = new List<Claim> { new Claim(ClaimTypes.Name, person.Email) };
                // создаем JWT-токен
                var jwt = new JwtSecurityToken(
                        issuer: AuthOptions.ISSUER,
                        audience: AuthOptions.AUDIENCE,
                        claims: claims,
                        expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
                        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                // формируем ответ
                var response = new
                {
                    access_token = encodedJwt,
                    username = person.Email
                };

                return Results.Json(response);
            });

            app.MapGet("/logout", async (HttpContext context) =>
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return Results.Redirect("/login");
            });

            app.Map("/", async (HttpContext context) =>
            {
                context.Response.ContentType = "text/html";
                await context.Response.SendFileAsync("html\\index.html");
            });

            app.MapGet("/api/users", [Authorize] async (ApplicationContext db) => await db.Users.ToListAsync());

            app.MapGet("/api/users/{id:int}", [Authorize] async (int id, ApplicationContext db) =>
            {
                // получаем пользователя по id
                User? user = await db.Users.FirstOrDefaultAsync(u => u.Id == id);

                // если не найден, отправляем статусный код и сообщение об ошибке
                if (user == null) return Results.NotFound(new { message = "Пользователь не найден" });

                // если пользователь найден, отправляем его
                return Results.Json(user);
            });

            app.MapDelete("/api/users/{id:int}", [Authorize] async (int id, ApplicationContext db) =>
            {
                // получаем пользователя по id
                User? user = await db.Users.FirstOrDefaultAsync(u => u.Id == id);

                // если не найден, отправляем статусный код и сообщение об ошибке
                if (user == null) return Results.NotFound(new { message = "Пользователь не найден" });

                // если пользователь найден, удаляем его
                db.Users.Remove(user);
                await db.SaveChangesAsync();
                return Results.Json(user);
            });

            app.MapPost("/api/users", [Authorize] async (User user, ApplicationContext db) =>
            {
                // добавляем пользователя в массив
                await db.Users.AddAsync(user);
                await db.SaveChangesAsync();
                return user;
            });

            app.MapPut("/api/users", [Authorize] async (User userData, ApplicationContext db) =>
            {
                // получаем пользователя по id
                var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userData.Id);

                // если не найден, отправляем статусный код и сообщение об ошибке
                if (user == null) return Results.NotFound(new { message = "Пользователь не найден" });

                // если пользователь найден, изменяем его данные и отправляем обратно клиенту
                user.Age = userData.Age;
                user.Name = userData.Name;
                await db.SaveChangesAsync();
                return Results.Json(user);
            });

            
            app.Run();
        }

        record class PersonFormdata(string Email, string Password);
        public class AuthOptions
        {
            public const string ISSUER = "TimurIssuer"; // издатель токена
            public const string AUDIENCE = "MyAuthClient"; // потребитель токена
            const string KEY = "mysupersecret_secretsecretsecretkey!123";   // ключ для шифрации
            public static SymmetricSecurityKey GetSymmetricSecurityKey() =>
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(KEY));
        }
    }
}
