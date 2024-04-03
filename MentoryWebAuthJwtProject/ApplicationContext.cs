using MentoryWebAuthJwtProject;
using Microsoft.EntityFrameworkCore;
public class ApplicationContext : DbContext
{
    public DbSet<User> Users { get; set; } = null!;
    public DbSet<Person> People { get; set; } = null!;
    public ApplicationContext(DbContextOptions<ApplicationContext> options)
        : base(options)
    {
        Database.Migrate();
        //Database.EnsureCreated();   // создаем базу данных при первом обращении
    }
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>().HasData(
                new User { Id = 1, Name = "Tom", Age = 37 },
                new User { Id = 2, Name = "Bob", Age = 41 },
                new User { Id = 3, Name = "Sam", Age = 24 }
        );

        modelBuilder.Entity<Person>().HasData(
            new Person { Id = 1, Name = "Admin", Email = "admin@gmail.com", PassHash = "JfnnlDI7RTiF9RgfG2JNCw==" }
        );
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseSqlServer();
    }
}