using System;
using System.IO;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Text;
using System.Threading.Tasks;

namespace StreamingProxy
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseIISPlatformHandler();

            app.Run(async context =>
            {
                Console.WriteLine("Writing response");
                await StreamingEncryptionMiddleware.EncryptResponseStream(context, false);
            });
        }

        public static void Main(string[] args) => WebApplication.Run<Startup>(args);
    }

    public static class StreamingEncryptionMiddleware
    {
        private static T With<T>(this T t, Action<T> a)
        {
            a(t);
            return t;
        }

        private static Stream Encrypt(Stream s, int length) => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true)
            .With(x => x.AddMethod("password_here".ToCharArray(), HashAlgorithmTag.MD5))
            .Open(s, length);

        private static Stream Compress(Stream s) => new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip).Open(s);
        private static Stream LiteralOutput(Stream s, long length) => new PgpLiteralDataGenerator().Open(s, 'a', "bob", length, DateTime.Now);

        public static async Task EncryptResponseStream(HttpContext context, bool armour)
        {
            var bytes = Encoding.UTF8.GetBytes("This is a test This is a test This is a test This is a test This is a test");

            var responseStream = context.Response.Body;

            if (armour) responseStream = new ArmoredOutputStream(responseStream);

            using (var encryptedStream = Encrypt(responseStream, bytes.Length))
            using (var compressedStream = Compress(encryptedStream))
            using (var literalStream = LiteralOutput(compressedStream, bytes.Length))
            {
                await literalStream.WriteAsync(bytes, 0, bytes.Length);
                if (armour) literalStream.Close();
            }
        }
    }
}