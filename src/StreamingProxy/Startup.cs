using System;
using System.IO;
using System.Net.Http;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace StreamingProxy
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(minLevel: LogLevel.Verbose);

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

        private static Task<HttpResponseMessage> GetUrl(string url) => new System.Net.Http.HttpClient().GetAsync(url);

        private static Stream Encrypt(Stream s, long length) => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true)
            .With(x => x.AddMethod("password_here".ToCharArray(), HashAlgorithmTag.MD5))
            .Open(s, length);

        private static Stream Compress(Stream s) => new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip).Open(s);
        private static Stream LiteralOutput(Stream s, long length) => new PgpLiteralDataGenerator().Open(s, 'a', "bob", length, DateTime.Now); // TODO - params 2 and 3 here are nonsense

        public static async Task EncryptResponseStream(HttpContext context, bool armour)
        {
            var url = context.Request.Query["url"];
            Console.WriteLine(url);
            var httpResponseMessage = await GetUrl(url);
            if (!httpResponseMessage.Content.Headers.ContentLength.HasValue)
            {
                throw new Exception("The response did not contain a content length");
            }

            var contentLength = httpResponseMessage.Content.Headers.ContentLength.Value;

            var responseStream = context.Response.Body;

            if (armour) responseStream = new ArmoredOutputStream(responseStream);

            using (var encryptedStream = Encrypt(responseStream, contentLength))
            using (var compressedStream = Compress(encryptedStream))
            using (var literalStream = LiteralOutput(compressedStream, contentLength))
            {
                await httpResponseMessage.Content.CopyToAsync(literalStream);
                if (armour) literalStream.Close();
            }
        }
    }
}