# Deep-Fried-inator

## Description

Welcome to the Deep-Fried-inator website! Crisp your memes, you might just find a spicy flag.

## Files

* [deepfried.zip](deepfried.zip)

## Writeup

First off, this challenge provides us with a zip file containing the source code, so extracting that is the best place to start!

Once we do that, we can see a C# ASP.NET web application and from our Dockerfile, we can see that our flag is located at `/flag.txt` on the server (and yes, it is still Linux even though it's running .NET).

Also in the Dockerfile, we see this line:

```dockerfile
# Install ImageMagick CLI
RUN apt-get update && \
    apt-get install -y imagemagick sqlite3 libmagickwand-6.q16-6 pango1.0-tools fonts-noto-color-emoji && \
    rm -rf /var/lib/apt/lists/*
```


Now, ImageMagick is quite notorious in CTFs. There are several where a vulnerability in this package is the entire solution. However, in this challenge, that is not the case, although it can be very easy to see this package and try to search for CVEs in the version downloaded through `apt`. However, our first sign that this isn't the solution should be that this isn't version-dependent and the Docker container just installs through `apt` without specifying a version. So if a new patch to a CVE was released during the competition, if it were that CVE that was the solution, the challenge would no longer work if the container was rebuilt for whatever reason.

However, that's not to say this isn't important that this package is included, just not for the same reasons.

In `src/src/Services/DeepFryService.cs`, we see that the ImageMagick `convert` binary is used.

```cs
    public async Task<string> DeepFryAsync(string inputPath, string outputPath, string[] emojis)
    {
        var workingPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString() + ".png");
        System.IO.File.Copy(inputPath, workingPath, true);
        var tempFiles = new List<string>();
        string finalOutputPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString() + ".png");
        try
        {
            foreach (var emoji in emojis)
            {
                var emojiPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString() + ".png");
                tempFiles.Add(emojiPath);
                // Randomize emoji size (between 400 and 900 px for much larger emoji)
                int emojiSize = Rng.Next(400, 901);
                int fontSize = emojiSize * 600;
                var xmlEntityRobust = ToXmlEntity(emoji);
                var emojiCmd = $"convert -size {emojiSize}x{emojiSize} -background none 'pango:<span font=\"Noto Color Emoji\" size=\"{fontSize}\">{xmlEntityRobust}</span>' {emojiPath}";
                await RunShellAsync(emojiCmd);
  
                // Randomize orientation (0-359 degrees)
                int angle = Rng.Next(0, 360);
                var rotatedEmojiPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString() + ".png");
                tempFiles.Add(rotatedEmojiPath);

                var rotateCmd = $"convert {emojiPath} -background none -rotate {angle} {rotatedEmojiPath}";
                await RunShellAsync(rotateCmd);
  
                // Randomize position (x, y) within 1024x1024, keeping emoji fully in bounds
                int maxPos = 1024 - emojiSize;
                int x = (maxPos > 0) ? Rng.Next(0, maxPos + 1) : Rng.Next(maxPos, 100);
                int y = (maxPos > 0) ? Rng.Next(0, maxPos + 1) : Rng.Next(maxPos, 100);
  
                // Overlay this emoji on the working image
                var nextWorkingPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString() + ".png");
                tempFiles.Add(nextWorkingPath);
                var fryCmd = $"convert {workingPath} -modulate 120,400,100 -contrast -contrast -resize 1024x1024\\! " +
                             $"{rotatedEmojiPath} -geometry +{x}+{y} -composite {nextWorkingPath}";
                await RunShellAsync(fryCmd);
                workingPath = nextWorkingPath;
            }
            System.IO.File.Copy(workingPath, finalOutputPath, true);
        }
        finally
        {
            foreach (var f in tempFiles)
            {
                if (System.IO.File.Exists(f))
                {
                    try { System.IO.File.Delete(f); } catch { /* ignore */ }
                }
            }
        }
        return finalOutputPath;
    }
```

And that `RunShellAsync` method that is called to use `convert` simply uses `Process.Start` to start a `bash` process with the correct command line arguments.

Now, this might also seem like possible command injection. Well, it sort of is, but not in the way you might think. You can't control the `emojiSize` since that is a randomized int. The same is true for `fontSize`. All the variables storing the paths are created through temporary directories with randomized GUIDs which we can't control. The `angle`, `x`, and `y` variables are also randomized. And even the `xmlEntityRobust` variable created based on the `emoji` input won't give us command injection since all characters are converted to their hexadecimal XML entities rather than their literal values.

The service is also called inside `src/src/Controllers/MemeController.cs`, which also controls the functionality for the entire website.

However, before invoking that service, one section stands out very significantly under the POST handler for `/submit`:

```cs
            var userFileName = file.FileName;
            var uploadPath = Path.Combine("/app/uploads", userFileName);
            using (var fs = new FileStream(uploadPath, FileMode.Create))
                await file.CopyToAsync(fs);
```

There is no input sanitation for the file name and it is simply concatenated to `/app/uploads` using `Path.Combine`. And it copies our file to that same path. Since we know the server is run as the `root` user, we can even overwrite system binaries, including `convert`! And since `convert` is always called with the output path as the last parameter of the command, we can just replace `convert` with a shell script to write our flag to the output file.

However, there will be a few checks we have to get through first. For one, the `ContentType` of the file has to start with "image/", although this will be very easy to edit in BurpSuite since no checks of the magic bytes of the file are performed to verify the MIME type is accurate. The file also can't be larger than 2 MB which shouldn't be a problem with a simple shell script. However, we do need to be signed in and that isn't as simple as creating an account.

We can see pretty clearly that the username and password aren't the only inputs required to register:

```cs
        app.MapGet("/register", () =>
        {
            var html =
                "<link rel='stylesheet' href='/deepfried.css'>\n" +
                "<meta charset='UTF-8'>\n" +
                "<h1>Sign up, netizen 🚀</h1>\n" +
                "<form method='post'>\n" +
                "  <input name='username' placeholder='Username' required>\n" +
                "  <input name='password' type='password' placeholder='Password' required>\n" +
                "  <input name='invite' placeholder='Invite Code' required>\n" +
                "  <button type='submit'>Jack in</button>\n" +
                "</form>\n";
            return Results.Content(html, "text/html");
        });
```

Perhaps a little nostalgia for anyone who remembers when you had to do this to sign up for HackTheBox, but we have to find an invite code!

Looking just a little further down, though, there is an error that isn't handled gracefully...

```cs
            if (!System.Text.RegularExpressions.Regex.IsMatch(invite, "^[a-zA-Z0-9]+$"))
            {
                throw new Exception("Unexpected invite code characters. Code must only contain alphanumeric chars.");
            }
```

If we have any special characters an `Exception` will be thrown. So we know that one of two things are true. Either this error will completely crash the server or it will be caught, perhaps displaying some useful information. And in fact, it is the second one! If we look in `src/src/Program.cs`, we see this:

```cs
// Custom error page
app.Use(async (ctx, next) =>
{
    try { await next(); }
    catch (Exception ex)
    {
        ctx.Response.StatusCode = 500;
        // Leak all environment variables
        var envVars = System.Environment.GetEnvironmentVariables();
        var envDump = string.Join("\n", envVars.Keys.Cast<object>().Select(k => $"{k}={envVars[k]}"));
        var html = $"""
            <link rel='stylesheet' href='/deepfried.css'>
            <meta charset='UTF-8'>
            <div class='system-meltdown'>
                <h1>💥 SYSTEM MELTDOWN! 💥</h1>
                <p>Whoa, something got <b>too spicy</b>: {ex.Message} <span style='font-size:2em;'>🔥🤯🔥</span></p>
                <pre>{ex.StackTrace}</pre>
                <h2>Environment Variables (HACK THE PLANET)</h2>
                <pre>{System.Net.WebUtility.HtmlEncode(envDump)}</pre>
                <p>Debug like a pro, or just vibe and try again. <span style='font-size:2em;'>🦄💾🦄</span></p>
            </div>
        """;

        await Results.Content(html, "text/html").ExecuteAsync(ctx);
    }
});
```

Leaking all environment variables, including `INVITE_CODE` which we know is set in `RESET.sh` is definitely an interesting choice! So all we need to do to get this invite code is just put a special character into the field before submitting the first time!

So we have our game plan to solve this:
1. Craft a shell script to copy `/flag.txt` to the file contained in the last argument to the script
2. Use the poor error handling in the server to leak the invite code using a special character in the field for the invite code in the registration form
3. Register an account using this invite code
4. Upload our crafted payload to traverse to the `convert` binary
5. Check the output for the flag

First, for making our payload, it's pretty simple. The following script should work perfectly:

```bash
#!/bin/bash

cat /flag.txt > ${@: -1}

```

We do need to make sure the correct "shebang" is there, though, so the server knows to execute this as Bash and not as an ELF binary!

That's really all there is to it.

Now, we can open BurpSuite and launch our instance to get started!

First, we put a special character into the registration form:

![Invite code](../../images/Pasted%20image%2020250618173953.png)

Now we use that invite code to log in and we can start to upload our payload!

Once we click "Submit Meme", we want to turn interception on in the Burp proxy. 

![Submit page](../../images/Pasted%20image%2020250618174107.png)

Once we submit, we see this form data:

![Intercepted request](../../images/Pasted%20image%2020250618174142.png)

We just need to change that `Content-Type` as well as the `filename`!

For the content type, `image/png` should work fine. For the filename, though, we know we need to get from `/app/uploads` to `/usr/bin/convert`, so `../../usr/bin/convert` should work!

So we just submit that!

![Payload](../../images/Pasted%20image%2020250618174443.png)

(ignore the slight differences, I made a typo in the filename at first)

Now, we can just view that first image!

![Not an image](../../images/Pasted%20image%2020250618174513.png)

That's clearly not a real image, so let's view its source:

![Flag](../../images/Pasted%20image%2020250618174547.png)

And we have our flag, `SVUSCG{d33p_fr1ed_p4th_tr4v3rsal_3moj1}`!

Now is a good time to mention how easy it is to mess up on this challenge though. At first, I thought that probably an immutable flag was set on the flag, as with most CTF challenges, and tried to copy the flag to the image file being passed through rather than overwriting `convert`. I didn't realize it at first, but I had actually overwritten the flag. So it is really good that this has private instances or otherwise that flag would be long gone and it would probably have no solves!
