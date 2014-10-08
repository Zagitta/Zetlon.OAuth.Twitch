A simple Twitch OAuth2 client/provider for ASP.NET websites 
==================

No guarantees are made about the functionality of this software.
 

Based on information from the following sources:

* https://github.com/jbubriski/GitHubOAuth2Client
* http://stackoverflow.com/questions/14973017/how-to-let-users-login-to-my-site-using-soundcloud
* https://github.com/justintv/twitch-api

 
Example:
==================

Make settings entries for your client id and secret from twitch and in your AuthConfig.cs register a TwitchClient like this:

```csharp
OAuthWebSecurity.RegisterClient(new TwitchClient(Settings.Default.ClientId, Settings.Default.ClientSecret, "channel_check_subscription"));
```

And in your AccountController do the following:

```csharp
[HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public ActionResult TwitchLogin()
{
    return new TwitchLoginResult(GetReturnUrl());
}

[AllowAnonymous]
public ActionResult TwitchCallback(string returnUrl)
{
    Uri redirectUrl;
    if (TwitchClient.DecodeCallback(out redirectUrl))
    {
        return RedirectToLocal(redirectUrl.PathAndQuery);
    }

    AuthenticationResult auth = OAuthWebSecurity.VerifyAuthentication();

    if(auth.IsSuccessful)
    {
        //Look at DotNetOpenAuth if you need to link twitch accounts to local accounts
       FormsAuthentication.SetAuthCookie(auth.ProviderUserId, false);
        
        return RedirectToLocal(returnUrl);
    }

    return View("LoginError");
}

class TwitchLoginResult : ActionResult
{
    public TwitchLoginResult(string returnUrl)
    {
        ReturnUrl = returnUrl;
    }

    public string ReturnUrl { get; private set; }

    public override void ExecuteResult(ControllerContext context)
    {
        OAuthWebSecurity.RequestAuthentication("Twitch", ReturnUrl);
    }
}
```

