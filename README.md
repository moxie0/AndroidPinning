Android Pinning
=================

AndroidPinning is a standalone Android library project that facilitates certificate pinning for SSL
connections from Android apps, in order to minimize dependence on Certificate Authorities.

CA signatures are necessary for *general purpose* network communication tools: things like web
browsers, which connect to arbitrary network endpoints and have no advance knowledge of what the SSL
certificates for those endpoint should look like.

Most mobile apps are not *general purpose* communication tools.  Instead, they typically connect
directly to a narrow set of backend services that the app's author either controls, or can
predict ahead of time.

This creates an opportunity for app developers to sidestep the security problems inherent with
Certificate Authorities.  The best way is to throw CA certificates out the window entirely by
signing your own endpoint certificates with your own offline signing certificate, which you then
distribute with your app.  See [this blog post](http://thoughtcrime.org/blog/authenticity-is-broken-in-ssl-but-your-app-ha/)
for examples of the no-CA technique.

Sometimes, however, that's not possible, and you need to continue using CA certificates for one
reason or another.  Perhaps the API endpoint is shared with a web browser's endpoint, for instance.

In that case, it's necessary to employ "pinning," which is simply the act of verifying that the
certificate chain looks the way you know it should, even if it's signed by a CA.  This prevents
*other* CAs from being able to effectively create forged certificates for your domain, as with the
many Comodo breaches, the DigiNotar breach, and the TurkTrust breach.

This library is designed to make pinning easier on Android.  It's structured as an Android library
project, so you can simply link it to your own project and begin.

Using AndroidPinning
-----------

If you're using gradle to build your project, you can include the AndroidPinning artifact by
adding a dependency:

```
   dependencies {
       compile 'org.thoughtcrime.ssl.pinning:AndroidPinning:1.0.0'
   }
```

Examples
-----------

Using a simple `HttpsURLConnection` with a `PinningTrustManager`:

```java
// Define an array of pins.  One of these must be present
// in the certificate chain you receive.  A pin is a hex-encoded
// hash of a X.509 certificate's SubjectPublicKeyInfo. A pin can
// be generated using the provided pin.py script:
// python ./tools/pin.py certificate_file.pem
String[] pins                 = new String[] {"f30012bbc18c231ac1a44b788e410ce754182513"};
URL url                       = new URL("https://www.google.com");
HttpsURLConnection connection = PinningHelper.getPinnedHttpsURLConnection(context, pins, url);

return connection.getInputStream();
```

Using a simple `HttpClient` with a `PinningTrustManager`:

```java
String[] pins         = new String[] {"f30012bbc18c231ac1a44b788e410ce754182513"};
HttpClient httpClient = PinningHelper.getPinnedHttpClient(context, pins);

HttpResponse response = httpClient.execute(new HttpGet("https://www.google.com/"));
```

It's also possible to work with `PinningTrustManager` and `PinningSSLSocketFactory` more directly:

```java
String[] pins                 = new String[] {"40c5401d6f8cbaf08b00edefb1ee87d005b3b9cd"};
SchemeRegistry schemeRegistry = new SchemeRegistry();
schemeRegistry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
schemeRegistry.register(new Scheme("https", new PinningSSLSocketFactory(getContext() ,pins, 0), 443));

HttpParams httpParams                     = new BasicHttpParams();
ClientConnectionManager connectionManager = new ThreadSafeClientConnManager(httpParams, schemeRegistry);
DefaultHttpClient httpClient              = new DefaultHttpClient(connectionManager, httpParams);

HttpResponse response = httpClient.execute(new HttpGet("https://www.google.com/"));
```

Issues
-----------

Have a bug? Please create an issue here on GitHub!

https://github.com/moxie0/AndroidPinning/issues

License
---------------------

Copyright 2011-2013 Moxie Marlinspike

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

Please contact me if this license doesn't work for you.
