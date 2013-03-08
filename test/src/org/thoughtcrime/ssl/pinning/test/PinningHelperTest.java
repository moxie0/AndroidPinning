package org.thoughtcrime.ssl.pinning.test;

import android.test.AndroidTestCase;
import android.util.Log;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.thoughtcrime.ssl.pinning.util.PinningHelper;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.URL;

public class PinningHelperTest extends AndroidTestCase {

  public void testGoodUrlConnection() throws IOException {
    String[] pins = new String[] {"40c5401d6f8cbaf08b00edefb1ee87d005b3b9cd"};
    HttpsURLConnection connection = PinningHelper.getPinnedHttpsURLConnection(getContext(), pins, new URL("https://www.google.com/"));
    connection.getInputStream();
  }

  public void testBadUrlConnection() throws IOException {
    String[] pins = new String[] {"40c5401d6f8cbaf08b00edefb1ee87d005b3b9cd"};
    HttpsURLConnection connection = PinningHelper.getPinnedHttpsURLConnection(getContext(), pins, new URL("https://www.twitter.com/"));

    try {
      connection.getInputStream();
    } catch (IOException ioe) {
      Log.w("PinningHelperTest", ioe);
      return;
    }

    fail("Accepted bad pin!");
  }

  public void testGoodHttpClient() throws IOException {
    String[] pins = new String[] {"40c5401d6f8cbaf08b00edefb1ee87d005b3b9cd"};
    HttpClient client = PinningHelper.getPinnedHttpClient(getContext(), pins);
    client.execute(new HttpGet("https://www.google.com"));
  }

  public void testBadHttpClient() {
    String[] pins = new String[] {"40c5401d6f8cbaf08b00edefb1ee87d005b3b9cd"};
    HttpClient client = PinningHelper.getPinnedHttpClient(getContext(), pins);
    try {
      client.execute(new HttpGet("https://www.twitter.com"));
    } catch (IOException ioe) {
      Log.w("PinningHelperTest", ioe);
      return;
    }

    fail("Accepted bad pin!");
  }


}
