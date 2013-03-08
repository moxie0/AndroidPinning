package org.thoughtcrime.ssl.pinning.test;

import android.test.AndroidTestCase;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.thoughtcrime.ssl.pinning.PinningTrustManager;
import org.thoughtcrime.ssl.pinning.SystemKeyStore;

public class PinningTrustManagerTest extends AndroidTestCase {

  private static final String GOOGLE_WILDCARD = "-----BEGIN CERTIFICATE-----\n" +
    "MIIFwjCCBSugAwIBAgIKFIjX3wAAAAB+EjANBgkqhkiG9w0BAQUFADBGMQswCQYD\n" +
    "VQQGEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzEiMCAGA1UEAxMZR29vZ2xlIElu\n" +
    "dGVybmV0IEF1dGhvcml0eTAeFw0xMzAyMjAxMzM5MDVaFw0xMzA2MDcxOTQzMjda\n" +
    "MGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1N\n" +
    "b3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMRUwEwYDVQQDFAwqLmdv\n" +
    "b2dsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASaZ9NYziybfOSUKy30\n" +
    "1ObuMLBenlTBt7XefQPQp9VT3GT99AzCbs88fKw63dUC7o4AAjYrlYxPLKzmELzC\n" +
    "SJtLo4ID3DCCA9gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAsGA1Ud\n" +
    "DwQEAwIHgDAdBgNVHQ4EFgQUdCmVkTNOPieALbnLYuaoJLpgHyowHwYDVR0jBBgw\n" +
    "FoAUv8Aw6/VDET5nup6R+/xq2uNrEiQwWwYDVR0fBFQwUjBQoE6gTIZKaHR0cDov\n" +
    "L3d3dy5nc3RhdGljLmNvbS9Hb29nbGVJbnRlcm5ldEF1dGhvcml0eS9Hb29nbGVJ\n" +
    "bnRlcm5ldEF1dGhvcml0eS5jcmwwZgYIKwYBBQUHAQEEWjBYMFYGCCsGAQUFBzAC\n" +
    "hkpodHRwOi8vd3d3LmdzdGF0aWMuY29tL0dvb2dsZUludGVybmV0QXV0aG9yaXR5\n" +
    "L0dvb2dsZUludGVybmV0QXV0aG9yaXR5LmNydDAMBgNVHRMBAf8EAjAAMIIClQYD\n" +
    "VR0RBIICjDCCAoiCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lkLmNvbYIWKi5hcHBl\n" +
    "bmdpbmUuZ29vZ2xlLmNvbYISKi5jbG91ZC5nb29nbGUuY29tghYqLmdvb2dsZS1h\n" +
    "bmFseXRpY3MuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUuY2yCDiouZ29vZ2xl\n" +
    "LmNvLmlugg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28udWuCDyouZ29vZ2xl\n" +
    "LmNvbS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5jb20uYnKCDyouZ29v\n" +
    "Z2xlLmNvbS5jb4IPKi5nb29nbGUuY29tLm14gg8qLmdvb2dsZS5jb20udHKCDyou\n" +
    "Z29vZ2xlLmNvbS52boILKi5nb29nbGUuZGWCCyouZ29vZ2xlLmVzggsqLmdvb2ds\n" +
    "ZS5mcoILKi5nb29nbGUuaHWCCyouZ29vZ2xlLml0ggsqLmdvb2dsZS5ubIILKi5n\n" +
    "b29nbGUucGyCCyouZ29vZ2xlLnB0gg8qLmdvb2dsZWFwaXMuY26CFCouZ29vZ2xl\n" +
    "Y29tbWVyY2UuY29tgg0qLmdzdGF0aWMuY29tggwqLnVyY2hpbi5jb22CECoudXJs\n" +
    "Lmdvb2dsZS5jb22CFioueW91dHViZS1ub2Nvb2tpZS5jb22CDSoueW91dHViZS5j\n" +
    "b22CCyoueXRpbWcuY29tggthbmRyb2lkLmNvbYIEZy5jb4IGZ29vLmdsghRnb29n\n" +
    "bGUtYW5hbHl0aWNzLmNvbYIKZ29vZ2xlLmNvbYISZ29vZ2xlY29tbWVyY2UuY29t\n" +
    "ggp1cmNoaW4uY29tggh5b3V0dS5iZYILeW91dHViZS5jb20wDQYJKoZIhvcNAQEF\n" +
    "BQADgYEAvByiw85X7a+NdFSIDEa83yCRgaSVwqCayfKTnaYXVPQEd439pb5ksJcl\n" +
    "D8WSqffIaknHXyM85g6yoDL97VjUlM7PCqh0JITydGYkSsowkIla60v7SU5C2ydr\n" +
    "jyxmNkJCZGIUJgdX31p8cMvW1tWUkdaf63IpQpJtz7W2+nlYNG8=\n"             +
    "-----END CERTIFICATE-----\n";

  private static final String GOOGLE_AUTHORITY = "-----BEGIN CERTIFICATE-----\n" +
      "MIICsDCCAhmgAwIBAgIDC2dxMA0GCSqGSIb3DQEBBQUAME4xCzAJBgNVBAYTAlVT\n" +
      "MRAwDgYDVQQKEwdFcXVpZmF4MS0wKwYDVQQLEyRFcXVpZmF4IFNlY3VyZSBDZXJ0\n" +
      "aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDkwNjA4MjA0MzI3WhcNMTMwNjA3MTk0MzI3\n" +
      "WjBGMQswCQYDVQQGEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzEiMCAGA1UEAxMZ\n" +
      "R29vZ2xlIEludGVybmV0IEF1dGhvcml0eTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw\n" +
      "gYkCgYEAye23pIucV+eEPkB9hPSP0XFjU5nneXQUr0SZMyCSjXvlKAy6rWxJfoNf\n" +
      "NFlOCnowzdDXxFdF7dWq1nMmzq0yE7jXDx07393cCDaob1FEm8rWIFJztyaHNWrb\n" +
      "qeXUWaUr/GcZOfqTGBhs3t0lig4zFEfC7wFQeeT9adGnwKziV28CAwEAAaOBozCB\n" +
      "oDAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFL/AMOv1QxE+Z7qekfv8atrjaxIk\n" +
      "MB8GA1UdIwQYMBaAFEjmaPkr0rKV10fYIyAQTzOYkJ/UMBIGA1UdEwEB/wQIMAYB\n" +
      "Af8CAQAwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20v\n" +
      "Y3Jscy9zZWN1cmVjYS5jcmwwDQYJKoZIhvcNAQEFBQADgYEAuIojxkiWsRF8YHde\n" +
      "BZqrocb6ghwYB8TrgbCoZutJqOkM0ymt9e8kTP3kS8p/XmOrmSfLnzYhLLkQYGfN\n" +
      "0rTw8Ktx5YtaiScRhKqOv5nwnQkhClIZmloJ0pC3+gz4fniisIWvXEyZ2VxVKfml\n" +
      "UUIuOss4jHg7y/j7lYe8vJD5UDI=\n" +
      "-----END CERTIFICATE-----\n";

  private static final String EQUIFAX_ROOT = "-----BEGIN CERTIFICATE-----\n" +
      "MIIDIDCCAomgAwIBAgIENd70zzANBgkqhkiG9w0BAQUFADBOMQswCQYDVQQGEwJV\n" +
      "UzEQMA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2Vy\n" +
      "dGlmaWNhdGUgQXV0aG9yaXR5MB4XDTk4MDgyMjE2NDE1MVoXDTE4MDgyMjE2NDE1\n" +
      "MVowTjELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0VxdWlmYXgxLTArBgNVBAsTJEVx\n" +
      "dWlmYXggU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eTCBnzANBgkqhkiG9w0B\n" +
      "AQEFAAOBjQAwgYkCgYEAwV2xWGcIYu6gmi0fCG2RFGiYCh7+2gRvE4RiIcPRfM6f\n" +
      "BeC4AfBONOziipUEZKzxa1NfBbPLZ4C/QgKO/t0BCezhABRP/PvwDN1Dulsr4R+A\n" +
      "cJkVV5MW8Q+XarfCaCMczE1ZMKxRHjuvK9buY0V7xdlfUNLjUA86iOe/FP3gx7kC\n" +
      "AwEAAaOCAQkwggEFMHAGA1UdHwRpMGcwZaBjoGGkXzBdMQswCQYDVQQGEwJVUzEQ\n" +
      "MA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2VydGlm\n" +
      "aWNhdGUgQXV0aG9yaXR5MQ0wCwYDVQQDEwRDUkwxMBoGA1UdEAQTMBGBDzIwMTgw\n" +
      "ODIyMTY0MTUxWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUSOZo+SvSspXXR9gj\n" +
      "IBBPM5iQn9QwHQYDVR0OBBYEFEjmaPkr0rKV10fYIyAQTzOYkJ/UMAwGA1UdEwQF\n" +
      "MAMBAf8wGgYJKoZIhvZ9B0EABA0wCxsFVjMuMGMDAgbAMA0GCSqGSIb3DQEBBQUA\n" +
      "A4GBAFjOKer89961zgK5F7WF0bnj4JXMJTENAKaSbn+2kmOeUJXRmm/kEd5jhW6Y\n" +
      "7qj/WsjTVbJmcVfewCHrPSqnI0kBBIZCe/zuf6IWUrVnZ9NA2zsmWLIodz2uFHdh\n" +
      "1voqZiegDfqnc1zqcPGUIWVEX/r87yloqaKHee9570+sB3c4\n" +
      "-----END CERTIFICATE-----\n";

  private static final String VERISIGN_CLASS_3_EV = "-----BEGIN CERTIFICATE-----\n" +
      "MIIF5DCCBMygAwIBAgIQW3dZxheE4V7HJ8AylSkoazANBgkqhkiG9w0BAQUFADCB\n" +
      "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\n" +
      "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\n" +
      "U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\n" +
      "ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\n" +
      "aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMTYxMTA3MjM1OTU5WjCBujEL\n" +
      "MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\n" +
      "ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQg\n" +
      "aHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykwNjE0MDIGA1UEAxMrVmVy\n" +
      "aVNpZ24gQ2xhc3MgMyBFeHRlbmRlZCBWYWxpZGF0aW9uIFNTTCBDQTCCASIwDQYJ\n" +
      "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJjboFXrnP0XeeOabhQdsVuYI4cWbod2\n" +
      "nLU4O7WgerQHYwkZ5iqISKnnnbYwWgiXDOyq5BZpcmIjmvt6VCiYxQwtt9citsj5\n" +
      "OBfH3doxRpqUFI6e7nigtyLUSVSXTeV0W5K87Gws3+fBthsaVWtmCAN/Ra+aM/EQ\n" +
      "wGyZSpIkMQht3QI+YXZ4eLbtfjeubPOJ4bfh3BXMt1afgKCxBX9ONxX/ty8ejwY4\n" +
      "P1C3aSijtWZfNhpSSENmUt+ikk/TGGC+4+peGXEFv54cbGhyJW+ze3PJbb0S/5tB\n" +
      "Ml706H7FC6NMZNFOvCYIZfsZl1h44TO/7Wg+sSdFb8Di7Jdp91zT91ECAwEAAaOC\n" +
      "AdIwggHOMB0GA1UdDgQWBBT8ilC6nrklWntVhU+VAGOP6VhrQzASBgNVHRMBAf8E\n" +
      "CDAGAQH/AgEAMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRw\n" +
      "czovL3d3dy52ZXJpc2lnbi5jb20vY3BzMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6\n" +
      "Ly9FVlNlY3VyZS1jcmwudmVyaXNpZ24uY29tL3BjYTMtZzUuY3JsMA4GA1UdDwEB\n" +
      "/wQEAwIBBjARBglghkgBhvhCAQEEBAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZ\n" +
      "MFcwVRYJaW1hZ2UvZ2lmMCEwHzAHBgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7\n" +
      "GS4wJRYjaHR0cDovL2xvZ28udmVyaXNpZ24uY29tL3ZzbG9nby5naWYwKQYDVR0R\n" +
      "BCIwIKQeMBwxGjAYBgNVBAMTEUNsYXNzM0NBMjA0OC0xLTQ3MD0GCCsGAQUFBwEB\n" +
      "BDEwLzAtBggrBgEFBQcwAYYhaHR0cDovL0VWU2VjdXJlLW9jc3AudmVyaXNpZ24u\n" +
      "Y29tMB8GA1UdIwQYMBaAFH/TZafC3ey78DAJ80M5+gKvMzEzMA0GCSqGSIb3DQEB\n" +
      "BQUAA4IBAQCWovp/5j3t1CvOtxU/wHIDX4u6FpAl98KD2Md1NGNoElMMU4l7yVYJ\n" +
      "p8M2RE4O0GJis4b66KGbNGeNUyIXPv2s7mcuQ+JdfzOE8qJwwG6Cl8A0/SXGI3/t\n" +
      "5rDFV0OEst4t8dD2SB8UcVeyrDHhlyQjyRNddOVG7wl8nuGZMQoIeRuPcZ8XZsg4\n" +
      "z+6Ml7YGuXNG5NOUweVgtSV1LdlpMezNlsOjdv3odESsErlNv1HoudRETifLriDR\n" +
      "fip8tmNHnna6l9AW5wtsbfdDbzMLKTB3+p359U64drPNGLT5IO892+bKrZvQTtKH\n" +
      "qQ2mRHNQ3XBb7a1+Srwi1agm5MKFIA3Z\n" +
      "-----END CERTIFICATE-----\n";

  private static final String VERISIGN_CLASS_THREE = "-----BEGIN CERTIFICATE-----\n" +
      "MIIExjCCBC+gAwIBAgIQNZcxh/OHOgcyfs5YDJt+2jANBgkqhkiG9w0BAQUFADBf\n" +
      "MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsT\n" +
      "LkNsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw\n" +
      "HhcNMDYxMTA4MDAwMDAwWhcNMjExMTA3MjM1OTU5WjCByjELMAkGA1UEBhMCVVMx\n" +
      "FzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVz\n" +
      "dCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAtIEZv\n" +
      "ciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFzcyAz\n" +
      "IFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzUwggEi\n" +
      "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1nmAMqudLO07cfLw8\n" +
      "RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbext0uz/o9+B1fs70Pb\n" +
      "ZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIzSdhDY2pSS9KP6HBR\n" +
      "TdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQGBO+QueQA5N06tRn/\n" +
      "Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+rCpSx4/VBEnkjWNH\n" +
      "iDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/NIeWiu5T6CUVAgMB\n" +
      "AAGjggGRMIIBjTAPBgNVHRMBAf8EBTADAQH/MDEGA1UdHwQqMCgwJqAkoCKGIGh0\n" +
      "dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTMuY3JsMA4GA1UdDwEB/wQEAwIBBjA9\n" +
      "BgNVHSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cudmVy\n" +
      "aXNpZ24uY29tL2NwczAdBgNVHQ4EFgQUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwNAYD\n" +
      "VR0lBC0wKwYJYIZIAYb4QgQBBgpghkgBhvhFAQgBBggrBgEFBQcDAQYIKwYBBQUH\n" +
      "AwIwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAHBgUr\n" +
      "DgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVyaXNp\n" +
      "Z24uY29tL3ZzbG9nby5naWYwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhho\n" +
      "dHRwOi8vb2NzcC52ZXJpc2lnbi5jb20wDQYJKoZIhvcNAQEFBQADgYEADyWuSO0b\n" +
      "M4VMDLXC1/5N1oMoTEFlYAALd0hxgv5/21oOIMzS6ke8ZEJhRDR0MIGBJopK90Rd\n" +
      "fjSAqLiD4gnXbSPdie0oCL1jWhFXCMSe2uJoKK/dUDzsgiHYAMJVRFBwQa2DF3m6\n" +
      "CPMr3u00HUSe0gST9MsFFy0JLS1j7/YmC3s=\n" +
      "-----END CERTIFICATE-----\n";

  private static final String VERISIGN_ROOT = "-----BEGIN CERTIFICATE-----\n" +
      "MIICPDCCAaUCEHC65B0Q2Sk0tjjKewPMur8wDQYJKoZIhvcNAQECBQAwXzELMAkG\n" +
      "A1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFz\n" +
      "cyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTk2\n" +
      "MDEyOTAwMDAwMFoXDTI4MDgwMTIzNTk1OVowXzELMAkGA1UEBhMCVVMxFzAVBgNV\n" +
      "BAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFzcyAzIFB1YmxpYyBQcmlt\n" +
      "YXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GN\n" +
      "ADCBiQKBgQDJXFme8huKARS0EN8EQNvjV69qRUCPhAwL0TPZ2RHP7gJYHyX3KqhE\n" +
      "BarsAx94f56TuZoAqiN91qyFomNFx3InzPRMxnVx0jnvT0Lwdd8KkMaOIG+YD/is\n" +
      "I19wKTakyYbnsZogy1Olhec9vn2a/iRFM9x2Fe0PonFkTGUugWhFpwIDAQABMA0G\n" +
      "CSqGSIb3DQEBAgUAA4GBALtMEivPLCYATxQT3ab7/AoRhIzzKBxnki98tsX63/Do\n" +
      "lbwdj2wsqFHMc9ikwFPwTtYmwHYBV4GSXiHx0bH/59AhWM1pF+NEHJwZRDmJXNyc\n" +
      "AA9WjQKZ7aKQRUzkuxCkPfAyAw7xzvjoyVGM5mKf5p/AfbdynMk2OmufTqj/ZA1k\n" +
      "-----END CERTIFICATE-----\n";

  private PinningTrustManager trustManager;

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    // Pinning GOOGLE_AUTHORITY
    trustManager =
        new PinningTrustManager(SystemKeyStore.getInstance(getContext()),
                                new String[] {"40c5401d6f8cbaf08b00edefb1ee87d005b3b9cd"},
                                0);
  }

  public void testValidChainAndPin() throws CertificateException, NoSuchAlgorithmException, KeyStoreException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
    X509Certificate googleWildcard  = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(GOOGLE_WILDCARD.getBytes()));
    X509Certificate googleAuthority = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(GOOGLE_AUTHORITY.getBytes()));
    X509Certificate equifaxRoot     = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(EQUIFAX_ROOT.getBytes()));

    X509Certificate[] chain = makeChain(googleWildcard, googleAuthority, equifaxRoot);
    trustManager.clearCache();
    trustManager.checkServerTrusted(chain, googleWildcard.getPublicKey().getAlgorithm());

    // Test cache
    trustManager.checkServerTrusted(chain, googleWildcard.getPublicKey().getAlgorithm());
  }

  public void testValidChainImpliedRootAndPin() throws CertificateException, NoSuchAlgorithmException, KeyStoreException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
    X509Certificate googleWildcard = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(GOOGLE_WILDCARD.getBytes()));
    X509Certificate googleAuthority = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(GOOGLE_AUTHORITY.getBytes()));

    X509Certificate[] chain = makeChain(googleWildcard, googleAuthority);
    trustManager.clearCache();
    trustManager.checkServerTrusted(chain,  googleWildcard.getPublicKey().getAlgorithm());
  }

  public void testInvalidChainWithValidPin() throws CertificateException, NoSuchAlgorithmException, KeyStoreException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
    X509Certificate verisignEv      = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(VERISIGN_CLASS_3_EV.getBytes()));
    X509Certificate googleAuthority = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(GOOGLE_AUTHORITY.getBytes()));

    X509Certificate[] chain = makeChain(verisignEv, googleAuthority);
    trustManager.clearCache();

    try {
      trustManager.checkServerTrusted(chain,  verisignEv.getPublicKey().getAlgorithm());
    } catch (CertificateException ce) {
      Log.w("PinningTrustManagerTest", ce);
      return;
    }

    fail("Trust manager didn't throw error on invalid but pinned chain!");
  }

  public void testValidChainWithNoPin() throws CertificateException, NoSuchAlgorithmException, KeyStoreException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
    X509Certificate verisignEv         = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(VERISIGN_CLASS_3_EV.getBytes()));
    X509Certificate verisignClassThree = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(VERISIGN_CLASS_THREE.getBytes()));
    X509Certificate verisignRoot       = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(VERISIGN_ROOT.getBytes()));

    X509Certificate[] chain = makeChain(verisignEv, verisignClassThree, verisignRoot);
    trustManager.clearCache();

    try {
      trustManager.checkServerTrusted(chain,  verisignEv.getPublicKey().getAlgorithm());
    } catch (CertificateException ce) {
      Log.w("PinningTrustManagerTest", ce);
      return;
    }

    fail("Trust manager didn't throw error on valid but unpinned chain!");
  }

  public void testValidChainWithGhostPin() throws CertificateException, NoSuchAlgorithmException, KeyStoreException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
    X509Certificate verisignEv         = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(VERISIGN_CLASS_3_EV.getBytes()));
    X509Certificate verisignClassThree = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(VERISIGN_CLASS_THREE.getBytes()));
    X509Certificate googleAuthority    = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(GOOGLE_AUTHORITY.getBytes()));

    X509Certificate[] chain = makeChain(verisignEv, verisignClassThree, googleAuthority);
    trustManager.clearCache();

    try {
      trustManager.checkServerTrusted(chain,  verisignEv.getPublicKey().getAlgorithm());
    } catch (CertificateException ce) {
      Log.w("PinningTrustManagerTest", ce);
      return;
    }

    fail("Trust manager didn't throw error on valid chain with ghost pin!");
  }

  private X509Certificate[] makeChain(X509Certificate...certificates) {
    return certificates;
  }
}
