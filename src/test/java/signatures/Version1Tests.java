package signatures;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.ISODateTimeFormat;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

public class Version1Tests {

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Test
    public void buildSignature() {
        ClassLoader classLoader = getClass().getClassLoader();
        File cfInstanceCertFile = new File(classLoader.getResource("instance.crt").getFile());
        File cfInstanceKeyFile = new File(classLoader.getResource("instance.key").getFile());
        environmentVariables.set("CF_INSTANCE_CERT", cfInstanceCertFile.getAbsolutePath());
        environmentVariables.set("CF_INSTANCE_KEY", cfInstanceKeyFile.getAbsolutePath());

        DateTime nowUTC = DateTime.now().withZone(DateTimeZone.UTC);
        Version1 version1 = new Version1("test-role");
        Assert.assertEquals("test-role", version1.getRole());
        Assert.assertEquals(Utilities.getFileBodyAt("CF_INSTANCE_CERT"), version1.getCFInstanceCertContents());
        Assert.assertEquals(344, version1.getSignature().length());

        // Assert that there is no more than 1 second between now and the signing time.
        DateTime signingTime = ISODateTimeFormat.dateTimeNoMillis().parseDateTime(version1.getSigningTime());
        long millisBetween = signingTime.getMillis() - nowUTC.getMillis();
        Assert.assertTrue(millisBetween < 1000);
    }

    // This test is here for firing test logins at a local instance of Vault
    // during development and debugging.
    @Ignore("for local testing only") @Test
    public void fireTestLogin() {
        ClassLoader classLoader = getClass().getClassLoader();
        File cfInstanceCertFile = new File(classLoader.getResource("instance.crt").getFile());
        File cfInstanceKeyFile = new File(classLoader.getResource("instance.key").getFile());
        environmentVariables.set("CF_INSTANCE_CERT", cfInstanceCertFile.getAbsolutePath());
        environmentVariables.set("CF_INSTANCE_KEY", cfInstanceKeyFile.getAbsolutePath());

        Version1 version1 = new Version1("test-role");
        try {

            Map<String,String> params = new LinkedHashMap<>();
            params.put("role", version1.getRole());
            params.put("signing_time", version1.getSigningTime());
            params.put("cf_instance_cert", version1.getCFInstanceCertContents());
            params.put("signature", version1.getSignature());

            Gson gson = new GsonBuilder().disableHtmlEscaping().create();
            String body = gson.toJson(params);
            System.out.println(body);

            URL url = new URL("http://localhost:8200/v1/auth/pcf/login");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
            wr.writeBytes(body);
            wr.flush();
            wr.close();

            int responseCode = conn.getResponseCode();
            System.out.println("Response Code : " + responseCode);

            InputStream inputStream;
            if (responseCode == 200) {
                inputStream = conn.getInputStream();
            } else {
                inputStream = conn.getErrorStream();
            }
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(inputStream));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            System.out.println(response.toString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
