# vault-tools-auth-pcf

This code is a simple demo of how to build a signature in Java for
[vault-plugin-auth-pcf](https://github.com/hashicorp/vault-plugin-auth-pcf).

## Example Use

This code is intended to be run in an environment where the `CF_INSTANCE_CERT`
and `CF_INSTANCE_KEY` variables exist as described
[here](https://docs.pivotal.io/pivotalcf/2-4/devguide/deploy-apps/instance-identity.html).

In this example, Vault is running on our localhost. It has been configured to point
at a mock instance of the PCF API that's running locally using the `mock-pcf-server`
tool available in the `vault-plugin-auth-pcf` repository, though in real life it would
need real API credentials.

```
vault auth enable pcf

vault write auth/pcf/config \
    identity_ca_certificates=@/home/tbex/java/vault-tools-auth-pcf/src/test/resources/ca.crt \
    pcf_api_addr=http://127.0.0.1:34085 \
    pcf_username=username \
    pcf_password=password

vault write auth/pcf/roles/test-role \
    bound_application_ids=2d3e834a-3a25-4591-974c-fa5626d5d0a1 \
    bound_space_ids=3d2eba6b-ef19-44d5-91dd-1975b0db5cc9 \
    bound_organization_ids=34a878d0-c2f9-4521-ba73-a9f664e82c7bf \
    policies=default
```

Then from a Java test, for instance:

```
// Find the path to our test data within our build, and set it as
// the expected environment variables.
ClassLoader classLoader = getClass().getClassLoader();
File cfInstanceCertFile = new File(classLoader.getResource("instance.crt").getFile());
File cfInstanceKeyFile = new File(classLoader.getResource("instance.key").getFile());
environmentVariables.set("CF_INSTANCE_CERT", cfInstanceCertFile.getAbsolutePath());
environmentVariables.set("CF_INSTANCE_KEY", cfInstanceKeyFile.getAbsolutePath());

Version1 signature = new Version1("test-role");
try {

    Map<String,String> params = new LinkedHashMap<>();
    params.put("role", signature.getRole());
    params.put("signing_time", signature.getSigningTime());
    params.put("cf_instance_cert", signature.getCFInstanceCertContents());
    params.put("signature", signature.getSignature());

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
```

These are provided as examples for you to edit to your needs.