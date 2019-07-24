package signatures;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;

public class Version1 {

    private final String role;
    private final String signingTime;
    private final String cfInstanceCertContents;
    private final String signature;

    public Version1(String role) {
        // Get the components of the string we'll sign.
        String cfInstanceCert = Utilities.getFileBodyAt("CF_INSTANCE_CERT");

        // Get the current time, UTC, formatted like so: 2019-05-20T22:08:40Z.
        DateTime signingTime = DateTime.now().withZone(DateTimeZone.UTC);
        DateTimeFormatter fmt = ISODateTimeFormat.dateTimeNoMillis();
        String signingTimeStr = fmt.print(signingTime);

        // Concatenate them to build our string to sign.
        String stringToSign = Utilities.getStringToSign(role, signingTimeStr, cfInstanceCert);

        // Sign it.
        String cfInstanceKey = Utilities.getFileBodyAt("CF_INSTANCE_KEY");
        String signature = Utilities.generateSignature(cfInstanceKey, stringToSign.getBytes());

        // Populate it.
        this.role = role;
        this.signingTime = signingTimeStr;
        this.cfInstanceCertContents = cfInstanceCert;
        this.signature = signature;
    }

    public String getRole() {
        return this.role;
    }

    public String getSigningTime() {
        return this.signingTime;
    }

    public String getCFInstanceCertContents() {
        return this.cfInstanceCertContents;
    }

    public String getSignature() {
        return this.signature;
    }

    @Override
    public String toString() {
        return "Version1{" +
                "role='" + role + '\'' +
                ", signingTime='" + signingTime + '\'' +
                ", cfInstanceCertContents='" + cfInstanceCertContents + '\'' +
                ", signature='" + signature + '\'' +
                '}';
    }
}