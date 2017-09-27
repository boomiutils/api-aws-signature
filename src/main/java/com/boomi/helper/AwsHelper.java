package com.boomi.helper;
// google imports
import com.google.common.hash.Hashing;

// java imports
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Created by Chris_Timmerman on 9/26/2017.
 */
public class AwsHelper {
    private String signatureKey = null;
    private String accessKey = null;
    private String timestamp = null;
    private String date = null;
    private String region = null;
    private String serviceName = null;

    /**
     * Constructor
     * @param sKey
     * @param aKey
     * @param reg
     * @param serv
     * @param isTest
     * @param tDate
     * @param tTimestamp
     */
    public AwsHelper(String sKey, String aKey, String reg, String serv, boolean isTest, String tDate, String tTimestamp) {
        signatureKey = sKey;
        accessKey = aKey;
        region = reg;
        serviceName = serv;
        if (isTest) {
            date = tDate;
            timestamp = tTimestamp;
        } else {
            date = new SimpleDateFormat("yyyyMMdd").format(new Date());
            timestamp = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'").format(new Date());
        }
    }

    /**
     * Returns the signature for version 4
     *
     * @param method
     * @param payload
     * @param params
     * @param headers
     * @return
     */
    public String generateSignatureVersion4(String method, String payload, HashMap<String, String> params, HashMap<String, String> headers) {
        String signature = null;
        // Step 1 Create the canonical string
        String canonicalString = createCanonicalString(method, payload, params, headers);
        String sts = createStringToSign(canonicalString);
        signature = createCompositeSigningKey(sts);
        return signature;
    }

    /**
     * Returns the formatted AuthHeader for Version 4
     *
     * @param method
     * @param payload
     * @param params
     * @param headers
     * @return
     */
    public String generateAuthHeaderVersion4(String method, String payload, HashMap<String, String> params, HashMap<String, String> headers) {
        String authHeader = null;
        // create the signature
        String signature = generateSignatureVersion4(method, payload, params, headers);
        if (signature != null) {
            authHeader = "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + date + "/" + region + "/" + serviceName + "/aws4_request, SignedHeaders=" + createCanonicalHeaderList(headers) + ", Signature=" + signature;
        }
        return authHeader;
    }

    /**
     * Step 1. Create the Canonical Request String
     *
     * @param method
     * @param payload
     * @param params
     * @param headers
     * @return
     */
    private String createCanonicalString(String method, String payload, HashMap<String, String> params, HashMap<String, String> headers) {
        String signString = "";
        signString = signString + method + "\n";
        signString = signString + "/\n";
        signString = signString + createCanonicalParameterString(params);
        signString = signString + "\n";
        signString = signString + createCanonicalHeaderString(headers);
        signString = signString + "\n";
        signString = signString + createCanonicalHeaderList(headers) + "\n";
        signString = signString + Hashing.sha256().hashString(payload.toLowerCase(), StandardCharsets.UTF_8).toString();
        signString = Hashing.sha256().hashString(signString, StandardCharsets.UTF_8).toString();
        System.out.println("\nStep 1 <RESULT>: Generated Canonical String: \n" + signString);
        return signString;
    }

    /**
     *  Utilzie aws version 4 method to create a string to sign
     * @param canonicalRequestString
     * @return
     */
    private String createStringToSign(String canonicalRequestString) {
        String stringToSign = "";
        stringToSign = stringToSign + "AWS4-HMAC-SHA256\n";
        stringToSign = stringToSign + timestamp + "\n";
        stringToSign = stringToSign + date + "/" + region + "/" + serviceName + "/aws4_request\n";
        stringToSign = stringToSign + canonicalRequestString;
        System.out.println("\nStep 2 <RESULT>: Generated String to Sign: \n" + stringToSign);
        return stringToSign;
    }

    /**
     * Use aws version 4 method to create the canonical parameter string
     * @param params
     * @return
     */
    private String createCanonicalParameterString(HashMap<String, String> params) {
        String paramString = "";
        if (params != null && !params.isEmpty()) {
            TreeMap<String, String> sortedMap = new TreeMap<String, String>(params);
            for (Map.Entry<String, String> entry : sortedMap.entrySet()) {
                paramString = paramString + entry.getKey() + "=" + entry.getValue();
                if (!sortedMap.lastKey().equals(entry.getKey())) {
                    paramString = paramString + "&";
                }
            }
        }
        return paramString;
    }

    /**
     * Use aws version 4 to create the list of headers with values
     * @param headers
     * @return
     */
    private String createCanonicalHeaderString(HashMap<String, String> headers) {
        String headerString = "";
        if (headers != null && !headers.isEmpty()) {
            Map<String, String> sortedMap = new TreeMap<String, String>(headers);
            for (HashMap.Entry<String, String> entry : sortedMap.entrySet()) {
                headerString = headerString + entry.getKey().toLowerCase() + ":" + entry.getValue() + "\n";
            }
        }
        return headerString;
    }

    /**
     * Use aws version 4 mehtod to create a ordered header list
     * @param headers
     * @return
     */
    private String createCanonicalHeaderList(HashMap<String, String> headers) {
        String headerString = "";
        if (headers != null && !headers.isEmpty()) {
            TreeMap<String, String> sortedMap = new TreeMap<String, String>(headers);
            for (HashMap.Entry<String, String> entry : sortedMap.entrySet()) {
                headerString = headerString + entry.getKey().toLowerCase();
                if (!sortedMap.lastKey().equals(entry.getKey())) {
                    headerString = headerString + ";";
                }
            }
        }
        return headerString;
    }

    /**
     * Utse the aws version 4 method to create a composite signing key
     * @param stringToSign
     * @return
     */
    private String createCompositeSigningKey(String stringToSign) {
        String compKey = "";
        try {
            byte[] kDate = mac(("AWS4" + signatureKey).getBytes(), date);
            byte[] kRegion = mac(kDate, region);
            byte[] kService = mac(kRegion, serviceName);
            byte[] derivedKey = mac(kService, "aws4_request");
            String tempCompKey = getHexValue(derivedKey);
            System.out.println("\nStep 3 <RESULT 1>: Generated Composite Signing Key in Hex: \n" + tempCompKey);
            compKey = getHexValue(mac(derivedKey, stringToSign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("\nStep 3 <RESULT 2>: Generated Signature: \n" + compKey);
        return compKey;
    }

    /**
     * Mac the passed string using the provided key
     *
     * @param key
     * @param stringToMac
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private byte[] mac(byte[] key, String stringToMac) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(stringToMac.getBytes());
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            throw new NoSuchAlgorithmException(ex.getMessage());
        } catch (InvalidKeyException ikx) {
            ikx.printStackTrace();
            throw new InvalidKeyException(ikx.getMessage());
        }
    }

    /**
     *
     * @param bytes
     * @return
     */
    private String getHexValue(byte[] bytes) {
        String hexString = "";
        StringBuilder sbDr = new StringBuilder();
        for (byte b : bytes) {
            sbDr.append(String.format("%02x", b));
        }
        hexString = sbDr.toString();
        return hexString;
    }

    /**
     *
     */
    public class SignatureType {
        public static final int TYPE_2 = 2;
        public static final int TYPE_4 = 4;
    }
}
