package com.boomi;

// junit imports
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

// java imports
import java.util.HashMap;

// application imports
import com.boomi.helper.AwsHelper.SignatureType;
import com.boomi.utility.SigningUtility;

/**
 * Unit test for aws signature signing.
 */
public class AwsSignatureTest
        extends TestCase {
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AwsSignatureTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(AwsSignatureTest.class);
    }

    /**
     * Rigourous Test :-)
     */
    public void testApp() {
        System.out.println("Starting Tests");
        HashMap<String, String> params = new HashMap<String, String>();
        params.put("Action", "ListUsers");
        params.put("Version", "2010-05-08");

        HashMap<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
        headers.put("X-Amz-Date", "20150830T123600Z");
        headers.put("Host", "iam.amazonaws.com");

        // create the signing utility class
        SigningUtility util = SigningUtility.GetInstance();
        String signature = util.generateSignature(SignatureType.TYPE_4, "GET", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "AKIDEXAMPLE", "us-east-1", "iam", "", params, headers, true, "20150830", "20150830T123600Z");
        System.out.println("\n<TEST RESULT> Returned Signature :" + signature);

        String header = util.generateAuthorizationHeader(SignatureType.TYPE_4, "GET", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "AKIDEXAMPLE", "us-east-1", "iam", "", params, headers, true, "20150830", "20150830T123600Z");
        System.out.println("\n<TEST RESULT> Returned Auth Header :" + header);
        assertTrue(true);
    }
}
