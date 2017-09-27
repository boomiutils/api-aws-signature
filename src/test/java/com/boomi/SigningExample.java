package com.boomi;

import com.boomi.helper.AwsHelper;
import com.boomi.utility.SigningUtility;
import java.util.HashMap;

/**
 * Created by Chris_Timmerman on 9/26/2017.
 */
public class SigningExample {

    public SigningExample(){}

    public void TestSignatureType4() {
        // Hashmap of Request Parameters
        HashMap<String, String> params = new HashMap<String, String>();
        params.put("Action", "ListUsers");
        params.put("Version", "2010-05-08");

        // Hashmap of Headers
        HashMap<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
        headers.put("X-Amz-Date", "20150830T123600Z");
        headers.put("Host", "iam.amazonaws.com");

        // the signing utility class
        SigningUtility util = SigningUtility.GetInstance();
        /**
         * Generates a AWS signature using either version 2 or 4
         *
         * @param version - Type 2 or 4
         * @param method - GET / POST
         * @param sKey - From AWS
         * @param aKey - From AWS
         * @param region - What ec2 region for example us-east-2
         * @param serviceName - the name of the webservice you are calling, iam for example
         * @param payload - the entire payload
         * @param params - the params hashmap
         * @param headers - the headers hashmap
         * @param isTest - if true only the date and timestamp passed to this method will be used to generate the signature
         * @param testDate - the testDate you would like to test with
         * @param headers - the testTimestamp you would like to test with
         * @return
         */
        String signature = util.generateSignature(AwsHelper.SignatureType.TYPE_4,
                "GET",
                "YOUR_SECRET_KEY",
                "YOUR_ACCESS_KEY",
                "us-east-1",
                "iam",
                "",
                params,
                headers,
                false,
                "",
                "");

        // print the exception
        System.out.println("\n<RESULT> Returned Signature :" + signature);
    }

    public static void main(String [] args) {
        SigningExample example = new SigningExample();
        example.TestSignatureType4();
    }
}
