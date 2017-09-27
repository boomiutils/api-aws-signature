package com.boomi.utility;

// standard imports
import java.util.HashMap;

// application imports
import com.boomi.helper.AwsHelper;
import com.boomi.helper.AwsHelper.SignatureType;

/**
 * Created by Chris_Timmerman on 9/22/2017.
 * <p>
 * Singleton utility class intended to be used within process mappings or data process components
 * within Boomi.
 */
public class SigningUtility {

    private static SigningUtility instance;

    /**
     * Constructor
     */
    public SigningUtility() {
    }


    /**
     * Singleton
     *
     * @return
     */
    public static synchronized SigningUtility GetInstance() {
        if (instance == null) {
            instance = new SigningUtility();
        }
        return instance;
    }

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
    public String generateSignature(int version,
                                    String method,
                                    String sKey,
                                    String aKey,
                                    String region,
                                    String serviceName,
                                    String payload,
                                    HashMap<String, String> params,
                                    HashMap<String, String> headers,
                                    boolean isTest,
                                    String testDate,
                                    String testTimestamp) {
        String signature = null;
        AwsHelper helper = new AwsHelper(sKey, aKey, region, serviceName, isTest, testDate, testTimestamp);
        switch (version) {
            case SignatureType.TYPE_2:
                break;
            case SignatureType.TYPE_4:
                signature = helper.generateSignatureVersion4(method, payload, params, headers);
                break;
            default:
                break;
        }
        return signature;
    }

    /**
     * Generates a AWS authorization header using either version 2 or 4
     *
     * @param version
     * @param method
     * @param sKey
     * @param aKey
     * @param region
     * @param serviceName
     * @param payload
     * @param params
     * @param headers
     * @return
     */
    public String generateAuthorizationHeader(int version,
                                              String method,
                                              String sKey,
                                              String aKey,
                                              String region,
                                              String serviceName,
                                              String payload,
                                              HashMap<String, String> params,
                                              HashMap<String, String> headers,
                                              boolean isTest,
                                              String testDate,
                                              String testTimestamp) {
        String header = null;
        AwsHelper helper = new AwsHelper(sKey, aKey, region, serviceName, isTest, testDate, testTimestamp);
        switch (version) {
            case SignatureType.TYPE_2:
                break;
            case SignatureType.TYPE_4:
                header = helper.generateAuthHeaderVersion4(method, payload, params, headers);
                break;
            default:
                break;
        }
        return header;
    }


}
