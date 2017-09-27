# Signing Utility Classes

Utlity classes to simplify version 4 signing requirements for AWS web services calls.

[Java](https://www.oracle.com/java/) implementation of [AWS](https://aws.amazon.com) [Signature Version 4 Signing Request](http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html).

## Usage

Refer to included [Test Classes](https://github.com/boomiutils/BoomiUtility/tree/master/src/test/java/com/boomi) for examples.

## Build

```
# To build the project
mvn compile

# To run the tests and generate the artifacts
mvn package
```

### Building

To build this project you will need Java 8 and Maven 3.

## JUnit

There is an included test class that will perform the basic test listed on the AWS site. This application should generate the same signature and/or header used in that example.

## Contributing

Contributions are welcome to the project - whether they are feature requests, improvements or bug fixes!

## License

This service is released under the [MIT License] (http://opensource.org/licenses/mit-license.php);