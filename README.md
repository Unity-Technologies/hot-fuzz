# HotFuzz

"Fuzzing or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program." [Fuzzing - OWASP](https://www.owasp.org/index.php/Fuzzing)

HotFuzz is a fuzz testing utility that generates random data and sends it to a service's endpoint over HTTP or HTTPS based on a given fuzzing model written in JSON. HotFuzz is useful for security testing of a public/private service's endpoint to discover vulnerabilities in data validation, service implementation or performance among others.

In HotFuzz, we define a service as a program hosted in a given domain and listening for HTTP or HTTPS requests, where an endpoint is understood as one of the resources made available through that service. These endpoints represent the main service entry point where HotFuzz can be used to verify their resilience against unexpected data and attacks.

# Setting up and fuzzing with HotFuzz

There are two ways you can setup and run HotFuzz: natively or in Docker. Running HotFuzz natively is the most straightforward option to have full control of the fuzzer settings. On the other hand, running HotFuzz in Docker isolates the fuzzer execution allowing you to run fuzz tests more automatically and with less modifications of your working environment.

# Setup

These are the software requirements to be met:

- [Python => 3.5.x](https://www.python.org/downloads/release/python-350)
- pip3
- wget
- [Docker => 17.x.x](https://www.docker.com/community-edition#/download)

Next, this is how you run the setup process:

```
$ cd hot-fuzz/
$ sudo make setup
(Docker users)
$ sudo make docker-build
```

### Dependencies

Running HotFuzz natively requires either to modify your current Python environment or to use a [Python virtual environment](https://docs.python.org/3/tutorial/venv.html) to isolate your working environment.

To install the HotFuzz dependencies natively:

```
$ pip3 install -r requirements.txt
```

To use instead a Python virtual environment:

```
$ source run_venv.sh
```

### Docker Configuration

If you are using Docker for Mac, you will need to enable file sharing so that the fuzzer's docker container can save files to your local file system. Do this by opening the docker app, then go to `Preferences -> File Sharing` and add the full path of the directory `hot-fuzz`, e.g. :

```
/Users/(user)/projects/hot-fuzz
```

### Validation

Once the setup is done and all dependencies satisfied it's time to run the HotFuzz's test suite. The next commands show you how to run it natively and in Docker.

To run the test suite natively:

```
$ make test
python3 -m unittest test.test_fuzzer
Starting mock server at 127.0.0.1:8080

Running tests...
----------------------------------------------------------------------
  chance (test.test_fuzzer.MutatorTests) ... OK (0.005s)
  roll_dice (test.test_fuzzer.MutatorTests) ... OK (0.019s)
  juggle_type (test.test_fuzzer.MutatorTests) ... OK (0.024s)
  mutate_radamsa_state_change (test.test_fuzzer.MutatorTests) ... OK (0.694s)
  mutate_radamsa_state_static (test.test_fuzzer.MutatorTests) ... OK (1.042s)
(...)
  get_states_from_file (test.test_fuzzer.FuzzerTests) ... OK (0.002s)

----------------------------------------------------------------------
Ran 43 tests in 6.063s

OK

Generating XML reports...
```

The number of tests may differ but a successful run will print `OK` at the end and generate both, `*.log` and `*.xml` files with more details under the `results` directory.

```
$ ls results/
20170828154439.log                  TEST-test.test_fuzzer.FuzzerTests-20170828154436.xml
```

Once your HotFuzz setup passes the test suite is time to fuzz something!

## Fuzzing

To start fuzzing with HotFuzz we provide the testing server `mockserver.py`. The objective is to fuzz an endpoint of this testing service as hosted at the `example` domain. To complete this task we will modify an existing fuzzing model, run the fuzzer and analyze the results.

Next, start the testing server to get ready to fuzz it:

```
$ make mock-server
python3 -m fuzz.test.mockserver
Starting mock server at 127.0.0.1:8080
```

### Models

HotFuzz requires a fuzzing model to know where and how to fuzz a specific service's endpoint.

For instance, the example model file [tutorial.json](fuzz/models/tutorial.json) defines the required details to fuzz the `/watch` endpoint hosted at the `example` domain as follows:

```
{
  "domains": {
    "example": {
      "host": "localhost",
      "port": 8080,
      "protocol": "http"
    }
  },
  "endpoints": [
    {
      "uri": "/watch",
      "comment": "watch video",
      "methods": ["GET"],
      "input": {
        "query": {
          "v": "9bZkp7q19f0",
          "t": "1m05s"
        }
      }
    }
  ]
}
```

This model instructs HotFuzz to send requests to the service listening for `http` connections at the host `localhost` port `8080`. These requests will be targeted to the `/watch` endpoint using the `GET` method and an input query consisting of two parameters `v` and `t` with the initial values `9bZkp7q19f0` and `1m05s` respectively.

### Fuzz it!

Run the fuzzer client to send three (`-i=3`) requests using the `tutorial.json` model file (`--model-path fuzz/models/tutorial.json`) against the `example` domain (`--domain example`) with full debug log (`--loglevel 0`) for further analysis:

```
$ ./cli.py -i=3 --model-path fuzz/models/tutorial.json --domain example --loglevel 0
```

Running the fuzzer successfully will generate no feedback output and leave the results under the `results` directory. Here we can have a more detailed look of how HotFuzz has sent the requests and how certain data fields were modified to fuzz the target endpoint.

In the output below you can see how the original values of the fields `v` and `t` have been modified. Sometimes these values remain the same, sometimes these have small variations and in other cases these have been completely replaced with "known-to-be-dangerous" values:

```
$ cat results/20170907164501_all_uris_all_methods.log
(...)
2017-09-07 16:45:01,476 DEBUG: http://localhost:8080 "GET /watch?v[]=9bZkp7q19f0&t=0m00m00s HTTP/1.1" 200 None
(...)
2017-09-07 16:45:01,522 DEBUG: http://localhost:8080 "GET /watch?v=340282366920938463463374607431768211457bZkp7q19f0&t=%3Cimg%20%5Cx12src%3Dx%20onerror%3D%22javascript%3Aalert%281%29%22%3E HTTP/1.1" 200 None
(...)
2017-09-07 16:45:01,538 DEBUG: http://localhost:8080 "GET /watch?v=9bZkp7q19fp7q19fp7qbZkp7q19bZkp7q19bZkp7q255f429bZkp7q197&t=1m05s HTTP/1.1" 200 None
```

HotFuzz will also log information about the response received by the service and more details about the request sent:

```
$ cat results/20170907164501_all_uris_all_methods.log
(...)
2017-09-07 16:45:01,513 ERROR: {"method": "GET", "headers": {"X-Hot-Fuzz-State": "0"}, "url": "http://localhost:8080/watch?v[]=9bZkp7q19f0&t=0m00m00s", "body": null, "size": 359, "response": "{\"success\": false, \"reason\": \"Not found\"}\n", "reason": "OK", "httpcode": 200, "time": 0.049}
(...)
```

In the above output, the field `response` stores the data received by the service when sending a request which details are summarized by the `methods`, `headers`, `url`, `body` and `size` fields.

### Custom mutation

In Fuzzing, mutation is commonly understood as the variations applied to the input data required to fuzz a given program. HotFuzz has a defined strategy to decide how to mutate input values, but it also offers to user a level of control over it. This control is provided by what we call the mutation placeholders which have the form `{name}` and are part of the fuzzing model.

Coming back to fuzzing the `example` domain, we can now make use of mutation placeholders to control what gets modified or mutated. Taking the original [tutorial.json](fuzz/models/tutorial.json) model we add the next modification to the `t` data field as follows:

```
      "input": {
        "query": {
          "v": "9bZkp7q19f0",
          "t": "1m{mutate_here}05s"
        }
      }
```

The above modification to the model will instruct HotFuzz to only mutate the `t` data field where the mutation placeholder `{mutate_here}` is located and let the rest of the data field untouched.

### Fuzz it, again!

Run the fuzzer again and see the differences with the new model:

```
$ ./cli.py -i=3 --model-path fuzz/models/tutorial.json --domain example --loglevel 0
```

In the results below you can verify how the `t` data field has been mutated differently this time by leaving the data chunks `1m` and `05s` intact:

```
$ cat results/20170907182405_all_uris_all_methods.log
(...)
2017-09-07 18:24:05,402 DEBUG: http://localhost:8080 "GET /watch?v[]=9bZkp7q19f0&t=1m%20%20%20%C2%9F%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%C2%80a%C2%8Aa05s HTTP/1.1" 200 None
(...)
2017-09-07 18:24:05,430 DEBUG: http://localhost:8080 "GET /watch?v=340282366920938463463374607431768211457bZkp7q19f0&t=1mo%CC%82%C2%8F%C2%BF3%E2%81%844a05s HTTP/1.1" 200 None
```

### Constants

To add further customization, HotFuzz allows to define data values in your model which may change or remain across different fuzzing runs, we call them constants. These can be detailed in either, a file like [constants.json](fuzz/test/constants.json) or in the command line.

First, update the fuzzing model `tutorial.json` to include two new constants name as `{endpoint}` and `{time}`:

```
  "endpoints": [
    {
      "uri": "/{endpoint}",
      "comment": "watch video",
      "methods": ["GET"],
      "input": {
        "query": {
          "v": "9bZkp7q19f0",
          "t": "{time}"
        }
      }
    }
  ]
```

Next, define the value of the new constant `{endpoint}` in the `constants.json` file as follows:

```
{
  "{endpoint}": "watch"
}
```

Then, use the command line parameters `--constants` and `--constants-file` to define the value of the `{time}` constant, and to include the `constants.json` file respectively:

```
(...) --constants '{"{time}": "1m05s"}' --constants-file fuzz/test/constants.json (...)
```

### Fuzz it, once more

Run the fuzzer with the new command line and see how the constants get replaced in the results:

```
$ ./cli.py -i=3 --model-path fuzz/models/tutorial.json --domain example --constants '{"{time}": "1m05s"}' --constants-file fuzz/test/constants.json --loglevel 0

$ cat results/20171204173210_all_uris_all_methods.log
(...)
2017-12-04 17:32:10,403 DEBUG: http://localhost:8080 "GET /watch?v=340282366920938463463374607431768211457bZkp7q19f0&t=%3Cimg%20%5Cx12src%3Dx%20onerror%3D%22javascript%3Aalert%281%29%22%3E HTTP/1.1" 200 None
(...)
2017-12-04 17:32:10,425 DEBUG: http://localhost:8080 "GET /watch?v=9bZkp7q19fp7q19fp7qbZkp7q19bZkp7q19bZkp7q255f429bZkp7q197&t=1m05s HTTP/1.1" 200 None
```
