## Models

The fuzzer requires a JSON model giving it a description of what and how to attack. A model template is available at `template.json` and a full example is given in `example.json`.

### Structure

Particular model fields would require an elaboration (optional fields are contained in parentheses):
- `domains`: a dictionary of top-level domains, each domain key is the domain identifier, has the following fields:
    - `host`: hostname of the target service
    - `port`: tcp/ip port number of the target service, if set to `null` it will default to 80
    - `protocol`: the transport protocol, can be either `http` or `https`
- `(expectations)`: global expectation (see *Expectations* section)
- `endpoints`: list of dictionaries describing each service endpoint, each dictionary has the following fields:
    - `uri`: route path of the service (e.g. `http://github.com[/uri]`), has special mutation behavior (see *Mutation Behavior* section)
    - `(timeout)`: the maximum time (seconds) between the request content sent and the response content to be received
    - `(headers)`: dictionary of request headers, has special mutation behavior (see *Mutation Behavior* section)
    - `(methods)`: list of http request methods, if this field is skipped, the fuzzer will use a pre-defined list of methods
    - `(comment)`: this is a cosmetic field which is only for user readability
    - `input`: the request's payload, which is either body, query, or both, has the following fields:
        - `body`: represents data sent in the request body, this will typically require a JSON content-type header to function correctly
        - `query`: dictionary of url query parameters
    - `(expectations)`: local expectation (see *Expectations* section)
- `(requestsPerSecond)`: if set, the fuzzer will send this many requests in one second. Any value that is 0 or less means there is no delay before sending a request. This value can be defined globally in the model and locally in an endpoint. If both are defined, the local value will override the global one.

### Field Mutation

HotFuzz modification of data fields or mutation can be controlled by the user with mutation placeholders. A mutation placeholder has the form `{name}` and can be included into any data field description in a fuzzing model like `"t": "1m{mutator1}05s"` where `mutator1` acts as a name label.

The mutation placeholders in a fuzzing model are interpreted as follows:

- If the data field includes a mutation placeholder, only the placeholder location is modified.
    - E.g. `"t": "1m{mutator1}05s"` would be mutated into `"t": "1m%20%20%20%C2%9F%2005s"`, `"t": "1mAAAAAAAA05s"`, ... etc.
- If the data field does not include any mutation placeholder, the whole data field is modified.
    - E.g. `"t": "1m05s"` would be mutated into `"t": "0m00m00s"`, `"t": "%3Cimg%20%5Cx12src%3Dx%20onerror%3D%22javascript%3Aalert%281%29%22%3E"`, ... etc.
- If the data field is an URI or header field, its data will not be modified unless there is a mutation placeholder.
    - E.g. `"uri": "/watch"` will remain intact, while `"uri": "/wa{mutate}tch"` would be mutated into `"uri": "/wa98s8d9fh!tch"`, `"uri": "/wa%20%20%20%C2%9F%20tch"`, ... etc.

## Expectations

Expectations are a set of user-defined rules that determine whether a request response is interpreted as good or bad. The fuzzer parses them in JSON format as a dictionary of Python code that is executed at runtime.

### Syntax and Semantics

1. Must conform to JSON format
1. Each expectation consists of a key for the name and an array of strings
1. The expectation strings must conform to Python 3.x syntax
1. Expectations can be defined in an endpoint object (local), the top-level of a data model (global), or in a separate JSON file which consists only of expectation definitions (default).
1. Local and global expectations can only have one key and must have "expectations" as the key name. Default expectations can have any string value as a key name and any number of keys.
1. Global expectations override defaults, while local expectations override all others.
1. Expectation definitions must assign a boolean value to the 'expectation' variable at least once. Otherwise, the evaluation will always be false.
1. Expectation definitions have access to the 'result' object which can be used for evaluating values.

## Making changes

When the fuzzer is run without a state file, it will periodically check for changes to the data model it loaded when starting. If it finds a change you made in your schema when comparing it to what is loaded in memory, it will reset its state to the starting state and apply the changes to the loaded model. This enables the fuzzer to run indefinitely as a service without requiring downtime to apply new changes to a data model. The `model_reload_interval_seconds` variable in fuzz/config/config.ini is the frequency, in seconds, in which the fuzzer will check for changes to the schema.
