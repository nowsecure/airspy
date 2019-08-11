# AirSpy

Tool for exploring Apple's AirDrop protocol implementation on i/macOS,
from the server's perspective.

Dumps requests and responses along with a linear code coverage trace
of the code processing each request.

## Building

```sh
$ git clone https://github.com/nowsecure/airspy.git
$ cd airspy/
$ npm install
```

## Running

To spy on the implementation:

```sh
# On a local macOS system:
$ node dist/bin/airspy.js

# Or on a USB-connected iOS device:
$ node dist/bin/airspy.js -U
```

Then pop open the AirDrop UI on a nearby i/macOS device. This should
result in data being captured and written to `out/$serial/events.log`,
where `$serial` is a zero-based number incrementing with each run.
Each request/response also gets written out to separate files for
easy inspection and diffing.

It is also possible to replay an `events.log` from a previous run,
which will re-generate the other output files:

```sh
$ node dist/bin/airspy.js -r out/0/events.log
```

This is also useful if you want to tweak the parsing of the requests
to generate better or additional output artifacts. (PRs welcome!)

Sample output directory:

```sh
$ ls -1 out/0/
001-post-discover-coverage-modules.log
001-post-discover-coverage-symbols.log
001-post-discover-request-body.plist
001-post-discover-request-head.txt
001-post-discover-response-body.plist
001-post-discover-response-head.txt
002-post-ask-coverage-modules.log
002-post-ask-coverage-symbols.log
002-post-ask-request-body.plist
002-post-ask-request-head.txt
002-post-ask-response-body.plist
002-post-ask-response-head.txt
003-post-upload-request-head.txt
003-post-upload-response-head.txt
events.log
$
```

Then you may want to compare the code coverage traces for two requests.

For example to compare the modules involved, and in which order:

```sh
$ diff -u 001-post-discover-coverage-modules.log 002-post-ask-coverage-modules.log
```

And to compare the basic blocks involved, and in which order:

```sh
$ diff -u 001-post-discover-coverage-symbols.log 002-post-ask-coverage-symbols.log
```

One example is that by looking at where execution first diverges, you
immediately know where the implementation decides what kind of request
it's dealing with, so you can inspect that code with r2. Or, you might
want to use it to guide a fuzzer.

## Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run build-app:watch
```

Plus another terminal with:

```sh
$ npm run build-agent:watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.