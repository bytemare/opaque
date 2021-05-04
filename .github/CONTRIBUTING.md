# How to contribute to OPAQUE

### Is your contribution related to the protocol or this implementation?

- If you have thoughts or questions, consider opening an issue in the [CFRG project of OPAQUE](https://github.com/cfrg/draft-irtf-cfrg-opaque) or sending an e-mail to the [mailing list](https://www.irtf.org/mailman/listinfo/cfrg).
- If not sure, you can [open a new issue](https://github.com/bytemare/opaque/issues/new) here.

### Did you find a bug? 🐞

* 🔎 Please ensure your findings have not already been reported by searching on the project repository under [Issues](https://github.com/bytemare/opaque).
* If you think your findings can be complementary to an existing issue, don't hesitate to join the conversation 😃☕
* If there's no issue addressing the problem, [open a new one](https://github.com/bytemare/opaque/issues/new). Please be clear in the title and description, and add relevant information. Bonus points if you provide a **code sample** and everything needed to reproduce the issue when expected behaviour is not occurring.
* If possible, use the relevant issue templates.

### Do you have a fix?

🎉 That's awesome! Pull requests are welcome!

* Please [open an issue](https://github.com/bytemare/opaque) beforehand, so we can discuss this.
* Fork this repo from `main`, and ensure your fork is up-to-date with it when submitting the PR.
* If your changes impact the documentation, please update it accordingly.
* If you added code that impact tests, please add tests with relevant coverage and test cases. Bonus points for fuzzing.
* 🛠️ Make sure the test suite passes.

If your changes might have an impact on performance, please benchmark your code and measure the impact, share the results and the tests that lead to these results.

Please note that changes that are purely cosmetic and do not add anything substantial to the stability, functionality, or testability of the project may not be accepted.

### Coding Convention

This project tries to be as Go idiomatic as possible. Conventions from [Effective Go](https://golang.org/doc/effective_go) apply here. Tests use a very opinionated linting configuration that you can use before committing to your changes.

### Licence

By contributing to this project, you agree that your contributions will be licensed under the project's [License](https://github.com/bytemare/opaque/blob/main/LICENSE).

Thanks! :heart: