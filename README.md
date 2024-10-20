# Predator Web Framework

Predator is an asynchronous web framework designed for performance and security, built on top of `aiohttp`. It offers a simple and flexible way to create web applications, with built-in support for encryption, static file serving, and robust middleware handling.

## Features

- **Asynchronous Support**: Leverages `asyncio` and `aiohttp` for non-blocking operations.
- **Security Headers**: Automatically applies security best practices with customizable response headers.
- **Encryption Tools**: Built-in AES encryption and decryption capabilities using `pycryptodome`.
- **Static File Serving**: Easily serve static files with support for byte-range requests.
- **Custom Middleware**: Define middleware functions for logging, request validation, and more.
- **DDoS Protection**: Configurable memory throttling to protect against resource exhaustion.

## Installation

To install Predator, clone the repository and install the required dependencies:

```bash
pip install git+https://github.com/anonyxbiz/predator.git
```

## Quick Start

Here's a simple example to get you started with Predator:

```python
import Predator as pd
from asyncio import run, to_thread as to
from json import dumps

web = run(pd.WebApp().init())

# Before middleware
@web.route
async def before_middleware(r):
    if r.method == "POST":
        r.args = await r.request.json()
    else:
        r.args = r.params
            
# / route for streaming text response
@web.route
async def _(r):
    stream = await pd.Stream_Response().init(r)
    await stream.text()
    await stream.write("Hello, world!")
    await stream.finish()

# /json route for streaming json response
@web.route
async def _json(r):
    stream = await pd.Stream_Response().init(r)
    await stream.text()
    await stream.write("Hello, world!")
    await stream.finish()

# /get/content route    
@web.route
async def _get_content(r):
    await app.get_content(r)
    
if __name__ == '__main__':
    config = run(pd.MyDict().init(host="0.0.0.0", port=8000))
    web.runner(config)
    
```

## Configuration

You can customize the server configuration by modifying the `Configs` class. For example:

```python
class Configs:
    def __init__(app):
        app.response_headers = {
            'Server': 'Predator',
            'Strict-Transport-Security': 'max-age=63072000; includeSubdomains',
            ...
        }
```

## Encryption Example

To encrypt and decrypt data, you can use the `Safe` class:

```python
from Predator.__safe__ import Safe
from Predator.Predator import Instance

key = "my_secret_key"
salt = "my_salt"
safe = Safe(key, salt)

# Encrypt data
data = "Sensitive data"
encrypted_data = safe.safe_tool_sync(Instance(encrypt=data))

# Decrypt data
decrypted_data = safe.safe_tool_sync(Instance(decrypt=encrypted_data))
```

## Static File Serving

To serve static files, simply use the `static_file_server` method:

```python
@app.route
async def serve_file(request):
    return await Static.static_file_server(request, override_file='example.txt')
```

## Middleware Example

Implement middleware by defining a function and registering it:

```python
@app.route(methods=["GET", "POST"])
async def before_middleware(request):
    # Perform some action before the main route handler
    return request
```

## Error Handling

Custom error handling can be implemented by extending the `Error` class:

```python
class CustomError(Error):
    def __init__(app, message):
        super().__init__(message)

# Usage
raise CustomError("Something went wrong!")
```

## Documentation

For more detailed documentation, please refer to the [Wiki](https://github.com/anonyxbiz/predator/wiki).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please fork the repository and create a pull request for any changes or enhancements.

## Contact

For questions or support, please open an issue in the GitHub repository.