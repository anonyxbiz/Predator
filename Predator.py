# Predator/Predator.py
from sys import exit
from functools import wraps
from typing import Callable, List, Dict, Optional
from inspect import signature as sig, Parameter, stack as inspect_stack
from psutil import virtual_memory
from aiofiles import open as iopen
from os import path
from mimetypes import guess_type
from asyncio import CancelledError, to_thread, run, sleep, create_task
from aiohttp import web, ClientConnectionError
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode, b64decode
from datetime import datetime as dt, timedelta
from json import loads, dumps
import time

p = print

class MyDict:
    async def init(app, **kwargs):
        app.__dict__.update(kwargs)
        return app

    async def get(app):
        return app.__dict__

class Stuff:
    @classmethod
    async def headers(app, **kwargs):
        response_headers = {
            'Server': 'Predator',
            'Strict-Transport-Security': 'max-age=63072000; includeSubdomains', 
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'origin-when-cross-origin'
        }

        if kwargs:
            response_headers.update(**kwargs)

        return response_headers

class Error(Exception):
    def __init__(app, message=None):
        super().__init__(message)
        app.message = str(message)

    def __str__(app) -> str:
        return app.message

class Abort(Exception):
    def __init__(app, message="Something went wrong", **kwargs):
        super().__init__(message)
        app.message = str(message)
        app.kwargs = kwargs

    def __str__(app) -> str:
        return app.message

    async def text(app, r):
        await Log.out(app.message)
        response = web.Response(
            status = app.kwargs.get("status", 403),
            text = app.message,
            headers = app.kwargs.get("headers", {})
        )

        r.response = response
        return response

class Pack:
    @classmethod
    async def set(app, **kwargs):
        app = app()
        app.__dict__.update(kwargs)
        return app

class Log:
    @classmethod
    async def out_(app, e):
        try:
            e = str(e).strip()
            fname = inspect_stack()[1].function
            log = False

            known_exceps = [
                "transport",
                "Task",
                "Cannot write",
                "closing transport",
                "Cannot write to closing transport"
            ]
            for a in known_exceps:
                if a in e:
                    log = False
                    break
                else:
                    log = True

            if log:
                e = "[%s]:: %s ::" % (
                    fname,
                    e
                )
                print("$: %s" % (e))
        except Exception as e:
            print(e)
    
    @classmethod
    async def out(app, e):
        try:
            e = str(e).strip()
            log = False

            known_exceps = [
                "transport",
                "Task",
                "Cannot write",
                "closing transport",
                "Cannot write to closing transport"
            ]
            for a in known_exceps:
                if a in e:
                    log = False
                    break
                else:
                    log = True

            if log:
                print("$ (%s): %s" % (dt.now(), e))
        except Exception as e:
            print(e)

class Safe:
    def __init__(app, key, salt="Kim Jong Un"):
        app.salt = str(salt)
        app.safe_key = str(key)
        app.key = None

    def safe_tool_sync(app, og: MyDict):
        try:
            if not app.key: app.key = PBKDF2(app.safe_key.encode(), app.salt.encode(), dkLen=16)

            cipher = AES.new(app.key, AES.MODE_EAX)
            if (data := og.__dict__.get("encrypt", 0)):
                if not isinstance(data, (bytearray, bytes,)): data = data.encode()
                ciphertext, tag = cipher.encrypt_and_digest(data)

            elif (data := og.__dict__.get("decrypt", 0)):
                try: data = data.replace(' ', '+')
                except: pass
                data = b64decode(data)
                nonce = data[:16]
                tag = data[16:32]
                ciphertext = data[32:]
                cipher = AES.new(app.key, AES.MODE_EAX, nonce=nonce)
                return cipher.decrypt_and_verify(ciphertext, tag)
            else:
                raise Error("Unidentified request")
            return b64encode(cipher.nonce + tag + ciphertext)
        except Exception as e:
            raise Error(e)

    async def safe_tool(app, og: MyDict):
        return await to_thread(app.safe_tool_sync, og)

class Stream:
    @classmethod
    async def init(app, r, **kwargs):
        app = app()
        app.r = r
        app.status = kwargs.get("status", 200)
        app.headers = await Stuff.headers()
        app.headers.update(kwargs.get("headers", {}))
        return app

    async def json(app):
        app.headers.update({
            'Content-Range': '',
            'Accept-Ranges': 'bytes',
            'Content-Type': "application/json",
        })
        return app

    async def raw(app):
        app.headers.update({
            'Content-Range': '',
            'Accept-Ranges': 'bytes',
        })
        return app

    async def text(app):
        app.headers.update({
            'Content-Range': '',
            'Accept-Ranges': 'bytes',
            'Content-Type': "text/plain",
        })
        return app

    async def write(app, content):
        try:
            if app.r.response is None:
                app.r.response = web.StreamResponse(
                    status=app.status,
                    reason="OK",
                    headers=app.headers
            )

            if not app.r.response.prepared:
                await app.r.response.prepare(app.r.request)

            if isinstance(content, (str,)):
                content = content.encode()

            await app.r.response.write(content)
        except Exception as e:
            await Log.out(e)

    async def finish(app, content=None):
        try:
            if content is not None:
                await app.write(content)
            await app.r.response.write_eof()
        except Exception as e:
            await Log.out(e)

class Static:
    @classmethod
    async def serve_file(app, r, file_path, chunk_size=1024, vars={}, response_headers={}):
        try:
            response_headers.update(await Stuff.headers())
            filename = path.basename(file_path)
            file_size = path.getsize(file_path)
            content_type, _ = guess_type(file_path)
            content_disposition = 'inline; filename="%s"' % (filename)

            if (range_header := r.headers.get('Range', r.params.get('Range'))):
                start, end = (byte_range := range_header.strip().split('=')[1]).split('-')

                start = int(start)
                end = int(end) if end else file_size - 1
            else:
                start, end = 0, file_size - 1

            content_range = 'bytes %s-%s/%s' % (start, end, file_size) if r.headers.get("Range") else ''
            content_length = str(end - start + 1)

            if not content_type:
                content_type = "application/octet-stream"
                content_disposition = 'attachment; filename="%s"' % (filename)
            status_code = 206 if range_header is not None else 200

            response_headers.update({
                'Content-Range': content_range,
                'Accept-Ranges': 'bytes',
                'Content-Length': content_length,
                'Content-Type': content_type,
                'Content-Disposition': content_disposition
            })

            r.response = web.StreamResponse(
                status=status_code,
                reason="OK",
                headers=response_headers
            )
            await r.response.prepare(r.request)

            async with iopen(file_path, "rb") as f:
                await f.seek(start)
                while True:
                    try:
                        if not (chunk := await f.read(chunk_size)):
                            return None
                        
                        if vars != {}:
                            for key, val in vars.items():
                                if not isinstance(key, (bytes, bytearray)):
                                    key = key.encode()

                                if not isinstance(val, (bytes, bytearray)):
                                    val = val.encode()
                                    
                                if key in chunk:
                                    chunk = chunk.replace(key, val)
                        
                        await r.response.write(chunk)
                    except Exception as e:
                        if "transport" not in str(e).strip():
                            p(e)
                        return None

        except Exception as e:
            return None

        await r.response.write_eof()

class Request:
    @classmethod
    async def gen(app, request):
        app = app() # Immutable dict
        app.request = request
        app.json = request.json
        app.content = request.content
        app.response = None
        app.tail = request.path
        app.params = request.query
        app.headers = request.headers
        app.method = request.method
        app.ip = request.remote
        app.route_name = request.path

        return app

class Make_request_:
    @classmethod
    async def json_response(app, r, _dict_={}):
        r.response = web.json_response(_dict_)
        return r

    @classmethod
    async def json(app, r, size=1024, body = b""):
        if r.method in ["POST"]:
            while not r.content.at_eof():
                try:
                    chunk = await r.content.read(size)
                    if not chunk:
                        break
                    else:
                        body += chunk
                except (UnicodeError, Exception) as e:
                    raise Error("Something went wrong")
                    return
            try:
                body = body.decode("utf-8")
                body = loads(body)
            except (UnicodeError, Exception) as e:
                raise Error("Something went wrong")
                return
    
            return body
        else:
            data = {a:b for a, b in r.request.query.items()}
            return data

    @classmethod
    async def chunks(app, r, size=1024):
        while not r.content.at_eof():
            try:
                chunk = await r.content.read(size)
                if not chunk:
                    break
                else:
                    yield chunk
            except (UnicodeError, Exception) as e:
                p(e)
                raise Error("Something went wrong")
                return
            
    @classmethod
    async def headers(app, r):
        h = {a:b for a,b in r.request.headers.items()}
        return h

class WebApp:
    environment = "development"
    @classmethod
    async def init(app, **kwargs):
        app = app()
        app.__dict__.update(kwargs)
        app.web = web
        app.response_headers = await Stuff.headers()
        app.dev = 1

        app.routes = await Pack.set()
        app.ddos_protection = 0
        app.throttle_at_ram = 0.20
        app.secure_host = 0
        app.requests_count = 0
        app.default_methods = ["GET", "POST", "OPTIONS", "PUT", "PATCH", "HEAD", "DELETE"]

        return app
    
    def add_route_sync(app, route_name: str, incoming_data: dict):
        if not (func := incoming_data.get("func")):
            raise Error("func is required")
        
        if not isinstance(func, (Callable,)):
            raise Error("func is not Callable")

        signature = sig(func)
        params = dict(signature.parameters)

        methods_param = params.get("methods", None)
        if methods_param:
            methods = methods_param.default
        else:
            methods = app.default_methods

        if isinstance(methods, list):
            methods = {method: True for method in methods}
        elif isinstance(methods, str):
            methods = {methods: True}

        data = {
            "func": func,
            "methods": methods,
            "params": incoming_data.get("params", {})
        }
    
        app.routes.__dict__[route_name] = data

    async def add_route(app, route_name: str, incoming_data: dict):
        app.add_route_sync(route_name, incoming_data)

    def route(app, func: Callable):
        route_name = str(func.__name__).replace("_", "/")
        app.add_route_sync(route_name, {"func": func})
        
        return func

    async def serve_route(app, r, route=None):
        if "before_middleware" in app.routes.__dict__:
            route = app.routes.__dict__["before_middleware"]
            if not r.method in route.get("methods", {}):
                raise Abort("Illegal method")

        if route is None and r.route_name in app.routes.__dict__:
            route = app.routes.__dict__[r.route_name]
            if not r.method in route.get("methods", {}):
                raise Abort("Illegal method")
        else:
            if route is None and "dynamic_routes" in app.__dict__:
                for key, val in app.routes.__dict__:
                    if r.route_name.startswith(key):
                        route = val

        if route is None and "handle_all" in app.routes.__dict__:
            route = app.routes.__dict__["handle_all"]
            if not r.method in route.get("methods", {}):
                raise Abort("Illegal method")

        if "after_middleware" in app.routes.__dict__:
            route = app.routes.__dict__["after_middleware"]
            if not r.method in route.get("methods", {}):
                raise Abort("Illegal method")

        if route is not None:
            await route.get("func")(r, **route.get("params"))
        else:
            raise Abort("Not Found", status=404)

    async def handle_preqs(app, r):
        if r.method in "HEAD":
            raise pd.Abort(
                "OK",
                status = 200,
                headers = {
                    "time": str(int(time.time())),
                },
            )

    async def router(app, aiohttp_request, r=None):
        try:
            r = await Request.gen(aiohttp_request)

            await Log.out("[%s] => %s@ %s" % (r.ip, r.method, r.tail))

            await app.handle_preqs(r)
            await app.serve_route(r)
            if r.response is None:
                raise Abort()

        except KeyboardInterrupt:
            return
        except Abort as e:
            await e.text(r)
        except Error as e:
            try:
                raise Abort(str(e), status=403)
            except Abort as e:
                await e.text(r)

        except (CancelledError, AttributeError, Exception) as e:
            await Log.out(e)
        finally:
            return await app.finalize(r)

    async def finalize(app, r):
        if r is not None and "response" in r.__dict__ and r.response is not None:
                r.response.headers.update(await Stuff.headers())
                return r.response

    async def config_ssl(app):
        def setup_ssl(system = None):
            try:
                if not path.exists(f"{app.app_config.certfile}") or not path.exists(f"{app.app_config.keyfile}"):
                    from os import system
                    system(f'openssl req -x509 -newkey rsa:2048 -keyout {app.app_config.keyfile} -out {app.app_config.certfile} -days 365 -nodes -subj "/CN={app.app_config.host}"')

                from ssl import create_default_context, Purpose 
                app.app_config.ssl_context = create_default_context(Purpose.CLIENT_AUTH)
                app.app_config.ssl_context.load_cert_chain(certfile=app.app_config.certfile, keyfile=app.app_config.keyfile)
            except Exception as e:
                p(e)
            finally:
                del system
                return

        if (ssl_data := app.app_config.__dict__.get("ssl")) is not None:
            app.web_protocol = "https"
            app.app_config.certfile, app.app_config.keyfile = ssl_data["certfile"], ssl_data["keyfile"]

            setup_ssl()
            app.app_config.site = web.TCPSite(app.app_config.runner, app.app_config.host, app.app_config.port, ssl_context=app.app_config.ssl_context)
        else:
            app.web_protocol = "http"
            app.app_config.site = web.TCPSite(app.app_config.runner, app.app_config.host, app.app_config.port)

    async def run(app, app_config):
        if not isinstance(app_config, (MyDict,)):
            if isinstance(app_config, (dict,)):
                config = MyDict()
                config.__dict__.update(app_config)
                app_config = config
            else:
                raise Error("app_config must be a valid dict")

        for a in ["host", "port"]:
            if not app_config.__dict__.get(a, None):
                raise Error(f"{a} is required.")

        app.app_config = app_config
        server = web.Server(app.router)
        server.client_max_size = None

        app.app_config.runner = web.ServerRunner(server)
            
        await app.app_config.runner.setup()
        await app.config_ssl()

        await app.app_config.site.start()

        await Log.out(
            "=== Predator Is Serving %s On %s://%s:%s ===" % (
                app.app_config.host,
                app.web_protocol,
                app.app_config.host,
                app.app_config.port
            )
        )
        
        await sleep(100*3600)
        
    def runner(app, app_config):
        try:
            run(app.run(app_config))
        except KeyboardInterrupt:
            exit("[%s]:: KeyboardInterrupted" % (str(dt.now())))
        except CancelledError:
            pass
        except Exception as e:
            p("Exception caught: %s" % str(e))

if __name__ == '__main__':
    config = run(MyDict(host="0.0.0.0", port=8000, ssl={"certfile": "cert.pem", "keyfile": "key.pem"}))
    wb = run(WebApp().init())
    wb.runner(config)
