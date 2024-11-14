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
        app = app()
        app.response_headers = {
            'Server': 'Predator',
            'Strict-Transport-Security': 'max-age=63072000; includeSubdomains', 
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'origin-when-cross-origin'
        }

        if kwargs:
            app.response_headers.update(**kwargs)

        return app.response_headers

class Error(Exception):
    def __init__(app, message=None):
        super().__init__(message)
        app.message = str(message)

    def __str__(app) -> str:
        return app.message

class Pack:
    @classmethod
    async def set(app, **kwargs):
        app = app()
        app.__dict__.update(kwargs)
        return app

class Log:
    known_exceps = [
        "transport",
        "Task",
        "Cannot write",
        "closing transport",
        "Cannot write to closing transport"
    ]

    embody = None
    @classmethod
    async def out(app, e, **kwargs):
        try:
            app = app()
            p(e)
            return app

            app.__dict__.update(kwargs)
            if app.embody is None:
                app.embody = await Pack.set()

            app.embody.e = str(e).strip()
            app.embody.fname = inspect_stack()[1].function
            app.embody.log = False

            for a in app.known_exceps:
                if a in app.embody.e:
                    app.embody.log = False
                    break
                else:
                    app.embody.log = True

            if app.embody.log:
                app.embody.e = "[%s]:: %s ::" % (
                    app.embody.fname,
                    app.embody.e
                )
                p("$: %s" % (app.embody.e))

            del app.embody
            return app

        except Exception as e:
            print(e)

class Stream_Response:
    @classmethod
    async def init(app, r, **kwargs):
        app = app()
        app.r = r

        app.r.response = web.StreamResponse(
            status=kwargs.get("status", 200),
            headers=await Stuff.headers(**kwargs.get("headers", {}))
        )
        return app

    async def json(app):
        app.r.response.headers.update({
            'Content-Range': '',
            'Accept-Ranges': 'bytes',
            'Content-Type': "application/json",
        })

    async def raw(app):
        app.r.response.headers.update({
            'Content-Range': '',
            'Accept-Ranges': 'bytes',
        })

    async def text(app):
        app.r.response.headers.update({
            'Content-Range': '',
            'Accept-Ranges': 'bytes',
            'Content-Type': "text/plain",
        })

    async def write(app, content):
        try:
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

class Static:
    async def init(app, **kwargs):
        app.__dict__.update(kwargs)
        return app

    async def initialize_response(app, r, **kwargs):
        async def _func():
            if not (file := r.override_file):
                if not (file := r.params.get(r.arg)):
                    raise Error("serve parameter is required.")

                r.file = "./static/%s" % (file)
            else:
                r.file = file

            if not path.exists(r.file):
                raise Error("Not found")

            r.d = await Pack.set()

            r.d.fname = r.file
            r.d.filename = path.basename(r.d.fname)
            r.d.file_size = path.getsize(r.d.fname)

            r.d.content_type, _ = guess_type(r.d.fname)
            r.d.content_disposition = 'inline; filename="%s"' % (r.d.filename)

            if (range_header := r.headers.get('Range', r.params.get('Range', None))):
                r.d.start, r.d.end = (byte_range := range_header.strip().split('=')[1]).split('-')

                r.d.start = int(r.d.start)
                r.d.end = int(r.d.end) if r.d.end else r.d.file_size - 1
            else:
                r.d.start, r.d.end = 0, r.d.file_size - 1

            r.d.content_range = 'bytes %s-%s/%s' % (r.d.start, r.d.end, r.d.file_size) if r.headers.get("Range", None) else ''

            r.d.content_length = str(r.d.end - r.d.start + 1)
            if not r.d.content_type or kwargs.get("download_file"):
                r.d.content_type = "application/octet-stream"
                r.d.content_disposition = 'attachment; filename="%s"' % (r.d.filename)

            r.d.status = 206 if range_header is not None else 200
            # expires_date = dt.utcnow() + timedelta(hours=24)
            # r.d.Expires = expires_date.strftime('%a, %d %b %Y %H:%M:%S GMT')

        await _func()

        if r.d:
            headers = {
                'Cache-Control': 'public, max-age=86400',
                'Expires': r.d.Expires,
                'Content-Range': r.d.content_range,
                'Accept-Ranges': 'bytes',
                'Content-Length': r.d.content_length,
                'Content-Type': r.d.content_type,
                'Content-Disposition': r.d.content_disposition
            }
            r.response = web.StreamResponse(
                status=r.d.status,
                headers=await Stuff.headers(**headers)
            )
        else:
            raise Error("Something went wrong")

        return r

    async def static_file_server(app, r, override_file=0, serve_chunk=0, arg="serve", config={}):
        r.override_file = override_file
        r.serve_chunk = serve_chunk
        r.arg = arg

        r = await app.initialize_response(r, **config)

        async with iopen(r.d.fname, "rb") as f:
            if not r.response.prepared:
                await r.response.prepare(r.request)

            while True:
                try:
                    await f.seek(r.d.start)

                    if not (chunk := await f.read(r.serve_chunk or 1024)):
                        break

                    r.d.start += len(chunk)
                    await r.response.write(chunk)
                except Exception as e:
                    await Log.out(e)
                    break
            try:
                await r.response.write_eof()
            except Exception as e:
                await Log.out(e)

        return r

class Stream:
    @classmethod
    async def init(app, r, **kwargs):
        app = app()
        app.r = r
        # app.__dict__.update(**kwargs)
        app.status = 200 if (sts := kwargs.get("status")) is None else sts

        app.headers = {
            'Server': 'Predator',
            'Strict-Transport-Security': 'max-age=63072000; includeSubdomains', 
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'origin-when-cross-origin'
        }
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

class WebApp:
    @classmethod
    async def init(app, **kwargs):
        app = app()
        app.__dict__.update(kwargs)
        app.web = web
        app.response_headers = await Stuff.headers()
        app.dev = 1

        app.routes = await Pack.set()
        app.methods = {}

        app.ddos_protection = 0
        app.throttle_at_ram = 0.20
        app.secure_host = 0
        app.requests_count = 0

        return app

    def route(app, func: Callable):
        route_name = func.__name__
        signature = sig(func)

        params = dict(signature.parameters)
        methods_param = params.get("methods", None)
        alt_route = params.get("route", None)
        methods = methods_param.default if methods_param and methods_param.default is not Parameter.empty else ["GET", "POST", "OPTIONS", "PUT", "PATCH", "HEAD", "DELETE"]

        if alt_route: route_name = alt_route.default.replace("/", "_")

        data = {
            'func': func,
            'params': params,
            'methods': methods,
        }

        app.methods[route_name] = data
        return func

    async def json_response(app, r, _dict_={}):
        r.response = web.json_response(_dict_)
        return

    async def serve_file(app, r, file_path, chunk_size=1, response_headers={}):
        try:
            response_headers.update({
                'Server': 'Predator',
                'Strict-Transport-Security': 'max-age=63072000; includeSubdomains', 
                'X-Frame-Options': 'SAMEORIGIN',
                'X-XSS-Protection': '1; mode=block',
                'Referrer-Policy': 'origin-when-cross-origin'
            })

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
                        else:
                            await r.response.write(chunk)
                    except Exception as e:
                        if "transport" not in str(e).strip():
                            p(e)
                        return None

        except Exception as e:
            # p("error: %s" % str(e))
            return None

        await r.response.write_eof()

    async def get_json(app, r, size=1024, body = b""):
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

    async def gen_request(app, incoming_request):
        r = await Pack.set()
        r.request = incoming_request
        r.json = r.request.json
        r.content = r.request.content
        
        r.response = None
        r.tail = r.request.path
        r.params = r.request.query
        r.headers = r.request.headers

        r.method = r.request.method
        r.ip = r.request.remote
        r.route_name = r.tail

        return r

    async def router(app, incoming_request, request=None):
        try:
            r = await app.gen_request(incoming_request)

            if r.response is None and "before_middleware" in app.routes.__dict__:
                route = app.routes.__dict__["before_middleware"]
                await route(r)

            if r.route_name in app.routes.__dict__:
                route = app.routes.__dict__[r.route_name]
                await route(r)

            if r.response is None and "handle_all" in app.routes.__dict__:
                route = app.routes.__dict__["handle_all"]
                await route(r)

            if r.response is None:
                r.response = web.Response(text=r.ip)

            if "after_middleware" in app.routes.__dict__:
                route = app.routes.__dict__["after_middleware"]
                await route(r)

            return await app.finalize(r)
        except (CancelledError, Error, AttributeError, Exception) as e:
            if isinstance(e, (Error,)):
                r.response = web.Response(status=403, text=str(e))
            else:
                p("Exception: %s" % str(e))
                r.response = web.Response(status=500, text="Something went wrong")

            return await app.finalize(r)

    async def finalize(app, r):
        if "response" in r.__dict__:
            r.response.headers.update(app.response_headers)
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
