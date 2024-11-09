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
from gc import collect

p = print

class MyDict:
    async def init(app, **kwargs):
        app.__dict__.update(kwargs)
        return app
        
    async def get(app):
        return app.__dict__

class Stuff(object):
    app = None
    @classmethod
    async def init(cls, **kwargs):
        app = cls()
        return app
    
    async def headers(app, **kwargs):
        response_headers = {
            'Server': 'Predator',
            'Strict-Transport-Security': 'max-age=63072000; includeSubdomains', 
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(self), microphone=()',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'Date': 'redacted',
        }
        
        async def func():
            for a, b in kwargs.items():
                response_headers[a] = b
        
        if kwargs:
            await func()
        return response_headers

class Error(Exception):
    def __init__(app, message=None):
        super().__init__(message)
        app.message = str(message)

    def __str__(app) -> str:
        return app.message

class Stream_Response(object):
    @classmethod
    async def init(app, r, **kwargs):
        app = app()
        app.r = r
        app.response_headers = {
            'Server': 'Predator',
            'Strict-Transport-Security': 'max-age=63072000; includeSubdomains', 
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(self), microphone=()',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'Date': 'redacted',
        }
        
        app.response_headers.update(kwargs.get("headers", {}))

        app.r.response = web.StreamResponse(
            status=kwargs.get("status", 200),
            headers=app.response_headers
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
        if not app.r.response.prepared:
            await app.r.response.prepare(app.r.request)
    
        try:
            if 0:
                if await to_thread(isinstance, content, (str,)):
                    content = content.encode()
            else:
                if isinstance(content, (str,)):
                    content = content.encode()
        except UnicodeError:
            pass
        except TypeError:
            pass
        except Exception as e:
            p(e)
            
        try:
            await app.r.response.write(content)
        except Exception as e:
            p(e)
            raise Error(e)

    async def finish(app, content=None):
        if content is not None:
            await app.write(content)
        try:
            await app.r.response.write_eof()
        except Exception as e:
            p(e)

class Garbage(object):
    jobs = []
    @classmethod
    async def init(app, **kwargs):
        app = app()
        return app

    async def cleaner(app):
        while True:
            try:
                await to_thread(collect,)
                await sleep(30)
            except Exception as e:
                p(e)
                break
            
    async def collect(app, workers=None):
        if not workers:
            workers = [app.cleaner]

        for worker in workers:
            app.jobs.append(
                create_task(worker())
            )
                
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
        
    async def initialize_response(app, r):
        def _func():
            if not (file := r.override_file):
                if not (file := r.params.get(r.arg)):
                    raise Error("serve parameter is required.")
                    
                r.file = "./static/%s" % (file)
            else:
                r.file = file
                
            if not path.exists(r.file):
                raise Error("Not found")
                
            r.d = MyDict()

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
            
            if not r.d.content_type:
                r.d.content_type = "application/octet-stream"
                r.d.content_disposition = 'attachment; filename="%s"' % (r.d.filename)
                    
            if range_header is not None:
                r.d.status = 206
            else:
                r.d.status = 200
                
        await to_thread(_func)
        # await _func()
        
        if r.d:
            headers = {
                'Server': 'Predator',
                'Strict-Transport-Security': 'max-age=63072000; includeSubdomains', 
                'X-Frame-Options': 'SAMEORIGIN',
                'X-XSS-Protection': '1; mode=block',
                'Referrer-Policy': 'origin-when-cross-origin',
                'Permissions-Policy': 'geolocation=(self), microphone=()',
                'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                'Date': 'redacted',
                'Content-Range': r.d.content_range,
                'Accept-Ranges': 'bytes',
                'Content-Length': r.d.content_length,
                'Content-Type': r.d.content_type,
                'Content-Disposition': r.d.content_disposition
            }
            
            r.response = web.StreamResponse(
                status=r.d.status,
                headers=headers
            )
        else:
            raise Error("Something went wrong")
        
        return r
        
    async def static_file_server(app, r, override_file=0, serve_chunk=0, arg="serve"):
        r.override_file = override_file
        r.serve_chunk = serve_chunk
        r.arg = arg

        r = await app.initialize_response(r)
        
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
                    if not "Cannot write to closing transport" in str(e):
                        p(e)
                    return r
            
            await r.response.write_eof()
            
        return r

class WebApp(object):
    @classmethod
    async def init(app, **kwargs):
        app = app()
        app.__dict__.update(kwargs)
        app.Static = await Static().init()
        app.Stuff = await Stuff.init()
        app.web = web
        app.response_headers = await app.Stuff.headers()
        app.dev = 1
        m = await MyDict().init(methods = {})
        app.methods = m.methods
        app.ddos_protection = 0
        app.throttle_at_ram = 0.20
        app.secure_host = 0

        if "collect_garbage" in app.__dict__:
            garbage = await Garbage.init()
            await garbage.collect()

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

    async def log(app, e):
        e = str(e)
        async def _func():
            ins = MyDict()
            known_exceps = ["transport", "Task"]
            ins.fname=inspect_stack()[3].function
            ins.e, ins.log = str(e), 0

            for a in known_exceps:
                if a in ins.e:
                    pass
                else:
                    ins.log = 1
                    break

            if ins.log:
                str_ = f"[{ins.fname}]:: {ins.e}"
            
                if len(str_) <= 100:
                    pass
                else:
                    str_ = str_[:100]
                p(str_)
                
        await _func()

    async def gen_request(app, incoming_request):
        if incoming_request is not None:
            async def const_r():
                request = MyDict()
                
                def get_system_resources():
                    ins = MyDict()
                    ins.memory_info = virtual_memory()
                    ins.aval_gb = float(f"{ins.memory_info.available / (1024 ** 3):.2f}")
                    return ins
                    
                def _func():
                    request.request = incoming_request
                    request.response = None
                    request.tail = request.request.path
                    request.params = {a:b for a,b in request.request.query.items()}
                    request.headers = {a:b for a,b in request.request.headers.items()}
                    request.method = request.request.method
                    request.ip = incoming_request.remote
                    
                    request.route_name = "_".join(request.tail.split("/"))
                    request.blocked = 0
                    
                    if not "_" in request.route_name: request.route_name = "_"
                    request.full_tail = request.route_name + "?" + "&&".join([f"{a}={b}" for a, b in request.params.items()])
                    
                    p(f"[{request.ip or '127.0.0.1'}] :{request.method}: @{request.tail}")

                    if app.secure_host and not request.headers.get("Host", "0").startswith(app.host):
                        request.blocked = "Unidentified Client"

                    if app.ddos_protection:
                        # ins = await to_thread(get_system_resources,)
                        ins = get_system_resources()
                        if ins.aval_gb <= app.throttle_at_ram:
                            request.blocked = f"Our server is currently busy, remaining resources are: {ins.aval_gb} GB, try again later when resources are available."
                            
                    return request
                    
                return await to_thread(_func,)
                
            return await const_r()
        
    async def router(app, incoming_request):
        try:
            request = await app.gen_request(incoming_request)
            if request.blocked: raise Error(request.blocked)
            
            if (a := "before_middleware") in app.methods:
                if request.method not in app.methods[a]["methods"]: raise Error("Method not allowed")
                
                if (_ := await app.methods[a]["func"](request)) is not None:
                    pass

            if request.response is None and request.route_name in app.methods:
                if request.method not in app.methods[request.route_name]["methods"]:
                    raise Error("Method not allowed")
                
                if (_ := await app.methods[request.route_name]["func"](request)) is not None:
                    pass
                
            if request.response is None:
                if (a := "not_found_method") in app.methods or (a := "handle_all") in app.methods:
                    if request.method not in app.methods[a]["methods"]: raise Error("Method not allowed")
                
                    if (_ := await app.methods[a]["func"](request)) is not None:
                        pass
                    if request.response is None:
                        raise Error("Not found")
                        
                else:
                    raise Error("Not found")
            
            if (a := "after_middleware") in app.methods:
                if (_ := await app.methods[a]["func"](request)) is not None:
                    pass
                    
        except Error as e:
            try:
                request.stream = await Stream_Response.init(request, status=403)
                await request.stream.json()
                await request.stream.write('{"detail": "')
                await request.stream.write(str(e))
                await request.stream.finish('"}')
            except Exception as e:
                await app.log(e)

        except KeyboardInterrupt:
            pass
        except Exception as e:
            await app.log(e)
            if app.dev:
                msg = str(e)
            else:
                msg = "Unexpected 403"
                
            request.stream = await Stream_Response.init(request, status=403)
            
            await request.stream.json()
            await request.stream.write('{"detail": "')
            await request.stream.write(msg)
            await request.stream.finish('"}')

        return await app.finalize_request(request)

    async def finalize_request(app, request):
        try:
            if request.response is None:
                request.stream = await Stream_Response.init(request, status=500)

                await request.stream.json()
                await request.stream.write('{"detail": "')
                await request.stream.write('Response not set.')
                await request.stream.finish('"}')
                
            request.response.headers.update(app.response_headers)
        except Exception as e:
            await app.log(e)
        
        try:
            return request.response
        except Exception as e:
            await app.log(e)
    
    async def handle(app, request):
        """Request handler from aiohttp web.server"""
        try:
            r = await app.router(request)
            
            if r is None:
                raise Error("Response was None")
            return r
            
        except (ConnectionResetError, OSError, AttributeError, TypeError) as e:
            return await app.handle_connection_error(app, request, e)
        except ClientConnectionError as e:
            return await app.handle_connection_error(app, request, e)
        except Error as e:
            return await app.handle_connection_error(app, request, e)
        except Exception as e:
            return await app.handle_connection_error(app, request, e)
            
    async def handle_connection_error(app, request, err):
        try:
            await app.log("Request handling error: %s" % err)
            await request.cancel()
        except Exception as e:
            p(e)

    def setup_ssl(app):
        if not path.exists(f"{app.app_config.certfile}") or not path.exists(f"{app.app_config.keyfile}"):
            from os import system
            system(f'openssl req -x509 -newkey rsa:2048 -keyout {app.app_config.keyfile} -out {app.app_config.certfile} -days 365 -nodes -subj "/CN={app.app_config.host}"')
        
        from ssl import create_default_context, Purpose 
        app.app_config.ssl_context = create_default_context(Purpose.CLIENT_AUTH)
        app.app_config.ssl_context.load_cert_chain(certfile=app.app_config.certfile, keyfile=app.app_config.keyfile)
        
    async def run(app, app_config: MyDict):
        app.app_config = app_config
        server = web.Server(app.handle)
        server.client_max_size = None
        app.app_config.runner = web.ServerRunner(server)
            
        await app.app_config.runner.setup()
        
        if not (ssl_data := app.app_config.__dict__.get("ssl", None)):
            app.app_config.site = web.TCPSite(app.app_config.runner, app.app_config.host, app.app_config.port)
        else:
            app.app_config.certfile, app.app_config.keyfile = ssl_data["certfile"], ssl_data["keyfile"]
            
            await to_thread(app.setup_ssl)
            app.app_config.site = web.TCPSite(app.app_config.runner, app.app_config.host, app.app_config.port, ssl_context=app.app_config.ssl_context)
            
        await app.app_config.site.start()
        
        if ssl_data: prot = "https"
        else: prot = "http"
        await app.log(f"=== Predator Is Serving {app.app_config.host} On {prot}://{app.app_config.host}:{app.app_config.port} ===")
        
        await sleep(100*3600)
        
    def runner(app, app_config: MyDict):
        try:
            for a in ["host", "port"]:
                if not app_config.__dict__.get(a, None):
                    raise Error(f"{a} is required.")
                    
            run(app.run(app_config))
        except KeyboardInterrupt: exit()
        except (ConnectionResetError, OSError, AttributeError, TypeError):
            pass
        except Exception as e:
            p("Exception catched: %s" % str(e))
        except BaseException as e:
            p("Base Exception catched: %s" % str(e))
            
if __name__ == '__main__':
    config = run(MyDict(host="0.0.0.0", port=8000, ssl={"certfile": "cert.pem", "keyfile": "key.pem"}))
    wb = run(WebApp().init())
    wb.runner(config)
