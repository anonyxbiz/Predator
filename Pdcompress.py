from gzip import GzipFile
from io import BytesIO

p = print

class Serve_compressed(object):
    @classmethod
    async def init(app, **kwargs):
        app = app()
        app.__dict__.update(kwargs)
        return app
    
    async def perform_checks(app, r):
        if not (file := r.override_file):
            if not (file := r.params.get(r.arg, 0)):
                raise Error("serve parameter is required.")
                
            r.file = "./static/%s" % (file)
        else:
            r.file = file
            
        if not await to_thread(path.exists, r.file):
            raise Error("Not found")
            
        r.d = MyDict()
    
    async def initialize_response(app, r):
        def _func():
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
            
            r.d.gzip_encoding = r.headers.get('Accept-Encoding', '')
            
            if 'gzip' in r.d.gzip_encoding:
                r.d.gzip_encoding = True
            else:
                r.d.gzip_encoding = False
                
        _ = await to_thread(_func)
        
        if r.d:
            r.stream = await Stream_Response().init(r, status=r.d.status)
                
            r.response.headers.update(
                {
                    'Content-Range': r.d.content_range,
                    'Accept-Ranges': 'bytes',
                    'Content-Length': r.d.content_length,
                    'Content-Type': r.d.content_type,
                    'Content-Disposition': r.d.content_disposition
                }
            )
            
            if r.d.gzip_encoding:
                r.response.headers.update(
                    {
                        'Content-Encoding': 'gzip',
                    }
                )
        else:
            raise Error("Something went wrong")
            
    async def chunks(app, r, override_file=0, serve_chunk=0, arg="serve"):
        r.override_file = override_file
        r.serve_chunk = serve_chunk
        r.arg = arg
        
        # Make python explicitly wait for the returns
        checks = await app.perform_checks(r)
        initialization = await app.initialize_response(r)

        async with iopen(r.d.fname, "rb") as f:
            while True:
                await f.seek(r.d.start)
                if not (chunk := await f.read(r.serve_chunk or 1024*1024)):
                    break
                else:
                    chunk = await app.compress_chunk(r, chunk)
                    r.d.start += len(chunk)
                    await r.stream.write(chunk)
                
            await r.stream.finish()
    
    async def compress_chunk(app, r, chunk):
        def compress(level=9):
            buf = BytesIO()
            with GzipFile(fileobj=buf, mode='wb', compresslevel=level) as f:
                f.write(chunk)
            return buf.getvalue()
        
        if r.d.gzip_encoding:
            chunk = await to_thread(compress)
        return chunk
