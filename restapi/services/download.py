# -*- coding: utf-8 -*-

"""
Download data from APIs.
"""

import os
import re
from mimetypes import MimeTypes
from flask import request, send_from_directory, stream_with_context, Response

from restapi.services.uploader import Uploader
from restapi.exceptions import RestApiException
from restapi.utilities.logs import log


class Downloader:

    # This is good for small files
    def download(self, filename=None, subfolder=None, get=False):

        # if not get:
        #     return self.response("No flow chunks for now", code=202)

        if filename is None:
            raise RestApiException(
                "No filename specified to download",
                status_code=400
            )

        path = Uploader.absolute_upload_file(
            filename,
            subfolder=subfolder,
            onlydir=True
        )
        log.info("Provide '{}' from '{}'", filename, path)

        return send_from_directory(path, filename)

    @staticmethod
    def read_in_chunks(file_object, chunk_size=1024):
        """
        Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    # this is good for large files
    def send_file_streamed(self, path, mime=None):
        if mime is None:
            mime = MimeTypes()
            mime_type = mime.guess_type(path)
            mime = mime_type[0]

        log.info("Providing streamed content from {} (mime={})", path, mime)

        f = open(path, "rb")
        return Response(stream_with_context(self.read_in_chunks(f)), mimetype=mime)

    # this is good for media files, based on Range header
    def send_file_partial(self, path, mime=None):
        """
        Simple wrapper around send_file which handles HTTP 206 Partial Content
        (byte ranges)
        TODO: handle all send_file args, mirror send_file's error handling
        (if it has any)
        """
        if mime is None:
            mime = MimeTypes()
            mime_type = mime.guess_type(path)
            mime = mime_type[0]

        range_header = request.headers.get('Range', None)
        if not range_header:
            return self.send_file_streamed(path, mime)

        log.critical(range_header)
        size = os.path.getsize(path)
        byte1, byte2 = 0, None

        m = re.search(r'(\d+)-(\d*)', range_header)
        g = m.groups()

        if g[0]:
            byte1 = int(g[0])
        if g[1]:
            byte2 = int(g[1])

        if byte2 is not None:
            length = byte2 + 1 - byte1
        else:
            length = size - byte1

        # 1 mb
        MAX_ALLOWED_LENGTH = 1048576
        if length > MAX_ALLOWED_LENGTH:
            length = MAX_ALLOWED_LENGTH

        log.debug(
            "Providing partial content (bytes {}-{}, len = {} bytes) from {}",
            byte1,
            byte2,
            length,
            path,
        )

        data = None
        with open(path, 'rb') as f:
            f.seek(byte1)
            data = f.read(length)

        rv = Response(
            data, 206, mimetype=mime, direct_passthrough=True
        )
        rv.headers.add(
            'Content-Range', 'bytes {}-{}/{}'.format(byte1, byte1 + length - 1, size)
        )
        rv.headers.add('Accept-Ranges', 'bytes')

        return rv
