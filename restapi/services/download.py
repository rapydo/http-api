# -*- coding: utf-8 -*-

"""
Download data from APIs.
"""

import os
import re
from flask import request, send_from_directory, stream_with_context, Response
from utilities import htmlcodes as hcodes

from utilities.logs import get_logger
log = get_logger(__name__)


class Downloader(object):

    def download(self, filename=None, subfolder=None, get=False):

        if not get:
            return self.force_response(
                "No flow chunks for now", code=hcodes.HTTP_OK_ACCEPTED)

        if filename is None:
            return self.force_response(errors={
                "Missing file": "No filename specified to download"})

        path = self.absolute_upload_file(
            filename, subfolder=subfolder, onlydir=True)
        log.info("Provide '%s' from '%s'", filename, path)

        return send_from_directory(path, filename)

    def read_in_chunks(self, file_object, chunk_size=1024):
        """
        Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def send_file_streamed(self, path, mime):
        log.info("Providing streamed content from %s", path)

        f = open(path, "rb")
        return Response(
            stream_with_context(self.read_in_chunks(f)),
            mimetype=mime)

    def send_file_partial(self, path, mime):
        """
        Simple wrapper around send_file which handles HTTP 206 Partial Content
        (byte ranges)
        TODO: handle all send_file args, mirror send_file's error handling
        (if it has any)
        """
        range_header = request.headers.get('Range', None)
        if not range_header:
            return self.send_file_streamed(path, mime)

        size = os.path.getsize(path)
        byte1, byte2 = 0, None

        m = re.search('(\d+)-(\d*)', range_header)
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

        log.info(
            "Providing partial content (bytes %s-%s, len = %s bytes) from %s",
            byte1, byte2, length, path
        )

        data = None
        with open(path, 'rb') as f:
            f.seek(byte1)
            data = f.read(length)

        rv = Response(
            data, hcodes.HTTP_PARTIAL_CONTENT,
            mimetype=mime,
            direct_passthrough=True
        )
        rv.headers.add(
            'Content-Range', 'bytes %d-%d/%d'
            % (byte1, byte1 + length - 1, size)
        )
        rv.headers.add('Accept-Ranges', 'bytes')

        return rv
