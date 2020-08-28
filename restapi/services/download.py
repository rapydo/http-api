"""
Download data from APIs
"""

from mimetypes import MimeTypes

from flask import Response, send_from_directory, stream_with_context

from restapi.exceptions import RestApiException
from restapi.services.uploader import Uploader
from restapi.utilities.logs import log


class Downloader:

    # This is good for small files
    # It is also good for media files by sending Range header
    @staticmethod
    def download(filename=None, subfolder=None, mime=None):

        if filename is None:
            raise RestApiException("No filename specified to download", status_code=400)

        path = Uploader.absolute_upload_file(
            filename, subfolder=subfolder, onlydir=True
        )
        log.info("Starting transfer of '{}' from '{}'", filename, path)

        return send_from_directory(path, filename, mimetype=mime)

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
    @staticmethod
    def send_file_streamed(path, mime=None):
        if mime is None:
            mime = MimeTypes()
            mime_type = mime.guess_type(path)
            mime = mime_type[0]

        log.info("Providing streamed content from {} (mime={})", path, mime)

        f = open(path, "rb")
        return Response(
            stream_with_context(Downloader.read_in_chunks(f)), mimetype=mime
        )
