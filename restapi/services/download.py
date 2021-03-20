"""
Download data from APIs
"""
from mimetypes import MimeTypes
from pathlib import Path
from typing import Iterator, Optional

from flask import Response, send_from_directory, stream_with_context
from werkzeug.utils import secure_filename

from restapi.exceptions import BadRequest
from restapi.services.uploader import Uploader
from restapi.utilities.logs import log


class Downloader:

    # This is good for small files
    # It is also good for media files by sending Range header
    @staticmethod
    def download(
        filename: Optional[str] = None,
        subfolder: Optional[Path] = None,
        mime: Optional[str] = None,
    ) -> Response:

        if filename is None:
            raise BadRequest("No filename specified to download")

        filename = secure_filename(filename)
        path = Uploader.absolute_upload_file(
            filename, subfolder=subfolder, onlydir=True
        )
        log.info("Starting transfer of '{}' from '{}'", filename, path)

        return send_from_directory(path, filename, mimetype=mime)

    @staticmethod
    def read_in_chunks(path: Path, chunk_size: int = 1024) -> Iterator[bytes]:
        """
        Lazy function (generator) to read a file piece by piece.
        """
        log.critical("DEBUG CODE: Reading path {}", str(path))
        with open(path, "rb") as file_handle:
            log.critical("File open")
            while data := file_handle.read(chunk_size):
                log.critical("Chunk")
                yield data

    # this is good for large files
    # Beware: path is expected to be already secured, no further validation applied here
    @staticmethod
    def send_file_streamed(path: Path, mime: Optional[str] = None) -> Response:
        if mime is None:
            # guess_type expects a str as argument because
            # it is intended to be used with urls and not with paths
            mime_type = MimeTypes().guess_type(str(path))
            mime = mime_type[0]

        log.info("Providing streamed content from {} (mime={})", path, mime)

        return Response(
            stream_with_context(Downloader.read_in_chunks(path)),
            mimetype=mime,
        )
