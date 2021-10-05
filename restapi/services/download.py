"""
Download data from APIs
"""
from mimetypes import MimeTypes
from pathlib import Path
from typing import Iterator, Optional

from flask import Response, send_from_directory, stream_with_context
from werkzeug.utils import secure_filename

from restapi.exceptions import BadRequest, NotFound
from restapi.services.uploader import Uploader
from restapi.utilities.logs import log

DEFAULT_CHUNK_SIZE = 1048576  # 1 MB


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
        log.info("Sending file content from {}/{}", path, filename)

        return send_from_directory(path, filename, mimetype=mime)

    @staticmethod
    def read_in_chunks(
        path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE
    ) -> Iterator[bytes]:
        """
        Lazy function (generator) to read a file piece by piece.
        """
        with open(path, "rb") as file_handle:
            while data := file_handle.read(chunk_size):
                yield data

    # this is good for large files
    @staticmethod
    def send_file_streamed(
        path: Path, mime: Optional[str] = None, out_filename: Optional[str] = None
    ) -> Response:

        str_path = secure_filename(str(path))
        path = Path(str_path)
        if mime is None:
            # guess_type expects a str as argument because
            # it is intended to be used with urls and not with paths
            mime_type = MimeTypes().guess_type(str_path)
            mime = mime_type[0]

        log.info("Providing streamed content from {} (mime={})", path, mime)

        if not path.is_file():
            raise NotFound("The requested file does not exist")

        response = Response(
            stream_with_context(Downloader.read_in_chunks(path)),
            mimetype=mime,
        )

        if not out_filename:
            out_filename = path.name

        response.headers["Content-Disposition"] = f"attachment; filename={out_filename}"
        response.headers["Content-Length"] = path.stat().st_size
        return response
