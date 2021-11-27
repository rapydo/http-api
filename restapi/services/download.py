"""
Download data from APIs
"""
from mimetypes import MimeTypes
from pathlib import Path
from typing import Iterator, Optional

from flask import Response, send_from_directory, stream_with_context
from werkzeug.utils import secure_filename

from restapi.config import DATA_PATH
from restapi.exceptions import NotFound
from restapi.services.uploader import Uploader
from restapi.utilities.logs import log

DEFAULT_CHUNK_SIZE = 1048576  # 1 MB


class Downloader:
    @staticmethod
    def guess_mime_type(path: Path) -> Optional[str]:
        # guess_type expects a str as argument because
        # it is intended to be used with urls and not with paths
        mime_type = MimeTypes().guess_type(str(path))
        return mime_type[0]

    # This is good for small files, in particular with displayable files
    # like images, videos or PDF files
    # It is also good for media files by sending Range header
    @staticmethod
    def send_file_content(
        filename: str,
        subfolder: Path,
        mime: Optional[str] = None,
    ) -> Response:

        Uploader.validate_upload_folder(subfolder)

        filename = secure_filename(filename)
        filepath = subfolder.joinpath(filename)
        if not filepath.is_file():
            raise NotFound("The requested file does not exist")

        if mime is None:
            mime = Downloader.guess_mime_type(filepath)

        log.info("Sending file content from {}", filepath)

        # This function is mainly used for displayable files like images and video
        # so that DO NOT SET as_attachment=True that would force the download
        return send_from_directory(subfolder, filename, mimetype=mime)

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
        filename: str,
        subfolder: Path,
        mime: Optional[str] = None,
        out_filename: Optional[str] = None,
    ) -> Response:

        Uploader.validate_upload_folder(subfolder)

        filename = secure_filename(filename)
        filepath = subfolder.joinpath(filename)

        if not filepath.is_file():
            raise NotFound("The requested file does not exist")

        if mime is None:
            mime = Downloader.guess_mime_type(filepath)

        log.info("Providing streamed content from {} (mime={})", filepath, mime)

        response = Response(
            stream_with_context(Downloader.read_in_chunks(filepath)),
            mimetype=mime,
        )

        if not out_filename:
            out_filename = filepath.name

        response.headers["Content-Disposition"] = f"attachment; filename={out_filename}"
        response.headers["Content-Length"] = filepath.stat().st_size
        return response
