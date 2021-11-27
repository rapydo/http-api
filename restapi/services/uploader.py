from pathlib import Path
from typing import Dict, List, Optional, Tuple

from flask import request
from plumbum.cmd import file
from werkzeug.http import parse_content_range_header
from werkzeug.utils import secure_filename

from restapi.config import DATA_PATH, get_backend_url
from restapi.exceptions import BadRequest, Conflict, Forbidden, ServiceUnavailable
from restapi.rest.definition import EndpointResource, Response
from restapi.utilities.logs import log

# Equivalent to -r--r-----
DEFAULT_PERMISSIONS = 0o440


class Uploader:

    allowed_exts: List[str] = []

    def set_allowed_exts(self, exts: List[str]) -> None:
        self.allowed_exts = exts

    def allowed_file(self, filename: str) -> bool:
        if not self.allowed_exts:
            return True
        return (
            "." in filename and filename.rsplit(".", 1)[1].lower() in self.allowed_exts
        )

    @staticmethod
    def validate_upload_folder(path: Path) -> None:

        if "\x00" in str(path):
            raise BadRequest("Invalid null byte in subfolder parameter")

        if path != path.resolve():
            log.error("Invalid path: path is relative or contains double-dots")
            raise Forbidden("Invalid file path")

        if path != DATA_PATH and DATA_PATH not in path.parents:
            log.error(
                "Invalid root path: {} is expected to be a child of {}",
                path,
                DATA_PATH,
            )
            raise Forbidden("Invalid file path")

    @staticmethod
    def get_file_metadata(abs_file: Path) -> Dict[str, str]:
        try:
            # Check the type
            # Example of output:
            # text/plain; charset=us-ascii
            out = file["-ib", str(abs_file)]().split(";")
            return {"type": out[0].strip(), "charset": out[1].split("=")[1].strip()}
        except Exception:
            log.warning("Unknown type for '{}'", abs_file)
            return {}

    # this method is used by mistral
    def upload(self, subfolder: Path, force: bool = False) -> Response:

        if "file" not in request.files:
            raise BadRequest("No files specified")

        myfile = request.files["file"]

        if not myfile.filename:  # pragma: no cover
            raise BadRequest("Invalid filename")

        if not self.allowed_file(myfile.filename):
            raise BadRequest("File extension not allowed")

        Uploader.validate_upload_folder(subfolder)

        if not subfolder.exists():
            subfolder.mkdir(parents=True, exist_ok=True)

        fname = secure_filename(myfile.filename)
        abs_file = subfolder.joinpath(fname)

        log.info("File request for [{}]({})", myfile, abs_file)

        if abs_file.exists():
            if not force:
                raise Conflict(
                    f"File '{fname}' already exists, use force parameter to overwrite"
                )
            abs_file.unlink()

        # Save the file
        try:
            myfile.save(abs_file)
            log.debug("Absolute file path should be '{}'", abs_file)
        except Exception as e:  # pragma: no cover
            log.error(e)
            raise ServiceUnavailable("Permission denied: failed to write the file")

        # Check exists - but it is basicaly a test that cannot fail...
        # The has just been uploaded!
        if not abs_file.exists():  # pragma: no cover
            raise ServiceUnavailable("Unable to retrieve the uploaded file")

        ########################
        # ## Final response

        abs_file.chmod(DEFAULT_PERMISSIONS)

        # Default redirect is to 302 state, which makes client
        # think that response was unauthorized....
        # see http://dotnet.dzone.com/articles/getting-know-cross-origin

        return EndpointResource.response(
            {"filename": fname, "meta": self.get_file_metadata(abs_file)},
            code=200,
        )

    # Compatible with
    # https://developers.google.com/drive/api/v3/manage-uploads#resumable
    # and with https://www.npmjs.com/package/ngx-uploadx and with
    def init_chunk_upload(
        self, upload_dir: Path, filename: str, force: bool = True
    ) -> Response:

        if not self.allowed_file(filename):
            raise BadRequest("File extension not allowed")

        Uploader.validate_upload_folder(upload_dir)

        if not upload_dir.exists():
            upload_dir.mkdir(parents=True, exist_ok=True)

        filename = secure_filename(filename)

        file_path = upload_dir.joinpath(filename)

        if file_path.exists():
            log.warning("File already exists")
            if force:
                file_path.unlink()
                log.debug("Forced removal")
            else:
                raise Conflict(f"File '{filename}' already exists")

        file_path.touch()

        host = get_backend_url()
        url = f"{host}{request.path}/{filename}"

        log.info("Upload initialized on url: {}", url)

        return EndpointResource.response(
            "",
            headers={"Access-Control-Expose-Headers": "Location", "Location": url},
            code=201,
        )

    @staticmethod
    def parse_content_range(
        range_header: Optional[str],
    ) -> Tuple[Optional[int], Optional[int], Optional[int]]:

        if range_header is None:
            return None, None, None

        content_range = parse_content_range_header(range_header)

        if content_range is None:
            log.error("Unable to parse Content-Range: {}", range_header)
            tokens = range_header.split("/")

            if len(tokens) != 2:
                log.error("Invalid Content-Range: {}", range_header)
                return None, None, None

            if not tokens[1].isnumeric():
                log.error("Invalid Content-Range: {}", range_header)
                return None, None, None

            # A pattern like */len is expected
            # => is returned start == 0 and stop == len
            tot_len = int(tokens[1])
            return tot_len, 0, tot_len

        total_length = content_range.length
        # es: 'bytes */35738983'
        if content_range.start is None:
            start = 0
        else:
            start = content_range.start

        if content_range.stop is None:
            stop = total_length
        else:
            stop = content_range.stop

        return total_length, start, stop

    # Please note that chunk_upload as to be used from a PUT endpoint
    # PUT request is way different compared to POST request. With PUT request
    # the file contents can be accessed using either request.data or request.stream.
    # The first one stores incoming data as string, while request.stream acts
    # more like a file object, making it more suitable for binary data
    # Ref. http://stackoverflow.com/a/9533843/2114395
    def chunk_upload(
        self, upload_dir: Path, filename: str, chunk_size: Optional[int] = None
    ) -> Tuple[bool, Response]:

        Uploader.validate_upload_folder(upload_dir)

        filename = secure_filename(filename)

        range_header = request.headers.get("Content-Range", "")
        total_length, start, stop = self.parse_content_range(range_header)

        if total_length is None or start is None or stop is None:
            raise BadRequest("Invalid request")

        completed = stop >= total_length

        # Default chunk size, put this somewhere
        if chunk_size is None:
            chunk_size = 1048576

        file_path = upload_dir.joinpath(filename)

        # Uhm... this upload is not initialized?
        if not file_path.exists():
            raise ServiceUnavailable(
                "Permission denied: the destination file does not exist"
            )

        try:
            with open(file_path, "ab") as f:
                while True:
                    chunk = request.stream.read(chunk_size)
                    if not chunk:
                        break
                    f.seek(start)
                    f.write(chunk)
        except PermissionError:
            raise ServiceUnavailable("Permission denied: failed to write the file")

        if completed:
            file_path.chmod(DEFAULT_PERMISSIONS)
            return (
                completed,
                EndpointResource.response(
                    {"filename": filename, "meta": self.get_file_metadata(file_path)},
                    code=200,
                ),
            )

        return (
            completed,
            EndpointResource.response(
                "partial",
                headers={
                    "Access-Control-Expose-Headers": "Range",
                    "Range": f"0-{stop - 1}",
                },
                code=206,
            ),
        )
