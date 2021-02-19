"""
Upload data to APIs

Interesting reading:
http://flask.pocoo.org/docs/0.11/patterns/fileuploads/
https://philsturgeon.uk/api/2016/01/04/http-rest-api-file-uploads/

Note: originally developed for POST, should/could be used also for PUT
http://stackoverflow.com/a/9533843/2114395

"""

import os
from typing import List, Optional, Tuple

from flask import request
from plumbum.cmd import file
from werkzeug.http import parse_content_range_header
from werkzeug.utils import secure_filename

from restapi.config import UPLOAD_PATH, get_backend_url
from restapi.exceptions import BadRequest, ServiceUnavailable
from restapi.rest.definition import EndpointResource, Response
from restapi.utilities.logs import log


######################################
# Save files http://API/upload
class Uploader:

    allowed_exts: List[str] = []

    def set_allowed_exts(self, exts):
        self.allowed_exts = exts

    def allowed_file(self, filename):
        if not self.allowed_exts:
            return True
        return (
            "." in filename and filename.rsplit(".", 1)[1].lower() in self.allowed_exts
        )

    @staticmethod
    def absolute_upload_file(filename, subfolder=None, onlydir=False):

        filename = secure_filename(filename)

        if subfolder is not None:
            filename = os.path.join(subfolder, filename)
            subdir = os.path.join(UPLOAD_PATH, subfolder)
            if not os.path.exists(subdir):  # pragma: no cover
                os.makedirs(subdir)
        abs_file = os.path.join(UPLOAD_PATH, filename)
        if onlydir:
            return os.path.dirname(abs_file)
        return abs_file

    @staticmethod
    def get_file_metadata(abs_file):
        try:
            # Check the type
            # Example of output:
            # text/plain; charset=us-ascii
            out = file["-ib", abs_file]().split(";")
            return {"type": out[0].strip(), "charset": out[1].split("=")[1].strip()}
        except Exception:
            log.warning("Unknown type for '{}'", abs_file)
            return {}

    # this method is used by b2stage and mistral
    def upload(self, subfolder: Optional[str] = None, force: bool = False) -> Response:

        if "file" not in request.files:
            raise BadRequest("No files specified")

        myfile = request.files["file"]

        # Check file extension?
        if not self.allowed_file(myfile.filename):
            raise BadRequest("File extension not allowed")

        # Check file name
        fname = secure_filename(myfile.filename)
        abs_file = Uploader.absolute_upload_file(fname, subfolder)
        log.info("File request for [{}]({})", myfile, abs_file)

        if os.path.exists(abs_file):
            if not force:
                raise BadRequest(
                    f"File '{fname}' already exists, use force parameter to overwrite"
                )
            os.remove(abs_file)
            log.debug("Already exists, forced removal")

        # Save the file
        try:
            myfile.save(abs_file)
            log.debug("Absolute file path should be '{}'", abs_file)
        except Exception:  # pragma: no cover
            raise ServiceUnavailable("Permission denied: failed to write the file")

        # Check exists - but it is basicaly a test that cannot fail...
        # The has just been uploaded!
        if not os.path.exists(abs_file):  # pragma: no cover
            raise ServiceUnavailable("Unable to retrieve the uploaded file")

        ########################
        # ## Final response

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
        self, upload_dir: str, filename: str, force: bool = True
    ) -> Response:

        if not os.path.exists(upload_dir):  # pragma: no cover
            os.makedirs(upload_dir)

        filename = secure_filename(filename)

        file_path = os.path.join(upload_dir, filename)

        if os.path.exists(file_path):
            log.warning("File already exists")
            if force:
                os.remove(file_path)
                log.debug("Forced removal")
            else:
                return EndpointResource.response(
                    f"File '{filename}' already exists",
                    code=400,
                )

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

            total_length = int(tokens[1])
            start = 0
            stop = total_length

            return total_length, start, stop

        total_length = int(content_range.length)
        # es: 'bytes */35738983'
        if content_range.start is None:
            start = 0
        else:
            start = int(content_range.start)

        if content_range.stop is None:
            stop = total_length
        else:
            stop = int(content_range.stop)

        return total_length, start, stop

    def chunk_upload(
        self, upload_dir: str, filename: str, chunk_size: Optional[int] = None
    ) -> Tuple[bool, Response]:
        filename = secure_filename(filename)

        range_header = request.headers.get("Content-Range", "")
        total_length, start, stop = self.parse_content_range(range_header)

        if total_length is None or start is None or stop is None:
            raise BadRequest("Invalid request")

        completed = stop >= total_length

        # Default chunk size, put this somewhere
        if chunk_size is None:
            chunk_size = 1048576

        file_path = os.path.join(upload_dir, filename)
        with open(file_path, "ab") as f:
            while True:
                chunk = request.stream.read(chunk_size)
                if not chunk:
                    break
                f.seek(start)
                f.write(chunk)

        if completed:
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
                    "Range": "0-{}".format(stop - 1),
                },
                code=206,
            ),
        )
