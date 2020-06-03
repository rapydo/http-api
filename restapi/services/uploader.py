"""
Upload data to APIs.

Interesting reading:
http://flask.pocoo.org/docs/0.11/patterns/fileuploads/
https://philsturgeon.uk/api/2016/01/04/http-rest-api-file-uploads/

Note: originally developed for POST, should/could be used also for PUT
http://stackoverflow.com/a/9533843/2114395

"""

import os

# import shutil
from flask import request  # , send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.http import parse_content_range_header
from restapi.confs import UPLOAD_PATH, PRODUCTION
from restapi.env import Env
from restapi.exceptions import RestApiException, ServiceUnavailable
from restapi.utilities.logs import log


######################################
# Save files http://API/upload
class Uploader:

    allowed_exts = []
    # allowed_exts = ['png', 'jpg', 'jpeg', 'tiff']

    @staticmethod
    def split_dir_and_extension(filepath):
        filebase, fileext = os.path.splitext(filepath)
        return filebase, fileext.strip('.')

    def allowed_file(self, filename):
        if len(self.allowed_exts) < 1:
            return True
        return (
            '.' in filename and filename.rsplit('.', 1)[1].lower() in self.allowed_exts
        )

    @staticmethod
    def absolute_upload_file(filename, subfolder=None, onlydir=False):
        if subfolder is not None:
            filename = os.path.join(subfolder, filename)
            subdir = os.path.join(UPLOAD_PATH, subfolder)
            if not os.path.exists(subdir):
                os.makedirs(subdir)
        abs_file = os.path.join(UPLOAD_PATH, filename)  # filename.lower())
        if onlydir:
            return os.path.dirname(abs_file)
        return abs_file

    # this method is used by b2stage and mistral
    def upload(self, subfolder=None, force=False):

        if 'file' not in request.files:

            raise RestApiException(
                "No files specified",
                status_code=400,
            )

        myfile = request.files['file']

        # Check file extension?
        if not self.allowed_file(myfile.filename):
            raise RestApiException("File extension not allowed")

        # Check file name
        fname = secure_filename(myfile.filename)
        abs_file = Uploader.absolute_upload_file(fname, subfolder)
        log.info("File request for [{}]({})", myfile, abs_file)

        # ## IMPORTANT NOTE TO SELF:
        # If you are going to receive chunks here there could be problems.
        # In fact a chunk will truncate the connection
        # and make a second request.
        # You will end up with having already the file
        # But corrupted...
        if os.path.exists(abs_file):

            log.warning("Already exists")
            if force:
                os.remove(abs_file)
                log.debug("Forced removal")
            else:
                e = f"File '{fname}' already exists, use force parameter to overwrite"
                raise RestApiException(e, status_code=400)

        # Save the file
        try:
            myfile.save(abs_file)
            log.debug("Absolute file path should be '{}'", abs_file)
        except Exception:
            raise ServiceUnavailable("Permission denied: failed to write the file")

        # Check exists
        if not os.path.exists(abs_file):
            raise ServiceUnavailable("Unable to retrieve the uploaded file")

        # Extra info
        ftype = None
        fcharset = None
        try:
            # Check the type
            from plumbum.cmd import file

            out = file["-ib", abs_file]()
            tmp = out.split(';')
            ftype = tmp[0].strip()
            fcharset = tmp[1].split('=')[1].strip()
        except Exception:
            log.warning("Unknown type for '{}'", abs_file)

        ########################
        # ## Final response

        # Default redirect is to 302 state, which makes client
        # think that response was unauthorized....
        # see http://dotnet.dzone.com/articles/getting-know-cross-origin

        return self.response(
            {'filename': fname, 'meta': {'type': ftype, 'charset': fcharset}},
            code=200,
        )

    # Compatible with
    # https://developers.google.com/drive/api/v3/manage-uploads#resumable
    # and with https://www.npmjs.com/package/ngx-uploadx and with
    def init_chunk_upload(self, upload_dir, filename, force=True):

        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)

        filename = secure_filename(filename)

        file_path = os.path.join(upload_dir, filename)

        if os.path.exists(file_path):
            log.warning("File already exists")
            if force:
                os.remove(file_path)
                log.debug("Forced removal")
            else:
                return self.response(
                    f"File '{filename}' already exists",
                    code=400,
                )

        domain = Env.get('DOMAIN')
        if PRODUCTION:
            host = f"https://{domain}"
        else:
            host = f"http://{domain}:8080"
        url = f"{host}{request.path}/{filename}"

        log.info("Upload initialized on url: {}", url)

        return self.response(
            "",
            headers={
                "Access-Control-Expose-Headers": "Location",
                "Location": url
            },
            code=201
        )

    @staticmethod
    def parse_content_range(range_header):

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

        # log.critical(content_range.units)
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

    def chunk_upload(self, upload_dir, filename, chunk_size=None):
        filename = secure_filename(filename)

        try:
            range_header = request.headers.get("Content-Range")

            total_length, start, stop = self.parse_content_range(range_header)

            if total_length is None:
                return False, self.response("Invalid request", code=400)

            completed = (stop >= total_length)

        except BaseException as e:
            log.error("Unable to parse Content-Range: {}", range_header)
            log.error(str(e))
            completed = False
            return completed, self.response("Invalid request", code=400)

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

            # Extra info
            ftype = None
            fcharset = None
            try:
                # Check the type
                from plumbum.cmd import file

                out = file["-ib", file_path]()
                tmp = out.split(';')
                ftype = tmp[0].strip()
                fcharset = tmp[1].split('=')[1].strip()
            except Exception:
                log.warning("Unknown type for '{}'", file_path)

            return completed, self.response(
                {
                    'filename': filename,
                    'meta': {'type': ftype, 'charset': fcharset}
                }, code=200)

        return completed, self.response(
            "partial",
            headers={
                "Access-Control-Expose-Headers": "Range",
                f"Range": "0-{stop - 1}"
            },
            code=206
        )
