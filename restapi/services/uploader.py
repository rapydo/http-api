# -*- coding: utf-8 -*-

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
from flask import request, send_from_directory
from werkzeug import secure_filename
from utilities import htmlcodes as hcodes
from restapi.confs import UPLOAD_FOLDER

from utilities.logs import get_logger
log = get_logger(__name__)


######################################
# Save files http://API/upload
class Uploader(object):

    allowed_exts = []
    # allowed_exts = ['png', 'jpg', 'jpeg', 'tiff']

    def split_dir_and_extension(self, filepath):
        filebase, fileext = os.path.splitext(filepath)
        return filebase, fileext.strip('.')

    def allowed_file(self, filename):
        if len(self.allowed_exts) < 1:
            return True
        return '.' in filename \
            and filename.rsplit('.', 1)[1].lower() in self.allowed_exts

    @staticmethod
    def absolute_upload_file(filename, subfolder=None, onlydir=False):
        if subfolder is not None:
            filename = os.path.join(subfolder, filename)
            dir = os.path.join(UPLOAD_FOLDER, subfolder)
            if not os.path.exists(dir):
                os.mkdir(dir)
        abs_file = os.path.join(UPLOAD_FOLDER, filename)  # filename.lower())
        if onlydir:
            return os.path.dirname(abs_file)
        return abs_file

    def download(self, filename=None, subfolder=None, get=False):

        log.warning("DEPRECATED: Use this function from the Downloader class")

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

    def ngflow_upload(self, filename, destination, content,
                      chunk_number, chunk_size, chunk_total,
                      overwrite=True
                      ):

        chunk_number = int(chunk_number)
        chunk_size = int(chunk_size)
        chunk_total = int(chunk_total)
        sec_filename = secure_filename(filename)
        abs_fname = os.path.join(destination, sec_filename)

# FIXME: what happens if chunk 2 arrives before chunk 1?
        if overwrite and chunk_number == 1:
            if os.path.exists(abs_fname):
                os.remove(abs_fname)

# FIXME: file is saved as data, not as ASCII/TEXT
        # with open(abs_fname, "wb") as f:
        with open(abs_fname, "ab") as f:
            # log.critical("Copying chunk %d" % chunk_number)
            # log.critical("Pos = %d" % ((chunk_number - 1) * chunk_size))
            # f.seek((int(chunk_number) - 1) * int(chunk_size), 0)
            content.save(f)
            f.close()

        return abs_fname, sec_filename

    def upload_data(self, filename, subfolder=None, force=False):

        filename = secure_filename(filename)

        # Check file extension?
        if not self.allowed_file(filename):
            return self.force_response(errors=[
                "Wrong extension, file extension not allowed"])

        content = request.data

        abs_file = self.absolute_upload_file(filename, subfolder)
        log.info("File request for %s", abs_file)

        if os.path.exists(abs_file):

            log.warn("Already exists")
            if force:
                os.remove(abs_file)
                log.debug("Forced removal")
            else:
                return self.force_response(
                    errors=[
                        "File '" + filename + "' already exists",
                    ], code=hcodes.HTTP_BAD_REQUEST)

        with open(abs_file, "ab") as f:
            f.write(content)
            f.close()

        # Check exists
        if not os.path.exists(abs_file):
            return self.force_response(errors=[
                "Server error: unable to recover the uploaded file"],
                code=hcodes.HTTP_DEFAULT_SERVICE_FAIL)

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
            log.warning("Unknown type for '%s'", abs_file)

        ########################
        # ## Final response

        # Default redirect is to 302 state, which makes client
        # think that response was unauthorized....
        # see http://dotnet.dzone.com/articles/getting-know-cross-origin

        return self.force_response({
            'filename': filename,
            'meta': {'type': ftype, 'charset': fcharset}
        }, code=hcodes.HTTP_OK_BASIC)

    def upload(self, subfolder=None, force=False):

        if 'file' not in request.files:

            # # the PUT problem for uploading?
            # tmp = request.stream.read()
            # print("TEST", len(tmp))
            # with open('uploaded_image.jpg', 'w') as f:
            #     f.write(request.stream.read())
            # # print("TEST", request.data)

            return self.force_response(errors={
                "Missing file": "No files specified"},
                code=hcodes.HTTP_BAD_METHOD_NOT_ALLOWED)

        myfile = request.files['file']

        # Check file extension?
        if not self.allowed_file(myfile.filename):
            return self.force_response(errors={
                "Wrong extension": "File extension not allowed"})

        # Check file name
        filename = secure_filename(myfile.filename)
        abs_file = self.absolute_upload_file(filename, subfolder)
        log.info("File request for [%s](%s)", myfile, abs_file)

        # ## IMPORTANT NOTE TO SELF:
        # If you are going to receive chunks here there could be problems.
        # In fact a chunk will truncate the connection
        # and make a second request.
        # You will end up with having already the file
        # But corrupted...
        if os.path.exists(abs_file):

            log.warn("Already exists")
            if force:
                os.remove(abs_file)
                log.debug("Forced removal")
            else:
                return self.force_response(
                    errors={
                        "File '" + filename + "' already exists.":
                        "Change file name or use the force parameter",
                    }, code=hcodes.HTTP_BAD_REQUEST)

        # Save the file
        try:
            myfile.save(abs_file)
            log.debug("Absolute file path should be '%s'", abs_file)
        except Exception:
            return self.force_response(errors={
                "Permissions": "Failed to write uploaded file"},
                code=hcodes.HTTP_DEFAULT_SERVICE_FAIL)

        # Check exists
        if not os.path.exists(abs_file):
            return self.force_response(errors={
                "Server file system": "Unable to recover the uploaded file"},
                code=hcodes.HTTP_DEFAULT_SERVICE_FAIL)

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
            log.warning("Unknown type for '%s'", abs_file)

        ########################
        # ## Final response

        # Default redirect is to 302 state, which makes client
        # think that response was unauthorized....
        # see http://dotnet.dzone.com/articles/getting-know-cross-origin

        return self.force_response({
            'filename': filename,
            'meta': {'type': ftype, 'charset': fcharset}
        }, code=hcodes.HTTP_OK_BASIC)

    def upload_chunked(self, destination, force=False, chunk_size=None):

        # Default chunk size, put this somewhere
        if chunk_size is None:
            chunk_size = 1048576

        if os.path.exists(destination):

            log.warn("Already exists")
            if force:
                os.remove(destination)
                log.debug("Forced removal")
            else:
                log.error("File '%s' already exists", destination)
                return False

        with open(destination, "ab") as f:
            while True:
                chunk = request.stream.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)

        # Check exists
        if not os.path.exists(destination):
            log.error("Unable to recover the uploaded file: %s", destination)
            return False

        log.info("File uploaded: %s", destination)
        return True

    def remove(self, filename, subfolder=None, skip_response=False):
        """ Remove the file if requested """

        abs_file = self.absolute_upload_file(filename, subfolder)

        # Check file existence
        if not os.path.exists(abs_file):
            log.critical("File '%s' not found", abs_file)
            return self.force_response(errors={
                "File missing": "File requested does not exists"},
                code=hcodes.HTTP_BAD_NOTFOUND)

        # Remove the real file
        try:
            os.remove(abs_file)
        except Exception:
            log.critical("Cannot remove local file %s", abs_file)
            return self.force_response(errors={
                "Permissions": "Failed to remove file"},
                code=hcodes.HTTP_DEFAULT_SERVICE_FAIL)
        log.warn("Removed '%s'", abs_file)

        if skip_response:
            return

        return self.force_response("Deleted", code=hcodes.HTTP_OK_BASIC)
