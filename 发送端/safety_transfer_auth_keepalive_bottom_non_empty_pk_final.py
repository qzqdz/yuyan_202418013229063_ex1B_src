__version__ = "1.0.0"

import os
import time
import sys
import socket
import posixpath
import platform
import threading
try:
    from html import escape
except ImportError:
    from cgi import escape
import shutil
import mimetypes
import re
import signal
from io import BytesIO
import codecs
import ssl
import urllib.parse
from collections import defaultdict
from http.cookies import SimpleCookie
import random
import zipfile


from urllib.parse import quote
from urllib.parse import unquote
from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn




# DOCUMENT_ROOT = os.getcwd()
DOCUMENT_ROOT = os.path.join(os.getcwd(), 'file_path')
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB
request_counts = defaultdict(list)
sessions = {}  # Store user sessions

# User bandwidth limits (bytes per second)
USER_BANDWIDTH_LIMITS = {
    # 'VIP': 1024 * 1024 * 1024 * 1024,       # 1 MB/s
    'VIP': 1024 * 1024,       # 1 MB/s
    'Regular': 256 * 1024,    # 256 KB/s
}

def is_safe_path(basedir, path, follow_symlinks=True):
    # Resolves symbolic links
    if follow_symlinks:
        return os.path.realpath(path).startswith(basedir)
    else:
        return os.path.abspath(path).startswith(basedir)

def sanitize_filename(filename):
    # Remove path separators and dangerous characters
    return os.path.basename(filename)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class MyHTTPRequestHandler(BaseHTTPRequestHandler):

    server_version = "simple_http_server/" + __version__

    mylist = []
    myspace = ""
    treefile = "dirtree.txt"
    IPAddress = socket.gethostbyname(socket.gethostname())

    request_counts = defaultdict(list)

    protocol_version = "HTTP/1.1"  # Use HTTP/1.1 protocol

    def buildTree(self, url):
        print("directories url:", url)
        files = os.listdir(r'' + url)
        for file in files:
            if not file.startswith('.'):
                myfile = url + "/" + file
                size_str = bytes_conversion(myfile)
                if os.path.isfile(myfile):
                    self.mylist.append(
                        str(self.myspace) + "|____" + file + " " + size_str + "\n")
                elif os.path.isdir(myfile):
                    self.mylist.append(
                        str(self.myspace) + "|____" + file + "\n")
                    # Enter the sub-directory, add "|    "
                    self.myspace = self.myspace + "|    "
                    self.buildTree(myfile)
                    # When sub-directory traversal is finished, reduce "|    "
                    self.myspace = self.myspace[:-5]

    def getAllFilesList(self):
        listofme = []
        for root, dirs, files in os.walk(translate_path(self.path)):
            files.sort()
            for fi in files:
                display_name = os.path.join(root, fi)
                relative_path = display_name[len(
                    os.getcwd()):].replace('\\', '/')[1:]
                if not relative_path.startswith('.'):
                    st = os.stat(display_name)
                    fsize = bytes_conversion(display_name)
                    fmtime = time.strftime(
                        '%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))
                    listofme.append(relative_path + "\t")
                    listofme.append(fsize + "\t")
                    listofme.append(str(fmtime) + "\t\n")
        return listofme

    def calculate_dir_size(self, pathvar):
        '''
        Calculate directory size (bytes)
        '''
        size = 0
        lst = os.listdir(pathvar)
        for i in lst:
            pathnew = os.path.join(pathvar, i)
            if os.path.isfile(pathnew):
                size += os.path.getsize(pathnew)
            elif os.path.isdir(pathnew):
                size += self.calculate_dir_size(pathnew)
        return size

    def writeList(self, url):
        tree_ = self.getAllFilesList()
        f = open(url, 'w', encoding="utf-8")
        f.write("http://" + str(self.IPAddress) +
                ":8000/ \ndirectory tree\n")
        f.writelines(self.mylist)
        f.write("\nFile Path\tFile Size\tFile Modify Time\n")
        f.writelines(tree_)
        self.mylist = []
        self.myspace = ""
        print("writing completed.")
        f.close()

    def rate_limit(self):
        ip = self.client_address[0]
        now = time.time()
        window = 60  # seconds
        max_requests = 60  # max requests per window per IP
        timestamps = self.request_counts[ip]
        timestamps = [t for t in timestamps if now - t < window]
        timestamps.append(now)
        self.request_counts[ip] = timestamps
        if len(timestamps) > max_requests:
            return False
        else:
            return True

    def is_authenticated(self):
        client_cert = self.connection.getpeercert()
        if client_cert:
            # Implement your certificate validation logic here
            return True
        else:
            return False

    def get_user_role(self):
        # Determine user role based on client certificate or other criteria
        # For simplicity, we assume all authenticated users are 'VIP'
        if self.is_authenticated():
            return 'VIP'
        else:
            return 'Regular'

    def handle_one_request(self):
        # Override this method to support persistent connections
        try:
            self.raw_requestline = self.rfile.readline()
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                # Parsing failed, skip processing
                return

            # Print request method and path to verify processing
            print(f"Handling {self.command} request for {self.path} on persistent connection.")

            # Execute the command, keep connection
            self.do_command()

            # Check if the connection should be closed
            if 'close' in self.headers.get('Connection', '').lower() or self.close_connection:
                self.close_connection = True
                print("Closing connection as requested.")
            else:
                self.close_connection = False
                print("Keeping connection alive for next request.")
        except socket.timeout as e:
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
            return

    def do_command(self):
        # Call the appropriate method based on the request command
        if self.command == 'GET':
            self.do_GET()
        elif self.command == 'HEAD':
            self.do_HEAD()
        elif self.command == 'POST':
            self.do_POST()
        else:
            self.send_error(501, "Unsupported method (%r)" % self.command)

    def do_GET(self):
        """Serve a GET request."""
        if self.path.startswith('/close'):
            # Handle close connection request
            self.handle_close_connection()
            return
        if not self.is_authenticated():
            # Send 403 Forbidden
            self.send_error(403, "Forbidden")
            return
        if not self.rate_limit():
            self.send_error(429, "Too Many Requests")
            return
        paths = unquote(self.path)
        path = str(paths)
        fd = self.send_head()
        if fd:
            if path == "/":
                self.mylist = []
                self.buildTree(translate_path(self.path))
                self.writeList(self.treefile)
            if hasattr(fd, 'seek') and hasattr(fd, 'tell'):
                # Handle range requests for resumable downloads
                self.copyfile_range(fd, self.wfile)
            else:
                shutil.copyfileobj(fd, self.wfile)
            fd.close()

    def do_HEAD(self):
        """Serve a HEAD request."""
        if not self.is_authenticated():
            # Send 403 Forbidden
            self.send_error(403, "Forbidden")
            return
        if not self.rate_limit():
            self.send_error(429, "Too Many Requests")
            return
        fd = self.send_head()
        if fd:
            fd.close()

    def do_POST(self):
        """Serve a POST request."""
        if not self.is_authenticated():
            # Send 403 Forbidden
            self.send_error(403, "Forbidden")
            return
        if not self.rate_limit():
            self.send_error(429, "Too Many Requests")
            return
        if self.path == '/delete':
            content_length = int(self.headers['Content-Length'])
            if content_length > MAX_UPLOAD_SIZE:
                self.send_error(413, "Uploaded data too large.")
                return
            post_data = self.rfile.read(content_length)
            fields = urllib.parse.parse_qs(post_data.decode('utf-8'))
            path_to_delete = fields.get('path', [None])[0]
            if path_to_delete:
                full_path = os.path.realpath(path_to_delete)
                if is_safe_path(DOCUMENT_ROOT, full_path):
                    if os.path.exists(full_path):
                        if os.path.isdir(full_path):
                            shutil.rmtree(full_path)
                        else:
                            os.remove(full_path)
                        self.send_response(302)
                        self.send_header('Location', '/')
                        self.send_header('Connection', 'keep-alive')
                        self.end_headers()
                    else:
                        self.send_error(404, "File not found")
                else:
                    self.send_error(403, "Forbidden")
            else:
                self.send_error(400, "Bad request")
            return
        if self.path == '/download_multiple':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            fields = urllib.parse.parse_qs(post_data.decode('utf-8'))
            file_list = fields.get('files', [])
            self.handle_multiple_download(file_list)
            return

        content_length = int(self.headers['Content-Length'])
        if content_length > MAX_UPLOAD_SIZE:
            self.send_error(413, "Uploaded file too large.")
            return

        r, info = self.deal_post_data()

        f = BytesIO()
        f.write(b'<!DOCTYPE html>')
        f.write(b'<html lang="en">')
        f.write(b'<head>')
        f.write(b'<meta charset="utf-8">')
        f.write(b'<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">')
        f.write(b'<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">')
        f.write(b"<title>Upload Result Page</title>\n")
        f.write(b'</head>')
        f.write(b"<body>\n<div class='container'>\n<h2>Upload Result Page</h2>\n")
        f.write(b"<hr>\n")
        if r:
            f.write(b"<div class='alert alert-success' role='alert'>")
            f.write(b"<strong>Success:</strong><br>")
        else:
            f.write(b"<div class='alert alert-danger' role='alert'>")
            f.write(b"<strong>Failed:</strong><br>")

        for i in info:
            print(r, i, "by: ", self.client_address)
            f.write(i.encode('utf-8') + b"<br>")
        f.write(b"</div>")
        f.write(b"<br><a href=\"%s\">back</a>" %
                self.headers['referer'].encode('ascii'))
        f.write(b"</div>\n</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html;charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.send_header('Connection', 'keep-alive')  # Keep connection
        self.end_headers()
        if f:
            shutil.copyfileobj(f, self.wfile)
            f.close()
        self.mylist = []
        # Update directory tree file after each POST request
        self.buildTree(translate_path(self.path))
        self.writeList(MyHTTPRequestHandler.treefile)

    def handle_close_connection(self):
        # Send a response indicating the connection will be closed
        f = BytesIO()
        f.write(b'<!DOCTYPE html>')
        f.write(b'<html lang="en">')
        f.write(b'<head>')
        f.write(b'<meta charset="utf-8">')
        f.write(b'<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">')
        f.write(b'<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">')
        f.write(b"<title>Connection Closed</title>\n")
        f.write(b'</head>')
        f.write(b"<body>\n<div class='container'>\n<h2>Connection Closed</h2>\n")
        f.write(b"<p>The connection has been closed.</p>\n")
        f.write(b"</div>\n</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html;charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.send_header('Connection', 'close')  # Indicate connection will close
        self.end_headers()
        self.wfile.write(f.read())
        f.close()
        # Set the close_connection flag
        self.close_connection = True
        print("Connection closed by client request.")

    def str_to_chinese(self, var):
        # This method handles encoding issues for file names
        not_end = True
        while not_end:
            start1 = var.find("\\x")
            if start1 > -1:
                str1 = var[start1 + 2:start1 + 4]
                start2 = var[start1 + 4:].find("\\x") + start1 + 4
                if start2 > -1:
                    str2 = var[start2 + 2:start2 + 4]
                    start3 = var[start2 + 4:].find("\\x") + start2 + 4
                    if start3 > -1:
                        str3 = var[start3 + 2:start3 + 4]
            else:
                not_end = False
            if start1 > -1 and start2 > -1 and start3 > -1:
                str_all = str1 + str2 + str3
                str_all = codecs.decode(str_all, "hex").decode('utf-8')
                str_re = var[start1:start3 + 4]
                var = var.replace(str_re, str_all)
        return var

    def deal_post_data(self):
        boundary = self.headers["Content-Type"].split("=")[1].encode('ascii')
        remain_bytes = int(self.headers['content-length'])
        if remain_bytes > MAX_UPLOAD_SIZE:
            return False, ["Uploaded file too large."]
        res = []
        line = self.rfile.readline()
        remain_bytes -= len(line)
        if boundary not in line:
            return False, ["Content NOT begin with boundary"]
        while remain_bytes > 0:
            line = self.rfile.readline()
            remain_bytes -= len(line)
            if line.strip() == b'':
                continue
            if boundary in line:
                continue
            fn = re.findall(
                r'Content-Disposition.*name="file"; filename="(.*)"', str(line))
            if not fn:
                return False, ["Can't find out file name..."]
            path = translate_path(self.path)
            fname = fn[0]
            fname = self.str_to_chinese(fname)
            fname = sanitize_filename(fname)
            fn = os.path.join(path, fname)
            fn = os.path.realpath(fn)
            if not is_safe_path(DOCUMENT_ROOT, fn):
                return False, ["Unsafe file path."]
            while os.path.exists(fn):
                fn += "_"
            dirname = os.path.dirname(fn)
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            # Skip headers
            while True:
                line = self.rfile.readline()
                remain_bytes -= len(line)
                if line.strip() == b'':
                    break
            try:
                out = open(fn, 'wb')
            except IOError:
                return False, ["Can't create file to write, do you have permission to write?"]
            pre_line = self.rfile.readline()
            remain_bytes -= len(pre_line)
            Flag = True
            file_size = 0  # For calculating file size
            while remain_bytes > 0:
                line = self.rfile.readline()
                remain_bytes -= len(line)
                if boundary in line:
                    pre_line = pre_line[0:-1]
                    if pre_line.endswith(b'\r'):
                        pre_line = pre_line[0:-1]
                    out.write(pre_line)
                    file_size += len(pre_line)
                    out.close()
                    if file_size == 0:
                        os.remove(fn)
                        res.append("Failed: Cannot upload empty file '%s'." % fn)
                        Flag = False
                        break
                    res.append("File '%s' upload success!" % fn)
                    Flag = False
                    break
                else:
                    out.write(pre_line)
                    file_size += len(pre_line)
                    pre_line = line
            if pre_line is not None and Flag == True:
                out.write(pre_line)
                file_size += len(pre_line)
                out.close()
                if file_size == 0:
                    os.remove(fn)
                    res.append("Failed: Cannot upload empty file '%s'." % fn)
                else:
                    res.append("File '%s' upload success!" % fn)
            # Check if there's another file
            if remain_bytes > 0 and boundary in line:
                continue
            else:
                break
        return True, res

    def handle_multiple_download(self, file_list):
        # Validate and sanitize file_list
        sanitized_file_list = []
        for file_name in file_list:
            file_name = sanitize_filename(file_name)
            file_path = os.path.join(DOCUMENT_ROOT, file_name)
            file_path = os.path.realpath(file_path)
            if is_safe_path(DOCUMENT_ROOT, file_path) and os.path.isfile(file_path):
                sanitized_file_list.append((file_name, file_path))

        if not sanitized_file_list:
            self.send_error(400, "No valid files selected.")
            return

        # Create a ZIP archive in memory
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            for file_name, file_path in sanitized_file_list:
                zip_file.write(file_path, arcname=file_name)
        zip_buffer.seek(0)

        # Send the ZIP file to the client
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", "attachment; filename=\"files.zip\"")
        self.send_header("Content-Length", str(len(zip_buffer.getvalue())))
        self.end_headers()
        shutil.copyfileobj(zip_buffer, self.wfile)
        zip_buffer.close()

    def send_head(self):
        """Handle request headers and return a file object."""
        path = translate_path(self.path)
        if not is_safe_path(DOCUMENT_ROOT, path):
            self.send_error(403, "Forbidden")
            return None
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                # Redirect browser
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.send_header('Connection', 'keep-alive')  # Keep connection
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        content_type = self.guess_type(path)
        try:            # Always read in binary mode
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        fs = os.fstat(f.fileno())
        size = fs[6]
        start = 0         # Handle range requests for resumable downloads
        end = size - 1
        length = size
        range_header = self.headers.get('Range', None)
        if range_header:
            match = re.match(r'bytes=(\d+)-(\d*)', range_header)
            if match:
                start = int(match.group(1))
                if match.group(2):
                    end = int(match.group(2))
                length = end - start + 1
                f.seek(start)
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            else:
                self.send_response(200)
        else:
            self.send_response(200)
        self.send_header("Content-type", content_type + ";charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header('Connection', 'keep-alive')  # Keep connection
        self.end_headers()
        return f

    def copyfile_range(self, source, outputfile):
        # Bandwidth throttling
        user_role = self.get_user_role()
        bandwidth_limit = USER_BANDWIDTH_LIMITS.get(user_role, USER_BANDWIDTH_LIMITS['Regular'])
        # bandwidth_limit = USER_BANDWIDTH_LIMITS.get(user_role, USER_BANDWIDTH_LIMITS['VIP'])
        # Read and write the file in chunks
        chunk_size = 64 * 1024  # 64KB
        start_time = time.time()
        bytes_sent = 0
        while True:
            data = source.read(chunk_size)
            if not data:
                break
            outputfile.write(data)
            bytes_sent += len(data)
            elapsed_time = time.time() - start_time
            expected_time = bytes_sent / bandwidth_limit
            if expected_time > elapsed_time:
                time.sleep(expected_time - elapsed_time)

    def list_directory(self, path):
        """Generate a directory listing."""
        if not is_safe_path(DOCUMENT_ROOT, path):
            self.send_error(403, "Forbidden")
            return None
        try:
            list_dir = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list_dir.sort(key=lambda a: a.lower())
        f = BytesIO()
        display_path = escape(unquote(self.path))
        f.write(b'<!DOCTYPE html>')
        f.write(b'<html lang="en">')
        f.write(b'<head>')
        f.write(b'<meta charset="utf-8">')
        f.write(b'<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">')
        f.write(b'<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">')
        f.write(b'<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css" crossorigin="anonymous">')
        f.write(b'<title>Directory listing for %s</title>\n' % display_path.encode('utf-8'))
        f.write(b'<script>')
        # Add client-side validation script to prevent uploading empty files
        f.write(b'''
            function validateUpload() {
                var files = document.getElementById('fileInput').files;
                if (files.length === 0) {
                    alert('Please select a file to upload.');
                    return false;
                }
                for (var i = 0; i < files.length; i++) {
                    if (files[i].size === 0) {
                        alert('Cannot upload empty file: ' + files[i].name);
                        return false;
                    }
                }
                return true;
            }
            function selectAllFiles(source) {
                checkboxes = document.getElementsByName('files');
                for(var i in checkboxes)
                    checkboxes[i].checked = source.checked;
            }
        ''')
        f.write(b'</script>')
        f.write(b'</head>')
        f.write(b'<body>')
        f.write(b'<nav class="navbar navbar-expand-lg navbar-light bg-light">')
        f.write(b'<a class="navbar-brand" href="#">File Transfer Helper</a>')
        f.write(b'<div class="collapse navbar-collapse" id="navbarSupportedContent">')
        f.write(b'<ul class="navbar-nav ml-auto">')
        f.write(b'<li class="nav-item">')
        f.write(b'<a class="nav-link" href="/close">Close Connection</a>')
        f.write(b'</li>')
        f.write(b'</ul>')
        f.write(b'</div>')
        f.write(b'</nav>')
        f.write(b'<div class="container">')
        f.write(b'<h2 class="mt-4">Directory listing %s</h2>\n' % display_path.encode('utf-8'))
        f.write(b'<hr>\n')

        # Upload files
        f.write(b'<div class="row">')
        f.write(b'<div class="col-md-6">')
        f.write(b'<h3>Upload Files</h3>')
        f.write(b'<form ENCTYPE="multipart/form-data" method="post" onsubmit="return validateUpload();">')
        f.write(b'<div class="form-group">')
        f.write(b'<input class="form-control-file" id="fileInput" multiple name="file" type="file"/>')
        f.write(b'</div>')
        f.write(b'<button type="submit" class="btn btn-primary">Upload Files</button>')
        f.write(b'</form>')
        f.write(b'</div>')
        f.write(b'</div>')

        f.write(b'<hr>\n')

        # Download multiple files
        f.write(b'<form method="POST" action="/download_multiple">')
        f.write(b'<table class="table table-striped mt-4">')
        f.write(b'<thead><tr>')
        f.write(b'<th><input type="checkbox" onclick="selectAllFiles(this)"></th>')
        f.write(b'<th>Name</th>')
        f.write(b'<th>Type</th>')
        f.write(b'<th>Size</th>')
        f.write(b'<th>Modified</th>')
        f.write(b'<th>Actions</th>')
        f.write(b'</tr></thead>')
        f.write(b'<tbody>')

        # List directory contents
        for name in list_dir:
            fullname = os.path.join(path, name)
            display_name = linkname = name
            if not display_name.startswith('.'):
                if display_name == "HTTP_SERVER.py" or display_name == "_config.yml":
                    continue
                relative_path = fullname[len(DOCUMENT_ROOT):].replace('\\', '/')
                st = os.stat(fullname)
                if os.path.isdir(fullname):
                    fsize = bytes_conversion(
                        "", self.calculate_dir_size(fullname))
                    fmtime = time.strftime(
                        '%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))
                    f.write(b'<tr>')
                    f.write(b'<td></td>')
                    f.write(b'<td><a href="%s"><i class="fas fa-folder"></i> %s</a></td>' % (
                        quote(relative_path).encode('utf-8'), escape(display_name).encode('utf-8')))
                    f.write(b'<td>Directory</td>')
                    f.write(b'<td>%s</td>' %
                            escape(fsize).encode('utf-8'))
                    f.write(b'<td>%s</td>' %
                            escape(fmtime).encode('utf-8'))
                    f.write(b'<td>')
                    f.write(b'<form method="POST" action="/delete" style="display:inline">')
                    f.write(b'<input type="hidden" name="path" value="%s">' % escape(fullname).encode('utf-8'))
                    f.write(b'<button type="submit" class="btn btn-danger btn-sm" onclick="return confirm(\'Are you sure you want to delete this directory?\')">Delete</button>')
                    f.write(b'</form>')
                    f.write(b'</td>')
                    f.write(b'</tr>')
                else:
                    fsize = bytes_conversion(fullname)
                    fmtime = time.strftime(
                        '%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))
                    f.write(b'<tr>')
                    f.write(b'<td><input type="checkbox" name="files" value="%s"></td>' % escape(name).encode('utf-8'))
                    f.write(b'<td><a href="%s"><i class="fas fa-file"></i> %s</a></td>' %
                            (quote(relative_path).encode('utf-8'), escape(display_name).encode('utf-8')))
                    f.write(b'<td>File</td>')
                    f.write(b'<td>%s</td>' % escape(fsize).encode('utf-8'))
                    f.write(b'<td>%s</td>' % escape(fmtime).encode('utf-8'))
                    f.write(b'<td>')
                    f.write(b'<form method="POST" action="/delete" style="display:inline">')
                    f.write(b'<input type="hidden" name="path" value="%s">' % escape(fullname).encode('utf-8'))
                    f.write(b'<button type="submit" class="btn btn-danger btn-sm" onclick="return confirm(\'Are you sure you want to delete this file?\')">Delete</button>')
                    f.write(b'</form>')
                    f.write(b'</td>')
                    f.write(b'</tr>')

        f.write(b'</tbody></table>')
        f.write(b'<button type="submit" class="btn btn-success">Download Selected Files</button>')
        f.write(b'</form>')
        f.write(b'</div>')  # Close container
        f.write(b'</body></html>')
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html;charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.send_header('Connection', 'keep-alive')  # Keep connection
        self.end_headers()
        return f

    def guess_type(self, path):
        """Guess the type of a file."""
        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init()  # Try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream',  # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
        '.txt': 'text/plain',
    })

def isWindows():
    '''
    Determine the current operating platform
    '''
    sysstr = platform.system()
    if (sysstr == "Windows"):
        return True
    elif (sysstr == "Linux"):
        return False
    else:
        print("Other System ")
    return False

def translate_path(path):
    """Translate a /-separated PATH to the local file system syntax."""
    path = path.split('?', 1)[0]
    path = path.split('#', 1)[0]
    path = posixpath.normpath(unquote(path))
    words = path.split('/')
    words = filter(None, words)
    path = DOCUMENT_ROOT
    for word in words:
        drive, word = os.path.splitdrive(word)
        head, word = os.path.split(word)
        if word in (os.curdir, os.pardir):
            continue
        path = os.path.join(path, word)
    return path

def bytes_conversion(file_path, total_size=-1):
    """
    Calculate file size and dynamically convert it to K, M, G, etc.
    :param file_path:
    :param total_size: the size of a directory
    :return: formatted file size
    """
    number = 0
    if total_size == -1:
        number = os.path.getsize(file_path)
    else:
        number = total_size
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = dict()
    for a, s in enumerate(symbols):
        prefix[s] = 1 << (a + 1) * 10
    for s in reversed(symbols):
        if int(number) >= prefix[s]:
            value = float(number) / prefix[s]
            return '%.2f%s' % (value, s)
    return "%sB" % number

def signal_handler(signal, frame):
    print("You choose to stop me.")
    exit()

def main():
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 1234
    server_address = ('', port)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    httpd = ThreadingHTTPServer(server_address, MyHTTPRequestHandler)
    httpd.allow_reuse_address = True  # Allow address reuse
    server = httpd.socket.getsockname()
    print("server_version: " + MyHTTPRequestHandler.server_version +
          ", python_version: " + MyHTTPRequestHandler.sys_version)
    print("Serving HTTPS on: " +
          str(server[0]) + ", port: " + str(server[1]) + " ...")
    # SSL configuration for mutual TLS authentication
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    # context.load_verify_locations(cafile='client.crt')
    context.load_verify_locations(cafile='server.crt')
    context.verify_mode = ssl.CERT_REQUIRED
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()

if __name__ == '__main__':
    main()
