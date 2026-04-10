FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/mushorg/snare.git /snare

WORKDIR /snare

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir .

RUN mkdir -p /var/log/snare /snare/pages/example.com /opt/snare

RUN echo '<!DOCTYPE html><html><head><title>404</title></head><body><h1>404 Not Found</h1></body></html>' \
    > /snare/pages/example.com/status_404

RUN echo '<!DOCTYPE html>\
<html><head><title>Login</title></head>\
<body>\
<h2>System Login</h2>\
<form action="/login" method="post">\
  <label>Username: <input type="text" name="username"/></label><br/>\
  <label>Password: <input type="password" name="password"/></label><br/>\
  <input type="submit" value="Login"/>\
</form>\
<a href="/admin">Admin Panel</a> |\
<a href="/?id=1">Products</a> |\
<a href="/search?q=test">Search</a>\
</body></html>' > /snare/pages/example.com/index.html

EXPOSE 8080

CMD ["snare", \
     "--port", "8080", \
     "--host-ip", "0.0.0.0", \
     "--page-dir", "/snare/pages/example.com", \
     "--tanner", "tanner"]
