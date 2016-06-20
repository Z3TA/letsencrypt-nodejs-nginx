# Mange letsencrypt certificates for Nginx


## Setup

Get the script: 
```git clone git@github.com:Z3TA/letsencrypt-nodejs-nginx.git```

Install dependencies:
```npm install```

Update your domain's nginx config file:

```
# Lets encrypt challange
location /.well-known/acme-challenge/ {
  proxy_pass http://127.0.0.1:8094;
  proxy_set_header Host $http_host;
  proxy_set_header        X-Real-IP       $remote_addr;
}
```
Change the port to whatever you want.

The script assumes your Nginx domain config files are located in /etc/nginx/sites-enabled/


Edit the file letsencrypt.js:

* If you changed the port nr, update it
* Replace e-mail address with your own
* Set the path to where certificates and keys will be stored
* Set the ACME_URL to the test-url (important!!!)


#### Optional

Create the letsencrypt user:
```sudo useradd -r -s /bin/false letsencrypt```

Create the cert and keys folders:
```
sudo mkdir /tank/ssl/cert/ /tank/ssl/keys/ -p
sudo chown letsencrypt:letsencrypt /tank/ssl/cert/ /tank/ssl/keys/
sudo chmod 755 /tank/ssl/cert/
sudo chmod 750 /tank/ssl/keys/
```

## Usage

```sudo -u letsencrypt node letsencrypt.js yourdomain.com```

Check all domains to see if they need to renew:
```sudo -u letsencrypt node letsencrypt.js```


Once everything works, change the ACME url to the production url.


### Add to crontab

crontab -u letsencrypt -e

```45 7,19 * * *       node /tank/nodejs/letsencrypt.js```

Change the first value (minute 45), and hours 7,19 to a "random" values to somewhat ease the load on the ACME servers


## Nginx config gues

Example nginx config file:
```
server {
  listen 80;
  #listen 443 ssl;

  #ssl_certificate      /tank/ssl/cert/www.webtigerteam.com.crt;
  #ssl_certificate_key  /tank/ssl/keys/www.webtigerteam.com.key;

  server_name www.webtigerteam.com;

  server_tokens off;

  root /tank/www/webtigerteam.com/;
  index index.html index.htm;

  location / {
    charset	utf-8;
    try_files $uri $uri/ =404;
  }

  # Lets encrypt challange
  location /.well-known/acme-challenge/ {
    proxy_pass http://127.0.0.1:8094;
    proxy_set_header Host $http_host;
    proxy_set_header        X-Real-IP       $remote_addr;
  }

}
```

Copy the file to /etc/nginx/sites-available/
Then link it to /etc/nginx/sites-enabled/
```sudo ln -s /etc/nginx/sites-available/www.webtigerteam.com.nginx /etc/nginx/sites-enabled/www.webtigerteam.com```

And reload Nginx: ```sudo service nginx reload```

If there is any problems, run: ```sudo nginx -t```



Once you have the certificate in place, uncomment/add:
```
listen 443 ssl;
ssl_certificate      /tank/ssl/cert/www.webtigerteam.com.crt;
ssl_certificate_key  /tank/ssl/keys/www.webtigerteam.com.key;
```
Copy the file to /etc/nginx/sites-available/: ```sudo cp ~/wwwcnf/www.webtigerteam.com.nginx /etc/nginx/sites-available/```
And reload nginx again: ```sudo service nginx reload```


 