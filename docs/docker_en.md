## Run in Docker

```shell
docker run -d --name zju-connect -v $PWD/config.toml:/home/nonroot/config.toml -p 1080:1080 -p 1081:1081 --restart unless-stopped mythologyli/zju-connect
```

You can also use Docker Compose. Create `docker-compose.yml` file with the following content:

```yaml
services:
   zju-connect:
      image: mythologyli/zju-connect
      container_name: zju-connect
      restart: unless-stopped
      ports:
         - 1080:1080
         - 1081:1081
      volumes:
         - ./config.toml:/home/nonroot/config.toml
```

Additionally, you can also use [configs top-level elements](https://docs.docker.com/compose/compose-file/08-configs/) to directly write the configuration files of zju-connect into docker-compose.yml, as shown below:

```yaml
services:
   zju-connect:
      container_name: zju-connect
      image: mythologyli/zju-connect
      restart: unless-stopped
      ports: [1080:1080, 1081:1081]
      configs: [{ source: zju-connect-config, target: /home/nonroot/config.toml }]

configs:
   zju-connect-config:
      content: |
         username = ""
         password = ""
         # other configs ...
```

And run the following command in the same directory:

```shell
docker compose up -d
```

### aTrust Protocol Login and Data Persistence

The aTrust protocol client needs to persist login credentials (`client_data.json`) inside the container. The following example saves credentials to a Docker volume:

```yaml
services:
   zju-connect:
      container_name: zju-connect
      image: mythologyli/zju-connect
      restart: unless-stopped
      ports:
         - 1080:1080
         - 1081:1081
      configs:
         - source: zju-connect-config
           target: /home/nonroot/config.toml
      volumes:
         - zju-connect-data:/home/nonroot/data
configs:
   zju-connect-config:
      content: |
         username = ""
         password = ""
         client_data_file = "/home/nonroot/data/client_data.json"
         # other configs ...
volumes:
   zju-connect-data:
```

When first logging in with the aTrust protocol, human verification is required. Use `network_mode: host` and run in interactive mode temporarily:

```shell
docker compose run --rm -it zju-connect
```

**1. Graphical Captcha**

The program starts a temporary HTTP server to display the captcha. The port is randomly assigned by the system. Check the logs for the actual address:

```
2026/03/25 09:10:46 Captcha server started at http://127.0.0.1:40855
2026/03/25 09:10:46 Failed to open browser: exec: "xdg-open": executable file not found in $PATH. Please visit: http://127.0.0.1:40855
```

After completing the captcha, the program will prompt for SMS verification:

**2. SMS Verification Code**

```
2026/03/25 09:10:57 SMS message sent successfully: 验证码已发送到您的手机：***, 请查收！
zju-connect-1  | 2026/03/25 09:11:50 Please enter the SMS verification code:
```

Enter the SMS code from your phone and press Enter. Upon successful login, you will see:

```
2026/03/25 09:12:12 Client data saved to /home/nonroot/data/client_data.json
2026/03/25 09:12:12 VPN client started
```

After successful login, press `Ctrl+C` to exit the container. You can then use `docker compose up -d` normally. The login state is persisted in the Docker volume and no further verification is needed.
