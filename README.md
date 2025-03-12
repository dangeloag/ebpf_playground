# eBPF Playground

This is a simple demo of how to create an eBPF application in `C` and run it using `Go`
with the library <https://github.com/cilium/ebpf>

The source code in `./c_source/xdp_filter.c` simply drop the `ICMP` traffic
passing through the specified interface

### Running the code

Tested with:

- Docker version 28.0.1, build 068a01e
- Docker Compose version v2.33.1
- go version go1.24.0 linux/amd64

Given how complicated it is sometimes to get the system ready to work with this
kind of application, I opted to use a docker image that I found in this
[post](https://andreybleme.com/2022-05-22/running-ebpf-programs-on-docker-containers/). Wit this we just need to run a few commands and have our application ready:

```bash
docker compose build
docker compose run \
  --user "$(id -u):$(id -g)" \
  --rm -it \
  app bash -c 'clang -O2 -target bpf -c c_source/xdp_filter.c -o xdp_filter.o'

# build and run the application
# replace <iface_name> with the desired interface in your machine
go build -o main 
sudo ./main -iface <iface_name>

# once the application is running, test the ICMP traffic is being dropped
ping -I <iface_name> 8.8.8.8

```
