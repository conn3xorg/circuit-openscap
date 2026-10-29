# Local example

Applies circuit-openscap to a throwaway Rocky Linux 10 container with systemd, scanning against CIS Level 1 Server with root SSH logins left alone. You need Conn3x and Podman.

```sh
./up.sh
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` The apply sets up the weekly timer but doesn't scan. To run a scan now and see the counts:

```sh
ssh -p 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1 'systemctl start conn3x-scap.service; cat /var/lib/conn3x-scap/latest/summary.txt'
```

To read the HTML report, copy it out:

```sh
scp -P 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1:/var/lib/conn3x-scap/latest/report.html .
```

Expect most rules to come back `notapplicable` here. The content marks rules about the kernel, boot and hardware as applying to a machine, not a container, so a container scan is good for trying the circuit, not for judging a host.

`up.sh` listens on `127.0.0.1:2222`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINERFILE` to test another distro, such as one of the images in Conn3x's `test/images`, which CI uses. On a Mac, rootful Podman is simplest: `export CONTAINER_CONNECTION=podman-machine-default-root`.

`./down.sh` removes the container, its volumes, the key and the state.
