# DNS cache poisoning attack

The [DNS cache poisoning lab](https://seedsecuritylabs.org/Labs_20.04/Networking/DNS/DNS_Remote/), carries out the [Kaminsky attack](https://duo.com/blog/the-great-dns-vulnerability-of-2008-by-dan-kaminsky) on a local LAN setup

See the [task](./assets/task.pdf) outline for more details.

## Launching the attack

1. ### Install dependencies
    ```shell
    $ pip install scapy
    ```

2. ### Create DNS query and response templates
    ```shell
    $ python dns.py -ql
    $ python dns.py --reply true
    ```


## Results
